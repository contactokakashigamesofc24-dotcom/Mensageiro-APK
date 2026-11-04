-- Synthetic-only subset of group functions, aligned with APK GraphQL field names.
CREATE OR REPLACE FUNCTION public.create_private_messenger_group(p_title text,p_member_ids uuid[],hasura_session json)
RETURNS SETOF public.group_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_title text; v_room uuid; v_friend uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid; v_title:=trim(coalesce(p_title,''));
 IF length(v_title) NOT BETWEEN 1 AND 60 OR coalesce(cardinality(p_member_ids),0)<1 OR cardinality(p_member_ids)>50 THEN RAISE EXCEPTION 'Invalid group'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(p_member_ids) x WHERE x IS NULL OR x=v_actor) OR (SELECT count(DISTINCT x) FROM unnest(p_member_ids) x)<>cardinality(p_member_ids) THEN RAISE EXCEPTION 'Invalid members'; END IF;
 FOREACH v_friend IN ARRAY p_member_ids LOOP
  IF NOT EXISTS(SELECT 1 FROM public.messenger_friend_requests f WHERE f.status='accepted' AND ((f.requester_id=v_actor AND f.recipient_id=v_friend) OR (f.recipient_id=v_actor AND f.requester_id=v_friend))) THEN RAISE EXCEPTION 'Every member must be an accepted friend'; END IF;
 END LOOP;
 INSERT INTO public.rooms(title,room_type,created_by) VALUES(v_title,'private',v_actor) RETURNING id INTO v_room;
 INSERT INTO public.messenger_groups(room_id,owner_id) VALUES(v_room,v_actor);
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES(v_room,v_actor,v_actor,now());
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) SELECT v_room,x,v_actor,NULL FROM unnest(p_member_ids) x;
 RETURN QUERY SELECT g.room_id,g.group_title,g.owner_id,g.created_at FROM public.group_result g WHERE g.room_id=v_room;
END;$fn$;
CREATE OR REPLACE FUNCTION public.my_messenger_groups(hasura_session json)
RETURNS SETOF public.group_member_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT g.room_id,r.title,g.owner_id,m.user_id,m.accepted_at FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id
 WHERE hasura_session->>'x-hasura-role'='user' AND coalesce(hasura_session->>'x-hasura-user-id','') ~* '^[0-9a-f-]{36}$' AND m.user_id=(hasura_session->>'x-hasura-user-id')::uuid AND m.accepted_at IS NOT NULL;
$fn$;
CREATE OR REPLACE FUNCTION public.my_pending_group_invites(hasura_session json)
RETURNS SETOF public.group_invite_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT g.room_id,r.title,m.invited_by,m.created_at,m.user_id FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id
 WHERE hasura_session->>'x-hasura-role'='user' AND coalesce(hasura_session->>'x-hasura-user-id','') ~* '^[0-9a-f-]{36}$' AND m.user_id=(hasura_session->>'x-hasura-user-id')::uuid AND m.accepted_at IS NULL;
$fn$;
CREATE OR REPLACE FUNCTION public.accept_messenger_group_invite(p_room_id uuid,hasura_session json)
RETURNS SETOF public.room_members LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 UPDATE public.room_members m SET accepted_at=coalesce(m.accepted_at,now()) FROM public.messenger_groups g WHERE m.room_id=p_room_id AND g.room_id=m.room_id AND m.user_id=v_actor AND m.accepted_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Group invitation not found'; END IF;
 RETURN QUERY SELECT m.* FROM public.room_members m WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NOT NULL;
END;$fn$;
REVOKE ALL ON FUNCTION public.create_private_messenger_group(text,uuid[],json),public.my_messenger_groups(json),public.my_pending_group_invites(json),public.accept_messenger_group_invite(uuid,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_messenger_group(text,uuid[],json),public.my_messenger_groups(json),public.my_pending_group_invites(json),public.accept_messenger_group_invite(uuid,json) TO PUBLIC;
