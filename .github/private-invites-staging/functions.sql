CREATE OR REPLACE FUNCTION public.invite_room_member_by_email(p_room_id uuid,p_email text,hasura_session json)
RETURNS SETOF public.rooms LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_target uuid; v_room public.rooms%ROWTYPE;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 SELECT * INTO v_room FROM public.rooms WHERE id=p_room_id AND room_type='private';
 IF NOT FOUND OR v_room.created_by<>v_actor THEN RAISE EXCEPTION 'Not authorized'; END IF;
 IF p_email IS NULL OR length(trim(p_email))<3 OR length(trim(p_email))>254 THEN RAISE EXCEPTION 'Invalid invitation'; END IF;
 SELECT id INTO v_target FROM auth.users WHERE lower(email)=lower(trim(p_email)) AND email_verified IS TRUE LIMIT 1;
 IF v_target IS NULL OR v_target=v_actor THEN RAISE EXCEPTION 'Account not found or cannot be invited'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.messenger_profiles WHERE user_id=v_actor) OR NOT EXISTS(SELECT 1 FROM public.messenger_profiles WHERE user_id=v_target) THEN RAISE EXCEPTION 'Configure profiles before inviting'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.messenger_friend_requests f WHERE f.status='accepted' AND ((f.requester_id=v_actor AND f.recipient_id=v_target) OR (f.recipient_id=v_actor AND f.requester_id=v_target))) THEN RAISE EXCEPTION 'Only an accepted friend can be invited'; END IF;
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES(p_room_id,v_target,v_actor,NULL) ON CONFLICT(room_id,user_id) DO NOTHING;
 RETURN QUERY SELECT r.* FROM public.rooms r WHERE r.id=p_room_id;
END;$fn$;

CREATE OR REPLACE FUNCTION public.accept_private_room_invite(p_room_id uuid,hasura_session json)
RETURNS SETOF public.room_members LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 UPDATE public.room_members m SET accepted_at=coalesce(m.accepted_at,now()) FROM public.rooms r WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NULL AND r.id=m.room_id AND r.room_type='private';
 IF NOT FOUND THEN RAISE EXCEPTION 'Invitation not found'; END IF;
 RETURN QUERY SELECT m.* FROM public.room_members m WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NOT NULL;
END;$fn$;

CREATE OR REPLACE FUNCTION public.my_pending_private_invites(hasura_session json)
RETURNS SETOF public.private_invite_results LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT v_actor,r.id,r.title,m.invited_by,m.created_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.user_id=v_actor AND m.accepted_at IS NULL AND r.room_type='private';
END;$fn$;

CREATE OR REPLACE FUNCTION public.my_accepted_private_rooms(hasura_session json)
RETURNS SETOF public.private_accepted_room_results LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT v_actor,r.id,r.title,r.created_by,m.accepted_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.user_id=v_actor AND m.accepted_at IS NOT NULL AND r.room_type='private';
END;$fn$;

CREATE OR REPLACE FUNCTION public.owner_room_members(p_room_id uuid,hasura_session json)
RETURNS SETOF public.private_owner_member_results LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT EXISTS(SELECT 1 FROM public.rooms WHERE id=p_room_id AND room_type='private' AND created_by=v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT v_actor,p_room_id,m.user_id,m.invited_by,m.accepted_at,m.created_at FROM public.room_members m WHERE m.room_id=p_room_id;
END;$fn$;

REVOKE ALL ON FUNCTION public.invite_room_member_by_email(uuid,text,json),public.accept_private_room_invite(uuid,json),public.my_pending_private_invites(json),public.my_accepted_private_rooms(json),public.owner_room_members(uuid,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.invite_room_member_by_email(uuid,text,json),public.accept_private_room_invite(uuid,json),public.my_pending_private_invites(json),public.my_accepted_private_rooms(json),public.owner_room_members(uuid,json) TO PUBLIC;
