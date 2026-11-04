-- Synthetic-only candidate: Hasura-trackable replacements for a subset of MESSENGER_GLOBAL_SWITCH.sql.
-- This file is loaded only by the ephemeral GitHub Actions test; NEVER apply to production.
CREATE OR REPLACE FUNCTION public.create_private_room_candidate(p_title text,hasura_session json)
RETURNS SETOF public.private_room_results
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_title text; v_id uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 v_title:=trim(coalesce(p_title,''));
 IF length(v_title) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'Room title must be 1 to 100 characters'; END IF;
 INSERT INTO public.rooms(title,room_type,created_by) VALUES(v_title,'private',v_actor) RETURNING id INTO v_id;
 RETURN QUERY SELECT r.id,r.title,r.room_type,r.created_by,r.created_at FROM public.private_room_results r WHERE r.id=v_id AND r.created_by=v_actor;
END;$fn$;

CREATE OR REPLACE FUNCTION public.send_private_message_candidate(p_room_id uuid,p_body text,hasura_session json)
RETURNS SETOF public.message_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_body text; v_id uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 v_body:=trim(coalesce(p_body,''));
 IF length(v_body) NOT BETWEEN 1 AND 4000 THEN RAISE EXCEPTION 'Message must be 1 to 4000 characters'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.rooms r WHERE r.id=p_room_id AND r.room_type='private' AND (r.created_by=v_actor OR EXISTS(SELECT 1 FROM public.room_members m WHERE m.room_id=r.id AND m.user_id=v_actor AND m.accepted_at IS NOT NULL))) THEN RAISE EXCEPTION 'Only accepted members may send'; END IF;
 INSERT INTO public.messages(room_id,sender_id,body) VALUES(p_room_id,v_actor,v_body) RETURNING id INTO v_id;
 RETURN QUERY SELECT m.id,m.sender_id FROM public.message_result m WHERE m.id=v_id AND m.sender_id=v_actor;
END;$fn$;

CREATE OR REPLACE FUNCTION public.my_owned_private_rooms_candidate(hasura_session json)
RETURNS SETOF public.private_room_results
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT r.id,r.title,r.room_type,r.created_by,r.created_at FROM public.private_room_results r
 WHERE hasura_session->>'x-hasura-role'='user' AND coalesce(hasura_session->>'x-hasura-user-id','') ~* '^[0-9a-f-]{36}$' AND r.created_by=(hasura_session->>'x-hasura-user-id')::uuid;
$fn$;

REVOKE ALL ON FUNCTION public.create_private_room_candidate(text,json),public.send_private_message_candidate(uuid,text,json),public.my_owned_private_rooms_candidate(json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_room_candidate(text,json),public.send_private_message_candidate(uuid,text,json),public.my_owned_private_rooms_candidate(json) TO PUBLIC;
