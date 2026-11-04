-- Synthetic-only candidate functions for APK profile, friend request, and presence operations.
CREATE OR REPLACE FUNCTION public.my_messenger_profile(hasura_session json)
RETURNS SETOF public.messenger_profiles LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT p.* FROM public.messenger_profiles p WHERE hasura_session->>'x-hasura-role'='user' AND p.user_id=(hasura_session->>'x-hasura-user-id')::uuid;
$fn$;
CREATE OR REPLACE FUNCTION public.upsert_my_profile(p_display_name text,p_avatar_data text,hasura_session json)
RETURNS SETOF public.messenger_profiles LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF length(trim(coalesce(p_display_name,''))) NOT BETWEEN 1 AND 60 OR (p_avatar_data IS NOT NULL AND (octet_length(p_avatar_data)>300000 OR p_avatar_data NOT LIKE 'data:image/jpeg;base64,%')) THEN RAISE EXCEPTION 'Invalid profile'; END IF;
 INSERT INTO public.messenger_profiles(user_id,display_name,avatar_data) VALUES(v_actor,trim(p_display_name),p_avatar_data) ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name,avatar_data=coalesce(excluded.avatar_data,public.messenger_profiles.avatar_data),updated_at=now();
 RETURN QUERY SELECT p.* FROM public.messenger_profiles p WHERE p.user_id=v_actor;
END;$fn$;
CREATE OR REPLACE FUNCTION public.request_friend_by_email(p_email text,hasura_session json)
RETURNS SETOF public.friend_request_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_target uuid; v_request uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 SELECT id INTO v_target FROM auth.users WHERE lower(email)=lower(trim(p_email)) AND email_verified IS TRUE LIMIT 1;
 IF v_target IS NULL OR v_target=v_actor THEN RAISE EXCEPTION 'Invalid friend account'; END IF;
 INSERT INTO public.messenger_friend_requests(requester_id,recipient_id,status) VALUES(v_actor,v_target,'pending') ON CONFLICT(requester_id,recipient_id) DO UPDATE SET status=CASE WHEN messenger_friend_requests.status='declined' THEN 'pending' ELSE messenger_friend_requests.status END,created_at=CASE WHEN messenger_friend_requests.status='declined' THEN now() ELSE messenger_friend_requests.created_at END RETURNING request_id INTO v_request;
 RETURN QUERY SELECT r.request_id,r.status FROM public.messenger_friend_requests r WHERE r.request_id=v_request;
END;$fn$;
CREATE OR REPLACE FUNCTION public.respond_friend_request(p_request_id uuid,p_accept boolean,hasura_session json)
RETURNS SETOF public.friend_request_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_status text;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 UPDATE public.messenger_friend_requests r SET status=CASE WHEN p_accept THEN 'accepted' ELSE 'declined' END,responded_at=now() WHERE r.request_id=p_request_id AND r.recipient_id=v_actor AND r.status='pending' RETURNING r.status INTO v_status;
 IF v_status IS NULL THEN RAISE EXCEPTION 'Request not found'; END IF;
 RETURN QUERY SELECT p_request_id,v_status;
END;$fn$;
CREATE OR REPLACE FUNCTION public.my_messenger_friends(hasura_session json)
RETURNS SETOF public.friend_profile_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT p.user_id,p.display_name,p.avatar_data FROM public.messenger_friend_requests r JOIN public.messenger_profiles p ON p.user_id=CASE WHEN r.requester_id=(hasura_session->>'x-hasura-user-id')::uuid THEN r.recipient_id ELSE r.requester_id END WHERE hasura_session->>'x-hasura-role'='user' AND r.status='accepted' AND (r.requester_id=(hasura_session->>'x-hasura-user-id')::uuid OR r.recipient_id=(hasura_session->>'x-hasura-user-id')::uuid);
$fn$;
CREATE OR REPLACE FUNCTION public.my_incoming_friend_requests(hasura_session json)
RETURNS SETOF public.incoming_friend_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT r.request_id,p.user_id,p.display_name,p.avatar_data FROM public.messenger_friend_requests r JOIN public.messenger_profiles p ON p.user_id=r.requester_id WHERE hasura_session->>'x-hasura-role'='user' AND r.recipient_id=(hasura_session->>'x-hasura-user-id')::uuid AND r.status='pending';
$fn$;
CREATE OR REPLACE FUNCTION public.set_my_presence(p_online boolean,hasura_session json)
RETURNS SETOF public.presence_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_online THEN INSERT INTO public.messenger_presence(user_id,last_seen) VALUES(v_actor,now()) ON CONFLICT(user_id) DO UPDATE SET last_seen=now(); ELSE DELETE FROM public.messenger_presence WHERE user_id=v_actor; END IF;
 RETURN QUERY SELECT p.user_id,p.last_seen FROM public.messenger_presence p WHERE p.user_id=v_actor;
END;$fn$;
CREATE OR REPLACE FUNCTION public.my_friends_presence(hasura_session json)
RETURNS SETOF public.friend_presence_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT CASE WHEN r.requester_id=(hasura_session->>'x-hasura-user-id')::uuid THEN r.recipient_id ELSE r.requester_id END,coalesce(p.last_seen>now()-interval '45 seconds',false),p.last_seen FROM public.messenger_friend_requests r LEFT JOIN public.messenger_presence p ON p.user_id=CASE WHEN r.requester_id=(hasura_session->>'x-hasura-user-id')::uuid THEN r.recipient_id ELSE r.requester_id END WHERE hasura_session->>'x-hasura-role'='user' AND r.status='accepted' AND (r.requester_id=(hasura_session->>'x-hasura-user-id')::uuid OR r.recipient_id=(hasura_session->>'x-hasura-user-id')::uuid);
$fn$;
REVOKE ALL ON FUNCTION public.my_messenger_profile(json),public.upsert_my_profile(text,text,json),public.request_friend_by_email(text,json),public.respond_friend_request(uuid,boolean,json),public.my_messenger_friends(json),public.my_incoming_friend_requests(json),public.set_my_presence(boolean,json),public.my_friends_presence(json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.my_messenger_profile(json),public.upsert_my_profile(text,text,json),public.request_friend_by_email(text,json),public.respond_friend_request(uuid,boolean,json),public.my_messenger_friends(json),public.my_incoming_friend_requests(json),public.set_my_presence(boolean,json),public.my_friends_presence(json) TO PUBLIC;
