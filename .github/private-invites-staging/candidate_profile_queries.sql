-- Synthetic-only profile lookup functions matching APK query names.
CREATE OR REPLACE FUNCTION public.get_message_profile(p_user_id uuid,hasura_session json)
RETURNS SETOF public.message_profile_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT p.display_name,p.avatar_data FROM public.messenger_profiles p WHERE p.user_id=p_user_id AND hasura_session->>'x-hasura-role'='user' AND (p_user_id=(hasura_session->>'x-hasura-user-id')::uuid OR EXISTS(SELECT 1 FROM public.messages m JOIN public.rooms r ON r.id=m.room_id WHERE m.sender_id=p_user_id AND (r.room_type='public' OR public.messenger_user_can_access_private_room(r.id,(hasura_session->>'x-hasura-user-id')::uuid))));
$fn$;
CREATE OR REPLACE FUNCTION public.room_message_profiles(p_room_id uuid,hasura_session json)
RETURNS SETOF public.room_message_profile_result LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT DISTINCT p.user_id AS sender_id,p.display_name,p.avatar_data FROM public.messenger_profiles p JOIN public.messages m ON m.sender_id=p.user_id WHERE m.room_id=p_room_id AND hasura_session->>'x-hasura-role'='user' AND (EXISTS(SELECT 1 FROM public.rooms r WHERE r.id=p_room_id AND r.room_type='public') OR public.messenger_user_can_access_private_room(p_room_id,(hasura_session->>'x-hasura-user-id')::uuid));
$fn$;
REVOKE ALL ON FUNCTION public.get_message_profile(uuid,json),public.room_message_profiles(uuid,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_message_profile(uuid,json),public.room_message_profiles(uuid,json) TO PUBLIC;
