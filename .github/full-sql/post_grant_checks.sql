DO $check$
DECLARE offenders text;
BEGIN
 SELECT string_agg(p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', ', ') INTO offenders
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.prokind='f' AND p.proname IN (
  'messenger_bot_status','set_messenger_bot_enabled','my_messenger_profile','room_message_profiles','get_message_profile','upsert_my_profile','request_friend_by_email','respond_friend_request','my_messenger_friends','my_incoming_friend_requests','invite_room_member_by_email','accept_private_room_invite','my_accepted_private_rooms','owner_room_members','my_pending_private_invites','create_private_messenger_group','my_messenger_groups','my_pending_group_invites','accept_messenger_group_invite','set_my_presence','my_presence_state','my_friends_presence','create_private_room_audio','add_private_room_audio_chunk','complete_private_room_audio','private_room_audio_message_ids','get_private_room_audio_chunks','create_private_room_media','add_private_room_media_chunk','complete_private_room_media','private_room_media_message_ids','private_room_media_info','get_private_room_media_chunks'
 ) AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE');
 RAISE NOTICE 'Functions still executable by PUBLIC: %',coalesce(offenders,'none');
 IF EXISTS (
   SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='public' AND p.prokind='f' AND p.proname IN (
    'messenger_bot_status','set_messenger_bot_enabled','my_messenger_profile','room_message_profiles','get_message_profile','upsert_my_profile','request_friend_by_email','respond_friend_request','my_messenger_friends','my_incoming_friend_requests','invite_room_member_by_email','accept_private_room_invite','my_accepted_private_rooms','owner_room_members','my_pending_private_invites','create_private_messenger_group','my_messenger_groups','my_pending_group_invites','accept_messenger_group_invite','set_my_presence','my_presence_state','my_friends_presence','create_private_room_audio','add_private_room_audio_chunk','complete_private_room_audio','private_room_audio_message_ids','get_private_room_audio_chunks','create_private_room_media','add_private_room_media_chunk','complete_private_room_media','private_room_media_message_ids','private_room_media_info','get_private_room_media_chunks'
   ) AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
 ) THEN RAISE EXCEPTION 'PUBLIC still has EXECUTE on one or more application functions'; END IF;
 IF NOT has_function_privilege('hasura_runtime','public.messenger_bot_status(json)','EXECUTE') THEN RAISE EXCEPTION 'Hasura runtime cannot execute allowed API function'; END IF;
 IF EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname='messenger_bot_status' AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) THEN RAISE EXCEPTION 'PostgreSQL PUBLIC can execute Bot status'; END IF;
 RAISE NOTICE 'PASS PUBLIC has no app function EXECUTE; isolated hasura_runtime can execute needed functions';
END;
$check$;
