DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='hasura_runtime') THEN
    CREATE ROLE hasura_runtime LOGIN PASSWORD 'runtime-only-disposable';
  END IF;
END;
$role$;
GRANT USAGE ON SCHEMA public,auth TO hasura_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO hasura_runtime;
GRANT INSERT ON public.rooms,public.messages TO hasura_runtime;
DO $grants$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS signature
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='public' AND p.proretset AND p.prokind='f'
      AND p.proname IN (
        'messenger_bot_status','set_messenger_bot_enabled','my_messenger_profile','room_message_profiles','get_message_profile','upsert_my_profile','request_friend_by_email','respond_friend_request','my_messenger_friends','my_incoming_friend_requests','invite_room_member_by_email','accept_private_room_invite','my_accepted_private_rooms','owner_room_members','my_pending_private_invites','create_private_messenger_group','my_messenger_groups','my_pending_group_invites','accept_messenger_group_invite','set_my_presence','my_presence_state','my_friends_presence','create_private_room_audio','add_private_room_audio_chunk','complete_private_room_audio','private_room_audio_message_ids','get_private_room_audio_chunks','create_private_room_media','add_private_room_media_chunk','complete_private_room_media','private_room_media_message_ids','private_room_media_info','get_private_room_media_chunks'
      )
  LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO hasura_runtime',r.signature);
  END LOOP;
END;
$grants$;
