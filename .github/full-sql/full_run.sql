CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE auth.users(
 id uuid PRIMARY KEY,
 email text UNIQUE NOT NULL,
 email_verified boolean NOT NULL DEFAULT true
);
INSERT INTO auth.users(id,email,email_verified) VALUES
('27a5eca4-18d2-4a67-9a34-3e075317740b','owner@example.test',true),
('40000000-0000-0000-0000-000000000002','member@example.test',true),
('40000000-0000-0000-0000-000000000003','pending@example.test',true),
('40000000-0000-0000-0000-000000000004','outsider@example.test',true),
('40000000-0000-0000-0000-000000000005','unverified@example.test',false);

-- Execute only in the dedicated Nhost project "Mensageiro".
-- First chat phase: public rooms and owner-only private rooms. Invites are intentionally not enabled yet.
create extension if not exists pgcrypto;

create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(trim(title)) between 1 and 100),
  room_type text not null check (room_type in ('public','private')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (length(trim(body)) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index if not exists messages_room_created_idx on public.messages(room_id, created_at);

-- Track public.rooms and public.messages in Hasura after executing this SQL.
-- Configure role "user" as described in HASURA_PERMISSIONS.md BEFORE installing/testing the app.
-- Nhost/Hasura is default-deny for user role. Never put the admin secret into the APK.

create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  invited_by uuid not null references auth.users(id) on delete cascade,
  accepted_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (room_id, user_id)
);
create index if not exists room_members_user_room_idx on public.room_members(user_id, room_id);

-- SAFE DRAFT — bot-only global switch. DO NOT RUN until reviewed and backed up.
-- This switch controls whether the future Bot worker may process messages; it does NOT gate
-- ordinary chat, room creation, public-room sending, or audio/photo/video uploads.
-- No Worker is connected and no bot response is activated by this SQL.
-- Target project fapcygtcubeukddoieus; verify the allowlisted account UUID before use.

CREATE TABLE IF NOT EXISTS public.messenger_bot_status_result (enabled boolean, updated_at timestamptz);
CREATE TABLE IF NOT EXISTS public.set_messenger_bot_enabled_result (enabled boolean, updated_at timestamptz);

CREATE TABLE IF NOT EXISTS public.messenger_bot_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled boolean NOT NULL DEFAULT false,
  updated_by uuid REFERENCES auth.users(id),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- Bot starts OFF. Migration bootstrap only; the runtime never inserts/deletes this row.
INSERT INTO public.messenger_bot_settings(singleton,enabled)
VALUES (true,false) ON CONFLICT(singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION public.messenger_user_can_access_private_room(p_room_id uuid,p_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
 SELECT EXISTS (
   SELECT 1 FROM public.rooms r
   WHERE r.id=p_room_id AND r.room_type='private'
     AND (r.created_by=p_user_id OR EXISTS (
       SELECT 1 FROM public.room_members m WHERE m.room_id=r.id AND m.user_id=p_user_id AND m.accepted_at IS NOT NULL
     ))
 );
$fn$;

CREATE OR REPLACE FUNCTION public.messenger_bot_status(hasura_session json)
RETURNS SETOF public.messenger_bot_status_result
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
    OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT s.enabled,s.updated_at FROM public.messenger_bot_settings s WHERE s.singleton=true;
END; $fn$;

CREATE OR REPLACE FUNCTION public.set_messenger_bot_enabled(p_enabled boolean,hasura_session json)
RETURNS SETOF public.set_messenger_bot_enabled_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
    OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF v_actor <> '27a5eca4-18d2-4a67-9a34-3e075317740b'::uuid THEN RAISE EXCEPTION 'Only the authorized administrator may change the Bot switch'; END IF;
 UPDATE public.messenger_bot_settings SET enabled=p_enabled,updated_by=v_actor,updated_at=now() WHERE singleton=true;
 IF NOT FOUND THEN RAISE EXCEPTION 'Bot settings row missing'; END IF;
 RETURN QUERY SELECT s.enabled,s.updated_at FROM public.messenger_bot_settings s WHERE s.singleton=true;
END; $fn$;

-- Protect chat identity and private-room membership while preserving existing public-room writes.
-- Hasura must continue to preset sender_id to X-Hasura-User-Id in its INSERT permission.
CREATE OR REPLACE FUNCTION public.enforce_messenger_message_identity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_session jsonb; v_actor uuid; v_room_type text;
BEGIN
 v_session:=nullif(current_setting('hasura.user',true),'')::jsonb;
 IF v_session IS NULL OR v_session->>'x-hasura-role'<>'user'
    OR coalesce(v_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(v_session->>'x-hasura-user-id')::uuid;
 IF NEW.sender_id IS DISTINCT FROM v_actor THEN RAISE EXCEPTION 'Sender must match authenticated session'; END IF;
 SELECT r.room_type INTO v_room_type FROM public.rooms r WHERE r.id=NEW.room_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Room not found'; END IF;
 IF v_room_type='private' AND NOT public.messenger_user_can_access_private_room(NEW.room_id,v_actor) THEN RAISE EXCEPTION 'Only owner or accepted private-room members may send'; END IF;
 -- Public-room behavior remains under the existing Hasura permissions; this trigger does not block it.
 RETURN NEW;
END; $fn$;
DROP TRIGGER IF EXISTS messenger_message_identity_gate ON public.messages;
CREATE TRIGGER messenger_message_identity_gate BEFORE INSERT ON public.messages
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_message_identity();

-- Keep normal public/private room creation, but prevent a client from assigning another owner.
CREATE OR REPLACE FUNCTION public.enforce_messenger_room_owner()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_session jsonb; v_actor uuid;
BEGIN
 v_session:=nullif(current_setting('hasura.user',true),'')::jsonb;
 IF v_session IS NULL OR v_session->>'x-hasura-role'<>'user'
    OR coalesce(v_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(v_session->>'x-hasura-user-id')::uuid;
 IF NEW.created_by IS DISTINCT FROM v_actor THEN RAISE EXCEPTION 'Room owner must match authenticated session'; END IF;
 IF NEW.room_type NOT IN ('public','private') THEN RAISE EXCEPTION 'Invalid room type'; END IF;
 RETURN NEW;
END; $fn$;
DROP TRIGGER IF EXISTS messenger_private_room_owner_gate ON public.rooms;
DROP TRIGGER IF EXISTS messenger_room_owner_gate ON public.rooms;
CREATE TRIGGER messenger_room_owner_gate BEFORE INSERT ON public.rooms
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_room_owner();

-- Attachment file/chunk rows stay private to their uploader and an authorized private room.
-- This is independent of the Bot flag so stopping the Bot never disrupts normal chat uploads.
CREATE OR REPLACE FUNCTION public.enforce_messenger_attachment_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_session jsonb; v_actor uuid; v_owner uuid; v_room uuid; v_parent_table text;
BEGIN
 v_session:=nullif(current_setting('hasura.user',true),'')::jsonb;
 IF v_session IS NULL OR v_session->>'x-hasura-role'<>'user'
    OR coalesce(v_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(v_session->>'x-hasura-user-id')::uuid;
 IF TG_TABLE_NAME IN ('message_audio_files','message_media_files') THEN
   v_owner:=NEW.uploaded_by;
 ELSE
   v_parent_table:=CASE TG_TABLE_NAME WHEN 'message_audio_chunks' THEN 'message_audio_files' WHEN 'message_media_chunks' THEN 'message_media_files' ELSE NULL END;
   IF v_parent_table IS NULL THEN RAISE EXCEPTION 'Invalid attachment table'; END IF;
   EXECUTE format('SELECT uploaded_by FROM public.%I WHERE message_id=$1',v_parent_table) INTO v_owner USING NEW.message_id;
 END IF;
 SELECT m.room_id INTO v_room FROM public.messages m WHERE m.id=NEW.message_id;
 IF v_owner IS NULL OR v_room IS NULL OR v_owner<>v_actor OR NOT public.messenger_user_can_access_private_room(v_room,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN NEW;
END; $fn$;

CREATE OR REPLACE FUNCTION public.enforce_messenger_bot_setting_owner()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_session jsonb; v_actor uuid;
BEGIN
 v_session:=nullif(current_setting('hasura.user',true),'')::jsonb;
 IF v_session IS NULL OR v_session->>'x-hasura-role'<>'user'
    OR coalesce(v_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(v_session->>'x-hasura-user-id')::uuid;
 IF v_actor<>'27a5eca4-18d2-4a67-9a34-3e075317740b'::uuid OR NEW.updated_by IS DISTINCT FROM v_actor THEN RAISE EXCEPTION 'Only the authorized administrator may change Bot settings'; END IF;
 IF TG_OP='INSERT' THEN RAISE EXCEPTION 'Initial settings are created by migration only'; END IF;
 RETURN NEW;
END; $fn$;
DROP TRIGGER IF EXISTS messenger_bot_settings_owner_gate ON public.messenger_bot_settings;
CREATE TRIGGER messenger_bot_settings_owner_gate BEFORE UPDATE ON public.messenger_bot_settings
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_bot_setting_owner();

REVOKE ALL ON public.messenger_bot_settings FROM PUBLIC;
REVOKE ALL ON FUNCTION public.messenger_user_can_access_private_room(uuid,uuid),public.enforce_messenger_message_identity(),public.enforce_messenger_room_owner(),public.enforce_messenger_attachment_write(),public.enforce_messenger_bot_setting_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.messenger_bot_status(json),public.set_messenger_bot_enabled(boolean,json) FROM PUBLIC;
-- Hasura DB-role execution privilege; Hasura API permissions must allow the status query only to authenticated user,
-- and the setter only to authenticated user with the UUID allowlist. Never add anonymous function permissions.
GRANT EXECUTE ON FUNCTION public.messenger_bot_status(json),public.set_messenger_bot_enabled(boolean,json) TO PUBLIC;

-- Intentionally absent: no message-acceptance pause, public-room write block, public-room creation block,
-- deletion restriction for normal users, or Bot-worker connection. The Bot toggle only changes this table's flag.

-- User profiles (display name + optional compressed avatar) and friend requests.
-- Apply only to Mensageiro Nhost project fapcygtcubeukddoieus.
-- Hasura-trackable composite result views required for SETOF function returns.
CREATE TABLE IF NOT EXISTS public.my_messenger_profile_result (
  display_name text,
  avatar_data text
);
CREATE TABLE IF NOT EXISTS public.upsert_my_profile_result (
  user_id uuid,
  display_name text,
  avatar_data text
);
CREATE TABLE IF NOT EXISTS public.my_incoming_friend_requests_result (
  request_id uuid,
  user_id uuid,
  display_name text,
  avatar_data text
);
CREATE TABLE IF NOT EXISTS public.my_messenger_friends_result (
  user_id uuid,
  display_name text,
  avatar_data text
);
CREATE TABLE IF NOT EXISTS public.respond_friend_request_result (
  request_id uuid,
  status text
);
CREATE TABLE IF NOT EXISTS public.request_friend_by_email_result (
  request_id uuid
);
CREATE TABLE IF NOT EXISTS public.get_message_profile_result (
  display_name text,
  avatar_data text
);
CREATE TABLE IF NOT EXISTS public.room_message_profiles_result (
  sender_id uuid,
  display_name text,
  avatar_data text
);

CREATE TABLE IF NOT EXISTS public.messenger_profiles (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name text NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 60),
  avatar_data text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT messenger_profiles_avatar_size CHECK (avatar_data IS NULL OR octet_length(avatar_data) <= 300000),
  CONSTRAINT messenger_profiles_avatar_type CHECK (avatar_data IS NULL OR avatar_data LIKE 'data:image/jpeg;base64,%')
);
CREATE TABLE IF NOT EXISTS public.messenger_friend_requests (
  request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  recipient_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','declined')),
  created_at timestamptz NOT NULL DEFAULT now(),
  responded_at timestamptz,
  CONSTRAINT messenger_friend_no_self CHECK (requester_id <> recipient_id),
  CONSTRAINT messenger_friend_pair_unique UNIQUE (requester_id, recipient_id)
);
CREATE INDEX IF NOT EXISTS messenger_friend_recipient_status_idx ON public.messenger_friend_requests(recipient_id,status);
CREATE INDEX IF NOT EXISTS messenger_friend_requester_status_idx ON public.messenger_friend_requests(requester_id,status);

CREATE OR REPLACE FUNCTION public.my_messenger_profile(hasura_session json)
RETURNS SETOF public.my_messenger_profile_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT p.display_name,p.avatar_data FROM public.messenger_profiles p WHERE p.user_id=v_actor;
END; $fn$;

CREATE OR REPLACE FUNCTION public.room_message_profiles(p_room_id uuid, hasura_session json)
RETURNS SETOF public.room_message_profiles_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  IF NOT EXISTS (
    SELECT 1 FROM public.rooms r WHERE r.id=p_room_id AND (
      r.room_type='public' OR r.created_by=v_actor OR EXISTS (
        SELECT 1 FROM public.room_members rm WHERE rm.room_id=r.id AND rm.user_id=v_actor AND rm.accepted_at IS NOT NULL
      )
    )
  ) THEN RAISE EXCEPTION 'Not authorized'; END IF;
  RETURN QUERY SELECT DISTINCT p.user_id,p.display_name,p.avatar_data FROM public.messages m
    JOIN public.messenger_profiles p ON p.user_id=m.sender_id WHERE m.room_id=p_room_id;
END; $fn$;

CREATE OR REPLACE FUNCTION public.get_message_profile(p_user_id uuid, hasura_session json)
RETURNS SETOF public.get_message_profile_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  IF p_user_id <> v_actor AND NOT EXISTS (
      SELECT 1 FROM public.rooms r
      JOIN public.messages m ON m.room_id=r.id
      WHERE m.sender_id=p_user_id AND (
        r.room_type='public' OR r.created_by=v_actor OR EXISTS (
          SELECT 1 FROM public.room_members rm WHERE rm.room_id=r.id AND rm.user_id=v_actor AND rm.accepted_at IS NOT NULL
        )
      )
  ) THEN RAISE EXCEPTION 'Not authorized'; END IF;
  RETURN QUERY SELECT p.display_name,p.avatar_data FROM public.messenger_profiles p WHERE p.user_id=p_user_id;
END; $fn$;

CREATE OR REPLACE FUNCTION public.upsert_my_profile(p_display_name text, p_avatar_data text, hasura_session json)
RETURNS SETOF public.upsert_my_profile_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  IF length(trim(p_display_name)) NOT BETWEEN 1 AND 60 OR (p_avatar_data IS NOT NULL AND (octet_length(p_avatar_data)>300000 OR p_avatar_data NOT LIKE 'data:image/jpeg;base64,%')) THEN RAISE EXCEPTION 'Invalid profile'; END IF;
  INSERT INTO public.messenger_profiles(user_id,display_name,avatar_data) VALUES(v_actor,trim(p_display_name),p_avatar_data)
  ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name, avatar_data=COALESCE(excluded.avatar_data,public.messenger_profiles.avatar_data), updated_at=now();
  RETURN QUERY SELECT p.user_id,p.display_name,p.avatar_data FROM public.messenger_profiles p WHERE p.user_id=v_actor;
END; $fn$;

CREATE OR REPLACE FUNCTION public.request_friend_by_email(p_email text, hasura_session json)
RETURNS SETOF public.request_friend_by_email_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_target uuid; v_request uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  SELECT id INTO v_target FROM auth.users WHERE lower(email)=lower(trim(p_email)) AND email_verified IS TRUE LIMIT 1;
  IF v_target IS NULL OR v_target=v_actor THEN RAISE EXCEPTION 'Conta não encontrada ou pedido inválido'; END IF;
  INSERT INTO public.messenger_friend_requests(requester_id,recipient_id,status) VALUES(v_actor,v_target,'pending')
  ON CONFLICT(requester_id,recipient_id) DO UPDATE SET status=CASE WHEN messenger_friend_requests.status='declined' THEN 'pending' ELSE messenger_friend_requests.status END,created_at=CASE WHEN messenger_friend_requests.status='declined' THEN now() ELSE messenger_friend_requests.created_at END
  RETURNING messenger_friend_requests.request_id INTO v_request;
  RETURN QUERY SELECT v_request;
END; $fn$;

CREATE OR REPLACE FUNCTION public.respond_friend_request(p_request_id uuid,p_accept boolean,hasura_session json)
RETURNS SETOF public.respond_friend_request_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_status text;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  UPDATE public.messenger_friend_requests r SET status=CASE WHEN p_accept THEN 'accepted' ELSE 'declined' END,responded_at=now()
  WHERE r.request_id=p_request_id AND r.recipient_id=v_actor AND r.status='pending' RETURNING r.status INTO v_status;
  IF v_status IS NULL THEN RAISE EXCEPTION 'Pedido não encontrado'; END IF;
  RETURN QUERY SELECT p_request_id,v_status;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_messenger_friends(hasura_session json)
RETURNS SETOF public.my_messenger_friends_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT p.user_id,p.display_name,p.avatar_data FROM public.messenger_friend_requests r JOIN public.messenger_profiles p ON p.user_id=CASE WHEN r.requester_id=v_actor THEN r.recipient_id ELSE r.requester_id END
  WHERE r.status='accepted' AND (r.requester_id=v_actor OR r.recipient_id=v_actor) ORDER BY p.display_name;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_incoming_friend_requests(hasura_session json)
RETURNS SETOF public.my_incoming_friend_requests_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT r.request_id,p.user_id,p.display_name,p.avatar_data FROM public.messenger_friend_requests r JOIN public.messenger_profiles p ON p.user_id=r.requester_id WHERE r.recipient_id=v_actor AND r.status='pending' ORDER BY r.created_at DESC;
END; $fn$;

REVOKE ALL ON FUNCTION public.my_messenger_profile(json), public.room_message_profiles(uuid,json), public.get_message_profile(uuid,json), public.upsert_my_profile(text,text,json), public.request_friend_by_email(text,json), public.respond_friend_request(uuid,boolean,json), public.my_messenger_friends(json), public.my_incoming_friend_requests(json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.my_messenger_profile(json), public.room_message_profiles(uuid,json), public.get_message_profile(uuid,json), public.upsert_my_profile(text,text,json), public.request_friend_by_email(text,json), public.respond_friend_request(uuid,boolean,json), public.my_messenger_friends(json), public.my_incoming_friend_requests(json) TO PUBLIC;
-- Track all eight functions in Hasura, mark hasura_session as session argument, grant execute only to role user.
-- Track messenger_profiles; permit authenticated user select only profile fields needed by chat, insert/update own user_id = X-Hasura-User-Id. Do not expose email.

-- Private-room invitations for EXISTING rows in public.rooms.
-- Apply only to Mensageiro Nhost project fapcygtcubeukddoieus.
-- Never creates/deletes rooms or messages; never put an admin secret in the APK.
-- Hasura must track these functions and mark `hasura_session` as its session argument,
-- then permit role `user` to execute them. See PRIVATE_ROOM_INVITES.md.

-- Hasura-trackable composite result views required for SETOF function returns.
CREATE TABLE IF NOT EXISTS public.invite_room_member_result (
  id uuid,
  title text,
  room_type text,
  created_by uuid
);
CREATE TABLE IF NOT EXISTS public.accept_private_room_invite_result (
  room_id uuid,
  accepted_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.my_pending_private_invites_result (
  room_id uuid,
  room_title text,
  inviter_id uuid,
  invited_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.owner_room_members_result (
  user_id uuid,
  invited_by uuid,
  accepted_at timestamptz,
  invited_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.my_accepted_private_rooms_result (
  room_id uuid,
  room_title text,
  owner_id uuid,
  joined_at timestamptz
);

CREATE OR REPLACE FUNCTION public.invite_room_member_by_email(
  p_room_id uuid, p_email text, hasura_session json
) RETURNS SETOF public.invite_room_member_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $fn$
DECLARE v_actor uuid; v_target uuid; v_room public.rooms%ROWTYPE;
BEGIN
  IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
     OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  SELECT * INTO v_room FROM public.rooms WHERE id=p_room_id AND room_type='private';
  IF NOT FOUND OR v_room.created_by <> v_actor THEN RAISE EXCEPTION 'Not authorized'; END IF;
  IF p_email IS NULL OR length(trim(p_email))<3 OR length(trim(p_email))>254 THEN RAISE EXCEPTION 'Invalid invitation'; END IF;
  SELECT id INTO v_target FROM auth.users WHERE lower(email)=lower(trim(p_email)) LIMIT 1;
  IF v_target IS NULL OR v_target=v_actor THEN RAISE EXCEPTION 'Account not found or cannot be invited'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.messenger_profiles p WHERE p.user_id=v_actor) OR NOT EXISTS(SELECT 1 FROM public.messenger_profiles p WHERE p.user_id=v_target) THEN RAISE EXCEPTION 'Configure profiles before inviting'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.messenger_friend_requests f WHERE f.status='accepted' AND ((f.requester_id=v_actor AND f.recipient_id=v_target) OR (f.recipient_id=v_actor AND f.requester_id=v_target))) THEN RAISE EXCEPTION 'Only an accepted friend can be invited'; END IF;
  -- Idempotent; accepted membership is never reset/downgraded.
  INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at)
    VALUES(p_room_id,v_target,v_actor,NULL) ON CONFLICT(room_id,user_id) DO NOTHING;
  -- Return only the owner-authorized room row, not a cross-user membership row.
  RETURN QUERY SELECT r.id,r.title,r.room_type,r.created_by FROM public.rooms r WHERE r.id=p_room_id;
END;
$fn$;

CREATE OR REPLACE FUNCTION public.accept_private_room_invite(
  p_room_id uuid, hasura_session json
) RETURNS SETOF public.accept_private_room_invite_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
     OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  UPDATE public.room_members m SET accepted_at=COALESCE(m.accepted_at,now())
    FROM public.rooms r WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NULL AND r.id=m.room_id AND r.room_type='private';
  IF NOT FOUND THEN RAISE EXCEPTION 'Invitation not found'; END IF;
  RETURN QUERY SELECT m.room_id,m.accepted_at
    FROM public.room_members m WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NOT NULL;
END;
$fn$;

-- Authenticated caller sees only accepted private rooms where they are a member.
CREATE OR REPLACE FUNCTION public.my_accepted_private_rooms(hasura_session json)
RETURNS SETOF public.my_accepted_private_rooms_result
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
     OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT r.id,r.title,r.created_by,m.accepted_at FROM public.room_members m
    JOIN public.rooms r ON r.id=m.room_id
    WHERE m.user_id=v_actor AND m.accepted_at IS NOT NULL AND r.room_type='private'
    ORDER BY m.accepted_at DESC;
END;
$fn$;

-- Owner-only minimal membership list for managing invites; no access to arbitrary room memberships.
CREATE OR REPLACE FUNCTION public.owner_room_members(p_room_id uuid, hasura_session json)
RETURNS SETOF public.owner_room_members_result
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
     OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  IF NOT EXISTS (SELECT 1 FROM public.rooms r WHERE r.id=p_room_id AND r.room_type='private' AND r.created_by=v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
  RETURN QUERY SELECT m.user_id,m.invited_by,m.accepted_at,m.created_at FROM public.room_members m WHERE m.room_id=p_room_id ORDER BY m.created_at;
END;
$fn$;

-- Invitee sees only their own pending invitations, and only minimal display metadata.
CREATE OR REPLACE FUNCTION public.my_pending_private_invites(hasura_session json)
RETURNS SETOF public.my_pending_private_invites_result
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF coalesce(hasura_session->>'x-hasura-role','') <> 'user'
     OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT r.id,r.title,m.invited_by,m.created_at FROM public.room_members m
    JOIN public.rooms r ON r.id=m.room_id
    WHERE m.user_id=v_actor AND m.accepted_at IS NULL AND r.room_type='private'
    ORDER BY m.created_at DESC;
END;
$fn$;

REVOKE ALL ON FUNCTION public.invite_room_member_by_email(uuid,text,json) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.accept_private_room_invite(uuid,json) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.my_pending_private_invites(json) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.my_accepted_private_rooms(json) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.owner_room_members(uuid,json) FROM PUBLIC;
-- Hasura's role permission is the API boundary; it injects the hasura_session argument.
GRANT EXECUTE ON FUNCTION public.invite_room_member_by_email(uuid,text,json) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.accept_private_room_invite(uuid,json) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.my_pending_private_invites(json) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.my_accepted_private_rooms(json) TO PUBLIC;
GRANT EXECUTE ON FUNCTION public.owner_room_members(uuid,json) TO PUBLIC;

-- Private groups in the Mensageiro. Apply only to Nhost project fapcygtcubeukddoieus after backup.
-- Groups use existing private rooms and accepted room_members memberships; do not grant anonymous access.
-- Hasura-trackable result composite types for functions; empty views are not data APIs.
CREATE TABLE IF NOT EXISTS public.accept_messenger_group_invite_result (
  room_id uuid,
  accepted_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.my_pending_group_invites_result (
  room_id uuid,
  group_title text,
  inviter_id uuid,
  invited_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.my_messenger_groups_result (
  room_id uuid,
  group_title text,
  owner_id uuid
);
CREATE TABLE IF NOT EXISTS public.create_private_messenger_group_result (
  room_id uuid,
  group_title text
);

CREATE TABLE IF NOT EXISTS public.messenger_groups (
  room_id uuid PRIMARY KEY REFERENCES public.rooms(id) ON DELETE CASCADE,
  owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messenger_groups_owner_idx ON public.messenger_groups(owner_id);

CREATE OR REPLACE FUNCTION public.create_private_messenger_group(p_title text,p_member_ids uuid[],hasura_session json)
RETURNS SETOF public.create_private_messenger_group_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_room uuid; v_friend uuid; v_title text;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 v_title:=trim(coalesce(p_title,''));
 IF length(v_title) NOT BETWEEN 1 AND 60 THEN RAISE EXCEPTION 'Group title must be 1 to 60 characters'; END IF;
 IF coalesce(cardinality(p_member_ids),0)<1 OR cardinality(p_member_ids)>50 THEN RAISE EXCEPTION 'Choose 1 to 50 friends'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(p_member_ids) x WHERE x IS NULL OR x=v_actor) OR (SELECT count(DISTINCT x) FROM unnest(p_member_ids) x)<>cardinality(p_member_ids) THEN RAISE EXCEPTION 'Invalid members'; END IF;
 FOREACH v_friend IN ARRAY p_member_ids LOOP
  IF NOT EXISTS(SELECT 1 FROM public.messenger_friend_requests f WHERE f.status='accepted' AND ((f.requester_id=v_actor AND f.recipient_id=v_friend) OR (f.recipient_id=v_actor AND f.requester_id=v_friend))) THEN RAISE EXCEPTION 'Every member must be an accepted friend'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.messenger_profiles p WHERE p.user_id=v_actor) OR NOT EXISTS(SELECT 1 FROM public.messenger_profiles p WHERE p.user_id=v_friend) THEN RAISE EXCEPTION 'Profiles and accepted friendship must be configured first'; END IF;
 END LOOP;
 INSERT INTO public.rooms(title,room_type,created_by) VALUES(v_title,'private',v_actor) RETURNING id INTO v_room;
 INSERT INTO public.messenger_groups(room_id,owner_id) VALUES(v_room,v_actor);
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES(v_room,v_actor,v_actor,now());
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) SELECT v_room,x,v_actor,NULL FROM unnest(p_member_ids) x;
 RETURN QUERY SELECT v_room,v_title;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_messenger_groups(hasura_session json)
RETURNS SETOF public.my_messenger_groups_result
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT r.id,r.title,g.owner_id FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id WHERE m.user_id=v_actor AND m.accepted_at IS NOT NULL ORDER BY g.created_at DESC;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_pending_group_invites(hasura_session json)
RETURNS SETOF public.my_pending_group_invites_result
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT r.id,r.title,m.invited_by,m.created_at FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id WHERE m.user_id=v_actor AND m.accepted_at IS NULL ORDER BY m.created_at DESC;
END; $fn$;

CREATE OR REPLACE FUNCTION public.accept_messenger_group_invite(p_room_id uuid,hasura_session json)
RETURNS SETOF public.accept_messenger_group_invite_result
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF coalesce(hasura_session->>'x-hasura-role','')<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 UPDATE public.room_members m SET accepted_at=coalesce(m.accepted_at,now()) FROM public.messenger_groups g WHERE m.room_id=p_room_id AND g.room_id=m.room_id AND m.user_id=v_actor AND m.accepted_at IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Group invitation not found'; END IF;
 RETURN QUERY SELECT m.room_id,m.accepted_at FROM public.room_members m WHERE m.room_id=p_room_id AND m.user_id=v_actor AND m.accepted_at IS NOT NULL;
END; $fn$;

REVOKE ALL ON FUNCTION public.create_private_messenger_group(text,uuid[],json),public.my_messenger_groups(json),public.my_pending_group_invites(json),public.accept_messenger_group_invite(uuid,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_messenger_group(text,uuid[],json),public.my_messenger_groups(json),public.my_pending_group_invites(json),public.accept_messenger_group_invite(uuid,json) TO PUBLIC;
-- Track four functions in Hasura. Mark each hasura_session parameter as injected session argument.
-- Grant execution only to authenticated `user`; deny anonymous. Keep messenger_groups table untracked/default-deny.
-- Hasura default permissions must deny direct INSERT into public.rooms with room_type='private' and deny UPDATE/DELETE on those rooms; only group/owner-approved functions may create them. Configure private room/message SELECT and message INSERT predicates to require owner OR room_members row for session user with accepted_at IS NOT NULL. Restrict room_type to public/private and preset created_by/sender_id from session. Do not grant public-room permissions to private rooms.
-- Deny direct inserts into messenger_groups and room_members; only these checked SECURITY DEFINER functions may create membership.

-- Presence for Messenger. Last heartbeat expires after 45 s if the app closes/crashes/offline.
-- Apply only to Nhost Mensageiro project.
-- Hasura-trackable composite result views required for SETOF function returns.
CREATE TABLE IF NOT EXISTS public.my_friends_presence_result (
  user_id uuid,
  is_online boolean,
  last_seen timestamptz
);
CREATE TABLE IF NOT EXISTS public.my_presence_state_result (
  is_online boolean,
  last_seen timestamptz
);
CREATE TABLE IF NOT EXISTS public.set_my_presence_result (
  user_id uuid,
  last_seen timestamptz
);

CREATE TABLE IF NOT EXISTS public.messenger_presence (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messenger_presence_last_seen_idx ON public.messenger_presence(last_seen);

CREATE OR REPLACE FUNCTION public.set_my_presence(p_online boolean, hasura_session json)
RETURNS SETOF public.set_my_presence_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  IF p_online THEN
    INSERT INTO public.messenger_presence(user_id,last_seen) VALUES(v_actor,now())
      ON CONFLICT(user_id) DO UPDATE SET last_seen=now();
  ELSE
    DELETE FROM public.messenger_presence p WHERE p.user_id=v_actor;
  END IF;
  RETURN QUERY SELECT p.user_id,p.last_seen FROM public.messenger_presence p WHERE p.user_id=v_actor;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_presence_state(hasura_session json)
RETURNS SETOF public.my_presence_state_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT coalesce(p.last_seen > now()-interval '45 seconds',false),p.last_seen FROM (SELECT 1) x LEFT JOIN public.messenger_presence p ON p.user_id=v_actor;
END; $fn$;

CREATE OR REPLACE FUNCTION public.my_friends_presence(hasura_session json)
RETURNS SETOF public.my_friends_presence_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
  IF hasura_session->>'x-hasura-role' <> 'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
  v_actor := (hasura_session->>'x-hasura-user-id')::uuid;
  RETURN QUERY SELECT f.user_id,coalesce(p.last_seen>now()-interval '45 seconds',false),p.last_seen
  FROM public.messenger_friend_requests r
  CROSS JOIN LATERAL (SELECT CASE WHEN r.requester_id=v_actor THEN r.recipient_id ELSE r.requester_id END AS user_id) f
  LEFT JOIN public.messenger_presence p ON p.user_id=f.user_id
  WHERE r.status='accepted' AND (r.requester_id=v_actor OR r.recipient_id=v_actor)
  ORDER BY coalesce(p.last_seen>now()-interval '45 seconds',false) DESC;
END; $fn$;

REVOKE ALL ON FUNCTION public.set_my_presence(boolean,json),public.my_presence_state(json),public.my_friends_presence(json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_my_presence(boolean,json),public.my_presence_state(json),public.my_friends_presence(json) TO PUBLIC;
-- Track messenger_presence and all three functions in Hasura; mark hasura_session as session argument.
-- Grant function execute to authenticated role user only. No direct table access or anonymous execute.
-- No tracking of public profile or room membership outside these functions.

-- Unbounded-duration voice notes, stored in sequential chunks in the dedicated Mensageiro Nhost database.
-- Duration is not capped by the app. Device storage, network, and Nhost storage/GraphQL quotas still apply.
-- Hasura-trackable composite result views required for SETOF function returns.
CREATE TABLE IF NOT EXISTS public.get_private_room_audio_chunks_result (
  chunk_index integer,
  audio_data text
);
CREATE TABLE IF NOT EXISTS public.private_room_audio_message_ids_result (
  message_id uuid
);
CREATE TABLE IF NOT EXISTS public.complete_private_room_audio_result (
  message_id uuid,
  chunk_count integer
);
CREATE TABLE IF NOT EXISTS public.add_private_room_audio_chunk_result (
  chunk_index integer
);
CREATE TABLE IF NOT EXISTS public.create_private_room_audio_result (
  message_id uuid
);

CREATE TABLE IF NOT EXISTS public.message_audio_files (
  message_id uuid PRIMARY KEY REFERENCES public.messages(id) ON DELETE CASCADE,
  uploaded_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  chunk_count integer,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CONSTRAINT message_audio_chunk_count CHECK (chunk_count IS NULL OR chunk_count BETWEEN 1 AND 2147483647)
);
CREATE TABLE IF NOT EXISTS public.message_audio_chunks (
  message_id uuid NOT NULL REFERENCES public.message_audio_files(message_id) ON DELETE CASCADE,
  chunk_index integer NOT NULL CHECK (chunk_index >= 0),
  audio_data text NOT NULL CHECK (octet_length(audio_data) <= 180000 AND audio_data LIKE 'data:audio/mp4;base64,%'),
  PRIMARY KEY(message_id,chunk_index)
);

DROP TRIGGER IF EXISTS messenger_audio_file_gate ON public.message_audio_files;
CREATE TRIGGER messenger_audio_file_gate BEFORE INSERT OR UPDATE ON public.message_audio_files
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_attachment_write();
DROP TRIGGER IF EXISTS messenger_audio_chunk_gate ON public.message_audio_chunks;
CREATE TRIGGER messenger_audio_chunk_gate BEFORE INSERT ON public.message_audio_chunks
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_attachment_write();

CREATE OR REPLACE FUNCTION public.create_private_room_audio(p_room_id uuid,hasura_session json)
RETURNS SETOF public.create_private_room_audio_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_message uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Only accepted private-room members may send audio'; END IF;
 INSERT INTO public.messages(room_id,sender_id,body) VALUES(p_room_id,v_actor,'Mensagem de áudio') RETURNING id INTO v_message;
 INSERT INTO public.message_audio_files(message_id,uploaded_by) VALUES(v_message,v_actor);
 RETURN QUERY SELECT v_message;
END; $fn$;

CREATE OR REPLACE FUNCTION public.add_private_room_audio_chunk(p_message_id uuid,p_chunk_index integer,p_audio_data text,hasura_session json)
RETURNS SETOF public.add_private_room_audio_chunk_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_chunk_index<0 OR p_chunk_index>=2147483647 OR octet_length(p_audio_data)>180000 OR p_audio_data NOT LIKE 'data:audio/mp4;base64,%' OR substring(p_audio_data from length('data:audio/mp4;base64,')+1) !~ '^[A-Za-z0-9+/]*={0,2}$' THEN RAISE EXCEPTION 'Invalid audio chunk'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id JOIN public.rooms r ON r.id=m.room_id WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 INSERT INTO public.message_audio_chunks(message_id,chunk_index,audio_data) VALUES(p_message_id,p_chunk_index,p_audio_data);
 RETURN QUERY SELECT p_chunk_index;
END; $fn$;

CREATE OR REPLACE FUNCTION public.complete_private_room_audio(p_message_id uuid,p_chunk_count integer,hasura_session json)
RETURNS SETOF public.complete_private_room_audio_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_rows bigint; v_min integer; v_max integer;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_chunk_count NOT BETWEEN 1 AND 2147483647 THEN RAISE EXCEPTION 'Invalid audio'; END IF;
 SELECT count(*),min(c.chunk_index),max(c.chunk_index) INTO v_rows,v_min,v_max FROM public.message_audio_chunks c WHERE c.message_id=p_message_id;
 IF v_rows<>p_chunk_count OR v_min<>0 OR v_max<>p_chunk_count-1 THEN RAISE EXCEPTION 'Audio upload incomplete'; END IF;
 UPDATE public.message_audio_files f SET chunk_count=p_chunk_count,completed_at=now()
 WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL
 AND EXISTS(SELECT 1 FROM public.messages m WHERE m.id=f.message_id AND public.messenger_user_can_access_private_room(m.room_id,v_actor));
 IF NOT FOUND THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT p_message_id,p_chunk_count;
END; $fn$;

CREATE OR REPLACE FUNCTION public.private_room_audio_message_ids(p_room_id uuid,hasura_session json)
RETURNS SETOF public.private_room_audio_message_ids_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT f.message_id FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id WHERE m.room_id=p_room_id AND f.completed_at IS NOT NULL ORDER BY m.created_at;
END; $fn$;

CREATE OR REPLACE FUNCTION public.get_private_room_audio_chunks(p_message_id uuid,p_start_index integer,p_limit integer,hasura_session json)
RETURNS SETOF public.get_private_room_audio_chunks_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_start_index<0 OR p_limit<1 OR p_limit>4 THEN RAISE EXCEPTION 'Invalid range'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id JOIN public.rooms r ON r.id=m.room_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT c.chunk_index,c.audio_data FROM public.message_audio_chunks c WHERE c.message_id=p_message_id AND c.chunk_index>=p_start_index ORDER BY c.chunk_index LIMIT p_limit;
END; $fn$;

REVOKE ALL ON FUNCTION public.create_private_room_audio(uuid,json),public.add_private_room_audio_chunk(uuid,integer,text,json),public.complete_private_room_audio(uuid,integer,json),public.private_room_audio_message_ids(uuid,json),public.get_private_room_audio_chunks(uuid,integer,integer,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_room_audio(uuid,json),public.add_private_room_audio_chunk(uuid,integer,text,json),public.complete_private_room_audio(uuid,integer,json),public.private_room_audio_message_ids(uuid,json),public.get_private_room_audio_chunks(uuid,integer,integer,json) TO PUBLIC;
-- Track functions in Hasura, mark hasura_session as injected session argument. Grant execute only to authenticated role `user`.
-- This attachment feature is private-room only; it does not change normal public-room message read/write behavior.
-- Do not grant anonymous access or direct CRUD on either audio table. The app never sees any admin secret.

-- Private-room photo/video attachments stored in ordered chunks; only authenticated users may use functions.
-- Hasura-trackable composite result views required for SETOF function returns.
CREATE TABLE IF NOT EXISTS public.get_private_room_media_chunks_result (
  chunk_index integer,
  media_data text
);
CREATE TABLE IF NOT EXISTS public.private_room_media_info_result (
  mime_type text,
  chunk_count integer
);
CREATE TABLE IF NOT EXISTS public.private_room_media_message_ids_result (
  message_id uuid,
  mime_type text
);
CREATE TABLE IF NOT EXISTS public.complete_private_room_media_result (
  message_id uuid
);
CREATE TABLE IF NOT EXISTS public.add_private_room_media_chunk_result (
  chunk_index integer
);
CREATE TABLE IF NOT EXISTS public.create_private_room_media_result (
  message_id uuid
);

CREATE TABLE IF NOT EXISTS public.message_media_files (
 message_id uuid PRIMARY KEY REFERENCES public.messages(id) ON DELETE CASCADE,
 uploaded_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 mime_type text NOT NULL CHECK (mime_type IN ('image/jpeg','video/mp4')),
 chunk_count integer,
 created_at timestamptz NOT NULL DEFAULT now(),
 completed_at timestamptz,
 CONSTRAINT message_media_count CHECK (chunk_count IS NULL OR chunk_count BETWEEN 1 AND 2147483647)
);
CREATE TABLE IF NOT EXISTS public.message_media_chunks (
 message_id uuid NOT NULL REFERENCES public.message_media_files(message_id) ON DELETE CASCADE,
 chunk_index integer NOT NULL CHECK(chunk_index>=0),
 media_data text NOT NULL CHECK(octet_length(media_data)<=180000),
 PRIMARY KEY(message_id,chunk_index)
);

DROP TRIGGER IF EXISTS messenger_media_file_gate ON public.message_media_files;
CREATE TRIGGER messenger_media_file_gate BEFORE INSERT OR UPDATE ON public.message_media_files
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_attachment_write();
DROP TRIGGER IF EXISTS messenger_media_chunk_gate ON public.message_media_chunks;
CREATE TRIGGER messenger_media_chunk_gate BEFORE INSERT ON public.message_media_chunks
FOR EACH ROW EXECUTE FUNCTION public.enforce_messenger_attachment_write();

CREATE OR REPLACE FUNCTION public.create_private_room_media(p_room_id uuid,p_mime_type text,hasura_session json)
RETURNS SETOF public.create_private_room_media_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_id uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Only accepted private-room members may send media'; END IF;
 IF p_mime_type NOT IN ('image/jpeg','video/mp4') THEN RAISE EXCEPTION 'Invalid media'; END IF;
 INSERT INTO public.messages(room_id,sender_id,body) VALUES(p_room_id,v_actor,CASE WHEN p_mime_type='image/jpeg' THEN 'Foto' ELSE 'Vídeo' END) RETURNING id INTO v_id;
 INSERT INTO public.message_media_files(message_id,uploaded_by,mime_type) VALUES(v_id,v_actor,p_mime_type);
 RETURN QUERY SELECT v_id;
END; $fn$;

CREATE OR REPLACE FUNCTION public.add_private_room_media_chunk(p_message_id uuid,p_chunk_index integer,p_mime_type text,p_media_data text,hasura_session json)
RETURNS SETOF public.add_private_room_media_chunk_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_expected text;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_mime_type NOT IN ('image/jpeg','video/mp4') OR p_chunk_index<0 OR octet_length(p_media_data)>180000 OR p_media_data NOT LIKE ('data:'||p_mime_type||';base64,%') OR substring(p_media_data from length('data:'||p_mime_type||';base64,')+1) !~ '^[A-Za-z0-9+/]*={0,2}$' THEN RAISE EXCEPTION 'Invalid media'; END IF;
 SELECT f.mime_type INTO v_expected FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id JOIN public.rooms r ON r.id=m.room_id WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor) FOR UPDATE OF f;
 IF NOT FOUND THEN RAISE EXCEPTION 'Not authorized'; END IF;
 IF v_expected<>p_mime_type THEN RAISE EXCEPTION 'MIME mismatch'; END IF;
 INSERT INTO public.message_media_chunks(message_id,chunk_index,media_data) VALUES(p_message_id,p_chunk_index,p_media_data);
 RETURN QUERY SELECT p_chunk_index;
END; $fn$;

CREATE OR REPLACE FUNCTION public.complete_private_room_media(p_message_id uuid,p_chunk_count integer,hasura_session json)
RETURNS SETOF public.complete_private_room_media_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_count bigint; v_min integer; v_max integer;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_chunk_count<1 THEN RAISE EXCEPTION 'Invalid count'; END IF;
 SELECT count(*),min(c.chunk_index),max(c.chunk_index) INTO v_count,v_min,v_max FROM public.message_media_chunks c WHERE c.message_id=p_message_id;
 IF v_count<>p_chunk_count OR v_min<>0 OR v_max<>p_chunk_count-1 THEN RAISE EXCEPTION 'Upload incomplete'; END IF;
 UPDATE public.message_media_files f SET chunk_count=p_chunk_count,completed_at=now() WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND EXISTS(SELECT 1 FROM public.messages m WHERE m.id=f.message_id AND public.messenger_user_can_access_private_room(m.room_id,v_actor));
 IF NOT FOUND THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT p_message_id;
END; $fn$;

CREATE OR REPLACE FUNCTION public.private_room_media_message_ids(p_room_id uuid,hasura_session json)
RETURNS SETOF public.private_room_media_message_ids_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT f.message_id,f.mime_type FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id WHERE m.room_id=p_room_id AND f.completed_at IS NOT NULL ORDER BY m.created_at;
END; $fn$;

CREATE OR REPLACE FUNCTION public.private_room_media_info(p_message_id uuid,hasura_session json)
RETURNS SETOF public.private_room_media_info_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT f.mime_type,f.chunk_count FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id JOIN public.rooms r ON r.id=m.room_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor);
END; $fn$;

CREATE OR REPLACE FUNCTION public.get_private_room_media_chunks(p_message_id uuid,p_start_index integer,p_limit integer,hasura_session json)
RETURNS SETOF public.get_private_room_media_chunks_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_start_index<0 OR p_limit<1 OR p_limit>4 THEN RAISE EXCEPTION 'Invalid range'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id JOIN public.rooms r ON r.id=m.room_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT c.chunk_index,c.media_data FROM public.message_media_chunks c WHERE c.message_id=p_message_id AND c.chunk_index>=p_start_index ORDER BY c.chunk_index LIMIT p_limit;
END; $fn$;

REVOKE ALL ON FUNCTION public.create_private_room_media(uuid,text,json),public.add_private_room_media_chunk(uuid,integer,text,text,json),public.complete_private_room_media(uuid,integer,json),public.private_room_media_message_ids(uuid,json),public.private_room_media_info(uuid,json),public.get_private_room_media_chunks(uuid,integer,integer,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_room_media(uuid,text,json),public.add_private_room_media_chunk(uuid,integer,text,text,json),public.complete_private_room_media(uuid,integer,json),public.private_room_media_message_ids(uuid,json),public.private_room_media_info(uuid,json),public.get_private_room_media_chunks(uuid,integer,integer,json) TO PUBLIC;
-- Track functions in Hasura, mark hasura_session as injected, grant execute only to authenticated `user` role. No direct CRUD on media tables.
-- Requires messenger_user_can_access_private_room helper; does not alter normal public-room read/write behavior.

-- Shared per-room chat wallpaper metadata/content for the Mensageiro Nhost project.
-- No files are stored on the server bucket: a compressed JPEG data URI is stored in this table.
-- Hasura permissions are mandatory before the client feature can work. See ROOM_WALLPAPER.md.
CREATE TABLE IF NOT EXISTS public.room_wallpapers (
  room_id uuid PRIMARY KEY REFERENCES public.rooms(id) ON DELETE CASCADE,
  wallpaper_data text NOT NULL,
  updated_by uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT room_wallpapers_data_size CHECK (octet_length(wallpaper_data) <= 550000),
  CONSTRAINT room_wallpapers_data_type CHECK (wallpaper_data LIKE 'data:image/jpeg;base64,%')
);
CREATE INDEX IF NOT EXISTS room_wallpapers_updated_at_idx ON public.room_wallpapers(updated_at);

CREATE OR REPLACE FUNCTION public.set_room_wallpaper_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;

DROP TRIGGER IF EXISTS room_wallpapers_set_updated_at ON public.room_wallpapers;
CREATE TRIGGER room_wallpapers_set_updated_at
BEFORE UPDATE ON public.room_wallpapers
FOR EACH ROW EXECUTE FUNCTION public.set_room_wallpaper_updated_at();

DO $test$
DECLARE
 owner_id uuid := '27a5eca4-18d2-4a67-9a34-3e075317740b';
 member_id uuid := '40000000-0000-0000-0000-000000000002';
 pending_id uuid := '40000000-0000-0000-0000-000000000003';
 rid uuid; gid uuid; audio_id uuid; media_id uuid; n integer; grp record;
 session_owner json := '{"x-hasura-role":"user","x-hasura-user-id":"27a5eca4-18d2-4a67-9a34-3e075317740b"}';
 session_member json := '{"x-hasura-role":"user","x-hasura-user-id":"40000000-0000-0000-0000-000000000002"}';
 session_pending json := '{"x-hasura-role":"user","x-hasura-user-id":"40000000-0000-0000-0000-000000000003"}';
BEGIN
 INSERT INTO public.messenger_profiles(user_id,display_name) SELECT id,'Test user' FROM auth.users ON CONFLICT(user_id) DO NOTHING;
 INSERT INTO public.messenger_friend_requests(requester_id,recipient_id,status) VALUES(owner_id,member_id,'accepted'),(owner_id,pending_id,'accepted') ON CONFLICT(requester_id,recipient_id) DO UPDATE SET status='accepted';
 PERFORM set_config('hasura.user',session_owner::text,true);
 INSERT INTO public.rooms(title,room_type,created_by) VALUES('Full SQL private test','private',owner_id) RETURNING id INTO rid;
 INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES(rid,owner_id,owner_id,now());
 IF NOT public.messenger_user_can_access_private_room(rid,owner_id) THEN RAISE EXCEPTION 'owner authorization failed'; END IF;
 IF public.messenger_user_can_access_private_room(rid,member_id) THEN RAISE EXCEPTION 'unaccepted user authorized'; END IF;
 PERFORM * FROM public.invite_room_member_by_email(rid,'member@example.test',session_owner);
 PERFORM * FROM public.invite_room_member_by_email(rid,'member@example.test',session_owner);
 SELECT count(*) INTO n FROM public.room_members WHERE room_id=rid AND user_id=member_id AND accepted_at IS NULL;
 IF n<>1 THEN RAISE EXCEPTION 'invite idempotency failed'; END IF;
 PERFORM set_config('hasura.user',session_member::text,true);
 PERFORM * FROM public.accept_private_room_invite(rid,session_member);
 IF NOT public.messenger_user_can_access_private_room(rid,member_id) THEN RAISE EXCEPTION 'accepted membership not authorized'; END IF;
 PERFORM * FROM public.upsert_my_profile('Member Test',NULL,session_member);
 PERFORM * FROM public.request_friend_by_email('pending@example.test',session_owner);
 PERFORM * FROM public.set_my_presence(true,session_member);
 PERFORM * FROM public.my_presence_state(session_member);
 PERFORM * FROM public.my_friends_presence(session_member);
 SELECT message_id INTO audio_id FROM public.create_private_room_audio(rid,session_member);
 PERFORM * FROM public.add_private_room_audio_chunk(audio_id,0,'data:audio/mp4;base64,QUJD',session_member);
 BEGIN
   PERFORM * FROM public.complete_private_room_audio(audio_id,2,session_member);
   RAISE EXCEPTION 'audio missing chunk unexpectedly completed';
 EXCEPTION WHEN raise_exception THEN IF SQLERRM='audio missing chunk unexpectedly completed' THEN RAISE; END IF;
 END;
 PERFORM * FROM public.add_private_room_audio_chunk(audio_id,1,'data:audio/mp4;base64,REVG',session_member);
 PERFORM * FROM public.complete_private_room_audio(audio_id,2,session_member);
 SELECT count(*) INTO n FROM public.get_private_room_audio_chunks(audio_id,0,1,session_member);
 IF n<>1 THEN RAISE EXCEPTION 'audio page 0 failed'; END IF;
 SELECT count(*) INTO n FROM public.get_private_room_audio_chunks(audio_id,1,1,session_member);
 IF n<>1 THEN RAISE EXCEPTION 'audio page 1 failed'; END IF;
 SELECT message_id INTO media_id FROM public.create_private_room_media(rid,'image/jpeg',session_member);
 PERFORM * FROM public.add_private_room_media_chunk(media_id,0,'image/jpeg','data:image/jpeg;base64,QUJD',session_member);
 PERFORM * FROM public.add_private_room_media_chunk(media_id,2,'image/jpeg','data:image/jpeg;base64,SElK',session_member);
 BEGIN
   PERFORM * FROM public.complete_private_room_media(media_id,3,session_member);
   RAISE EXCEPTION 'media gap unexpectedly completed';
 EXCEPTION WHEN raise_exception THEN IF SQLERRM='media gap unexpectedly completed' THEN RAISE; END IF;
 END;
 PERFORM * FROM public.add_private_room_media_chunk(media_id,1,'image/jpeg','data:image/jpeg;base64,REVG',session_member);
 PERFORM * FROM public.complete_private_room_media(media_id,3,session_member);
 SELECT count(*) INTO n FROM public.get_private_room_media_chunks(media_id,0,1,session_member);
 IF n<>1 THEN RAISE EXCEPTION 'media first page failed'; END IF;
 SELECT count(*) INTO n FROM public.get_private_room_media_chunks(media_id,1,2,session_member);
 IF n<>2 THEN RAISE EXCEPTION 'media second page failed'; END IF;
 SELECT count(*) INTO n FROM public.get_private_room_media_chunks(media_id,3,1,session_member);
 IF n<>0 THEN RAISE EXCEPTION 'media page after end not empty'; END IF;
 PERFORM set_config('hasura.user',session_owner::text,true);
 SELECT * INTO grp FROM public.create_private_messenger_group('Full SQL group test',ARRAY[pending_id]::uuid[],session_owner);
 gid:=grp.room_id;
 PERFORM set_config('hasura.user',session_pending::text,true);
 PERFORM * FROM public.accept_messenger_group_invite(gid,session_pending);
 IF NOT public.messenger_user_can_access_private_room(gid,pending_id) THEN RAISE EXCEPTION 'group accepted membership denied'; END IF;
 PERFORM set_config('hasura.user',session_owner::text,true);
 PERFORM * FROM public.set_messenger_bot_enabled(false,session_owner);
 SELECT count(*) INTO n FROM public.messenger_bot_status(session_owner) WHERE enabled=false;
 IF n<>1 THEN RAISE EXCEPTION 'Bot switch not off'; END IF;
 RAISE NOTICE 'PASS full SQL functions, invite/idempotence, membership, profiles/friends/presence, media completeness/pagination, groups, Bot OFF';
END;
$test$;
