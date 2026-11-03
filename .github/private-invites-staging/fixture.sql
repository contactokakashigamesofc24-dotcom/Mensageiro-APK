CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA auth;
CREATE TABLE auth.users(id uuid PRIMARY KEY,email text UNIQUE NOT NULL,email_verified boolean NOT NULL DEFAULT true);
INSERT INTO auth.users(id,email) VALUES
('40000000-0000-0000-0000-000000000001','owner@example.test'),
('40000000-0000-0000-0000-000000000002','accepted@example.test'),
('40000000-0000-0000-0000-000000000003','pending@example.test'),
('40000000-0000-0000-0000-000000000004','outsider@example.test');
CREATE TABLE public.rooms(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),title text NOT NULL,room_type text NOT NULL CHECK(room_type IN ('public','private')),created_by uuid NOT NULL REFERENCES auth.users(id),created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.room_members(room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,user_id uuid NOT NULL,invited_by uuid,accepted_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(room_id,user_id));
CREATE TABLE public.messenger_profiles(user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,display_name text NOT NULL);
CREATE TABLE public.messenger_friend_requests(request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),requester_id uuid NOT NULL REFERENCES auth.users(id),recipient_id uuid NOT NULL REFERENCES auth.users(id),status text NOT NULL CHECK(status IN ('pending','accepted','declined')),UNIQUE(requester_id,recipient_id));
CREATE TABLE public.messages(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),room_id uuid NOT NULL REFERENCES public.rooms(id),sender_id uuid NOT NULL,body text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
-- Hasura custom SQL functions must return SETOF a tracked table; these typed result tables are tracked only in this ephemeral test.
CREATE TABLE public.private_invite_results(invitee_id uuid NOT NULL,room_id uuid NOT NULL,room_title text NOT NULL,inviter_id uuid NOT NULL,invited_at timestamptz NOT NULL);
CREATE TABLE public.private_accepted_room_results(member_id uuid NOT NULL,room_id uuid NOT NULL,room_title text NOT NULL,owner_id uuid NOT NULL,joined_at timestamptz NOT NULL);
CREATE TABLE public.private_owner_member_results(owner_id uuid NOT NULL,room_id uuid NOT NULL,user_id uuid NOT NULL,invited_by uuid,accepted_at timestamptz,invited_at timestamptz NOT NULL);
INSERT INTO public.messenger_profiles(user_id,display_name) SELECT id,'Synthetic profile' FROM auth.users;
INSERT INTO public.messenger_friend_requests(requester_id,recipient_id,status) VALUES
('40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002','accepted'),
('40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000003','accepted'),
('40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000004','accepted');
INSERT INTO public.rooms(id,title,room_type,created_by) VALUES
('10000000-0000-0000-0000-000000000001','Synthetic existing private room','private','40000000-0000-0000-0000-000000000001'),
('10000000-0000-0000-0000-000000000003','Synthetic second private room','private','40000000-0000-0000-0000-000000000001'),
('10000000-0000-0000-0000-000000000002','Synthetic public room','public','40000000-0000-0000-0000-000000000004');
INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001',now()),
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001',now());
INSERT INTO public.messages(room_id,sender_id,body) VALUES
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','Synthetic private owner message'),
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002','Synthetic private member message'),
('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000004','Synthetic public message');
