CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA auth;
CREATE TABLE auth.users(id uuid PRIMARY KEY,email text UNIQUE NOT NULL,email_verified boolean NOT NULL DEFAULT true);
INSERT INTO auth.users(id,email,email_verified) VALUES
('40000000-0000-0000-0000-000000000001','owner@example.test',true),
('40000000-0000-0000-0000-000000000002','accepted@example.test',true),
('40000000-0000-0000-0000-000000000003','pending@example.test',true),
('40000000-0000-0000-0000-000000000004','outsider@example.test',true),
('40000000-0000-0000-0000-000000000005','unverified@example.test',false),
('40000000-0000-0000-0000-000000000006','notfriend@example.test',true);
CREATE TABLE public.rooms(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),title text NOT NULL,room_type text NOT NULL CHECK(room_type IN ('public','private')),created_by uuid NOT NULL REFERENCES auth.users(id),created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.room_members(room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,user_id uuid NOT NULL,invited_by uuid,accepted_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(room_id,user_id));
CREATE TABLE public.messenger_profiles(user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,display_name text NOT NULL);
CREATE TABLE public.messenger_friend_requests(request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),requester_id uuid NOT NULL REFERENCES auth.users(id),recipient_id uuid NOT NULL REFERENCES auth.users(id),status text NOT NULL CHECK(status IN ('pending','accepted','declined')),UNIQUE(requester_id,recipient_id));
CREATE TABLE public.messages(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),room_id uuid NOT NULL REFERENCES public.rooms(id),sender_id uuid NOT NULL,body text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
-- Read-only views provide Hasura-trackable composite return types for synthetic list functions.
CREATE VIEW public.private_invite_results AS SELECT m.user_id AS invitee_id,r.id AS room_id,r.title AS room_title,m.invited_by AS inviter_id,m.created_at AS invited_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.accepted_at IS NULL AND r.room_type='private';
CREATE VIEW public.private_accepted_room_results AS SELECT m.user_id AS member_id,r.id AS room_id,r.title AS room_title,r.created_by AS owner_id,m.accepted_at AS joined_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.accepted_at IS NOT NULL AND r.room_type='private';
CREATE VIEW public.private_owner_member_results AS SELECT r.created_by AS owner_id,r.id AS room_id,m.user_id,m.invited_by,m.accepted_at,m.created_at AS invited_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE r.room_type='private';
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
