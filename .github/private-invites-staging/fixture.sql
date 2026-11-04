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
CREATE TABLE public.messenger_profiles(user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,display_name text NOT NULL,avatar_data text,updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.messenger_friend_requests(request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),requester_id uuid NOT NULL REFERENCES auth.users(id),recipient_id uuid NOT NULL REFERENCES auth.users(id),status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),created_at timestamptz NOT NULL DEFAULT now(),responded_at timestamptz,UNIQUE(requester_id,recipient_id));
CREATE TABLE public.messenger_presence(user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,last_seen timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.messages(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),room_id uuid NOT NULL REFERENCES public.rooms(id),sender_id uuid NOT NULL,body text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE public.messenger_groups(room_id uuid PRIMARY KEY REFERENCES public.rooms(id) ON DELETE CASCADE,owner_id uuid NOT NULL REFERENCES auth.users(id),created_at timestamptz NOT NULL DEFAULT now());
CREATE VIEW public.group_result AS SELECT g.room_id,r.title AS group_title,g.owner_id,g.created_at FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id WHERE r.room_type='private';
CREATE VIEW public.group_invite_result AS SELECT g.room_id,r.title AS group_title,m.invited_by AS inviter_id,m.created_at AS invited_at,m.user_id AS invitee_id FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id WHERE r.room_type='private' AND m.accepted_at IS NULL;
CREATE VIEW public.group_member_result AS SELECT g.room_id,r.title AS group_title,g.owner_id,m.user_id AS member_id,m.accepted_at FROM public.messenger_groups g JOIN public.rooms r ON r.id=g.room_id JOIN public.room_members m ON m.room_id=g.room_id WHERE r.room_type='private' AND m.accepted_at IS NOT NULL;
CREATE VIEW public.friend_request_result AS SELECT request_id,status FROM public.messenger_friend_requests;
CREATE VIEW public.friend_profile_result AS SELECT f.viewer_id,p.user_id,p.display_name,p.avatar_data FROM public.messenger_profiles p JOIN (SELECT requester_id AS viewer_id,recipient_id AS friend_id FROM public.messenger_friend_requests WHERE status='accepted' UNION ALL SELECT recipient_id,requester_id FROM public.messenger_friend_requests WHERE status='accepted') f ON f.friend_id=p.user_id;
CREATE VIEW public.incoming_friend_result AS SELECT r.recipient_id AS viewer_id,r.request_id,p.user_id,p.display_name,p.avatar_data FROM public.messenger_friend_requests r JOIN public.messenger_profiles p ON p.user_id=r.requester_id WHERE r.status='pending';
CREATE VIEW public.presence_result AS SELECT p.user_id,p.last_seen FROM public.messenger_presence p;
CREATE VIEW public.friend_presence_result AS SELECT f.requester_id AS user_id,false AS is_online,NULL::timestamptz AS last_seen FROM public.messenger_friend_requests f WHERE f.status='accepted';
-- Read-only views provide Hasura-trackable composite return types for synthetic list functions.
CREATE VIEW public.private_invite_results AS SELECT m.user_id AS invitee_id,r.id AS room_id,r.title AS room_title,m.invited_by AS inviter_id,m.created_at AS invited_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.accepted_at IS NULL AND r.room_type='private';
CREATE VIEW public.private_accepted_room_results AS SELECT m.user_id AS member_id,r.id AS room_id,r.title AS room_title,r.created_by AS owner_id,m.accepted_at AS joined_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE m.accepted_at IS NOT NULL AND r.room_type='private';
CREATE VIEW public.private_owner_member_results AS SELECT r.created_by AS owner_id,r.id AS room_id,m.user_id,m.invited_by,m.accepted_at,m.created_at AS invited_at FROM public.room_members m JOIN public.rooms r ON r.id=m.room_id WHERE r.room_type='private';
CREATE VIEW public.private_room_results AS SELECT r.id,r.title,r.room_type,r.created_by,r.created_at FROM public.rooms r WHERE r.room_type='private';
CREATE VIEW public.message_result AS SELECT m.id,m.sender_id FROM public.messages m;
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
