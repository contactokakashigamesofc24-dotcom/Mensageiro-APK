CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE public.bot_settings (
  id uuid PRIMARY KEY,
  enabled boolean NOT NULL DEFAULT false,
  scope text NOT NULL DEFAULT 'all_rooms' CHECK (scope='all_rooms')
);
INSERT INTO public.bot_settings(id,enabled,scope) VALUES
('30000000-0000-0000-0000-000000000001',true,'all_rooms');

CREATE TABLE public.rooms (
  id uuid PRIMARY KEY,
  title text NOT NULL,
  room_type text NOT NULL CHECK (room_type IN ('public','private')),
  created_by uuid NOT NULL,
  bot_settings_id uuid NOT NULL DEFAULT '30000000-0000-0000-0000-000000000001' REFERENCES public.bot_settings(id)
);

CREATE TABLE public.room_members (
  room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  invited_by uuid,
  accepted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (room_id,user_id)
);

CREATE TABLE public.messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.rooms(id,title,room_type,created_by) VALUES
('10000000-0000-0000-0000-000000000001','Synthetic public room','public','40000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000002','Synthetic private room owned by user','private','40000000-0000-0000-0000-000000000001'),
('10000000-0000-0000-0000-000000000003','Synthetic public room created after policy','public','40000000-0000-0000-0000-000000000002'),
('10000000-0000-0000-0000-000000000004','Synthetic private room created after policy','private','40000000-0000-0000-0000-000000000002');

-- The sample user is listed as invited/member of a private room they did not create,
-- but current exported Hasura message filters do not use this table for message access.
INSERT INTO public.room_members(room_id,user_id,invited_by,accepted_at) VALUES
('10000000-0000-0000-0000-000000000004','40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002',now());

INSERT INTO public.messages(room_id,sender_id,body) VALUES
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002','Synthetic public message'),
('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001','Synthetic private message created by user'),
('10000000-0000-0000-0000-000000000003','40000000-0000-0000-0000-000000000002','Synthetic new-public-room message'),
('10000000-0000-0000-0000-000000000004','40000000-0000-0000-0000-000000000002','Synthetic private message in room where user is member but not creator');
