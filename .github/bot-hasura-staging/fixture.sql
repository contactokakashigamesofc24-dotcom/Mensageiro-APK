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
  bot_settings_id uuid NOT NULL DEFAULT '30000000-0000-0000-0000-000000000001' REFERENCES public.bot_settings(id)
);

CREATE TABLE public.room_members (
  room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  PRIMARY KEY (room_id,user_id)
);

CREATE TABLE public.messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Fake rooms: public, private, and rooms created after the Bot rule was defined.
INSERT INTO public.rooms(id,title,room_type) VALUES
('10000000-0000-0000-0000-000000000001','Synthetic public room','public'),
('10000000-0000-0000-0000-000000000002','Synthetic private room','private'),
('10000000-0000-0000-0000-000000000003','Synthetic newly-created public room','public'),
('10000000-0000-0000-0000-000000000004','Synthetic newly-created private room','private');

-- Only the fake human user is a member of the first private room.
INSERT INTO public.room_members(room_id,user_id) VALUES
('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001');

INSERT INTO public.messages(room_id,sender_id,body) VALUES
('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001','Synthetic public message'),
('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001','Synthetic private message'),
('10000000-0000-0000-0000-000000000003','40000000-0000-0000-0000-000000000001','Synthetic new-public-room message'),
('10000000-0000-0000-0000-000000000004','40000000-0000-0000-0000-000000000001','Synthetic new-private-room message');
