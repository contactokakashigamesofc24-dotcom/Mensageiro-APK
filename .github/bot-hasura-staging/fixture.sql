CREATE TABLE public.rooms (
  id uuid PRIMARY KEY,
  title text NOT NULL,
  room_type text NOT NULL CHECK (room_type IN ('public','private'))
);

CREATE TABLE public.bot_room_allowlist (
  room_id uuid PRIMARY KEY REFERENCES public.rooms(id) ON DELETE CASCADE,
  bot_user_id uuid NOT NULL
);

CREATE TABLE public.messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  room_id uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  sender_id uuid NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.rooms(id,title,room_type) VALUES
('10000000-0000-0000-0000-000000000001','Fictitious selected public room','public'),
('10000000-0000-0000-0000-000000000002','Fictitious unselected public room','public'),
('10000000-0000-0000-0000-000000000003','Fictitious private room','private');

INSERT INTO public.bot_room_allowlist(room_id,bot_user_id) VALUES
('10000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001');
