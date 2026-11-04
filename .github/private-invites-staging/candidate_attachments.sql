-- Synthetic-only simplified attachment candidates. Mirrors APK GraphQL names, not production SQL.
CREATE OR REPLACE FUNCTION public.create_private_room_audio(p_room_id uuid,hasura_session json)
RETURNS SETOF public.audio_create_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_id uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 INSERT INTO public.messages(room_id,sender_id,body) VALUES(p_room_id,v_actor,'Audio') RETURNING id INTO v_id;
 INSERT INTO public.message_audio_files(message_id,uploaded_by) VALUES(v_id,v_actor);
 RETURN QUERY SELECT v_id;
END;$fn$;
CREATE OR REPLACE FUNCTION public.add_private_room_audio_chunk(p_message_id uuid,p_chunk_index integer,p_audio_data text,hasura_session json)
RETURNS SETOF public.audio_chunk_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF p_chunk_index<0 OR octet_length(p_audio_data)>180000 OR p_audio_data NOT LIKE 'data:audio/mp4;base64,%' THEN RAISE EXCEPTION 'Invalid audio chunk'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 INSERT INTO public.message_audio_chunks(message_id,chunk_index,audio_data) VALUES(p_message_id,p_chunk_index,p_audio_data);
 RETURN QUERY SELECT p_message_id,p_chunk_index,p_audio_data;
END;$fn$;
CREATE OR REPLACE FUNCTION public.complete_private_room_audio(p_message_id uuid,p_chunk_count integer,hasura_session json)
RETURNS SETOF public.audio_complete_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_count bigint; v_min integer; v_max integer;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF;
 v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 SELECT count(*),min(chunk_index),max(chunk_index) INTO v_count,v_min,v_max FROM public.message_audio_chunks WHERE message_id=p_message_id;
 IF p_chunk_count<1 OR v_count<>p_chunk_count OR v_min<>0 OR v_max<>p_chunk_count-1 THEN RAISE EXCEPTION 'Audio upload incomplete'; END IF;
 UPDATE public.message_audio_files f SET chunk_count=p_chunk_count,completed_at=now() FROM public.messages m WHERE f.message_id=p_message_id AND m.id=f.message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor);
 IF NOT FOUND THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT p_message_id,p_chunk_count;
END;$fn$;
CREATE OR REPLACE FUNCTION public.private_room_audio_message_ids(p_room_id uuid,hasura_session json)
RETURNS SETOF public.audio_id_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT f.message_id FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id WHERE m.room_id=p_room_id AND f.completed_at IS NOT NULL;
END;$fn$;
CREATE OR REPLACE FUNCTION public.get_private_room_audio_chunks(p_message_id uuid,p_start_index integer,p_limit integer,hasura_session json)
RETURNS SETOF public.audio_chunk_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' OR p_start_index<0 OR p_limit<1 OR p_limit>4 THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT EXISTS(SELECT 1 FROM public.message_audio_files f JOIN public.messages m ON m.id=f.message_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT c.message_id,c.chunk_index,c.audio_data FROM public.message_audio_chunks c WHERE c.message_id=p_message_id AND c.chunk_index>=p_start_index ORDER BY c.chunk_index LIMIT p_limit;
END;$fn$;
CREATE OR REPLACE FUNCTION public.create_private_room_media(p_room_id uuid,p_mime_type text,hasura_session json)
RETURNS SETOF public.media_create_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_id uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' OR p_mime_type NOT IN ('image/jpeg','video/mp4') THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 INSERT INTO public.messages(room_id,sender_id,body) VALUES(p_room_id,v_actor,CASE WHEN p_mime_type='image/jpeg' THEN 'Foto' ELSE 'Vídeo' END) RETURNING id INTO v_id;
 INSERT INTO public.message_media_files(message_id,uploaded_by,mime_type) VALUES(v_id,v_actor,p_mime_type);
 RETURN QUERY SELECT v_id;
END;$fn$;
CREATE OR REPLACE FUNCTION public.add_private_room_media_chunk(p_message_id uuid,p_chunk_index integer,p_mime_type text,p_media_data text,hasura_session json)
RETURNS SETOF public.media_chunk_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_expected text;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' OR p_mime_type NOT IN ('image/jpeg','video/mp4') OR p_chunk_index<0 OR octet_length(p_media_data)>180000 OR p_media_data NOT LIKE ('data:'||p_mime_type||';base64,%') THEN RAISE EXCEPTION 'Invalid media'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 SELECT f.mime_type INTO v_expected FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id WHERE f.message_id=p_message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor);
 IF NOT FOUND OR v_expected<>p_mime_type THEN RAISE EXCEPTION 'Not authorized'; END IF;
 INSERT INTO public.message_media_chunks(message_id,chunk_index,media_data) VALUES(p_message_id,p_chunk_index,p_media_data);
 RETURN QUERY SELECT p_message_id,p_chunk_index,p_mime_type,p_media_data;
END;$fn$;
CREATE OR REPLACE FUNCTION public.complete_private_room_media(p_message_id uuid,p_chunk_count integer,hasura_session json)
RETURNS SETOF public.media_complete_result LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid; v_count bigint; v_min integer; v_max integer;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 SELECT count(*),min(chunk_index),max(chunk_index) INTO v_count,v_min,v_max FROM public.message_media_chunks WHERE message_id=p_message_id;
 IF p_chunk_count<1 OR v_count<>p_chunk_count OR v_min<>0 OR v_max<>p_chunk_count-1 THEN RAISE EXCEPTION 'Media upload incomplete'; END IF;
 UPDATE public.message_media_files f SET chunk_count=p_chunk_count,completed_at=now() FROM public.messages m WHERE f.message_id=p_message_id AND m.id=f.message_id AND f.uploaded_by=v_actor AND f.completed_at IS NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor);
 IF NOT FOUND THEN RAISE EXCEPTION 'Not authorized'; END IF; RETURN QUERY SELECT p_message_id;
END;$fn$;
CREATE OR REPLACE FUNCTION public.private_room_media_message_ids(p_room_id uuid,hasura_session json)
RETURNS SETOF public.media_id_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT public.messenger_user_can_access_private_room(p_room_id,v_actor) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT f.message_id,f.mime_type FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id WHERE m.room_id=p_room_id AND f.completed_at IS NOT NULL;
END;$fn$;
CREATE OR REPLACE FUNCTION public.private_room_media_info(p_message_id uuid,hasura_session json)
RETURNS SETOF public.media_info_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 RETURN QUERY SELECT f.mime_type,f.chunk_count FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor);
END;$fn$;
CREATE OR REPLACE FUNCTION public.get_private_room_media_chunks(p_message_id uuid,p_start_index integer,p_limit integer,hasura_session json)
RETURNS SETOF public.media_chunk_result LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,auth AS $fn$
DECLARE v_actor uuid;
BEGIN
 IF hasura_session->>'x-hasura-role'<>'user' OR coalesce(hasura_session->>'x-hasura-user-id','') !~* '^[0-9a-f-]{36}$' OR p_start_index<0 OR p_limit<1 OR p_limit>4 THEN RAISE EXCEPTION 'Not authorized'; END IF; v_actor:=(hasura_session->>'x-hasura-user-id')::uuid;
 IF NOT EXISTS(SELECT 1 FROM public.message_media_files f JOIN public.messages m ON m.id=f.message_id WHERE f.message_id=p_message_id AND f.completed_at IS NOT NULL AND public.messenger_user_can_access_private_room(m.room_id,v_actor)) THEN RAISE EXCEPTION 'Not authorized'; END IF;
 RETURN QUERY SELECT c.message_id,c.chunk_index,f.mime_type,c.media_data FROM public.message_media_chunks c JOIN public.message_media_files f ON f.message_id=c.message_id WHERE c.message_id=p_message_id AND c.chunk_index>=p_start_index ORDER BY c.chunk_index LIMIT p_limit;
END;$fn$;
REVOKE ALL ON FUNCTION public.create_private_room_audio(uuid,json),public.add_private_room_audio_chunk(uuid,integer,text,json),public.complete_private_room_audio(uuid,integer,json),public.private_room_audio_message_ids(uuid,json),public.get_private_room_audio_chunks(uuid,integer,integer,json),public.create_private_room_media(uuid,text,json),public.add_private_room_media_chunk(uuid,integer,text,text,json),public.complete_private_room_media(uuid,integer,json),public.private_room_media_message_ids(uuid,json),public.private_room_media_info(uuid,json),public.get_private_room_media_chunks(uuid,integer,integer,json) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_private_room_audio(uuid,json),public.add_private_room_audio_chunk(uuid,integer,text,json),public.complete_private_room_audio(uuid,integer,json),public.private_room_audio_message_ids(uuid,json),public.get_private_room_audio_chunks(uuid,integer,integer,json),public.create_private_room_media(uuid,text,json),public.add_private_room_media_chunk(uuid,integer,text,text,json),public.complete_private_room_media(uuid,integer,json),public.private_room_media_message_ids(uuid,json),public.private_room_media_info(uuid,json),public.get_private_room_media_chunks(uuid,integer,integer,json) TO PUBLIC;
