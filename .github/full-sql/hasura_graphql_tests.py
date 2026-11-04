import base64, hashlib, hmac, json, os, subprocess, time, urllib.request, urllib.error

URL='http://127.0.0.1:8080'
ADMIN='ephemeral-full-sql-admin'
SECRET='ephemeral-full-sql-test-only-secret'
OWNER='27a5eca4-18d2-4a67-9a34-3e075317740b'
MEMBER='40000000-0000-0000-0000-000000000002'

def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def jwt(uid,role='user'):
    head=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    claims={'https://hasura.io/jwt/claims':{'x-hasura-allowed-roles':[role],'x-hasura-default-role':role,'x-hasura-user-id':uid}}
    payload=b64(json.dumps(claims).encode()); msg=f'{head}.{payload}'.encode()
    return f'{head}.{payload}.{b64(hmac.new(SECRET.encode(),msg,hashlib.sha256).digest())}'
def gql_role(uid,role,query,variables=None):
    status,res=post('/v1/graphql',{'query':query,'variables':variables or {}},{'Authorization':'Bearer '+jwt(uid,role)})
    return status,res
def post(path,obj,headers=None):
    req=urllib.request.Request(URL+path,data=json.dumps(obj).encode(),headers={'Content-Type':'application/json',**(headers or {})},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=30) as r: return r.status,json.loads(r.read().decode())
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read().decode())
def meta(op,args):
    status,res=post('/v1/metadata',{'type':op,'args':args},{'X-Hasura-Admin-Secret':ADMIN})
    if status!=200: raise AssertionError(f'metadata {op}: {res}')
def psql(sql):
    return subprocess.check_output(['docker','exec','full-sql-db','psql','-U','postgres','-d','messenger_test','-At','-c',sql],text=True).strip()
def gql(uid,query,variables=None):
    status,res=post('/v1/graphql',{'query':query,'variables':variables or {}},{'Authorization':'Bearer '+jwt(uid)})
    if status!=200 or res.get('errors'): raise AssertionError(f'GraphQL failed: {res}')
    return res.get('data') or {}
def gql_result(uid,query,variables=None):
    headers={} if uid is None else {'Authorization':'Bearer '+jwt(uid)}
    return post('/v1/graphql',{'query':query,'variables':variables or {}},headers)

def set_exact_app_permissions():
    # Reproduce the exported Nhost permissions for these three tables, not broad admin access.
    meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
    meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'room_members'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
    meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}})
    meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'check':{},'set':{'created_by':'X-Hasura-User-Id'},'columns':['title','room_type']}})
    meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}}})
    meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
    meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'user','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
    # No anonymous role function permissions are created.
    
def main():
    meta('replace_metadata',{'version':3,'sources':[{'name':'default','kind':'postgres','configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}},'tables':[]}]})
    tables=psql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").splitlines()
    for table in tables:
        meta('pg_track_table',{'source':'default','table':{'schema':'public','name':table}})
    # Only the result-table columns are visible to the test client; no direct writes are granted.
    for table in [t for t in tables if t.endswith('_result')]:
        cols=psql("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='"+table+"' ORDER BY ordinal_position").splitlines()
        if cols:
            meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':table},'role':'user','permission':{'columns':cols,'filter':{}}})
    funcs=psql("SELECT p.proname || '|' || pg_get_function_arguments(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proretset AND p.prokind='f' AND p.proname IN ('messenger_bot_status','set_messenger_bot_enabled','my_messenger_profile','room_message_profiles','get_message_profile','upsert_my_profile','request_friend_by_email','respond_friend_request','my_messenger_friends','my_incoming_friend_requests','invite_room_member_by_email','accept_private_room_invite','my_accepted_private_rooms','owner_room_members','my_pending_private_invites','create_private_messenger_group','my_messenger_groups','my_pending_group_invites','accept_messenger_group_invite','set_my_presence','my_presence_state','my_friends_presence','create_private_room_audio','add_private_room_audio_chunk','complete_private_room_audio','private_room_audio_message_ids','get_private_room_audio_chunks','create_private_room_media','add_private_room_media_chunk','complete_private_room_media','private_room_media_message_ids','private_room_media_info','get_private_room_media_chunks') ORDER BY p.proname").splitlines()
    tracked=[]
    for line in funcs:
        name,args=line.split('|',1)
        cfg={}
        if 'hasura_session' in args: cfg={'session_argument':'hasura_session'}
        meta('pg_track_function',{'source':'default','function':{'schema':'public','name':name},'configuration':cfg})
        meta('pg_create_function_permission',{'source':'default','function':{'schema':'public','name':name},'role':'user'})
        tracked.append(name)
    set_exact_app_permissions()
    # Hasura health, exact app metadata role, identity-injected query/mutation, completed upload reads and Bot state.
    prof=gql(OWNER,'query { my_messenger_profile { display_name avatar_data } }')
    assert len(prof['my_messenger_profile'])==1
    changed=gql(MEMBER,'mutation { upsert_my_profile(args:{p_display_name:"GraphQL member",p_avatar_data:null}) { user_id display_name avatar_data } }')
    assert changed['upsert_my_profile'][0]['user_id']==MEMBER and changed['upsert_my_profile'][0]['display_name']=='GraphQL member'
    rooms=gql(MEMBER,'query { my_accepted_private_rooms { room_id room_title owner_id joined_at } }')['my_accepted_private_rooms']
    assert rooms, 'member did not receive accepted private room from complete SQL functions'
    room=rooms[0]['room_id']
    audios=gql(MEMBER,'query($room:uuid!){private_room_audio_message_ids(args:{p_room_id:$room}){message_id}}',{'room':room})['private_room_audio_message_ids']
    assert audios, 'no completed audio returned through Hasura'
    aid=audios[0]['message_id']
    audio_chunks=gql(MEMBER,'query($id:uuid!){get_private_room_audio_chunks(args:{p_message_id:$id,p_start_index:0,p_limit:4}){chunk_index audio_data}}',{'id':aid})['get_private_room_audio_chunks']
    assert audio_chunks and audio_chunks[0]['chunk_index']==0
    medias=gql(MEMBER,'query($room:uuid!){private_room_media_message_ids(args:{p_room_id:$room}){message_id mime_type}}',{'room':room})['private_room_media_message_ids']
    assert medias, 'no completed media returned through Hasura'
    mid=medias[0]['message_id']
    pages=gql(MEMBER,'query($id:uuid!){get_private_room_media_chunks(args:{p_message_id:$id,p_start_index:1,p_limit:2}){chunk_index media_data}}',{'id':mid})['get_private_room_media_chunks']
    assert [r['chunk_index'] for r in pages]==[1,2]
    status=gql(OWNER,'query { messenger_bot_status { enabled updated_at } }')['messenger_bot_status']
    assert len(status)==1 and status[0]['enabled'] is False
    public_rooms=gql(OWNER,'query { rooms(where:{room_type:{_eq:"public"}}) { id title room_type created_by } }')['rooms']
    assert public_rooms, 'authenticated user cannot read public room via app metadata'
    public_room=public_rooms[0]['id']
    outsider_query=gql_role('40000000-0000-0000-0000-000000000004','user','query($id:uuid!){rooms(where:{id:{_eq:$id}}){id}}',{'id':room})
    assert outsider_query[0]==200 and outsider_query[1].get('data',{}).get('rooms')==[], f'outsider could see private room: {outsider_query}'
    other_owner_room=gql_role('40000000-0000-0000-0000-000000000004','user','mutation { insert_rooms_one(object:{title:"Outsider-owned private room",room_type:"private"}) { id created_by } }')
    assert other_owner_room[0]==200 and not other_owner_room[1].get('errors'), f'failed to create other-owned private fixture: {other_owner_room}'
    outsider_private_room=other_owner_room[1]['data']['insert_rooms_one']['id']
    outsider_room_query=gql_role('27a5eca4-18d2-4a67-9a34-3e075317740b','user','query($id:uuid!){rooms(where:{id:{_eq:$id}}){id}}',{'id':outsider_private_room})
    assert outsider_room_query[0]==200 and outsider_room_query[1].get('data',{}).get('rooms')==[], f'outsider private room readable by non-owner: {outsider_room_query}'
    outsider_seed=gql_role('40000000-0000-0000-0000-000000000004','user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"private seed"}){id}}',{'room':outsider_private_room})
    assert outsider_seed[0]==200 and not outsider_seed[1].get('errors'), f'failed to seed other-owned private message: {outsider_seed}'
    member_owner_query=gql_role(MEMBER,'user','query($id:uuid!){rooms(where:{id:{_eq:$id}}){id}}',{'id':room})
    assert member_owner_query[0]==200 and member_owner_query[1].get('data',{}).get('rooms')==[], 'current legacy metadata unexpectedly exposes accepted private room'
    # Try the candidate accepted-member policy only in disposable Hasura metadata.
    meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'room_members','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_members'},'column':'room_id'}}})
    meta('pg_drop_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user'})
    meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}}})
    meta('pg_drop_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user'})
    meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}}}})
    meta('pg_drop_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user'})
    meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
    candidate_rooms=gql_role(MEMBER,'user','query($id:uuid!){rooms(where:{id:{_eq:$id}}){id}}',{'id':room})
    assert candidate_rooms[0]==200 and candidate_rooms[1].get('data',{}).get('rooms')==[{'id':room}], f'candidate accepted private room read failed: {candidate_rooms}'
    candidate_msgs=gql_role(MEMBER,'user','query($room:uuid!){messages(where:{room_id:{_eq:$room}}){id body}}',{'room':room})
    assert candidate_msgs[0]==200 and len(candidate_msgs[1].get('data',{}).get('messages',[]))==1, f'candidate accepted private history read failed: {candidate_msgs}'
    denied_msgs=gql_role('40000000-0000-0000-0000-000000000004','user','query($room:uuid!){messages(where:{room_id:{_eq:$room}}){id}}',{'room':room})
    assert denied_msgs[0]==200 and denied_msgs[1].get('data',{}).get('messages')==[], 'candidate leaked private history to outsider'
    member_write=gql_role(MEMBER,'user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"accepted private member write"}){id sender_id}}',{'room':room})
    assert member_write[0]==200 and not member_write[1].get('errors') and member_write[1].get('data',{}).get('insert_messages_one',{}).get('sender_id')==MEMBER, f'candidate accepted member write failed: {member_write}'
    outsider_write=gql_role('40000000-0000-0000-0000-000000000004','user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"outsider private write"}){id}}',{'room':room})
    assert outsider_write[1].get('errors'), f'candidate allowed outsider private write: {outsider_write}'
    pending_invite_write=gql_role('40000000-0000-0000-0000-000000000003','user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"pending private write"}){id}}',{'room':room})
    assert pending_invite_write[1].get('errors'), f'candidate allowed pending invite private write: {pending_invite_write}'
    outsider_insert=gql_role('40000000-0000-0000-0000-000000000004','user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"outsider attempt"}){id}}',{'room':room})
    assert outsider_insert[1].get('errors'), f'outsider private insert unexpectedly allowed: {outsider_insert}'
    member_private_read=gql_role(MEMBER,'user','query($room:uuid!){messages(where:{room_id:{_eq:$room}}){id}}',{'room':room})
    assert member_private_read[0]==200 and member_private_read[1].get('data',{}).get('messages')==[], 'legacy message metadata unexpectedly exposes private room messages to accepted member'
    member_private_insert=gql_role(MEMBER,'user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"accepted member attempt"}){id}}',{'room':room})
    assert member_private_insert[1].get('errors'), f'legacy metadata unexpectedly allowed accepted member private send: {member_private_insert}'
    public_insert=gql_role(OWNER,'user','mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"normal public write"}){id sender_id}}',{'room':public_room})
    assert public_insert[0]==200 and not public_insert[1].get('errors') and public_insert[1].get('data',{}).get('insert_messages_one',{}).get('sender_id')==OWNER, f'public room normal write not preserved: {public_insert}'
    create_room=gql_role(MEMBER,'user','mutation { insert_rooms_one(object:{title:"GraphQL public room",room_type:"public"}) { id created_by room_type } }')
    assert create_room[0]==200 and not create_room[1].get('errors') and create_room[1].get('data',{}).get('insert_rooms_one',{}).get('created_by')==MEMBER, f'normal public room creation not preserved: {create_room}'
    anon_query=gql_result(None,'query { rooms { id } }')
    assert anon_query[1].get('errors'), f'unauthenticated query should be default-denied: {anon_query}'
    anon_status=gql_result(None,'query { messenger_bot_status { enabled } }')
    assert anon_status[1].get('errors'), f'unauthenticated Bot status unexpectedly available: {anon_status}'
    anon_mutation=gql_result(None,'mutation($room:uuid!){insert_messages_one(object:{room_id:$room,body:"anonymous"}){id}}',{'room':public_room})
    assert anon_mutation[1].get('errors'), f'unauthenticated public write unexpectedly allowed: {anon_mutation}'
    print('PASS Hasura metadata tracking:',len(tables),'tables,',len(tracked),'functions; session argument configured where required')
    print('PASS exact app metadata: public-room read/write works; outsider denied; candidate metadata grants accepted private member access only')
    print('PASS anonymous GraphQL query, Bot-status, and message mutation denied')
    print('PASS authenticated profile query/upsert, attachments, pagination, Bot OFF')
    print('NOTE current export first denied accepted members; candidate private-room metadata was tested only in disposable Hasura and is not applied to Nhost.')
    print('NOTE candidate relationship/filter behavior is a test result, not a production migration.')
    print('NOTE disposable PostgreSQL/Hasura and synthetic JWT only; no production Nhost/Auth/device tested')

if __name__=='__main__': main()
