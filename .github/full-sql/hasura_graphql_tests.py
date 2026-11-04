import base64, hashlib, hmac, json, os, subprocess, time, urllib.request, urllib.error

URL='http://127.0.0.1:8080'
ADMIN='ephemeral-full-sql-admin'
SECRET='ephemeral-full-sql-test-only-secret'
OWNER='27a5eca4-18d2-4a67-9a34-3e075317740b'
MEMBER='40000000-0000-0000-0000-000000000002'

def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
def jwt(uid):
    head=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    claims={'https://hasura.io/jwt/claims':{'x-hasura-allowed-roles':['user'],'x-hasura-default-role':'user','x-hasura-user-id':uid}}
    payload=b64(json.dumps(claims).encode()); msg=f'{head}.{payload}'.encode()
    return f'{head}.{payload}.{b64(hmac.new(SECRET.encode(),msg,hashlib.sha256).digest())}'
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
        if name=='messenger_user_can_access_private_room': continue
        cfg={}
        if 'hasura_session' in args: cfg={'session_argument':'hasura_session'}
        meta('pg_track_function',{'source':'default','function':{'schema':'public','name':name},'configuration':cfg})
        meta('pg_create_function_permission',{'source':'default','function':{'schema':'public','name':name},'role':'user'})
        tracked.append(name)
    # Hasura health, identity-injected query/mutation, completed upload reads and Bot state.
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
    print('PASS Hasura metadata tracking:',len(tables),'tables,',len(tracked),'functions; session argument configured where required')
    print('PASS authenticated GraphQL profile query/upsert with injected caller identity')
    print('PASS GraphQL accepted-room listing; completed audio read; media second-page retrieval')
    print('PASS GraphQL owner Bot-status query reports OFF')
    print('NOTE disposable PostgreSQL/Hasura and synthetic JWT only; no production Nhost/Auth/device tested')

if __name__=='__main__': main()
