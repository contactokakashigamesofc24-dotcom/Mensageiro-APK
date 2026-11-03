#!/usr/bin/env python3
"""Offline-fixture Hasura authorization tests. Uses only ephemeral containers and fake JWTs."""
import base64, hashlib, hmac, json, os, time, urllib.request, urllib.error

URL = 'http://127.0.0.1:8080'
ADMIN = 'ephemeral-admin-only-for-this-job'
JWT_SECRET = 'ephemeral-jwt-secret-for-this-job-only-32bytes'
USER_ID = '40000000-0000-0000-0000-000000000001'
BOT_ID = '20000000-0000-0000-0000-000000000001'
ROOM_ALLOWED = '10000000-0000-0000-0000-000000000001'
ROOM_UNSELECTED = '10000000-0000-0000-0000-000000000002'
ROOM_PRIVATE = '10000000-0000-0000-0000-000000000003'

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def token(role, uid):
    header = b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    claims = {'https://hasura.io/jwt/claims': {'x-hasura-allowed-roles':[role], 'x-hasura-default-role':role, 'x-hasura-user-id':uid}}
    payload = b64(json.dumps(claims).encode())
    msg = f'{header}.{payload}'.encode()
    sig = b64(hmac.new(JWT_SECRET.encode(),msg,hashlib.sha256).digest())
    return f'{header}.{payload}.{sig}'

def request(path, body, headers=None):
    data=json.dumps(body).encode()
    req=urllib.request.Request(URL+path,data=data,headers={'Content-Type':'application/json',**(headers or {})},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=15) as res: return res.status,json.loads(res.read().decode())
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read().decode())

def assert_ok(condition, message):
    if not condition: raise AssertionError(message)

def main():
    metadata={'type':'replace_metadata','args':{'version':3,'sources':[{
      'name':'default','kind':'postgres','tables':[
        {'table':{'schema':'public','name':'rooms'},
         'array_relationships':[{'name':'bot_room_allowlist','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'bot_room_allowlist'},'column':'room_id'}}}],
         'select_permissions':[{'role':'user','permission':{'columns':['id','title','room_type'],'filter':{'room_type':{'_eq':'public'}}}}]},
        {'table':{'schema':'public','name':'bot_room_allowlist'}},
        {'table':{'schema':'public','name':'messages'},
         'object_relationships':[{'name':'room','using':{'foreign_key_constraint_on':'room_id'}}],
         'select_permissions':[{'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'room_type':{'_eq':'public'}}}}}],
         'insert_permissions':[{'role':'bot','permission':{
           'check':{'room':{'room_type':{'_eq':'public'},'bot_room_allowlist':{'bot_user_id':{'_eq':'X-Hasura-User-Id'}}}},
           'set':{'sender_id':'x-hasura-user-id'},'columns':['room_id','body']
         }}]}
      ],
      'configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}}
    }]}}
    status,result=request('/v1/metadata',metadata,{'X-Hasura-Admin-Secret':ADMIN})
    assert_ok(status==200 and result.get('message')=='success',f'metadata setup failed: {result}')

    # Regular authenticated user must not have public-message insert permission.
    query='mutation($room:uuid!,$body:String!){insert_messages_one(object:{room_id:$room,body:$body}){id}}'
    headers={'Authorization':'Bearer '+token('user',USER_ID)}
    _,result=request('/v1/graphql',{'query':query,'variables':{'room':ROOM_ALLOWED,'body':'ordinary user test'}},headers)
    assert_ok(bool(result.get('errors')),'ordinary user unexpectedly inserted a public message')

    # Bot can insert once in the selected public room; sender_id is set server-side from the Bot JWT.
    bot_headers={'Authorization':'Bearer '+token('bot',BOT_ID)}
    _,result=request('/v1/graphql',{'query':query.replace('{id}','{id sender_id room_id}'),'variables':{'room':ROOM_ALLOWED,'body':'fake Bot reply'}},bot_headers)
    row=(result.get('data') or {}).get('insert_messages_one')
    assert_ok(row is not None and row['sender_id']==BOT_ID and row['room_id']==ROOM_ALLOWED,
              f'Bot selected-room insert failed or identity was not server-set: {result}')

    # Bot must fail in unselected public room and in private room.
    for room,label in [(ROOM_UNSELECTED,'unselected public room'),(ROOM_PRIVATE,'private room')]:
        _,result=request('/v1/graphql',{'query':query,'variables':{'room':room,'body':'must be rejected'}},bot_headers)
        assert_ok(bool(result.get('errors')) and not (result.get('data') or {}).get('insert_messages_one'),
                  f'Bot unexpectedly wrote to {label}: {result}')

    # A client cannot override the preset identity; sender_id is outside the Bot role's allowed columns.
    forged='mutation($room:uuid!,$body:String!,$sender:uuid!){insert_messages_one(object:{room_id:$room,body:$body,sender_id:$sender}){id sender_id}}'
    _,result=request('/v1/graphql',{'query':forged,'variables':{'room':ROOM_ALLOWED,'body':'forged sender','sender':'40000000-0000-0000-0000-000000000001'}},bot_headers)
    assert_ok(bool(result.get('errors')),'Bot client unexpectedly supplied sender_id')

    print('PASS: ordinary user cannot write public messages')
    print('PASS: Bot writes only in allowlisted public room with server-set identity')
    print('PASS: Bot denied in unselected public and private rooms')
    print('PASS: client cannot forge sender identity')
    print('NOTE: ephemeral fixture only; does not validate Nhost production schema, Auth/JWT setup, app polling or Gemini integration')

if __name__=='__main__': main()
