#!/usr/bin/env python3
"""Ephemeral Hasura fixture authorization checks; no production systems."""
import base64, hashlib, hmac, json, urllib.request, urllib.error
URL='http://127.0.0.1:8080'; ADMIN='ephemeral-admin-only-for-this-job'
SECRET='ephemeral-jwt-secret-for-this-job-only-32bytes'
USER='40000000-0000-0000-0000-000000000001'; BOT='20000000-0000-0000-0000-000000000001'
ALLOW='10000000-0000-0000-0000-000000000001'; OTHER='10000000-0000-0000-0000-000000000002'; PRIVATE='10000000-0000-0000-0000-000000000003'
def b64(v): return base64.urlsafe_b64encode(v).rstrip(b'=').decode()
def jwt(role,uid):
 h=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
 c={'https://hasura.io/jwt/claims':{'x-hasura-allowed-roles':[role],'x-hasura-default-role':role,'x-hasura-user-id':uid}}
 p=b64(json.dumps(c).encode()); msg=f'{h}.{p}'.encode(); sig=b64(hmac.new(SECRET.encode(),msg,hashlib.sha256).digest())
 return f'{h}.{p}.{sig}'
def post(path,obj,headers=None):
 req=urllib.request.Request(URL+path,data=json.dumps(obj).encode(),headers={'Content-Type':'application/json',**(headers or {})},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=15) as r: return r.status,json.loads(r.read().decode())
 except urllib.error.HTTPError as e: return e.code,json.loads(e.read().decode())
def check(ok,msg):
 if not ok: raise AssertionError(msg)
def main():
 # Track only synthetic fixture tables. Public users can read public room metadata/messages; no insert grant.
 # Bot may read public rooms and only its own allowlist row; insert preset sets sender from JWT.
 tables=[
  {'table':{'schema':'public','name':'rooms'},
   'array_relationships':[{'name':'bot_room_allowlist','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'bot_room_allowlist'},'column':'room_id'}}}],
   'select_permissions':[
    {'role':'user','permission':{'columns':['id','title','room_type'],'filter':{'room_type':{'_eq':'public'}}}},
    {'role':'bot','permission':{'columns':['id','room_type'],'filter':{'room_type':{'_eq':'public'}}}}]},
  {'table':{'schema':'public','name':'bot_room_allowlist'},
   'select_permissions':[{'role':'bot','permission':{'columns':['room_id','bot_user_id'],'filter':{'bot_user_id':{'_eq':'X-Hasura-User-Id'}}}}]},
  {'table':{'schema':'public','name':'messages'},
   'object_relationships':[{'name':'room','using':{'foreign_key_constraint_on':'room_id'}}],
   'select_permissions':[{'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'room_type':{'_eq':'public'}}}}}],
   'insert_permissions':[{'role':'bot','permission':{'check':{'room':{'room_type':{'_eq':'public'},'bot_room_allowlist':{'bot_user_id':{'_eq':'X-Hasura-User-Id'}}}},'set':{'sender_id':'x-hasura-user-id'},'columns':['room_id','body']}}]}]
 meta={'type':'replace_metadata','args':{'version':3,'sources':[{'name':'default','kind':'postgres','tables':tables,'configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}}}]}}
 status,res=post('/v1/metadata',meta,{'X-Hasura-Admin-Secret':ADMIN}); check(status==200 and res.get('message')=='success',f'metadata setup: {res}')
 q='mutation($room:uuid!,$body:String!){insert_messages_one(object:{room_id:$room,body:$body}){id}}'
 _,res=post('/v1/graphql',{'query':q,'variables':{'room':ALLOW,'body':'regular-user fake write'}},{'Authorization':'Bearer '+jwt('user',USER)})
 check(bool(res.get('errors')),'ordinary user unexpectedly inserted message')
 bh={'Authorization':'Bearer '+jwt('bot',BOT)}
 _,res=post('/v1/graphql',{'query':q.replace('{id}','{id sender_id room_id}'),'variables':{'room':ALLOW,'body':'fake Bot reply'}},bh)
 row=(res.get('data') or {}).get('insert_messages_one'); check(row and row['sender_id']==BOT and row['room_id']==ALLOW,f'allowlisted Bot insert failed: {res}')
 for room,label in [(OTHER,'unselected public'),(PRIVATE,'private')]:
  _,res=post('/v1/graphql',{'query':q,'variables':{'room':room,'body':'must be denied'}},bh)
  check(bool(res.get('errors')) and not (res.get('data') or {}).get('insert_messages_one'),f'Bot wrote to {label}: {res}')
 forged='mutation($room:uuid!,$body:String!,$sender:uuid!){insert_messages_one(object:{room_id:$room,body:$body,sender_id:$sender}){id sender_id}}'
 _,res=post('/v1/graphql',{'query':forged,'variables':{'room':ALLOW,'body':'forged','sender':USER}},bh)
 check(bool(res.get('errors')),'client was able to set sender_id')
 print('PASS: regular user has no public insert permission')
 print('PASS: Bot can insert only into allowlisted public room; sender is server-preset')
 print('PASS: Bot denied in unselected public and private rooms')
 print('PASS: forged sender_id rejected')
 print('NOTE: synthetic isolated Hasura fixture only; not production schema/Auth/app/Gemini validation')
if __name__=='__main__': main()
