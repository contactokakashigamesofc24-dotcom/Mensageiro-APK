#!/usr/bin/env python3
"""Ephemeral Hasura authorization checks with synthetic JWTs and fixture rows only."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080'; ADMIN='ephemeral-admin-only-for-this-job'; SECRET='ephemeral-jwt-secret-for-this-job-only-32bytes'
USER='40000000-0000-0000-0000-000000000001'; BOT='20000000-0000-0000-0000-000000000001'
ALLOW='10000000-0000-0000-0000-000000000001'; OTHER='10000000-0000-0000-0000-000000000002'; PRIVATE='10000000-0000-0000-0000-000000000003'
def b64(v): return base64.urlsafe_b64encode(v).rstrip(b'=').decode()
def jwt(role,uid):
 h=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode()); claims={'https://hasura.io/jwt/claims':{'x-hasura-allowed-roles':[role],'x-hasura-default-role':role,'x-hasura-user-id':uid}}
 p=b64(json.dumps(claims).encode()); msg=f'{h}.{p}'.encode(); return f'{h}.{p}.{b64(hmac.new(SECRET.encode(),msg,hashlib.sha256).digest())}'
def post(path,obj,headers=None):
 req=urllib.request.Request(URL+path,data=json.dumps(obj).encode(),headers={'Content-Type':'application/json',**(headers or {})},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=15) as r:return r.status,json.loads(r.read().decode())
 except urllib.error.HTTPError as e:return e.code,json.loads(e.read().decode())
def meta(op,args):
 status,res=post('/v1/metadata',{'type':op,'args':args},{'X-Hasura-Admin-Secret':ADMIN})
 if status!=200: raise AssertionError(f'{op} metadata failed: {res}')
 return res
def check(ok,msg):
 if not ok:raise AssertionError(msg)
def main():
 source={'name':'default','kind':'postgres','configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}},'tables':[]}
 st,res=post('/v1/metadata',{'type':'replace_metadata','args':{'version':3,'sources':[source]}},{'X-Hasura-Admin-Secret':ADMIN})
 check(st==200 and res.get('message')=='success',f'replace metadata: {res}')
 for name in ['rooms','bot_room_allowlist','messages']:
  meta('pg_track_table',{'source':'default','table':{'schema':'public','name':name}})
 # Explicitly configure safe read access and narrowly scoped Bot insert access.
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'bot_room_allowlist','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'bot_room_allowlist'},'column':'room_id'}}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type'],'filter':{'room_type':{'_eq':'public'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'bot','permission':{'columns':['id','room_type'],'filter':{'room_type':{'_eq':'public'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'bot_room_allowlist'},'role':'bot','permission':{'columns':['room_id','bot_user_id'],'filter':{'bot_user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'room_type':{'_eq':'public'}}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'bot','permission':{'check':{'room':{'room_type':{'_eq':'public'},'bot_room_allowlist':{'bot_user_id':{'_eq':'X-Hasura-User-Id'}}}},'set':{'sender_id':'x-hasura-user-id'},'columns':['room_id','body'],'backend_only':True}})
 introspection='query { __type(name:"mutation_root") { fields { name } } }'
 _,schema=post('/v1/graphql',{'query':introspection},{'X-Hasura-Admin-Secret':ADMIN})
 fields=[f['name'] for f in (((schema.get('data') or {}).get('__type') or {}).get('fields') or [])]
 if 'insert_messages_one' not in fields:
  raise AssertionError(f'Hasura schema missing insert_messages_one; mutation fields={fields}')
 query='mutation($room:uuid!,$body:String!){insert_messages_one(object:{room_id:$room,body:$body}){id}}'
 _,res=post('/v1/graphql',{'query':query,'variables':{'room':ALLOW,'body':'regular-user fake write'}},{'Authorization':'Bearer '+jwt('user',USER)})
 check(bool(res.get('errors')),'ordinary user unexpectedly inserted public message')
 # Public-facing role bot must not see the backend-only mutation without trusted backend headers.
 _,res=post('/v1/graphql',{'query':query,'variables':{'room':ALLOW,'body':'must be hidden'}},{'Authorization':'Bearer '+jwt('bot',BOT)})
 check(bool(res.get('errors')),'Bot backend-only mutation unexpectedly visible to an ordinary JWT request')
 # trusted backend-only mode must expose the constrained mutation.
 _,res=post('/v1/graphql',{'query':introspection},{'X-Hasura-Admin-Secret':ADMIN,'X-Hasura-Role':'bot','X-Hasura-User-Id':BOT,'X-Hasura-Use-Backend-Only-Permissions':'true'})
 trusted_fields=[f['name'] for f in (((res.get('data') or {}).get('__type') or {}).get('fields') or [])]
 check('insert_messages_one' in trusted_fields,f'backend-only mutation not exposed; fields={trusted_fields}')
 # Proceed with same constrained operation using the trusted server-only path.
 bh={'X-Hasura-Admin-Secret':ADMIN,'X-Hasura-Role':'bot','X-Hasura-User-Id':BOT,'X-Hasura-Use-Backend-Only-Permissions':'true'}
 _,res=post('/v1/graphql',{'query':query.replace('{id}','{id sender_id room_id}'),'variables':{'room':ALLOW,'body':'fake Bot reply'}},bh)
 row=(res.get('data') or {}).get('insert_messages_one');check(row and row['sender_id']==BOT and row['room_id']==ALLOW,f'allowlisted Bot insert failed: {res}')
 for room,label in [(OTHER,'unselected public'),(PRIVATE,'private')]:
  _,res=post('/v1/graphql',{'query':query,'variables':{'room':room,'body':'must be denied'}},bh)
  check(bool(res.get('errors')) and not (res.get('data') or {}).get('insert_messages_one'),f'Bot wrote to {label}: {res}')
 forged='mutation($room:uuid!,$body:String!,$sender:uuid!){insert_messages_one(object:{room_id:$room,body:$body,sender_id:$sender}){id sender_id}}'
 _,res=post('/v1/graphql',{'query':forged,'variables':{'room':ALLOW,'body':'forged','sender':USER}},bh)
 check(bool(res.get('errors')),'client was able to set sender_id')
 print('PASS: regular user has no public insert permission')
 print('PASS: Bot writes only to allowlisted public room with server-preset identity')
 print('PASS: Bot denied in unselected public and private rooms')
 print('PASS: forged sender_id rejected')
 print('NOTE: synthetic ephemeral Hasura fixture only; not Nhost production schema/Auth/app/Gemini validation')
if __name__=='__main__':main()
