#!/usr/bin/env python3
"""Synthetic ephemeral Hasura policy tests only; no production credentials or data."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080'; ADMIN='ephemeral-admin-only-for-this-job'; SECRET='ephemeral-jwt-secret-for-this-job-only-32bytes'
USER='40000000-0000-0000-0000-000000000001'; BOT='20000000-0000-0000-0000-000000000001'; SETTINGS='30000000-0000-0000-0000-000000000001'
PUBLIC='10000000-0000-0000-0000-000000000001'; PRIVATE='10000000-0000-0000-0000-000000000002'; NEWPUB='10000000-0000-0000-0000-000000000003'; NEWPRIV='10000000-0000-0000-0000-000000000004'
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
 if not ok: raise AssertionError(msg)
def main():
 source={'name':'default','kind':'postgres','configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}},'tables':[]}
 st,res=post('/v1/metadata',{'type':'replace_metadata','args':{'version':3,'sources':[source]}},{'X-Hasura-Admin-Secret':ADMIN})
 check(st==200 and res.get('message')=='success',f'replace metadata: {res}')
 for name in ['bot_settings','rooms','room_members','messages']:
  meta('pg_track_table',{'source':'default','table':{'schema':'public','name':name}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'bot_settings','using':{'foreign_key_constraint_on':'bot_settings_id'}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'room_members','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_members'},'column':'room_id'}}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'room_members'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'bot_settings'},'name':'rooms','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'rooms'},'column':'bot_settings_id'}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'bot_settings'},'role':'bot','permission':{'columns':['id','enabled','scope'],'filter':{'id':{'_eq':SETTINGS}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','bot_settings_id'],'filter':{}}})
 # Candidate for ALL rooms is global enabled setting; user must be a member of private rooms.
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'bot','permission':{'columns':['id','title','room_type','bot_settings_id'],'filter':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'bot','permission':{'columns':['room_id','user_id'],'filter':{'room':{'bot_settings':{'enabled':{'_eq':True}}}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'user','permission':{'columns':['room_id','user_id'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'$or':[{'room_type':{'_eq':'public'}},{'room_members':{'user_id':{'_eq':'X-Hasura-User-Id'}}}]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'bot','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'bot','permission':{'check':{'room':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}},'set':{'sender_id':'x-hasura-user-id'},'columns':['room_id','body'],'backend_only':True}})
 meta('pg_create_update_permission',{'source':'default','table':{'schema':'public','name':'bot_settings'},'role':'bot_control','permission':{'columns':['enabled'],'filter':{'id':{'_eq':SETTINGS}}}})
 user_h={'Authorization':'Bearer '+jwt('user',USER)};bot_h={'Authorization':'Bearer '+jwt('bot',BOT)}
 readq='query($room:uuid!){messages(where:{room_id:{_eq:$room}}){id body room_id sender_id}}'
 # Verify ordinary user baseline: public is readable; private room is readable only by its member.
 for room,label,allowed in [(PUBLIC,'public room',True),(PRIVATE,'private room for its member',True),(NEWPUB,'new public room',True),(NEWPRIV,'private room not joined by this user',False)]:
  _,u=post('/v1/graphql',{'query':readq,'variables':{'room':room}},user_h); rows=(u.get('data') or {}).get('messages')
  check(rows is not None,f'ordinary user read failed in {label}: {u}')
  check((len(rows)>0)==allowed,f'ordinary user privacy baseline unexpected in {label}: {u}')
 # Bot reads all public/private existing and future rooms while the global setting is enabled.
 for room,label in [(PUBLIC,'public room'),(PRIVATE,'private room'),(NEWPUB,'new public room created after policy'),(NEWPRIV,'new private room created after policy')]:
  _,b=post('/v1/graphql',{'query':readq,'variables':{'room':room}},bot_h); rows=(b.get('data') or {}).get('messages')
  check(rows is not None and len(rows)==1,f'Bot did not read {label}: {b}')
 # Public GraphQL clients must not see backend-only insert, but ordinary users cannot write either.
 introspection='query { __type(name:"mutation_root") { fields { name } } }'
 _,schema=post('/v1/graphql',{'query':introspection},{'X-Hasura-Admin-Secret':ADMIN})
 fields=[f['name'] for f in (((schema.get('data') or {}).get('__type') or {}).get('fields') or [])]
 check('insert_messages' in fields,f'Hasura schema missing insert_messages: {fields}')
 insert='mutation($room:uuid!,$body:String!){insert_messages(objects:[{room_id:$room,body:$body}]){affected_rows returning{id sender_id room_id}}}'
 _,res=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'ordinary fake write'}},user_h)
 check(bool(res.get('errors')),'ordinary user unexpectedly inserted a public message')
 _,res=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'must stay hidden'}},bot_h)
 check(bool(res.get('errors')),'backend-only mutation exposed to an ordinary Bot JWT')
 trusted={'X-Hasura-Admin-Secret':ADMIN,'X-Hasura-Role':'bot','X-Hasura-User-Id':BOT,'X-Hasura-Use-Backend-Only-Permissions':'true'}
 _,schema=post('/v1/graphql',{'query':introspection},trusted);fields=[f['name'] for f in (((schema.get('data') or {}).get('__type') or {}).get('fields') or [])]
 check('insert_messages' in fields,f'backend-only mutation not available to trusted service: {fields}')
 for room,label in [(PUBLIC,'public room'),(PRIVATE,'private room'),(NEWPUB,'new public room'),(NEWPRIV,'new private room')]:
  _,res=post('/v1/graphql',{'query':insert,'variables':{'room':room,'body':'synthetic Bot reply'}},trusted)
  rows=((res.get('data') or {}).get('insert_messages') or {}).get('returning') or []
  check(len(rows)==1 and rows[0]['sender_id']==BOT and rows[0]['room_id']==room,f'Bot could not post safely to {label}: {res}')
 forged='mutation($room:uuid!,$body:String!,$sender:uuid!){insert_messages(objects:[{room_id:$room,body:$body,sender_id:$sender}]){affected_rows returning{sender_id}}}'
 _,res=post('/v1/graphql',{'query':forged,'variables':{'room':PRIVATE,'body':'forged','sender':USER}},trusted)
 check(bool(res.get('errors')),'client could forge sender_id')
 # Disable global Bot setting and verify both reads and writes fail-closed.
 st,res=post('/v1/graphql',{'query':'mutation($id:uuid!){update_bot_settings_by_pk(pk_columns:{id:$id},_set:{enabled:false}){id enabled}}','variables':{'id':SETTINGS}},{'X-Hasura-Admin-Secret':ADMIN})
 check(st==200 and not res.get('errors') and (res.get('data') or {}).get('update_bot_settings_by_pk',{}).get('enabled') is False,f'could not disable synthetic Bot: {res}')
 for room,label in [(PUBLIC,'public'),(PRIVATE,'private'),(NEWPUB,'new public'),(NEWPRIV,'new private')]:
  _,res=post('/v1/graphql',{'query':readq,'variables':{'room':room}},bot_h)
  check(not ((res.get('data') or {}).get('messages') or []),f'Bot still read {label} after global off: {res}')
 _,res=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'must be stopped'}},trusted)
 check(bool(res.get('errors')) or ((res.get('data') or {}).get('insert_messages') or {}).get('affected_rows',0)==0,f'Bot wrote after global off: {res}')
 print('PASS: regular user room privacy behavior unchanged')
 print('PASS: Bot reads all rooms, including private/new, only while synthetic global switch is on')
 print('PASS: Bot posts with server-preset identity in public/private/new rooms')
 print('PASS: backend-only mutation hidden from ordinary JWT clients')
 print('PASS: forged sender_id rejected; global off stops Bot reads and writes')
 print('NOTE: synthetic ephemeral Hasura simulation only; no Nhost production/Auth/app/Gemini validation')
if __name__=='__main__':main()
