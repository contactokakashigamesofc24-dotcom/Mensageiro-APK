#!/usr/bin/env python3
"""Synthetic ephemeral Hasura policy tests based on exported metadata structure only."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080'; ADMIN='ephemeral-admin-only-for-this-job'; SECRET='ephemeral-jwt-secret-for-this-job-only-32bytes'
USER='40000000-0000-0000-0000-000000000001'; OTHERUSER='40000000-0000-0000-0000-000000000002'; BOT='20000000-0000-0000-0000-000000000001'; SETTINGS='30000000-0000-0000-0000-000000000001'
PUBLIC='10000000-0000-0000-0000-000000000001'; PRIVATE_OWN='10000000-0000-0000-0000-000000000002'; NEWPUB='10000000-0000-0000-0000-000000000003'; NEWPRIV='10000000-0000-0000-0000-000000000004'
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
 # Existing user visibility modeled after metadata export: public + rooms created by that user.
 user_room_filter={'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by','bot_settings_id'],'filter':user_room_filter}})
 # Existing user message insert behavior preserved: public room or room created by sender.
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':user_room_filter}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':user_room_filter}}})
 # Proposed Bot policy: all rooms while one global switch is enabled.
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'bot_settings'},'role':'bot','permission':{'columns':['id','enabled','scope'],'filter':{'id':{'_eq':SETTINGS}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'bot','permission':{'columns':['id','title','room_type','bot_settings_id'],'filter':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'bot','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'bot','permission':{'check':{'room':{'bot_settings':{'enabled':{'_eq':True},'scope':{'_eq':'all_rooms'}}}},'set':{'sender_id':'x-hasura-user-id'},'columns':['room_id','body'],'backend_only':True}})
 user_h={'Authorization':'Bearer '+jwt('user',USER)};bot_h={'Authorization':'Bearer '+jwt('bot',BOT)}
 readq='query($room:uuid!){messages(where:{room_id:{_eq:$room}}){id body room_id sender_id}}'
 # Existing user permissions: regular public read/write remains. Private ownership criterion is created_by in exported metadata.
 _,r=post('/v1/graphql',{'query':readq,'variables':{'room':PUBLIC}},user_h); check(len((r.get('data') or {}).get('messages') or [])==1,f'user public read changed: {r}')
 insert='mutation($room:uuid!,$body:String!){insert_messages(objects:[{room_id:$room,body:$body}]){affected_rows returning{id sender_id room_id}}}'
 _,r=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'user normal public post'}},user_h)
 rows=((r.get('data') or {}).get('insert_messages') or {}).get('returning') or [];check(len(rows)==1 and rows[0]['sender_id']==USER,'normal user public write was accidentally restricted')
 _,r=post('/v1/graphql',{'query':readq,'variables':{'room':PRIVATE_OWN}},user_h);check(len((r.get('data') or {}).get('messages') or [])==1,'user should see private room created by them')
 _,r=post('/v1/graphql',{'query':readq,'variables':{'room':NEWPRIV}},user_h);check(not (r.get('data') or {}).get('messages'),'user unexpectedly reads private room created by another')
 # Bot can read messages in all current and future rooms with the global switch on.
 for room,label in [(PUBLIC,'public room'),(PRIVATE_OWN,'private room'),(NEWPUB,'new public room'),(NEWPRIV,'new private room')]:
  _,b=post('/v1/graphql',{'query':readq,'variables':{'room':room}},bot_h); check(len((b.get('data') or {}).get('messages') or [])==1,f'Bot cannot read {label}: {b}')
 introspection='query { __type(name:"mutation_root") { fields { name } } }'
 _,schema=post('/v1/graphql',{'query':introspection},{'X-Hasura-Admin-Secret':ADMIN});fields=[f['name'] for f in (((schema.get('data') or {}).get('__type') or {}).get('fields') or [])]
 check('insert_messages' in fields,f'Hasura missing insert mutation: {fields}')
 _,r=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'ordinary Bot JWT must not post'}},bot_h);check(bool(r.get('errors')),'backend-only mutation visible to ordinary Bot JWT')
 trusted={'X-Hasura-Admin-Secret':ADMIN,'X-Hasura-Role':'bot','X-Hasura-User-Id':BOT,'X-Hasura-Use-Backend-Only-Permissions':'true'}
 _,schema=post('/v1/graphql',{'query':introspection},trusted);fields=[f['name'] for f in (((schema.get('data') or {}).get('__type') or {}).get('fields') or [])];check('insert_messages' in fields,'trusted backend-only mutation is not exposed')
 for room,label in [(PUBLIC,'public'),(PRIVATE_OWN,'private'),(NEWPUB,'new public'),(NEWPRIV,'new private')]:
  _,r=post('/v1/graphql',{'query':insert,'variables':{'room':room,'body':'synthetic Bot reply'}},trusted); rows=((r.get('data') or {}).get('insert_messages') or {}).get('returning') or []
  check(len(rows)==1 and rows[0]['sender_id']==BOT and rows[0]['room_id']==room,f'Bot cannot post safely in {label}: {r}')
 forged='mutation($room:uuid!,$body:String!,$sender:uuid!){insert_messages(objects:[{room_id:$room,body:$body,sender_id:$sender}]){affected_rows}}'
 _,r=post('/v1/graphql',{'query':forged,'variables':{'room':PRIVATE_OWN,'body':'forged','sender':USER}},trusted);check(bool(r.get('errors')),'client can forge sender_id')
 # Global switch off must prevent Bot reads and posts; normal users remain able to use public room.
 _,r=post('/v1/graphql',{'query':'mutation($id:uuid!){update_bot_settings_by_pk(pk_columns:{id:$id},_set:{enabled:false}){id enabled}}','variables':{'id':SETTINGS}},{'X-Hasura-Admin-Secret':ADMIN})
 check(not r.get('errors') and (r.get('data') or {}).get('update_bot_settings_by_pk',{}).get('enabled') is False,f'could not disable synthetic Bot: {r}')
 for room,label in [(PUBLIC,'public'),(PRIVATE_OWN,'private'),(NEWPUB,'new public'),(NEWPRIV,'new private')]:
  _,r=post('/v1/graphql',{'query':readq,'variables':{'room':room}},bot_h);check(not (r.get('data') or {}).get('messages'),f'Bot still reads {label} after global off')
 _,r=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'must stop'}},trusted);check(bool(r.get('errors')) or ((r.get('data') or {}).get('insert_messages') or {}).get('affected_rows',0)==0,'Bot posts after global off')
 _,r=post('/v1/graphql',{'query':insert,'variables':{'room':PUBLIC,'body':'user can still post publicly'}},user_h);check(not r.get('errors') and ((r.get('data') or {}).get('insert_messages') or {}).get('affected_rows')==1,'turning Bot off changed normal public user posting')
 print('PASS: modeled exported normal public read/write preserved; owner-based private behavior preserved')
 print('PASS: Bot reads and writes public/private/new rooms only while synthetic global switch is on')
 print('PASS: backend-only mutation hidden from ordinary JWT clients; server-set identity; forged sender rejected')
 print('PASS: global off stops Bot while ordinary public posting remains available')
 print('NOTE: fixture derived from exported metadata structure but still synthetic; not production Nhost/Auth/JWT/session integration')
if __name__=='__main__':main()
