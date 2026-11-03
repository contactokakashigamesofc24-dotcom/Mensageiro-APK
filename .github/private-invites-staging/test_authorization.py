#!/usr/bin/env python3
"""Ephemeral synthetic tests for private-room invitations and membership authorization."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080';ADMIN='ephemeral-admin-only-for-this-job';SECRET='ephemeral-private-invite-test-only-secret'
OWNER='40000000-0000-0000-0000-000000000001';MEMBER='40000000-0000-0000-0000-000000000002';PENDING='40000000-0000-0000-0000-000000000003';OUTSIDER='40000000-0000-0000-0000-000000000004'
ROOM='10000000-0000-0000-0000-000000000001';PUBLIC='10000000-0000-0000-0000-000000000002'
def b64(v):return base64.urlsafe_b64encode(v).rstrip(b'=').decode()
def jwt(role,uid):
 h=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode());c={'https://hasura.io/jwt/claims':{'x-hasura-allowed-roles':[role],'x-hasura-default-role':role,'x-hasura-user-id':uid}};p=b64(json.dumps(c).encode());m=f'{h}.{p}'.encode();return f'{h}.{p}.{b64(hmac.new(SECRET.encode(),m,hashlib.sha256).digest())}'
def post(path,obj,headers=None):
 req=urllib.request.Request(URL+path,data=json.dumps(obj).encode(),headers={'Content-Type':'application/json',**(headers or {})},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=15) as r:return r.status,json.loads(r.read().decode())
 except urllib.error.HTTPError as e:return e.code,json.loads(e.read().decode())
def meta(op,args):
 s,r=post('/v1/metadata',{'type':op,'args':args},{'X-Hasura-Admin-Secret':ADMIN})
 if s!=200:raise AssertionError(f'{op}: {r}')
def check(ok,msg):
 if not ok:raise AssertionError(msg)
def main():
 source={'name':'default','kind':'postgres','configuration':{'connection_info':{'database_url':{'from_env':'HASURA_GRAPHQL_DATABASE_URL'},'isolation_level':'read-committed','use_prepared_statements':True}},'tables':[]}
 s,r=post('/v1/metadata',{'type':'replace_metadata','args':{'version':3,'sources':[source]}},{'X-Hasura-Admin-Secret':ADMIN});check(s==200 and r.get('message')=='success',str(r))
 for name in ['rooms','room_members','messages','messenger_profiles','messenger_friend_requests']:
  meta('pg_track_table',{'source':'default','table':{'schema':'public','name':name}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'room_members','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_members'},'column':'room_id'}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by'],'filter':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'user','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 # The proposed private-user role differs only in private-room relation predicate: owner OR accepted membership.
 accepted={'_or':[{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'private_user_test','permission':{'columns':['id','title','room_type','created_by'],'filter':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'private_user_test','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 q='query($id:uuid!){messages(where:{room_id:{_eq:$id}}){id sender_id body}}';rq='query { rooms { id title room_type } }'
 def req(uid,role,query,vars=None):return post('/v1/graphql',{'query':query,'variables':vars or {}},{'Authorization':'Bearer '+jwt(role,uid)})[1]
 # Compare current exported policy: owner sees own private room/messages, other users do not.
 old_owner=req(OWNER,'user',q,{'id':ROOM});check(len((old_owner.get('data') or {}).get('messages') or [])>=1,'old policy owner lost access')
 for uid in [MEMBER,PENDING,OUTSIDER]:
  r=req(uid,'user',q,{'id':ROOM});check(not r.get('errors') and len((r.get('data') or {}).get('messages') or [])==0,f'old exported filter unexpectedly grants private access {uid}: {r}')
 # Candidate policy should give owner + accepted member access, but deny pending invitee and outsider despite UUID known.
 for uid,role,allowed,label in [(OWNER,'private_user_test',True,'owner'),(MEMBER,'private_user_test',True,'accepted member'),(PENDING,'private_user_test',False,'pending invitee'),(OUTSIDER,'private_user_test',False,'outsider')]:
  r=req(uid,role,q,{'id':ROOM});rows=(r.get('data') or {}).get('messages') or [];check((len(rows)>0)==allowed,f'candidate message filter wrong for {label}: {r}')
  rooms=req(uid,role,rq); visible=(rooms.get('data') or {}).get('rooms') or [];listed=any(x['id']==ROOM for x in visible);check(listed==allowed,f'candidate room listing wrong for {label}: {rooms}')
 # Existing public room read and public posting stay available to ordinary role.
 r=req(OUTSIDER,'user',q,{'id':PUBLIC});check(len((r.get('data') or {}).get('messages') or [])==1,'public history changed')
 ins='mutation($room:uuid!,$body:String!){insert_messages(objects:[{room_id:$room,body:$body}]){affected_rows returning{sender_id}}}'
 r=req(OUTSIDER,'user',ins,{'room':PUBLIC,'body':'still allowed synthetic public post'});rows=((r.get('data') or {}).get('insert_messages') or {}).get('returning') or [];check(len(rows)==1 and rows[0]['sender_id']==OUTSIDER,'normal public posting was changed')
 # Ensure client cannot directly add/accept membership; no insert/update permission on room_members.
 forged='mutation($room:uuid!,$uid:uuid!){insert_room_members_one(object:{room_id:$room,user_id:$uid,invited_by:$uid}){room_id}}'
 r=req(OWNER,'user',forged,{'room':ROOM,'uid':OUTSIDER});check(bool(r.get('errors')),'client could directly forge room membership')
 print('PASS: current exported private message policy owner-only reproduced; accepted member denied')
 print('PASS: candidate policy grants owner and accepted member, denies pending/outsider for known UUID')
 print('PASS: existing public read/write remains available; direct client membership insert denied')
 print('NOTE: no invite/accept SECURITY DEFINER functions installed or invoked in this fixture; not production validation')
if __name__=='__main__':main()
