#!/usr/bin/env python3
"""Ephemeral synthetic tests for private-room invitations and membership authorization."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080';ADMIN='ephemeral-private-invite-test-admin';SECRET='ephemeral-private-invite-test-only-secret'
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
 for name in ['rooms','room_members','messages','messenger_profiles','messenger_friend_requests','private_invite_results','private_accepted_room_results','private_owner_member_results','private_room_results','message_result']:
  meta('pg_track_table',{'source':'default','table':{'schema':'public','name':name}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'room_members','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_members'},'column':'room_id'}}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'private_room_results'},'name':'room_members','using':{'manual_configuration':{'remote_table':{'schema':'public','name':'room_members'},'column_mapping':{'id':'room_id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by'],'filter':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'user','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 # The proposed private-user role differs only in private-room relation predicate: owner OR accepted membership.
 accepted={'_or':[{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'private_user_test','permission':{'columns':['id','title','room_type','created_by'],'filter':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 # Candidate role's direct insert permissions mirror the APK's insert_rooms_one / insert_messages_one shapes.
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'private_user_test','permission':{'check':{'room_type':{'_eq':'private'}},'set':{'created_by':'X-Hasura-User-Id'},'columns':['title','room_type']}})
 # The preceding private_user_test messages insert permission already represents the exact direct APK insert shape.
 # These function permissions are applied only to the isolated Hasura instance.
 for fn in ['invite_room_member_by_email','accept_private_room_invite','my_pending_private_invites','my_accepted_private_rooms','owner_room_members','create_private_room_candidate','send_private_message_candidate','my_owned_private_rooms_candidate']:
  meta('pg_track_function',{'source':'default','function':{'schema':'public','name':fn},'configuration':{'session_argument':'hasura_session'}})
  meta('pg_create_function_permission',{'source':'default','function':fn,'role':'user'})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messenger_profiles'},'role':'user','permission':{'columns':['user_id','display_name'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messenger_friend_requests'},'role':'user','permission':{'columns':['requester_id','recipient_id','status'],'filter':{'$or':[{'requester_id':{'_eq':'X-Hasura-User-Id'}},{'recipient_id':{'_eq':'X-Hasura-User-Id'}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_invite_results'},'role':'user','permission':{'columns':['invitee_id','room_id','room_title','inviter_id','invited_at'],'filter':{'invitee_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_accepted_room_results'},'role':'user','permission':{'columns':['member_id','room_id','room_title','owner_id','joined_at'],'filter':{'member_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_owner_member_results'},'role':'user','permission':{'columns':['owner_id','room_id','user_id','invited_by','accepted_at','invited_at'],'filter':{'owner_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_room_results'},'role':'user','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'created_by':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_room_results'},'role':'private_user_test','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'message_result'},'role':'user','permission':{'columns':['id','sender_id'],'filter':{'sender_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'message_result'},'role':'private_user_test','permission':{'columns':['id','sender_id'],'filter':{'sender_id':{'_eq':'X-Hasura-User-Id'}}}})
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
 # Candidate private posting permits an accepted member, while pending and outsider are denied.
 r=req(MEMBER,'private_user_test',ins,{'room':ROOM,'body':'accepted member synthetic private post'});rows=((r.get('data') or {}).get('insert_messages') or {}).get('returning') or [];check(len(rows)==1 and rows[0]['sender_id']==MEMBER,'accepted member could not post to private room')
 for uid,label in [(PENDING,'pending invitee'),(OUTSIDER,'outsider')]:
  r=req(uid,'private_user_test',ins,{'room':ROOM,'body':'should be rejected'});check(bool(r.get('errors')) or not ((r.get('data') or {}).get('insert_messages') or {}).get('returning'),f'{label} posted to private room')
 # Repeat invite for an already accepted member: keep the existing accepted membership.
 invite='mutation($room:uuid!,$email:String!){invite_room_member_by_email(args:{p_room_id:$room,p_email:$email}){id}}'
 r=req(OWNER,'user',invite,{'room':ROOM,'email':'accepted@example.test'});check(not r.get('errors'),f're-invite accepted member failed: {r}')
 memq='query($room:uuid!){room_members(where:{room_id:{_eq:$room}}){room_id user_id accepted_at}}'
 r=req(MEMBER,'user',memq,{'room':ROOM});members=(r.get('data') or {}).get('room_members') or [];check(len(members)==1 and members[0]['accepted_at'] is not None,'re-invite reset accepted membership or duplicated it')
 # The list functions are Hasura-trackable SETOF views and must scope rows to injected session claims.
 acceptedq='query { my_accepted_private_rooms { room_id room_title owner_id joined_at } }'
 r=req(MEMBER,'user',acceptedq);rows=(r.get('data') or {}).get('my_accepted_private_rooms') or [];check(any(x['room_id']==ROOM for x in rows),'accepted member room list missing their room')
 r=req(OUTSIDER,'user',acceptedq);rows=(r.get('data') or {}).get('my_accepted_private_rooms') or [];check(not rows,'outsider saw accepted private rooms')
 pendingq='query { my_pending_private_invites { room_id room_title inviter_id invited_at } }'
 r=req(OUTSIDER,'user',pendingq);rows=(r.get('data') or {}).get('my_pending_private_invites') or [];check(not rows,'outsider saw another user pending invitation')
 # Hasura must keep injected session argument out of caller-supplied GraphQL args.
 forged_session='query { my_accepted_private_rooms(hasura_session:{"x-hasura-role":"user","x-hasura-user-id":"'+OWNER+'"}) { room_id } }'
 r=req(OUTSIDER,'user',forged_session);check(bool(r.get('errors')),'caller supplied the injected Hasura session argument')
 membersq='query($room:uuid!){owner_room_members(args:{p_room_id:$room}){user_id accepted_at}}'
 r=req(OWNER,'user',membersq,{'room':ROOM});rows=(r.get('data') or {}).get('owner_room_members') or [];check(len(rows)==2,'owner roster did not return expected synthetic members')
 r=req(OUTSIDER,'user',membersq,{'room':ROOM});check(bool(r.get('errors')),'outsider accessed owner roster')
 # Exercise the invite function against the second synthetic private room using its session_argument.
 invite='mutation($room:uuid!,$email:String!){invite_room_member_by_email(args:{p_room_id:$room,p_email:$email}){id}}'
 r=req(OWNER,'user',invite,{'room':'10000000-0000-0000-0000-000000000003','email':'pending@example.test'});check(not r.get('errors') and len((r.get('data') or {}).get('invite_room_member_by_email') or [])==1,f'owner invite failed: {r}')
 # Repeating invite must remain idempotent.
 r=req(OWNER,'user',invite,{'room':'10000000-0000-0000-0000-000000000003','email':'pending@example.test'});check(not r.get('errors'),f're-invite failed: {r}')
 # Negative invitation cases: non-owner, unverified account, non-friend, self, and invalid address.
 for uid,room,email,label in [(MEMBER,ROOM,'outsider@example.test','non-owner'),(OWNER,'10000000-0000-0000-0000-000000000003','unverified@example.test','unverified account'),(OWNER,'10000000-0000-0000-0000-000000000003','notfriend@example.test','non-friend'),(OWNER,'10000000-0000-0000-0000-000000000003','owner@example.test','self invite'),(OWNER,'10000000-0000-0000-0000-000000000003','bad','invalid email')]:
  r=req(uid,'user',invite,{'room':room,'email':email});check(bool(r.get('errors')),f'{label} invitation unexpectedly succeeded')
 # Anonymous callers cannot invoke owner invite.
 anon=post('/v1/graphql',{'query':invite,'variables':{'room':ROOM,'email':'outsider@example.test'}})[1];check(bool(anon.get('errors')),'anonymous caller unexpectedly invoked invite')
 # A non-owner cannot inspect the owner-only member list.
 membersq='query($room:uuid!){owner_room_members(args:{p_room_id:$room}){user_id accepted_at}}'
 r=req(MEMBER,'user',membersq,{'room':ROOM});check(bool(r.get('errors')),'non-owner read room member list')
 pendingq='query { my_pending_private_invites { room_id room_title inviter_id invited_at } }'
 r=req(PENDING,'user',pendingq);pending_rows=(r.get('data') or {}).get('my_pending_private_invites') or [];check(any(x['room_id']=='10000000-0000-0000-0000-000000000003' for x in pending_rows),f'pending invite missing: {r}')
 # Pending invitee cannot read private history before acceptance, even with the room UUID.
 r=req(PENDING,'private_user_test',q,{'id':'10000000-0000-0000-0000-000000000003'});check(not (r.get('data') or {}).get('messages'),'pending invitee read before accepting')
 # Outsider cannot accept another user's invitation.
 accept='mutation($room:uuid!){accept_private_room_invite(args:{p_room_id:$room}){room_id accepted_at}}'
 r=req(OUTSIDER,'user',accept,{'room':'10000000-0000-0000-0000-000000000003'});check(bool(r.get('errors')),'outsider accepted an invitation')
 # Invitee accepts; access begins, pending item disappears, and re-accept by outsider remains denied.
 r=req(PENDING,'user',accept,{'room':'10000000-0000-0000-0000-000000000003'});check(not r.get('errors') and len((r.get('data') or {}).get('accept_private_room_invite') or [])==1,f'accept failed: {r}')
 r=req(PENDING,'user',pendingq);check(not any(x['room_id']=='10000000-0000-0000-0000-000000000003' for x in ((r.get('data') or {}).get('my_pending_private_invites') or [])),'accepted invite still pending')
 acceptedq='query { my_accepted_private_rooms { room_id room_title owner_id joined_at } }'
 r=req(PENDING,'user',acceptedq);check(any(x['room_id']=='10000000-0000-0000-0000-000000000003' for x in ((r.get('data') or {}).get('my_accepted_private_rooms') or [])),f'accepted room missing: {r}')
 r=req(PENDING,'private_user_test',q,{'id':'10000000-0000-0000-0000-000000000003'});check(len((r.get('data') or {}).get('messages') or [])==0,'new empty accepted room unexpectedly contains messages')
 # Exercise the exact direct insert GraphQL field/argument shapes currently used by the APK.
 apk_create='mutation($object:rooms_insert_input!){insert_rooms_one(object:$object){id title room_type created_by}}'
 r=req(OWNER,'private_user_test',apk_create,{'object':{'title':'Synthetic APK-created private room','room_type':'private'}});created=((r.get('data') or {}).get('insert_rooms_one') or {});check(created.get('room_type')=='private' and created.get('created_by')==OWNER,f'APK insert_rooms_one failed for owner: {r}');apk_room=created['id']
 r=req(OUTSIDER,'private_user_test',apk_create,{'object':{'title':'Forged public room','room_type':'public'}});check(bool(r.get('errors')) or not (r.get('data') or {}).get('insert_rooms_one'),'APK insert_rooms_one created a public room through private role')
 apk_send='mutation($object:messages_insert_input!){insert_messages_one(object:$object){id sender_id}}'
 r=req(MEMBER,'private_user_test',apk_send,{'object':{'room_id':ROOM,'body':'Accepted member through exact APK insert'}});posted=((r.get('data') or {}).get('insert_messages_one') or {});check(posted.get('sender_id')==MEMBER,f'APK insert_messages_one failed for accepted member: {r}')
 for uid,label in [(PENDING,'pending invitee'),(OUTSIDER,'outsider')]:
  r=req(uid,'private_user_test',apk_send,{'object':{'room_id':ROOM,'body':'Should be rejected'}});check(bool(r.get('errors')) or not (r.get('data') or {}).get('insert_messages_one'),f'{label} used APK insert_messages_one in private room')
 # Exercise candidate replacements for private-room creation/listing and private message sending.
 createq='mutation($title:String!){create_private_room_candidate(args:{p_title:$title}){id title room_type created_by created_at}}'
 r=req(OWNER,'user',createq,{'title':'Synthetic created private room'});created=((r.get('data') or {}).get('create_private_room_candidate') or []);check(len(created)==1 and created[0]['room_type']=='private' and created[0]['created_by']==OWNER,f'private room creation failed: {r}');new_room=created[0]['id']
 r=req(OUTSIDER,'user',createq,{'title':'   '});check(bool(r.get('errors')),'empty private room title accepted')
 ownedq='query { my_owned_private_rooms_candidate { id title created_by } }'
 r=req(OWNER,'user',ownedq);rows=(r.get('data') or {}).get('my_owned_private_rooms_candidate') or [];check(any(x['id']==new_room for x in rows),'owner room list omitted newly created room')
 r=req(OUTSIDER,'user',ownedq);rows=(r.get('data') or {}).get('my_owned_private_rooms_candidate') or [];check(not rows,'outsider saw owner private rooms')
 sendq='mutation($room:uuid!,$body:String!){send_private_message_candidate(args:{p_room_id:$room,p_body:$body}){id sender_id}}'
 r=req(MEMBER,'user',sendq,{'room':ROOM,'body':'accepted member via function'});sent=((r.get('data') or {}).get('send_private_message_candidate') or []);check(len(sent)==1 and sent[0]['sender_id']==MEMBER,f'accepted private message mutation failed: {r}')
 for uid,label in [(PENDING,'pending invitee'),(OUTSIDER,'outsider')]:
  r=req(uid,'user',sendq,{'room':ROOM,'body':'denied function message'});check(bool(r.get('errors')),f'{label} sent private function message')
 r=req(OWNER,'user',sendq,{'room':PUBLIC,'body':'public not allowed via private function'});check(bool(r.get('errors')),'private-message function accepted a public room')
 r=req(OWNER,'user',sendq,{'room':ROOM,'body':'   '});check(bool(r.get('errors')),'empty message body accepted')
 # Ensure client cannot directly add/accept membership; no insert permission on room_members.
 forged='mutation($room:uuid!,$uid:uuid!){insert_room_members_one(object:{room_id:$room,user_id:$uid,invited_by:$uid}){room_id}}'
 r=req(OWNER,'user',forged,{'room':ROOM,'uid':OUTSIDER});check(bool(r.get('errors')),'client could directly forge room membership')
 print('PASS: current exported private message policy owner-only reproduced; accepted member denied')
 print('PASS: candidate policy grants owner and accepted member, denies pending/outsider for known UUID')
 print('PASS: invite is owner-only and idempotent; pending has no history; accept grants membership')
 print('PASS: public read/write remains; direct client membership insertion denied')
 print('NOTE: synthetic ephemeral database and JWT only; no production Nhost/Auth/app test')
if __name__=='__main__':main()
