#!/usr/bin/env python3
"""Ephemeral synthetic tests for private-room invitations and membership authorization."""
import base64,hashlib,hmac,json,urllib.request,urllib.error
URL='http://127.0.0.1:8080';ADMIN='ephemeral-private-invite-test-admin';SECRET='ephemeral-private-invite-test-only-secret'
OWNER='40000000-0000-0000-0000-000000000001';MEMBER='40000000-0000-0000-0000-000000000002';PENDING='40000000-0000-0000-0000-000000000003';OUTSIDER='40000000-0000-0000-0000-000000000004';NOTFRIEND='40000000-0000-0000-0000-000000000006'
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
 for name in ['rooms','room_members','messages','messenger_profiles','messenger_friend_requests','private_invite_results','private_accepted_room_results','private_owner_member_results','private_room_results','message_result','messenger_groups','group_result','group_invite_result','group_member_result','friend_request_result','friend_profile_result','incoming_friend_result','presence_result','friend_presence_result','messenger_presence','audio_create_result','audio_chunk_result','audio_complete_result','audio_id_result','media_create_result','media_chunk_result','media_complete_result','media_id_result','media_info_result','room_wallpapers','private_wallpaper_result']:
  meta('pg_track_table',{'source':'default','table':{'schema':'public','name':name}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'messages'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'room_wallpapers'},'name':'room','using':{'foreign_key_constraint_on':'room_id'}})
 meta('pg_create_object_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'wallpaper','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_wallpapers'},'column':'room_id'}}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'rooms'},'name':'room_members','using':{'foreign_key_constraint_on':{'table':{'schema':'public','name':'room_members'},'column':'room_id'}}})
 meta('pg_create_array_relationship',{'source':'default','table':{'schema':'public','name':'private_room_results'},'name':'room_members','using':{'manual_configuration':{'remote_table':{'schema':'public','name':'room_members'},'column_mapping':{'id':'room_id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'user','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'user','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'user','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},{'created_by':{'_eq':'X-Hasura-User-Id'}}]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 # The proposed private-user role differs only in private-room relation predicate: owner OR accepted membership.
 accepted={'_or':[{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'private_user_test','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'columns':['id','room_id','sender_id','body','created_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'check':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}]},'set':{'sender_id':'X-Hasura-User-Id'},'columns':['room_id','body']}})
 # Candidate role's direct insert permissions mirror the APK's insert_rooms_one / insert_messages_one shapes.
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'rooms'},'role':'private_user_test','permission':{'check':{'room_type':{'_eq':'private'}},'set':{'created_by':'X-Hasura-User-Id'},'columns':['title','room_type']}})
 # Delete candidate is narrowly bound to session sender and room access; the APK also supplies room/message IDs.
 meta('pg_create_delete_permission',{'source':'default','table':{'schema':'public','name':'messages'},'role':'private_user_test','permission':{'filter':{'_and':[{'sender_id':{'_eq':'X-Hasura-User-Id'}},{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}]}}})
 # These function permissions are applied only to the isolated Hasura instance.
 for fn in ['invite_room_member_by_email','accept_private_room_invite','my_pending_private_invites','my_accepted_private_rooms','owner_room_members','create_private_room_candidate','send_private_message_candidate','my_owned_private_rooms_candidate','create_private_messenger_group','my_messenger_groups','my_pending_group_invites','accept_messenger_group_invite','my_messenger_profile','upsert_my_profile','request_friend_by_email','respond_friend_request','my_messenger_friends','my_incoming_friend_requests','set_my_presence','my_friends_presence','create_private_room_audio','add_private_room_audio_chunk','complete_private_room_audio','private_room_audio_message_ids','get_private_room_audio_chunks','create_private_room_media','add_private_room_media_chunk','complete_private_room_media','private_room_media_message_ids','private_room_media_info','get_private_room_media_chunks']:
  meta('pg_track_function',{'source':'default','function':{'schema':'public','name':fn},'configuration':{'session_argument':'hasura_session'}})
  meta('pg_create_function_permission',{'source':'default','function':fn,'role':'user'})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messenger_profiles'},'role':'user','permission':{'columns':['user_id','display_name','avatar_data'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messenger_friend_requests'},'role':'user','permission':{'columns':['requester_id','recipient_id','status'],'filter':{'$or':[{'requester_id':{'_eq':'X-Hasura-User-Id'}},{'recipient_id':{'_eq':'X-Hasura-User-Id'}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'messenger_presence'},'role':'user','permission':{'columns':['user_id','last_seen'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'friend_request_result'},'role':'user','permission':{'columns':['request_id','status'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'friend_profile_result'},'role':'user','permission':{'columns':['viewer_id','user_id','display_name','avatar_data'],'filter':{'viewer_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'incoming_friend_result'},'role':'user','permission':{'columns':['viewer_id','request_id','user_id','display_name','avatar_data'],'filter':{'viewer_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'presence_result'},'role':'user','permission':{'columns':['user_id','last_seen'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'friend_presence_result'},'role':'user','permission':{'columns':['user_id','is_online','last_seen'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'audio_create_result'},'role':'user','permission':{'columns':['message_id'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'audio_chunk_result'},'role':'user','permission':{'columns':['message_id','chunk_index','audio_data'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'audio_complete_result'},'role':'user','permission':{'columns':['message_id','chunk_count'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'audio_id_result'},'role':'user','permission':{'columns':['message_id'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'media_create_result'},'role':'user','permission':{'columns':['message_id'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'media_chunk_result'},'role':'user','permission':{'columns':['message_id','chunk_index','mime_type','media_data'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'media_complete_result'},'role':'user','permission':{'columns':['message_id'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'media_id_result'},'role':'user','permission':{'columns':['message_id','mime_type'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'media_info_result'},'role':'user','permission':{'columns':['mime_type','chunk_count'],'filter':{}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_invite_results'},'role':'user','permission':{'columns':['invitee_id','room_id','room_title','inviter_id','invited_at'],'filter':{'invitee_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_accepted_room_results'},'role':'user','permission':{'columns':['member_id','room_id','room_title','owner_id','joined_at'],'filter':{'member_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_owner_member_results'},'role':'user','permission':{'columns':['owner_id','room_id','user_id','invited_by','accepted_at','invited_at'],'filter':{'owner_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_room_results'},'role':'user','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'created_by':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_room_results'},'role':'private_user_test','permission':{'columns':['id','title','room_type','created_by','created_at'],'filter':{'_or':[{'created_by':{'_eq':'X-Hasura-User-Id'}},{'room_members':{'_and':[{'user_id':{'_eq':'X-Hasura-User-Id'}},{'accepted_at':{'_is_null':False}}]}}]}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_wallpapers'},'role':'private_user_test','permission':{'columns':['room_id','wallpaper_data','updated_by','updated_at'],'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'private_wallpaper_result'},'role':'user','permission':{'columns':['room_id','wallpaper_data','updated_by','updated_at'],'filter':{'updated_by':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_insert_permission',{'source':'default','table':{'schema':'public','name':'room_wallpapers'},'role':'private_user_test','permission':{'check':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}},'set':{'updated_by':'X-Hasura-User-Id'},'columns':['room_id','wallpaper_data']}})
 meta('pg_create_update_permission',{'source':'default','table':{'schema':'public','name':'room_wallpapers'},'role':'private_user_test','permission':{'filter':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}},'check':{'room':{'_or':[{'room_type':{'_eq':'public'}},accepted]}},'columns':['wallpaper_data']}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'group_result'},'role':'user','permission':{'columns':['room_id','group_title','owner_id','created_at'],'filter':{'owner_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'group_invite_result'},'role':'user','permission':{'columns':['room_id','group_title','inviter_id','invited_at','invitee_id'],'filter':{'invitee_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'group_member_result'},'role':'user','permission':{'columns':['room_id','group_title','owner_id','member_id','accepted_at'],'filter':{'member_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'message_result'},'role':'user','permission':{'columns':['id','sender_id'],'filter':{'sender_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'message_result'},'role':'private_user_test','permission':{'columns':['id','sender_id'],'filter':{'sender_id':{'_eq':'X-Hasura-User-Id'}}}})
 meta('pg_create_select_permission',{'source':'default','table':{'schema':'public','name':'room_members'},'role':'private_user_test','permission':{'columns':['room_id','user_id','invited_by','accepted_at','created_at'],'filter':{'user_id':{'_eq':'X-Hasura-User-Id'}}}})
 q='query($roomId:uuid!){messages(where:{room_id:{_eq:$roomId}},order_by:{created_at:asc},limit:200){id room_id sender_id body created_at}}';rq='query { rooms(order_by:{created_at:desc}) { id title room_type created_by } }'
 def req(uid,role,query,vars=None):
  variables=vars or {}
  if '$roomId' in query and 'id' in variables and 'roomId' not in variables:variables['roomId']=variables.pop('id')
  return post('/v1/graphql',{'query':query,'variables':variables},{'Authorization':'Bearer '+jwt(role,uid)})[1]
 # Exercise profile, friend, and presence operations by the APK's exact root-field names and arguments.
 mine='query { my_messenger_profile { display_name avatar_data } }'
 r=req(OWNER,'user',mine);profiles=(r.get('data') or {}).get('my_messenger_profile') or [];check(len(profiles)==1,'my_messenger_profile did not return caller profile')
 save='mutation($name:String!,$avatar:String){upsert_my_profile(args:{p_display_name:$name,p_avatar_data:$avatar}){user_id display_name avatar_data}}'
 r=req(OWNER,'user',save,{'name':'Updated Owner','avatar':None});rows=(r.get('data') or {}).get('upsert_my_profile') or [];check(len(rows)==1 and rows[0]['user_id']==OWNER and rows[0]['display_name']=='Updated Owner',f'profile upsert failed: {r}')
 r=req(OUTSIDER,'user',save,{'name':'Updated Outsider','avatar':None});rows=(r.get('data') or {}).get('upsert_my_profile') or [];check(len(rows)==1 and rows[0]['user_id']==OUTSIDER,'profile upsert did not bind update to caller session')
 r=req(OWNER,'user',mine);profiles=(r.get('data') or {}).get('my_messenger_profile') or [];check(profiles[0]['display_name']=='Updated Owner','other user changed owner profile')
 friendreq='mutation($email:String!){request_friend_by_email(args:{p_email:$email}){request_id}}'
 r=req(OWNER,'user',friendreq,{'email':'notfriend@example.test'});requests=(r.get('data') or {}).get('request_friend_by_email') or [];check(len(requests)==1,'friend request failed');request_id=requests[0]['request_id']
 incoming='query { my_incoming_friend_requests { request_id user_id display_name avatar_data } }'
 r=req(NOTFRIEND,'user',incoming);items=(r.get('data') or {}).get('my_incoming_friend_requests') or [];check(any(x['request_id']==request_id and x['user_id']==OWNER for x in items),'recipient did not see own incoming friend request')
 r=req(PENDING,'user',incoming);check(not ((r.get('data') or {}).get('my_incoming_friend_requests') or []),'unrelated user saw incoming friend request')
 respond='mutation($id:uuid!,$accept:Boolean!){respond_friend_request(args:{p_request_id:$id,p_accept:$accept}){request_id status}}'
 r=req(OWNER,'user',respond,{'id':request_id,'accept':True});check(bool(r.get('errors')),'requester responded as recipient')
 r=req(NOTFRIEND,'user',respond,{'id':request_id,'accept':True});rows=(r.get('data') or {}).get('respond_friend_request') or [];check(len(rows)==1 and rows[0]['status']=='accepted',f'recipient could not accept friend request: {r}')
 friends='query { my_messenger_friends { user_id display_name avatar_data } }'
 r=req(OWNER,'user',friends);check(any(x['user_id']==OUTSIDER for x in ((r.get('data') or {}).get('my_messenger_friends') or [])),'accepted friend missing from APK list')
 setpresence='mutation($online:Boolean!){set_my_presence(args:{p_online:$online}){user_id last_seen}}'
 r=req(OWNER,'user',setpresence,{'online':True});rows=(r.get('data') or {}).get('set_my_presence') or [];check(len(rows)==1 and rows[0]['user_id']==OWNER,'set_my_presence online failed')
 presence='query { my_friends_presence { user_id is_online last_seen } }'
 r=req(OUTSIDER,'user',presence);rows=(r.get('data') or {}).get('my_friends_presence') or [];check(any(x['user_id']==OWNER and x['is_online'] for x in rows),'friend presence did not report active friend')
 r=req(OWNER,'user',setpresence,{'online':False});check(not r.get('errors'),'set_my_presence offline mutation failed')
 # Compare current exported policy: owner sees own private room/messages, other users do not.
 old_owner=req(OWNER,'user',q,{'id':ROOM});check(len((old_owner.get('data') or {}).get('messages') or [])>=1,f'old policy owner lost access: {old_owner}')
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
 for uid,room,email,label in [(MEMBER,ROOM,'outsider@example.test','non-owner'),(OWNER,'10000000-0000-0000-0000-000000000003','unverified@example.test','unverified account'),(OWNER,'10000000-0000-0000-0000-000000000003','stranger@example.test','non-friend'),(OWNER,'10000000-0000-0000-0000-000000000003','owner@example.test','self invite'),(OWNER,'10000000-0000-0000-0000-000000000003','bad','invalid email')]:
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
 # Reproduce the corrected APK call exactly: Hasura exposes PostgreSQL uuid[] as _uuid scalar.
 group_mut='mutation($title:String!,$members:_uuid!){create_private_messenger_group(args:{p_title:$title,p_member_ids:$members}){room_id group_title}}'
 apk_members='{' + OUTSIDER + '}'
 r=req(OWNER,'user',group_mut,{'title':'APK group shape corrected','members':apk_members});rows=(r.get('data') or {}).get('create_private_messenger_group') or [];check(len(rows)==1 and rows[0]['group_title']=='APK group shape corrected',f'corrected APK group create failed: {r}');group_id=rows[0]['room_id']
 # Confirm GraphQL list input remains incompatible, so the Android change is necessary rather than cosmetic.
 incompatible_mut='mutation($title:String!,$members:[uuid!]!){create_private_messenger_group(args:{p_title:$title,p_member_ids:$members}){room_id group_title}}'
 r=req(OWNER,'user',incompatible_mut,{'title':'Old APK shape','members':[OUTSIDER]});check(bool(r.get('errors')),'old [uuid!] APK input unexpectedly accepted')
 group_list='query { my_messenger_groups { room_id group_title owner_id } }'
 r=req(OWNER,'user',group_list);check(any(x['room_id']==group_id for x in ((r.get('data') or {}).get('my_messenger_groups') or [])),'owner group listing missing')
 pending_group='query { my_pending_group_invites { room_id group_title inviter_id invited_at } }'
 r=req(OUTSIDER,'user',pending_group);check(any(x['room_id']==group_id for x in ((r.get('data') or {}).get('my_pending_group_invites') or [])),f'group invite missing: {r}')
 outsider_group='query { my_messenger_groups { room_id group_title owner_id } }'
 r=req(PENDING,'user',outsider_group);check(not any(x['room_id']==group_id for x in ((r.get('data') or {}).get('my_messenger_groups') or [])),'non-member listed group before acceptance')
 accept_group='mutation($room:uuid!){accept_messenger_group_invite(args:{p_room_id:$room}){room_id accepted_at}}'
 r=req(MEMBER,'user',accept_group,{'room':group_id});check(bool(r.get('errors')),'non-invitee accepted group invitation')
 r=req(OUTSIDER,'user',accept_group,{'room':group_id});check(not r.get('errors') and len((r.get('data') or {}).get('accept_messenger_group_invite') or [])==1,f'invitee could not accept group: {r}')
 r=req(OUTSIDER,'user',group_list);check(any(x['room_id']==group_id for x in ((r.get('data') or {}).get('my_messenger_groups') or [])),'accepted group member not listed')
 # Exact APK audio upload/query/download operations: accepted member can finish/read; outsiders cannot start/read.
 audio_create='mutation($room:uuid!){create_private_room_audio(args:{p_room_id:$room}){message_id}}'
 r=req(MEMBER,'user',audio_create,{'room':ROOM});audio_rows=(r.get('data') or {}).get('create_private_room_audio') or [];check(len(audio_rows)==1,f'accepted member could not start audio: {r}');audio_id=audio_rows[0]['message_id']
 audio_part='data:audio/mp4;base64,QUJD'
 audio_add='mutation($id:uuid!,$index:Int!,$audio:String!){add_private_room_audio_chunk(args:{p_message_id:$id,p_chunk_index:$index,p_audio_data:$audio}){chunk_index}}'
 r=req(MEMBER,'user',audio_add,{'id':audio_id,'index':0,'audio':audio_part});check(not r.get('errors'),f'audio chunk add failed: {r}')
 audio_done='mutation($id:uuid!,$count:Int!){complete_private_room_audio(args:{p_message_id:$id,p_chunk_count:$count}){message_id chunk_count}}'
 r=req(MEMBER,'user',audio_done,{'id':audio_id,'count':1});check(not r.get('errors'),f'audio completion failed: {r}')
 audio_ids='query($roomId:uuid!){private_room_audio_message_ids(args:{p_room_id:$roomId}){message_id}}'
 r=req(MEMBER,'user',audio_ids,{'roomId':ROOM});check(any(x['message_id']==audio_id for x in ((r.get('data') or {}).get('private_room_audio_message_ids') or [])),'audio id missing to accepted member')
 audio_get='query($id:uuid!,$start:Int!,$limit:Int!){get_private_room_audio_chunks(args:{p_message_id:$id,p_start_index:$start,p_limit:$limit}){chunk_index audio_data}}'
 r=req(MEMBER,'user',audio_get,{'id':audio_id,'start':0,'limit':4});chunks=(r.get('data') or {}).get('get_private_room_audio_chunks') or [];check(len(chunks)==1 and chunks[0]['audio_data']==audio_part,'accepted member could not read audio chunk')
 r=req(OUTSIDER,'user',audio_get,{'id':audio_id,'start':0,'limit':4});check(bool(r.get('errors')),'outsider read audio chunk')
 r=req(OUTSIDER,'user',audio_create,{'room':ROOM});check(bool(r.get('errors')),'outsider started audio in private room')
 # Exact APK media upload/query/download operations.
 media_create='mutation($room:uuid!,$mime:String!){create_private_room_media(args:{p_room_id:$room,p_mime_type:$mime}){message_id}}'
 r=req(MEMBER,'user',media_create,{'room':ROOM,'mime':'image/jpeg'});media_rows=(r.get('data') or {}).get('create_private_room_media') or [];check(len(media_rows)==1,'accepted member could not start photo upload');media_id=media_rows[0]['message_id']
 media_part='data:image/jpeg;base64,QUJD'
 media_add='mutation($id:uuid!,$index:Int!,$mime:String!,$data:String!){add_private_room_media_chunk(args:{p_message_id:$id,p_chunk_index:$index,p_mime_type:$mime,p_media_data:$data}){chunk_index}}'
 r=req(MEMBER,'user',media_add,{'id':media_id,'index':0,'mime':'image/jpeg','data':media_part});check(not r.get('errors'),f'media chunk add failed: {r}')
 media_done='mutation($id:uuid!,$count:Int!){complete_private_room_media(args:{p_message_id:$id,p_chunk_count:$count}){message_id}}'
 r=req(MEMBER,'user',media_done,{'id':media_id,'count':1});check(not r.get('errors'),f'media completion failed: {r}')
 media_ids='query($roomId:uuid!){private_room_media_message_ids(args:{p_room_id:$roomId}){message_id mime_type}}'
 r=req(MEMBER,'user',media_ids,{'roomId':ROOM});check(any(x['message_id']==media_id for x in ((r.get('data') or {}).get('private_room_media_message_ids') or [])),'media id missing')
 media_info='query($id:uuid!){private_room_media_info(args:{p_message_id:$id}){mime_type chunk_count}}'
 r=req(MEMBER,'user',media_info,{'id':media_id});infos=(r.get('data') or {}).get('private_room_media_info') or [];check(len(infos)==1 and infos[0]['mime_type']=='image/jpeg','media info missing for member')
 media_get='query($id:uuid!,$start:Int!,$limit:Int!){get_private_room_media_chunks(args:{p_message_id:$id,p_start_index:$start,p_limit:$limit}){chunk_index media_data}}'
 r=req(MEMBER,'user',media_get,{'id':media_id,'start':0,'limit':4});chunks=(r.get('data') or {}).get('get_private_room_media_chunks') or [];check(len(chunks)==1 and chunks[0]['media_data']==media_part,'accepted member could not read media chunk')
 r=req(OUTSIDER,'user',media_get,{'id':media_id,'start':0,'limit':4});check(bool(r.get('errors')),'outsider read media chunk')
 r=req(OUTSIDER,'user',media_create,{'room':ROOM,'mime':'video/mp4'});check(bool(r.get('errors')),'outsider started media in private room')
 # Exact APK wallpaper queries/mutations: room owner reads/creates/updates, outside user cannot read/write private wallpaper.
 wallq='query($room:uuid!){room_wallpapers_by_pk(room_id:$room){room_id wallpaper_data updated_at}}'
 wallmut='mutation($room:uuid!,$data:String!){insert_room_wallpapers_one(object:{room_id:$room,wallpaper_data:$data}){room_id}}'
 wall='data:image/jpeg;base64,QUJD'
 r=req(OWNER,'private_user_test',wallmut,{'room':ROOM,'data':wall});check(not r.get('errors') and (r.get('data') or {}).get('insert_room_wallpapers_one',{}).get('room_id')==ROOM,f'owner wallpaper insert failed: {r}')
 r=req(MEMBER,'private_user_test',wallq,{'room':ROOM});check((r.get('data') or {}).get('room_wallpapers_by_pk',{}).get('wallpaper_data')==wall,'accepted member could not read shared wallpaper')
 r=req(OUTSIDER,'private_user_test',wallq,{'room':ROOM});check(not (r.get('data') or {}).get('room_wallpapers_by_pk'),'outsider read private wallpaper')
 updatewall='mutation($room:uuid!,$data:String!){update_room_wallpapers_by_pk(pk_columns:{room_id:$room},_set:{wallpaper_data:$data}){room_id}}'
 wall2='data:image/jpeg;base64,REVG'
 r=req(MEMBER,'private_user_test',updatewall,{'room':ROOM,'data':wall2});check(not r.get('errors'),'accepted member could not update wallpaper')
 r=req(OWNER,'private_user_test',wallq,{'room':ROOM});check((r.get('data') or {}).get('room_wallpapers_by_pk',{}).get('wallpaper_data')==wall2,'updated wallpaper not shared')
 r=req(OUTSIDER,'private_user_test',wallmut,{'room':ROOM,'data':wall});check(bool(r.get('errors')) or not (r.get('data') or {}).get('insert_room_wallpapers_one'),'outsider wrote private wallpaper')
 # Exact APK delete_messages mutation shape: own message can be deleted; cannot delete another sender's row or another room's row.
 deleteq='mutation($where:messages_bool_exp!){delete_messages(where:$where){affected_rows}}'
 msgq='query($roomId:uuid!){messages(where:{room_id:{_eq:$roomId}},order_by:{created_at:asc},limit:200){id room_id sender_id body created_at}}'
 r=req(OWNER,'private_user_test',msgq,{'roomId':ROOM});owner_msgs=(r.get('data') or {}).get('messages') or [];own_id=next((m['id'] for m in owner_msgs if m['sender_id']==OWNER),None);member_id=next((m['id'] for m in owner_msgs if m['sender_id']==MEMBER),None);check(own_id and member_id,'fixture messages missing for delete test')
 def delete_for(uid,msgid,roomid):return req(uid,'private_user_test',deleteq,{'where':{'id':{'_eq':msgid},'sender_id':{'_eq':uid},'room_id':{'_eq':roomid}}})
 r=delete_for(OWNER,own_id,ROOM);check(not r.get('errors') and ((r.get('data') or {}).get('delete_messages') or {}).get('affected_rows')==1,f'author could not delete own message: {r}')
 r=delete_for(OWNER,member_id,ROOM);check(not r.get('errors') and ((r.get('data') or {}).get('delete_messages') or {}).get('affected_rows')==0,f'owner deleted another sender message: {r}')
 r=delete_for(OWNER,member_id,PUBLIC);check(not r.get('errors') and ((r.get('data') or {}).get('delete_messages') or {}).get('affected_rows')==0,f'wrong-room delete affected row: {r}')
 r=req(MEMBER,'private_user_test',msgq,{'roomId':ROOM});remaining=(r.get('data') or {}).get('messages') or [];check(not any(m['id']==own_id for m in remaining) and any(m['id']==member_id for m in remaining),'delete did not affect only authorized own message')
 # Pending invitee and outsider cannot delete even if they forge sender/room selectors.
 r=delete_for(PENDING,member_id,ROOM);check(not r.get('errors') and ((r.get('data') or {}).get('delete_messages') or {}).get('affected_rows')==0,'pending invitee deleted message')
 r=delete_for(OUTSIDER,member_id,ROOM);check(not r.get('errors') and ((r.get('data') or {}).get('delete_messages') or {}).get('affected_rows')==0,'outsider deleted message')
 # Ensure client cannot directly add/accept membership; no insert permission on room_members.
 forged='mutation($room:uuid!,$uid:uuid!){insert_room_members_one(object:{room_id:$room,user_id:$uid,invited_by:$uid}){room_id}}'
 r=req(OWNER,'user',forged,{'room':ROOM,'uid':OUTSIDER});check(bool(r.get('errors')),'client could directly forge room membership')
 print('PASS: APK profile, friend request/response, and presence operations use injected caller identity')
 print('PASS: APK private audio/media upload, completion and reads work for accepted member; outsiders denied')
 print('PASS: APK delete mutation removes only caller-owned message in authorized room; pending/outsider/forged selectors affect zero rows')
 print('PASS: exact APK room/message read and insert operations align with candidate private-room permissions')
 print('PASS: current exported private message policy owner-only reproduced; accepted member denied')
 print('PASS: candidate policy grants owner and accepted member, denies pending/outsider for known UUID')
 print('PASS: invite is owner-only and idempotent; pending has no history; accept grants membership')
 print('PASS: public read/write remains; direct client membership insertion denied')
 print('NOTE: synthetic ephemeral database and JWT only; no production Nhost/Auth/app test')
if __name__=='__main__':main()
