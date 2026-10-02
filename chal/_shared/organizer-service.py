"""Isolated challenge runtime. Organizer source; never served to players."""
import base64, hashlib, hmac, io, json, os, secrets, threading, time, zipfile
from pathlib import Path
from urllib.parse import unquote
from flask import Flask, request, jsonify, send_from_directory, render_template, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
ROOT=Path(__file__).resolve().parent
cfg=json.loads((ROOT/'settings.json').read_text())
FLAG=os.getenv('FLAG',cfg.get('flag','NOT_CONFIGURED'))
app=Flask(__name__);app.secret_key=secrets.token_bytes(32)
kind=cfg['kind'];state={};lock=threading.Lock()
def digest(s):return hashlib.sha256(s.encode()).hexdigest()
def result(ok,value=None):return jsonify({'ok':bool(ok),'message':(value or FLAG) if ok else 'The request could not be completed.'}),200 if ok else 403
def b64(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def unb64(s):return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def issue(payload,key=b'front-desk'):
 h=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode());p=b64(json.dumps(payload).encode());return h+'.'+p+'.'+b64(hmac.new(key,(h+'.'+p).encode(),hashlib.sha256).digest())
def claims():
 token=request.headers.get('Authorization','').removeprefix('Bearer ')
 h,p,s=token.split('.');head=json.loads(unb64(h));key=unb64(head['jwk']['k']) if 'jwk' in head else b'front-desk'
 if not hmac.compare_digest(unb64(s),hmac.new(key,(h+'.'+p).encode(),hashlib.sha256).digest()):raise ValueError('signature')
 return json.loads(unb64(p))
@app.get('/health')
def health():return {'status':'ok'}
@app.get('/')
def home():return render_template('index.html',c=cfg,downloads=sorted(p.name for p in (ROOT/'downloads').glob('*') if p.is_file()))
@app.get('/downloads/<name>')
def download(name):return send_from_directory(ROOT/'downloads',name,as_attachment=True)
@app.post('/submit')
def submit():
 data=request.get_json(silent=True) or request.form
 answer=str(data.get('answer','')).strip()
 return result(hmac.compare_digest(digest(answer),cfg.get('answer_hash','!')))
@app.route('/api/<path:operation>',methods=['GET','POST','PATCH'])
def api(operation):
 data=request.get_json(silent=True) or request.form.to_dict() or {}
 try:return dispatch(operation,data)
 except (ValueError,KeyError,TypeError,IndexError,FileNotFoundError,zipfile.BadZipFile):return jsonify({'message':'Request unavailable.'}),400

def dispatch(op,d):
 if kind=='web-path':
  if op=='library':return {'items':['schedule.txt','welcome.txt']}
  if op=='view':
   name=unquote(request.args.get('name','welcome.txt').replace('../',''))
   p=ROOT/'documents'/name
   return {'text':p.read_text()[:10000]}
 if kind=='web-reset':
  if op=='members':return {'members':['visitor@studio.test','director@studio.test']}
  if op=='recovery':
   raw=request.args.getlist('member');target=raw[-1] if raw else 'visitor@studio.test';recipient=raw[0] if raw else target
   token=secrets.token_hex(18);state[token]=target
   if recipient=='visitor@studio.test':return {'mailbox':[{'subject':'Your sign-in link','token':token}]}
   return {'queued':True}
  if op=='entry':return result(state.get(d.get('token'))=='director@studio.test')
 if kind=='web-render':
  if op=='session':return {'token':issue({'role':'visitor'})}
  if op=='proof':
   if claims().get('role')!='curator':return result(False)
   text=d.get('layout','')
   if any(x in text for x in ['_','[',']']):return result(False)
   return {'proof':render_template_string(text)}
 if kind=='api-object':
  if op=='orders':return {'items':[{'reference':'TOUR-2401','object':digest('TOUR-2401')[:24]}],'next_reference':'TOUR-2402'}
  if op.startswith('orders/'):
   oid=op.split('/')[-1]
   if oid==digest('TOUR-2402')[:24]:return {'receipt':FLAG}
   return {'receipt':'Two seats, balcony level.'}
 if kind=='api-merge':
  token=request.headers.get('X-Session','demo');user=state.setdefault(token,{'role':'member','profile':{'theme':'night'}})
  if op=='profile':
   if request.method=='PATCH':
    if set(d)-{'profile'}:return result(False)
    for key,val in d.get('profile',{}).items():
     if key.startswith('../'):user[key[3:]]=val
     else:user['profile'][key]=val
   return user
  if op=='settlement':return result(user['role']=='producer')
 if kind=='api-canonical':
  if op=='sync':return json.loads((ROOT/'downloads/sync.json').read_text())
  if op=='dispatch':
   raw=request.get_data();first=json.loads(raw,object_pairs_hook=lambda pairs:dict(reversed(pairs)))
   canonical=json.dumps(first,sort_keys=True,separators=(',',':')).encode()
   sig=hmac.new(bytes.fromhex(cfg['signing_key']),canonical,hashlib.sha256).hexdigest()
   if not hmac.compare_digest(sig,request.headers.get('X-Signature','')):return result(False)
   return result(d.get('operation')=='settle' and d.get('account')=='house')
 if kind=='cloud-store':
  if op=='objects':return {'keys':['public/lineup.txt','public/receipts.json']}
  if op=='object':
   key=request.args.get('key','')
   if not key.startswith('public/'):return result(False)
   import posixpath
   normalized=posixpath.normpath(unquote(key))
   return {'body':FLAG if normalized=='finance/final.txt' else 'The next performance begins at eight.'}
 if kind=='cloud-role':
  if op=='identity':return {'role':'visitor','account':'stageworks','session':'guest'}
  if op=='assume':
   if d.get('role')=='lighting' and d.get('external_id')==cfg['external_id']:
    token=secrets.token_hex(18);state[token]=d.get('tags',{});return {'token':token}
   return result(False)
  if op=='object':return result(state.get(request.headers.get('X-Session'),{}).get('department')=='finance')
 if kind=='cloud-kube':
  token=request.headers.get('Authorization','').removeprefix('Bearer ')
  rights=state.setdefault('bindings',{'tour-bot':'viewer'})
  if op=='login':return {'token':'tour-bot','namespace':'backstage'}
  if op=='bindings' and request.method=='PATCH':
   if token!='tour-bot' or d.get('roleRef')!='editor':return result(False)
   rights['tour-bot']='editor';return {'updated':True}
  if op=='workloads' and request.method=='POST':
   if rights.get(token)!='editor':return result(False)
   spec=d.get('spec',{});sa=spec.get('serviceAccountName','default');name=secrets.token_hex(8)
   state[name]={'serviceAccountName':sa,'automountServiceAccountToken':spec.get('automountServiceAccountToken',False)}
   return {'name':name}
  if op.startswith('workloads/') and op.endswith('/logs'):
   rec=state[op.split('/')[1]]
   return {'token':'archive-agent'} if rec['serviceAccountName']=='archive-agent' and rec['automountServiceAccountToken'] else {'lines':['Ready.']}
  if op=='secrets':return result(token=='archive-agent')
 if kind=='crypto-oracle':
  if op=='parcel':return json.loads((ROOT/'downloads/parcel.json').read_text())
  if op=='receipt':
   raw=bytes.fromhex(d.get('parcel',''));key=bytes.fromhex(cfg['aes_key'])
   try:unpad(AES.new(key,AES.MODE_CBC,raw[:16]).decrypt(raw[16:]),16)
   except ValueError:return {'status':'damaged'},422
   return {'status':'pending'},202
 if kind=='misc-machine':
  if op=='round':
   sid=secrets.token_hex(8);state[sid]=0;return {'round':sid}
  if op=='move':
   sid=d['round'];current=state[sid];symbol=d.get('symbol','')
   table=cfg['transitions'];state[sid]=table[str(current)].get(symbol,0)
   return result(state[sid]==cfg['goal'],'Round complete: '+FLAG) if state[sid]==cfg['goal'] else {'position':state[sid]}
 if kind=='misc-zip':
  if op=='import':
   raw=base64.b64decode(d['bundle']);z=zipfile.ZipFile(io.BytesIO(raw));entries=z.infolist()
   if len(entries)>12:return result(False)
   first=next(x for x in entries if x.filename=='show.json');checked=json.loads(z.read(first))
   if checked.get('mode')!='preview':return result(False)
   last=json.loads(z.read('show.json'));return result(last.get('mode')=='publish' and last.get('stage')=='main')
 if kind=='ad-certificate':
  if op=='enroll':
   t=cfg['templates'].get(d.get('template'),{})
   if t.get('enroll')!='members' or not t.get('clientAuth') or t.get('approval'):return result(False)
   upn=d.get('upn') if t.get('supplySubject') else 'visitor@orchard.test'
   token=issue({'upn':upn},bytes.fromhex(cfg['ca_key']));return {'certificate':token}
  if op=='session':
   h,p,s=d['certificate'].split('.');sig=hmac.new(bytes.fromhex(cfg['ca_key']),(h+'.'+p).encode(),hashlib.sha256).digest()
   return result(hmac.compare_digest(sig,unb64(s)) and json.loads(unb64(p)).get('upn')=='archivist@orchard.test')
 return {'message':'Not found'},404

if __name__=='__main__':
 # The path challenge intentionally has an in-container private document.
 if kind in ('web-path','web-render'):
  (ROOT/'private').mkdir(exist_ok=True);(ROOT/'private/reserve.txt').write_text(FLAG)
 app.run(host='0.0.0.0',port=8080,threaded=True,debug=False)
