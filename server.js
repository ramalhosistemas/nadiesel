'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3015);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const MIME = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webmanifest':'application/manifest+json','.svg':'image/svg+xml'};
const id = p => `${p}_${crypto.randomBytes(7).toString('hex')}`;
const now = () => new Date().toISOString();
const passwordHash = password => crypto.scryptSync(String(password), 'gl-electromechanic-v1', 32).toString('hex');
const AUTH_SECRET=process.env.AUTH_SECRET||'na-diesel-auth-v2-2026';
const createAuthToken=userId=>{const payload=Buffer.from(JSON.stringify({sub:userId,iat:Date.now(),nonce:crypto.randomBytes(12).toString('hex')})).toString('base64url'),signature=crypto.createHmac('sha256',AUTH_SECRET).update(payload).digest('base64url');return `${payload}.${signature}`};
const tokenUserId=token=>{try{const [payload,signature]=String(token||'').split('.');if(!payload||!signature)return'';const expected=crypto.createHmac('sha256',AUTH_SECRET).update(payload).digest('base64url');if(signature.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected)))return'';const data=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));return Date.now()-Number(data.iat)<1000*60*60*24*30?data.sub:''}catch{return''}};
const b64url = data => Buffer.from(data).toString('base64url');
const fromB64url = data => Buffer.from(String(data),'base64url');
const newChallenge = (userId,type) => {const value=b64url(crypto.randomBytes(32));db.biometricChallenges??={};db.biometricChallenges[value]={userId,type,expires:Date.now()+120000};return value;};
const consumeChallenge = (value,userId,type) => {const item=db.biometricChallenges?.[value];if(db.biometricChallenges)delete db.biometricChallenges[value];return !!(item&&item.userId===userId&&item.type===type&&item.expires>Date.now());};

function seedDB(){
  const initialPasswords=[process.env.INITIAL_ADMIN_PASSWORD||'admin123',process.env.INITIAL_GABRIEL_PASSWORD||'1234',process.env.INITIAL_LEONARDO_PASSWORD||'1234',process.env.INITIAL_NALDO_PASSWORD||'1234'];
  const users = ['Admin','Gabriel','Leonardo','Naldo'].map((name,i)=>({id:`usr_${i+1}`,name,username:name.toLowerCase(),role:'admin',passwordHash:passwordHash(initialPasswords[i]),active:true,createdAt:now()}));
  return {
    meta:{version:1,createdAt:now(),osCounter:10251}, users, sessions:{}, biometricChallenges:{}, shares:[], vehicles:[], clients:[], stock:[], finance:[], orders:[], notifications:[], audit:[],
    agenda:[]
  };
}
function normalizeDB(value){
  const normalized=value&&typeof value==='object'?value:{};
  const collections=['users','vehicles','clients','stock','finance','orders','notifications','agenda','shares','audit'];
  collections.forEach(key=>{if(!Array.isArray(normalized[key]))normalized[key]=[]});
  normalized.sessions=normalized.sessions&&typeof normalized.sessions==='object'&&!Array.isArray(normalized.sessions)?normalized.sessions:{};
  normalized.biometricChallenges=normalized.biometricChallenges&&typeof normalized.biometricChallenges==='object'&&!Array.isArray(normalized.biometricChallenges)?normalized.biometricChallenges:{};
  normalized.meta=normalized.meta&&typeof normalized.meta==='object'?normalized.meta:{version:1,createdAt:now(),osCounter:10251};
  normalized.meta.version??=1;normalized.meta.createdAt??=now();normalized.meta.osCounter=Number(normalized.meta.osCounter||10251);
  normalized.users.forEach(user=>{user.role=user.role||'admin';user.active=user.active!==false;user.passkeys=Array.isArray(user.passkeys)?user.passkeys:[]});
  normalized.orders.forEach(order=>{order.services=Array.isArray(order.services)?order.services:[];order.parts=Array.isArray(order.parts)?order.parts:[];order.expenses=Array.isArray(order.expenses)?order.expenses:[];order.timeline=Array.isArray(order.timeline)?order.timeline:[];order.checklist=order.checklist&&typeof order.checklist==='object'&&!Array.isArray(order.checklist)?order.checklist:{};if(!order.paymentTerms||order.paymentTerms==='15-30')order.paymentTerms='dia-30';if(order.paymentTerms==='dia-05')order.paymentTerms='dia-15'});
  return normalized;
}
function loadDB(){
  if(process.env.NA_DIESEL_SERVERLESS||process.env.AWS_LAMBDA_FUNCTION_NAME||process.env.LAMBDA_TASK_ROOT)return seedDB();
  fs.mkdirSync(DATA_DIR,{recursive:true});
  if(!fs.existsSync(DB_FILE)){ const db=seedDB(); saveDB(db); return db; }
  try{return normalizeDB(JSON.parse(fs.readFileSync(DB_FILE,'utf8')))}catch{const db=seedDB();saveDB(db);return db;}
}
function saveDB(db){if(process.env.NA_DIESEL_SERVERLESS||process.env.AWS_LAMBDA_FUNCTION_NAME||process.env.LAMBDA_TASK_ROOT)return;const temp=DB_FILE+'.tmp';fs.writeFileSync(temp,JSON.stringify(db,null,2));fs.renameSync(temp,DB_FILE);}
let db=loadDB();

function json(res,status,data){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));}
function body(req){return new Promise((resolve,reject)=>{let raw='';req.on('data',c=>{raw+=c;if(raw.length>100_000_000){reject(new Error('Payload muito grande'));req.destroy();}});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('JSON inválido'));}});req.on('error',reject);});}
function auth(req){const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'');const userId=tokenUserId(token)||db.sessions?.[token];return db.users.find(u=>u.id===userId&&u.active);}
function safeUser(u){return u&&({id:u.id,name:u.name,username:u.username,role:u.role,active:u.active,avatar:u.avatar||''});}
function audit(user,action,target){db.audit.unshift({id:id('aud'),userId:user.id,user:user.name,action,target,at:now()});db.audit=db.audit.slice(0,500);}
function canAccess(user,ownerId,resource,mode='view',resourceId=''){
  if(user.role==='admin'||ownerId===user.id)return true;
  return db.shares.some(s=>s.ownerId===ownerId&&s.recipientId===user.id&&s.resource===resource&&(!s.resourceId||s.resourceId===resourceId)&&s.status==='approved'&&(mode==='view'||s.permission==='edit'));
}
function routeParts(url){return new URL(url,'http://localhost').pathname.split('/').filter(Boolean);}
function orderTotal(o){return (o.services||[]).reduce((sum,item)=>sum+Number(item.value||0),0)+(o.parts||[]).reduce((sum,item)=>sum+Number(item.qty||0)*Number(item.value||0),0)+(o.expenses||[]).reduce((sum,item)=>sum+Number(item.value||0),0);}
function syncClientFromVehicle(vehicle,user){
  const name=String(vehicle.company||vehicle.ownerName||'').trim();if(!name)return;
  const doc=String(vehicle.document||'').replace(/\D/g,'');
  let client=(doc&&db.clients.find(c=>String(c.document||'').replace(/\D/g,'')===doc))||db.clients.find(c=>String(c.name||'').trim().toLowerCase()===name.toLowerCase()&&canAccess(user,c.ownerId,'clients','edit'));
  const data={name,document:vehicle.document||'',contact:vehicle.contact||'',phone:vehicle.phone||'',email:vehicle.email||'',city:vehicle.city||'',state:vehicle.state||'',updatedAt:now()};
  if(client&&canAccess(user,client.ownerId,'clients','edit'))Object.assign(client,data);
  else{client={...data,id:id('cli'),ownerId:user.id,createdAt:now()};db.clients.unshift(client)}
  vehicle.clientId=client.id;vehicle.clientName=client.name;
}
function syncOrderClient(order){
  const vehicle=db.vehicles.find(v=>v.id===order.vehicleId);
  const client=db.clients.find(c=>c.id===order.clientId);
  if(client)order.clientName=client.name;
  else if(vehicle){order.clientId=vehicle.clientId||order.clientId||'';order.clientName=vehicle.clientName||vehicle.company||vehicle.ownerName||order.clientName||'';}
}

async function api(req,res){
  const parts=routeParts(req.url); const method=req.method;
  if(method==='POST'&&parts[1]==='login'){
    const b=await body(req);const u=db.users.find(x=>x.active&&(x.username.toLowerCase()===String(b.username||'').toLowerCase()||x.name.toLowerCase()===String(b.username||'').toLowerCase()));
    if(!u||u.passwordHash!==passwordHash(b.password||''))return json(res,401,{error:'Usuário ou senha inválidos.'});
    const token=createAuthToken(u.id);audit(u,'login','session');saveDB(db);return json(res,200,{token,user:safeUser(u)});
  }
  if(method==='POST'&&parts[1]==='biometric'&&parts[2]==='login-options'){
    const b=await body(req);const u=db.users.find(x=>x.active&&(x.username.toLowerCase()===String(b.username||'').toLowerCase()||x.name.toLowerCase()===String(b.username||'').toLowerCase()));
    if(!u||!u.passkeys?.length)return json(res,404,{error:'Biometria ainda não cadastrada para este usuário.'});
    const rpId=String(req.headers.host||'127.0.0.1').split(':')[0];return json(res,200,{userId:u.id,challenge:newChallenge(u.id,'login'),rpId,allowCredentials:u.passkeys.map(k=>({id:k.credentialId,type:'public-key'}))});
  }
  if(method==='POST'&&parts[1]==='biometric'&&parts[2]==='login-complete'){
    const b=await body(req);const u=db.users.find(x=>x.id===b.userId&&x.active),key=u?.passkeys?.find(k=>k.credentialId===b.credentialId);if(!u||!key)return json(res,401,{error:'Credencial biométrica inválida.'});
    try{const client=JSON.parse(fromB64url(b.clientDataJSON).toString('utf8'));if(client.type!=='webauthn.get'||!consumeChallenge(client.challenge,u.id,'login'))throw new Error('Desafio inválido');const origin=new URL(client.origin),rpId=origin.hostname,allowedLocal=client.origin==='http://127.0.0.1:3015'||client.origin==='http://localhost:3015',allowedWeb=origin.protocol==='https:';if(!allowedLocal&&!allowedWeb)throw new Error('Origem inválida');const authData=fromB64url(b.authenticatorData),expectedRp=crypto.createHash('sha256').update(rpId).digest();if(!authData.subarray(0,32).equals(expectedRp)||(authData[32]&1)!==1)throw new Error('Autenticador inválido');const signed=Buffer.concat([authData,crypto.createHash('sha256').update(fromB64url(b.clientDataJSON)).digest()]);if(!crypto.verify('sha256',signed,crypto.createPublicKey({key:fromB64url(key.publicKey),format:'der',type:'spki'}),fromB64url(b.signature)))throw new Error('Assinatura inválida');const token=createAuthToken(u.id);audit(u,'login biométrico',key.name||'dispositivo');saveDB(db);return json(res,200,{token,user:safeUser(u)});}catch(e){return json(res,401,{error:'Não foi possível validar a biometria.'});}
  }
  const user=auth(req);if(!user)return json(res,401,{error:'Sessão inválida ou expirada.'});
  if(method==='POST'&&parts[1]==='logout'){for(const [t,uid]of Object.entries(db.sessions||{}))if(uid===user.id)delete db.sessions[t];saveDB(db);return json(res,200,{ok:true});}
  if(method==='GET'&&parts[1]==='me')return json(res,200,{user:safeUser(user)});
  if(method==='GET'&&parts[1]==='users')return json(res,200,db.users.map(safeUser));
  if(parts[1]==='profile'&&method==='PUT'){const b=await body(req);if(typeof b.name==='string'&&b.name.trim())user.name=b.name.trim().slice(0,80);if(typeof b.avatar==='string'&&(b.avatar===''||b.avatar.startsWith('data:image/')))user.avatar=b.avatar;audit(user,b.avatar?'atualizou avatar':'removeu avatar','perfil');saveDB(db);return json(res,200,{user:safeUser(user)});}
  if(method==='POST'&&parts[1]==='biometric'&&parts[2]==='register-options'){const rpId=String(req.headers.host||'127.0.0.1').split(':')[0];return json(res,200,{challenge:newChallenge(user.id,'register'),rp:{id:rpId,name:'N.A.Diesel Diagnósticos e Programação'},user:{id:b64url(user.id),name:user.username,displayName:user.name}});}
  if(method==='POST'&&parts[1]==='biometric'&&parts[2]==='register-complete'){
    const b=await body(req);let client;try{client=JSON.parse(fromB64url(b.clientDataJSON).toString('utf8'));}catch{return json(res,400,{error:'Resposta biométrica inválida.'});}let validOrigin=false;try{const origin=new URL(client.origin);validOrigin=(origin.protocol==='https:'||client.origin==='http://127.0.0.1:3015'||client.origin==='http://localhost:3015');}catch{}if(client.type!=='webauthn.create'||!consumeChallenge(client.challenge,user.id,'register')||!validOrigin)return json(res,400,{error:'Cadastro biométrico expirado ou inválido.'});if(!b.credentialId||!b.publicKey)return json(res,400,{error:'O dispositivo não forneceu uma chave biométrica compatível.'});user.passkeys??=[];user.passkeys=user.passkeys.filter(k=>k.credentialId!==b.credentialId);user.passkeys.push({credentialId:b.credentialId,publicKey:b.publicKey,name:b.name||'Dispositivo biométrico',createdAt:now()});audit(user,'cadastrou biometria',b.name||'dispositivo');saveDB(db);return json(res,201,{ok:true,count:user.passkeys.length});
  }
  if(method==='DELETE'&&parts[1]==='biometric'){user.passkeys=[];audit(user,'removeu biometrias','todos os dispositivos');saveDB(db);return json(res,200,{ok:true});}
  if(parts[1]==='backup'){
    if(user.role!=='admin')return json(res,403,{error:'Somente o Administrador pode fazer ou restaurar backups.'});
    if(method==='GET'){audit(user,'gerou backup','banco completo');saveDB(db);return json(res,200,{application:'N.A.Diesel Diagnósticos e Programação',version:1,exportedAt:now(),data:db});}
    if(method==='POST'){const backup=await body(req),incoming=backup?.data||backup;if(!incoming||!Array.isArray(incoming.users)||!Array.isArray(incoming.vehicles)||!Array.isArray(incoming.orders))return json(res,400,{error:'Arquivo de backup inválido ou incompatível.'});const restored=normalizeDB(JSON.parse(JSON.stringify(incoming)));const restoredUser=restored.users.find(u=>u.id===user.id)||restored.users.find(u=>u.role==='admin');if(!restoredUser)return json(res,400,{error:'O backup não possui um usuário administrador válido.'});db=restored;audit(restoredUser,'restaurou backup',backup.exportedAt||'arquivo externo');saveDB(db);return json(res,200,{ok:true,message:'Backup restaurado com sucesso. Os dados foram atualizados para a versão atual.'});}
  }

  if(parts[1]==='dashboard'&&method==='GET'){
    db=normalizeDB(db);const vehicles=db.vehicles.filter(v=>canAccess(user,v.ownerId,'vehicles'));
    const orders=db.orders.filter(o=>canAccess(user,o.ownerId,'orders','view',o.id));
    const today=new Date(),todayKey=today.toISOString().slice(0,10),monthKey=today.toISOString().slice(0,7),monthNames=['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
    const monthlyRevenue=Array.from({length:12},(_,index)=>{const d=new Date(today.getFullYear(),today.getMonth()-11+index,1),key=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}`,value=db.finance.filter(item=>item.type==='Receita'&&item.status!=='pending'&&String(item.date||item.createdAt||'').startsWith(key)).reduce((sum,item)=>sum+Number(item.value||0),0);return{key,label:monthNames[d.getMonth()],value}}),currentRevenue=monthlyRevenue.at(-1)?.value||0,finishedThisMonth=orders.filter(o=>o.status==='Finalizada'&&String(o.closedAt||o.updatedAt||'').startsWith(monthKey)).length,readyThisMonth=new Set(orders.filter(o=>['Finalizada','Entregue'].includes(o.status)&&String(o.closedAt||o.updatedAt||'').startsWith(monthKey)).map(o=>o.vehicleId).filter(Boolean)).size;
    return json(res,200,{vehicles,orders,agenda:db.agenda.filter(a=>canAccess(user,a.ownerId,'agenda')),indicators:{monthlyRevenue,currentRevenue,finishedThisMonth,readyThisMonth,averageTicket:finishedThisMonth?currentRevenue/finishedThisMonth:0},stats:{vehicles:vehicles.length,open:orders.filter(o=>!['Finalizada','Entregue','Cancelada'].includes(o.status)).length,waiting:orders.filter(o=>o.status==='Aguardando peça').length,electrical:orders.filter(o=>o.category==='Elétrica'&&!['Finalizada','Entregue','Cancelada'].includes(o.status)).length,mechanical:orders.filter(o=>o.category==='Mecânica'&&!['Finalizada','Entregue','Cancelada'].includes(o.status)).length,finished:orders.filter(o=>o.status==='Finalizada'&&String(o.closedAt||o.updatedAt||'').startsWith(todayKey)).length,delivered:orders.filter(o=>o.status==='Entregue'&&String(o.updatedAt||'').startsWith(todayKey)).length,readyThisMonth}});
  }

  if(parts[1]==='vehicles'){
    if(method==='GET'&&!parts[2]){const vehicles=db.vehicles.filter(v=>canAccess(user,v.ownerId,'vehicles'));vehicles.forEach(v=>syncClientFromVehicle(v,user));saveDB(db);return json(res,200,vehicles);}
    if(method==='GET'&&parts[2]){const v=db.vehicles.find(x=>x.id===parts[2]);return v&&canAccess(user,v.ownerId,'vehicles')?json(res,200,v):json(res,404,{error:'Veículo não encontrado.'});}
    if(method==='POST'){
      const b=await body(req);const v={...b,id:id('veh'),ownerId:user.id,photos:Array.isArray(b.photos)?b.photos.slice(0,8):[],active:b.active!==false,createdAt:now(),updatedAt:now()};syncClientFromVehicle(v,user);db.vehicles.unshift(v);audit(user,'criou veículo',v.plate||v.id);saveDB(db);return json(res,201,v);
    }
    if(method==='PUT'&&parts[2]){const v=db.vehicles.find(x=>x.id===parts[2]);if(!v||!canAccess(user,v.ownerId,'vehicles','edit'))return json(res,403,{error:'Sem permissão para editar.'});const b=await body(req);Object.assign(v,b,{id:v.id,ownerId:v.ownerId,photos:Array.isArray(b.photos)?b.photos.slice(0,8):v.photos,updatedAt:now()});syncClientFromVehicle(v,user);db.orders.filter(o=>o.vehicleId===v.id).forEach(syncOrderClient);audit(user,'editou veículo',v.plate||v.id);saveDB(db);return json(res,200,v);}
    if(method==='DELETE'&&parts[2]){const i=db.vehicles.findIndex(x=>x.id===parts[2]);if(i<0||!canAccess(user,db.vehicles[i].ownerId,'vehicles','edit'))return json(res,403,{error:'Sem permissão.'});const [v]=db.vehicles.splice(i,1);audit(user,'removeu veículo',v.plate||v.id);saveDB(db);return json(res,200,{ok:true});}
  }

  if(parts[1]==='orders'){
    if(method==='GET'&&!parts[2])return json(res,200,db.orders.filter(o=>canAccess(user,o.ownerId,'orders','view',o.id)));
    if(method==='POST'&&parts[2]&&parts[3]==='close'){
      const o=db.orders.find(x=>x.id===parts[2]);if(!o||!canAccess(user,o.ownerId,'orders','edit',o.id))return json(res,403,{error:'Sem permissão para finalizar esta OS.'});
      const b=await body(req),allowed=['dia-15','dia-30','avista','pix','credito','debito'];if(!allowed.includes(b.paymentTerms))return json(res,400,{error:'Prazo ou forma de pagamento inválido.'});
      const total=orderTotal(o),paymentStatus=b.paymentStatus==='paid'?'paid':'pending',closedAt=now();
      Object.assign(o,{status:'Finalizada',paymentTerms:b.paymentTerms,paymentStatus,paymentDueDate:b.dueDate||'',receivedValue:Number(b.receivedValue||total),financialNotes:b.financialNotes||'',closedAt,updatedAt:closedAt});o.timeline=o.timeline||[];o.timeline.push({at:closedAt,label:paymentStatus==='paid'?'OS finalizada e recebida':'OS finalizada — recebimento pendente',user:user.name});
      let entry=db.finance.find(x=>x.orderId===o.id);const financeData={description:`Recebimento OS #${o.number}`,type:'Receita',category:'Ordem de Serviço',value:Number(b.receivedValue||total),date:closedAt.slice(0,10),dueDate:b.dueDate||closedAt.slice(0,10),status:paymentStatus,paymentTerms:b.paymentTerms,notes:b.financialNotes||'',orderId:o.id,updatedAt:closedAt};
      if(entry)Object.assign(entry,financeData);else{entry={...financeData,id:id('fin'),ownerId:o.ownerId,createdAt:closedAt};db.finance.unshift(entry)}audit(user,'finalizou OS',`#${o.number}`);saveDB(db);return json(res,200,{order:o,finance:entry});
    }
    if(method==='POST'&&parts[2]&&parts[3]==='cancel'){
      const o=db.orders.find(x=>x.id===parts[2]);if(!o||!canAccess(user,o.ownerId,'orders','edit',o.id))return json(res,403,{error:'Sem permissao para cancelar esta OS.'});
      const b=await body(req),reason=String(b.reason||'').trim();if(!reason)return json(res,400,{error:'Informe o motivo do cancelamento.'});
      const cancelledAt=now();Object.assign(o,{status:'Cancelada',cancellationReason:reason,cancelledAt,cancelledBy:user.name,updatedAt:cancelledAt});o.timeline=o.timeline||[];o.timeline.push({at:cancelledAt,label:`OS cancelada: ${reason}`,user:user.name});
      const financeIndex=db.finance.findIndex(x=>x.orderId===o.id&&x.status==='pending');if(financeIndex>=0)db.finance.splice(financeIndex,1);audit(user,'cancelou OS',`#${o.number}: ${reason}`);saveDB(db);return json(res,200,o);
    }
    if(method==='GET'&&parts[2]){const o=db.orders.find(x=>x.id===parts[2]);return o&&canAccess(user,o.ownerId,'orders','view',o.id)?json(res,200,o):json(res,404,{error:'OS não encontrada.'});}
    if(method==='POST'){const b=await body(req);const allowed=['dia-15','dia-30','avista','pix','credito','debito'];const o={...b,warrantyDays:Math.max(0,Number(b.warrantyDays||90)),id:id('os'),number:db.meta.osCounter++,ownerId:user.id,status:b.status||'Aberta',paymentTerms:allowed.includes(b.paymentTerms)?b.paymentTerms:'dia-15',services:[],parts:[],expenses:[],checklist:{},timeline:[{at:now(),label:'OS aberta',user:user.name}],createdAt:now(),updatedAt:now()};syncOrderClient(o);db.orders.unshift(o);audit(user,'abriu OS',`#${o.number}`);saveDB(db);return json(res,201,o);}
    if(method==='PUT'&&parts[2]){const o=db.orders.find(x=>x.id===parts[2]);if(!o||!canAccess(user,o.ownerId,'orders','edit',o.id))return json(res,403,{error:'Sem permissão para editar.'});const b=await body(req),previousStatus=o.status,updatedAt=now();Object.assign(o,b,{id:o.id,number:o.number,ownerId:o.ownerId,warrantyDays:Math.max(0,Number(b.warrantyDays??o.warrantyDays??90)),updatedAt});if(b.status==='Entregue'&&previousStatus!=='Entregue')o.deliveredAt=updatedAt;o.expenses??=[];syncOrderClient(o);audit(user,'editou OS',`#${o.number}`);saveDB(db);return json(res,200,o);}
  }

  if(parts[1]==='agenda'){
    if(method==='GET')return json(res,200,db.agenda.filter(a=>canAccess(user,a.ownerId,'agenda')));
    if(method==='POST'){const b=await body(req);const a={...b,id:id('ag'),ownerId:user.id,createdAt:now()};db.agenda.push(a);saveDB(db);return json(res,201,a);}
  }

  if(['clients','stock','finance'].includes(parts[1])){
    const collection=parts[1];
    if(method==='GET'&&!parts[2]){if(collection==='clients'){db.vehicles.filter(v=>canAccess(user,v.ownerId,'vehicles')).forEach(v=>syncClientFromVehicle(v,user));saveDB(db)}return json(res,200,db[collection].filter(x=>canAccess(user,x.ownerId,collection)));}
    if(method==='GET'&&parts[2]){const item=db[collection].find(x=>x.id===parts[2]);return item&&canAccess(user,item.ownerId,collection)?json(res,200,item):json(res,404,{error:'Registro não encontrado.'});}
    if(method==='POST'){const b=await body(req);const item={...b,id:id(collection.slice(0,3)),ownerId:user.id,createdAt:now(),updatedAt:now()};db[collection].unshift(item);audit(user,`criou registro em ${collection}`,item.name||item.description||item.id);saveDB(db);return json(res,201,item);}
    if(method==='PUT'&&parts[2]){const item=db[collection].find(x=>x.id===parts[2]);if(!item||!canAccess(user,item.ownerId,collection,'edit'))return json(res,403,{error:'Sem permissão para editar.'});const b=await body(req);Object.assign(item,b,{id:item.id,ownerId:item.ownerId,updatedAt:now()});audit(user,`editou registro em ${collection}`,item.name||item.description||item.id);saveDB(db);return json(res,200,item);}
    if(method==='DELETE'&&parts[2]){const i=db[collection].findIndex(x=>x.id===parts[2]);if(i<0||!canAccess(user,db[collection][i].ownerId,collection,'edit'))return json(res,403,{error:'Sem permissão.'});db[collection].splice(i,1);saveDB(db);return json(res,200,{ok:true});}
  }

  if(parts[1]==='shares'){
    if(method==='GET')return json(res,200,db.shares.filter(s=>s.ownerId===user.id||s.recipientId===user.id).map(s=>({...s,owner:safeUser(db.users.find(u=>u.id===s.ownerId)),recipient:safeUser(db.users.find(u=>u.id===s.recipientId)),orderNumber:s.resource==='orders'&&s.resourceId?db.orders.find(o=>o.id===s.resourceId)?.number:null})));
    if(method==='POST'){const b=await body(req);if(!db.users.some(u=>u.id===b.recipientId&&u.active))return json(res,400,{error:'Usuário inválido.'});if(b.resource==='orders'&&b.resourceId){const order=db.orders.find(o=>o.id===b.resourceId);if(!order||order.ownerId!==user.id)return json(res,403,{error:'Somente o responsável pela OS pode compartilhá-la.'});}const s={id:id('shr'),ownerId:user.id,recipientId:b.recipientId,resource:b.resource,resourceId:b.resourceId||'',permission:b.permission||'view',status:'pending',createdAt:now()};db.shares.unshift(s);saveDB(db);return json(res,201,s);}
    if(method==='PUT'&&parts[2]){const s=db.shares.find(x=>x.id===parts[2]);if(!s||s.recipientId!==user.id)return json(res,403,{error:'Solicitação inválida.'});const b=await body(req);s.status=b.status==='approved'?'approved':'rejected';s.respondedAt=now();saveDB(db);return json(res,200,s);}
    if(method==='DELETE'&&parts[2]){const i=db.shares.findIndex(x=>x.id===parts[2]&&(x.ownerId===user.id||x.recipientId===user.id));if(i<0)return json(res,404,{error:'Permissão não encontrada.'});db.shares.splice(i,1);saveDB(db);return json(res,200,{ok:true});}
  }
  if(parts[1]==='audit'&&method==='GET')return json(res,200,user.role==='admin'?db.audit:db.audit.filter(a=>a.userId===user.id));
  return json(res,404,{error:'Rota não encontrada.'});
}

function staticFile(req,res){
  let pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname);if(pathname==='/')pathname='/index.html';
  let file=path.normalize(path.join(PUBLIC,pathname));if(!file.startsWith(PUBLIC))return json(res,403,{error:'Acesso negado.'});
  fs.stat(file,(err,stat)=>{if(err||!stat.isFile()){file=path.join(PUBLIC,'index.html');}fs.readFile(file,(e,data)=>{if(e)return json(res,404,{error:'Arquivo não encontrado.'});res.writeHead(200,{'Content-Type':MIME[path.extname(file).toLowerCase()]||'application/octet-stream','Cache-Control':path.extname(file)==='.html'?'no-cache':'public, max-age=3600'});res.end(data);});});
}

const server=http.createServer((req,res)=>{Promise.resolve(req.url.startsWith('/api/')?api(req,res):staticFile(req,res)).catch(err=>{console.error(err);if(!res.headersSent)json(res,500,{error:err.message||'Erro interno.'});});});
if(require.main===module)server.listen(PORT,()=>console.log(`N.A.Diesel Diagnósticos e Programação em http://127.0.0.1:${PORT}`));
module.exports={api,seedDB,getDatabase:()=>db,setDatabase:value=>{db=value||seedDB();db.sessions??={};db.biometricChallenges??={};}};
