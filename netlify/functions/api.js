'use strict';

process.env.NA_DIESEL_SERVERLESS='true';

const {Readable}=require('node:stream');
const {getStore}=require('@netlify/blobs');
const {api,seedDB,getDatabase,setDatabase}=require('../../server');

exports.handler=async event=>{
  const store=getStore('na-diesel-data');
  const stored=await store.get('database',{type:'json',consistency:'strong'});
  setDatabase(stored?.data&&stored?.etag?stored.data:(stored||seedDB()));

  const req=new Readable({read(){if(event.body)this.push(Buffer.from(event.body,event.isBase64Encoded?'base64':'utf8'));this.push(null);}});
  const rawPath=event.path||'/api/';
  req.url=rawPath.startsWith('/.netlify/functions/api')?rawPath.replace('/.netlify/functions/api','/api'):rawPath;
  req.method=event.httpMethod||'GET';
  req.headers=Object.fromEntries(Object.entries(event.headers||{}).map(([k,v])=>[k.toLowerCase(),v]));

  let statusCode=200,headers={};
  let finish;
  const completed=new Promise(resolve=>finish=resolve);
  const res={
    headersSent:false,
    writeHead(status,nextHeaders={}){statusCode=status;headers={...headers,...nextHeaders};this.headersSent=true;},
    end(value=''){finish({statusCode,headers,body:Buffer.isBuffer(value)?value.toString('utf8'):String(value)});}
  };

  try{await api(req,res);}catch(error){if(!res.headersSent){statusCode=500;headers={'Content-Type':'application/json; charset=utf-8'};res.end(JSON.stringify({error:'Erro interno do serviço.'}));}}
  const response=await completed;
  await store.setJSON('database',getDatabase());
  return response;
};
