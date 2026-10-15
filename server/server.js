'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const PUBLIC = path.join(__dirname, 'public');
const sessions = new Map();
const MAX_FRAME = 4 * 1024 * 1024;
const SESSION_TTL = 20 * 60 * 1000;

function json(res, code, obj, headers={}) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Content-Length':body.length,'Cache-Control':'no-store',...headers});
  res.end(body);
}
function text(res, code, value) {
  const body = Buffer.from(value);
  res.writeHead(code, {'Content-Type':'text/plain; charset=utf-8','Content-Length':body.length,'Cache-Control':'no-store'});
  res.end(body);
}
function readBody(req, max=64*1024) {
  return new Promise((resolve,reject)=>{
    let n=0; const chunks=[];
    req.on('data', c=>{ n+=c.length; if(n>max){reject(new Error('too_large')); req.destroy();} else chunks.push(c); });
    req.on('end', ()=>resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function hash(v){ return crypto.createHash('sha256').update(String(v)).digest(); }
function safeEq(a,b){ if(!Buffer.isBuffer(a))a=hash(a); if(!Buffer.isBuffer(b))b=hash(b); return a.length===b.length && crypto.timingSafeEqual(a,b); }
function getSession(code){
  const s=sessions.get(String(code||''));
  if(!s) return null;
  if(Date.now()-s.lastSeen>SESSION_TTL){ sessions.delete(String(code)); return null; }
  return s;
}
function authViewer(s,pw){ return s && typeof pw==='string' && safeEq(s.passwordHash, hash(pw)); }
function authHost(s,token){ return s && typeof token==='string' && safeEq(s.hostTokenHash, hash(token)); }
function cors(req,res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,X-Code,X-Password,X-Host-Token,X-Screen-Width,X-Screen-Height');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS'){res.writeHead(204);res.end();return true;} return false;
}
function serveStatic(req,res,u){
  let rel = u.pathname === '/' ? '/index.html' : u.pathname;
  if(rel.includes('..')) return false;
  const file=path.join(PUBLIC,rel);
  if(!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return false;
  const ext=path.extname(file).toLowerCase();
  const types={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.ico':'image/x-icon'};
  const st=fs.statSync(file);
  res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Content-Length':st.size,'Cache-Control': ext==='.html'?'no-store':'public, max-age=3600'});
  fs.createReadStream(file).pipe(res); return true;
}

setInterval(()=>{
  const now=Date.now();
  for(const [code,s] of sessions) if(now-s.lastSeen>SESSION_TTL) sessions.delete(code);
}, 60_000).unref();

const server=http.createServer(async (req,res)=>{
  if(cors(req,res)) return;
  const u=new URL(req.url, `http://${req.headers.host||'localhost'}`);
  try {
    if(req.method==='POST' && u.pathname==='/api/register'){
      const data=JSON.parse((await readBody(req)).toString('utf8'));
      const code=String(data.code||'').replace(/\D/g,'').slice(0,9);
      const password=String(data.password||'').slice(0,32);
      const width=Math.max(1,Math.min(10000,Number(data.width||1)));
      const height=Math.max(1,Math.min(10000,Number(data.height||1)));
      if(code.length<6 || password.length<4) return json(res,400,{error:'invalid_session'});
      if(sessions.has(code)) return json(res,409,{error:'code_in_use'});
      const hostToken=crypto.randomBytes(32).toString('hex');
      sessions.set(code,{passwordHash:hash(password),hostTokenHash:hash(hostToken),width,height,frame:null,frameAt:0,inputs:[],createdAt:Date.now(),lastSeen:Date.now()});
      return json(res,200,{ok:true,hostToken});
    }
    if(req.method==='POST' && u.pathname==='/api/frame'){
      const code=req.headers['x-code']; const token=req.headers['x-host-token'];
      const s=getSession(code); if(!authHost(s,token)) return json(res,403,{error:'forbidden'});
      const body=await readBody(req,MAX_FRAME);
      if(!String(req.headers['content-type']||'').startsWith('image/jpeg')) return json(res,415,{error:'jpeg_required'});
      s.frame=body; s.frameAt=Date.now(); s.lastSeen=Date.now();
      s.width=Math.max(1,Math.min(10000,Number(req.headers['x-screen-width']||s.width)));
      s.height=Math.max(1,Math.min(10000,Number(req.headers['x-screen-height']||s.height)));
      res.writeHead(204,{'Cache-Control':'no-store'}); return res.end();
    }
    if(req.method==='GET' && u.pathname==='/api/frame'){
      const code=u.searchParams.get('code'); const pw=req.headers['x-password']||u.searchParams.get('password');
      const s=getSession(code); if(!authViewer(s,pw)) return json(res,403,{error:'forbidden'});
      s.lastSeen=Date.now(); if(!s.frame) return json(res,204,{ok:false});
      res.writeHead(200,{'Content-Type':'image/jpeg','Content-Length':s.frame.length,'Cache-Control':'no-store, no-cache, must-revalidate','X-Screen-Width':String(s.width),'X-Screen-Height':String(s.height),'X-Frame-Time':String(s.frameAt)});
      return res.end(s.frame);
    }
    if(req.method==='GET' && u.pathname==='/api/status'){
      const code=u.searchParams.get('code'); const pw=req.headers['x-password']||u.searchParams.get('password');
      const s=getSession(code); if(!authViewer(s,pw)) return json(res,403,{error:'forbidden'});
      s.lastSeen=Date.now(); return json(res,200,{ok:true,width:s.width,height:s.height,hasFrame:!!s.frame});
    }
    if(req.method==='POST' && u.pathname==='/api/input'){
      const code=req.headers['x-code']; const pw=req.headers['x-password'];
      const s=getSession(code); if(!authViewer(s,pw)) return json(res,403,{error:'forbidden'});
      const data=JSON.parse((await readBody(req,16*1024)).toString('utf8'));
      if(s.inputs.length>200) s.inputs.splice(0,s.inputs.length-100);
      data.t=Date.now(); s.inputs.push(data); s.lastSeen=Date.now();
      return json(res,200,{ok:true});
    }
    if(req.method==='GET' && u.pathname==='/api/input'){
      const code=req.headers['x-code']; const token=req.headers['x-host-token'];
      const s=getSession(code); if(!authHost(s,token)) return json(res,403,{error:'forbidden'});
      const items=s.inputs.splice(0,100); s.lastSeen=Date.now(); return json(res,200,{items});
    }
    if(req.method==='POST' && u.pathname==='/api/end'){
      const code=req.headers['x-code']; const token=req.headers['x-host-token'];
      const s=getSession(code); if(!authHost(s,token)) return json(res,403,{error:'forbidden'});
      sessions.delete(String(code)); return json(res,200,{ok:true});
    }
    if(req.method==='GET' && u.pathname==='/health') return text(res,200,'ok');
    if(serveStatic(req,res,u)) return;
    return json(res,404,{error:'not_found'});
  } catch(e){
    if(e && e.message==='too_large') return json(res,413,{error:'too_large'});
    console.error(e); return json(res,500,{error:'server_error'});
  }
});
server.listen(PORT,()=>console.log(`Ramat Remote server listening on :${PORT}`));
