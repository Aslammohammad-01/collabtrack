/**
 * CollabTrack — Cloudflare Worker API (Multi-User)
 * ──────────────────────────────────────────────────
 * SETUP (Cloudflare Dashboard):
 *
 * 1. Create Worker → paste this file → Save & Deploy
 * 2. Go to Settings → Variables → Add ONE Secret:
 *      JWT_SECRET  → any random 40+ char string
 * 3. Go to Settings → KV Namespace Bindings → Add binding:
 *      Variable name: COLLABTRACK_KV
 *      Namespace: (select the KV namespace you created)
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const json = (d, s = 200) => new Response(JSON.stringify(d), {
  status: s, headers: { ...CORS, 'Content-Type': 'application/json' }
});
const err = (m, s = 400) => json({ error: m }, s);

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const saltHex = [...salt].map(b => b.toString(16).padStart(2,'0')).join('');
  const hashHex = [...new Uint8Array(derived)].map(b => b.toString(16).padStart(2,'0')).join('');
  return `pbkdf2:${saltHex}:${hashHex}`;
}
async function verifyPassword(password, stored) {
  try {
    const [,saltHex,hashHex] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b,16)));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    const newHex = [...new Uint8Array(derived)].map(b => b.toString(16).padStart(2,'0')).join('');
    return newHex === hashHex;
  } catch { return false; }
}

function b64url(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function b64urlDecode(s) { return atob(s.replace(/-/g,'+').replace(/_/g,'/')); }
async function signJWT(payload, secret) {
  const enc = s => new TextEncoder().encode(s);
  const h = btoa(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const b = btoa(JSON.stringify(payload));
  const data = `${h}.${b}`;
  const key = await crypto.subtle.importKey('raw', enc(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc(data));
  return `${data}.${b64url(sig)}`;
}
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h,b,sig] = parts;
    const enc = s => new TextEncoder().encode(s);
    const key = await crypto.subtle.importKey('raw', enc(secret), {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
    const sigBytes = Uint8Array.from(b64urlDecode(sig), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, enc(`${h}.${b}`));
    if (!ok) return null;
    const payload = JSON.parse(b64urlDecode(b));
    if (payload.exp && payload.exp < Date.now()/1000) return null;
    return payload;
  } catch { return null; }
}

async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}

const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MOBILE_RE   = /^\+?[0-9]{7,15}$/;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;

async function signup(req, env) {
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const { fullName, username, email, mobile, password } = b;
  if (!fullName?.trim())               return err('Full name is required');
  if (!username?.trim())               return err('Username is required');
  if (!USERNAME_RE.test(username))     return err('Username: 3-30 chars, letters/numbers/underscore only');
  if (!email?.trim())                  return err('Email is required');
  if (!EMAIL_RE.test(email))           return err('Invalid email address');
  if (!mobile?.trim())                 return err('Mobile number is required');
  if (!MOBILE_RE.test(mobile.trim()))  return err('Invalid mobile number');
  if (!password || password.length < 8) return err('Password must be at least 8 characters');

  const emailKey    = `user:email:${email.toLowerCase().trim()}`;
  const usernameKey = `user:username:${username.toLowerCase().trim()}`;
  const mobileKey   = `user:mobile:${mobile.trim()}`;

  const [existingEmail, existingUsername, existingMobile] = await Promise.all([
    env.COLLABTRACK_KV.get(emailKey),
    env.COLLABTRACK_KV.get(usernameKey),
    env.COLLABTRACK_KV.get(mobileKey),
  ]);
  if (existingEmail)    return err('Email already registered', 409);
  if (existingUsername) return err('Username already taken', 409);
  if (existingMobile)   return err('Mobile number already registered', 409);

  const userId       = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  const user = {
    id: userId,
    fullName: fullName.trim(),
    username: username.trim(),
    email: email.toLowerCase().trim(),
    mobile: mobile.trim(),
    createdAt: new Date().toISOString(),
  };

  await Promise.all([
    env.COLLABTRACK_KV.put(`user:${userId}`, JSON.stringify(user)),
    env.COLLABTRACK_KV.put(emailKey, JSON.stringify({ userId, passwordHash })),
    env.COLLABTRACK_KV.put(usernameKey, userId),
    env.COLLABTRACK_KV.put(mobileKey, userId),
  ]);

  const token = await signJWT({ sub: userId, username: user.username, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+60*60*24*30 }, env.JWT_SECRET);
  return json({ token, user }, 201);
}

async function login(req, env) {
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const { email, password } = b;
  if (!email || !password) return err('Email and password are required');
  const record = await env.COLLABTRACK_KV.get(`user:email:${email.toLowerCase().trim()}`, 'json');
  if (!record) return err('Invalid email or password', 401);
  const ok = await verifyPassword(password, record.passwordHash);
  if (!ok) return err('Invalid email or password', 401);
  const user = await env.COLLABTRACK_KV.get(`user:${record.userId}`, 'json');
  if (!user) return err('Account not found', 404);
  const token = await signJWT({ sub: record.userId, username: user.username, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+60*60*24*30 }, env.JWT_SECRET);
  return json({ token, user });
}

async function getMe(env, userId) {
  const user = await env.COLLABTRACK_KV.get(`user:${userId}`, 'json');
  if (!user) return err('User not found', 404);
  return json(user);
}

const TKEY = (userId, id) => `tracker:${userId}:${id}`;
async function kvListTrackers(kv, userId) {
  const list  = await kv.list({ prefix: `tracker:${userId}:` });
  const items = await Promise.all(list.keys.map(k => kv.get(k.name, 'json')));
  return items.filter(Boolean);
}

async function listTrackers(env, userId) {
  const all = await kvListTrackers(env.COLLABTRACK_KV, userId);
  all.sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));
  return json(all);
}

async function createTracker(req, env, userId) {
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const { brandName,contentType,platform,goLiveDate,pocName,pocContact,commercialAmount,expectedPaymentDate,notes } = b;
  if (!brandName?.trim()) return err('brandName required');
  if (!contentType)       return err('contentType required');
  if (!platform)          return err('platform required');
  if (!goLiveDate)        return err('goLiveDate required');
  const tracker = {
    id: crypto.randomUUID(), userId,
    brandName: brandName.trim(), contentType, platform, goLiveDate,
    pocName: pocName?.trim()||null, pocContact: pocContact?.trim()||null,
    commercialAmount: commercialAmount?Number(commercialAmount):null,
    expectedPaymentDate: expectedPaymentDate||null,
    notes: notes?.trim()||null,
    status:'live', paymentCreditedAt:null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };
  await env.COLLABTRACK_KV.put(TKEY(userId, tracker.id), JSON.stringify(tracker));
  return json(tracker, 201);
}

async function updateTracker(req, env, userId, id) {
  const existing = await env.COLLABTRACK_KV.get(TKEY(userId,id),'json');
  if (!existing) return err('Not found',404);
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const { userId:_,id:__,...rest } = b;
  const updated = { ...existing,...rest,id,userId,updatedAt:new Date().toISOString() };
  await env.COLLABTRACK_KV.put(TKEY(userId,id), JSON.stringify(updated));
  return json(updated);
}

async function markPaid(env, userId, id) {
  const existing = await env.COLLABTRACK_KV.get(TKEY(userId,id),'json');
  if (!existing) return err('Not found',404);
  const updated = { ...existing, status:'payment_credited', paymentCreditedAt:new Date().toISOString(), updatedAt:new Date().toISOString() };
  await env.COLLABTRACK_KV.put(TKEY(userId,id), JSON.stringify(updated));
  return json(updated);
}

async function deleteTracker(env, userId, id) {
  if (!await env.COLLABTRACK_KV.get(TKEY(userId,id))) return err('Not found',404);
  await env.COLLABTRACK_KV.delete(TKEY(userId,id));
  return json({success:true});
}

async function getStats(env, userId) {
  const all = await kvListTrackers(env.COLLABTRACK_KV, userId);
  const now = new Date();
  return json({
    totalTrackers:    all.length,
    activeTrackers:   all.filter(t=>t.status==='live').length,
    creditedTrackers: all.filter(t=>t.status==='payment_credited').length,
    thisMonthCount:   all.filter(t=>{ const d=new Date(t.createdAt); return d.getMonth()===now.getMonth()&&d.getFullYear()===now.getFullYear(); }).length,
  });
}

export default {
  async fetch(req, env) {
    if (req.method==='OPTIONS') return new Response(null,{headers:CORS});
    const {pathname} = new URL(req.url);
    const path = pathname.replace(/\/$/,'');
    const method = req.method;

    if (path==='/api/signup' && method==='POST') return signup(req,env);
    if (path==='/api/login'  && method==='POST') return login(req,env);

    const claims = await getUser(req,env);
    if (!claims) return err('Unauthorized',401);
    const userId = claims.sub;

    if (path==='/api/me'       && method==='GET')  return getMe(env,userId);
    if (path==='/api/stats'    && method==='GET')  return getStats(env,userId);
    if (path==='/api/trackers' && method==='GET')  return listTrackers(env,userId);
    if (path==='/api/trackers' && method==='POST') return createTracker(req,env,userId);

    const m1 = path.match(/^\/api\/trackers\/([\w-]+)$/);
    if (m1) {
      const id = m1[1];
      if (method==='PUT')    return updateTracker(req,env,userId,id);
      if (method==='DELETE') return deleteTracker(env,userId,id);
    }

    const m2 = path.match(/^\/api\/trackers\/([\w-]+)\/mark-paid$/);
    if (m2 && method==='PATCH') return markPaid(env,userId,m2[1]);

    return err('Not found',404);
  }
};
