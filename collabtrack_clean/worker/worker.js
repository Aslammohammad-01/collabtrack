/**
 * CollabTrack — Cloudflare Worker API
 * ─────────────────────────────────────
 * SETUP (Cloudflare Dashboard):
 *
 * 1. Create Worker → paste this file → Save & Deploy
 * 2. Go to Settings → Variables → Add these Environment Variables:
 *      AUTH_PASSWORD  → your chosen login password   (set as Secret)
 *      JWT_SECRET     → any random 40+ char string   (set as Secret)
 * 3. Go to Settings → KV Namespace Bindings → Add binding:
 *      Variable name: COLLABTRACK_KV
 *      Namespace: (select the KV namespace you created)
 */

// ── CORS ─────────────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

// ── TINY JWT (HS256, no dependencies) ────────────────────────────────────────
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function b64urlDecode(s) {
  return atob(s.replace(/-/g,'+').replace(/_/g,'/'));
}
async function signJWT(payload, secret) {
  const enc = s => new TextEncoder().encode(s);
  const h = btoa(JSON.stringify({alg:'HS256',typ:'JWT'}));
  const b = btoa(JSON.stringify(payload));
  const data = `${h}.${b}`;
  const key  = await crypto.subtle.importKey('raw', enc(secret),
    {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig  = await crypto.subtle.sign('HMAC', key, enc(data));
  return `${data}.${b64url(sig)}`;
}
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, b, sig] = parts;
    const enc = s => new TextEncoder().encode(s);
    const key = await crypto.subtle.importKey('raw', enc(secret),
      {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
    const sigBytes = Uint8Array.from(b64urlDecode(sig), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, enc(`${h}.${b}`));
    if (!ok) return null;
    const payload = JSON.parse(b64urlDecode(b));
    if (payload.exp && payload.exp < Date.now()/1000) return null;
    return payload;
  } catch { return null; }
}

// ── RESPONSE HELPERS ─────────────────────────────────────────────────────────
const json = (d, s=200) => new Response(JSON.stringify(d), {
  status: s, headers: {...CORS, 'Content-Type':'application/json'}
});
const err = (m, s=400) => json({error: m}, s);

// ── KV HELPERS ───────────────────────────────────────────────────────────────
const KEY = id => `tracker:${id}`;

async function kvList(kv) {
  const list = await kv.list({prefix:'tracker:'});
  const items = await Promise.all(list.keys.map(k => kv.get(k.name,'json')));
  return items.filter(Boolean);
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}

// ── HANDLERS ─────────────────────────────────────────────────────────────────
async function login(req, env) {
  let body; try { body = await req.json(); } catch { return err('Bad JSON'); }
  if (!body.password || body.password !== env.AUTH_PASSWORD)
    return err('Wrong password', 401);
  const token = await signJWT({
    sub: 'user',
    iat: Math.floor(Date.now()/1000),
    exp: Math.floor(Date.now()/1000) + 60*60*24*30, // 30 days
  }, env.JWT_SECRET);
  return json({token});
}

async function listTrackers(env) {
  const all = await kvList(env.COLLABTRACK_KV);
  all.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  return json(all);
}

async function createTracker(req, env) {
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const {brandName,contentType,platform,goLiveDate,pocName,pocContact,
         commercialAmount,expectedPaymentDate,notes} = b;
  if (!brandName?.trim()) return err('brandName required');
  if (!contentType)       return err('contentType required');
  if (!platform)          return err('platform required');
  if (!goLiveDate)        return err('goLiveDate required');

  const tracker = {
    id: crypto.randomUUID(),
    brandName: brandName.trim(),
    contentType, platform, goLiveDate,
    pocName:             pocName?.trim()      || null,
    pocContact:          pocContact?.trim()   || null,
    commercialAmount:    commercialAmount ? Number(commercialAmount) : null,
    expectedPaymentDate: expectedPaymentDate  || null,
    notes:               notes?.trim()        || null,
    status: 'live',
    paymentCreditedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await env.COLLABTRACK_KV.put(KEY(tracker.id), JSON.stringify(tracker));
  return json(tracker, 201);
}

async function updateTracker(req, env, id) {
  const existing = await env.COLLABTRACK_KV.get(KEY(id),'json');
  if (!existing) return err('Not found', 404);
  let b; try { b = await req.json(); } catch { return err('Bad JSON'); }
  const updated = {...existing, ...b, id, updatedAt: new Date().toISOString()};
  await env.COLLABTRACK_KV.put(KEY(id), JSON.stringify(updated));
  return json(updated);
}

async function markPaid(env, id) {
  const existing = await env.COLLABTRACK_KV.get(KEY(id),'json');
  if (!existing) return err('Not found', 404);
  const updated = {
    ...existing,
    status: 'payment_credited',
    paymentCreditedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await env.COLLABTRACK_KV.put(KEY(id), JSON.stringify(updated));
  return json(updated);
}

async function deleteTracker(env, id) {
  if (!await env.COLLABTRACK_KV.get(KEY(id))) return err('Not found', 404);
  await env.COLLABTRACK_KV.delete(KEY(id));
  return json({success: true});
}

async function getStats(env) {
  const all = await kvList(env.COLLABTRACK_KV);
  const now = new Date();
  return json({
    totalTrackers:    all.length,
    activeTrackers:   all.filter(t => t.status==='live').length,
    creditedTrackers: all.filter(t => t.status==='payment_credited').length,
    thisMonthCount:   all.filter(t => {
      const d = new Date(t.createdAt);
      return d.getMonth()===now.getMonth() && d.getFullYear()===now.getFullYear();
    }).length,
  });
}

// ── ROUTER ────────────────────────────────────────────────────────────────────
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, {headers: CORS});

    const {pathname} = new URL(req.url);
    const path = pathname.replace(/\/$/,'');
    const method = req.method;

    // Public
    if (path==='/api/login' && method==='POST') return login(req, env);

    // Auth required
    const user = await getUser(req, env);
    if (!user) return err('Unauthorized', 401);

    if (path==='/api/stats'    && method==='GET')  return getStats(env);
    if (path==='/api/trackers' && method==='GET')  return listTrackers(env);
    if (path==='/api/trackers' && method==='POST') return createTracker(req, env);

    const m1 = path.match(/^\/api\/trackers\/([\w-]+)$/);
    if (m1) {
      const id = m1[1];
      if (method==='PUT')    return updateTracker(req, env, id);
      if (method==='DELETE') return deleteTracker(env, id);
    }

    const m2 = path.match(/^\/api\/trackers\/([\w-]+)\/mark-paid$/);
    if (m2 && method==='PATCH') return markPaid(env, m2[1]);

    return err('Not found', 404);
  }
};
