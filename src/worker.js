/**
 * FlyTripVisa - Login — Auth Worker
 * Cloudflare Worker handling /api/auth/signup, /api/auth/login, /api/auth/me.
 * Connects to D1 for user storage, hashes passwords with PBKDF2 (Web Crypto),
 * and issues HS256 JWT session tokens.
 *
 * Bindings (see wrangler.jsonc):
 *   - DB          (D1)       → users table
 *   - AUTH_SECRET (secret)   → HMAC key for signing JWTs
 *   - ASSETS      (assets)   → serves static files from /public
 *
 * If D1 is not bound (local dev without --local DB), the Worker falls back
 * to an in-memory mock store so the UI is fully testable.
 */

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', ...extra },
  });

const b64url = (buf) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

const b64urlStr = (str) => btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

// ──────────────────────────────────────────────
// Password hashing — PBKDF2 (SHA-256), 100k iterations
// ──────────────────────────────────────────────
async function hashPassword(password, saltB64) {
  const salt = saltB64
    ? Uint8Array.from(atob(saltB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return `${b64url(salt)}:${b64url(bits)}`;
}

async function verifyPassword(password, stored) {
  const [saltB64] = stored.split(':');
  const computed = await hashPassword(password, saltB64);
  return computed === stored;
}

// ──────────────────────────────────────────────
// JWT (HS256) — sign & verify
// ──────────────────────────────────────────────
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const data = `${b64urlStr(JSON.stringify(header))}.${b64urlStr(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'HMAC', key,
    Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
    enc.encode(data)
  );
  if (!valid) return null;
  const payload = JSON.parse(dec.decode(Uint8Array.from(atob(data.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

// ──────────────────────────────────────────────
// Mock store (fallback when D1 is absent)
// ──────────────────────────────────────────────
const mockUsers = new Map();

// ──────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ──────────────────────────────────────────────
// Main handler
// ──────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    // ── API routes take priority ──
    if (url.pathname.startsWith('/api/')) {
      return handleAPI(request, env, url);
    }

    // ── Static assets via ASSETS binding ──
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return json({ error: 'Static assets binding not configured.' }, 500);
  },
};

async function handleAPI(request, env, url) {
  const hasD1 = typeof env.DB !== 'undefined';
  const secret = env.AUTH_SECRET || 'dev-secret-change-me';

  // ── /api/auth/signup ──
  if (url.pathname === '/api/auth/signup' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

    const name = (body.name || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!name) return json({ error: 'Name is required.' }, 400);
    if (!emailRe.test(email)) return json({ error: 'A valid email address is required.' }, 400);
    if (password.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400);

    const passwordHash = await hashPassword(password);

    if (hasD1) {
      try {
        await env.DB.prepare(
          'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
        ).bind(name, email, passwordHash).run();
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json({ error: 'An account with that email already exists.' }, 409);
        }
        return json({ error: 'Database error: ' + e.message }, 500);
      }
    } else {
      if ([...mockUsers.values()].some(u => u.email === email)) {
        return json({ error: 'An account with that email already exists.' }, 409);
      }
      const id = mockUsers.size + 1;
      mockUsers.set(id, { id, name, email, password_hash: passwordHash, created_at: new Date().toISOString() });
    }

    const token = await signJWT(
      { sub: email, name, iat: Date.now(), exp: Date.now() + 30 * 24 * 60 * 60 * 1000 },
      secret
    );
    return json({ token, user: { name, email }, redirect: 'index.html' }, 201);
  }

  // ── /api/auth/login ──
  if (url.pathname === '/api/auth/login' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body.' }, 400); }

    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!email || !password) return json({ error: 'Email and password are required.' }, 400);

    let user;
    if (hasD1) {
      user = await env.DB.prepare(
        'SELECT * FROM users WHERE email = ?'
      ).bind(email).first();
    } else {
      user = [...mockUsers.values()].find(u => u.email === email) || null;
    }

    if (!user) return json({ error: 'No account found with that email.' }, 401);

    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) return json({ error: 'Incorrect password. Please try again.' }, 401);

    const token = await signJWT(
      { sub: user.email, name: user.name, iat: Date.now(), exp: Date.now() + 30 * 24 * 60 * 60 * 1000 },
      secret
    );
    return json({ token, user: { name: user.name, email: user.email }, redirect: 'index.html' }, 200);
  }

  // ── /api/auth/me (verify token) ──
  if (url.pathname === '/api/auth/me' && request.method === 'GET') {
    const auth = request.headers.get('Authorization') || '';
    const token = auth.replace(/^Bearer\s+/i, '');
    if (!token) return json({ error: 'No token provided.' }, 401);
    const payload = await verifyJWT(token, secret);
    if (!payload) return json({ error: 'Invalid or expired token.' }, 401);
    return json({ user: { name: payload.name, email: payload.sub } }, 200);
  }

  // ── 404 ──
  return json({ error: 'Endpoint not found.', path: url.pathname }, 404);
}
