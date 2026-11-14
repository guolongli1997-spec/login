/**
 * flytripvisa-auth — Cloudflare Worker
 * Zero dependencies. Web Crypto only.
 *
 * Routes:
 *   POST /api/auth/signup
 *   POST /api/auth/login
 *   GET  /api/auth/me
 *   (everything else -> static assets from ./public)
 */

// ------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN_BITS = 256;
const JWT_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ------------------------------------------------------------------
// In-memory fallback store (used only when env.DB is not bound)
// ------------------------------------------------------------------
const MEMORY_USERS = new Map(); // email -> user record
let warnedNoDB = false;

function warnNoDB() {
  if (!warnedNoDB) {
    console.warn(
      "[flytripvisa-auth] WARNING: env.DB not bound. Using in-memory store. Data will NOT persist and is NOT shared across isolates."
    );
    warnedNoDB = true;
  }
}

// ------------------------------------------------------------------
// Encoding helpers
// ------------------------------------------------------------------
const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}
function b64urlEncode(bytes) {
  let str = "";
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlEncodeString(s) {
  return b64urlEncode(enc.encode(s));
}

// ------------------------------------------------------------------
// PBKDF2 password hashing
// ------------------------------------------------------------------
async function hashPassword(password, saltHex) {
  const saltBytes = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    PBKDF2_KEYLEN_BITS
  );
  return { hash: toHex(bits), salt: toHex(saltBytes) };
}

async function verifyPassword(password, saltHex, expectedHashHex) {
  const { hash } = await hashPassword(password, saltHex);
  if (hash.length !== expectedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
  return diff === 0;
}

// ------------------------------------------------------------------
// JWT (HS256) — manual implementation
// ------------------------------------------------------------------
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64urlEncodeString(JSON.stringify(header));
  const p = b64urlEncodeString(JSON.stringify(payload));
  const data = `${h}.${p}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return `${data}.${b64urlEncode(sig)}`;
}

async function verifyJWT(token, secret) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const key = await hmacKey(secret);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    b64urlDecode(s),
    enc.encode(`${h}.${p}`)
  );
  if (!valid) return null;
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
  } catch {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now) return null;
  return payload;
}

// ------------------------------------------------------------------
// Response helpers
// ------------------------------------------------------------------
// NOTE: CORS is wide-open for development convenience.
// In production, replace "*" with your real domain, e.g.
//   "https://flytripvisa.com"
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
  });
}

function err(message, status = 400) {
  return json({ success: false, error: message }, status);
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role || "user" };
}

// ------------------------------------------------------------------
// Storage abstraction (D1 with in-memory fallback)
// ------------------------------------------------------------------
async function findUserByEmail(env, email) {
  if (env.DB) {
    const row = await env.DB.prepare("SELECT * FROM users WHERE email = ?1").bind(email).first();
    return row || null;
  }
  warnNoDB();
  return MEMORY_USERS.get(email) || null;
}

async function createUser(env, user) {
  if (env.DB) {
    await env.DB.prepare(
      `INSERT INTO users (id, email, name, password_hash, salt, role)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`
    )
      .bind(user.id, user.email, user.name, user.password_hash, user.salt, user.role || "user")
      .run();
    return user;
  }
  warnNoDB();
  MEMORY_USERS.set(user.email, user);
  return user;
}

// ------------------------------------------------------------------
// Route handlers
// ------------------------------------------------------------------
async function handleSignup(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("Invalid JSON body", 400);
  }
  const name = (body.name || "").trim();
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  if (!name || !email || !password) return err("name, email and password are required", 400);
  if (!EMAIL_RE.test(email)) return err("Invalid email format", 400);
  if (password.length < 6) return err("Password must be at least 6 characters", 400);

  const existing = await findUserByEmail(env, email);
  if (existing) return err("Email already registered", 409);

  const { hash, salt } = await hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    email,
    name,
    password_hash: hash,
    salt,
    role: "user",
  };

  try {
    await createUser(env, user);
  } catch (e) {
    // Race condition on UNIQUE constraint
    if (String(e).includes("UNIQUE")) return err("Email already registered", 409);
    console.error("[signup] DB error:", e.message);
    return err("Internal server error", 500);
  }

  const now = Math.floor(Date.now() / 1000);
  const token = await signJWT(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      iat: now,
      exp: now + JWT_TTL_SECONDS,
    },
    env.AUTH_SECRET
  );

  return json({
    success: true,
    token,
    user: publicUser(user),
    redirect: "/index.html",
  });
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("Invalid JSON body", 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  if (!email || !password) return err("email and password are required", 400);
  if (!EMAIL_RE.test(email)) return err("Invalid email format", 400);

  const user = await findUserByEmail(env, email);
  if (!user) return err("Invalid email or password", 401);

  const ok = await verifyPassword(password, user.salt, user.password_hash);
  if (!ok) return err("Invalid email or password", 401);

  const now = Math.floor(Date.now() / 1000);
  const token = await signJWT(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role || "user",
      iat: now,
      exp: now + JWT_TTL_SECONDS,
    },
    env.AUTH_SECRET
  );

  return json({
    success: true,
    token,
    user: publicUser(user),
    redirect: "/index.html",
  });
}

async function handleMe(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return err("Missing bearer token", 401);

  const payload = await verifyJWT(m[1], env.AUTH_SECRET);
  if (!payload) return err("Invalid or expired token", 401);

  return json({
    success: true,
    user: {
      id: payload.sub,
      name: payload.name,
      email: payload.email,
      role: payload.role,
    },
  });
}

// ------------------------------------------------------------------
// Main fetch handler
// ------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    // CORS preflight
    if (request.method === "OPTIONS" && pathname.startsWith("/api/")) {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (pathname === "/api/auth/signup" && request.method === "POST") {
        return await handleSignup(request, env);
      }
      if (pathname === "/api/auth/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }
      if (pathname === "/api/auth/me" && request.method === "GET") {
        return await handleMe(request, env);
      }
      if (pathname.startsWith("/api/")) {
        return err("Not found", 404);
      }
    } catch (e) {
      console.error("[worker] unhandled error:", e && e.message);
      return err("Internal server error", 500);
    }

    // Fall through to static assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response("Not found", { status: 404 });
  },
};
