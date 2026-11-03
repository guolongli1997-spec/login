# FlyTripVisa-Login — Full-Stack Serverless Auth

A production-ready authentication system built entirely on Cloudflare's edge platform:

- **`auth.html`** — Dark-themed (pure black) login/signup portal with animated tab toggle and authentic Google / Facebook / Instagram social buttons.
- **`index.html`** — Landing page with a session-aware navbar that reads `localStorage.ftv_auth_token` and shows a personalized greeting + logout, or guest login/signup links.
- **`worker.js`** — Cloudflare Worker backend with `/api/auth/signup`, `/api/auth/login`, and `/api/auth/me`. PBKDF2 password hashing, HS256 JWT sessions, D1 storage, and an in-memory mock fallback for local testing.
- **`wrangler.jsonc`** — Worker configuration with D1 binding.
- **`schema.sql`** — D1 `users` table definition.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | ≥ 18 | https://nodejs.org |
| Wrangler | latest | `npm install -g wrangler` |
| Cloudflare account | free tier OK | https://dash.cloudflare.com/sign-up |

Log in once:
```bash
wrangler login
```

---

## Step 1 — Create the D1 database

```bash
wrangler d1 create flytripvisa-db
```

Copy the `database_id` from the output and paste it into `wrangler.jsonc`, replacing `REPLACE_WITH_YOUR_D1_DATABASE_ID`.

---

## Step 2 — Run the schema migration

Apply the schema to your **remote** (production) database:

```bash
wrangler d1 execute flytripvisa-db --remote --file=schema.sql
```

For **local** development, apply it to the local SQLite mirror:

```bash
wrangler d1 execute flytripvisa-db --local --file=schema.sql
```

---

## Step 3 — Set the JWT signing secret

```bash
wrangler secret put AUTH_SECRET
```

When prompted, paste a long random string (e.g. generate one with `openssl rand -base64 32`). This is the HMAC key used to sign session tokens — never commit it to git.

> **Local dev note:** `wrangler dev` reads secrets from `.dev.vars`. Create that file:
> ```
> AUTH_SECRET="your-local-dev-secret"
> ```
> (Add `.dev.vars` to `.gitignore`.)

---

## Step 4 — Local testing with `wrangler dev`

```bash
wrangler dev
```

This starts the Worker at `http://localhost:8787`. Because `wrangler dev` uses the **local** D1 mirror by default, run the local migration (Step 2) first.

Serve the static HTML files alongside the Worker. The simplest approach is to open `auth.html` and `index.html` directly in a browser, but the forms POST to `/api/auth/*` — so either:

- **Option A:** Deploy the Worker and point the forms at its URL, or
- **Option B:** Serve everything from one origin. Add a static-assets binding or use `wrangler pages dev`:

```bash
wrangler pages dev . --binding DB=flytripvisa-db --d1 flytripvisa-db
```

**Test the endpoints directly:**

```bash
# Signup
curl -X POST http://localhost:8787/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8787/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jane@example.com","password":"password123"}'

# Verify token
curl http://localhost:8787/api/auth/me \
  -H "Authorization: Bearer <token-from-login>"
```

> If D1 is not bound (e.g. running without `--local`), the Worker automatically falls back to an in-memory mock user store so you can still test the full UI flow end-to-end.

---

## Step 5 — Global deployment

```bash
wrangler deploy
```

This publishes the Worker to Cloudflare's global edge network. You'll get a URL like:

```
https://flytripvisa-auth.<your-subdomain>.workers.dev
```

---

## Step 6 — Connect the frontend to the Worker

The forms in `auth.html` POST to relative paths (`/api/auth/login`, `/api/auth/signup`). For this to work, the HTML and the Worker must be served from the **same origin**. Two options:

### Option A — Cloudflare Pages (recommended for static assets)

```bash
wrangler pages deploy . --project-name flytripvisa
```

Then add a Pages Function or a Worker binding so `/api/*` routes to your auth Worker. In the Pages dashboard, set a **Worker binding** named `AUTH` pointing to `flytripvisa-auth`, and add a `_routes.json`:

```json
{ "version": 1, "include": ["/*"], "exclude": ["/api/*"] }
```

### Option B — Worker serves everything

Add static-asset serving to `worker.js` using the `assets` binding in `wrangler.jsonc`:

```jsonc
{
  "assets": {
    "directory": "./",
    "binding": "ASSETS"
  }
}
```

Then in the Worker's `fetch`, serve assets for non-API routes. The Worker's `/api/*` routes take priority.

---

## Step 7 — Session flow

1. User visits `index.html`. The navbar script checks `localStorage.ftv_auth_token`.
2. If absent → shows **Log In** and **Sign Up** buttons. Clicking either stores the preferred tab in `sessionStorage.ftv_preferred_tab` and redirects to `auth.html?mode=<login|signup>`.
3. `auth.html` reads the URL `?mode=` or `sessionStorage` to open the correct tab.
4. On submit, the form POSTs to the Worker. On success, the Worker returns `{ token, user, redirect }`.
5. The frontend stores `ftv_auth_token` and `ftv_user` in `localStorage`, then redirects to `index.html`.
6. `index.html` now detects the token and renders **"Hi, {name} 👋"** + **Log out**.
7. Log out clears `localStorage` and `sessionStorage`, then reloads.

---

## Security notes

- **Password hashing** uses PBKDF2 (SHA-256, 100,000 iterations) with a per-user random salt — handled entirely in the Worker via the Web Crypto API.
- **JWT tokens** are HS256-signed with `AUTH_SECRET` and expire after 30 days.
- **CORS** is permissive (`*`) for development — restrict `Access-Control-Allow-Origin` to your production domain before launch.
- **HTTPS** is automatic on all `*.workers.dev` and Pages domains.
- For social OAuth, register apps at Google / Facebook / Instagram developer consoles and add OAuth callback routes to the Worker.

---

## Project structure

```
flytripvisa/
├── auth.html        # Dark login/signup portal
├── index.html       # Session-aware landing page
├── worker.js        # Cloudflare Worker auth API
├── wrangler.jsonc   # Worker + D1 config
├── schema.sql       # D1 users table
└── README.md        # This file
```
