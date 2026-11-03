-- ============================================================
--  FlyTripVisa — Cloudflare D1 Schema
--  Table: users
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT    NOT NULL DEFAULT '',
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  provider      TEXT    NOT NULL DEFAULT 'local',
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Index for fast email lookups during login
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- ============================================================
--  Seed a demo user (optional — remove in production)
--  Password: "password123" (PBKDF2-SHA256, 100k iterations)
--  Generate the real hash via the Worker's /api/auth/signup endpoint.
-- ============================================================
