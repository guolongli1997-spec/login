-- ============================================================
-- flytripvisa-auth — D1 schema
-- Apply with:
--   npx wrangler d1 execute flytripvisa-db --remote --file=./schema.sql
-- ============================================================

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  role          TEXT DEFAULT 'user',
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

-- ============================================================
-- Seed admin user
--   email:    admin@flytripvisa.local
--   password: pass1122
--   role:     admin
--
-- Hash parameters (must match src/worker.js):
--   algorithm  = PBKDF2
--   hash       = SHA-256
--   iterations = 100000
--   keylen     = 256 bits (32 bytes)
--   salt       = 16 random bytes, stored as 32 hex chars
--   hash       = 32 derived bytes, stored as 64 hex chars
-- ============================================================
INSERT INTO users (id, email, name, password_hash, salt, role)
VALUES (
  'admin-00000000-0000-4000-8000-000000000001',
  'admin@flytripvisa.local',
  'admin',
  'f1e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0e0b8b0',
  '00000000000000000000000000000001',
  'admin'
);
