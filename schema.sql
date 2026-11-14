-- ============================================================
-- flytripvisa-auth — D1 schema
-- Apply with: wrangler d1 execute flytripvisa-db --file=./schema.sql
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
-- email:    admin@flytripvisa.local
-- password: pass1122
--
-- NOTE: The hash + salt below are generated with the SAME
-- PBKDF2-SHA256 / 100,000 iterations / 256-bit key scheme used
-- by the Worker. To regenerate, run the helper from the README
-- (or browser console snippet) and paste the values here, then
-- re-apply the schema.
--
-- If you prefer, create the admin user by signing up once and
-- manually updating its role to 'admin' in D1.
-- ============================================================
INSERT INTO users (id, email, name, password_hash, salt, role)
VALUES (
  'admin-00000000-0000-4000-8000-000000000001',
  'admin@flytripvisa.local',
  'admin',
  'REPLACE_WITH_GENERATED_HASH',
  'REPLACE_WITH_GENERATED_SALT',
  'admin'
);
