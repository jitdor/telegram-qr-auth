-- Schema for D1OidcStore (src/oidc/d1-store.js).
--
--   wrangler d1 execute <your-db> --remote --file=node_modules/telegram-qr-auth/migrations/oidc-d1.sql
--
-- Unlike the login table, some of this is durable: consents live until withdrawn and refresh
-- tokens for months. Back the database up accordingly. Codes and paused requests are short-lived
-- and swept opportunistically.

CREATE TABLE IF NOT EXISTS oidc_requests (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_codes (
  code TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
  token TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_family ON oidc_refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_grant ON oidc_refresh_tokens (user_id, client_id);

-- Families killed by reuse detection or consent withdrawal. Checked when a token is saved, so a
-- request that was mid-flight at revocation cannot plant a live token afterwards.
CREATE TABLE IF NOT EXISTS oidc_revoked_families (
  family_id TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_consents (
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, client_id)
);
