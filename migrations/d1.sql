-- Schema for D1LoginStore (src/stores/d1.js).
--
-- Apply to the database that BOTH halves of the flow bind: the web app that mints tokens and the
-- bot that confirms them. On Cloudflare that usually means two Workers with a D1 binding each,
-- pointing at the same database.
--
--   wrangler d1 execute <your-db> --remote --file=node_modules/telegram-qr-auth/migrations/d1.sql
--
-- Rows here are short-lived by design: one per sign-in attempt, swept a day after expiry by the
-- store's own opportunistic cleanup. Nothing in this table is a durable record of anything — the
-- session lives in a signed cookie, not here — so it can be truncated at any time and the only
-- cost is that sign-ins in flight have to be restarted.
--
-- If you renamed the table via `new D1LoginStore(db, { table: "..." })`, rename it here too.

CREATE TABLE IF NOT EXISTS telegram_qr_logins (
  -- The one-time token, also the primary key: it is already a 128-bit random value.
  token TEXT PRIMARY KEY,

  -- Which app minted it. Lets one bot and one database serve several apps without their tokens
  -- being interchangeable — a token is only ever looked up together with its namespace.
  namespace TEXT NOT NULL,

  -- 'pending' until the bot confirms a scan, then 'confirmed'. There is no 'used' state: a token
  -- is deleted the moment it is redeemed, so a spent token is indistinguishable from one that
  -- never existed.
  status TEXT NOT NULL DEFAULT 'pending',

  -- Who scanned it. Null while pending. Cached here purely so the poll response can sign a
  -- display name into the session cookie without a second Telegram round-trip.
  telegram_user_id INTEGER,
  telegram_first_name TEXT,
  telegram_last_name TEXT,
  telegram_username TEXT,

  -- Unix epoch seconds. Stored as integers rather than SQLite datetime strings so the same rows
  -- read identically from Workers, Node and a plain sqlite3 shell, with no timezone ambiguity.
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  confirmed_at INTEGER,

  -- JSON: origin/IP/user-agent captured when the QR was displayed, echoed back by the bot so the
  -- person scanning can see what they are signing into. Null when captureClient is off.
  client TEXT
);

-- Serves the opportunistic sweep (DELETE ... WHERE expires_at < ?) and the expiry check.
CREATE INDEX IF NOT EXISTS idx_telegram_qr_logins_expires_at ON telegram_qr_logins (expires_at);
