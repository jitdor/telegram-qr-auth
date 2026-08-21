// Cloudflare D1 store — the strict-consistency option, and what the original implementation this
// package was extracted from used.
//
// Prefer KVLoginStore unless one of these applies:
//
//   - You want a hard single-use guarantee. The conditional UPDATE in `confirm` below is atomic,
//     so two simultaneous scans of one QR can never both succeed.
//   - You already run D1 in this app, and one more table is cheaper than one more binding.
//   - You want to be able to look at sign-in attempts with `wrangler d1 execute`.
//
// The web Worker and the bot Worker bind the *same* database, and this table is the hand-off point
// between them. See ../../migrations/d1.sql. The table name is configurable so it can slot into an
// existing app database next to whatever else lives there.

const DEFAULT_TABLE = "telegram_qr_logins";

// A table name is interpolated into SQL, not bound as a parameter (SQLite doesn't allow binding
// identifiers), so it is validated rather than escaped.
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export class D1LoginStore {
  /**
   * @param {D1Database} db          A D1 binding, e.g. `env.DB`.
   * @param {object} [options]
   * @param {string} [options.table="telegram_qr_logins"]
   * @param {number} [options.sweepAfterSeconds=86400]  How long a spent/abandoned row may linger
   *   before the opportunistic sweep removes it. The sweep runs on `create` — the only path that
   *   adds rows — so a deployment needs no cron job for cleanup.
   */
  constructor(db, { table = DEFAULT_TABLE, sweepAfterSeconds = 24 * 3600 } = {}) {
    if (!db) throw new Error("D1LoginStore: a D1 database binding is required");
    if (!SAFE_IDENTIFIER.test(table)) throw new Error(`D1LoginStore: unsafe table name ${JSON.stringify(table)}`);
    this.db = db;
    this.table = table;
    this.sweepAfterSeconds = sweepAfterSeconds;
  }

  async create({ token, namespace, expiresAt, client = null }) {
    await this.sweep();
    await this.db
      .prepare(
        `INSERT INTO ${this.table} (token, namespace, status, created_at, expires_at, client)
         VALUES (?1, ?2, 'pending', ?3, ?4, ?5)`
      )
      .bind(token, namespace, nowSeconds(), expiresAt, client ? JSON.stringify(client) : null)
      .run();
  }

  async get(token, namespace) {
    const row = await this.db
      .prepare(
        `SELECT token, namespace, status, telegram_user_id, telegram_first_name, telegram_last_name,
                telegram_username, created_at, expires_at, confirmed_at, client
         FROM ${this.table} WHERE token = ?1 AND namespace = ?2`
      )
      .bind(token, namespace)
      .first();
    return row ? rowToRecord(row) : null;
  }

  async confirm(token, namespace, user) {
    // The `status = 'pending' AND expires_at > now` predicate lives in the UPDATE itself rather
    // than in a read-then-write pair, so two simultaneous scans of the same QR cannot both come
    // back true: exactly one of them reports changes === 1.
    const res = await this.db
      .prepare(
        `UPDATE ${this.table}
         SET status = 'confirmed', telegram_user_id = ?1, telegram_first_name = ?2,
             telegram_last_name = ?3, telegram_username = ?4, confirmed_at = ?5
         WHERE token = ?6 AND namespace = ?7 AND status = 'pending' AND expires_at > ?5`
      )
      .bind(
        user.id,
        user.first_name ?? "",
        user.last_name ?? "",
        user.username ?? "",
        nowSeconds(),
        token,
        namespace
      )
      .run();
    return res.meta.changes > 0;
  }

  async remove(token, namespace) {
    await this.db.prepare(`DELETE FROM ${this.table} WHERE token = ?1 AND namespace = ?2`).bind(token, namespace).run();
  }

  async sweep() {
    await this.db
      .prepare(`DELETE FROM ${this.table} WHERE expires_at < ?1`)
      .bind(nowSeconds() - this.sweepAfterSeconds)
      .run();
  }
}

function rowToRecord(row) {
  return {
    token: row.token,
    namespace: row.namespace,
    status: row.status,
    user:
      row.telegram_user_id == null
        ? null
        : {
            id: Number(row.telegram_user_id),
            first_name: row.telegram_first_name ?? "",
            last_name: row.telegram_last_name ?? "",
            username: row.telegram_username ?? "",
          },
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
    confirmedAt: row.confirmed_at == null ? null : Number(row.confirmed_at),
    client: parseJson(row.client),
  };
}

function parseJson(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
