// Cloudflare D1 store for the OIDC provider — the option to use when third parties depend on it.
//
// What KvOidcStore can only approximate, this does with single conditional statements:
//
//   consumeCode          DELETE ... RETURNING          exactly one redeemer gets the row
//   rotateRefreshToken   UPDATE ... WHERE used = 0     exactly one presenter wins the rotation
//
// D1 serializes writes to one database, so those statements are atomic against themselves.
// Schema: ../../migrations/oidc-d1.sql.

const MINUTE = 60;

export class D1OidcStore {
  /** @param {D1Database} db  A D1 binding, e.g. `env.DB`. */
  constructor(db) {
    if (!db) throw new Error("D1OidcStore: a D1 database binding is required");
    this.db = db;
  }

  run(sql, ...args) {
    return this.db.prepare(sql).bind(...args).run();
  }

  first(sql, ...args) {
    return this.db.prepare(sql).bind(...args).first();
  }

  // ---- authorization requests ----

  async saveRequest(id, request, ttlSeconds = 15 * MINUTE) {
    const expiresAt = nowSeconds() + ttlSeconds;
    await this.run("DELETE FROM oidc_requests WHERE expires_at < ?1", nowSeconds());
    await this.run(
      "INSERT OR REPLACE INTO oidc_requests (id, payload, expires_at) VALUES (?1, ?2, ?3)",
      id,
      JSON.stringify({ ...request, expiresAt }),
      expiresAt
    );
  }

  async peekRequest(id) {
    const row = await this.first("SELECT payload FROM oidc_requests WHERE id = ?1 AND expires_at > ?2", id, nowSeconds());
    return row ? JSON.parse(row.payload) : null;
  }

  async takeRequest(id) {
    const row = await this.first("DELETE FROM oidc_requests WHERE id = ?1 RETURNING payload, expires_at", id);
    return row && row.expires_at > nowSeconds() ? JSON.parse(row.payload) : null;
  }

  // ---- authorization codes ----

  async saveCode(code, payload, ttlSeconds = MINUTE) {
    const expiresAt = nowSeconds() + ttlSeconds;
    await this.run("DELETE FROM oidc_codes WHERE expires_at < ?1", nowSeconds());
    await this.run(
      "INSERT OR REPLACE INTO oidc_codes (code, payload, expires_at) VALUES (?1, ?2, ?3)",
      code,
      JSON.stringify({ ...payload, expiresAt }),
      expiresAt
    );
  }

  /** Delete-and-return in one statement: a second redeemer finds nothing. Burns expired codes too. */
  async consumeCode(code) {
    const row = await this.first("DELETE FROM oidc_codes WHERE code = ?1 RETURNING payload, expires_at", code);
    return row && row.expires_at > nowSeconds() ? JSON.parse(row.payload) : null;
  }

  // ---- refresh tokens ----

  async saveRefreshToken(token, payload, ttlSeconds) {
    const expiresAt = nowSeconds() + ttlSeconds;
    const { used = false, ...rest } = payload;
    // The NOT EXISTS guard is part of the insert, so a save cannot slip in after a revocation.
    await this.run(
      `INSERT OR REPLACE INTO oidc_refresh_tokens (token, family_id, user_id, client_id, payload, used, expires_at)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
       WHERE NOT EXISTS (SELECT 1 FROM oidc_revoked_families WHERE family_id = ?2)`,
      token,
      String(payload.familyId),
      String(payload.userId),
      String(payload.clientId),
      JSON.stringify(rest),
      used ? 1 : 0,
      expiresAt
    );
  }

  async getRefreshToken(token) {
    const row = await this.first("SELECT payload, used, expires_at FROM oidc_refresh_tokens WHERE token = ?1", token);
    if (!row) return null;
    if (row.expires_at <= nowSeconds()) {
      await this.deleteRefreshToken(token);
      return null;
    }
    return rowToToken(row);
  }

  /** One conditional UPDATE: of any number of simultaneous presenters, exactly one flips `used`. */
  async rotateRefreshToken(token) {
    const won = await this.first(
      `UPDATE oidc_refresh_tokens SET used = 1
       WHERE token = ?1 AND used = 0 AND expires_at > ?2
       RETURNING payload, used, expires_at`,
      token,
      nowSeconds()
    );
    if (won) return { status: "ok", payload: { ...rowToToken(won), used: false } };

    const row = await this.first("SELECT payload, used, expires_at FROM oidc_refresh_tokens WHERE token = ?1", token);
    if (!row || row.expires_at <= nowSeconds()) return { status: "missing" };
    return { status: "reused", payload: rowToToken(row) };
  }

  async deleteRefreshToken(token) {
    await this.run("DELETE FROM oidc_refresh_tokens WHERE token = ?1", token);
  }

  async revokeFamily(familyId) {
    await this.run(
      "INSERT OR IGNORE INTO oidc_revoked_families (family_id, revoked_at) VALUES (?1, ?2)",
      String(familyId),
      nowSeconds()
    );
    await this.run("DELETE FROM oidc_refresh_tokens WHERE family_id = ?1", String(familyId));
  }

  // ---- consent ----

  async getConsent(userId, clientId) {
    const row = await this.first(
      "SELECT scopes, granted_at FROM oidc_consents WHERE user_id = ?1 AND client_id = ?2",
      String(userId),
      String(clientId)
    );
    return row ? { scopes: JSON.parse(row.scopes), grantedAt: Number(row.granted_at) } : null;
  }

  async saveConsent(userId, clientId, scopes) {
    await this.run(
      "INSERT OR REPLACE INTO oidc_consents (user_id, client_id, scopes, granted_at) VALUES (?1, ?2, ?3, ?4)",
      String(userId),
      String(clientId),
      JSON.stringify(scopes),
      nowSeconds()
    );
  }

  async revokeConsent(userId, clientId) {
    await this.run("DELETE FROM oidc_consents WHERE user_id = ?1 AND client_id = ?2", String(userId), String(clientId));
    // Withdrawing consent has to take the client's live access with it.
    const rows = await this.db
      .prepare("SELECT DISTINCT family_id FROM oidc_refresh_tokens WHERE user_id = ?1 AND client_id = ?2")
      .bind(String(userId), String(clientId))
      .all();
    for (const { family_id } of rows.results) await this.revokeFamily(family_id);
  }
}

function rowToToken(row) {
  return { ...JSON.parse(row.payload), used: Boolean(row.used), expiresAt: Number(row.expires_at) };
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
