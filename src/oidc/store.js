// Storage for the OIDC provider.
//
// The base package needs one ten-minute nonce record. A provider needs rather more, and unlike the
// login store, some of it is genuinely durable:
//
//   authorization requests  minutes   survives the QR sign-in detour, then discarded
//   authorization codes     ~60s      single-use, and reuse must be *detectable*
//   refresh tokens          months    rotated, and revocable — the only real revocation lever
//   consent grants          forever   "this user allowed this client these scopes"
//
// Codes and refresh tokens carry a hard single-use requirement, so `consumeCode` and
// `rotateRefreshToken` must be atomic against themselves. MemoryOidcStore gets that by doing each
// of them in a single synchronous step (no await between the check and the write — single-threaded
// JS makes one map operation atomic, not a span that awaits in the middle). KvOidcStore cannot:
// KV has no compare-and-swap, so it approximates. For a provider that third parties integrate
// with, use D1OidcStore (one conditional UPDATE per redemption), a Durable Object, or Postgres —
// the contract below is four collections of ordinary rows.

const MINUTE = 60;

/**
 * In-process implementation. Correct and complete, but only usable when one process serves every
 * endpoint — a single Node server, or tests. On Workers, sessions land in different isolates and
 * this store forgets everything between them.
 */
export class MemoryOidcStore {
  constructor() {
    this.requests = new Map();
    this.codes = new Map();
    this.refreshTokens = new Map();
    this.consents = new Map();
    this.revokedFamilies = new Set();
  }

  // ---- authorization requests (paused while the user scans a QR) ----

  async saveRequest(id, request, ttlSeconds = 15 * MINUTE) {
    this.requests.set(id, { ...request, expiresAt: nowSeconds() + ttlSeconds });
  }

  async takeRequest(id) {
    const request = this.requests.get(id);
    if (!request) return null;
    this.requests.delete(id);
    return request.expiresAt > nowSeconds() ? request : null;
  }

  /** Read without consuming — the consent screen needs to render before it decides. */
  async peekRequest(id) {
    const request = this.requests.get(id);
    if (!request || request.expiresAt <= nowSeconds()) return null;
    return request;
  }

  // ---- authorization codes ----

  async saveCode(code, payload, ttlSeconds = MINUTE) {
    this.codes.set(code, { ...payload, expiresAt: nowSeconds() + ttlSeconds });
  }

  /**
   * Single-use redemption. Returns the payload once and never again.
   *
   * The delete happens before any validation so that a *failed* redemption still burns the code:
   * an attacker who has stolen a code must not be able to probe it repeatedly.
   */
  async consumeCode(code) {
    const payload = this.codes.get(code);
    if (!payload) return null;
    this.codes.delete(code);
    return payload.expiresAt > nowSeconds() ? payload : null;
  }

  // ---- refresh tokens ----

  async saveRefreshToken(token, payload, ttlSeconds) {
    // A family killed by reuse detection stays dead: a request that was mid-flight when the family
    // was revoked must not be able to plant a fresh, live token in it afterwards.
    if (this.revokedFamilies.has(payload.familyId)) return;
    this.refreshTokens.set(token, { ...payload, expiresAt: nowSeconds() + ttlSeconds });
  }

  /**
   * Atomically spends a refresh token. The check and the write happen in one synchronous step, so
   * of any number of concurrent callers presenting the same token exactly one gets `status: "ok"`.
   *
   * @returns {Promise<{status: "ok"|"reused"|"missing", payload?: object}>}
   */
  async rotateRefreshToken(token) {
    const payload = this.refreshTokens.get(token);
    if (!payload || payload.expiresAt <= nowSeconds()) return { status: "missing" };
    if (payload.used) return { status: "reused", payload };
    this.refreshTokens.set(token, { ...payload, used: true });
    return { status: "ok", payload };
  }

  async getRefreshToken(token) {
    const payload = this.refreshTokens.get(token);
    if (!payload) return null;
    if (payload.expiresAt <= nowSeconds()) {
      this.refreshTokens.delete(token);
      return null;
    }
    return payload;
  }

  async deleteRefreshToken(token) {
    this.refreshTokens.delete(token);
  }

  /**
   * Revokes an entire token family.
   *
   * Called when a refresh token is presented twice. The second presentation means either the
   * client retried, or someone stole the token and the legitimate client already rotated it — and
   * the provider cannot tell which. Killing the whole family resolves it safely: the thief is cut
   * off, and the real user signs in again.
   */
  async revokeFamily(familyId) {
    this.revokedFamilies.add(familyId);
    for (const [token, payload] of this.refreshTokens) {
      if (payload.familyId === familyId) this.refreshTokens.delete(token);
    }
  }

  // ---- consent ----

  async getConsent(userId, clientId) {
    return this.consents.get(consentKey(userId, clientId)) ?? null;
  }

  async saveConsent(userId, clientId, scopes) {
    this.consents.set(consentKey(userId, clientId), { scopes, grantedAt: nowSeconds() });
  }

  async revokeConsent(userId, clientId) {
    this.consents.delete(consentKey(userId, clientId));
    for (const [token, payload] of this.refreshTokens) {
      // Withdrawing consent has to take the client's live access with it, or the button is a lie.
      if (String(payload.userId) === String(userId) && payload.clientId === clientId) {
        this.refreshTokens.delete(token);
      }
    }
  }
}

/**
 * Workers KV implementation.
 *
 * Read the caveat at the top of this file before using it for anything third parties touch: KV's
 * lack of compare-and-swap means `consumeCode` is a read-then-delete, so two simultaneous
 * redemptions of one stolen code could both succeed. Codes live 60 seconds and PKCE still has to
 * pass, so this is a narrow window rather than an open door — but it is a real difference from a
 * transactional store, and "narrow" is not "closed".
 */
export class KvOidcStore {
  constructor(kv, { prefix = "oidc:" } = {}) {
    if (!kv) throw new Error("KvOidcStore: a KV namespace binding is required");
    this.kv = kv;
    this.prefix = prefix;
  }

  key(kind, id) {
    return `${this.prefix}${kind}:${id}`;
  }

  async put(kind, id, value, ttlSeconds) {
    await this.kv.put(this.key(kind, id), JSON.stringify(value), { expirationTtl: Math.max(60, ttlSeconds) });
  }

  async saveRequest(id, request, ttlSeconds = 15 * MINUTE) {
    await this.put("req", id, { ...request, expiresAt: nowSeconds() + ttlSeconds }, ttlSeconds);
  }

  async peekRequest(id) {
    const request = await this.kv.get(this.key("req", id), "json");
    if (!request || request.expiresAt <= nowSeconds()) return null;
    return request;
  }

  async takeRequest(id) {
    const request = await this.peekRequest(id);
    if (request) await this.kv.delete(this.key("req", id));
    return request;
  }

  async saveCode(code, payload, ttlSeconds = MINUTE) {
    await this.put("code", code, { ...payload, expiresAt: nowSeconds() + ttlSeconds }, ttlSeconds);
  }

  async consumeCode(code) {
    const payload = await this.kv.get(this.key("code", code), "json");
    if (!payload) return null;
    await this.kv.delete(this.key("code", code)); // burn it even if it turns out to be expired
    return payload.expiresAt > nowSeconds() ? payload : null;
  }

  async saveRefreshToken(token, payload, ttlSeconds) {
    if (await this.kv.get(this.key("famrev", payload.familyId))) return; // family already killed
    await this.put("rt", token, { ...payload, expiresAt: nowSeconds() + ttlSeconds }, ttlSeconds);
    // Index by family so revokeFamily does not have to scan the namespace. Read-modify-write, so
    // two simultaneous saves into one family can lose an entry — see the caveat on this class.
    await this.appendIndex(this.key("fam", payload.familyId), token, ttlSeconds);
    // Index by grant (user + client) so revokeConsent can find the families it has to end.
    await this.appendIndex(this.key("grant", consentKey(payload.userId, payload.clientId)), payload.familyId, ttlSeconds);
  }

  async appendIndex(key, entry, ttlSeconds) {
    const list = (await this.kv.get(key, "json")) ?? [];
    if (!list.includes(entry)) list.push(entry);
    await this.kv.put(key, JSON.stringify(list), { expirationTtl: Math.max(60, ttlSeconds) });
  }

  /**
   * Best-effort rotation: KV has no compare-and-swap, so two simultaneous redemptions can both
   * read `used: false`. Use D1OidcStore where refresh-token theft matters.
   */
  async rotateRefreshToken(token) {
    const payload = await this.getRefreshToken(token);
    if (!payload) return { status: "missing" };
    if (payload.used) return { status: "reused", payload };
    await this.kv.put(this.key("rt", token), JSON.stringify({ ...payload, used: true }), {
      expirationTtl: Math.max(60, payload.expiresAt - nowSeconds()),
    });
    return { status: "ok", payload };
  }

  async getRefreshToken(token) {
    const payload = await this.kv.get(this.key("rt", token), "json");
    if (!payload) return null;
    if (payload.expiresAt <= nowSeconds()) {
      await this.kv.delete(this.key("rt", token));
      return null;
    }
    return payload;
  }

  async deleteRefreshToken(token) {
    await this.kv.delete(this.key("rt", token));
  }

  async revokeFamily(familyId) {
    // Tombstone first, so a save racing this revocation is refused rather than resurrecting it.
    await this.kv.put(this.key("famrev", familyId), "1", { expirationTtl: 400 * 24 * 3600 });
    const familyKey = this.key("fam", familyId);
    const family = (await this.kv.get(familyKey, "json")) ?? [];
    await Promise.all(family.map((token) => this.kv.delete(this.key("rt", token))));
    await this.kv.delete(familyKey);
  }

  async getConsent(userId, clientId) {
    return this.kv.get(this.key("consent", consentKey(userId, clientId)), "json");
  }

  async saveConsent(userId, clientId, scopes) {
    // No TTL: consent is durable until withdrawn, which is the point of asking once.
    await this.kv.put(
      this.key("consent", consentKey(userId, clientId)),
      JSON.stringify({ scopes, grantedAt: nowSeconds() })
    );
  }

  async revokeConsent(userId, clientId) {
    await this.kv.delete(this.key("consent", consentKey(userId, clientId)));
    // Withdrawing consent has to take the client's live access with it, or the button is a lie.
    const grantKey = this.key("grant", consentKey(userId, clientId));
    const families = (await this.kv.get(grantKey, "json")) ?? [];
    for (const familyId of families) await this.revokeFamily(familyId);
    await this.kv.delete(grantKey);
  }
}

function consentKey(userId, clientId) {
  return `${userId}|${clientId}`;
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
