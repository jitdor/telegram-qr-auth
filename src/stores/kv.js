// Cloudflare Workers KV store — the recommended default.
//
// Nothing to create, nothing to migrate, nothing to clean up: `wrangler kv namespace create`, add
// the binding, done. KV's own TTL expires abandoned tokens, so there is no sweep and no cron. For
// a ten-minute nonce hand-off that happens a handful of times a day, this is the right shape of
// storage — a relational table would be a schema and a migration in exchange for guarantees this
// data mostly does not need.
//
// The two places KV is weaker than D1, stated plainly so the choice is informed:
//
//   1. Eventual consistency. The bot's write can take a moment to become visible to the polling
//      Worker. In practice that is an extra poll cycle or two before the page says "signed in" —
//      the token's 10-minute TTL absorbs it comfortably.
//   2. `confirm` is a read-then-write, and KV has no compare-and-swap, so two *genuinely
//      simultaneous* scans of the same QR could both succeed. Note what that actually costs: both
//      scanners already passed the authorization gate, so the outcome is two sessions for two
//      people who were each entitled to one — not an unauthorized session. The token is still
//      consumed on first redemption, so it cannot be replayed later.
//
// If neither of those is acceptable — you want one QR to mean exactly one session, always — use
// D1LoginStore, or a Durable Object.

export class KVLoginStore {
  /**
   * @param {KVNamespace} kv          A KV binding, e.g. `env.LOGINS`.
   * @param {object} [options]
   * @param {string} [options.prefix="tgqr:"]  Key prefix, so the namespace can be shared.
   */
  constructor(kv, { prefix = "tgqr:" } = {}) {
    if (!kv) throw new Error("KVLoginStore: a KV namespace binding is required");
    this.kv = kv;
    this.prefix = prefix;
  }

  key(token, namespace) {
    return `${this.prefix}${namespace}:${token}`;
  }

  async create({ token, namespace, expiresAt, client = null }) {
    const record = {
      token,
      namespace,
      status: "pending",
      user: null,
      createdAt: nowSeconds(),
      expiresAt,
      client,
    };
    // KV requires a TTL of at least 60s; pad past expiry so `get` can still tell an *expired*
    // token (report "expired", offer a fresh QR) apart from one that never existed ("invalid").
    const ttl = Math.max(60, expiresAt - nowSeconds() + 60);
    await this.kv.put(this.key(token, namespace), JSON.stringify(record), { expirationTtl: ttl });
  }

  async get(token, namespace) {
    return this.kv.get(this.key(token, namespace), "json");
  }

  async confirm(token, namespace, user) {
    const record = await this.get(token, namespace);
    if (!record || record.status !== "pending" || record.expiresAt <= nowSeconds()) return false;
    record.status = "confirmed";
    record.user = user;
    record.confirmedAt = nowSeconds();
    const ttl = Math.max(60, record.expiresAt - nowSeconds() + 60);
    await this.kv.put(this.key(token, namespace), JSON.stringify(record), { expirationTtl: ttl });
    return true;
  }

  async remove(token, namespace) {
    await this.kv.delete(this.key(token, namespace));
  }
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
