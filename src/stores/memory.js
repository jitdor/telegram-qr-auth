/**
 * In-process store. Correct and complete, but only usable when the page that mints the token and
 * the bot that confirms it run in the *same* process — a single Node/Bun/Deno server that also
 * handles the bot webhook, or a test. On Cloudflare Workers (separate isolates per request, and
 * usually a separate Worker for the bot) reach for D1LoginStore or KVLoginStore instead.
 */
export class MemoryLoginStore {
  constructor() {
    this.records = new Map();
  }

  key(token, namespace) {
    return `${namespace}:${token}`;
  }

  async create({ token, namespace, expiresAt, client = null }) {
    this.sweep();
    this.records.set(this.key(token, namespace), {
      token,
      namespace,
      status: "pending",
      user: null,
      createdAt: nowSeconds(),
      expiresAt,
      client,
    });
  }

  async get(token, namespace) {
    return this.records.get(this.key(token, namespace)) ?? null;
  }

  async confirm(token, namespace, user) {
    const record = this.records.get(this.key(token, namespace));
    // JS is single-threaded between these lines, so the pending check and the write are atomic.
    if (!record || record.status !== "pending" || record.expiresAt <= nowSeconds()) return false;
    record.status = "confirmed";
    record.user = user;
    record.confirmedAt = nowSeconds();
    return true;
  }

  /** Atomically takes a confirmed record out of the store; null if it wasn't there or confirmed. */
  async consume(token, namespace) {
    const key = this.key(token, namespace);
    const record = this.records.get(key);
    // Same as confirm: nothing yields between the check and the delete.
    if (!record || record.status !== "confirmed") return null;
    this.records.delete(key);
    return record;
  }

  async remove(token, namespace) {
    this.records.delete(this.key(token, namespace));
  }

  /** Drops expired records. Called on every create, so nothing else has to schedule it. */
  sweep() {
    const now = nowSeconds();
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) this.records.delete(key);
    }
  }
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}
