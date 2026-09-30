// Cloudflare Durable Object storage — one SQLite-backed object that can hold the login records,
// the OIDC provider's state, or both.
//
// This lives behind its own entry point (`telegram-qr-auth/do`) on purpose: the object class runs
// both the login store's SQL and the OIDC store's SQL, so importing it pulls in both. Keeping it
// out of the main and `/stores` entry points means a deployment that does not use Durable Objects,
// or does not use OIDC, never loads code it does not need.
//
// Choose it when you want a hard consistency guarantee without running a database:
//
//   - A Durable Object handles one request at a time and every method below is synchronous
//     against its own SQLite, so "check then write" spans cannot interleave. That is the property
//     KV lacks, and it is what makes `confirm`, `consumeCode` and `rotateRefreshToken` atomic.
//   - It is strongly consistent everywhere: a scan confirmed by the bot Worker is visible to the
//     poll on the very next request, which KV's eventual consistency does not promise.
//   - Objects are created on demand, so there is no database to provision and no schema to apply:
//     the object creates its own tables on first use.
//
// The trade-off is that everything routed to one object name funnels through one single-threaded
// object. That is a non-issue for a handful of users; `name` lets you shard by site if it ever is.
//
// The SQL is the D1 stores' SQL, run through a thin adapter, so D1 and DO behave identically and
// share one test suite. Only SQLite-backed Durable Objects are supported (`new_sqlite_classes`).
//
// Setup, in your Worker:
//
//     import { DurableObject } from "cloudflare:workers";
//     import { defineQrAuthStorage } from "telegram-qr-auth/do";
//     export class QrAuthStorage extends defineQrAuthStorage(DurableObject) {}
//
// and in wrangler.jsonc:
//
//     "durable_objects": { "bindings": [{ "name": "QRAUTH_DO", "class_name": "QrAuthStorage" }] },
//     "migrations": [{ "tag": "v1", "new_sqlite_classes": ["QrAuthStorage"] }]
//
// If the bot runs in a different Worker, bind the same class there with `script_name` pointing at
// the Worker that exports it — both halves then reach the same object.

import { D1LoginStore } from "./stores/d1.js";
import { D1OidcStore } from "./oidc/d1-store.js";

// The same tables as migrations/d1.sql and migrations/oidc-d1.sql, kept inline because a Worker
// cannot read files. One statement per entry: the DO SQL API is not asked to split them.
export const DO_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS telegram_qr_logins (
     token TEXT PRIMARY KEY, namespace TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
     telegram_user_id INTEGER, telegram_first_name TEXT, telegram_last_name TEXT, telegram_username TEXT,
     created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, confirmed_at INTEGER, client TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_telegram_qr_logins_expires_at ON telegram_qr_logins (expires_at)`,
  `CREATE TABLE IF NOT EXISTS oidc_requests (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oidc_codes (code TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
     token TEXT PRIMARY KEY, family_id TEXT NOT NULL, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
     payload TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_oidc_refresh_family ON oidc_refresh_tokens (family_id)`,
  `CREATE INDEX IF NOT EXISTS idx_oidc_refresh_grant ON oidc_refresh_tokens (user_id, client_id)`,
  `CREATE TABLE IF NOT EXISTS oidc_revoked_families (family_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oidc_consents (
     user_id TEXT NOT NULL, client_id TEXT NOT NULL, scopes TEXT NOT NULL, granted_at INTEGER NOT NULL,
     PRIMARY KEY (user_id, client_id))`,
];

export const LOGIN_METHODS = ["create", "get", "confirm", "consume", "remove", "sweep"];
export const OIDC_METHODS = [
  "saveRequest",
  "peekRequest",
  "takeRequest",
  "saveCode",
  "consumeCode",
  "saveRefreshToken",
  "getRefreshToken",
  "rotateRefreshToken",
  "deleteRefreshToken",
  "revokeFamily",
  "getConsent",
  "saveConsent",
  "revokeConsent",
];

/** Presents the D1 prepare/bind/run|first|all surface over a Durable Object's `storage.sql`. */
function d1Shim(sql) {
  return {
    prepare(query) {
      return {
        bind(...args) {
          // toArray() drains the cursor, which is also what makes rowsWritten final.
          const exec = () => {
            const cursor = sql.exec(query, ...args);
            return { rows: cursor.toArray(), cursor };
          };
          return {
            async all() {
              return { results: exec().rows };
            },
            async first() {
              return exec().rows[0] ?? null;
            },
            async run() {
              return { meta: { changes: exec().cursor.rowsWritten } };
            },
          };
        },
      };
    },
  };
}

/**
 * Builds the Durable Object class. `DurableObject` comes from "cloudflare:workers", which only
 * exists inside the Workers runtime — taking it as an argument keeps this file importable (and
 * testable) everywhere else.
 */
export function defineQrAuthStorage(Base) {
  class QrAuthStorage extends Base {
    constructor(ctx, env) {
      super(ctx, env);
      for (const statement of DO_SCHEMA) ctx.storage.sql.exec(statement);
      const db = d1Shim(ctx.storage.sql);
      this._login = new D1LoginStore(db);
      this._oidc = new D1OidcStore(db);
    }
  }

  // Public RPC surface: login_* and oidc_*. Each delegates to the D1 store method of the same name.
  for (const method of LOGIN_METHODS) {
    QrAuthStorage.prototype[`login_${method}`] = function (...args) {
      return this._login[method](...args);
    };
  }
  for (const method of OIDC_METHODS) {
    QrAuthStorage.prototype[`oidc_${method}`] = function (...args) {
      return this._oidc[method](...args);
    };
  }
  return QrAuthStorage;
}

/** Resolves the object for `name` on a Durable Object namespace binding. */
export function storageStub(binding, name) {
  if (!binding || typeof binding.idFromName !== "function") {
    throw new Error("a Durable Object namespace binding is required (e.g. env.QRAUTH_DO)");
  }
  return binding.get(binding.idFromName(name));
}

/**
 * Login-record store backed by a Durable Object. Drop-in for KVLoginStore / D1LoginStore.
 *
 * @param {DurableObjectNamespace} binding  e.g. `env.QRAUTH_DO`.
 * @param {object} [options]
 * @param {string} [options.name="default"]  Which object holds the records. The web Worker and the
 *   bot Worker must use the same name.
 */
export class DoLoginStore {
  constructor(binding, { name = "default" } = {}) {
    storageStub(binding, name); // fail at construction, not on the first sign-in
    this.binding = binding;
    this.name = name;
  }
}

for (const method of LOGIN_METHODS) {
  DoLoginStore.prototype[method] = function (...args) {
    return storageStub(this.binding, this.name)[`login_${method}`](...args);
  };
}

/**
 * OIDC provider state in the same Durable Object. Every operation is a single call into one object,
 * so code redemption and refresh rotation are atomic exactly as they are in D1OidcStore (which
 * supplies the SQL). Also exported from `telegram-qr-auth/oidc` for discoverability.
 *
 * @param {DurableObjectNamespace} binding  e.g. `env.QRAUTH_DO`.
 * @param {object} [options]
 * @param {string} [options.name="default"]  Object name. Sharing it with DoLoginStore is fine.
 */
export class DoOidcStore {
  constructor(binding, { name = "default" } = {}) {
    storageStub(binding, name);
    this.binding = binding;
    this.name = name;
  }
}

for (const method of OIDC_METHODS) {
  DoOidcStore.prototype[method] = function (...args) {
    return storageStub(this.binding, this.name)[`oidc_${method}`](...args);
  };
}
