// Test doubles. The D1 double runs *real* SQLite (node:sqlite) against the *real* migration file,
// so the store tests exercise the actual SQL — including the conditional UPDATE that makes
// `confirm` single-use — rather than a hand-rolled mock that would agree with whatever the code
// happens to do.

import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function makeFakeD1({ sql = "d1.sql" } = {}) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync(join(__dirname, "..", "migrations", sql), "utf8"));

  return {
    sqlite,
    prepare(query) {
      const stmt = sqlite.prepare(query);
      return {
        bind(...args) {
          return {
            async all() {
              return { results: stmt.all(...args) };
            },
            async first() {
              return stmt.get(...args) ?? null;
            },
            async run() {
              const info = stmt.run(...args);
              return { meta: { last_row_id: info.lastInsertRowid, changes: info.changes } };
            },
          };
        },
        // D1 allows .run() without .bind() for parameterless statements.
        async run() {
          const info = stmt.run();
          return { meta: { last_row_id: info.lastInsertRowid, changes: info.changes } };
        },
      };
    },
  };
}

/** An in-memory KV double covering the slice of the Workers KV API KVLoginStore uses. */
export function makeFakeKV() {
  const map = new Map();
  return {
    map,
    async put(key, value) {
      map.set(key, value);
    },
    async get(key, type) {
      const value = map.get(key);
      if (value === undefined) return null;
      return type === "json" ? JSON.parse(value) : value;
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

/**
 * Records API calls instead of hitting Telegram. `members` is the set of user ids that
 * getChatMember should report as being in the chat.
 */
export function makeFakeTelegram({ members = [], status = "member" } = {}) {
  const calls = [];
  const memberIds = new Set(members.map(Number));
  return {
    calls,
    memberIds,
    async call(method, payload) {
      calls.push({ method, payload });
      if (method === "getChatMember") {
        return { ok: true, result: { status: memberIds.has(Number(payload.user_id)) ? status : "left" } };
      }
      if (method === "sendMessage") return { ok: true, result: { message_id: 1 + calls.length } };
      return { ok: true, result: true };
    },
    async getChatMember(chatId, userId) {
      return this.call("getChatMember", { chat_id: chatId, user_id: userId });
    },
    async sendMessage(chatId, text, extra = {}) {
      return this.call("sendMessage", { chat_id: chatId, text, ...extra });
    },
    async deleteMessage(chatId, messageId) {
      return this.call("deleteMessage", { chat_id: chatId, message_id: messageId });
    },
  };
}

export function makeRequest(url, { method = "GET", cookie, headers = {} } = {}) {
  const merged = new Headers(headers);
  if (cookie) merged.set("Cookie", cookie);
  return new Request(url, { method, headers: merged });
}

/** Pulls a named cookie's value out of a Response's Set-Cookie header. */
export function cookieFrom(response, name) {
  const header = response.headers.get("Set-Cookie") || "";
  const match = header.match(new RegExp(`(?:^|,\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

export const ALICE = { id: 111, first_name: "Alice", last_name: "Ng", username: "alice" };
export const MALLORY = { id: 999, first_name: "Mallory" };

/**
 * A Durable Object namespace double. It builds the *real* storage class (from defineQrAuthStorage)
 * over real SQLite, and calls it the way RPC does: asynchronously, with arguments and results
 * passed through structuredClone so anything that could not cross the wire fails here too.
 */
export function makeFakeDONamespace(defineStorage) {
  class FakeDurableObject {
    constructor(ctx, env) {
      this.ctx = ctx;
      this.env = env;
    }
  }
  const StorageClass = defineStorage(FakeDurableObject);
  const objects = new Map();

  function makeSql() {
    const sqlite = new DatabaseSync(":memory:");
    return {
      exec(query, ...args) {
        const rows = sqlite.prepare(query).all(...args);
        const isRead = /^\s*select/i.test(query);
        const changes = isRead ? 0 : sqlite.prepare("SELECT changes() AS c").get().c;
        return { toArray: () => rows, rowsWritten: changes };
      },
    };
  }

  return {
    objects,
    idFromName: (name) => name,
    get(id) {
      if (!objects.has(id)) objects.set(id, new StorageClass({ storage: { sql: makeSql() } }, {}));
      const target = objects.get(id);
      return new Proxy(
        {},
        {
          get: (_, method) => async (...args) => structuredClone(await target[method](...structuredClone(args))),
        }
      );
    },
  };
}
