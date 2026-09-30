// Login-token stores.
//
// A store holds one short-lived record per pending sign-in and is the only shared state in this
// package. Worth being precise about how little that is: there is no user table, ever. Identity
// comes from Telegram, authorization comes from a group membership check or an env var, and the
// session is a signed cookie. All a store ever holds is "someone is part-way through signing in",
// for ten minutes, and then nothing.
//
// It exists at all because the two halves of the flow are usually two different processes — a web
// app and the bot's webhook, often two separate Workers — and the browser has to learn, seconds
// later, that a phone somewhere else confirmed its token. That hand-off is irreducibly shared
// mutable state: it cannot be an env var, a config file, or a signed value, because one process
// writes it and a different one reads it. Hence an injected store rather than an in-process map.
//
// KVLoginStore is the recommended default: no schema, no migration, TTL-based cleanup for free.
// Reach for D1LoginStore, or DoLoginStore from `telegram-qr-auth/do` (a SQLite-backed Durable
// Object; no database to provision), if you want a strictly atomic single-use guarantee and
// read-your-writes consistency between the web Worker and the bot, and for MemoryLoginStore only
// when both halves share one process.
//
// The contract:
//
//   create(record)                   record = { token, namespace, expiresAt, client }
//   get(token, namespace)            returns record or null
//   confirm(token, namespace, user)  returns true only if it was still pending
//   remove(token, namespace)
//
// `confirm` should be atomic against a concurrent `confirm` — two scans of the same QR should not
// both succeed. D1LoginStore gets that from a conditional single-statement UPDATE and
// MemoryLoginStore from JS being single-threaded; KVLoginStore can only approximate it, since KV
// has no compare-and-swap (see its own notes).
//
// A returned record looks like:
//   { token, namespace, status: "pending" | "confirmed", user: null | { id, first_name, last_name,
//     username }, createdAt: epochSeconds, expiresAt: epochSeconds, client: null | {...} }

export { KVLoginStore } from "./kv.js";
export { D1LoginStore } from "./d1.js";
export { MemoryLoginStore } from "./memory.js";
