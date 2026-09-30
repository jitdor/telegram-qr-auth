// The same contract test run against every bundled store, so a new store can be added by
// dropping it into the table below.

import test from "node:test";
import assert from "node:assert/strict";

import { MemoryLoginStore } from "../src/stores/memory.js";
import { D1LoginStore } from "../src/stores/d1.js";
import { KVLoginStore } from "../src/stores/kv.js";
import { DoLoginStore, defineQrAuthStorage } from "../src/do.js";
import { makeFakeD1, makeFakeKV, makeFakeDONamespace, ALICE } from "./helpers.mjs";

const NS = "cockpit";
const USER = { id: ALICE.id, first_name: "Alice", last_name: "Ng", username: "alice" };

const stores = [
  ["MemoryLoginStore", () => new MemoryLoginStore()],
  ["D1LoginStore", () => new D1LoginStore(makeFakeD1())],
  ["KVLoginStore", () => new KVLoginStore(makeFakeKV())],
  ["DoLoginStore", () => new DoLoginStore(makeFakeDONamespace(defineQrAuthStorage))],
];

function future(seconds = 600) {
  return Math.floor(Date.now() / 1000) + seconds;
}

for (const [name, make] of stores) {
  test(`${name}: create then get returns a pending record`, async () => {
    const store = make();
    await store.create({ token: "a".repeat(32), namespace: NS, expiresAt: future() });
    const record = await store.get("a".repeat(32), NS);
    assert.equal(record.status, "pending");
    assert.equal(record.user, null);
    assert.equal(record.namespace, NS);
    assert.ok(record.expiresAt > Math.floor(Date.now() / 1000));
  });

  test(`${name}: confirm stores the user and flips status once`, async () => {
    const store = make();
    const token = "b".repeat(32);
    await store.create({ token, namespace: NS, expiresAt: future() });

    assert.equal(await store.confirm(token, NS, USER), true);
    assert.equal(await store.confirm(token, NS, { ...USER, id: 999 }), false, "confirm must be single-use");

    const record = await store.get(token, NS);
    assert.equal(record.status, "confirmed");
    assert.deepEqual(record.user, USER);
  });

  test(`${name}: an expired record cannot be confirmed`, async () => {
    const store = make();
    const token = "c".repeat(32);
    await store.create({ token, namespace: NS, expiresAt: Math.floor(Date.now() / 1000) - 1 });
    assert.equal(await store.confirm(token, NS, USER), false);
  });

  test(`${name}: unknown tokens are null, not errors`, async () => {
    const store = make();
    assert.equal(await store.get("d".repeat(32), NS), null);
    assert.equal(await store.confirm("d".repeat(32), NS, USER), false);
    await store.remove("d".repeat(32), NS); // must not throw
  });

  test(`${name}: namespaces are isolated`, async () => {
    const store = make();
    const token = "e".repeat(32);
    await store.create({ token, namespace: NS, expiresAt: future() });
    assert.equal(await store.get(token, "other"), null);
    assert.equal(await store.confirm(token, "other", USER), false);
  });

  test(`${name}: remove really removes`, async () => {
    const store = make();
    const token = "f".repeat(32);
    await store.create({ token, namespace: NS, expiresAt: future() });
    await store.remove(token, NS);
    assert.equal(await store.get(token, NS), null);
  });

  test(`${name}: consume takes a confirmed record exactly once`, async () => {
    const store = make();
    const token = "c".repeat(32);
    await store.create({ token, namespace: NS, expiresAt: future() });
    assert.equal(await store.consume(token, NS), null, "a pending record is not consumable");
    assert.equal((await store.get(token, NS)).status, "pending", "and is left alone");

    await store.confirm(token, NS, USER);
    const consumed = await store.consume(token, NS);
    assert.equal(consumed.status, "confirmed");
    assert.deepEqual(consumed.user, USER);
    assert.equal(await store.consume(token, NS), null, "consume is single-use");
    assert.equal(await store.get(token, NS), null);
  });

  test(`${name}: client context round-trips`, async () => {
    const store = make();
    const token = "1".repeat(32);
    const client = { ip: "203.0.113.7", userAgent: "UA", origin: "https://app.example", at: "2026-08-22T00:00:00.000Z" };
    await store.create({ token, namespace: NS, expiresAt: future(), client });
    assert.deepEqual((await store.get(token, NS)).client, client);
  });
}

test("D1LoginStore rejects an unsafe table name instead of interpolating it", () => {
  // The table name goes into SQL as an identifier, which cannot be bound as a parameter.
  assert.throws(() => new D1LoginStore(makeFakeD1(), { table: "logins; DROP TABLE users" }), /unsafe table name/);
  assert.throws(() => new D1LoginStore(makeFakeD1(), { table: "1bad" }), /unsafe table name/);
  assert.doesNotThrow(() => new D1LoginStore(makeFakeD1(), { table: "telegram_qr_logins" }));
});

test("D1LoginStore sweeps rows that expired long ago, and spares the rest", async () => {
  const db = makeFakeD1();
  const store = new D1LoginStore(db, { sweepAfterSeconds: 3600 });
  const now = Math.floor(Date.now() / 1000);

  const rows = [
    ["stale", now - 7200],
    ["recent", now - 60],
    ["live", now + 600],
  ];
  for (const [token, expiresAt] of rows) {
    await db
      .prepare(
        `INSERT INTO telegram_qr_logins (token, namespace, status, created_at, expires_at)
         VALUES (?1, ?2, 'pending', ?3, ?4)`
      )
      .bind(token, NS, now - 100, expiresAt)
      .run();
  }

  await store.sweep();
  assert.equal(await store.get("stale", NS), null);
  assert.ok(await store.get("recent", NS), "a just-expired row is kept so the page can say 'expired'");
  assert.ok(await store.get("live", NS));
});

test("stores require their binding", () => {
  assert.throws(() => new D1LoginStore(null), /required/);
  assert.throws(() => new KVLoginStore(undefined), /required/);
});
