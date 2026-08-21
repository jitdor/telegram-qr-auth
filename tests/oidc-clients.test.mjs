// The client registry, and redirect_uri matching in particular — the function where a mistake
// becomes "an attacker receives an authorization code for whoever just signed in".

import test from "node:test";
import assert from "node:assert/strict";

import {
  StaticClientRegistry,
  StoreClientRegistry,
  validateClient,
  matchRedirectUri,
  verifyClientSecret,
  subjectFor,
  sectorIdentifierFor,
} from "../src/oidc/clients.js";

const BASE = {
  client_id: "app-a",
  client_name: "App A",
  redirect_uris: ["https://app-a.example.com/callback"],
};

test("a valid client registers and comes back with defaults filled in", async () => {
  const registry = new StaticClientRegistry([BASE]);
  const client = await registry.get("app-a");

  assert.equal(client.client_id, "app-a");
  assert.equal(client.type, "public");
  assert.deepEqual(client.scopes, ["openid", "profile"]);
  assert.equal(client.first_party, false);
  assert.equal(client.pairwise, false);
  assert.equal(await registry.get("nope"), null);
});

test("configuration mistakes fail at construction", () => {
  assert.throws(() => new StaticClientRegistry([]), /at least one/);
  assert.throws(() => new StaticClientRegistry([{ ...BASE, client_id: undefined }]), /client_id/);
  assert.throws(() => new StaticClientRegistry([{ ...BASE, client_name: undefined }]), /client_name/);
  assert.throws(() => new StaticClientRegistry([{ ...BASE, redirect_uris: [] }]), /redirect_uris/);
  assert.throws(() => new StaticClientRegistry([BASE, BASE]), /duplicate client_id/);

  // A confidential client without a secret cannot authenticate; a public one with a secret is
  // pretending to keep something it cannot keep.
  assert.throws(() => new StaticClientRegistry([{ ...BASE, type: "confidential" }]), /client_secret/);
  assert.throws(() => new StaticClientRegistry([{ ...BASE, client_secret: "s3cret" }]), /must not have a `client_secret`/);
  assert.throws(() => new StaticClientRegistry([{ ...BASE, type: "weird" }]), /must be "public" or "confidential"/);
});

test("unsafe redirect_uris are rejected at registration", () => {
  const bad = [
    ["not-a-uri", /absolute URI/],
    ["/relative/callback", /absolute URI/],
    ["http://app-a.example.com/cb", /must use https/],
    ["https://app-a.example.com/cb#fragment", /must not contain a fragment/],
  ];

  for (const [uri, pattern] of bad) {
    assert.throws(() => validateClient({ ...BASE, redirect_uris: [uri] }), pattern, `expected ${uri} to be rejected`);
  }
});

test("http is allowed for loopback and custom schemes for native apps", () => {
  assert.doesNotThrow(() => validateClient({ ...BASE, redirect_uris: ["http://127.0.0.1:8123/cb"] }));
  assert.doesNotThrow(() => validateClient({ ...BASE, redirect_uris: ["http://localhost:8123/cb"] }));
  assert.doesNotThrow(() => validateClient({ ...BASE, redirect_uris: ["com.example.app:/oauth"] }));
});

test("redirect_uri matching is exact — no prefixes, no wildcards, no normalisation", () => {
  const client = validateClient({ ...BASE, redirect_uris: ["https://app-a.example.com/callback"] });

  assert.equal(matchRedirectUri(client, "https://app-a.example.com/callback"), "https://app-a.example.com/callback");

  // Every one of these is a real-world open-redirect shape.
  const attacks = [
    "https://app-a.example.com/callback/../../evil",
    "https://app-a.example.com/callback2",
    "https://app-a.example.com/callback?next=https://evil.example",
    "https://app-a.example.com/callback/",
    "https://app-a.example.com.evil.example/callback",
    "https://evil.example/callback",
    "https://app-a.example.com:8443/callback",
    "http://app-a.example.com/callback",
    "//evil.example",
    "",
    null,
    undefined,
  ];

  for (const candidate of attacks) {
    assert.equal(matchRedirectUri(client, candidate), null, `expected ${String(candidate)} to be refused`);
  }
});

test("loopback ports are ignored, and only for loopback", () => {
  // RFC 8252: a native app binds whatever port the OS hands it, so the port cannot be pre-registered.
  const native = validateClient({ ...BASE, redirect_uris: ["http://127.0.0.1:0/cb"] });
  assert.equal(matchRedirectUri(native, "http://127.0.0.1:54321/cb"), "http://127.0.0.1:54321/cb");
  assert.equal(matchRedirectUri(native, "http://127.0.0.1:54321/other"), null, "the path still has to match");
  assert.equal(matchRedirectUri(native, "http://evil.example:54321/cb"), null);

  // The same leniency must NOT apply to a normal https client.
  const web = validateClient(BASE);
  assert.equal(matchRedirectUri(web, "https://app-a.example.com:9999/callback"), null);
});

test("a client secret is compared in constant time and rejects near misses", async () => {
  const client = validateClient({ ...BASE, type: "confidential", client_secret: "correct-horse-battery-staple" });

  assert.equal(await verifyClientSecret(client, "correct-horse-battery-staple"), true);
  assert.equal(await verifyClientSecret(client, "correct-horse-battery-stapl"), false);
  assert.equal(await verifyClientSecret(client, "Correct-Horse-Battery-Staple"), false);
  assert.equal(await verifyClientSecret(client, ""), false);
  assert.equal(await verifyClientSecret(client, null), false);
  assert.equal(await verifyClientSecret(validateClient(BASE), "anything"), false, "a public client has no secret to match");
});

test("public subjects are the Telegram id; pairwise subjects are not", async () => {
  const plain = validateClient(BASE);
  const pairwise = validateClient({ ...BASE, pairwise: true });

  assert.equal(await subjectFor(plain, 39644372), "39644372");

  const sub = await subjectFor(pairwise, 39644372, "salt");
  assert.notEqual(sub, "39644372");
  assert.match(sub, /^[0-9a-f]{32}$/);
  assert.equal(await subjectFor(pairwise, 39644372, "salt"), sub, "must be stable for the same user");
});

test("pairwise subjects stop two clients from correlating the same person", async () => {
  const a = validateClient({ client_id: "a", client_name: "A", redirect_uris: ["https://a.example.com/cb"], pairwise: true });
  const b = validateClient({ client_id: "b", client_name: "B", redirect_uris: ["https://b.example.com/cb"], pairwise: true });

  const subA = await subjectFor(a, 39644372, "salt");
  const subB = await subjectFor(b, 39644372, "salt");
  assert.notEqual(subA, subB, "the whole point: different clients, different sub for one user");

  // Clients sharing a declared sector DO see the same sub — that is how one vendor's apps
  // recognise a returning user.
  const sameSector = validateClient({ ...b, sector_identifier: "a.example.com" });
  assert.equal(await subjectFor(sameSector, 39644372, "salt"), subA);

  assert.equal(sectorIdentifierFor(a), "a.example.com");
  await assert.rejects(() => subjectFor(a, 1), /pairwiseSalt/);
});

test("a store-backed registry validates what it loads and refuses junk", async () => {
  const store = {
    data: new Map([
      ["oidc:client:app-a", BASE],
      ["oidc:client:broken", { client_id: "broken" }],
    ]),
    async get(key) {
      return this.data.get(key) ?? null;
    },
  };
  const registry = new StoreClientRegistry(store);

  assert.equal((await registry.get("app-a")).client_name, "App A");
  assert.equal(await registry.get("broken"), null, "a malformed stored client must not load permissively");
  assert.equal(await registry.get("missing"), null);
  assert.throws(() => new StoreClientRegistry(null), /required/);
});
