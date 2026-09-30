// Refresh-token rotation under concurrency, and the store contract it depends on. The sequential
// reuse test in oidc-token.test.mjs cannot see a race: it never has two requests in flight.

import test from "node:test";
import assert from "node:assert/strict";

import { createTelegramQrAuth } from "../src/provider.js";
import { MemoryLoginStore } from "../src/stores/memory.js";
import { createOidcProvider } from "../src/oidc/provider.js";
import { generateSigningKey, loadSigningKeys } from "../src/oidc/keys.js";
import { StaticClientRegistry } from "../src/oidc/clients.js";
import { MemoryOidcStore, KvOidcStore } from "../src/oidc/store.js";
import { D1OidcStore } from "../src/oidc/d1-store.js";
import { DoOidcStore } from "../src/oidc/do-store.js";
import { defineQrAuthStorage } from "../src/stores/do.js";
import { createPkcePair } from "../src/oidc/pkce.js";
import { renderConsentPage } from "../src/oidc/consent-page.js";
import { parseCookies } from "../src/session.js";
import { makeFakeTelegram, makeFakeD1, makeFakeKV, makeFakeDONamespace, makeRequest, cookieFrom, ALICE } from "./helpers.mjs";

const ISSUER = "https://auth.example.com";
const REDIRECT = "https://app-a.example.com/callback";

const STORES = [
  ["MemoryOidcStore", () => new MemoryOidcStore()],
  ["D1OidcStore", () => new D1OidcStore(makeFakeD1({ sql: "oidc-d1.sql" }))],
  ["DoOidcStore", () => new DoOidcStore(makeFakeDONamespace(defineQrAuthStorage))],
];

async function setup(store, { clientOverrides = {} } = {}) {
  const allowed = new Set([ALICE.id]);
  const outage = { on: false };
  const events = [];
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "idp",
    telegram: makeFakeTelegram({ members: [ALICE.id] }),
    // Async on purpose: the gate yields, which is what lets concurrent refreshes interleave.
    authorize: async (user) => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      if (outage.on) return { ok: false, reason: "telegram_unavailable", transient: true };
      return allowed.has(user.id);
    },
    claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),
  });
  const oidc = createOidcProvider({
    auth,
    issuer: ISSUER,
    keys: await loadSigningKeys(await generateSigningKey()),
    clients: new StaticClientRegistry([
      {
        client_id: "app-a",
        client_name: "App A",
        redirect_uris: [REDIRECT],
        scopes: ["openid", "profile", "offline_access"],
        first_party: true,
        ...clientOverrides,
      },
    ]),
    store,
    onEvent: (event) => events.push(event),
  });
  return { oidc, auth, allowed, outage, events };
}

const post = (oidc, body) =>
  oidc.handle(
    new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
    })
  );

async function firstTokens(oidc, auth) {
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start idp_${token}`, from: ALICE });
  const polled = await auth.poll(makeRequest(`${ISSUER}/auth/poll?token=${token}`));
  const cookie = `${auth.cookieName}=${cookieFrom(polled, auth.cookieName)}`;

  const pkce = await createPkcePair();
  const url = new URL(`${ISSUER}/authorize`);
  Object.entries({
    client_id: "app-a",
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid profile offline_access",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  }).forEach(([k, v]) => url.searchParams.set(k, v));
  const authorized = await oidc.handle(makeRequest(url.toString(), { cookie }));
  const code = new URL(authorized.headers.get("Location")).searchParams.get("code");

  return (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();
}

for (const [name, makeStore] of STORES) {
  test(`${name}: two simultaneous refreshes with one token cannot both succeed`, async () => {
    const { oidc, auth, events } = await setup(makeStore());
    const first = await firstTokens(oidc, auth);

    const body = { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" };
    const [a, b] = await Promise.all([post(oidc, body), post(oidc, body)]);

    assert.deepEqual([a.status, b.status].sort(), [200, 400], "exactly one of the two may win the rotation");
    assert.ok(events.some((e) => e.type === "token.refresh_reuse"), "the loser must be reported as reuse");

    // Reuse kills the family, including the winner's freshly issued token.
    const winner = await (a.status === 200 ? a : b).json();
    const after = await post(oidc, { grant_type: "refresh_token", refresh_token: winner.refresh_token, client_id: "app-a" });
    assert.equal(after.status, 400, "the winner's rotated token must die with the family");
  });

  test(`${name}: a user removed from the gate cannot refresh`, async () => {
    const { oidc, auth, allowed, events } = await setup(makeStore());
    const first = await firstTokens(oidc, auth);

    allowed.delete(ALICE.id);
    const denied = await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" });
    assert.equal(denied.status, 400);
    assert.ok(events.some((e) => e.type === "token.refresh_denied"));

    // Refused, not revoked: the gate re-runs on every refresh, so tearing the family down would add
    // nothing for a user who really lost access, and would punish one whose gate misreported.
    allowed.add(ALICE.id);
    const again = await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" });
    assert.equal(again.status, 200, "restored access works with the same token");
  });

  test(`${name}: a gate outage answers 503 and leaves the refresh token usable`, async () => {
    const { oidc, auth, outage, events } = await setup(makeStore());
    const first = await firstTokens(oidc, auth);

    outage.on = true;
    const during = await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" });
    assert.equal(during.status, 503);
    assert.equal((await during.json()).error, "temporarily_unavailable");
    assert.equal(events.some((e) => e.type === "token.refresh_denied"), false, "an outage is not a denial");

    outage.on = false;
    const after = await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" });
    assert.equal(after.status, 200, "the same refresh token still works once the gate answers again");
  });

  test(`${name}: consumeCode is single-use even when raced`, async () => {
    const store = makeStore();
    await store.saveCode("c1", { clientId: "x" }, 60);
    const results = await Promise.all([store.consumeCode("c1"), store.consumeCode("c1"), store.consumeCode("c1")]);
    assert.equal(results.filter(Boolean).length, 1);
  });

  test(`${name}: revokeConsent takes the client's refresh tokens with it`, async () => {
    const store = makeStore();
    await store.saveConsent("7", "app-a", ["openid"]);
    await store.saveRefreshToken("rt1", { userId: 7, clientId: "app-a", familyId: "f1", scopes: ["openid"], used: false }, 600);
    await store.revokeConsent(7, "app-a");
    assert.equal(await store.getConsent(7, "app-a"), null);
    assert.equal(await store.getRefreshToken("rt1"), null);
  });

  test(`${name}: a revoked family cannot be resurrected by a late save`, async () => {
    const store = makeStore();
    await store.revokeFamily("f9");
    await store.saveRefreshToken("late", { userId: 1, clientId: "c", familyId: "f9", scopes: [], used: false }, 600);
    assert.equal(await store.getRefreshToken("late"), null);
  });
}

test("KvOidcStore: revokeConsent takes the client's refresh tokens with it", async () => {
  const store = new KvOidcStore(makeFakeKV());
  await store.saveConsent("7", "app-a", ["openid"]);
  await store.saveRefreshToken("rt1", { userId: 7, clientId: "app-a", familyId: "f1", scopes: ["openid"], used: false }, 600);
  await store.saveRefreshToken("rt2", { userId: 7, clientId: "app-b", familyId: "f2", scopes: ["openid"], used: false }, 600);

  await store.revokeConsent(7, "app-a");

  assert.equal(await store.getRefreshToken("rt1"), null);
  assert.ok(await store.getRefreshToken("rt2"), "another client's grant is untouched");
});

test("the consent screen shows the callback host that was actually matched", () => {
  const client = { client_name: "App", redirect_uris: ["https://first.example/cb", "https://second.example/cb"] };
  const page = renderConsentPage({
    client,
    scopes: ["openid"],
    session: { name: "Alice" },
    redirectUri: "https://second.example/cb",
    requestId: "r",
    csrfToken: "c",
    actionPath: "/consent",
  });
  assert.match(page, /<code>second\.example<\/code>/);
  assert.doesNotMatch(page, /first\.example/);
});

test("parseCookies survives malformed percent-encoding elsewhere in the jar", () => {
  const jar = parseCookies("bad=%E0%A4%A; session=abc%20def");
  assert.equal(jar.session, "abc def");
});

test("DoLoginStore and DoOidcStore can share one object without touching each other's rows", async () => {
  const binding = makeFakeDONamespace(defineQrAuthStorage);
  const { DoLoginStore } = await import("../src/stores/do.js");
  const login = new DoLoginStore(binding);
  const oidc = new DoOidcStore(binding);

  await login.create({ token: "t".repeat(32), namespace: "site", expiresAt: Math.floor(Date.now() / 1000) + 600 });
  await oidc.saveCode("c1", { clientId: "x" }, 60);

  assert.equal((await login.get("t".repeat(32), "site")).status, "pending");
  assert.ok(await oidc.consumeCode("c1"));
});

test("Do stores refuse a missing binding at construction", async () => {
  assert.throws(() => new DoOidcStore(undefined), /Durable Object namespace binding/);
});
