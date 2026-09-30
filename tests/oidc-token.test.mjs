// The token endpoint: client authentication, code redemption, PKCE binding, refresh rotation with
// reuse detection, userinfo and revocation.

import test from "node:test";
import assert from "node:assert/strict";

import { createTelegramQrAuth } from "../src/provider.js";
import { MemoryLoginStore } from "../src/stores/memory.js";
import { allowlist } from "../src/gates.js";
import { createOidcProvider } from "../src/oidc/provider.js";
import { generateSigningKey, loadSigningKeys } from "../src/oidc/keys.js";
import { StaticClientRegistry } from "../src/oidc/clients.js";
import { MemoryOidcStore } from "../src/oidc/store.js";
import { createPkcePair } from "../src/oidc/pkce.js";
import { makeFakeTelegram, makeRequest, cookieFrom, ALICE } from "./helpers.mjs";

const ISSUER = "https://auth.example.com";
const PUBLIC_REDIRECT = "https://app-a.example.com/callback";
const CONF_REDIRECT = "https://app-b.example.com/cb";
const SECRET = "shh-very-secret";

const CLIENTS = [
  {
    client_id: "app-a",
    client_name: "App A",
    redirect_uris: [PUBLIC_REDIRECT],
    scopes: ["openid", "profile", "offline_access"],
    first_party: true,
  },
  {
    client_id: "app-b",
    client_name: "App B",
    type: "confidential",
    client_secret: SECRET,
    redirect_uris: [CONF_REDIRECT],
    scopes: ["openid", "profile", "offline_access"],
    first_party: true,
  },
];

async function setup(overrides = {}) {
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "idp",
    telegram: makeFakeTelegram({ members: [ALICE.id] }),
    authorize: allowlist([ALICE.id]),
    claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),
  });

  const oidc = createOidcProvider({
    auth,
    issuer: ISSUER,
    keys: await loadSigningKeys(await generateSigningKey()),
    clients: new StaticClientRegistry(CLIENTS),
    store: new MemoryOidcStore(),
    ...overrides,
  });

  return { oidc, auth };
}

async function signIn(auth) {
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start idp_${token}`, from: ALICE });
  const response = await auth.poll(makeRequest(`${ISSUER}/auth/poll?token=${token}`));
  return `${auth.cookieName}=${cookieFrom(response, auth.cookieName)}`;
}

/** Runs authorize for a first-party client and returns { code, pkce }. */
async function getCode(oidc, cookie, { clientId = "app-a", redirectUri = PUBLIC_REDIRECT, scope = "openid profile offline_access" } = {}) {
  const pkce = await createPkcePair();
  const url = new URL(`${ISSUER}/authorize`);
  Object.entries({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  }).forEach(([k, v]) => url.searchParams.set(k, v));

  const response = await oidc.handle(makeRequest(url.toString(), { cookie }));
  assert.equal(response.status, 302, "expected a code redirect");
  return { code: new URL(response.headers.get("Location")).searchParams.get("code"), pkce };
}

function post(oidc, body, headers = {}) {
  return oidc.handle(
    new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(body),
    })
  );
}

// ---- client authentication ----------------------------------------------------------------------

test("a confidential client authenticates by Basic or by form field, but must authenticate", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);

  const basic = "Basic " + Buffer.from(`app-b:${SECRET}`).toString("base64");

  const viaBasic = await getCode(oidc, cookie, { clientId: "app-b", redirectUri: CONF_REDIRECT });
  const ok = await post(
    oidc,
    { grant_type: "authorization_code", code: viaBasic.code, redirect_uri: CONF_REDIRECT, code_verifier: viaBasic.pkce.verifier },
    { Authorization: basic }
  );
  assert.equal(ok.status, 200);

  const viaPost = await getCode(oidc, cookie, { clientId: "app-b", redirectUri: CONF_REDIRECT });
  assert.equal(
    (
      await post(oidc, {
        grant_type: "authorization_code",
        code: viaPost.code,
        redirect_uri: CONF_REDIRECT,
        client_id: "app-b",
        client_secret: SECRET,
        code_verifier: viaPost.pkce.verifier,
      })
    ).status,
    200
  );

  // No secret, and the wrong secret, both fail the same way.
  const noSecret = await getCode(oidc, cookie, { clientId: "app-b", redirectUri: CONF_REDIRECT });
  const missing = await post(oidc, {
    grant_type: "authorization_code",
    code: noSecret.code,
    redirect_uri: CONF_REDIRECT,
    client_id: "app-b",
    code_verifier: noSecret.pkce.verifier,
  });
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).error, "invalid_client");

  const wrong = await post(
    oidc,
    { grant_type: "authorization_code", code: "irrelevant", redirect_uri: CONF_REDIRECT },
    { Authorization: "Basic " + Buffer.from("app-b:wrong").toString("base64") }
  );
  assert.equal(wrong.status, 401);
});

test("an unknown client and a wrong secret are indistinguishable", async () => {
  const { oidc } = await setup();

  const unknown = await post(oidc, { grant_type: "authorization_code", client_id: "ghost", code: "x" });
  const wrongSecret = await post(
    oidc,
    { grant_type: "authorization_code", code: "x" },
    { Authorization: "Basic " + Buffer.from("app-b:wrong").toString("base64") }
  );

  assert.equal(unknown.status, wrongSecret.status);
  assert.deepEqual(await unknown.json(), await wrongSecret.json(), "responses must not let a caller enumerate client ids");
});

test("a public client must not present a secret", async () => {
  const { oidc } = await setup();
  const response = await post(oidc, { grant_type: "authorization_code", client_id: "app-a", client_secret: "invented", code: "x" });
  assert.equal(response.status, 401);
});

// ---- code redemption ----------------------------------------------------------------------------

test("a code is single-use", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);

  const body = { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier };

  assert.equal((await post(oidc, body)).status, 200);

  const replay = await post(oidc, body);
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "invalid_grant");
});

test("a failed redemption still burns the code", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);

  // Wrong verifier: rejected.
  const wrong = await createPkcePair();
  assert.equal(
    (await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: wrong.verifier }))
      .status,
    400
  );

  // And now the right verifier does not work either — no probing a stolen code.
  assert.equal(
    (await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier }))
      .status,
    400
  );
});

test("PKCE is enforced and a missing verifier is refused", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code } = await getCode(oidc, cookie);

  const response = await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a" });
  assert.equal(response.status, 400);
  assert.match((await response.json()).error_description, /invalid, expired, or does not match/);
});

test("a code issued to one client cannot be redeemed by another", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie); // issued to app-a

  const stolen = await post(
    oidc,
    { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, code_verifier: pkce.verifier },
    { Authorization: "Basic " + Buffer.from(`app-b:${SECRET}`).toString("base64") }
  );

  assert.equal(stolen.status, 400);
  assert.match((await stolen.json()).error_description, /invalid, expired, or does not match/);
});

test("redirect_uri must be repeated exactly at redemption", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);

  const response = await post(oidc, {
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://app-a.example.com/callback2",
    client_id: "app-a",
    code_verifier: pkce.verifier,
  });
  assert.equal(response.status, 400);
});

test("unsupported grant types and malformed requests are refused cleanly", async () => {
  const { oidc } = await setup();

  const unsupported = await post(oidc, { grant_type: "password", client_id: "app-a", username: "a", password: "b" });
  assert.equal((await unsupported.json()).error, "unsupported_grant_type");

  const noGrant = await post(oidc, { client_id: "app-a" });
  assert.equal((await noGrant.json()).error, "unsupported_grant_type");

  const wrongMethod = await oidc.handle(makeRequest(`${ISSUER}/token`));
  assert.equal(wrongMethod.status, 405);
});

// ---- refresh tokens -----------------------------------------------------------------------------

test("refresh rotates the token and keeps the session going", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);

  const first = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();
  assert.ok(first.refresh_token);

  const second = await (await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" })).json();

  assert.ok(second.access_token);
  assert.notEqual(second.refresh_token, first.refresh_token, "the refresh token must rotate");

  const claims = await oidc.verifyIdToken(second.id_token, "app-a");
  assert.equal(claims.sub, String(ALICE.id));
  assert.equal(claims.nonce, undefined, "a refresh must not carry the original nonce");
});

test("reusing a refresh token revokes the whole family", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);

  const first = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();
  const second = await (await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" })).json();

  // Presenting the already-rotated token means it leaked (or the client retried — indistinguishable).
  const reuse = await post(oidc, { grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: "app-a" });
  assert.equal(reuse.status, 400);
  assert.match((await reuse.json()).error_description, /already been used/);

  // The thief is cut off AND so is whoever holds the current token: the family is dead.
  const afterRevocation = await post(oidc, { grant_type: "refresh_token", refresh_token: second.refresh_token, client_id: "app-a" });
  assert.equal(afterRevocation.status, 400, "the rest of the family must be revoked too");
});

test("a refresh token belongs to its client, and scope may narrow but not widen", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie, { scope: "openid profile offline_access" });

  const tokens = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();

  const wrongClient = await post(
    oidc,
    { grant_type: "refresh_token", refresh_token: tokens.refresh_token },
    { Authorization: "Basic " + Buffer.from(`app-b:${SECRET}`).toString("base64") }
  );
  assert.equal(wrongClient.status, 400);

  const narrowed = await (
    await post(oidc, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "app-a", scope: "openid" })
  ).json();
  assert.equal(narrowed.scope, "openid");
});

test("no offline_access means no refresh token", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie, { scope: "openid profile" });

  const tokens = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();
  assert.equal(tokens.refresh_token, undefined);
});

// ---- userinfo and revocation --------------------------------------------------------------------

test("userinfo refuses everything that is not a live access token", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);
  const tokens = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();

  const call = (header) => oidc.handle(makeRequest(`${ISSUER}/userinfo`, header ? { headers: { Authorization: header } } : {}));

  assert.equal((await call(`Bearer ${tokens.access_token}`)).status, 200);

  const missing = await call(undefined);
  assert.equal(missing.status, 401);
  assert.match(missing.headers.get("WWW-Authenticate"), /Bearer/);

  assert.equal((await call("Bearer nonsense")).status, 401);
  assert.equal((await call(tokens.access_token)).status, 401, "the Bearer scheme is required");

  // An id_token is a JWT signed by the same key — and must still be refused here. Different
  // audience, different typ, different purpose.
  assert.equal((await call(`Bearer ${tokens.id_token}`)).status, 401, "an id_token must not work as an access token");
});

test("revoking kills the family, and says nothing about tokens that are not yours", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const { code, pkce } = await getCode(oidc, cookie);
  const tokens = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier })
  ).json();

  const revoke = (body, headers) =>
    oidc.handle(
      new Request(`${ISSUER}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
        body: new URLSearchParams(body),
      })
    );

  // Another client trying to revoke it: 200 (RFC 7009) but nothing happens.
  const byOther = await revoke({ token: tokens.refresh_token }, { Authorization: "Basic " + Buffer.from(`app-b:${SECRET}`).toString("base64") });
  assert.equal(byOther.status, 200);
  assert.equal(
    (await post(oidc, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "app-a" })).status,
    200,
    "another client must not be able to revoke this token"
  );

  // Re-establish a token (the refresh above rotated it) and revoke it as its rightful owner.
  const current = await (
    await post(oidc, { grant_type: "authorization_code", ...(await freshCode(oidc, cookie)) })
  ).json();

  assert.equal((await revoke({ token: current.refresh_token, client_id: "app-a" })).status, 200);
  assert.equal(
    (await post(oidc, { grant_type: "refresh_token", refresh_token: current.refresh_token, client_id: "app-a" })).status,
    400,
    "the owning client's revocation must actually take effect"
  );

  // An unknown token is still a 200: callers must not be able to probe which tokens exist.
  assert.equal((await revoke({ token: "not-a-real-token", client_id: "app-a" })).status, 200);
});

/** A fresh code plus the fields the token endpoint needs to redeem it. */
async function freshCode(oidc, cookie) {
  const { code, pkce } = await getCode(oidc, cookie);
  return { code, redirect_uri: PUBLIC_REDIRECT, client_id: "app-a", code_verifier: pkce.verifier };
}

test("withdrawing consent ends the client's access at the next refresh", async () => {
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "idp",
    telegram: makeFakeTelegram({ members: [ALICE.id] }),
    authorize: allowlist([ALICE.id]),
    claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),
  });

  // A third-party (non first-party) client, so consent is real.
  const oidc = createOidcProvider({
    auth,
    issuer: ISSUER,
    keys: await loadSigningKeys(await generateSigningKey()),
    clients: new StaticClientRegistry([
      { client_id: "third", client_name: "Third Party", redirect_uris: [PUBLIC_REDIRECT], scopes: ["openid", "profile", "offline_access"] },
    ]),
    store: new MemoryOidcStore(),
  });

  const cookie = await signIn(auth);
  const pkce = await createPkcePair();
  const url = new URL(`${ISSUER}/authorize`);
  Object.entries({
    client_id: "third",
    redirect_uri: PUBLIC_REDIRECT,
    response_type: "code",
    scope: "openid profile offline_access",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  }).forEach(([k, v]) => url.searchParams.set(k, v));

  const page = await (await oidc.handle(makeRequest(url.toString(), { cookie }))).text();
  const approved = await oidc.handle(
    new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
      body: new URLSearchParams({
        request_id: page.match(/name="request_id" value="([^"]+)"/)[1],
        csrf: page.match(/name="csrf" value="([^"]+)"/)[1],
        decision: "allow",
      }),
    })
  );
  const code = new URL(approved.headers.get("Location")).searchParams.get("code");

  const tokens = await (
    await post(oidc, { grant_type: "authorization_code", code, redirect_uri: PUBLIC_REDIRECT, client_id: "third", code_verifier: pkce.verifier })
  ).json();
  assert.ok(tokens.refresh_token);

  await oidc.revokeConsent(ALICE.id, "third");

  const afterWithdrawal = await post(oidc, { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: "third" });
  assert.equal(afterWithdrawal.status, 400, "withdrawing consent must end the grant, or the button is a lie");
});
