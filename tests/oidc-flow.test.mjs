// The authorization code flow end to end, and every way it is meant to refuse.

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
import { verifyJwt } from "../src/oidc/jwt.js";
import { makeFakeTelegram, makeRequest, cookieFrom, ALICE, MALLORY } from "./helpers.mjs";

const ISSUER = "https://auth.example.com";
const REDIRECT = "https://app-a.example.com/callback";

const PUBLIC_CLIENT = {
  client_id: "app-a",
  client_name: "App A",
  redirect_uris: [REDIRECT],
  scopes: ["openid", "profile", "offline_access"],
};

const CONFIDENTIAL_CLIENT = {
  client_id: "app-b",
  client_name: "App B",
  type: "confidential",
  client_secret: "shh-very-secret",
  redirect_uris: ["https://app-b.example.com/cb"],
  scopes: ["openid", "profile", "offline_access"],
  first_party: true, // skips consent, so tests can drive it without the form
};

async function setup({ clients = [PUBLIC_CLIENT, CONFIDENTIAL_CLIENT], members = [ALICE.id], authOverrides = {}, ...overrides } = {}) {
  const telegram = makeFakeTelegram({ members });
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "idp",
    telegram,
    authorize: allowlist(members),
    claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),
    ...authOverrides,
  });

  const oidc = createOidcProvider({
    auth,
    issuer: ISSUER,
    keys: await loadSigningKeys(await generateSigningKey()),
    clients: new StaticClientRegistry(clients),
    store: new MemoryOidcStore(),
    pairwiseSalt: "test-salt",
    ...overrides,
  });

  return { oidc, auth, telegram };
}

/** Signs a user in through the QR flow and returns the provider session cookie. */
async function signIn(auth, user = ALICE) {
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start idp_${token}`, from: user });
  const response = await auth.poll(makeRequest(`${ISSUER}/auth/poll?token=${token}`));
  return `${auth.cookieName}=${cookieFrom(response, auth.cookieName)}`;
}

function authorizeUrl(params) {
  const url = new URL(`${ISSUER}/authorize`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) url.searchParams.set(key, value);
  }
  return url.toString();
}

async function tokenRequest(oidc, body, headers = {}) {
  return oidc.handle(
    new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(body),
    })
  );
}

// ---- discovery ----------------------------------------------------------------------------------

test("discovery and JWKS describe the provider accurately", async () => {
  const { oidc } = await setup();

  const discovery = await (await oidc.handle(makeRequest(`${ISSUER}/.well-known/openid-configuration`))).json();
  assert.equal(discovery.issuer, ISSUER);
  assert.equal(discovery.authorization_endpoint, `${ISSUER}/authorize`);
  assert.deepEqual(discovery.id_token_signing_alg_values_supported, ["ES256"]);
  assert.deepEqual(discovery.code_challenge_methods_supported, ["S256"], "plain must not be advertised");
  assert.deepEqual(discovery.response_types_supported, ["code"], "implicit and hybrid must not be advertised");

  const jwksResponse = await oidc.handle(makeRequest(`${ISSUER}/.well-known/jwks.json`));
  const jwks = await jwksResponse.json();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].d, undefined, "private material must never be served");
  assert.match(jwksResponse.headers.get("Cache-Control"), /max-age/);
});

// ---- the happy path -----------------------------------------------------------------------------

test("full flow: authorize, consent, code, tokens, userinfo", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const pkce = await createPkcePair();

  // 1. Authorize. The user is signed in but has not consented, so a consent screen comes back.
  const consentPage = await oidc.handle(
    makeRequest(
      authorizeUrl({
        client_id: "app-a",
        redirect_uri: REDIRECT,
        response_type: "code",
        scope: "openid profile offline_access",
        state: "state-123",
        nonce: "nonce-abc",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      }),
      { cookie }
    )
  );
  assert.equal(consentPage.status, 200);
  const html = await consentPage.text();
  assert.match(html, /App A/, "the consent screen must name the client");
  assert.match(html, /app-a\.example\.com/, "and show where the user will be sent");

  const requestId = html.match(/name="request_id" value="([^"]+)"/)[1];
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];

  // 2. Approve.
  const approved = await oidc.handle(
    new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
      body: new URLSearchParams({ request_id: requestId, csrf, decision: "allow" }),
    })
  );
  assert.equal(approved.status, 302);
  const location = new URL(approved.headers.get("Location"));
  assert.equal(location.origin + location.pathname, REDIRECT);
  assert.equal(location.searchParams.get("state"), "state-123", "state must round-trip");
  const code = location.searchParams.get("code");
  assert.ok(code);

  // 3. Redeem.
  const tokens = await (
    await tokenRequest(oidc, {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT,
      client_id: "app-a",
      code_verifier: pkce.verifier,
    })
  ).json();

  assert.equal(tokens.token_type, "Bearer");
  assert.ok(tokens.access_token && tokens.id_token && tokens.refresh_token);

  // 4. The id token says what OIDC requires it to say.
  const idClaims = await oidc.verifyIdToken(tokens.id_token, "app-a");
  assert.equal(idClaims.iss, ISSUER);
  assert.equal(idClaims.aud, "app-a");
  assert.equal(idClaims.sub, String(ALICE.id));
  assert.equal(idClaims.nonce, "nonce-abc", "nonce must be echoed — it is the client's replay defence");
  assert.equal(idClaims.name, "Alice Ng");
  assert.ok(idClaims.auth_time);

  // 5. userinfo accepts the access token.
  const userinfo = await (
    await oidc.handle(makeRequest(`${ISSUER}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } }))
  ).json();
  assert.equal(userinfo.sub, String(ALICE.id));
  assert.equal(userinfo.name, "Alice Ng");
});

test("a first-party client skips consent and lands straight on a code", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const pkce = await createPkcePair();

  const response = await oidc.handle(
    makeRequest(
      authorizeUrl({
        client_id: "app-b",
        redirect_uri: "https://app-b.example.com/cb",
        response_type: "code",
        scope: "openid profile",
        state: "s",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      }),
      { cookie }
    )
  );

  assert.equal(response.status, 302);
  assert.ok(new URL(response.headers.get("Location")).searchParams.get("code"));
});

test("a signed-out user gets the QR page, and the flow resumes afterwards", async () => {
  const { oidc, auth } = await setup();
  const pkce = await createPkcePair();

  const response = await oidc.handle(
    makeRequest(
      authorizeUrl({
        client_id: "app-b",
        redirect_uri: "https://app-b.example.com/cb",
        response_type: "code",
        scope: "openid",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      })
    )
  );

  // The QR sign-in page, carrying a resume link back into /authorize.
  const page = await response.text();
  assert.match(page, /<svg/);
  const resumeUrl = page.match(/"redirectTo":"([^"]+)"/)[1];
  assert.match(resumeUrl, /^\/authorize\?request_id=[0-9a-f]{32}$/);

  // Scan, then follow the resume link — the original parameters are still in force.
  const cookie = await signIn(auth);
  const resumed = await oidc.handle(makeRequest(ISSUER + resumeUrl, { cookie }));
  assert.equal(resumed.status, 302);
  assert.ok(new URL(resumed.headers.get("Location")).searchParams.get("code"));
});

// ---- authorize: refusals ------------------------------------------------------------------------

test("an unknown client or unregistered redirect_uri renders a page and redirects NOWHERE", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);

  const unknownClient = await oidc.handle(
    makeRequest(authorizeUrl({ client_id: "ghost", redirect_uri: REDIRECT, response_type: "code", scope: "openid" }), { cookie })
  );
  assert.equal(unknownClient.status, 400);
  assert.equal(unknownClient.headers.get("Location"), null, "must not redirect");

  // The attack this blocks: a valid client_id with an attacker's callback.
  const evilRedirect = await oidc.handle(
    makeRequest(
      authorizeUrl({ client_id: "app-a", redirect_uri: "https://evil.example/steal", response_type: "code", scope: "openid" }),
      { cookie }
    )
  );
  assert.equal(evilRedirect.status, 400);
  assert.equal(evilRedirect.headers.get("Location"), null, "an unregistered redirect_uri must never be redirected to");
  assert.match(await evilRedirect.text(), /Nothing was shared/);
});

test("bad parameters after redirect_uri validation go back to the client as errors", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const pkce = await createPkcePair();

  const cases = [
    [{ response_type: "token" }, "unsupported_response_type"],
    [{ scope: "profile" }, "invalid_scope"], // missing openid
    [{ scope: "openid admin" }, "invalid_scope"], // not permitted for this client
    [{ code_challenge: undefined }, "invalid_request"], // PKCE required
    [{ code_challenge: "too-short" }, "invalid_request"],
    [{ code_challenge_method: "plain" }, "invalid_request"],
  ];

  for (const [override, expected] of cases) {
    const response = await oidc.handle(
      makeRequest(
        authorizeUrl({
          client_id: "app-a",
          redirect_uri: REDIRECT,
          response_type: "code",
          scope: "openid profile",
          state: "st",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256",
          ...override,
        }),
        { cookie }
      )
    );

    assert.equal(response.status, 302, `${expected}: expected a redirect back to the client`);
    const location = new URL(response.headers.get("Location"));
    assert.equal(location.origin + location.pathname, REDIRECT);
    assert.equal(location.searchParams.get("error"), expected);
    assert.equal(location.searchParams.get("state"), "st", "state must survive an error too");
  }
});

test("a user the gate rejects cannot get a code", async () => {
  const { oidc, auth } = await setup({ members: [ALICE.id] });
  const cookie = await signIn(auth, ALICE);
  const pkce = await createPkcePair();

  // Revoke Alice's access after she signed in — the gate runs on every authorize.
  const revoked = createOidcProvider({
    auth: { ...auth, authorize: async () => ({ ok: false, reason: "not_a_member" }) },
    issuer: ISSUER,
    keys: await loadSigningKeys(await generateSigningKey()),
    clients: new StaticClientRegistry([PUBLIC_CLIENT]),
    store: new MemoryOidcStore(),
  });

  const response = await revoked.handle(
    makeRequest(
      authorizeUrl({
        client_id: "app-a",
        redirect_uri: REDIRECT,
        response_type: "code",
        scope: "openid",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      }),
      { cookie }
    )
  );

  assert.equal(new URL(response.headers.get("Location")).searchParams.get("error"), "access_denied");
});

test("prompt=none never shows UI", async () => {
  const { oidc, auth } = await setup();
  const pkce = await createPkcePair();
  const params = {
    client_id: "app-a",
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid",
    prompt: "none",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  };

  const signedOut = await oidc.handle(makeRequest(authorizeUrl(params)));
  assert.equal(new URL(signedOut.headers.get("Location")).searchParams.get("error"), "login_required");

  const cookie = await signIn(auth);
  const noConsent = await oidc.handle(makeRequest(authorizeUrl(params), { cookie }));
  assert.equal(new URL(noConsent.headers.get("Location")).searchParams.get("error"), "consent_required");
});

// ---- consent ------------------------------------------------------------------------------------

test("consent is remembered, and widening the scope asks again", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);

  const start = async (scope) => {
    const pkce = await createPkcePair();
    return oidc.handle(
      makeRequest(
        authorizeUrl({
          client_id: "app-a",
          redirect_uri: REDIRECT,
          response_type: "code",
          scope,
          code_challenge: pkce.challenge,
          code_challenge_method: "S256",
        }),
        { cookie }
      )
    );
  };

  const first = await start("openid profile");
  const html = await first.text();
  await oidc.handle(
    new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
      body: new URLSearchParams({
        request_id: html.match(/name="request_id" value="([^"]+)"/)[1],
        csrf: html.match(/name="csrf" value="([^"]+)"/)[1],
        decision: "allow",
      }),
    })
  );

  // Same scopes: straight through.
  assert.equal((await start("openid profile")).status, 302);
  // A subset: still covered.
  assert.equal((await start("openid")).status, 302);
  // More than was granted: ask again.
  assert.equal((await start("openid profile offline_access")).status, 200, "a wider scope must re-prompt");
});

test("declining consent tells the client, and issues nothing", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth);
  const pkce = await createPkcePair();

  const page = await (
    await oidc.handle(
      makeRequest(
        authorizeUrl({
          client_id: "app-a",
          redirect_uri: REDIRECT,
          response_type: "code",
          scope: "openid profile",
          state: "xyz",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256",
        }),
        { cookie }
      )
    )
  ).text();

  const denied = await oidc.handle(
    new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
      body: new URLSearchParams({
        request_id: page.match(/name="request_id" value="([^"]+)"/)[1],
        csrf: page.match(/name="csrf" value="([^"]+)"/)[1],
        decision: "deny",
      }),
    })
  );

  const location = new URL(denied.headers.get("Location"));
  assert.equal(location.searchParams.get("error"), "access_denied");
  assert.equal(location.searchParams.get("state"), "xyz");
  assert.equal(location.searchParams.get("code"), null);
});

test("the consent form is bound to its CSRF token and to the user who was shown it", async () => {
  const { oidc, auth } = await setup();
  const cookie = await signIn(auth, ALICE);
  const pkce = await createPkcePair();

  const page = await (
    await oidc.handle(
      makeRequest(
        authorizeUrl({
          client_id: "app-a",
          redirect_uri: REDIRECT,
          response_type: "code",
          scope: "openid profile",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256",
        }),
        { cookie }
      )
    )
  ).text();
  const requestId = page.match(/name="request_id" value="([^"]+)"/)[1];
  const csrf = page.match(/name="csrf" value="([^"]+)"/)[1];

  const post = (body, withCookie = cookie) =>
    oidc.handle(
      new Request(`${ISSUER}/consent`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: withCookie },
        body: new URLSearchParams(body),
      })
    );

  // Wrong CSRF token.
  assert.equal((await post({ request_id: requestId, csrf: "wrong", decision: "allow" })).status, 400);

  // A different signed-in user must not be able to approve someone else's pending request.
  const { auth: otherAuth } = await setup({ members: [MALLORY.id] });
  const mallorysCookie = await signIn(otherAuth, MALLORY);
  const hijack = await post({ request_id: requestId, csrf, decision: "allow" }, mallorysCookie);
  assert.equal(hijack.status, 400);

  // Signed out entirely.
  const anonymous = await oidc.handle(
    new Request(`${ISSUER}/consent`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ request_id: requestId, csrf, decision: "allow" }),
    })
  );
  assert.equal(anonymous.status, 400);
});

// ---- re-authentication and CORS -------------------------------------------------------------------

// Two sign-ins inside one second would sign identical cookies; a counter keeps them distinct, as
// the seconds that pass during a real scan would.
let signInCount = 0;
const distinctSessions = { claims: () => ({ auth_time: Math.floor(Date.now() / 1000), n: ++signInCount }) };

async function startFirstParty(oidc, extra, cookie) {
  const pkce = await createPkcePair();
  return oidc.handle(
    makeRequest(
      authorizeUrl({
        client_id: "app-b",
        redirect_uri: "https://app-b.example.com/cb",
        response_type: "code",
        scope: "openid",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        ...extra,
      }),
      cookie ? { cookie } : {}
    )
  );
}

test("prompt=login asks for a fresh sign-in once, then resumes instead of looping", async () => {
  const { oidc, auth } = await setup({ authOverrides: distinctSessions });
  const oldCookie = await signIn(auth);

  const page = await (await startFirstParty(oidc, { prompt: "login" }, oldCookie)).text();
  const resumeUrl = page.match(/"redirectTo":"([^"]+)"/)[1];

  // Coming back with the session it already had does not count as signing in again.
  const stale = await oidc.handle(makeRequest(ISSUER + resumeUrl, { cookie: oldCookie }));
  assert.equal(stale.status, 200, "still the sign-in page");
  assert.match(await stale.text(), /<svg/);

  const freshCookie = await signIn(auth);
  const resumed = await oidc.handle(makeRequest(ISSUER + resumeUrl, { cookie: freshCookie }));
  assert.equal(resumed.status, 302);
  assert.ok(new URL(resumed.headers.get("Location")).searchParams.get("code"));
});

test("max_age without auth_time still completes after a sign-in during the flow", async () => {
  const { oidc, auth } = await setup({ authOverrides: { claims: undefined } });
  const page = await (await startFirstParty(oidc, { max_age: "60" })).text();
  const resumeUrl = page.match(/"redirectTo":"([^"]+)"/)[1];

  const cookie = await signIn(auth);
  const resumed = await oidc.handle(makeRequest(ISSUER + resumeUrl, { cookie }));
  assert.equal(resumed.status, 302);
  assert.ok(new URL(resumed.headers.get("Location")).searchParams.get("code"));
});

test("browser apps on another origin can call the fetch endpoints, and preflights succeed", async () => {
  const { oidc } = await setup();
  const origin = { Origin: "https://spa.example" };

  const preflight = await oidc.handle(
    new Request(`${ISSUER}/token`, {
      method: "OPTIONS",
      headers: { ...origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type" },
    })
  );
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("Access-Control-Allow-Origin"), "*");
  assert.match(preflight.headers.get("Access-Control-Allow-Methods"), /POST/);
  assert.match(preflight.headers.get("Access-Control-Allow-Headers"), /Content-Type/);
  assert.equal(preflight.headers.get("Access-Control-Allow-Credentials"), null, "never credentialed");

  const token = await tokenRequest(oidc, { grant_type: "authorization_code", code: "nope", client_id: "app-a" }, origin);
  assert.equal(token.headers.get("Access-Control-Allow-Origin"), "*", "errors must be readable too");

  const userinfo = await oidc.handle(makeRequest(`${ISSUER}/userinfo`, { headers: origin }));
  assert.equal(userinfo.status, 401);
  assert.equal(userinfo.headers.get("Access-Control-Allow-Origin"), "*");
  assert.match(userinfo.headers.get("Access-Control-Expose-Headers"), /WWW-Authenticate/);

  for (const path of ["/.well-known/openid-configuration", "/.well-known/jwks.json"]) {
    const response = await oidc.handle(makeRequest(ISSUER + path, { headers: origin }));
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), "*", path);
  }

  const authorize = await startFirstParty(oidc, {});
  assert.equal(authorize.headers.get("Access-Control-Allow-Origin"), null, "/authorize is a navigation");
});

test("cors can be narrowed to listed origins, or turned off", async () => {
  const listed = (await setup({ cors: ["https://spa.example"] })).oidc;
  const ok = await listed.handle(makeRequest(`${ISSUER}/.well-known/jwks.json`, { headers: { Origin: "https://spa.example" } }));
  assert.equal(ok.headers.get("Access-Control-Allow-Origin"), "https://spa.example");
  assert.match(ok.headers.get("Vary"), /Origin/);

  const other = await listed.handle(makeRequest(`${ISSUER}/.well-known/jwks.json`, { headers: { Origin: "https://evil.example" } }));
  assert.equal(other.headers.get("Access-Control-Allow-Origin"), null);
  const otherPreflight = await listed.handle(new Request(`${ISSUER}/token`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } }));
  assert.equal(otherPreflight.status, 403);

  const off = (await setup({ cors: false })).oidc;
  const offPreflight = await off.handle(new Request(`${ISSUER}/token`, { method: "OPTIONS", headers: { Origin: "https://spa.example" } }));
  assert.equal(offPreflight.status, 403);
});
