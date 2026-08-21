// Bearer assertions — the path clients without a cookie jar use, and the cross-language contract
// that lets a PHP or C# service verify a session this package signed.

import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { createTelegramQrAuth } from "../src/provider.js";
import { createSessionCodec } from "../src/session.js";
import { MemoryLoginStore } from "../src/stores/memory.js";
import { allowlist } from "../src/gates.js";
import { makeFakeTelegram, makeRequest, cookieFrom, ALICE } from "./helpers.mjs";

function setup(options = {}) {
  return createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "demo",
    telegram: makeFakeTelegram({ members: [ALICE.id] }),
    authorize: allowlist([ALICE.id]),
    ...options,
  });
}

async function scanAndPoll(auth, query = "") {
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start demo_${token}`, from: ALICE });
  return auth.poll(makeRequest(`https://auth.example/auth/poll?token=${token}${query}`));
}

test("assertion mode is off unless asked for", async () => {
  const auth = setup();
  const response = await scanAndPoll(auth, "&mode=token");
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /not enabled/);
});

test("with allowAssertions the signed value comes back in the body, not a cookie", async () => {
  const auth = setup({ allowAssertions: true });
  const response = await scanAndPoll(auth, "&mode=token");
  const body = await response.json();

  assert.equal(body.status, "confirmed");
  assert.ok(body.assertion, "expected an assertion");
  assert.equal(response.headers.get("Set-Cookie"), null, "assertion mode must not also set a cookie");
  assert.equal(body.expiresIn, 30 * 24 * 3600);

  const claims = await auth.verifyAssertion(body.assertion);
  assert.equal(claims.id, ALICE.id);
  assert.equal(claims.name, "Alice Ng");
});

test("enabling assertions does not change the browser path", async () => {
  const auth = setup({ allowAssertions: true });
  const response = await scanAndPoll(auth);
  const body = await response.json();
  assert.equal(body.assertion, undefined, "a plain poll must never leak the session value into the body");
  assert.ok(cookieFrom(response, auth.cookieName));
});

test("verifyAssertion accepts a raw value or an Authorization header", async () => {
  const auth = setup({ allowAssertions: true });
  const { assertion } = await (await scanAndPoll(auth, "&mode=token")).json();

  assert.equal((await auth.verifyAssertion(assertion)).id, ALICE.id);
  assert.equal((await auth.verifyAssertion(`Bearer ${assertion}`)).id, ALICE.id);
  assert.equal((await auth.verifyAssertion(`bearer ${assertion}`)).id, ALICE.id);
  assert.equal(await auth.verifyAssertion("Bearer nonsense"), null);
  assert.equal(await auth.verifyAssertion(null), null);
});

test("an assertion is the same value a cookie carries, so both verify identically", async () => {
  // This is what makes one auth service usable from several apps in several languages: there is
  // one format, not a cookie format and a token format.
  const auth = setup({ allowAssertions: true });
  const { assertion } = await (await scanAndPoll(auth, "&mode=token")).json();
  const viaCookie = await auth.getSession(makeRequest("https://app.example/", { cookie: `${auth.cookieName}=${assertion}` }));
  assert.equal(viaCookie.id, ALICE.id);
});

// -------------------------------------------------------------------------------------------------
// The cross-language contract.
//
// Ports of the verifier (see examples/php and examples/csharp) have exactly two steps to get right,
// and both are plain HMAC-SHA-256 available in every language's standard library:
//
//     key       = HMAC(key: keyLabel, message: secret)          -> 32 raw bytes
//     signature = HMAC(key: key,      message: payloadB64)      -> lowercase hex
//
// The value is `<payloadB64>.<signature>`, where payloadB64 is unpadded base64url of the claims
// JSON. The fixed vector below is reproduced verbatim in the README and in both example files, so a
// port can check itself against a known answer instead of against a live server. The values below
// were produced by this package and independently reproduced with Python's hmac module, so they
// pin the *protocol*, not just this implementation.

const VECTOR = {
  secret: "123456:AAHfake-bot-token",
  keyLabel: "TelegramQrAuthSessionKey",
  claims: { id: 39644372, name: "Alice Ng", username: "alice", exp: 4102444800 },
};

test("cross-language vector: the documented recipe reproduces a real signature", async () => {
  const codec = createSessionCodec({ secret: VECTOR.secret });

  // Sign a *known* payload rather than a fresh one, so the expected string below is stable.
  const payloadB64 = Buffer.from(JSON.stringify(VECTOR.claims)).toString("base64url");
  const derivedKey = createHmac("sha256", VECTOR.keyLabel).update(VECTOR.secret).digest();
  const signature = createHmac("sha256", derivedKey).update(payloadB64).digest("hex");
  const value = `${payloadB64}.${signature}`;

  // The known answer. A PHP or C# port that produces these two strings from VECTOR is correct.
  assert.equal(
    payloadB64,
    "eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9"
  );
  assert.equal(signature, "ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95");

  // And the package itself accepts it — the recipe and the implementation agree.
  const claims = await codec.verify(value);
  assert.deepEqual(claims, VECTOR.claims);
});

test("cross-language vector: the wrong key label produces a value the package rejects", async () => {
  const payloadB64 = Buffer.from(JSON.stringify(VECTOR.claims)).toString("base64url");
  const wrongKey = createHmac("sha256", "SomeOtherLabel").update(VECTOR.secret).digest();
  const signature = createHmac("sha256", wrongKey).update(payloadB64).digest("hex");

  const codec = createSessionCodec({ secret: VECTOR.secret });
  assert.equal(await codec.verify(`${payloadB64}.${signature}`), null);
});

test("cross-language vector: a port must check expiry too, not just the signature", async () => {
  // The signature stays valid forever; `exp` is the only thing that stops an old assertion, so a
  // port that verifies the HMAC and skips the exp check has built a permanent credential.
  const expired = { ...VECTOR.claims, exp: 1 };
  const payloadB64 = Buffer.from(JSON.stringify(expired)).toString("base64url");
  const key = createHmac("sha256", VECTOR.keyLabel).update(VECTOR.secret).digest();
  const signature = createHmac("sha256", key).update(payloadB64).digest("hex");

  const codec = createSessionCodec({ secret: VECTOR.secret });
  assert.equal(await codec.verify(`${payloadB64}.${signature}`), null, "expired must be rejected despite a valid signature");
});
