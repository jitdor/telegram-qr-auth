import test from "node:test";
import assert from "node:assert/strict";

import { createSessionCodec, parseCookies } from "../src/session.js";

const SECRET = "123456:AAHfake-bot-token";

test("a signed cookie round-trips its claims", async () => {
  const codec = createSessionCodec({ secret: SECRET });
  const value = await codec.sign({ id: 42, name: "Alice Ng" });
  const claims = await codec.verify(value);
  assert.equal(claims.id, 42);
  assert.equal(claims.name, "Alice Ng");
  assert.ok(claims.exp > Date.now() / 1000);
});

test("a tampered payload does not verify", async () => {
  const codec = createSessionCodec({ secret: SECRET });
  const value = await codec.sign({ id: 42, name: "Alice" });
  const [payload, signature] = value.split(".");

  // Re-encode the payload with a different user id, keeping the original signature.
  const forged = Buffer.from(JSON.stringify({ id: 999, name: "Mallory", exp: 2_000_000_000 }))
    .toString("base64url");
  assert.equal(await codec.verify(`${forged}.${signature}`), null);
  assert.equal(await codec.verify(`${payload}.${"0".repeat(signature.length)}`), null);
  assert.equal(await codec.verify(payload), null);
  assert.equal(await codec.verify(""), null);
  assert.equal(await codec.verify(null), null);
});

test("a cookie signed with a different secret does not verify", async () => {
  const mine = createSessionCodec({ secret: SECRET });
  const theirs = createSessionCodec({ secret: "a-completely-different-secret" });
  assert.equal(await mine.verify(await theirs.sign({ id: 1, name: "x" })), null);
});

test("the key label is domain separation, not decoration", async () => {
  // Same secret, different label: signatures from one must be worthless to the other. This is what
  // keeps a session cookie from ever being interchangeable with some other HMAC an app derives
  // from the same bot token (a Login Widget hash, a webhook signature, a share link).
  const sessions = createSessionCodec({ secret: SECRET, keyLabel: "SessionKey" });
  const other = createSessionCodec({ secret: SECRET, keyLabel: "SomethingElse" });
  assert.equal(await sessions.verify(await other.sign({ id: 1, name: "x" })), null);
});

test("expired cookies are rejected", async () => {
  const codec = createSessionCodec({ secret: SECRET });
  const value = await codec.sign({ id: 42, name: "Alice" }, -1);
  assert.equal(await codec.verify(value), null);
});

test("cookie attributes are the safe ones by default", async () => {
  const codec = createSessionCodec({ secret: SECRET, cookieName: "app_session" });
  const header = codec.cookieHeader("abc");
  assert.match(header, /^app_session=abc; Path=\/; Max-Age=\d+; HttpOnly; SameSite=Lax; Secure$/);
  assert.match(codec.clearCookieHeader(), /Max-Age=0/);
});

test("secure can be turned off for local http development, and nothing else changes", async () => {
  const codec = createSessionCodec({ secret: SECRET, secure: false });
  const header = codec.cookieHeader("abc");
  assert.equal(/Secure/.test(header), false);
  assert.match(header, /HttpOnly/);
});

test("createSessionCodec refuses to run without a secret", () => {
  assert.throws(() => createSessionCodec({}), /secret/);
});

test("parseCookies handles the shapes browsers actually send", () => {
  assert.deepEqual(parseCookies("a=1; b=2"), { a: "1", b: "2" });
  assert.deepEqual(parseCookies("a=hello%20world"), { a: "hello world" });
  assert.deepEqual(parseCookies("  a=1 ;;  b = 2 "), { a: "1", b: "2" });
  assert.deepEqual(parseCookies("novalue"), {});
  assert.deepEqual(parseCookies(null), {});
});

test("a session cookie survives a codec rebuild with the same config", async () => {
  // Workers spin up fresh isolates constantly, so the codec that verifies a cookie is almost never
  // the object that signed it.
  const signed = await createSessionCodec({ secret: SECRET }).sign({ id: 7, name: "Bo" });
  const claims = await createSessionCodec({ secret: SECRET }).verify(signed);
  assert.equal(claims.id, 7);
});
