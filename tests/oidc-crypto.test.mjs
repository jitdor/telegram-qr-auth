// Keys, JWTs and PKCE.

import test from "node:test";
import assert from "node:assert/strict";

import { generateSigningKey, loadSigningKeys, toJwks, jwkThumbprint } from "../src/oidc/keys.js";
import { signJwt, verifyJwt, decodeJwt } from "../src/oidc/jwt.js";
import { createPkcePair, deriveChallenge, verifyChallenge, isValidVerifier, isValidChallenge } from "../src/oidc/pkce.js";
import { base64UrlEncode } from "../src/crypto.js";

const ISSUER = "https://auth.example.com";

async function keys() {
  return loadSigningKeys(await generateSigningKey());
}

// ---- keys ---------------------------------------------------------------------------------------

test("a generated key is a private EC P-256 JWK with a derived kid", async () => {
  const jwk = await generateSigningKey();
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.equal(jwk.alg, "ES256");
  assert.ok(jwk.d, "expected a private component");
  assert.equal(jwk.kid, await jwkThumbprint(jwk), "kid must be the RFC 7638 thumbprint");
});

test("the JWKS never contains private material", async () => {
  const loaded = await keys();
  const jwks = toJwks(loaded);

  assert.equal(jwks.keys.length, 1);
  const published = jwks.keys[0];
  assert.equal(published.d, undefined, "the private scalar must never be published");
  assert.equal(published.kty, "EC");
  assert.ok(published.x && published.y && published.kid);

  // Belt and braces: nothing anywhere in the serialized document looks like a private component.
  assert.equal(JSON.stringify(jwks).includes('"d"'), false);
});

test("loadSigningKeys rejects anything that is not a private P-256 key", async () => {
  const jwk = await generateSigningKey();
  const { d, ...publicOnly } = jwk;

  await assert.rejects(() => loadSigningKeys(publicOnly), /private/);
  await assert.rejects(() => loadSigningKeys({ ...jwk, crv: "P-384" }), /P-256/);
  await assert.rejects(() => loadSigningKeys({ kty: "RSA", d: "x" }), /P-256/);
  await assert.rejects(() => loadSigningKeys([]), /at least one/);
});

test("the same key always gets the same kid, and different keys never collide", async () => {
  const jwk = await generateSigningKey();
  const [first] = await loadSigningKeys(jwk);
  const [second] = await loadSigningKeys(JSON.stringify(jwk));
  assert.equal(first.kid, second.kid);

  const [other] = await loadSigningKeys(await generateSigningKey());
  assert.notEqual(first.kid, other.kid);
});

test("rotation: a token signed by an old key still verifies while it is published", async () => {
  const oldJwk = await generateSigningKey();
  const newJwk = await generateSigningKey();

  const before = await loadSigningKeys(oldJwk);
  const token = await signJwt({ iss: ISSUER, exp: future() }, before[0]);

  // Prepend the new key: it signs from now on, the old one still verifies.
  const after = await loadSigningKeys([newJwk, oldJwk]);
  assert.ok(await verifyJwt(token, { keys: after, issuer: ISSUER }), "old tokens must survive rotation");
  assert.equal(toJwks(after).keys.length, 2);

  // Drop the old key once its tokens have expired and it stops verifying.
  const dropped = await loadSigningKeys(newJwk);
  assert.equal(await verifyJwt(token, { keys: dropped, issuer: ISSUER }), null);
});

// ---- JWT ----------------------------------------------------------------------------------------

test("sign then verify round-trips the claims", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, sub: "42", aud: "client-a", exp: future() }, loaded[0]);

  const claims = await verifyJwt(token, { keys: loaded, issuer: ISSUER, audience: "client-a" });
  assert.equal(claims.sub, "42");

  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
  assert.deepEqual({ alg: header.alg, typ: header.typ }, { alg: "ES256", typ: "JWT" });
  assert.equal(header.kid, loaded[0].kid);
});

test("alg:none is refused", async () => {
  const loaded = await keys();
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: "JWT", kid: loaded[0].kid })));
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ iss: ISSUER, sub: "1", exp: future() })));

  assert.equal(await verifyJwt(`${header}.${payload}.`, { keys: loaded, issuer: ISSUER }), null);
  assert.equal(await verifyJwt(`${header}.${payload}.anything`, { keys: loaded, issuer: ISSUER }), null);
});

test("algorithm confusion is refused: an HS256 header does not get a second look", async () => {
  const loaded = await keys();
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT", kid: loaded[0].kid })));
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ iss: ISSUER, sub: "1", exp: future() })));
  assert.equal(await verifyJwt(`${header}.${payload}.sig`, { keys: loaded, issuer: ISSUER }), null);
});

test("a token signed by a key we do not publish is refused", async () => {
  const mine = await keys();
  const theirs = await keys();
  const forged = await signJwt({ iss: ISSUER, sub: "1", exp: future() }, theirs[0]);
  assert.equal(await verifyJwt(forged, { keys: mine, issuer: ISSUER }), null);
});

test("an unknown kid is refused rather than tried against every key", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, exp: future() }, loaded[0]);
  const [header, payload, signature] = token.split(".");
  const swapped = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "not-a-key" })));
  assert.equal(await verifyJwt(`${swapped}.${payload}.${signature}`, { keys: loaded, issuer: ISSUER }), null);
});

test("a tampered payload is refused", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, sub: "42", exp: future() }, loaded[0]);
  const [header, , signature] = token.split(".");
  const forged = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ iss: ISSUER, sub: "999", exp: future() })));
  assert.equal(await verifyJwt(`${header}.${forged}.${signature}`, { keys: loaded, issuer: ISSUER }), null);
});

test("issuer, audience, expiry and typ are all enforced", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, sub: "1", aud: "client-a", exp: future() }, loaded[0], "at+jwt");

  assert.ok(await verifyJwt(token, { keys: loaded, issuer: ISSUER, audience: "client-a", typ: "at+jwt" }));
  assert.equal(await verifyJwt(token, { keys: loaded, issuer: "https://evil.example" }), null, "wrong issuer");
  assert.equal(await verifyJwt(token, { keys: loaded, issuer: ISSUER, audience: "client-b" }), null, "wrong audience");
  assert.equal(await verifyJwt(token, { keys: loaded, issuer: ISSUER, typ: "JWT" }), null, "wrong typ");

  const expired = await signJwt({ iss: ISSUER, sub: "1", exp: Math.floor(Date.now() / 1000) - 3600 }, loaded[0]);
  assert.equal(await verifyJwt(expired, { keys: loaded, issuer: ISSUER }), null, "expired");
});

test("an array audience is accepted when it contains us", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, aud: ["client-a", "client-b"], exp: future() }, loaded[0]);
  assert.ok(await verifyJwt(token, { keys: loaded, issuer: ISSUER, audience: "client-b" }));
  assert.equal(await verifyJwt(token, { keys: loaded, issuer: ISSUER, audience: "client-c" }), null);
});

test("malformed input returns null instead of throwing", async () => {
  const loaded = await keys();
  for (const bad of ["", "a", "a.b", "a.b.c.d", "....", "%%%.%%%.%%%", null, undefined, 42, {}]) {
    assert.equal(await verifyJwt(bad, { keys: loaded, issuer: ISSUER }), null);
  }
});

test("decodeJwt reads claims without authenticating them", async () => {
  const loaded = await keys();
  const token = await signJwt({ iss: ISSUER, sub: "42", exp: future() }, loaded[0]);
  assert.equal(decodeJwt(token).sub, "42");

  // The trap the doc comment warns about: a forged token decodes fine and must not verify.
  const forged = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiI5OTkifQ.nope";
  assert.equal(decodeJwt(forged).sub, "999");
  assert.equal(await verifyJwt(forged, { keys: loaded, issuer: ISSUER }), null);
});

// ---- PKCE ---------------------------------------------------------------------------------------

test("a generated PKCE pair verifies", async () => {
  const { verifier, challenge } = await createPkcePair();
  assert.ok(isValidVerifier(verifier));
  assert.ok(isValidChallenge(challenge));
  assert.equal(await verifyChallenge(verifier, challenge), true);
});

test("PKCE known answer from RFC 7636 appendix B", async () => {
  // Pinning against the RFC rather than against ourselves.
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(await deriveChallenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

test("the wrong verifier does not verify", async () => {
  const { challenge } = await createPkcePair();
  const other = await createPkcePair();
  assert.equal(await verifyChallenge(other.verifier, challenge), false);
});

test("the plain method is refused even when the values match", async () => {
  // `plain` would make the challenge equal the verifier, which defeats the whole mechanism.
  const verifier = "a".repeat(43);
  assert.equal(await verifyChallenge(verifier, verifier, "plain"), false);
  assert.equal(await verifyChallenge(verifier, await deriveChallenge(verifier), "plain"), false);
});

test("out-of-spec verifiers and challenges are refused", async () => {
  const { challenge } = await createPkcePair();
  assert.equal(await verifyChallenge("short", challenge), false);
  assert.equal(await verifyChallenge("a".repeat(129), challenge), false);
  assert.equal(await verifyChallenge("a".repeat(43) + "!", challenge), false);
  assert.equal(await verifyChallenge("a".repeat(43), "not-a-challenge"), false);
  assert.equal(await verifyChallenge(null, challenge), false);
});

function future() {
  return Math.floor(Date.now() / 1000) + 3600;
}
