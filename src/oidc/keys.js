// Signing keys for the OIDC provider.
//
// This is the change that makes a *public* identity provider possible at all. The base package
// signs sessions with HMAC, which means anyone who can verify a token can also mint one — fine
// when you own every relying party, unacceptable the moment a third party integrates, because
// their verification key would also let them impersonate any of your users to anybody else.
//
// Here the provider holds an ECDSA P-256 private key and publishes only the public half at
// /.well-known/jwks.json. Relying parties can check signatures and can never forge them. ES256
// rather than RS256 because WebCrypto's ECDSA output is already the raw r||s pair JOSE wants (no
// DER unwrapping), keys and tokens are far smaller, and every JWT library supports it.

import { base64UrlEncode, base64UrlDecode } from "../crypto.js";

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };
export const SIGNING_ALG = "ES256";

/**
 * Generates a fresh signing key. Run once, store the private JWK as a secret:
 *
 *   node -e "import('telegram-qr-auth/oidc').then(async m => console.log(JSON.stringify(await m.generateSigningKey())))"
 *
 * The result contains the private key. Treat it exactly as you would a TLS private key: a secret
 * manager or `wrangler secret put`, never the repo, never a var.
 */
export async function generateSigningKey() {
  const pair = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { ...jwk, kid: await jwkThumbprint(jwk), alg: SIGNING_ALG, use: "sig" };
}

/**
 * Loads one or more private JWKs into usable signing keys.
 *
 * The *first* key signs; every key is published in the JWKS. That ordering is the whole rotation
 * procedure: prepend a new key, deploy, and tokens signed by the old one keep verifying until they
 * expire, at which point the old key can be dropped. Rotating by replacing the only key instead
 * would invalidate every token in flight.
 *
 * @param {object|string|Array} input  A private JWK, a JSON string of one, or an array of either.
 */
export async function loadSigningKeys(input) {
  const raw = typeof input === "string" ? JSON.parse(input) : input;
  const list = Array.isArray(raw) ? raw : [raw];
  if (!list.length) throw new Error("loadSigningKeys: at least one key is required");

  return Promise.all(list.map(loadOne));
}

async function loadOne(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Error("loadSigningKeys: expected an EC P-256 JWK");
  }
  if (!jwk.d) throw new Error("loadSigningKeys: expected a *private* JWK (no `d` component found)");

  // Import twice: WebCrypto will not derive a verify key from a private one, and a key object is
  // single-purpose. `d` is stripped for the public half so the private scalar cannot leak into
  // the JWKS by accident — the one mistake in this file that would be catastrophic and silent.
  const { d, key_ops, ext, ...publicJwk } = jwk;
  const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, key_ops: ["sign"] }, ALGORITHM, false, ["sign"]);
  const publicKey = await crypto.subtle.importKey("jwk", { ...publicJwk, key_ops: ["verify"] }, ALGORITHM, true, ["verify"]);

  const kid = jwk.kid || (await jwkThumbprint(jwk));

  return {
    kid,
    alg: SIGNING_ALG,
    privateKey,
    publicKey,
    /** The public half, safe to serve to anyone. */
    publicJwk: { kty: "EC", crv: "P-256", x: publicJwk.x, y: publicJwk.y, kid, alg: SIGNING_ALG, use: "sig" },
  };
}

/** The JWKS document served at /.well-known/jwks.json. Public material only. */
export function toJwks(keys) {
  return { keys: keys.map((key) => key.publicJwk) };
}

/**
 * RFC 7638 JWK thumbprint, used as the `kid`.
 *
 * Deriving the id from the key itself rather than naming it by hand means two deployments of the
 * same key always agree on its id, and a rotated key can never accidentally reuse the previous
 * one's name — which would make caches serve the wrong key for the wrong signature.
 */
export async function jwkThumbprint(jwk) {
  // Required members only, lexicographic order, no whitespace. The spec is exact about this
  // because any deviation produces a different id for the same key.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64UrlEncode(new Uint8Array(digest));
}

/** Imports a *public* JWK for verification — what a relying party does with a JWKS entry. */
export async function importPublicJwk(jwk) {
  return crypto.subtle.importKey("jwk", { ...jwk, key_ops: ["verify"] }, ALGORITHM, true, ["verify"]);
}

export { base64UrlEncode, base64UrlDecode };
