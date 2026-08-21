// Compact JWS (JWT) signing and verification, ES256 only.
//
// Deliberately not a general JOSE library: it supports exactly one algorithm and refuses everything
// else. That is a feature. The classic JWT vulnerabilities — `alg: none`, and RS256 tokens replayed
// as HS256 against a public key used as an HMAC secret — are both *algorithm agility* bugs. A
// verifier that accepts one algorithm and reads `alg` only to reject mismatches cannot have them.

import { base64UrlEncode, base64UrlDecode } from "../crypto.js";
import { SIGNING_ALG } from "./keys.js";

const SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" };

function encodeSegment(object) {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(object)));
}

function decodeSegment(segment) {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
}

/**
 * Signs claims into a compact JWS.
 *
 * @param {object} claims  Already-complete claim set; nothing is added here except `typ`/`kid`
 *                         in the header, so callers stay in charge of iss/aud/exp.
 * @param {object} key     A key from loadSigningKeys().
 * @param {string} [typ]   Header `typ` — "JWT" for id tokens, "at+jwt" for access tokens (RFC 9068),
 *                         so a resource server can tell them apart and refuse the wrong one.
 */
export async function signJwt(claims, key, typ = "JWT") {
  const header = { alg: SIGNING_ALG, typ, kid: key.kid };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  const signature = await crypto.subtle.sign(SIGN_PARAMS, key.privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

/**
 * Verifies a compact JWS and its time and identity claims.
 *
 * Every check here is mandatory somewhere in OIDC core, and each one exists because skipping it is
 * a known attack:
 *   - `alg` must be ES256          — stops `alg: none` and algorithm confusion
 *   - `kid` must name a known key  — stops a token signed by a key we never published
 *   - `iss` must match             — stops a token from another provider entirely
 *   - `aud` must contain us        — stops a token issued for a *different* relying party
 *   - `exp`/`nbf` with clock skew  — stops replay of an expired token
 *
 * @returns {Promise<object|null>} The claims, or null. Never throws on bad input.
 */
export async function verifyJwt(token, { keys, issuer, audience, clockToleranceSeconds = 60, now = () => Date.now() / 1000, typ } = {}) {
  if (typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;

  let header;
  let claims;
  try {
    header = decodeSegment(headerB64);
    claims = decodeSegment(payloadB64);
  } catch {
    return null;
  }
  if (!header || !claims || typeof claims !== "object") return null;

  if (header.alg !== SIGNING_ALG) return null;
  if (typ && header.typ !== typ) return null;

  // Look the key up by kid. Falling back to "try every key" when kid is absent would let an
  // attacker strip the header field to widen the search; if we published a kid, we require one.
  const key = keys.find((candidate) => candidate.kid === header.kid);
  if (!key) return null;

  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      SIGN_PARAMS,
      key.publicKey,
      base64UrlDecode(signatureB64),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`)
    );
  } catch {
    return null;
  }
  if (!valid) return null;

  const seconds = now();
  if (typeof claims.exp !== "number" || claims.exp + clockToleranceSeconds < seconds) return null;
  if (typeof claims.nbf === "number" && claims.nbf - clockToleranceSeconds > seconds) return null;
  if (issuer && claims.iss !== issuer) return null;

  if (audience) {
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(audience)) return null;
  }

  return claims;
}

/**
 * Reads the claims WITHOUT verifying anything.
 *
 * For logging and for a client that wants to show a name it already trusts by other means. Never
 * for an access decision — the payload is signed, not sealed, and anyone can write anything here.
 */
export function decodeJwt(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return decodeSegment(parts[1]);
  } catch {
    return null;
  }
}
