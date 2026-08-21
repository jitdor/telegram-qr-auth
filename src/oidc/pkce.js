// PKCE (RFC 7636).
//
// What it defends against: an authorization code is delivered through the user's browser, and on a
// native app that means through the OS, where another app can register the same custom scheme and
// steal the callback. PKCE makes the stolen code useless — redeeming it requires the random
// verifier that never left the client that started the flow.
//
// This provider requires PKCE for public clients and accepts only S256. The `plain` method puts the
// verifier in the authorization request in clear text, which defeats the entire mechanism if the
// request is what leaked; it exists in the RFC for devices that cannot do SHA-256, and nothing that
// can run a browser is one of those.

import { base64UrlEncode, timingSafeEqualHex, toHex } from "../crypto.js";

export const S256 = "S256";

/** RFC 7636 says 43-128 characters from an unreserved alphabet. */
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9\-._]{43}$/; // base64url of a SHA-256 digest, unpadded

export function isValidChallenge(challenge) {
  return typeof challenge === "string" && CHALLENGE_RE.test(challenge);
}

export function isValidVerifier(verifier) {
  return typeof verifier === "string" && VERIFIER_RE.test(verifier);
}

/** challenge = base64url(SHA-256(ASCII(verifier))) */
export async function deriveChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Checks a presented verifier against the stored challenge.
 *
 * Compares hex digests of both sides rather than the base64 strings directly: the comparison is
 * then fixed-length and constant-time whatever the client sent.
 */
export async function verifyChallenge(verifier, challenge, method = S256) {
  if (method !== S256) return false;
  if (!isValidVerifier(verifier) || !isValidChallenge(challenge)) return false;

  const derived = await deriveChallenge(verifier);
  const encoder = new TextEncoder();
  return timingSafeEqualHex(toHex(encoder.encode(derived)), toHex(encoder.encode(challenge)));
}

/** Generates a verifier/challenge pair — for clients and for tests. */
export async function createPkcePair() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const verifier = base64UrlEncode(bytes); // 43 chars, within the RFC's range
  return { verifier, challenge: await deriveChallenge(verifier), method: S256 };
}
