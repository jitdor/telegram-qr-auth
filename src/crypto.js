// Crypto primitives, built only on WebCrypto + the base64 globals, so this file runs unchanged on
// Cloudflare Workers, Deno, Bun and Node 18+. Nothing here is Telegram-specific.

/** HMAC-SHA-256 of `message` (string) under `keyBytes` (Uint8Array), as raw bytes. */
export async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

export function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Constant-time comparison of two hex strings. Length is allowed to leak (both sides are
 * fixed-width hex digests here); the byte values are not.
 */
export function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function base64UrlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(str.length / 4) * 4, "=");
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * A cryptographically random login token, hex-encoded. 16 bytes (128 bits) by default — the token
 * is single-use and short-lived, but it is also the *only* thing standing between a scan and a
 * session, so it must not be guessable within its TTL.
 */
export function randomToken(byteLength = 16) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** Matches what `randomToken(byteLength)` produces — used to reject junk before it reaches the store. */
export function tokenPattern(byteLength = 16) {
  return new RegExp(`^[0-9a-f]{${byteLength * 2}}$`);
}
