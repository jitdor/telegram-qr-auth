// Stateless signed session cookies.
//
// There is deliberately no server-side session table: the cookie carries its own signed, expiring
// payload, so a consuming app can be a single stateless Worker with nothing to clean up. What that
// buys in simplicity it gives up in revocability — a signed cookie cannot be torn up server-side —
// which is exactly why `createTelegramQrAuth().guard()` re-runs the authorization gate live on
// every request instead of trusting the cookie's claims. See "Security model" in the README.

import { hmacSha256, toHex, timingSafeEqualHex, base64UrlEncode, base64UrlDecode } from "./crypto.js";

export const DEFAULT_MAX_AGE_SECONDS = 30 * 24 * 3600; // 30 days

/**
 * @param {object} options
 * @param {string} options.secret          Signing secret. The bot token works, but a dedicated
 *                                         secret is better — see README.
 * @param {string} [options.cookieName="tg_qr_session"]
 * @param {number} [options.maxAgeSeconds]
 * @param {string} [options.keyLabel]      HMAC domain-separation label. Two codecs sharing a
 *                                         secret but not a label cannot verify each other's
 *                                         cookies — which is what keeps a session signature from
 *                                         ever being confused with, say, a Telegram Login Widget
 *                                         hash derived from the same bot token.
 * @param {"Strict"|"Lax"|"None"} [options.sameSite="Lax"]
 * @param {boolean} [options.secure=true]  Set false only for plain-HTTP local development.
 * @param {string} [options.path="/"]
 * @param {string} [options.domain]
 */
export function createSessionCodec(options) {
  const {
    secret,
    cookieName = "tg_qr_session",
    maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS,
    keyLabel = "TelegramQrAuthSessionKey",
    sameSite = "Lax",
    secure = true,
    path = "/",
    domain,
  } = options;

  if (!secret) throw new Error("createSessionCodec: `secret` is required");

  let keyPromise = null;
  function key() {
    // Derived once per codec instance. The derivation is itself an HMAC so the label, not the raw
    // secret, is what this codec signs with.
    keyPromise ??= hmacSha256(new TextEncoder().encode(keyLabel), secret);
    return keyPromise;
  }

  return {
    cookieName,
    maxAgeSeconds,

    /**
     * Signs `claims` into a cookie value. `exp` is stamped here and always wins over any `exp`
     * passed in.
     */
    async sign(claims, ttlSeconds = maxAgeSeconds) {
      const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
      const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ ...claims, exp })));
      const sig = toHex(await hmacSha256(await key(), payloadB64));
      return `${payloadB64}.${sig}`;
    },

    /** Returns the claims object if the value is validly signed and unexpired, else null. */
    async verify(cookieValue) {
      if (!cookieValue) return null;
      const [payloadB64, sig] = cookieValue.split(".");
      if (!payloadB64 || !sig) return null;
      const expected = toHex(await hmacSha256(await key(), payloadB64));
      if (!timingSafeEqualHex(expected, sig)) return null;
      let payload;
      try {
        payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
      } catch {
        return null;
      }
      if (!payload || typeof payload !== "object") return null;
      if (!Number.isFinite(payload.exp) || payload.exp < Date.now() / 1000) return null;
      return payload;
    },

    /** A `Set-Cookie` header value. Pass maxAge 0 to clear. */
    cookieHeader(value, maxAge = maxAgeSeconds) {
      const parts = [`${cookieName}=${value}`, `Path=${path}`, `Max-Age=${maxAge}`, "HttpOnly", `SameSite=${sameSite}`];
      if (secure) parts.push("Secure");
      if (domain) parts.push(`Domain=${domain}`);
      return parts.join("; ");
    },

    clearCookieHeader() {
      return this.cookieHeader("", 0);
    },

    /** Reads this codec's cookie out of a `Request`. */
    read(request) {
      return parseCookies(request.headers.get("Cookie"))[cookieName] ?? null;
    },
  };
}

export function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    if (!key) return;
    const raw = part.slice(idx + 1).trim();
    try {
      out[key] = decodeURIComponent(raw);
    } catch {
      // A malformed value in some unrelated cookie must not take the whole request down; a mangled
      // value of ours simply fails signature verification later.
      out[key] = raw;
    }
  });
  return out;
}
