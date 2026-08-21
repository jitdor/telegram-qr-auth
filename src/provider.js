// The provider — everything the two halves of the flow need, behind one object.
//
// The flow, end to end:
//
//   1. A signed-out browser hits the app. `guard()` finds no valid cookie and returns the sign-in
//      page, which embeds a freshly minted one-time token as a QR encoding
//      https://t.me/<bot>?start=<namespace>_<token>.
//   2. The user scans it with the Telegram app they are already signed into. Telegram opens a chat
//      with the bot and sends "/start <namespace>_<token>". That is the entire user input budget:
//      one scan. No phone number, no login code, no password, no typing.
//   3. The bot Worker calls `confirm()`, which runs the authorization gate against the scanner's
//      Telegram identity and, if it passes, flips the token to confirmed in the shared store.
//   4. The browser has been polling `/auth/poll` the whole time. The first poll after confirmation
//      re-runs the gate, consumes the token, and sets a signed HttpOnly session cookie.
//   5. Every later request re-runs the gate against the cookie's user id, so access revoked in
//      Telegram is revoked here on the next request rather than at cookie expiry.
//
// Why not Telegram's own Login Widget: it authenticates by phone number entry and SMS/app code —
// there is no QR path through it. Deep-link `/start` payloads are the only mechanism Telegram
// offers where a scan alone carries a server-chosen nonce back to you.

import { randomToken, tokenPattern } from "./crypto.js";
import { qrSvg as renderQrSvg } from "./qr.js";
import { createSessionCodec, DEFAULT_MAX_AGE_SECONDS } from "./session.js";
import { TelegramClient, displayName, toAuthUser } from "./telegram.js";
import { anyUser, normalize as normalizeGate } from "./gates.js";
import { renderLoginPage as defaultRenderLoginPage } from "./login-page.js";

/** The status values `/auth/poll` can return. A custom login page must understand all five. */
export const POLL_STATUSES = ["pending", "confirmed", "expired", "invalid", "denied"];

const DEFAULT_TOKEN_TTL_SECONDS = 600; // 10 minutes — long enough to find your phone, short enough to matter
const NAMESPACE_RE = /^[A-Za-z0-9-]{1,24}$/; // no "_": it is the payload separator

/**
 * @param {object} config
 * @param {string} [config.botToken]        Bot token. Required unless `telegram` is supplied.
 * @param {string} config.botUsername       Bot @username without the "@" — the QR points at it.
 * @param {object} config.store             A login store (see ./stores).
 * @param {string} [config.namespace="app"] Distinguishes this app's tokens in the deep-link
 *   payload and in the store, so one bot can front several apps. Also the default cookie name.
 * @param {Function} [config.authorize]     Authorization gate (see ./gates.js). Defaults to
 *   `anyUser()` — override it for anything real.
 * @param {object} [config.session]         Session cookie options; `session.secret` defaults to
 *   the bot token.
 * @param {object} [config.telegram]        Bring-your-own Telegram client exposing
 *   `call(method, payload)`.
 * @param {number} [config.tokenTtlSeconds=600]
 * @param {number} [config.tokenBytes=16]
 * @param {string} [config.basePath="/auth"]
 * @param {string} [config.redirectTo="/"]  Where the page sends the browser after sign-in.
 * @param {number} [config.pollIntervalMs=2000]
 * @param {object} [config.branding]        See DEFAULT_BRANDING in ./login-page.js.
 * @param {object} [config.qr]              See qrSvg options in ./qr.js.
 * @param {Function} [config.renderLoginPage]  Replace the built-in page entirely.
 * @param {Function} [config.claims]        `(user) => object` of extra claims to sign into the
 *   cookie. Keep it small: it rides on every request, and it is signed, not encrypted.
 * @param {boolean} [config.captureClient=true]  Record IP/user-agent at mint time so the bot can
 *   show the user what they are signing into (see "QR phishing" in the README).
 * @param {Function} [config.now]           Clock override, returns epoch seconds. Tests only.
 */
export function createTelegramQrAuth(config) {
  const {
    botToken,
    botUsername,
    store,
    namespace = "app",
    authorize = anyUser(),
    telegram = botToken ? new TelegramClient(botToken) : null,
    tokenTtlSeconds = DEFAULT_TOKEN_TTL_SECONDS,
    tokenBytes = 16,
    basePath = "/auth",
    redirectTo = "/",
    pollIntervalMs = 2000,
    branding,
    qr: qrOptions,
    renderLoginPage = defaultRenderLoginPage,
    claims,
    captureClient = true,
    now = () => Math.floor(Date.now() / 1000),
  } = config;

  if (!store) throw new Error("createTelegramQrAuth: `store` is required");
  if (!botUsername) throw new Error("createTelegramQrAuth: `botUsername` is required");
  if (!telegram && !botToken) throw new Error("createTelegramQrAuth: pass `botToken` or `telegram`");
  if (!NAMESPACE_RE.test(namespace)) {
    throw new Error("createTelegramQrAuth: `namespace` must be 1-24 chars of A-Z a-z 0-9 - (no underscore)");
  }

  const sessionOptions = config.session ?? {};
  const codec = createSessionCodec({
    cookieName: `${namespace}_session`,
    maxAgeSeconds: DEFAULT_MAX_AGE_SECONDS,
    ...sessionOptions,
    // The bot token is a workable default because both halves already hold it, but it means
    // rotating the bot token signs everyone out. See "Choosing a session secret" in the README.
    secret: sessionOptions.secret ?? botToken,
  });

  const TOKEN_RE = tokenPattern(tokenBytes);
  const pollPath = joinPath(basePath, "poll");
  const loginPath = joinPath(basePath, "login");
  const logoutPath = joinPath(basePath, "logout");
  const qrPath = joinPath(basePath, "qr");

  /** `<namespace>_<token>` — what the QR carries and what `/start` hands back. */
  function payloadFor(token) {
    return `${namespace}_${token}`;
  }

  function deepLinkFor(token) {
    return `https://t.me/${botUsername}?start=${payloadFor(token)}`;
  }

  /**
   * Pulls this app's token out of a `/start` payload or a whole message body. Returns null for
   * anything that isn't ours — including another app's namespace on the same bot, which is how one
   * bot can serve several apps without them stepping on each other.
   */
  function parseStartPayload(input) {
    if (typeof input !== "string") return null;
    let payload = input.trim();
    const startMatch = payload.match(/^\/start(?:@\S+)?\s+(\S+)/);
    if (startMatch) payload = startMatch[1];
    const separator = payload.indexOf("_");
    if (separator === -1) return null;
    if (payload.slice(0, separator) !== namespace) return null;
    const token = payload.slice(separator + 1);
    return TOKEN_RE.test(token) ? token : null;
  }

  /** Mints a token and returns everything needed to display it. */
  async function beginLogin({ request } = {}) {
    const token = randomToken(tokenBytes);
    await store.create({
      token,
      namespace,
      expiresAt: now() + tokenTtlSeconds,
      client: captureClient && request ? describeClient(request) : null,
    });
    const deepLink = deepLinkFor(token);
    return { token, deepLink, payload: payloadFor(token), svg: renderQrSvg(deepLink, qrOptions), expiresIn: tokenTtlSeconds };
  }

  /** The sign-in page as an HTML string, with a fresh token already minted into it. */
  async function loginPage({ error, request, redirectTo: to = redirectTo } = {}) {
    const { token, deepLink, svg } = await beginLogin({ request });
    return renderLoginPage({
      token,
      deepLink,
      qrSvg: svg,
      error,
      pollPath,
      pollIntervalMs,
      branding,
      redirectTo: to,
    });
  }

  /** The sign-in page as a `Response`. `clearCookie` also tears up a now-invalid session. */
  async function loginResponse({ error, status = 200, request, clearCookie = false, redirectTo: to } = {}) {
    const headers = new Headers({
      "Content-Type": "text/html; charset=UTF-8",
      // The page embeds a live one-time token, so it must never be cached by a browser, a proxy,
      // or the back button.
      "Cache-Control": "no-store, must-revalidate",
    });
    if (clearCookie) headers.append("Set-Cookie", codec.clearCookieHeader());
    return new Response(await loginPage({ error, request, redirectTo: to }), { status, headers });
  }

  /**
   * Bot side. Confirms a scanned token against the authorization gate.
   * Returns `{ ok, reason, user }`; reasons are "bad_token" | "unknown_or_used" | a gate reason.
   */
  async function confirm({ token, user: rawUser }) {
    if (!token || !TOKEN_RE.test(token)) return { ok: false, reason: "bad_token", user: null };
    const user = toAuthUser(rawUser);

    // The gate runs *before* the token is marked confirmed, so an unauthorized scan burns nothing:
    // the token stays pending and the real user can still use the same QR.
    const gate = normalizeGate(await authorize(user, { telegram, stage: "confirm" }));
    if (!gate.ok) return { ok: false, reason: gate.reason, user };

    const record = await store.get(token, namespace);
    const confirmed = await store.confirm(token, namespace, user);
    if (!confirmed) return { ok: false, reason: "unknown_or_used", user };
    return { ok: true, reason: null, user, client: record?.client ?? null };
  }

  /**
   * Bot side, one step up. Give it an incoming message and it tells you whether it was a sign-in
   * link for this app, what happened, and what to say back — leaving the actual sending to
   * whatever bot framework you already use. See ./bot.js to skip that last step too.
   */
  async function handleStart({ text, from }) {
    const token = parseStartPayload(text);
    if (!token) return { matched: false };
    const result = await confirm({ token, user: from });
    return { matched: true, ...result, replyText: replyTextFor(result, branding) };
  }

  /** Browser side. Polled by the sign-in page; the response that says "confirmed" carries the cookie. */
  async function poll(request) {
    const url = new URL(request.url);
    if (request.method !== "GET") return jsonResponse({ status: "invalid" }, 405);

    const token = url.searchParams.get("token") || "";
    // Reject junk before it reaches the store — this endpoint is unauthenticated by definition.
    if (!TOKEN_RE.test(token)) return jsonResponse({ status: "invalid" }, 400);

    const record = await store.get(token, namespace);
    if (!record) return jsonResponse({ status: "invalid" });

    if (record.status === "pending") {
      if (record.expiresAt <= now()) {
        await store.remove(token, namespace);
        return jsonResponse({ status: "expired" });
      }
      return jsonResponse({ status: "pending" });
    }

    if (record.status === "confirmed") {
      // Single-use, whatever happens next: a token that has been polled once is spent, so a
      // confirmation cannot be replayed into a second session.
      await store.remove(token, namespace);

      // Re-check authorization even though the bot already did at scan time. It costs one API call
      // and it closes the window between "scanned" and "polled".
      const gate = normalizeGate(await authorize(record.user, { telegram, request, stage: "poll" }));
      if (!gate.ok) return jsonResponse({ status: "denied", reason: gate.reason });

      const cookieValue = await codec.sign(sessionClaims(record.user));
      const headers = new Headers();
      headers.append("Set-Cookie", codec.cookieHeader(cookieValue));
      return jsonResponse({ status: "confirmed" }, 200, headers);
    }

    return jsonResponse({ status: "invalid" });
  }

  function sessionClaims(user) {
    return {
      id: user.id,
      name: displayName(user),
      username: user.username || undefined,
      ...(claims ? claims(user) : {}),
    };
  }

  /** Verified cookie claims, or null. Signature and expiry only — no authorization check. */
  async function getSession(request) {
    return codec.verify(codec.read(request));
  }

  /**
   * The guard to put in front of protected routes. Verifies the cookie *and* re-runs the
   * authorization gate live, so this is the call that makes revocation immediate.
   *
   * @returns {Promise<{ok: true, session: object} | {ok: false, reason: string, response: Response}>}
   */
  async function guard(request, { onDenied } = {}) {
    const session = await getSession(request);
    if (!session) {
      return { ok: false, reason: "unauthenticated", response: await loginResponse({ request }) };
    }

    const gate = normalizeGate(await authorize({ id: session.id, username: session.username }, { telegram, request, stage: "session" }));
    if (!gate.ok) {
      const response =
        (await onDenied?.(session, gate.reason)) ??
        (await loginResponse({
          request,
          status: 403,
          clearCookie: true,
          error: branding?.deniedText ?? "Your access to this app has been revoked.",
        }));
      return { ok: false, reason: gate.reason, response };
    }

    return { ok: true, session };
  }

  function logoutResponse({ redirectTo: to = redirectTo } = {}) {
    const headers = new Headers({ Location: to, "Cache-Control": "no-store" });
    headers.append("Set-Cookie", codec.clearCookieHeader());
    return new Response(null, { status: 302, headers });
  }

  /**
   * Drop-in router for the auth endpoints. Returns null for paths it doesn't own, so it composes
   * with whatever routing the app already has:
   *
   *     const handled = await auth.handle(request);
   *     if (handled) return handled;
   */
  async function handle(request) {
    const url = new URL(request.url);

    if (url.pathname === pollPath) return poll(request);
    if (url.pathname === logoutPath) {
      // GET is accepted because a plain <a href="/auth/logout"> is what most apps reach for, and
      // the worst a forged logout can do is sign someone out. Prefer POST where you can.
      if (request.method !== "GET" && request.method !== "POST") return new Response("Method not allowed", { status: 405 });
      return logoutResponse();
    }
    if (url.pathname === loginPath) return loginResponse({ request });
    if (url.pathname === qrPath) {
      // For apps that render their own sign-in UI and just want the ingredients.
      const { token, deepLink, svg, expiresIn } = await beginLogin({ request });
      return jsonResponse({ token, deepLink, svg, expiresIn, pollPath });
    }
    return null;
  }

  return {
    namespace,
    basePath,
    paths: { poll: pollPath, login: loginPath, logout: logoutPath, qr: qrPath },
    cookieName: codec.cookieName,
    tokenTtlSeconds,

    beginLogin,
    parseStartPayload,
    confirm,
    handleStart,
    poll,
    getSession,
    guard,
    loginPage,
    loginResponse,
    logoutResponse,
    handle,
    deepLinkFor,

    // Escape hatches for apps that need to go below the convenience layer.
    store,
    telegram,
    session: codec,
    authorize,
  };
}

function replyTextFor(result, branding = {}) {
  if (result.ok) return branding.botSuccessText ?? "✅ You're signed in — head back to your browser tab.";
  switch (result.reason) {
    case "bad_token":
      return branding.botBadTokenText ?? "That sign-in link looks invalid. Open the sign-in page again and scan the new QR code.";
    case "unknown_or_used":
      return branding.botExpiredText ?? "That sign-in link has expired or was already used. Refresh the sign-in page for a new QR code.";
    default:
      return branding.botDeniedText ?? "You're not authorized to sign in to this app.";
  }
}

/** Mint-time context, echoed back by the bot so the user can see what they are signing into. */
function describeClient(request) {
  return {
    ip: request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || null,
    userAgent: request.headers.get("User-Agent") || null,
    origin: safeOrigin(request.url),
    at: new Date().toISOString(),
  };
}

function safeOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

export function jsonResponse(data, status = 200, extraHeaders) {
  const headers = new Headers({ "Content-Type": "application/json", "Cache-Control": "no-store" });
  if (extraHeaders) for (const [key, value] of extraHeaders.entries()) headers.append(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

function joinPath(base, segment) {
  const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
  return `${trimmed}/${segment}`;
}
