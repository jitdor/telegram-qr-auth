// The bot half, as a ready-made webhook handler.
//
// `auth.handleStart()` already does the security-relevant work and hands back a reply string;
// this file is the thin layer that actually sends it, and it exists so the common case is a
// three-line bot rather than a hand-rolled update loop. Apps that already run grammY, Telegraf or
// their own dispatcher should skip this and call `auth.handleStart()` from inside whatever
// `/start` handler they already have — that path is fully supported and no less complete.

import { hmacSha256, toHex, timingSafeEqualHex } from "./crypto.js";

/** Constant-time string compare: MACs both sides under the secret so length cannot leak either. */
async function safeEqual(candidate, secret) {
  const key = new TextEncoder().encode(secret);
  const [a, b] = await Promise.all([hmacSha256(key, candidate), hmacSha256(key, secret)]);
  return timingSafeEqualHex(toHex(a), toHex(b));
}

/**
 * @param {object} auth   The object returned by createTelegramQrAuth.
 * @param {object} [options]
 * @param {object} [options.telegram]  Client to reply with. Defaults to the provider's.
 * @param {boolean} [options.deleteCommandMessage=true]  Delete the "/start <token>" message once
 *   it has done its job, so the chat isn't left as a scrollback of spent sign-in links. Best
 *   effort — a failure here is never allowed to fail the sign-in.
 * @param {boolean} [options.showClientContext=true]  Append where the sign-in was started from
 *   (origin, IP, browser) to the success message. Costs nothing and is the main defence against
 *   someone being talked into scanning a QR that isn't theirs — see the README.
 * @param {Function} [options.onSignIn]  `(user, result) => void|Promise` after a successful confirm.
 * @returns {(update: object) => Promise<boolean>}  true if the update was a sign-in for this app.
 */
export function createStartHandler(auth, options = {}) {
  const {
    telegram = auth.telegram,
    deleteCommandMessage = true,
    showClientContext = true,
    onSignIn,
  } = options;

  return async function handleUpdate(update) {
    const message = update?.message;
    const text = message?.text;
    const from = message?.from;
    if (!text || !from) return false;

    // Cheap pre-check so this handler stays silent on every message that isn't ours — including
    // /start payloads belonging to a *different* app sharing the same bot.
    if (!auth.parseStartPayload(text)) return false;

    const result = await auth.handleStart({ text, from });
    if (!result.matched) return false;

    let reply = result.replyText;
    if (result.ok && showClientContext && result.client) {
      reply += `\n\n${formatClientContext(result.client)}`;
    }

    await send(telegram, message.chat.id, reply);

    if (deleteCommandMessage) {
      try {
        await remove(telegram, message.chat.id, message.message_id);
      } catch {
        // Deleting someone else's message needs permissions the bot may not have in this chat,
        // and the sign-in has already succeeded either way.
      }
    }

    if (result.ok) await onSignIn?.(result.user, result);
    return true;
  };
}

/**
 * A whole webhook endpoint for a bot that does nothing but sign-ins. Verifies Telegram's secret
 * token header when you give it one — always do, on a public URL.
 *
 * @param {object} auth
 * @param {object} [options]  Everything createStartHandler takes, plus:
 * @param {string} [options.secretToken]  Value configured as `secret_token` on setWebhook.
 * @param {Function} [options.onUnhandled]  `(update) => void|Promise` for updates that weren't sign-ins.
 * @param {Function} [options.onError]  `(err, update) => void|Promise` when handling an update
 *   throws. Defaults to `console.error`. The webhook answers 200 either way.
 */
export function createWebhookHandler(auth, options = {}) {
  const { secretToken, onUnhandled, onError = defaultOnError, ...handlerOptions } = options;
  const handleUpdate = createStartHandler(auth, handlerOptions);

  return async function handleRequest(request) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    if (secretToken && !(await safeEqual(request.headers.get("X-Telegram-Bot-Api-Secret-Token") ?? "", secretToken))) {
      return new Response("Forbidden", { status: 403 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("Bad Request", { status: 400 });
    }

    // Telegram retries a non-2xx and holds every later update behind it, so one failed reply
    // (a Telegram outage, a bug) would block every sign-in after it. The confirm has already
    // happened by the time the reply is sent; report the error and ack regardless.
    try {
      const handled = await handleUpdate(update);
      if (!handled) await onUnhandled?.(update);
    } catch (err) {
      try {
        await onError(err, update);
      } catch {
        // An error reporter that throws must not turn the ack into a 500 either.
      }
    }
    return new Response("ok");
  };
}

function defaultOnError(err) {
  console.error("telegram-qr-auth: webhook update failed", err);
}

function formatClientContext(client) {
  const parts = [];
  if (client.origin) parts.push(client.origin);
  if (client.userAgent) parts.push(describeBrowser(client.userAgent));
  if (client.ip) parts.push(client.ip);
  if (!parts.length) return "";
  return `Signed in to: ${parts.join(" · ")}\nIf that wasn't you, sign out and tell whoever runs this app.`;
}

/** Deliberately coarse — a one-line hint for a human, not analytics. */
function describeBrowser(userAgent) {
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /OPR\/|Opera/.test(userAgent)
      ? "Opera"
      : /Firefox\//.test(userAgent)
        ? "Firefox"
        : /Chrome\//.test(userAgent)
          ? "Chrome"
          : /Safari\//.test(userAgent)
            ? "Safari"
            : "browser";
  const platform = /Windows/.test(userAgent)
    ? "Windows"
    : /Macintosh|Mac OS/.test(userAgent)
      ? "macOS"
      : /Android/.test(userAgent)
        ? "Android"
        : /iPhone|iPad/.test(userAgent)
          ? "iOS"
          : /Linux/.test(userAgent)
            ? "Linux"
            : null;
  return platform ? `${browser} on ${platform}` : browser;
}

function send(telegram, chatId, text) {
  return telegram.sendMessage
    ? telegram.sendMessage(chatId, text)
    : telegram.call("sendMessage", { chat_id: chatId, text });
}

function remove(telegram, chatId, messageId) {
  return telegram.deleteMessage
    ? telegram.deleteMessage(chatId, messageId)
    : telegram.call("deleteMessage", { chat_id: chatId, message_id: messageId });
}
