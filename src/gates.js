// Authorization gates — "this scan proves *who* you are; a gate decides whether that person gets
// in." Authentication and authorization are kept separate on purpose: the QR flow is identical for
// every app, while who's allowed differs completely between them.
//
// A gate is just:
//     async (user, ctx) => boolean | { ok: boolean, reason?: string }
// where ctx is { telegram, request, stage }. `stage` is "confirm" when the scan is being confirmed
// by the bot, "poll" when the browser redeems it, "session" when an existing cookie is being
// re-checked on a page load, and "refresh" when the OIDC provider handles a refresh-token grant —
// the same gate runs at every point, so revocation takes effect on the next request rather than at
// cookie expiry.

import { isChatMember, MEMBER_STATUSES } from "./telegram.js";

/** Lets anyone with a Telegram account in. Only sensible for demos or genuinely public apps. */
export function anyUser() {
  return async () => true;
}

/**
 * Membership of a Telegram group/supergroup/channel — the gate the original implementation used.
 * The group *is* the access list: add someone to the chat and they can sign in; remove them and
 * they are locked out on their next request.
 */
export function chatMember({ chatId, statuses = MEMBER_STATUSES, onError = (err) => console.error("getChatMember failed", err) }) {
  if (chatId === undefined || chatId === null || chatId === "") {
    throw new Error("chatMember gate: `chatId` is required");
  }
  return async (user, ctx) => {
    if (!ctx?.telegram) throw new Error("chatMember gate needs a Telegram client — pass `botToken` or `telegram`");
    let failed = false;
    const ok = await isChatMember(ctx.telegram, chatId, user.id, {
      statuses,
      onError: (err) => {
        failed = true;
        onError?.(err);
      },
    });
    if (ok) return true;
    // "Telegram could not be asked" is not "the user is not a member". Marking it transient lets
    // callers refuse this request without doing anything destructive (clearing a session, revoking
    // a refresh-token family) on the strength of an outage.
    return failed ? { ok: false, reason: "telegram_unavailable", transient: true } : { ok: false, reason: "not_a_member" };
  };
}

/**
 * Membership of ANY chat in a list — "staff OR contractors OR the board". Takes a comma-separated
 * string so it can come straight from an env var.
 */
export function chatMemberOfAny(chatIds, options = {}) {
  const ids = splitList(chatIds);
  if (!ids.length) throw new Error("chatMemberOfAny gate: at least one chat id is required");
  return some(...ids.map((chatId) => chatMember({ ...options, chatId })));
}

/**
 * Membership of EVERY chat in a list — "in the company chat AND in this project's chat". Costs one
 * getChatMember call per chat, but `every` short-circuits on the first miss.
 */
export function chatMemberOfAll(chatIds, options = {}) {
  const ids = splitList(chatIds);
  if (!ids.length) throw new Error("chatMemberOfAll gate: at least one chat id is required");
  return every(...ids.map((chatId) => chatMember({ ...options, chatId })));
}

/** A fixed allowlist of Telegram user ids. Accepts numbers, numeric strings, or a comma-separated string. */
export function allowlist(ids) {
  const allowed = new Set(parseIdList(ids));
  return async (user) => (allowed.has(Number(user.id)) ? true : { ok: false, reason: "not_allowlisted" });
}

/** A fixed denylist — everyone else passes. Useful layered under a broader gate via `every`. */
export function denylist(ids) {
  const denied = new Set(parseIdList(ids));
  return async (user) => (denied.has(Number(user.id)) ? { ok: false, reason: "denied" } : true);
}

/** Passes only if every gate passes. Short-circuits on the first failure and keeps its reason. */
export function every(...gates) {
  return async (user, ctx) => {
    for (const gate of gates) {
      const result = normalize(await gate(user, ctx));
      if (!result.ok) return result;
    }
    return true;
  };
}

/**
 * Passes if any gate passes. Reports the last failure's reason when all of them fail — except that
 * a transient failure wins: a gate that could not be checked might have passed, so the outcome is
 * "try again", not a definitive denial.
 */
export function some(...gates) {
  return async (user, ctx) => {
    let last = { ok: false, reason: "denied" };
    let transient = null;
    for (const gate of gates) {
      const result = normalize(await gate(user, ctx));
      if (result.ok) return true;
      last = result;
      if (result.transient) transient = result;
    }
    return transient ?? last;
  };
}

/**
 * Coerces a gate's return value into `{ ok, reason, transient? }`. `transient: true` means the gate
 * could not decide (an upstream outage), as opposed to deciding "no".
 */
export function normalize(result) {
  if (result === true) return { ok: true };
  if (result === false || result == null) return { ok: false, reason: "denied" };
  if (typeof result === "object") {
    const ok = Boolean(result.ok);
    return { ok, reason: result.reason ?? "denied", ...(!ok && result.transient ? { transient: true } : {}) };
  }
  return { ok: Boolean(result) };
}

/**
 * "39644372, 12345" | ["39644372"] | [39644372] -> [39644372, 12345]
 *
 * Blank entries are dropped *before* the Number() conversion, not after: `Number("")` is 0, which
 * would otherwise turn an unset env var into an allowlist containing user id 0.
 */
/**
 * Splits a comma-separated string (or passes an array through), trimming and dropping blanks.
 * Unlike parseIdList this keeps values as strings — chat ids are handed straight back to Telegram
 * and there is no reason to round-trip them through a float.
 */
export function splitList(values) {
  const raw = Array.isArray(values) ? values : String(values ?? "").split(",");
  return raw.map((value) => String(value).trim()).filter((value) => value !== "");
}

export function parseIdList(ids) {
  const raw = Array.isArray(ids) ? ids : String(ids ?? "").split(",");
  return raw
    .map((value) => String(value).trim())
    .filter((value) => value !== "")
    .map(Number)
    .filter(Number.isInteger);
}
