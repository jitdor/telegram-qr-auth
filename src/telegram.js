// The smallest Telegram Bot API client this package needs. Deliberately not a general-purpose
// wrapper: if a consuming app already has grammY, Telegraf or its own client, it can pass that in
// instead as long as it exposes `call(method, payload)` — see `telegram` in createTelegramQrAuth.

export class TelegramClient {
  // The default is a wrapper, not `fetch` itself: stored on the instance and called as
  // `this.fetchImpl(...)`, a bare `fetch` would run with the client as `this`, which Workers
  // rejects with "Illegal invocation".
  constructor(token, { apiBase = "https://api.telegram.org", fetchImpl = (...args) => fetch(...args) } = {}) {
    if (!token) throw new Error("TelegramClient: bot token is required");
    this.endpoint = `${apiBase}/bot${token}`;
    this.fetchImpl = fetchImpl;
  }

  async call(method, payload) {
    const res = await this.fetchImpl(`${this.endpoint}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Telegram API ${method} failed: ${res.status} ${body}`);
    }
    return res.json();
  }

  getChatMember(chatId, userId) {
    return this.call("getChatMember", { chat_id: chatId, user_id: userId });
  }

  sendMessage(chatId, text, extra = {}) {
    return this.call("sendMessage", { chat_id: chatId, text, ...extra });
  }

  deleteMessage(chatId, messageId) {
    return this.call("deleteMessage", { chat_id: chatId, message_id: messageId });
  }
}

/** Best available human-readable name for a Telegram user, in the order a person would expect. */
export function displayName(user) {
  if (!user) return "";
  const name = [user.first_name, user.last_name].filter(Boolean).join(" ");
  return name || user.username || `User ${user.id}`;
}

/**
 * Statuses that count as "in the chat". `left` and `kicked` are the ones that don't, and a
 * `restricted` member counts only while Telegram also reports `is_member: true`.
 */
export const MEMBER_STATUSES = new Set(["creator", "administrator", "member", "restricted"]);

/**
 * Live membership check — no caching anywhere in this package, on purpose. Someone removed from
 * the group loses access on their very next request, not whenever a cache or cookie expires.
 * Fails closed: a Telegram API error is treated as "not a member".
 */
export async function isChatMember(telegram, chatId, userId, { statuses = MEMBER_STATUSES, onError } = {}) {
  try {
    // Works with this package's client and with any bring-your-own client that only exposes
    // `call(method, payload)` (grammY's `api.raw`, a hand-rolled fetch wrapper, a test double).
    const res = telegram.getChatMember
      ? await telegram.getChatMember(chatId, userId)
      : await telegram.call("getChatMember", { chat_id: chatId, user_id: userId });
    const member = res?.result;
    if (!statuses.has(member?.status)) return false;
    // "restricted" covers both a muted member and someone who was restricted and then *left*:
    // Telegram keeps the restriction on file after they go. Only `is_member` tells them apart.
    if (member.status === "restricted" && member.is_member !== true) return false;
    return true;
  } catch (err) {
    onError?.(err);
    return false;
  }
}

/** Normalizes a Telegram `User` down to the fields this package stores and signs. */
export function toAuthUser(user) {
  return {
    id: Number(user.id),
    first_name: user.first_name ?? "",
    last_name: user.last_name ?? "",
    username: user.username ?? "",
  };
}
