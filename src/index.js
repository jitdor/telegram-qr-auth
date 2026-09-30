// telegram-qr-auth — Telegram as an identity provider, by QR scan, with zero user input.
//
// Start with `createTelegramQrAuth`; everything else here is either a piece it is built from or a
// piece you swap out. See README.md for the 30-line quickstart.

export { createTelegramQrAuth, POLL_STATUSES, LOGIN_PAGE_HEADER, jsonResponse, sameSitePath } from "./provider.js";
export { createStartHandler, createWebhookHandler } from "./bot.js";

export { KVLoginStore, D1LoginStore, MemoryLoginStore } from "./stores/index.js";

export * as gates from "./gates.js";
export { anyUser, chatMember, chatMemberOfAny, chatMemberOfAll, allowlist, denylist, every, some, parseIdList, splitList } from "./gates.js";

export { TelegramClient, displayName, isChatMember, toAuthUser, MEMBER_STATUSES } from "./telegram.js";
export { createSessionCodec, parseCookies, DEFAULT_MAX_AGE_SECONDS } from "./session.js";
export { qrSvg, qrDataUri } from "./qr.js";
export { renderLoginPage, pollScript, appLinkFromDeepLink, DEFAULT_BRANDING, DEFAULT_POLL_TEXTS, DEFAULT_POLL_IDS, escapeHtml } from "./login-page.js";
export { hmacSha256, toHex, timingSafeEqualHex, base64UrlEncode, base64UrlDecode, randomToken, tokenPattern } from "./crypto.js";
