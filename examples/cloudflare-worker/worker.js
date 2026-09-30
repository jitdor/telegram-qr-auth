// A complete, deployable example: one Cloudflare Worker that is both halves of the flow — a
// protected page and the bot webhook that confirms scans for it.
//
// Real deployments often split these into two Workers (the bot usually already exists and does
// other things). Splitting changes nothing except which file each half lives in: both halves
// construct the same `createTelegramQrAuth({...})` with the same config, and both bind the same KV
// namespace. That shared binding is the only thing they need in common.
//
// Setup — no database, no schema, no migration:
//   wrangler kv namespace create LOGINS
//   wrangler secret put TELEGRAM_BOT_TOKEN
//   wrangler secret put TELEGRAM_WEBHOOK_SECRET      # any long random string you choose
//   wrangler deploy
//   curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://<worker>/telegram/webhook&secret_token=<WEBHOOK_SECRET>"

import { createTelegramQrAuth, KVLoginStore, chatMember, escapeHtml } from "telegram-qr-auth";
import { createWebhookHandler } from "telegram-qr-auth/bot";

function buildAuth(env) {
  return createTelegramQrAuth({
    botToken: env.TELEGRAM_BOT_TOKEN,
    botUsername: env.TELEGRAM_BOT_USERNAME,
    // KV holds one 10-minute record per in-flight sign-in and nothing else — there is no user
    // table anywhere in this app. Swap in `new D1LoginStore(env.DB)` if you want a strictly atomic
    // single-use guarantee, or `new MemoryLoginStore()` if both halves share one process.
    store: new KVLoginStore(env.LOGINS),

    // Distinguishes this app's tokens from any other app served by the same bot.
    namespace: "demo",

    // Who gets in: members of one Telegram group — the group IS the user list, so there is nothing
    // to keep in sync. Other shapes, none of which need storage either:
    //   allowlist(env.ALLOWED_IDS)                    ids straight from an env var
    //   chatMemberOfAny(env.CHAT_IDS)                 in ANY of several groups
    //   chatMemberOfAll(env.CHAT_IDS)                 in EVERY one of them
    //   every(chatMember({ chatId }), allowlist(env.ADMINS))
    authorize: chatMember({ chatId: env.CHAT_ID }),

    // Sign cookies with a dedicated secret rather than the bot token, so rotating the bot token
    // doesn't sign everyone out (and vice versa).
    session: { secret: env.SESSION_SECRET ?? env.TELEGRAM_BOT_TOKEN },

    branding: {
      title: "Demo — Sign in",
      heading: "📈 Demo Dashboard",
      subtitle: "Scan with Telegram to sign in. Only members of the team group can get in.",
      accent: "#6366f1",
    },
  });
}

export default {
  async fetch(request, env) {
    const auth = buildAuth(env);
    const url = new URL(request.url);

    // The bot webhook. In a two-Worker setup this lives in the bot Worker instead.
    if (url.pathname === "/telegram/webhook") {
      return createWebhookHandler(auth, { secretToken: env.TELEGRAM_WEBHOOK_SECRET })(request);
    }

    // /auth/login, /auth/poll, /auth/logout, /auth/qr. Returns null for anything else, so it
    // composes with whatever routing you already have.
    const handled = await auth.handle(request);
    if (handled) return handled;

    if (url.pathname === "/health") return new Response("ok");

    // Everything below here is signed-in-only. `guard` verifies the cookie *and* re-checks group
    // membership live, so someone removed from the group is locked out on their next request.
    const gate = await auth.guard(request);
    if (!gate.ok) return gate.response;

    return new Response(page(gate.session), { headers: { "Content-Type": "text/html; charset=UTF-8" } });
  },
};

function page(session) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Demo Dashboard</title></head>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto;">
  <h1>Signed in as ${escapeHtml(session.name)}</h1>
  <p>Telegram user id: <code>${session.id}</code></p>
  <p>They never typed a thing — one QR scan got them here.</p>
  <p><a href="/auth/logout">Sign out</a></p>
</body>
</html>`;
}
