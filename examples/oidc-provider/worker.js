// A deployable OpenID Connect provider whose sign-in is a Telegram QR scan.
//
// Deploy this at https://auth.example.com and any app in any language can federate to it with a
// stock OIDC library, pointed at:
//
//     https://auth.example.com/.well-known/openid-configuration
//
// Setup:
//   wrangler kv namespace create LOGINS
//   EITHER a Durable Object (one binding, no provisioning — see wrangler.jsonc), OR:
//   wrangler d1 create oidc && wrangler d1 execute oidc --remote --file=migrations/oidc-d1.sql
//   wrangler unsafe ratelimit ...             # bind RATE_LIMITER — the worker refuses to boot without it
//   node -e "import('telegram-qr-auth/oidc').then(async m => console.log(JSON.stringify(await m.generateSigningKey())))"
//   wrangler secret put OIDC_SIGNING_KEY        # the JSON from the line above
//   wrangler secret put TELEGRAM_BOT_TOKEN
//   wrangler secret put TELEGRAM_WEBHOOK_SECRET
//   wrangler secret put PAIRWISE_SALT           # any long random string
//   wrangler deploy
//   curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://auth.example.com/telegram/webhook&secret_token=<WEBHOOK_SECRET>"
//
// Read docs/oidc.md before pointing third parties at this — particularly the notes on rate
// limiting. Refresh-token rotation and code redemption need atomic writes, which is why this
// example uses D1 rather than KV for the OIDC store.

import { DurableObject } from "cloudflare:workers";
import { createTelegramQrAuth, KVLoginStore, chatMember } from "telegram-qr-auth";
import { DoLoginStore, DoOidcStore, defineQrAuthStorage } from "telegram-qr-auth/do";
import { createWebhookHandler } from "telegram-qr-auth/bot";
import { createOidcProvider, loadSigningKeys, StaticClientRegistry, D1OidcStore } from "telegram-qr-auth/oidc";

// One SQLite-backed Durable Object can hold both the QR sign-in records and the provider state.
export class QrAuthStorage extends defineQrAuthStorage(DurableObject) {}

// Choose storage by binding: QRAUTH_DO (Durable Object) or LOGINS + OIDC_DB (KV + D1).
const loginStore = (env) => (env.QRAUTH_DO ? new DoLoginStore(env.QRAUTH_DO) : new KVLoginStore(env.LOGINS));
const oidcStore = (env) => (env.QRAUTH_DO ? new DoOidcStore(env.QRAUTH_DO) : new D1OidcStore(env.OIDC_DB));

function buildAuth(env) {
  return createTelegramQrAuth({
    botToken: env.TELEGRAM_BOT_TOKEN,
    botUsername: env.TELEGRAM_BOT_USERNAME,
    store: loginStore(env),
    namespace: "idp",

    // Who may sign in AT ALL. Per-client restrictions go on the client itself; this is the front
    // door. It re-runs on every /authorize, so removing someone from the group stops them minting
    // new tokens immediately.
    authorize: chatMember({ chatId: env.CHAT_ID }),

    // Puts auth_time in id tokens, and lets `max_age` accept a session that is still fresh. Without
    // it the provider cannot prove freshness, and re-authenticates instead of assuming.
    claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),

    branding: {
      title: "Sign in",
      heading: "Sign in with Telegram",
      subtitle: "Scan with the Telegram app. No phone number, nothing to type.",
    },
  });
}

function buildClients(env) {
  return new StaticClientRegistry([
    {
      // A first-party SPA: no secret it could keep, PKCE required, consent skipped.
      client_id: "dashboard",
      client_name: "Acme Dashboard",
      redirect_uris: ["https://dashboard.example.com/callback", "http://127.0.0.1:5173/callback"],
      scopes: ["openid", "profile", "offline_access"],
      type: "public",
      first_party: true,
    },
    {
      // A third party. Consent is shown and remembered; a pairwise sub means they cannot correlate
      // this user with any other relying party's view of them.
      client_id: "partner-crm",
      client_name: "Partner CRM",
      redirect_uris: ["https://crm.partner.example/oauth/callback"],
      scopes: ["openid", "profile"],
      type: "confidential",
      client_secret: env.PARTNER_CRM_SECRET,
      pairwise: true,
    },
  ]);
}

export default {
  async fetch(request, env, ctx) {
    // /authorize and /token are unauthenticated by definition, so running without a limiter is
    // running open. Fail closed instead of silently shipping that.
    if (!env.RATE_LIMITER && env.ALLOW_UNLIMITED !== "true") {
      return new Response("Misconfigured: bind RATE_LIMITER (or set ALLOW_UNLIMITED=true for local development).", { status: 500 });
    }

    const auth = buildAuth(env);
    const url = new URL(request.url);

    // The bot half. In a bigger deployment this is its own Worker; both halves only need to share
    // the LOGINS binding.
    if (url.pathname === "/telegram/webhook") {
      return createWebhookHandler(auth, { secretToken: env.TELEGRAM_WEBHOOK_SECRET })(request);
    }

    const oidc = createOidcProvider({
      auth,
      issuer: env.ISSUER,
      keys: await loadSigningKeys(env.OIDC_SIGNING_KEY),
      clients: buildClients(env),
      store: oidcStore(env),
      pairwiseSalt: env.PAIRWISE_SALT,

      rateLimit: env.RATE_LIMITER ? async (key) => (await env.RATE_LIMITER.limit({ key })).success : undefined,

      // Every issuance, denial and reuse detection. Send it somewhere durable — reuse detection in
      // particular is the signal that a refresh token leaked, and it is worth alerting on.
      onEvent: (event) => {
        console.log(JSON.stringify({ ...event, at: new Date().toISOString() }));
      },
    });

    // Serves the OIDC endpoints and falls through to /auth/* for the QR itself.
    return oidc.handle(request);
  },
};
