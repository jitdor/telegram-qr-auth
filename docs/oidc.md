# Running a public identity provider

`telegram-qr-auth/oidc` turns the QR sign-in into a standards-compliant OpenID Connect provider —
the shape Microsoft runs for consumer accounts, with Telegram as the authentication method instead
of a password. Relying parties integrate with a stock OIDC library and never learn that Telegram is
involved.

## When you need this, and when you don't

The base package signs sessions with **HMAC and a shared secret**. Verification and forgery use the
same key, so any party that can check a session can also mint one — for any user, to any of your
apps. Among apps you control, that is fine; you already trust yourself.

The moment someone you don't control needs to sign users in, it stops being fine. This module
exists for that boundary:

| | Base package | OIDC provider |
| --- | --- | --- |
| Signing | HMAC-SHA256, shared secret | **ES256**, private key held only here |
| A verifier can forge tokens | **yes** | no — they hold public keys |
| Token scoped to one app | no | `aud` per client |
| Consent | none | consent screen, remembered, withdrawable |
| Revocation | shorten the session | refresh rotation, reuse detection, `/revoke` |
| Cross-domain browser sign-in | shared parent domain only | any domain, via redirect |
| Client integration | verify a string | any OIDC library |

Use the base package for your own apps. Use this when third parties integrate — and it is worth
using even internally, because it removes "every verifier can also forge" from your own estate.

## Setup

**1. Generate a signing key** (once — then treat it exactly like a TLS private key):

```bash
node -e "import('telegram-qr-auth/oidc').then(async m => console.log(JSON.stringify(await m.generateSigningKey())))"
```

```bash
wrangler secret put OIDC_SIGNING_KEY
```

**2. Wire it up:**

```js
import { createTelegramQrAuth, KVLoginStore, chatMember } from "telegram-qr-auth";
import { createOidcProvider, loadSigningKeys, StaticClientRegistry, D1OidcStore } from "telegram-qr-auth/oidc";

const auth = createTelegramQrAuth({
  botToken: env.TELEGRAM_BOT_TOKEN,
  botUsername: env.TELEGRAM_BOT_USERNAME,
  store: new KVLoginStore(env.LOGINS),
  namespace: "idp",
  authorize: chatMember({ chatId: env.CHAT_ID }),
  // Required for max_age and prompt=login to mean anything.
  claims: () => ({ auth_time: Math.floor(Date.now() / 1000) }),
});

const oidc = createOidcProvider({
  auth,
  issuer: "https://auth.example.com",       // exactly what RPs configure; no trailing slash
  keys: await loadSigningKeys(env.OIDC_SIGNING_KEY),
  clients: new StaticClientRegistry([...]),
  store: new D1OidcStore(env.OIDC_DB),
  pairwiseSalt: env.PAIRWISE_SALT,
});

export default { fetch: (request) => oidc.handle(request) };
```

`oidc.handle()` serves every OIDC endpoint and falls through to the base package's `/auth/*` routes,
where the QR lives.

## Registering clients

```js
new StaticClientRegistry([
  {
    client_id: "acme-dashboard",
    client_name: "Acme Dashboard",          // shown on the consent screen — use the real name
    redirect_uris: ["https://acme.example.com/callback"],
    scopes: ["openid", "profile", "offline_access"],
    type: "public",                          // SPA/mobile/desktop: no secret, PKCE required
  },
  {
    client_id: "internal-admin",
    client_name: "Admin Console",
    type: "confidential",                    // has a server side that can hold a secret
    client_secret: env.ADMIN_CLIENT_SECRET,
    redirect_uris: ["https://admin.example.com/cb"],
    first_party: true,                       // skip consent — ONLY for apps you ship
    pairwise: false,
  },
])
```

`redirect_uris` is an **exact-match allowlist**. No prefixes, no wildcards, no trailing-slash
tolerance — every "OAuth open redirect" incident is a provider that was lenient here. The one
exception is the port of a loopback URI, which RFC 8252 requires be ignored because native apps
bind whatever port the OS gives them.

Use `StoreClientRegistry` instead once editing a config gets old; it validates the same way.

## What a relying party does

Nothing unusual — it is ordinary OIDC:

```
https://auth.example.com/.well-known/openid-configuration
```

Point any library at that. Authorization code + PKCE is the only flow offered; implicit and hybrid
are not advertised and not implemented, because both put tokens in a URL fragment and neither has a
reason to exist any more.

## Decisions worth understanding

### Consent breaks "zero user input", deliberately

For a third-party client the user gets one screen and one tap. Without it, any client that talks
someone into scanning a QR silently collects their identity, and the user never learns which app
asked. `first_party: true` skips it for apps you ship.

It doubles as the strongest anti-phishing control the flow has: the screen names the client and the
callback host, so someone who scanned expecting their own dashboard is told, before anything is
issued, that a different app is about to receive their identity.

### Pairwise subjects

With `pairwise: true`, each client sees a different opaque `sub` for the same person, so two
relying parties comparing notes cannot tell they are talking about the same user. For a service
third parties integrate with, this is the difference between an identity provider and a tracking
network, and it costs one HMAC. Clients sharing a `sector_identifier` still see the same `sub`, so
one vendor's several apps recognise a returning user.

### Refresh reuse means theft, not retry

Refresh tokens rotate on every use. Presenting an already-rotated token means either the client
retried or someone stole it and the real client already rotated — and the provider cannot tell
which. It revokes the whole token family: the thief loses access, the user signs in again.

A refresh also re-runs your authorization gate. If the gate says no, the refresh is refused
(`invalid_grant`) but the family is left intact, since the gate re-runs every time and a user who
really lost access can never mint tokens. If the gate could not be evaluated — the built-in
`chatMember` gate marks Telegram API errors `transient` — the answer is `503
temporarily_unavailable` and the same refresh token works again once Telegram is back. Custom gates
should return `{ ok: false, transient: true }` for outages rather than a plain `false`.

That includes two *simultaneous* refreshes with the same token: exactly one wins, and the other is
treated as reuse, which signs the user out. So clients must **serialize refreshes and never retry
one concurrently** — hold a single in-flight refresh per token and have other callers await it, and
retry a failed refresh only after the first attempt has definitely finished. HTTP libraries with
aggressive automatic retry or request hedging are the usual way to trip this by accident.

### Access tokens carry profile claims

`/userinfo` re-serves claims from the access token rather than reading storage. That keeps the
endpoint stateless, and it means profile claims are a **snapshot from sign-in**, not a live read of
Telegram. Keep `accessTokenTtlSeconds` short if that matters to you.

### Key rotation

`loadSigningKeys([newKey, oldKey])` — the first key signs, all keys are published. Deploy, let old
tokens expire, then drop the old key. Replacing the only key instead would invalidate every token
in flight.

## Before you open it to third parties

The code enforces the protocol. These are yours:

- **Rate limiting.** `/authorize` and `/token` are unauthenticated by definition. Pass a
  `rateLimit(key, ctx)` function; wire it to Cloudflare's rate-limiting binding or equivalent.
- **A transactional store.** `KvOidcStore` is best-effort, not race-free: it cannot do compare-and-swap, so `consumeCode` and
  `rotateRefreshToken` are read-then-write, and its family index is a read-modify-write: two
  simultaneous redemptions of one stolen code — or two simultaneous refreshes with one stolen
  token — could both succeed, defeating reuse detection. Use `D1OidcStore` (schema in
  `migrations/oidc-d1.sql`) or `DoOidcStore` (from `telegram-qr-auth/do`: a SQLite-backed Durable Object, no
  database to provision) for anything third parties touch.
  `examples/oidc-provider` uses D1 and refuses to boot without a rate limiter.
- **Audit logging.** Wire `onEvent` to real storage. Every issuance, denial and reuse detection
  passes through it.
- **Telegram's limits.** Every user of every relying party starts a chat with *your* single bot.
  That bot is one choke point for Bot API rate limits and for abuse, and users see your bot's name
  rather than the relying party's.
- **You become a data controller** for other people's users. That has legal weight independent of
  anything in this repo — worth checking before you launch, not after.
- **Get it reviewed.** These 150 tests cover the failure modes I could think of. An identity
  provider that strangers depend on deserves someone else's eyes as well.
