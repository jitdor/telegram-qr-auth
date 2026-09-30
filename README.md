# telegram-qr-auth

**Telegram as an identity provider. One QR scan. Zero user input.**

No phone number. No login code. No password. No form fields at all — the sign-in page has no
`<input>` on it, and the only thing the user does is point their phone at a square.

```
┌──────────────────────────┐
│   Scan to sign in        │        1. page shows a QR encoding
│   ▄▄▄▄▄▄▄ ▄  ▄ ▄▄▄▄▄▄▄   │           t.me/yourbot?start=app_<one-time token>
│   █ ▄▄▄ █ ▀▄▀█ █ ▄▄▄ █   │        2. phone scans it → Telegram sends /start to your bot
│   █ ███ █ █▄▀▄ █ ███ █   │        3. bot checks who they are, confirms the token
│   █▄▄▄▄▄█ ▀ █▀ █▄▄▄▄▄█   │        4. page was polling; it gets a signed session cookie
│   Waiting for scan…      │
└──────────────────────────┘        Total keystrokes: 0
```

Zero dependencies. One file per concern, no build step. Runs on Cloudflare Workers, Deno, Bun and
Node 22.13+.

---

## Why not Telegram's Login Widget

Telegram's official Login Widget authenticates by **phone number entry followed by a code**. There
is no QR path through it — that is a property of the widget, not a configuration option. If you
want a scan-only sign-in, deep-link `/start` payloads are the only mechanism Telegram gives you
where a scan carries a server-chosen nonce back to your own code.

That is what this package packages: the deep-link dance, the one-time token store, the QR
rendering, the session cookie, and the authorization checks — as pieces you can each swap out.

|                          | Login Widget         | telegram-qr-auth              |
| ------------------------ | -------------------- | ----------------------------- |
| User input               | Phone number + code  | **None**                      |
| Works from a laptop      | Yes                  | Yes (scan with your phone)    |
| Works on the phone itself| Yes                  | Yes (tap the link instead)    |
| Third-party JS on page   | Telegram's widget    | **None** — QR is inline SVG   |
| Authorization            | Yours to build       | Pluggable gates, checked live |

---

## How it works

```mermaid
sequenceDiagram
    participant B as Browser
    participant W as Your app
    participant S as Shared store
    participant T as Telegram
    participant P as Phone

    B->>W: GET / (no cookie)
    W->>S: create pending token
    W-->>B: sign-in page + inline QR (t.me/bot?start=app_TOKEN)
    loop every 2s
        B->>W: GET /auth/poll?token=TOKEN
        W-->>B: {status:"pending"}
    end
    P->>T: scan → /start app_TOKEN
    T->>W: webhook update
    W->>W: authorize(user) — group member? allowlisted?
    W->>S: mark confirmed + who scanned
    B->>W: GET /auth/poll?token=TOKEN
    W->>W: re-authorize, consume token
    W-->>B: {status:"confirmed"} + Set-Cookie (signed, HttpOnly)
    B->>W: GET / (with cookie)
    W->>W: verify signature + re-authorize live
    W-->>B: the actual app
```

Two halves, one shared store. The **web half** mints and polls; the **bot half** confirms. They are
usually separate deployments (two Workers, or an app plus the bot you already run), which is why
the store is injected rather than in-process.

---

## Install

Not on npm — install straight from GitHub:

```bash
npm install github:jitdor/telegram-qr-auth
```

This tracks `main`, which is the supported version — there are no release tags to pin. npm records
the exact commit it fetched in your lockfile, so **commit `package-lock.json`**: installs stay
reproducible, and you only move when you choose to:

```bash
npm update telegram-qr-auth      # fetch the latest main and record the new commit
```

**Knowing when there is an update.** There is no version number to watch. Follow the commit feed
(`https://github.com/jitdor/telegram-qr-auth/commits/main.atom`) in a feed reader, or use
GitHub's **Watch → Custom** on the repo. Changes that alter behaviour are called out in the commit
message and the pull request title, so skim those before running `npm update`.

It lands in `node_modules/telegram-qr-auth` and imports by that name either way. Vendoring the
`src/` directory into your own repo is also a legitimate option: it is nine dependency-free ESM
files with no build step, and that is partly the point.

---

## Quickstart — Cloudflare Workers

**1. One KV namespace** — no database, no schema, no migration:

```bash
wrangler kv namespace create LOGINS
```

**2. The web half:**

```js
import { createTelegramQrAuth, KVLoginStore, chatMember } from "telegram-qr-auth";

const auth = (env) => createTelegramQrAuth({
  botToken: env.TELEGRAM_BOT_TOKEN,
  botUsername: env.TELEGRAM_BOT_USERNAME,   // without the "@"
  store: new KVLoginStore(env.LOGINS),
  namespace: "myapp",
  authorize: chatMember({ chatId: env.CHAT_ID }),
});

export default {
  async fetch(request, env) {
    const a = auth(env);

    // /auth/login, /auth/poll, /auth/logout, /auth/qr — returns null for anything else
    const handled = await a.handle(request);
    if (handled) return handled;

    const gate = await a.guard(request);
    if (!gate.ok) return gate.response;      // the sign-in page, or 403

    return new Response(`Hello ${gate.session.name}`);
  },
};
```

**3. The bot half** — in the Worker that receives your bot's webhook:

```js
import { createWebhookHandler } from "telegram-qr-auth/bot";

// as a whole endpoint...
export default { fetch: (req, env) => createWebhookHandler(auth(env), { secretToken: env.HOOK_SECRET })(req) };
```

...or, if you already have a bot with its own `/start` handling, drop one call into it:

```js
const signIn = await auth(env).handleStart({ text: message.text, from: message.from });
if (signIn.matched) {
  await bot.sendMessage(message.chat.id, signIn.replyText);
  return;                                   // it was a sign-in link, not a normal /start
}
```

`handleStart` returns `{ matched: false }` for anything that isn't a sign-in link for **this**
namespace, so one bot can front several apps without them colliding.

A complete deployable version of both halves is in
[`examples/cloudflare-worker/`](examples/cloudflare-worker/worker.js), and a Cloudflare-free
Node version in [`examples/node-server/`](examples/node-server/server.mjs).

---

## Authorization

Authentication ("who is this?") is identical for every app. Authorization ("do they get in?") never
is — so it is a function you supply:

```js
async (user, ctx) => boolean | { ok: boolean, reason?: string }
```

None of these need a database — they either ask Telegram or read a string.

```js
import { chatMember, chatMemberOfAny, chatMemberOfAll, allowlist, denylist, every, some, anyUser } from "telegram-qr-auth";

chatMember({ chatId: "-1001234567890" })              // the group IS the access list
chatMember({ chatId, statuses: new Set(["creator", "administrator"]) })   // admins only
chatMemberOfAny("-100111,-100222")                    // in ANY of these groups
chatMemberOfAll("-100111,-100222")                    // in EVERY one of them
allowlist("39644372,12345")                           // ids straight from an env var
denylist(env.BLOCKED)
every(chatMember({ chatId }), allowlist(env.ADMINS))  // in the group AND on the shortlist
some(allowlist(env.STAFF), chatMember({ chatId }))
anyUser()                                             // the default — override it
```

Your own gate is just a function:

```js
authorize: async (user) => {
  const row = await db.prepare("SELECT 1 FROM staff WHERE telegram_id = ?").bind(user.id).first();
  return row ? true : { ok: false, reason: "not_staff" };
}
```

**The gate runs at up to four points**, and `ctx.stage` tells you which (`"refresh"` applies only
if you run the OIDC provider):

| `stage`     | When                                    | Why it matters                                        |
| ----------- | --------------------------------------- | ----------------------------------------------------- |
| `"confirm"` | The bot receives the scan               | An unauthorized scan is refused *before* the token is spent |
| `"poll"`    | The browser redeems the confirmed token | Closes the gap between scan and redemption            |
| `"session"` | **Every** guarded request               | Access revoked in Telegram is revoked here immediately |
| `"refresh"` | OIDC provider: a refresh-token grant    | Someone removed from the group cannot keep minting tokens |

A gate that cannot decide — the built-in `chatMember` when Telegram is unreachable — returns
`{ ok: false, reason: "telegram_unavailable", transient: true }`. Refusals flagged `transient`
are answered with a 503 / "try again" and never sign anyone out or revoke anything, so an outage
does not become a mass logout. Custom gates should do the same.

That last row is the important one: because the gate re-runs on every request, removing someone
from the group locks them out on their next page load — not whenever their cookie happens to
expire.

---

## Storage — what state actually exists

Worth being precise, because "requires a database" would be the wrong impression:

| State                  | Where it lives                                    | Storage needed        |
| ---------------------- | ------------------------------------------------- | --------------------- |
| **Who your users are** | Telegram. It's already the identity provider.     | **None, ever.** There is no user table in this package. |
| **Who is allowed in**  | A group membership check, or an env var           | **None** — `chatMember({ chatId })` asks Telegram; `allowlist(env.ALLOWED_IDS)` reads a string |
| **The session**        | A signed `HttpOnly` cookie on the client          | **None** — stateless  |
| **A sign-in in flight**| A 10-minute record: "token X was confirmed by user Y" | One key-value write |

Only the last row needs anywhere to put anything, and it needs it for ten minutes. It cannot be
avoided or moved into config: the browser is polling in one process while the phone confirms in
another, so *something* has to be written by one and read by the other. (If both halves genuinely
share a process — a single Node server that also long-polls the bot — `MemoryLoginStore` needs
nothing at all.)

### Picking a store

| Store              | Setup                          | Use when                                                  |
| ------------------ | ------------------------------ | --------------------------------------------------------- |
| `KVLoginStore`     | `wrangler kv namespace create` | **The default.** No schema, no migration, TTL cleanup free |
| `D1LoginStore`     | one table, one migration       | You want strictly atomic single-use, or already run D1     |
| `DoLoginStore`     | one Durable Object class       | Atomic + consistent, with no database to provision         |
| `MemoryLoginStore` | nothing                        | Both halves in one process, or tests                       |

```js
new KVLoginStore(env.LOGINS, { prefix: "tgqr:" })
new D1LoginStore(env.DB, { table: "telegram_qr_logins", sweepAfterSeconds: 86400 })
new DoLoginStore(env.QRAUTH_DO, { name: "default" })
new MemoryLoginStore()
```

**Durable Object store.** Export the class from your Worker, bind it, and pass the binding:

```js
import { DurableObject } from "cloudflare:workers";
import { defineQrAuthStorage, DoLoginStore } from "telegram-qr-auth/do";
export class QrAuthStorage extends defineQrAuthStorage(DurableObject) {}
// wrangler.jsonc: durable_objects.bindings [{ name: "QRAUTH_DO", class_name: "QrAuthStorage" }]
//                 migrations [{ tag: "v1", new_sqlite_classes: ["QrAuthStorage"] }]
```

It is strongly consistent and `confirm` is atomic, like D1, but the object creates its own tables, so
there is nothing to provision or migrate. It has its own entry point so deployments that don't use
Durable Objects (or OIDC) never load that code. For the OIDC provider use `DoOidcStore`, from the
same `telegram-qr-auth/do` entry point (also re-exported by `telegram-qr-auth/oidc`); one object can
hold both. If the bot is a separate Worker, bind the
class there with `script_name`, and use the same `name` on both sides.

**The KV trade-off, stated honestly.** KV is eventually consistent, so a confirmation may take an
extra poll cycle to become visible — invisible against a 2-second poll and a 10-minute TTL. And its
`confirm` is a read-then-write with no compare-and-swap available, so two *genuinely simultaneous*
scans of the same QR could both succeed. Note what that costs: both scanners already passed the
authorization gate, so the outcome is two sessions for two people each entitled to one — not an
unauthorized session, and the token is still consumed on first redemption so it can't be replayed
later. If you want one QR to mean exactly one session always, use `D1LoginStore` (its `confirm` is
a single conditional `UPDATE`, atomic by construction) or `DoLoginStore`.

D1 needs its table created once:

```bash
wrangler d1 execute my-db --remote --file=node_modules/telegram-qr-auth/migrations/d1.sql
```

### Writing a store

Four methods, ~40 lines. Redis, Postgres, a Durable Object, Deno KV — all fine:

```js
class MyStore {
  async create({ token, namespace, expiresAt, client }) {}
  async get(token, namespace) {}                    // -> record | null
  async confirm(token, namespace, user) {}          // -> true only if it was still pending
  async remove(token, namespace) {}
}
```

`tests/stores.test.mjs` runs one contract suite across all three bundled stores — point it at yours
to check it behaves.

---

## Theming

Restyle the built-in page:

```js
branding: {
  title: "Acme — Sign in",
  heading: "📈 Acme Dashboard",
  subtitle: "Scan with Telegram. Nothing to type.",
  accent: "#0ea5e9", gradientFrom: "#0ea5e9", gradientTo: "#6366f1",
  qrDark: "#0f172a", qrLight: "#ffffff",
  logoHtml: '<img src="data:image/svg+xml;base64,..." alt="" width="48">',
  botSuccessText: "✅ You're in — back to your browser.",
}
```

**The QR is always a link.** Clicking it opens the same `t.me` deep link the code encodes — on a
computer that launches the installed Telegram client, which is often quicker than fetching a phone.
It opens in a new tab so the sign-in page stays put and keeps polling. On touch devices, where
scanning your own screen is impossible, the page leads with an "Open Telegram to sign in" button and
its own subtitle. Text is customisable via `branding.mobileLinkText`, `mobileSubtitle`, `qrHintText`
and `qrLinkTitle`. A custom `renderLoginPage` should keep this: wrap the QR in an `<a href={deepLink}
target="_blank" rel="noopener noreferrer">`.

Or replace the page entirely — `renderLoginPage({ token, deepLink, qrSvg, error, pollPath, redirectTo })`
returns an HTML string. The only contract a replacement must keep is polling `pollPath` and
understanding the five statuses in `POLL_STATUSES`:
`pending` · `confirmed` · `expired` · `invalid` · `denied`.

Rendering your own UI entirely? `GET /auth/qr` returns `{ token, deepLink, svg, expiresIn, pollPath }`
as JSON, or call `auth.beginLogin()` directly.

---

## Running a public identity provider

Everything above assumes you own every app that verifies a session. If third parties need to sign
users in, that assumption breaks in a specific way: HMAC verification and HMAC forgery use the same
key, so a relying party that can check a token can also mint one — for any user, to any of your
apps.

`telegram-qr-auth/oidc` is the answer to that: a standards-compliant OpenID Connect provider with
the QR scan as its authentication method. ES256 signing, published JWKS, per-client audiences,
PKCE, consent, and refresh rotation with reuse detection. Relying parties integrate with a stock
OIDC library and never learn Telegram is involved.

```js
import { createOidcProvider, loadSigningKeys, StaticClientRegistry, D1OidcStore } from "telegram-qr-auth/oidc";

const oidc = createOidcProvider({
  auth,                                        // your createTelegramQrAuth instance
  issuer: "https://auth.example.com",
  keys: await loadSigningKeys(env.OIDC_SIGNING_KEY),
  clients: new StaticClientRegistry([...]),
  store: new D1OidcStore(env.OIDC_DB),
});

export default { fetch: (request) => oidc.handle(request) };
```

Relying parties then point any OIDC library at
`https://auth.example.com/.well-known/openid-configuration`.

| | Base package | OIDC provider |
| --- | --- | --- |
| Signing | HMAC, shared secret | **ES256**, private key held only by the provider |
| A verifier can forge tokens | **yes** | no |
| Token scoped to one app | no | `aud` per client |
| Consent | none | shown, remembered, withdrawable |
| Revocation | shorten the session | rotation, reuse detection, `/revoke` |
| Cross-domain browser sign-in | shared parent domain only | any domain |

Authorization code + PKCE only — implicit and hybrid are neither advertised nor implemented.

**[docs/oidc.md](docs/oidc.md)** is the deployment guide, and it is worth reading before you point
strangers at this: consent deliberately costs one tap, `KvOidcStore` has no compare-and-swap (use `D1OidcStore`), rate
limiting is yours to wire up, and running an IdP for other people's users carries obligations that
no amount of test coverage addresses.

Runnable example: [`examples/oidc-provider/`](examples/oidc-provider/worker.js).

---

## Using it from other languages

The package is JavaScript, but only **one** component ever runs it: the auth service. Deploy that
once as a Worker; every other app — PHP, Go, C#, Python, another Worker — either *verifies* a
session it issued or *drives* a sign-in over HTTP. Neither needs a port of the package, an SDK, or
a dependency.

Verifying is two HMAC-SHA-256 calls against a `<payloadB64>.<signature>` string:

```
key       = HMAC-SHA256(key: keyLabel, message: secret)      -> 32 raw bytes
signature = HMAC-SHA256(key: key,      message: payloadB64)  -> lowercase hex
```

It is local: no call back to the auth service, so a verifier keeps working while the service is
down and only new sign-ins stop. The trade is that a local verifier sees a signature, not a live
authorization — see [`examples/README.md`](examples/README.md) for how to close that gap.

Working ports, each carrying the same known-answer test vector:

| Language | Verifier | Client | Status |
| --- | --- | --- | --- |
| [Go](examples/go/telegramqrauth.go) | yes, plus `net/http` middleware | yes | `go test` — 13 subtests pass |
| [Python](examples/python/telegram_qr_auth.py) | yes | yes | `--selftest` — 9 checks pass |
| [PHP](examples/php/telegram_qr_auth.php) | yes | — | reviewed, not executed |
| [C#](examples/csharp/TelegramQrAuth.cs) | yes, plus ASP.NET middleware | yes | reviewed, not executed |
| JS / Workers | `auth.guard()` | built in | covered by the package's own tests |

All standard library — `hmac`/`hashlib`, `crypto/hmac`, `hash_hmac`, `HMACSHA256`.

### Getting the session to your app

**Same registrable domain** — use the cookie. Set
`session: { cookieName: "myapp_session", domain: ".example.com" }` on the service, and your app
just verifies `$_COOKIE` / `r.Cookie` / `Request.Cookies`.

**Different domains, or a native client** — use a bearer assertion:

```js
allowAssertions: true      // off by default
```

The client polls `/auth/poll?token=...&mode=token` and gets

```json
{ "status": "confirmed", "assertion": "<payloadB64>.<signature>", "expiresIn": 2592000 }
```

to send onward as `Authorization: Bearer ...`. It is opt-in because returning the session value in
a body is exactly what `HttpOnly` prevents — appropriate when the poller is a desktop app or a CLI,
not when it is a browser.

### The known-answer vector

Any port should check itself against this before being trusted:

```
secret     123456:AAHfake-bot-token
keyLabel   TelegramQrAuthSessionKey
claims     {"id":39644372,"name":"Alice Ng","username":"alice","exp":4102444800}

payloadB64 eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9
signature  ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95
```

Two mistakes account for nearly every failed port: swapping the HMAC key and message in the
derivation step (the **label** is the key, the **secret** is the message), and verifying the
signature but forgetting to check `exp` — which turns every assertion into a permanent credential.

---

## Security model

What this package does:

- **One-time tokens.** 128 bits of `crypto.getRandomValues`, deleted the moment they are redeemed.
  A spent token is indistinguishable from one that never existed.
- **Short TTL.** 10 minutes by default (`tokenTtlSeconds`).
- **The token never leaves the server until it is scanned.** The QR is rendered server-side as
  inline SVG — no client-side QR library, no `api.qrserver.com`, no image CDN holding your
  credentials in its logs.
- **Refused scans don't burn the token.** Authorization runs before confirmation, so a wrong person
  scanning your QR doesn't force you to refresh it.
- **Signed, `HttpOnly`, `Secure`, `SameSite=Lax` cookies**, verified with a constant-time compare.
- **Domain-separated keys.** The signing key is `HMAC(label, secret)`, so a session signature can
  never be confused with another HMAC derived from the same bot token.
- **Live re-authorization on every request** — the answer to "a signed cookie can't be revoked".
- **No caching, anywhere.** Sign-in pages and poll responses are `Cache-Control: no-store`; the
  login page is `noindex`.
- **Input validated before it reaches storage.** Malformed tokens are rejected by regex, table
  names by allowlist.

### QR phishing — read this one

The unavoidable weakness of *every* scan-to-log-in system, this one included: if an attacker can
get **their** QR in front of **your** eyes — a fake page, a screen share, a printed sticker over a
real one — and you scan it, they get a session as you. The scan proves who scanned; it cannot prove
whose screen was scanned.

Mitigations here, and their honest limits:

1. **Context in the confirmation message.** The bot tells the user what they just signed into —
   origin, browser, IP — captured when the QR was minted (`captureClient`, on by default). Someone
   who scans a QR while sitting at their own laptop and is told they just signed into
   `https://not-your-app.example` from `Chrome on Windows` in another country has a real chance of
   noticing. This costs nothing and is on by default.
2. **A tight TTL** shrinks the window for a QR harvested and re-displayed later.
3. **A gate that means something.** `chatMember` limits the blast radius to people already in your
   group.

If your threat model includes deliberate phishing of your users, add an explicit confirmation step:
have the bot reply with an inline keyboard and only call `auth.confirm()` from the callback handler.
That trades away the zero-input property for an unambiguous "yes, that's me" — this package leaves
the choice to you rather than making it for you, and `confirm()` is a plain function you can call
from anywhere.

### Choosing a session secret

`session.secret` defaults to the bot token, which works because both halves already hold it. Prefer
a dedicated secret:

```js
session: { secret: env.SESSION_SECRET }
```

Otherwise rotating your bot token signs every user out, and any other component that derives an
HMAC from that token is one implementation mistake away from your session key.

### What this package deliberately does not do

- **Refresh tokens / server-side session revocation.** Sessions are stateless signed cookies; live
  re-authorization is the revocation mechanism. If you need to kill a *specific* session, put a
  session id in `claims` and check it against a denylist in your gate.
- **CSRF protection for your app's own forms.** `SameSite=Lax` covers the common cases; anything
  state-changing still needs its own token.
- **Rate limiting.** `/auth/poll` is unauthenticated by design (it must be). Put your platform's
  rate limiter in front of it.

---

## Configuration reference

```js
createTelegramQrAuth({
  botToken,                  // required unless you pass `telegram`
  botUsername,               // required — the QR points at t.me/<botUsername>
  store,                     // required

  namespace: "app",          // deep-link prefix, store scope, default cookie name.
                             // 1-24 chars of A-Z a-z 0-9 - (no underscore: it's the separator)
  authorize: anyUser(),      // see Authorization
  telegram,                  // bring your own client: { call(method, payload) }

  session: {
    secret,                  // defaults to botToken
    cookieName,              // defaults to `${namespace}_session`
    maxAgeSeconds: 2592000,  // 30 days
    sameSite: "Lax",
    secure: true,            // false only for plain-HTTP localhost
    keyLabel, path, domain,
  },

  tokenTtlSeconds: 600,
  tokenBytes: 16,
  basePath: "/auth",
  redirectTo: "/",           // where the page goes after sign-in
  pollIntervalMs: 2000,
  captureClient: true,       // record origin/IP/UA at mint time for the bot's message
  allowAssertions: false,    // let non-browser clients get the session in the body, not a cookie
  claims: (user) => ({}),    // extra signed cookie claims — keep small, signed not encrypted
  branding, qr, renderLoginPage, now,
});
```

Returned object:

| Member                  | Half    | Purpose                                                |
| ----------------------- | ------- | ------------------------------------------------------ |
| `handle(request)`       | web     | Router for `/auth/*`; `null` if the path isn't its own |
| `guard(request)`        | web     | `{ok:true, session}` or `{ok:false, reason, response}` |
| `getSession(request)`   | web     | Verified claims, signature+expiry only, no gate        |
| `verifyAssertion(value)`| web     | Same, for an `Authorization: Bearer` value             |
| `beginLogin({request})` | web     | `{ token, deepLink, payload, svg, expiresIn }`         |
| `loginPage/loginResponse` | web   | Render the sign-in page yourself                       |
| `logoutResponse()`      | web     | 302 + cleared cookie                                   |
| `poll(request)`         | web     | The poll endpoint, if you route it yourself            |
| `handleStart({text,from})` | bot  | Parse + confirm + a reply string                       |
| `confirm({token,user})` | bot     | The raw confirm, for custom bot flows                  |
| `parseStartPayload(text)` | bot   | Token for this namespace, or `null`                    |
| `store` `telegram` `session` `authorize` | both | Escape hatches                        |

---

## Runtime support

Built on WebCrypto, `fetch`, `Request`/`Response` and `btoa`/`atob` only.

| Runtime            | Status                                                        |
| ------------------ | ------------------------------------------------------------- |
| Cloudflare Workers | Primary target — D1/KV stores included                        |
| Node 22.13+        | Yes (`Request`/`Response` are global)                         |
| Deno, Bun          | Yes                                                           |
| Browsers           | No, and never — this is server-side by construction           |

---

## Migrating a hand-rolled implementation

If you already have this flow inline in an app, the mapping is mechanical:

| Hand-rolled                                  | Here                                       |
| -------------------------------------------- | ------------------------------------------ |
| `randomToken()` + `INSERT INTO ..._logins`   | `auth.beginLogin()`                        |
| `qrSvg(deepLink)` + vendored QR library      | included; delete the vendored copy         |
| `renderQrLoginPage(...)`                     | `auth.loginPage({ branding })`             |
| `handleAuthPoll(request, env, url)`          | `auth.poll(request)` / `auth.handle(...)`  |
| `signSession` / `verifySession` / `parseCookies` | `auth.session` (`createSessionCodec`)  |
| `isGroupMember(...)` checks scattered per route | `chatMember({ chatId })` + `auth.guard()` |
| `handleCockpitLogin(...)` in the bot         | `auth.handleStart({ text, from })`         |
| `cockpit_logins` table                       | `KVLoginStore` (drop the table entirely), or `migrations/d1.sql` to stay on D1 — `namespace` replaces the `chat_id` column and epoch seconds replace `datetime('now')` strings |

The old table is not migrated in place — rows there are short-lived sign-in attempts, so point the
new store wherever you want it, deploy both halves together, and let any in-flight sign-in be
retried. Moving from D1 to KV is a fine time to do it: the login table was the only reason the
cockpit needed a write path into that database at all.

---

## Development

There is nothing to install and nothing to build — clone it and run the tests:

```bash
node --test tests/*.test.mjs
```

150 tests, no network, no wrangler, no D1 emulator: the D1 tests run real SQLite (`node:sqlite`)
against the real migration file, so the SQL that makes `confirm` single-use is actually exercised.

---

## License

MIT © Kenny.

Bundles [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase
(MIT), vendored in `src/qrcode-generator.js` so this package stays dependency-free — see `LICENSE`.
