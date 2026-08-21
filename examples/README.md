# Examples

## The shape of a multi-language deployment

The package is JavaScript, and only one component ever runs it: **the auth service**. Deploy it
once as a Worker at, say, `https://auth.example.com`. It owns the whole Telegram side — minting
one-time tokens, rendering the QR, talking to the bot, checking group membership, signing sessions.

Every other app, in any language, only ever does one of two things:

```
                    ┌──────────────────────────────┐
                    │  auth.example.com (Worker)   │   ← the only place the JS package runs
                    │  telegram-qr-auth            │
                    └──────────────┬───────────────┘
                                   │  issues a signed session value
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
        VERIFY it             VERIFY it              DRIVE a sign-in
       (PHP, Go, C#,          (another                (C#/Python/Go
        Python backend)        Worker)                 desktop or CLI)
       2 HMAC calls,          auth.guard()            /auth/qr then poll
       no network             in-process              → bearer assertion
```

**Verifying is local.** The session value is `<payloadB64>.<signature>` — an HMAC-SHA-256 your app
recomputes with the shared secret. No call back to the auth service, no SDK, no dependency, and no
availability coupling: if the auth service is down, existing sessions keep working and only new
sign-ins stop.

The trade that comes with it: a local verifier sees a *signature*, not a live authorization. The
auth service re-checks Telegram group membership on every request **it** serves; your PHP or Go app
checks maths. Close that gap by shortening the session (`session: { maxAgeSeconds: 3600 }`), by
routing sensitive actions through the Worker, or by checking the user id against your own
revocation list.

## What's here

| Directory | Language | What it shows | Verified |
| --- | --- | --- | --- |
| [`cloudflare-worker/`](cloudflare-worker/worker.js) | JS | The auth service itself — both halves in one Worker | Covered by the package's 150 tests |
| [`node-server/`](node-server/server.mjs) | JS | The whole flow with no Cloudflare at all | — |
| [`oidc-provider/`](oidc-provider/worker.js) | JS | A full OpenID Connect provider — see [docs/oidc.md](../docs/oidc.md) | Covered by 57 OIDC tests |
| [`go/`](go/telegramqrauth.go) | Go | Verifier + middleware + CLI client | **`go test` — 13 subtests pass** |
| [`python/`](python/telegram_qr_auth.py) | Python | Verifier + client | **`--selftest` — 9 checks pass** |
| [`php/`](php/index.php) | PHP | Verifier + protected page | Reviewed, not executed (no PHP here) |
| [`csharp/`](csharp/TelegramQrAuth.cs) | C# | Verifier + ASP.NET middleware + console client | Reviewed, not executed (no .NET here) |

Every port carries the same known-answer test vector, so a port proves itself against the protocol
rather than against itself:

```
secret     123456:AAHfake-bot-token
keyLabel   TelegramQrAuthSessionKey
claims     {"id":39644372,"name":"Alice Ng","username":"alice","exp":4102444800}

payloadB64 eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9
signature  ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95
```

Produced by the JavaScript implementation, independently reproduced with Python's `hmac`, and
asserted in `tests/assertions.test.mjs`, `examples/go/telegramqrauth_test.go`, the PHP
`tqa_selftest()` and the C# `SelfTest()`. Run the self-test in CI, not just once — it catches a
changed `keyLabel` or a rotated secret immediately.

## Getting the session to your app

**Same registrable domain** (`auth.example.com` + `app.example.com`) — use the cookie:

```js
session: { secret: env.SESSION_SECRET, cookieName: "myapp_session", domain: ".example.com" },
redirectTo: "https://app.example.com/",
```

Your app reads `myapp_session` and verifies it. Nothing else to build.

**Different domains, or a native client** — use a bearer assertion. Turn it on explicitly:

```js
allowAssertions: true
```

Then poll `/auth/poll?token=…&mode=token`, which returns

```json
{ "status": "confirmed", "assertion": "<payloadB64>.<signature>", "expiresIn": 2592000 }
```

and send it onward as `Authorization: Bearer <assertion>`.

It is off by default deliberately: returning the session value in a response body is exactly what
`HttpOnly` exists to prevent, so it is appropriate only when the client polling is *not* a browser.
Leave it off for browser sign-ins and let the cookie do its job.

## The secret, and where this model stops working

Every verifier needs the auth service's `session.secret`. Anyone holding it can mint a session for
any user id, so it is a signing key, not a config value: environment variable or secret manager,
never the repo, and rotate it by rotating both sides together (every session is invalidated, and
everyone re-scans once).

Which is exactly why this model has a boundary. HMAC verification and HMAC forgery use the same
key, so **every app in the table above can also forge sessions for every other one**. Among apps
you control that is a shrug — you already trust yourself. Hand that secret to a third party and you
have handed them the ability to impersonate any of your users to any of your apps.

When apps you do not control need to sign users in, use
[`telegram-qr-auth/oidc`](../docs/oidc.md) instead: ES256 signatures, a published JWKS, and
per-client audiences, so a relying party can verify and never forge.
