// The same flow with no Cloudflare anywhere: a plain Node server that serves the protected page,
// polls, and long-polls Telegram for updates itself. Run it and you can see the whole thing work
// on localhost in about a minute.
//
//   TELEGRAM_BOT_TOKEN=... TELEGRAM_BOT_USERNAME=your_bot ALLOWED_IDS=39644372 node server.mjs
//
// Both halves are in one process here, which is the one situation where MemoryLoginStore is the
// right call. Split them across processes and you need a shared store (D1, KV, Redis, Postgres —
// see "Writing a store" in the README).

import { createServer } from "node:http";
import { createTelegramQrAuth, MemoryLoginStore, allowlist, anyUser, TelegramClient, escapeHtml } from "telegram-qr-auth";
import { createStartHandler } from "telegram-qr-auth/bot";

const PORT = Number(process.env.PORT ?? 8787);
const { TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_USERNAME, ALLOWED_IDS } = process.env;

if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_BOT_USERNAME) {
  console.error("Set TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_USERNAME");
  process.exit(1);
}

const auth = createTelegramQrAuth({
  botToken: TELEGRAM_BOT_TOKEN,
  botUsername: TELEGRAM_BOT_USERNAME,
  store: new MemoryLoginStore(),
  namespace: "demo",
  authorize: ALLOWED_IDS ? allowlist(ALLOWED_IDS) : anyUser(),
  // localhost is plain HTTP, so the Secure attribute would stop the cookie from ever being set.
  // Never do this in production.
  session: { secret: process.env.SESSION_SECRET ?? "dev-only-secret", secure: false },
  branding: { heading: "Node demo", subtitle: "Scan with Telegram. Nothing to type." },
});

// ---- The web half -----------------------------------------------------------------------------

const server = createServer(async (req, res) => {
  const request = toWebRequest(req);
  const response = (await auth.handle(request)) ?? (await protectedPage(request));
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
});

async function protectedPage(request) {
  const gate = await auth.guard(request);
  if (!gate.ok) return gate.response;
  return new Response(
    `<h1>Signed in as ${escapeHtml(gate.session.name)}</h1><p>id ${gate.session.id}</p><p><a href="/auth/logout">Sign out</a></p>`,
    { headers: { "Content-Type": "text/html; charset=UTF-8" } }
  );
}

function toWebRequest(req) {
  return new Request(new URL(req.url, `http://localhost:${PORT}`), {
    method: req.method,
    headers: req.headers,
  });
}

// ---- The bot half -----------------------------------------------------------------------------
// Long polling instead of a webhook, because localhost has no public URL. In production use a
// webhook — see createWebhookHandler and the Cloudflare example.

const telegram = new TelegramClient(TELEGRAM_BOT_TOKEN);
const handleUpdate = createStartHandler(auth, { telegram });

async function pollTelegram() {
  let offset = 0;
  for (;;) {
    try {
      const res = await telegram.call("getUpdates", { offset, timeout: 30 });
      for (const update of res.result ?? []) {
        offset = update.update_id + 1;
        await handleUpdate(update);
      }
    } catch (err) {
      console.error("getUpdates failed", err);
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

server.listen(PORT, () => {
  console.log(`Open http://localhost:${PORT} and scan the QR with Telegram.`);
  pollTelegram();
});
