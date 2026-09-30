// The default sign-in page: a QR, a status line, and a way in for people who cannot scan.
//
// The QR image encodes the https t.me deep link, because that is what a phone camera can open.
// Clicking the QR (on a computer) and the "Open Telegram" button (on a phone or tablet) use the
// tg:// app link instead, which goes straight to the installed Telegram app rather than through a
// t.me web page, an "Open in Telegram?" prompt and a leftover browser tab. Opening an app link
// does not navigate this page away, so it stays put and keeps polling. No framework, no bundler,
// no external requests — it is one self-contained HTML string, which is what lets a consuming app
// be a single file with no build step.
//
// Replace it wholesale by passing `renderLoginPage` to createTelegramQrAuth; restyle it by passing
// `branding`. A replacement can reuse the polling script via `pollScript()` and supply only the
// markup — see POLL_STATUSES in provider.js for the contract it implements.

export const DEFAULT_BRANDING = {
  title: "Sign in",
  heading: "Sign in with Telegram",
  subtitle: "Scan the code with the Telegram app on your phone. No phone number, no code to type.",
  mobileSubtitle: "Telegram opens. Tap Start at the bottom of the chat, then come back to this tab.",
  orScanText: "or scan from another phone",
  qrHintText: "Telegram on this computer? Click the code.",
  qrLinkTitle: "Open Telegram to sign in",
  waitingText: "Waiting for Telegram…",
  successText: "Signed in. Loading…",
  expiredText: "This sign-in code expired.",
  deniedText: "Your Telegram account isn't allowed to sign in here.",
  retryText: "Get a new code",
  mobileLinkText: "Open Telegram",
  accent: "#2aabee",
  background: "#0e1a2f",
  gradientFrom: "#2aabee",
  gradientTo: "#8b5cf6",
  qrDark: "#0f172a",
  qrLight: "#ffffff",
  logoHtml: "",
  footerHtml: "",
  headHtml: "",
};

// Telegram's paper plane, drawn inline so the page makes no external requests.
const PLANE_ICON = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21.4 3.6 2.9 10.8c-1 .4-1 1.8.1 2.1l4.6 1.5 1.8 5.6c.3.9 1.4 1.1 2 .4l2.6-2.7 4.8 3.5c.8.6 1.9.1 2.1-.9l3-15.1c.2-1.1-.8-2-1.9-1.6Zm-3.6 4.1-8.5 7.6-.4 3.4-1.2-4 9.6-6.9c.4-.3.9.2.5.6Z"/></svg>`;

/**
 * @param {object} params
 * @param {string} params.token       The pending login token, handed to the polling script.
 * @param {string} params.deepLink    https://t.me/<bot>?start=<payload> — what the QR encodes.
 * @param {string} [params.appLink]   tg://resolve?domain=<bot>&start=<payload> — what the button
 *   and a click on the QR open. Derived from `deepLink` when omitted.
 * @param {string} params.qrSvg       Inline SVG markup from qr.js.
 * @param {string} [params.error]     Message to show above the QR (e.g. "you were removed").
 * @param {string} params.pollPath    Absolute path the page should poll.
 * @param {number} params.pollIntervalMs
 * @param {object} [params.branding]
 * @param {string} [params.redirectTo="/"]  Where to send the browser once signed in.
 */
export function renderLoginPage(params) {
  const branding = { ...DEFAULT_BRANDING, ...(params.branding ?? {}) };
  const { token, deepLink, qrSvg, error, pollPath, pollIntervalMs = 2000, redirectTo = "/" } = params;
  const appLink = escapeHtml(params.appLink ?? appLinkFromDeepLink(deepLink));
  const errorHtml = error ? `<p class="tqa-error" role="alert">${escapeHtml(error)}</p>` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(branding.title)}</title>
${branding.headHtml}
<style>
  :root {
    color-scheme: dark;
    --tqa-accent: ${branding.accent};
    --tqa-bg: ${branding.background};
    --tqa-glow-a: ${branding.gradientFrom};
    --tqa-glow-b: ${branding.gradientTo};
    --tqa-card: #fbfbfd;
    --tqa-ink: #111a2c;
    --tqa-muted: #5e6779;
    --tqa-rule: #e2e6ed;
    --tqa-font: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; }
  html, body { min-height: 100%; }
  body {
    margin: 0; min-height: 100vh; min-height: 100dvh; display: grid; place-items: center;
    padding: max(24px, env(safe-area-inset-top)) 16px max(24px, env(safe-area-inset-bottom));
    background: var(--tqa-bg); color: var(--tqa-ink);
    font: 16px/1.5 var(--tqa-font); -webkit-font-smoothing: antialiased;
  }
  /* Two soft glows in the brand colours, over a dark ground: colour without a loud gradient. */
  body::before {
    content: ""; position: fixed; inset: 0; pointer-events: none;
    background:
      radial-gradient(55% 60% at 88% 12%, color-mix(in srgb, var(--tqa-glow-a) 24%, transparent), transparent 70%),
      radial-gradient(50% 55% at 8% 96%, color-mix(in srgb, var(--tqa-glow-b) 22%, transparent), transparent 70%);
  }
  .tqa-card {
    position: relative; width: 100%; max-width: 23rem; background: var(--tqa-card); border-radius: 22px;
    padding: 28px 24px 22px; box-shadow: 0 30px 60px -24px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.06);
  }
  .tqa-head { text-align: center; padding-bottom: 20px; margin-bottom: 20px; border-bottom: 2px dashed var(--tqa-rule); }
  .tqa-head h1 { margin: 0; font-size: 1.4rem; line-height: 1.2; font-weight: 700; letter-spacing: -0.02em; }
  .tqa-sub { margin: 8px 0 0; color: var(--tqa-muted); font-size: 0.9rem; text-wrap: balance; }
  .tqa-error { margin: 0 0 16px; padding: 10px 14px; border-radius: 12px; background: #fdece7; color: #a42a17; font-size: 0.88rem; }
  .tqa-open, .tqa-retry {
    display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%;
    padding: 15px 20px; border: 0; border-radius: 999px; background: var(--tqa-accent); color: #fff;
    font: 600 1.05rem/1.2 var(--tqa-font); text-decoration: none; cursor: pointer;
    box-shadow: 0 8px 20px -10px color-mix(in srgb, var(--tqa-accent) 80%, transparent);
  }
  .tqa-open svg { width: 20px; height: 20px; fill: currentColor; flex: none; }
  .tqa-open:active, .tqa-retry:active { transform: scale(0.98); }
  .tqa-how { margin: 12px 0 0; color: var(--tqa-muted); font-size: 0.85rem; text-align: center; text-wrap: balance; }
  .tqa-or { align-items: center; gap: 12px; margin: 20px 0 14px; color: var(--tqa-muted); font-size: 0.8rem; }
  .tqa-or::before, .tqa-or::after { content: ""; flex: 1; height: 1px; background: var(--tqa-rule); }
  .tqa-qr { display: flex; justify-content: center; }
  .tqa-qr-link { display: block; line-height: 0; padding: 10px; border-radius: 16px; border: 1px solid var(--tqa-rule); background: #fff; transition: border-color 0.15s; }
  .tqa-qr-link:hover { border-color: var(--tqa-accent); }
  .tqa-qr svg { width: 13.5rem; max-width: 100%; height: auto; display: block; }
  .tqa-hint { margin: 12px 0 0; color: var(--tqa-muted); font-size: 0.82rem; text-align: center; }
  .tqa-status {
    display: flex; align-items: center; justify-content: center; gap: 8px; min-height: 1.3rem;
    margin: 16px 0 0; color: var(--tqa-muted); font-size: 0.85rem; text-align: center;
  }
  .tqa-status::before {
    content: ""; flex: none; width: 8px; height: 8px; border-radius: 50%;
    background: var(--tqa-accent); animation: tqa-pulse 1.6s ease-in-out infinite;
  }
  [data-tqa-state="signed-in"] .tqa-status::before { background: #1f9d63; animation: none; }
  [data-tqa-state="expired"] .tqa-status::before, [data-tqa-state="denied"] .tqa-status::before { background: #d23c26; animation: none; }
  @keyframes tqa-pulse { 50% { opacity: 0.25; } }
  .tqa-foot { margin: 16px 0 0; color: var(--tqa-muted); font-size: 0.75rem; text-align: center; }
  a:focus-visible, button:focus-visible { outline: 3px solid var(--tqa-accent); outline-offset: 3px; }
  [hidden] { display: none !important; }
  /* Phones and tablets can't scan their own screen: lead with the button, keep the QR for a second device. */
  .tqa-touch-only { display: none; }
  @media (hover: none) and (pointer: coarse) {
    .tqa-touch-only { display: block; }
    .tqa-open.tqa-touch-only, .tqa-or.tqa-touch-only { display: flex; }
    .tqa-pointer-only { display: none; }
    .tqa-qr svg { width: 10.5rem; }
  }
  @media (prefers-reduced-motion: reduce) {
    .tqa-status::before { animation: none; }
    .tqa-open:active, .tqa-retry:active { transform: none; }
  }
</style>
</head>
<body>
  <main class="tqa-card">
    <header class="tqa-head">
      ${branding.logoHtml}
      <h1>${escapeHtml(branding.heading)}</h1>
      <p class="tqa-sub tqa-pointer-only">${escapeHtml(branding.subtitle)}</p>
    </header>
    ${errorHtml}
    <a class="tqa-open tqa-touch-only" id="tqa-open" href="${appLink}">${PLANE_ICON}<span>${escapeHtml(branding.mobileLinkText)}</span></a>
    <p class="tqa-how tqa-touch-only" id="tqa-how">${escapeHtml(branding.mobileSubtitle)}</p>
    <p class="tqa-or tqa-touch-only" id="tqa-or">${escapeHtml(branding.orScanText)}</p>
    <div class="tqa-qr" id="tqa-qr"><a class="tqa-qr-link" href="${appLink}" title="${escapeHtml(branding.qrLinkTitle)}" aria-label="${escapeHtml(branding.qrLinkTitle)}">${qrSvg}</a></div>
    <p class="tqa-hint tqa-pointer-only" id="tqa-hint">${escapeHtml(branding.qrHintText)}</p>
    <p class="tqa-status" id="tqa-status" role="status">${escapeHtml(branding.waitingText)}</p>
    ${branding.footerHtml ? `<p class="tqa-foot">${branding.footerHtml}</p>` : ""}
  </main>
<script>
${pollScript({
  token,
  pollPath,
  redirectTo,
  pollIntervalMs,
  texts: { success: branding.successText, expired: branding.expiredText, denied: branding.deniedText, retry: branding.retryText },
  ids: { status: "tqa-status", qr: "tqa-qr", hide: ["tqa-open", "tqa-how", "tqa-or", "tqa-hint"] },
})}
</script>
</body>
</html>`;
}

/**
 * The tg:// app link for a t.me deep link: `https://t.me/<bot>?start=<payload>` becomes
 * `tg://resolve?domain=<bot>&start=<payload>`. Anything else is returned unchanged.
 */
export function appLinkFromDeepLink(deepLink) {
  let url;
  try {
    url = new URL(deepLink);
  } catch {
    return deepLink;
  }
  const domain = url.pathname.replace(/^\/+|\/+$/g, "");
  if (url.protocol !== "https:" || url.hostname !== "t.me" || !/^[A-Za-z0-9_]+$/.test(domain)) return deepLink;
  const start = url.searchParams.get("start");
  return `tg://resolve?domain=${domain}${start ? `&start=${encodeURIComponent(start)}` : ""}`;
}

export const DEFAULT_POLL_TEXTS = {
  success: DEFAULT_BRANDING.successText,
  expired: DEFAULT_BRANDING.expiredText,
  denied: DEFAULT_BRANDING.deniedText,
  retry: DEFAULT_BRANDING.retryText,
};

export const DEFAULT_POLL_IDS = {
  status: "tqa-status",
  qr: "tqa-qr",
  hide: ["tqa-open", "tqa-hint"],
};

/**
 * The sign-in page's polling script, as JavaScript source for a custom page to put in a
 * `<script>` element (add a CSP nonce there if you use one). It handles all of POLL_STATUSES, so a
 * custom page only supplies markup:
 *
 * - `ids.status`: element whose text shows progress. Optional.
 * - `ids.qr`: element whose contents are replaced by a "new QR code" button on expiry. Optional.
 * - `ids.hide`: elements hidden once the sign-in is over (links that would open a dead token).
 *
 * It also sets `data-tqa-state` on `<html>` to "waiting", "signed-in", "expired" or "denied", so a
 * page can style a status indicator in CSS alone.
 *
 * @param {object} params
 * @param {string} params.token
 * @param {string} params.pollPath
 * @param {string} [params.redirectTo="/"]
 * @param {number} [params.pollIntervalMs=2000]
 * @param {object} [params.texts]  `{ success, expired, denied, retry }`; see DEFAULT_POLL_TEXTS.
 * @param {object} [params.ids]    `{ status, qr, hide }`; see DEFAULT_POLL_IDS.
 */
export function pollScript({ token, pollPath, redirectTo = "/", pollIntervalMs = 2000, texts, ids } = {}) {
  const interval = Math.max(250, Number(pollIntervalMs) || 2000);
  const config = {
    token,
    pollPath,
    redirectTo,
    interval,
    texts: { ...DEFAULT_POLL_TEXTS, ...(texts ?? {}) },
    ids: { ...DEFAULT_POLL_IDS, ...(ids ?? {}) },
  };
  return `(function () {
  var cfg = ${scriptJson(config)};
  var text = cfg.texts;
  var statusEl = cfg.ids.status ? document.getElementById(cfg.ids.status) : null;
  var qrEl = cfg.ids.qr ? document.getElementById(cfg.ids.qr) : null;
  var root = document.documentElement;
  var stopped = false;
  var inFlight = false;
  var timer = null;

  function setState(state, message) {
    root.setAttribute("data-tqa-state", state);
    if (statusEl && message) statusEl.textContent = message;
  }

  // Once the sign-in is over (expired, denied) the links would open a dead or refused token.
  function hideOpenLinks() {
    (cfg.ids.hide || []).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.hidden = true;
    });
  }

  function stop() {
    stopped = true;
    clearTimeout(timer);
    timer = null;
  }

  function showExpired() {
    stop();
    hideOpenLinks();
    setState("expired", text.expired);
    if (!qrEl) return;
    // Replacing the QR with the button rather than leaving a dead QR on screen: a stale QR that
    // still looks scannable is the single most confusing state this page can be in.
    qrEl.textContent = "";
    var button = document.createElement("button");
    button.type = "button";
    button.className = "tqa-retry";
    button.textContent = text.retry;
    button.addEventListener("click", function () { window.location.reload(); });
    qrEl.appendChild(button);
  }

  // One loop only: every path into poll() goes through here, and a poll already on the wire is
  // never doubled up by a timer or a visibility change.
  function schedule(delay) {
    clearTimeout(timer);
    timer = stopped ? null : setTimeout(poll, delay);
  }

  function poll() {
    clearTimeout(timer);
    timer = null;
    if (stopped || inFlight) return;
    inFlight = true;
    fetch(cfg.pollPath + "?token=" + encodeURIComponent(cfg.token), { credentials: "same-origin", cache: "no-store" })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        inFlight = false;
        var status = data && data.status;
        if (status === "confirmed") {
          stop();
          setState("signed-in", text.success);
          // Full navigation, not a fetch: the session cookie arrived on the poll response and the
          // app needs a fresh document request to render as the signed-in user.
          window.location.href = cfg.redirectTo;
          return;
        }
        if (status === "expired" || status === "invalid") { showExpired(); return; }
        if (status === "denied") {
          stop();
          hideOpenLinks();
          // data.reason is a machine code for logs and gates, not copy for a person to read.
          setState("denied", text.denied);
          return;
        }
        schedule(cfg.interval);
      })
      // A failed poll is usually a blip (sleeping laptop, flaky tunnel), so back off rather than
      // giving up — the token's own TTL is what ends this loop.
      .catch(function () {
        inFlight = false;
        schedule(cfg.interval + 1000);
      });
  }

  // Background tabs have their timers throttled, so coming back from Telegram could mean a long
  // wait for the next poll. Poll the moment the tab is visible again instead.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible" && !stopped && !inFlight) poll();
  });

  root.setAttribute("data-tqa-state", "waiting");
  schedule(cfg.interval);
})();`;
}

/** JSON that is safe inside a <script> element: no "</script>", no HTML comment openers. */
function scriptJson(value) {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
