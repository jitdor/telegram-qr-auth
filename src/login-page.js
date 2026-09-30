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
  subtitle: "Scan this QR code with the Telegram app on your phone, or click it to open Telegram on this computer. No phone number, no code to type.",
  mobileSubtitle: "Telegram opens. Tap Start at the bottom of the chat, then come back to this tab.",
  qrHintText: "Telegram installed on this computer? Click the code to open it.",
  qrLinkTitle: "Open Telegram to sign in",
  waitingText: "Waiting for scan…",
  successText: "Signed in — loading…",
  expiredText: "This QR code expired.",
  deniedText: "Your Telegram account isn't allowed to sign in here.",
  retryText: "Get a new QR code",
  mobileLinkText: "Open Telegram to sign in",
  accent: "#6366f1",
  gradientFrom: "#38bdf8",
  gradientTo: "#6366f1",
  qrDark: "#0f172a",
  qrLight: "#ffffff",
  logoHtml: "",
  footerHtml: "",
  headHtml: "",
};

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
  const appLink = params.appLink ?? appLinkFromDeepLink(deepLink);
  const errorHtml = error ? `<p class="tqa-error">${escapeHtml(error)}</p>` : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(branding.title)}</title>
${branding.headHtml}
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: linear-gradient(160deg, ${branding.gradientFrom} 0%, ${branding.gradientTo} 100%);
    padding: 24px;
  }
  .tqa-card {
    background: #fff; border-radius: 16px; padding: 32px 28px; max-width: 360px; width: 100%;
    text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.2);
  }
  .tqa-card h1 { font-size: 20px; margin: 0 0 6px; color: #1e293b; }
  .tqa-sub { color: #64748b; font-size: 13px; margin: 0 0 20px; line-height: 1.5; }
  .tqa-error {
    background: #fee2e2; color: #b91c1c; font-size: 13px; border-radius: 8px;
    padding: 10px 12px; margin: 0 0 18px;
  }
  .tqa-qr { display: flex; justify-content: center; margin: 0 0 14px; }
  .tqa-qr-link { display: block; border-radius: 8px; cursor: pointer; line-height: 0; }
  .tqa-qr-link:focus-visible, .tqa-open:focus-visible { outline: 3px solid ${branding.accent}; outline-offset: 3px; }
  .tqa-qr svg { width: 220px; height: 220px; }
  .tqa-hint { font-size: 12px; color: #94a3b8; margin: -4px 0 12px; line-height: 1.4; }
  .tqa-open {
    display: block; margin: 0 0 18px; padding: 14px 18px; border-radius: 10px; font-size: 16px;
    font-weight: 600; text-decoration: none; background: ${branding.accent}; color: #fff;
  }
  [hidden] { display: none !important; }
  /* Phones and tablets: scanning your own screen is impossible, so lead with the button. */
  .tqa-touch-only { display: none; }
  @media (hover: none) and (pointer: coarse) {
    .tqa-touch-only { display: block; }
    .tqa-pointer-only { display: none; }
  }
  .tqa-status { font-size: 12px; color: #94a3b8; margin: 0 0 16px; min-height: 16px; }
  .tqa-retry {
    border: none; border-radius: 8px; padding: 10px 18px; font-size: 14px; font-weight: 600;
    background: ${branding.accent}; color: #fff; cursor: pointer;
  }
  .tqa-foot { margin: 16px 0 0; font-size: 11px; color: #cbd5e1; }
</style>
</head>
<body>
  <main class="tqa-card">
    ${branding.logoHtml}
    <h1>${escapeHtml(branding.heading)}</h1>
    <p class="tqa-sub tqa-pointer-only">${escapeHtml(branding.subtitle)}</p>
    <p class="tqa-sub tqa-touch-only">${escapeHtml(branding.mobileSubtitle)}</p>
    ${errorHtml}
    <a class="tqa-open tqa-touch-only" id="tqa-open" href="${escapeHtml(appLink)}">${escapeHtml(branding.mobileLinkText)}</a>
    <div class="tqa-qr" id="tqa-qr"><a class="tqa-qr-link" href="${escapeHtml(appLink)}" title="${escapeHtml(branding.qrLinkTitle)}" aria-label="${escapeHtml(branding.qrLinkTitle)}">${qrSvg}</a></div>
    <p class="tqa-hint tqa-pointer-only" id="tqa-hint">${escapeHtml(branding.qrHintText)}</p>
    <p class="tqa-status" id="tqa-status">${escapeHtml(branding.waitingText)}</p>
    ${branding.footerHtml ? `<p class="tqa-foot">${branding.footerHtml}</p>` : ""}
  </main>
<script>
${pollScript({
  token,
  pollPath,
  redirectTo,
  pollIntervalMs,
  texts: { success: branding.successText, expired: branding.expiredText, denied: branding.deniedText, retry: branding.retryText },
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
