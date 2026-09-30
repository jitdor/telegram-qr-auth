// The default sign-in page: a QR, a status line, and a tap-through link for people already on
// their phone. No framework, no bundler, no external requests — it is one self-contained HTML
// string, which is what lets a consuming app be a single file with no build step.
//
// Replace it wholesale by passing `renderLoginPage` to createTelegramQrAuth; restyle it by passing
// `branding`. The one thing a replacement must keep is the polling script's contract with
// `/auth/poll` — see POLL_STATUSES in provider.js.

export const DEFAULT_BRANDING = {
  title: "Sign in",
  heading: "Sign in with Telegram",
  subtitle: "Scan this QR code with the Telegram app on your phone. No phone number, no code to type.",
  waitingText: "Waiting for scan…",
  successText: "Signed in — loading…",
  expiredText: "This QR code expired.",
  deniedText: "Your Telegram account isn't allowed to sign in here.",
  retryText: "Get a new QR code",
  mobileLinkText: "On this phone? Tap here to open Telegram instead",
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
 * @param {string} params.deepLink    https://t.me/<bot>?start=<payload>
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
  .tqa-qr svg { width: 220px; height: 220px; }
  .tqa-status { font-size: 12px; color: #94a3b8; margin: 0 0 16px; min-height: 16px; }
  .tqa-retry {
    border: none; border-radius: 8px; padding: 10px 18px; font-size: 14px; font-weight: 600;
    background: ${branding.accent}; color: #fff; cursor: pointer;
  }
  .tqa-link { font-size: 12px; color: ${branding.accent}; text-decoration: none; }
  .tqa-foot { margin: 16px 0 0; font-size: 11px; color: #cbd5e1; }
</style>
</head>
<body>
  <main class="tqa-card">
    ${branding.logoHtml}
    <h1>${escapeHtml(branding.heading)}</h1>
    <p class="tqa-sub">${escapeHtml(branding.subtitle)}</p>
    ${errorHtml}
    <div class="tqa-qr" id="tqa-qr">${qrSvg}</div>
    <p class="tqa-status" id="tqa-status">${escapeHtml(branding.waitingText)}</p>
    <a class="tqa-link" href="${escapeHtml(deepLink)}">${escapeHtml(branding.mobileLinkText)}</a>
    ${branding.footerHtml ? `<p class="tqa-foot">${branding.footerHtml}</p>` : ""}
  </main>
<script>
(function () {
  var token = ${JSON.stringify(token)};
  var pollPath = ${JSON.stringify(pollPath)};
  var redirectTo = ${JSON.stringify(redirectTo)};
  var text = ${JSON.stringify({
    success: branding.successText,
    expired: branding.expiredText,
    denied: branding.deniedText,
    retry: branding.retryText,
  })};
  var statusEl = document.getElementById("tqa-status");
  var qrEl = document.getElementById("tqa-qr");
  var stopped = false;

  function showExpired() {
    stopped = true;
    statusEl.textContent = text.expired;
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

  function poll() {
    if (stopped) return;
    fetch(pollPath + "?token=" + encodeURIComponent(token), { credentials: "same-origin" })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        var status = data && data.status;
        if (status === "confirmed") {
          stopped = true;
          statusEl.textContent = text.success;
          // Full navigation, not a fetch: the session cookie arrived on the poll response and the
          // app needs a fresh document request to render as the signed-in user.
          window.location.href = redirectTo;
          return;
        }
        if (status === "expired" || status === "invalid") { showExpired(); return; }
        if (status === "denied") {
          stopped = true;
          // data.reason is a machine code for logs and gates, not copy for a person to read.
          statusEl.textContent = text.denied;
          return;
        }
        setTimeout(poll, ${Number(pollIntervalMs)});
      })
      // A failed poll is usually a blip (sleeping laptop, flaky tunnel), so back off rather than
      // giving up — the token's own TTL is what ends this loop.
      .catch(function () { setTimeout(poll, ${Number(pollIntervalMs) + 1000}); });
  }
  setTimeout(poll, ${Number(pollIntervalMs)});
})();
</script>
</body>
</html>`;
}

export function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
