// The consent screen.
//
// This is the one place the "zero user input" promise is deliberately broken, and it is worth
// being clear why. Among your own apps, consent is theatre: you already know the answer, and
// `first_party: true` skips it. The moment a third party can send users at your provider, skipping
// it means any client that talks someone into scanning a QR silently collects their identity —
// the user never learns which app asked or what it got. One tap is the honest price.
//
// It also happens to be the strongest anti-phishing control the flow has. The screen names the
// client and shows the callback host, so a user who scanned a QR expecting their own dashboard is
// told, before anything is issued, that "Totally Legit Analytics" is about to receive their
// identity.

import { escapeHtml } from "../login-page.js";

export const SCOPE_DESCRIPTIONS = {
  openid: "Confirm your identity",
  profile: "See your name and Telegram username",
  offline_access: "Stay signed in when you are not using the app",
};

/**
 * @param {object} params
 * @param {object} params.client       The registered client.
 * @param {string[]} params.scopes     Scopes being requested.
 * @param {object} params.session      The signed-in user's claims.
 * @param {string} params.requestId    Opaque id of the paused authorization request.
 * @param {string} params.csrfToken    Must come back with the form.
 * @param {string} params.actionPath   Where the form posts.
 * @param {object} [params.branding]
 */
export function renderConsentPage({ client, scopes, session, requestId, csrfToken, actionPath, branding = {} }) {
  const accent = branding.accent ?? "#6366f1";
  const callbackHost = hostOf(client.redirect_uris[0]);

  const scopeItems = scopes
    .map((scope) => {
      const description = SCOPE_DESCRIPTIONS[scope] ?? scope;
      return `<li><span class="tqa-scope">${escapeHtml(description)}</span><code>${escapeHtml(scope)}</code></li>`;
    })
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Authorize ${escapeHtml(client.client_name)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f1f5f9; padding: 24px; color: #1e293b;
  }
  .tqa-card { background: #fff; border-radius: 16px; padding: 28px; max-width: 420px; width: 100%;
    box-shadow: 0 10px 30px rgba(15,23,42,0.12); }
  h1 { font-size: 19px; margin: 0 0 4px; }
  .tqa-sub { color: #64748b; font-size: 13px; margin: 0 0 20px; line-height: 1.5; }
  .tqa-who { display: flex; align-items: center; gap: 10px; background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 10px; padding: 10px 12px; margin: 0 0 18px; font-size: 13px; }
  .tqa-who strong { font-weight: 600; }
  ul { list-style: none; padding: 0; margin: 0 0 20px; }
  li { display: flex; justify-content: space-between; align-items: center; gap: 12px;
    padding: 10px 0; border-bottom: 1px solid #f1f5f9; font-size: 14px; }
  li:last-child { border-bottom: none; }
  li code { color: #94a3b8; font-size: 11px; }
  .tqa-host { font-size: 12px; color: #64748b; margin: 0 0 20px; }
  .tqa-host code { color: #0f172a; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; }
  .tqa-actions { display: flex; gap: 10px; }
  button { flex: 1; border: none; border-radius: 8px; padding: 11px 16px; font-size: 14px;
    font-weight: 600; cursor: pointer; font-family: inherit; }
  .tqa-allow { background: ${accent}; color: #fff; }
  .tqa-deny { background: #e2e8f0; color: #334155; }
  .tqa-foot { margin: 18px 0 0; font-size: 11px; color: #94a3b8; line-height: 1.5; }
</style>
</head>
<body>
  <main class="tqa-card">
    <h1>${escapeHtml(client.client_name)} wants to sign you in</h1>
    <p class="tqa-sub">This app is not operated by us. Authorize it only if you started this sign-in yourself.</p>

    <div class="tqa-who">
      <span>Signed in as</span> <strong>${escapeHtml(session.name)}</strong>
    </div>

    <ul>${scopeItems}</ul>

    <p class="tqa-host">You will be returned to <code>${escapeHtml(callbackHost)}</code></p>

    <form method="POST" action="${escapeHtml(actionPath)}">
      <input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <div class="tqa-actions">
        <button class="tqa-deny" type="submit" name="decision" value="deny">Cancel</button>
        <button class="tqa-allow" type="submit" name="decision" value="allow">Authorize</button>
      </div>
    </form>

    <p class="tqa-foot">You can withdraw this at any time. Withdrawing also signs the app out.</p>
  </main>
</body>
</html>`;
}

/** A minimal error page for failures that must NOT be redirected back to the client. */
export function renderErrorPage(error, description) {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="robots" content="noindex, nofollow"><title>Sign-in error</title></head>
<body style="font-family: system-ui; max-width: 32rem; margin: 4rem auto; color: #1e293b;">
  <h1 style="font-size: 19px;">Sign-in could not continue</h1>
  <p style="color: #64748b; font-size: 14px;">${escapeHtml(description)}</p>
  <p style="color: #94a3b8; font-size: 12px;">Error code: <code>${escapeHtml(error)}</code></p>
  <p style="color: #94a3b8; font-size: 12px;">
    Nothing was shared with the application that sent you here. If you arrived from a link you did
    not expect, close this page.
  </p>
</body>
</html>`;
}

function hostOf(uri) {
  try {
    return new URL(uri).host;
  } catch {
    return uri;
  }
}
