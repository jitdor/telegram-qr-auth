<?php
/**
 * A protected PHP page.
 *
 * Deployment shape this assumes:
 *
 *   auth.example.com   the Worker running telegram-qr-auth (mints tokens, shows the QR, polls)
 *   app.example.com    this PHP app (verifies only)
 *
 * Both under one registrable domain, and the Worker configured with:
 *
 *   session: {
 *     secret:     env.SESSION_SECRET,     // the same secret this file reads
 *     cookieName: "myapp_session",
 *     domain:     ".example.com",         // <- what lets app.example.com see the cookie
 *   },
 *   redirectTo: "https://app.example.com/",
 *
 * If the two are NOT under a shared parent domain, a cookie cannot reach PHP at all. Use the
 * bearer path instead: enable `allowAssertions: true` on the Worker, have your front end poll
 * `/auth/poll?token=...&mode=token`, and send the returned assertion to PHP as
 * `Authorization: Bearer <assertion>` — tqa_session_from_request() already accepts that.
 */

declare(strict_types=1);

require __DIR__ . '/telegram_qr_auth.php';

// Same value as the Worker's `session.secret`. Keep it out of the document root and out of git —
// an env var, or a file above the web root. Anyone with this can mint sessions for any user.
$secret   = getenv('TELEGRAM_QR_AUTH_SECRET') ?: '';
$authBase = getenv('TELEGRAM_QR_AUTH_URL') ?: 'https://auth.example.com';

if ($secret === '') {
    http_response_code(500);
    exit('TELEGRAM_QR_AUTH_SECRET is not set.');
}

// Redirects to the QR page if there is no valid session; returns the claims if there is.
$user = tqa_require_session($secret, $authBase, 'myapp_session');

// -------------------------------------------------------------------------------------------------
// Everything below here runs only for a signed-in visitor.
//
// One caveat worth understanding: PHP is verifying a *signature*, which means it learns who the
// user is without asking Telegram anything — fast, but it cannot see a revocation. The Worker
// re-checks group membership live on every request it serves; PHP does not. Options, in order of
// how much work they are:
//
//   1. Shorten the session: `session: { maxAgeSeconds: 3600 }` on the Worker. Revocation then takes
//      effect within an hour, and the user re-scans. Usually enough.
//   2. Have PHP call the Worker for anything sensitive and let the Worker be the one that checks.
//   3. Keep a small local table of revoked user ids and check $user['id'] against it here.
// -------------------------------------------------------------------------------------------------

$name = htmlspecialchars((string) $user['name'], ENT_QUOTES, 'UTF-8');
$id   = (int) $user['id'];
$until = date('c', (int) $user['exp']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Protected PHP page</title>
</head>
<body style="font-family: system-ui; max-width: 40rem; margin: 4rem auto;">
  <h1>Signed in as <?= $name ?></h1>
  <p>Telegram user id: <code><?= $id ?></code></p>
  <p>Session valid until <?= htmlspecialchars($until, ENT_QUOTES, 'UTF-8') ?>.</p>
  <p>They never typed anything — one QR scan, verified here with two HMAC calls and no round trip.</p>
  <p><a href="<?= htmlspecialchars(rtrim($authBase, '/') . '/auth/logout', ENT_QUOTES, 'UTF-8') ?>">Sign out</a></p>
</body>
</html>
