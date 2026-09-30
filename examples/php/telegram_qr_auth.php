<?php
/**
 * telegram-qr-auth — PHP verifier.
 *
 * PHP cannot run the package (it is JavaScript), and it does not need to. The package's *web half*
 * runs once as a small Worker at, say, https://auth.example.com; PHP never mints tokens, never
 * renders a QR, and never talks to Telegram. All it does is verify the signed session value that
 * Worker issued — which is two HMAC-SHA-256 calls, both in PHP's standard library, no Composer
 * package required.
 *
 * The value format:
 *
 *     <payloadB64>.<signature>
 *
 *     payloadB64 = unpadded base64url of the claims JSON, e.g. {"id":123,"name":"Alice","exp":...}
 *     key        = hash_hmac('sha256', message: $secret,     key: $keyLabel)   raw 32 bytes
 *     signature  = hash_hmac('sha256', message: $payloadB64, key: $key)        lowercase hex
 *
 * Note the argument order: PHP's hash_hmac() takes ($algo, $data, $key), so the secret is the
 * *data* in the first call and the derived key is the *key* in the second. Getting these the wrong
 * way round is the single most likely porting mistake — check yourself against TQA_TEST_VECTOR at
 * the bottom of this file before debugging anything else.
 *
 * Requires PHP 5.6+ (for hash_equals). No extensions beyond the
 * always-available hash and json.
 */

declare(strict_types=1);

/** Must match `session.keyLabel` on the Worker. Do not change it without changing both sides. */
const TQA_KEY_LABEL = 'TelegramQrAuthSessionKey';

/**
 * Verifies a signed session value.
 *
 * @param string|null $value    The cookie value or bearer assertion.
 * @param string      $secret   The Worker's `session.secret`. Same value, both sides.
 * @param string      $keyLabel Must match the Worker's `session.keyLabel`.
 * @return array|null           The claims (id, name, username, exp), or null if it does not verify.
 */
function tqa_verify(?string $value, string $secret, string $keyLabel = TQA_KEY_LABEL): ?array
{
    if ($value === null || $value === '') {
        return null;
    }

    $parts = explode('.', $value);
    if (count($parts) !== 2) {
        return null;
    }
    [$payloadB64, $signature] = $parts;

    // Step 1: derive the signing key. The label is the HMAC key and the secret is the message —
    // this is domain separation, so a signature made with a different label is worthless here.
    $key = hash_hmac('sha256', $secret, $keyLabel, true);

    // Step 2: recompute the signature over the *encoded* payload, never the decoded JSON.
    $expected = hash_hmac('sha256', $payloadB64, $key, false);

    // Constant-time compare. A plain === here leaks the signature one byte at a time to anyone
    // willing to time the responses.
    if (!hash_equals($expected, $signature)) {
        return null;
    }

    $claims = json_decode(tqa_base64url_decode($payloadB64), true);
    if (!is_array($claims) || !isset($claims['id'], $claims['exp'])) {
        return null;
    }

    // The signature never expires on its own — `exp` is the only thing that ends a session, so
    // skipping this check turns every assertion into a permanent credential.
    if (!is_numeric($claims['exp']) || (int) $claims['exp'] < time()) {
        return null;
    }

    return $claims;
}

/** The package strips base64 padding and uses the URL-safe alphabet; restore both before decoding. */
function tqa_base64url_decode(string $input): string
{
    $padded = strtr($input, '-_', '+/');
    $remainder = strlen($padded) % 4;
    if ($remainder !== 0) {
        $padded .= str_repeat('=', 4 - $remainder);
    }
    return (string) base64_decode($padded, true);
}

/**
 * Reads the session from the incoming request: cookie first, then an Authorization: Bearer header
 * for service-to-service calls.
 */
function tqa_session_from_request(string $secret, string $cookieName = 'myapp_session'): ?array
{
    if (isset($_COOKIE[$cookieName])) {
        $claims = tqa_verify($_COOKIE[$cookieName], $secret);
        if ($claims !== null) {
            return $claims;
        }
    }

    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (stripos($header, 'Bearer ') === 0) {
        return tqa_verify(substr($header, 7), $secret);
    }

    return null;
}

/**
 * Sends a signed-out visitor to the auth service, which shows the QR and comes back here.
 *
 * IMPORTANT: the Worker only honours a `redirectTo` you configured on it, or a same-origin path.
 * Never build this from user input — an open redirect on a sign-in endpoint hands your sessions to
 * whoever asks.
 */
function tqa_require_session(string $secret, string $authBase, string $cookieName = 'myapp_session'): array
{
    $claims = tqa_session_from_request($secret, $cookieName);
    if ($claims !== null) {
        return $claims;
    }
    header('Location: ' . rtrim($authBase, '/') . '/auth/login', true, 302);
    exit;
}

/**
 * Known-answer vector, reproduced from the package's own tests (tests/assertions.test.mjs) and
 * independently with Python. If tqa_verify() accepts this, the port is correct.
 *
 *   php -r 'require "telegram_qr_auth.php"; var_dump(tqa_selftest());'
 */
const TQA_TEST_VECTOR = [
    'secret' => '123456:AAHfake-bot-token',
    'value'  => 'eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9'
              . '.ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95',
];

function tqa_selftest(): bool
{
    $claims = tqa_verify(TQA_TEST_VECTOR['value'], TQA_TEST_VECTOR['secret']);
    // exp is in 2100, so this stays valid; if it ever starts failing, check the clock before the code.
    return $claims !== null
        && $claims['id'] === 39644372
        && $claims['name'] === 'Alice Ng'
        && tqa_verify(TQA_TEST_VECTOR['value'], 'wrong-secret') === null;
}
