// telegram-qr-auth — C# client and verifier.
//
// Two independent pieces, and which one you want depends on what the C# is:
//
//   TelegramQrAuthClient    A *client*: a desktop app, CLI or service that signs a human in. It
//                           asks the auth service for a deep link, shows it as a QR, polls until
//                           the human scans, and receives a bearer assertion. No cookie jar needed.
//
//   TelegramQrAuthVerifier  A *verifier*: an ASP.NET backend that receives an assertion (or the
//                           shared-domain cookie) and checks the signature locally. Two HMAC calls,
//                           no round trip, no dependency.
//
// Neither runs the JavaScript package. That runs once, as a Worker, at https://auth.example.com.
//
// Target: .NET 6+ (uses System.Text.Json and HttpClient). No NuGet packages required for either
// class; the QR *rendering* in the sample app below is the one place you may want one.

using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace TelegramQrAuth
{
    /// <summary>Claims carried by a verified session.</summary>
    public sealed class TelegramQrSession
    {
        [JsonPropertyName("id")] public long Id { get; set; }
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("username")] public string? Username { get; set; }
        [JsonPropertyName("exp")] public long Exp { get; set; }

        public DateTimeOffset ExpiresAt => DateTimeOffset.FromUnixTimeSeconds(Exp);
    }

    /// <summary>What the auth service hands back when a sign-in starts.</summary>
    public sealed class TelegramQrChallenge
    {
        [JsonPropertyName("token")] public string Token { get; set; } = "";
        [JsonPropertyName("deepLink")] public string DeepLink { get; set; } = "";
        [JsonPropertyName("svg")] public string Svg { get; set; } = "";
        [JsonPropertyName("expiresIn")] public int ExpiresIn { get; set; }
    }

    public enum SignInOutcome { Confirmed, Denied, Expired, Invalid }

    public sealed class SignInResult
    {
        public SignInOutcome Outcome { get; init; }
        public string? Assertion { get; init; }
        public TelegramQrSession? Session { get; init; }
        public string? Reason { get; init; }
        public bool Succeeded => Outcome == SignInOutcome.Confirmed;
    }

    /// <summary>
    /// Drives a sign-in from a client with no browser and no cookie jar.
    ///
    /// The auth service must be configured with <c>allowAssertions: true</c>, which is off by
    /// default — it hands the signed session value back in the response body rather than as an
    /// HttpOnly cookie, and that is only appropriate for non-browser clients like this one.
    /// </summary>
    public sealed class TelegramQrAuthClient
    {
        private readonly HttpClient _http;
        private readonly Uri _authBase;

        public TelegramQrAuthClient(Uri authBase, HttpClient? http = null)
        {
            _authBase = authBase;
            _http = http ?? new HttpClient();
        }

        /// <summary>Asks for a fresh challenge: a deep link to display, and a token to poll on.</summary>
        public async Task<TelegramQrChallenge> BeginAsync(CancellationToken ct = default)
        {
            var challenge = await _http.GetFromJsonAsync<TelegramQrChallenge>(
                new Uri(_authBase, "/auth/qr"), ct).ConfigureAwait(false);

            if (challenge is null || string.IsNullOrEmpty(challenge.Token))
                throw new InvalidOperationException("Auth service returned no challenge.");

            return challenge;
        }

        /// <summary>
        /// Polls until the user scans, the token expires, or <paramref name="ct"/> is cancelled.
        /// Returns the outcome; on success, <c>Assertion</c> is the value to store and send back as
        /// <c>Authorization: Bearer</c>.
        /// </summary>
        public async Task<SignInResult> WaitForScanAsync(
            string token,
            TimeSpan? pollInterval = null,
            CancellationToken ct = default)
        {
            var interval = pollInterval ?? TimeSpan.FromSeconds(2);
            var pollUri = new Uri(_authBase, $"/auth/poll?token={Uri.EscapeDataString(token)}&mode=token");

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                using var response = await _http.GetAsync(pollUri, ct).ConfigureAwait(false);
                var body = await response.Content.ReadFromJsonAsync<PollResponse>(cancellationToken: ct)
                    .ConfigureAwait(false);

                switch (body?.Status)
                {
                    case "confirmed":
                        return new SignInResult
                        {
                            Outcome = SignInOutcome.Confirmed,
                            Assertion = body.Assertion,
                            // Claims are readable without the secret — they are signed, not
                            // encrypted. Read them for display; never *trust* them client-side.
                            Session = TelegramQrAuthVerifier.ReadUnverifiedClaims(body.Assertion),
                        };

                    case "denied":
                        return new SignInResult { Outcome = SignInOutcome.Denied, Reason = body.Reason };

                    case "expired":
                        return new SignInResult { Outcome = SignInOutcome.Expired };

                    case "invalid":
                        // Also what you get if the service does not have allowAssertions turned on.
                        return new SignInResult { Outcome = SignInOutcome.Invalid, Reason = body.Error };

                    default:
                        // "pending" — the QR is on screen and nobody has scanned it yet.
                        await Task.Delay(interval, ct).ConfigureAwait(false);
                        break;
                }
            }
        }

        private sealed class PollResponse
        {
            [JsonPropertyName("status")] public string? Status { get; set; }
            [JsonPropertyName("assertion")] public string? Assertion { get; set; }
            [JsonPropertyName("reason")] public string? Reason { get; set; }
            [JsonPropertyName("error")] public string? Error { get; set; }
        }
    }

    /// <summary>
    /// Verifies a signed session value locally. This is the whole server-side integration for an
    /// ASP.NET app: no HTTP call, no SDK, two HMACs.
    ///
    /// Format: <c>&lt;payloadB64&gt;.&lt;signature&gt;</c> where
    ///   key       = HMAC-SHA256(key: keyLabel, message: secret)      -> 32 raw bytes
    ///   signature = HMAC-SHA256(key: key,      message: payloadB64)  -> lowercase hex
    /// and payloadB64 is unpadded base64url of the claims JSON.
    /// </summary>
    public sealed class TelegramQrAuthVerifier
    {
        public const string DefaultKeyLabel = "TelegramQrAuthSessionKey";

        private readonly byte[] _key;

        /// <param name="secret">The auth service's <c>session.secret</c>. Same value, both sides.</param>
        /// <param name="keyLabel">Must match the service's <c>session.keyLabel</c>.</param>
        public TelegramQrAuthVerifier(string secret, string keyLabel = DefaultKeyLabel)
        {
            if (string.IsNullOrEmpty(secret)) throw new ArgumentException("secret is required", nameof(secret));

            // Domain separation: the label is the key and the secret is the message, so a signature
            // made under a different label cannot verify here.
            using var derive = new HMACSHA256(Encoding.UTF8.GetBytes(keyLabel));
            _key = derive.ComputeHash(Encoding.UTF8.GetBytes(secret));
        }

        /// <summary>
        /// Returns the claims if the value is validly signed and unexpired, otherwise null.
        /// Accepts a bare value or one prefixed with "Bearer ".
        /// </summary>
        public TelegramQrSession? Verify(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;

            if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                value = value.Substring(7).Trim();

            var dot = value.IndexOf('.');
            if (dot <= 0 || dot == value.Length - 1) return null;

            var payloadB64 = value.Substring(0, dot);
            var signature = value.Substring(dot + 1);

            // Sign the *encoded* payload, never the decoded JSON — re-serializing would change the
            // bytes and the signature would never match.
            using var hmac = new HMACSHA256(_key);
            var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadB64))).ToLowerInvariant();

            // Constant-time: FixedTimeEquals, not string ==.
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(signature)))
            {
                return null;
            }

            var claims = ReadUnverifiedClaims(value);
            if (claims is null || claims.Id == 0) return null;

            // The signature alone never expires. Skipping this check builds a permanent credential.
            if (claims.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;

            return claims;
        }

        /// <summary>
        /// Decodes the claims WITHOUT checking the signature. Safe for showing a name in a UI;
        /// never for an access decision. Anyone can write whatever they like into this half.
        /// </summary>
        public static TelegramQrSession? ReadUnverifiedClaims(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            var dot = value.IndexOf('.');
            var payloadB64 = dot > 0 ? value.Substring(0, dot) : value;

            try
            {
                return JsonSerializer.Deserialize<TelegramQrSession>(Base64UrlDecode(payloadB64));
            }
            catch (Exception ex) when (ex is JsonException or FormatException)
            {
                return null;
            }
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
                case 1: throw new FormatException("Invalid base64url length.");
            }
            return Convert.FromBase64String(s);
        }

        /// <summary>
        /// Known-answer test, matching tests/assertions.test.mjs in the package (and independently
        /// reproduced with Python). If this returns true, the port is correct.
        /// </summary>
        public static bool SelfTest()
        {
            const string secret = "123456:AAHfake-bot-token";
            const string value =
                "eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9" +
                ".ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95";

            var good = new TelegramQrAuthVerifier(secret).Verify(value);
            var bad = new TelegramQrAuthVerifier("wrong-secret").Verify(value);

            return good is { Id: 39644372, Name: "Alice Ng" } && bad is null;
        }
    }
}
