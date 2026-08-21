// A console app that signs a human in with a QR code and nothing else.
//
//   dotnet run --project examples/csharp -- https://auth.example.com
//
// The auth service must have `allowAssertions: true` (see TelegramQrAuth.cs for why that is off by
// default). For an ASP.NET app you usually want only the *verifier* half — skip to
// AspNetIntegration at the bottom of this file.

using System;
using System.Threading;
using System.Threading.Tasks;
using TelegramQrAuth;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        // Prove the crypto port is right before trusting anything it says.
        Console.WriteLine(TelegramQrAuthVerifier.SelfTest()
            ? "verifier self-test: ok"
            : "verifier self-test: FAILED — do not ship this");

        var authBase = new Uri(args.Length > 0 ? args[0] : "https://auth.example.com");
        var client = new TelegramQrAuthClient(authBase);

        var challenge = await client.BeginAsync();

        Console.WriteLine();
        Console.WriteLine("Scan this with Telegram, or open it on this device:");
        Console.WriteLine("  " + challenge.DeepLink);
        Console.WriteLine($"  (expires in {challenge.ExpiresIn}s)");
        Console.WriteLine();

        // The service already rendered a QR as SVG in challenge.Svg — write it to a file, or hand
        // it to whatever UI you have. For a terminal, a package like QRCoder or Net.Codecrete.QrCodeGenerator
        // will draw the DeepLink as ASCII blocks; the deep link is all any QR renderer needs, and
        // nothing about it is secret until it is displayed.
        Console.WriteLine("Waiting for scan… (Ctrl+C to give up)");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(challenge.ExpiresIn + 5));
        var result = await client.WaitForScanAsync(challenge.Token, ct: cts.Token);

        switch (result.Outcome)
        {
            case SignInOutcome.Confirmed:
                Console.WriteLine($"Signed in as {result.Session?.Name} (id {result.Session?.Id}).");
                Console.WriteLine($"Session valid until {result.Session?.ExpiresAt:u}.");
                // Store result.Assertion the way you'd store any credential — the OS keychain,
                // DPAPI, libsecret. It is a bearer token: whoever holds it is the user until it
                // expires. Not a plain text file next to the binary.
                Console.WriteLine("Send it onward as: Authorization: Bearer <assertion>");
                return 0;

            case SignInOutcome.Denied:
                Console.WriteLine($"That Telegram account isn't allowed in ({result.Reason}).");
                return 1;

            case SignInOutcome.Expired:
                Console.WriteLine("The QR expired before it was scanned. Run again for a fresh one.");
                return 1;

            default:
                Console.WriteLine($"Sign-in failed: {result.Reason ?? "invalid"}.");
                return 1;
        }
    }
}

/*
-- ASP.NET Core: the verifier as middleware -------------------------------------------------------

Nothing here calls the auth service. It verifies the signature the service produced, which is why
it costs no round trip and no availability dependency.

    var verifier = new TelegramQrAuthVerifier(builder.Configuration["TelegramQrAuth:Secret"]!);
    builder.Services.AddSingleton(verifier);

    app.Use(async (context, next) =>
    {
        // Bearer for API clients (the console app above), cookie for browsers when the auth
        // service shares a registrable domain with this app and sets Domain=.example.com.
        var value = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(value))
            context.Request.Cookies.TryGetValue("myapp_session", out value);

        var session = verifier.Verify(value);
        if (session is null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;                    // or: redirect to https://auth.example.com/auth/login
        }

        context.Items["TelegramUser"] = session;
        await next();
    });

One thing to be deliberate about: verifying locally means this app cannot see a revocation. The
auth service re-checks Telegram group membership on every request it serves; this app checks a
signature. Close the gap by shortening the session on the service (`maxAgeSeconds: 3600`), or by
checking session.Id against your own revocation list here.
*/
