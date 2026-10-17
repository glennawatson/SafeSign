// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Refit.Testing;
using SafeSign.Providers.Certum;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Tests;

/// <summary>Verifies <see cref="CertumTotp"/>, <see cref="CertumMultipart"/>, <see cref="CertumRequests"/>, and <see cref="CertumSimplySignProvider"/> using <see cref="StubHttp"/>.</summary>
public sealed class CertumSimplySignTests
{
    /// <summary>The RSA key size for the synthetic SimplySign certificate.</summary>
    private const int RsaKeySize = 2048;

    /// <summary>The expected TOTP digit count.</summary>
    private const int ExpectedTotpDigits = 6;

    /// <summary>The expected TOTP step period in seconds.</summary>
    private const int ExpectedTotpPeriodSeconds = 30;

    /// <summary>The RFC 6238 test timestamp (59 seconds after Unix epoch).</summary>
    private const long Rfc6238TestSeconds = 59L;

    /// <summary>The RFC 6238 SHA-256 32-byte ASCII test secret encoded in Base32.</summary>
    private const string Rfc6238Sha256Base32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";

    /// <summary>The CAS OAuth 2.0 authorize route path.</summary>
    private const string AuthorizeRoute = "/idp/oauth2.0/authorize";

    /// <summary>The CAS login route path.</summary>
    private const string LoginRoute = "/idp/login";

    /// <summary>Verifies RFC 6238 SHA-256 6-digit TOTP generation and <c>otpauth://</c> URI parsing.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumTotp_GeneratesRfc6238Sha256CodeAndParsesOtpAuthUri()
    {
        const string uri = $"otpauth://totp/Certum:dev@example.com?secret={Rfc6238Sha256Base32Secret}&algorithm=SHA256&digits=6&period=30";
        var totp = CertumTotp.Parse(uri);
        var code = totp.GenerateCode(DateTimeOffset.FromUnixTimeSeconds(Rfc6238TestSeconds));

        await Assert.That(totp.Algorithm).IsEqualTo(CertumTotpAlgorithm.Sha256);
        await Assert.That(totp.Digits).IsEqualTo(ExpectedTotpDigits);
        await Assert.That(totp.PeriodSeconds).IsEqualTo(ExpectedTotpPeriodSeconds);
        await Assert.That(code).IsEqualTo("119246");
    }

    /// <summary>Verifies <see cref="CertumOptions.FromSettings"/> reads <c>CERTUM_USER_ID</c> and <c>CERTUM_OTP_URI</c> and parses <c>SHA256</c> <c>otpauth://</c> URIs.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumOptions_FromSettings_SupportsGitHubReleaseSecretsAndSha256OtpAuthUri()
    {
        const string sha256Uri = $"otpauth://totp/Certum:ci@example.com?secret={Rfc6238Sha256Base32Secret}&algorithm=SHA256&digits=6&period=30";
        Dictionary<string, string> env = new(StringComparer.Ordinal) { ["CERTUM_USER_ID"] = "ci@example.com", ["CERTUM_OTP_URI"] = sha256Uri };

        var settings = new ProviderSettings(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), key => env.GetValueOrDefault(key));
        var options = CertumOptions.FromSettings(settings);
        var totp = CertumTotp.Parse(options.TotpSecret!);
        var code = totp.GenerateCode(DateTimeOffset.FromUnixTimeSeconds(Rfc6238TestSeconds));

        await Assert.That(options.Email).IsEqualTo("ci@example.com");
        await Assert.That(options.TotpSecret).IsEqualTo(sha256Uri);
        await Assert.That(totp.Algorithm).IsEqualTo(CertumTotpAlgorithm.Sha256);
        await Assert.That(code).IsEqualTo("119246");
    }

    /// <summary>Verifies <see cref="CertumTotp.Parse"/> supports <c>algorithm=SHA1</c> in <c>otpauth://</c> URIs.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumTotp_SupportsSha1OtpAuthUri()
    {
        const string sha1Uri = "otpauth://totp/Certum:me@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Certum&algorithm=SHA1&digits=8&period=30";
        var totp = CertumTotp.Parse(sha1Uri);
        var code = totp.GenerateCode(DateTimeOffset.FromUnixTimeSeconds(Rfc6238TestSeconds));

        await Assert.That(totp.Algorithm).IsEqualTo(CertumTotpAlgorithm.Sha1);
        await Assert.That(code).IsEqualTo("94287082");
    }

    /// <summary>Verifies that a CAS <c>401 Unauthorized</c> response produces a detailed <see cref="ProviderRequestException"/> with the server error message.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_AcquireTokenAsync_ReportsDetailedDiagnosticMessageOnCas401()
    {
        using var http = new StubHttp();
        AddCas401Routes(http);

        var options = new CertumOptions { Email = "dev@example.com", TotpSecret = Rfc6238Sha256Base32Secret, RetryOptions = ProviderRetryOptions.FastTest };

        var exception = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.AcquireTokenAsync(http.ToSettings(), options, TimeProvider.System, CancellationToken.None));

        await Assert.That(exception!.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(exception.Message).Contains("401");
        await Assert.That(exception.Message).Contains("The provided credentials could not be recognized as valid.");
    }

    /// <summary>Verifies UTF-8 span multipart extraction for certificate PEM payloads.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumMultipart_ExtractsNamedPartUsingUtf8Spans()
    {
        var payload =
            """
            --boundary123
            Content-Disposition: form-data; name="metadata"

            ignored
            --boundary123
            Content-Disposition: form-data; name="certificate"; filename="user.pem"
            Content-Type: application/x-pem-file

            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            --boundary123--
            """u8;

        var extracted = CertumMultipart.ExtractCertificatePart(payload);
        var text = Encoding.UTF8.GetString(extracted);

        await Assert.That(text).Contains("-----BEGIN CERTIFICATE-----");
        await Assert.That(text).Contains("-----END CERTIFICATE-----");
    }

    /// <summary>
    /// Verifies the full Certum SimplySign CAS OAuth 2.0 login, SCS1_ATOM card &amp; certificate materialization,
    /// digest signing with transient 503 retry, and automatic <c>refresh_token</c> renewal when the initial token expires.
    /// </summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumSimplySignProvider_LogsInMaterializesCardSignsDigestAndRefreshesExpiredToken()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateCodeSigningCertificate(rsa);
        var certPemBytes = Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
        var payloadDigest = SHA256.HashData("SafeSign Certum payload"u8);
        var precomputedSignatureHex = Convert.ToHexStringLower(rsa.SignHash(payloadDigest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var signatureReplyJson = $"[{{\"{Convert.ToHexStringLower(payloadDigest)}\":\"{precomputedSignatureHex}\"}}]";

        using var http = new StubHttp();
        AddCasOAuthRoutes(http);
        AddCardAndSignatureRoutes(http, certPemBytes, signatureReplyJson);

        var options = new CertumOptions
        {
            Email = "dev@example.com",
            TotpSecret = Rfc6238Sha256Base32Secret,
            CardSerial = "CARD-777",
            TaskPollDelay = TimeSpan.Zero,
            RetryOptions = ProviderRetryOptions.FastTest,
        };

        var provider = new CertumSimplySignProvider(http.ToSettings(), options, TimeProvider.System);
        var signingCertificate = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCertificate.Certificate.Subject).Contains("CN=SafeSign Certum Test");

        var signature = await provider.SignDigestAsync(new(payloadDigest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(rsa.VerifyHash(payloadDigest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).IsTrue();
        await http.VerifyAllCalledAsync();
    }

    /// <summary>Registers a failing CAS OAuth 2.0 login sequence returning <c>401 Unauthorized</c> on <paramref name="http"/>.</summary>
    /// <param name="http">The stub HTTP host.</param>
    private static void AddCas401Routes(StubHttp http)
    {
        http.Add(
            Route.Get(AuthorizeRoute),
            Reply.From(static (_, _) => Task.FromResult(
                CreateRedirectResponse("https://cloudsign.webnotarius.pl/idp/login?service=https%3A%2F%2Fcloudsign.webnotarius.pl%2Fidp%2Foauth2.0%2FcallbackAuthorize"))));
        http.Add(
            Route.Get(LoginRoute),
            Reply.From(static (_, _) => Task.FromResult(
                CreateHtmlResponse(
                    HttpStatusCode.OK,
                    """<form method="post"><input data-name="ignored" type="hidden" name="execution" value="e1s1" /><input type="hidden" name="lt" value="" /></form>"""u8))));
        http.Add(
            Route.Post(LoginRoute),
            Reply.From(static (_, _) => Task.FromResult(
                CreateHtmlResponse(
                    HttpStatusCode.Unauthorized,
                    """
                    <html><body>
                    <div class="ds-form-message ds-form-message--error">
                        <i class="ico-warning"></i><span>The provided credentials could not be recognized as valid.</span>
                    </div>
                    </body></html>
                    """u8))));
    }

    /// <summary>Registers the CAS OAuth 2.0 login and token endpoints on <paramref name="http"/>.</summary>
    /// <param name="http">The stub HTTP host.</param>
    private static void AddCasOAuthRoutes(StubHttp http)
    {
        const string loginLocation =
            "https://cloudsign.webnotarius.pl/idp/login?service="
            + "https%3A%2F%2Fcloudsign.webnotarius.pl%2Fidp%2Foauth2.0%2FcallbackAuthorize"
            + "%3Fclient_id%3D44rvDKKEWY53a7xBeF5w%26response_type%3Dcode"
            + "%26redirect_uri%3Dhttps%253A%252F%252Fcloudsign.webnotarius.pl%252Fredirect%26client_name%3DCasOAuthClient";
        const string callbackLocation =
            "https://cloudsign.webnotarius.pl/idp/oauth2.0/callbackAuthorize"
            + "?client_id=44rvDKKEWY53a7xBeF5w&response_type=code"
            + "&redirect_uri=https%3A%2F%2Fcloudsign.webnotarius.pl%2Fredirect&client_name=CasOAuthClient&ticket=ST-1";
        const string authorizeLocation =
            "https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize"
            + "?response_type=code&client_id=44rvDKKEWY53a7xBeF5w"
            + "&redirect_uri=https%3A%2F%2Fcloudsign.webnotarius.pl%2Fredirect"
            + "&scope=https%3A%2F%2Fcloudsign.webnotarius.pl%2Fidp%2Foauth2.0%2Fprofile&api_key=";
        var loginFormHtml =
            """
            <form method="post">
                <input autocomplete="username" name="username" value="" />
                <input type="hidden" name="lt" value="" />
                <input type="hidden" name="execution" value="e1s1" />
            </form>
            """u8;
        var loginPageReply = CreateHtmlResponse(HttpStatusCode.OK, loginFormHtml);

        http.Add(
            Route.Get(AuthorizeRoute),
            Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse(loginLocation, "SESSION=sess-1; Path=/idp/; Secure; HttpOnly;SameSite=None"))));
        http.Add(Route.Get(LoginRoute), Reply.From((_, _) => Task.FromResult(loginPageReply)));
        http.Add(
            Route.Post(LoginRoute),
            Reply.From(static (_, _) => Task.FromResult(
                CreateRedirectResponse(
                    callbackLocation,
                    "CASPRIVACY=\"\"; Domain=.cloudsign.webnotarius.pl; Max-Age=0; Path=/idp; Secure; HttpOnly",
                    "TGC=tgt-1; Path=/idp/; Secure; HttpOnly;SameSite=None"))));
        http.Add(
            Route.Get("/idp/oauth2.0/callbackAuthorize"),
            Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse(authorizeLocation))));
        http.Add(
            Route.Get(AuthorizeRoute),
            Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse("https://cloudsign.webnotarius.pl/redirect?code=OC-AUTH-CODE-1"))));
        http.Add(
            Route.Post("/idp/oauth2.0/accessToken"),
            Reply.Json("{\"access_token\":\"AT-INITIAL\",\"refresh_token\":\"RT-REUSABLE\",\"expires_in\":30}"));
        http.Add(
            Route.Post("/idp/oauth2.0/accessToken"),
            Reply.Json("{\"access_token\":\"AT-REFRESHED\",\"refresh_token\":\"RT-REUSABLE\",\"expires_in\":1800}"));
    }

    /// <summary>Creates a <c>302 Found</c> response with a <c>Location</c> header and optional <c>Set-Cookie</c> headers.</summary>
    /// <param name="location">The redirect target URL.</param>
    /// <param name="setCookies">Optional <c>Set-Cookie</c> header values.</param>
    /// <returns>The constructed redirect response.</returns>
    private static HttpResponseMessage CreateRedirectResponse(string location, params string[] setCookies)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new(location);
        foreach (var cookie in setCookies)
        {
            response.Headers.Add("Set-Cookie", cookie);
        }

        return response;
    }

    /// <summary>Creates an HTML <see cref="HttpResponseMessage"/> with the given status code and UTF-8 body.</summary>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="html">The UTF-8 HTML payload.</param>
    /// <returns>The constructed HTML response.</returns>
    private static HttpResponseMessage CreateHtmlResponse(HttpStatusCode status, ReadOnlySpan<byte> html)
    {
        var content = new ByteArrayContent(html.ToArray());
        content.Headers.ContentType = new("text/html");
        return new(status) { Content = content };
    }

    /// <summary>Registers the SCS1_ATOM card, certificate, and signature task endpoints on <paramref name="http"/>.</summary>
    /// <param name="http">The stub HTTP host.</param>
    /// <param name="certPemBytes">The PEM certificate bytes.</param>
    /// <param name="signatureReplyJson">The JSON signature task response.</param>
    private static void AddCardAndSignatureRoutes(StubHttp http, byte[] certPemBytes, string signatureReplyJson)
    {
        http.Add(
            Route.Post("/card/v1/cards/tasks"),
            Reply.Json("{\"atom:link\":\"/card/v1/cards/tasks/cards-task-1\",\"ping-after\":200,\"state\":\"queued\"}", HttpStatusCode.Accepted));
        http.Add(
            Route.Get("/card/v1/cards/tasks/cards-task-1"),
            Reply.Json("[{\"cardno\":\"CARD-777\",\"valid-from\":\"2026-01-01\",\"valid-to\":\"2029-01-01\"}]"));
        http.Add(
            Route.Post("/card/v1/cards/CARD-777/certificates/tasks"),
            Reply.Json("{\"atom:link\":\"https://cloudsign.webnotarius.pl/card/v1/cards/CARD-777/certificates/tasks/cert-task-1\",\"ping-after\":150}", HttpStatusCode.Accepted));
        http.Add(
            Route.Get("/card/v1/cards/CARD-777/certificates/tasks/cert-task-1"),
            Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(certPemBytes))));
        http.Add(
            Route.Post("/card/v1/cards/CARD-777/certificates/signature"),
            Reply.Json("{\"atom:link\":\"/card/v1/cards/CARD-777/certificates/signature/sig-task-1\",\"ping-after\":100}", HttpStatusCode.Accepted));
        http.Add(
            Route.Get("/card/v1/cards/CARD-777/certificates/signature/sig-task-1"),
            Reply.From(static (_, _) =>
            {
                var busy = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                busy.Headers.Add("retry-after-ms", "1");
                return Task.FromResult(busy);
            }));
        http.Add(
            Route.Get("/card/v1/cards/CARD-777/certificates/signature/sig-task-1"),
            Reply.Json(signatureReplyJson));
    }

    /// <summary>Creates a synthetic code-signing certificate for <paramref name="rsa"/>.</summary>
    /// <param name="rsa">The RSA key pair.</param>
    /// <returns>The self-signed code-signing certificate.</returns>
    private static X509Certificate2 CreateCodeSigningCertificate(RSA rsa)
    {
        var now = TimeProvider.System.GetUtcNow();
        var req = new CertificateRequest("CN=SafeSign Certum Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return req.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    /// <summary>Creates a <c>multipart/form-data</c> response carrying a PEM certificate part.</summary>
    /// <param name="pemBytes">The PEM certificate bytes.</param>
    /// <returns>The multipart HTTP response.</returns>
    private static HttpResponseMessage CreateCertificateMultipartResponse(byte[] pemBytes)
    {
        var prefix = "--certum-boundary\r\nContent-Disposition: form-data; name=\"certificate\"; filename=\"cert.pem\"\r\nContent-Type: application/x-pem-file\r\n\r\n"u8;
        var suffix = "\r\n--certum-boundary--\r\n"u8;
        var body = new byte[prefix.Length + pemBytes.Length + suffix.Length];
        prefix.CopyTo(body);
        pemBytes.CopyTo(body.AsSpan(prefix.Length));
        suffix.CopyTo(body.AsSpan(prefix.Length + pemBytes.Length));

        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new("multipart/form-data");
        return new(HttpStatusCode.OK) { Content = content };
    }
}
