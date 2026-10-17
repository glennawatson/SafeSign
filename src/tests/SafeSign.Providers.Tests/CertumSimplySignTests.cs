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

    /// <summary>Registers the CAS OAuth 2.0 login and token endpoints on <paramref name="http"/>.</summary>
    /// <param name="http">The stub HTTP host.</param>
    private static void AddCasOAuthRoutes(StubHttp http)
    {
        http.Add(
            Route.Get("/idp/oauth2.0/authorize"),
            Reply.From(static (_, _) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Found);
                response.Headers.Location = new("https://cloudsign.webnotarius.pl/idp/login?service=https%3A%2F%2Fcloudsign.webnotarius.pl%2Fidp%2Foauth2.0%2FcallbackAuthorize");
                return Task.FromResult(response);
            }));
        http.Add(
            Route.Get("/idp/login"),
            Reply.From(static (_, _) =>
            {
                var html =
                    """<form method="post"><input type="hidden" name="execution" value="e1s1" /><input type="hidden" name="lt" value="LT-99" /></form>"""u8;
                var content = new ByteArrayContent(html.ToArray());
                content.Headers.ContentType = new("text/html");
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
                response.Headers.Add("Set-Cookie", "JSESSIONID=sess-1; Path=/idp; HttpOnly");
                return Task.FromResult(response);
            }));
        http.Add(
            Route.Post("/idp/login"),
            Reply.From(static (_, _) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Found);
                response.Headers.Location = new("https://cloudsign.webnotarius.pl/redirect?code=ST-AUTH-CODE-1");
                return Task.FromResult(response);
            }));
        http.Add(
            Route.Post("/idp/oauth2.0/accessToken"),
            Reply.Json("{\"access_token\":\"AT-INITIAL\",\"refresh_token\":\"RT-REUSABLE\",\"expires_in\":30}"));
        http.Add(
            Route.Post("/idp/oauth2.0/accessToken"),
            Reply.Json("{\"access_token\":\"AT-REFRESHED\",\"refresh_token\":\"RT-REUSABLE\",\"expires_in\":1800}"));
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
