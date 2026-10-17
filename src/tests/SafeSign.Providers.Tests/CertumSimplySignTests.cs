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

    /// <summary>The SCS1_ATOM list-cards task route path.</summary>
    private const string CardsTasksRoute = "/card/v1/cards/tasks";

    /// <summary>The SCS1_ATOM list-certificates route for card C-1.</summary>
    private const string CardC1CertTasksRoute = "/card/v1/cards/C-1/certificates/tasks";

    /// <summary>A single-card JSON array payload for card C-1.</summary>
    private const string SingleCardC1Json = "[{\"cardno\":\"C-1\"}]";

    /// <summary>The HTML hidden input field name for CAS flow execution.</summary>
    private const string ExecutionFieldName = "execution";

    /// <summary>The expected 7-digit TOTP length.</summary>
    private const int SevenTotpDigits = 7;

    /// <summary>The custom 60-second TOTP period.</summary>
    private const int CustomTotpPeriodSeconds = 60;

    /// <summary>An out-of-range TOTP digit count.</summary>
    private const int InvalidTotpDigits = 5;

    /// <summary>An out-of-range TOTP algorithm enum value.</summary>
    private const CertumTotpAlgorithm InvalidTotpAlgorithm = (CertumTotpAlgorithm)99;

    /// <summary>The hex character count of a SHA-256 fingerprint.</summary>
    private const int Sha256HexLength = 64;

    /// <summary>The hex chunk size for colon-separated fingerprints.</summary>
    private const int HexByteChunkLength = 2;

    /// <summary>Random byte length for synthetic tokens.</summary>
    private const int RandomTokenBytes = 16;

    /// <summary>Redirect count exceeding the 20-redirect CAS authorize limit.</summary>
    private const int ExcessAuthorizeRedirects = 21;

    /// <summary>Poll iteration count reaching the 120-poll SCS1_ATOM limit.</summary>
    private const int MaxPollIterations = 120;

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

    /// <summary>Verifies <see cref="CertumTotp.Parse(string)"/> supports <c>algorithm=SHA1</c> in <c>otpauth://</c> URIs.</summary>
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

    /// <summary>Verifies UTF-8 span multipart extraction for certificate PEM payloads and error cases.</summary>
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
        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            static () =>
            {
                _ = CertumMultipart.ExtractCertificatePart("not-a-boundary\n"u8);
                return Task.CompletedTask;
            });
        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            static () =>
            {
                _ = CertumMultipart.ExtractCertificatePart("--b\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nx\r\n--b--\r\n"u8);
                return Task.CompletedTask;
            });
        var tokenReply = new CertumTokenResponse(null, "bearer", ExpectedTotpPeriodSeconds, null);
        await Assert.That(tokenReply.ToString()).Contains("bearer");
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
        http.Add(Route.Post("/card/v1/cards/CARD-777/certificates/signature"), Reply.Json(signatureReplyJson));

        var options = new CertumOptions
        {
            Email = "dev@example.com",
            TotpSecret = Rfc6238Sha256Base32Secret,
            CardSerial = "CARD-777",
            TaskPollDelay = TimeSpan.Zero,
            RetryOptions = ProviderRetryOptions.FastTest,
        };

        var provider = new CertumSimplySignProvider(http.ToSettings(), options, TimeProvider.System);
        await Assert.That(provider.Name).IsEqualTo("certum");
        var signingCertificate = await provider.GetCertificateAsync(CancellationToken.None);
        var cachedCertificate = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCertificate.Certificate.Subject).Contains("CN=SafeSign Certum Test");
        await Assert.That(cachedCertificate.Certificate.Thumbprint).IsEqualTo(signingCertificate.Certificate.Thumbprint);

        var signature = await provider.SignDigestAsync(new(payloadDigest, HashAlgorithmName.SHA256), CancellationToken.None);
        var secondSignature = await provider.SignDigestAsync(new(payloadDigest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(rsa.VerifyHash(payloadDigest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).IsTrue();
        await Assert.That(CryptographicOperations.FixedTimeEquals(secondSignature, signature)).IsTrue();
        await http.VerifyAllCalledAsync();
    }

    /// <summary>
    /// Verifies that <see cref="CertumRequests.MaterializeCardAsync"/> dynamically downloads the issuing
    /// intermediate CA certificate from the leaf certificate's X.509 Authority Information Access (AIA)
    /// <c>CA Issuers</c> URI (<c>http://repository.certum.pl/ccsca2021.cer</c>) and stops at the self-signed root CA.
    /// </summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_MaterializeCardAsync_DownloadsIntermediateCaFromAiaExtensionAndSelectsCardByFingerprint()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var rootRsa = RSA.Create(RsaKeySize);
        var rootReq = new CertificateRequest("CN=SafeSign Root CA", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var rootCert = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        using var intermediateRsa = RSA.Create(RsaKeySize);
        var intermediateReq = new CertificateRequest("CN=SafeSign Intermediate CA", intermediateRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateReq.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(["http://subca.ocsp-certum.com"], ["http://repository.certum.pl/ctnca2.cer"]));
        using var intermediatePublic = intermediateReq.Create(rootCert, now.AddDays(-1), now.AddYears(1), [1]);
        using var intermediateCert = intermediatePublic.CopyWithPrivateKey(intermediateRsa);

        using var otherRsa = RSA.Create(RsaKeySize);
        using var otherLeaf = CreateCodeSigningCertificate(otherRsa);

        using var leafRsa = RSA.Create(RsaKeySize);
        var leafReq = new CertificateRequest("CN=SafeSign Aia Leaf", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(null, ["ldap://directory.certum.pl/cn=ca", "http://repository.certum.pl/ccsca2021.cer"]));
        using var leafCert = leafReq.Create(intermediateCert, now.AddDays(-1), now.AddYears(1), [1, 1]);

        var otherPem = Encoding.ASCII.GetBytes(otherLeaf.ExportCertificatePem());
        var leafPem = Encoding.ASCII.GetBytes(leafCert.ExportCertificatePem());
        var intermediateAndExtraPem = Encoding.ASCII.GetBytes($"{otherLeaf.ExportCertificatePem()}\n{intermediateCert.ExportCertificatePem()}");
        var rootDer = rootCert.RawData;

        using var http = new StubHttp
        {
            { Route.Post(CardsTasksRoute), Reply.Json("[{\"cardno\":\"CARD-1\"},{\"cardno\":\"CARD-2\"}]") },
            { Route.Post("/card/v1/cards/CARD-1/certificates/tasks"), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(otherPem))) },
            { Route.Post("/card/v1/cards/CARD-2/certificates/tasks"), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(leafPem))) },
            { Route.Get("/ccsca2021.cer"), Reply.From((_, _) => Task.FromResult(CreateBinaryResponse(intermediateAndExtraPem))) },
            { Route.Get("/ctnca2.cer"), Reply.From((_, _) => Task.FromResult(CreateBinaryResponse(rootDer))) },
        };

        var sha256HexWithColons = string.Join(':', Convert.ToHexString(leafCert.GetCertHash(HashAlgorithmName.SHA256)).Chunk(HexByteChunkLength).Select(static c => new string(c)));
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomTokenBytes));
        var options = new CertumOptions { AccessToken = token, CertificateFingerprint = sha256HexWithColons, RetryOptions = ProviderRetryOptions.FastTest };

        var materialized = await CertumRequests.MaterializeCardAsync(http.ToSettings(), options, token, TimeProvider.System, CancellationToken.None);

        await Assert.That(materialized.Serial).IsEqualTo("CARD-2");
        await Assert.That(materialized.SigningCertificate.Certificate.Subject).Contains("CN=SafeSign Aia Leaf");
        await Assert.That(materialized.SigningCertificate.Chain.Length).IsEqualTo(1);
        await Assert.That(materialized.SigningCertificate.Chain[0].Subject).Contains("CN=SafeSign Intermediate CA");
    }

    /// <summary>Verifies <see cref="CertumIntermediateCertificates"/> edge cases when AIA is absent, non-HTTP, empty, or returns 404.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumIntermediateCertificates_HandlesEmptyListsAndFailedOrEmptyAiaResponses()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var rootRsa = RSA.Create(RsaKeySize);
        var rootReq = new CertificateRequest("CN=SafeSign Root 2", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var rootCert = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        using var leafRsa = RSA.Create(RsaKeySize);
        var leafNoHttpAiaReq = new CertificateRequest("CN=Leaf No Http AIA", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafNoHttpAiaReq.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(null, ["ldap://directory.example.com/ca"]));
        using var leafNoHttpAia = leafNoHttpAiaReq.Create(rootCert, now.AddDays(-1), now.AddYears(1), [1]);

        var leafHttpAiaReq = new CertificateRequest("CN=Leaf Http AIA", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafHttpAiaReq.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(null, ["https://repository.certum.pl/missing.cer"]));
        using var leafHttpAia = leafHttpAiaReq.Create(rootCert, now.AddDays(-1), now.AddYears(1), [1, 1]);

        using var http = new StubHttp
        {
            { Route.Get("/missing.cer"), Reply.Status(HttpStatusCode.NotFound) },
            { Route.Get("/missing.cer"), Reply.From(static (_, _) => Task.FromResult(CreateBinaryResponse([]))) },
        };

        List<X509Certificate2> empty = [];
        await CertumIntermediateCertificates.TryAddMatchingIntermediatesAsync(http.ToSettings(), empty, CancellationToken.None);
        await Assert.That(empty.Count).IsEqualTo(0);

        List<X509Certificate2> nonHttpList = [leafNoHttpAia];
        await CertumIntermediateCertificates.TryAddMatchingIntermediatesAsync(http.ToSettings(), nonHttpList, CancellationToken.None);
        await Assert.That(nonHttpList.Count).IsEqualTo(1);

        List<X509Certificate2> notFoundList = [leafHttpAia];
        await CertumIntermediateCertificates.TryAddMatchingIntermediatesAsync(http.ToSettings(), notFoundList, CancellationToken.None);
        await Assert.That(notFoundList.Count).IsEqualTo(1);

        List<X509Certificate2> emptyBodyList = [leafHttpAia];
        await CertumIntermediateCertificates.TryAddMatchingIntermediatesAsync(http.ToSettings(), emptyBodyList, CancellationToken.None);
        await Assert.That(emptyBodyList.Count).IsEqualTo(1);
    }

    /// <summary>Verifies <see cref="CertumTotp"/> validation, 7-digit/8-digit SHA-512 codes, lowercase Base32, and error branches.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumTotp_CoversAlgorithmsDigitLengthsAndValidationErrors()
    {
        var secretBytes = CertumTotp.DecodeBase32("gezdgnbvgy3tqojq=== ");
        var defaultTotp = new CertumTotp(secretBytes);
        await Assert.That(defaultTotp.Algorithm).IsEqualTo(CertumTotpAlgorithm.Sha256);

        var sha512Seven = CertumTotp.Parse("otpauth://totp/Test?flag&secret=gezdgnbvgy3tqojq&algorithm=SHA512&digits=7&period=60");
        await Assert.That(sha512Seven.Algorithm).IsEqualTo(CertumTotpAlgorithm.Sha512);
        await Assert.That(sha512Seven.Digits).IsEqualTo(SevenTotpDigits);
        await Assert.That(sha512Seven.PeriodSeconds).IsEqualTo(CustomTotpPeriodSeconds);
        await Assert.That(sha512Seven.GenerateCode(Rfc6238TestSeconds).Length).IsEqualTo(SevenTotpDigits);

        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = new CertumTotp([]));
        _ = Assert.Throws<ProviderConfigurationException>(() => _ = new CertumTotp(secretBytes, CertumTotpAlgorithm.Sha256, InvalidTotpDigits, ExpectedTotpPeriodSeconds));
        _ = Assert.Throws<ProviderConfigurationException>(() => _ = new CertumTotp(secretBytes, CertumTotpAlgorithm.Sha256, ExpectedTotpDigits, 0));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("   "));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("otpauth://totp/Test?algorithm=SHA256"));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("otpauth://totp/Test?secret=GEZD&algorithm=MD5"));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("otpauth://totp/Test?secret=GEZD&digits=abc"));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("==== "));
        _ = Assert.Throws<ProviderConfigurationException>(static () => _ = CertumTotp.Parse("INVALID!CHAR"));

        var invalidAlgoTotp = new CertumTotp(secretBytes, InvalidTotpAlgorithm, ExpectedTotpDigits, ExpectedTotpPeriodSeconds);
        _ = Assert.Throws<InvalidOperationException>(() => _ = invalidAlgoTotp.GenerateCode(Rfc6238TestSeconds));
    }

    /// <summary>
    /// Verifies <see cref="CertumOptions"/> validation, <see cref="CertumRequests.DigestType"/>,
    /// <see cref="CertumRequests.ExtractHiddenInputValue"/>, and <see cref="CertumRequests.ExtractCasErrorMessage"/>.
    /// </summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_HelpersAndOptionsCoverAllBranches()
    {
        var emptySettings = new ProviderSettings(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), static _ => null);
        _ = Assert.Throws<ProviderConfigurationException>(() => _ = CertumOptions.FromSettings(emptySettings));

        var opt = new CertumOptions { Email = "a@b.c", CardSerial = "C1" };
        await Assert.That(opt.ToString()).Contains("CertumOptions");

        await Assert.That(CertumRequests.DigestType(HashAlgorithmName.SHA256)).IsEqualTo("SHA256");
        await Assert.That(CertumRequests.DigestType(HashAlgorithmName.SHA384)).IsEqualTo("SHA384");
        await Assert.That(CertumRequests.DigestType(HashAlgorithmName.SHA512)).IsEqualTo("SHA512");
        _ = Assert.Throws<NotSupportedException>(static () => _ = CertumRequests.DigestType(HashAlgorithmName.SHA1));

        await Assert.That(CertumRequests.ExtractHiddenInputValue("no inputs here", ExecutionFieldName)).IsNull();
        await Assert.That(CertumRequests.ExtractHiddenInputValue("<input name=\"execution\" unclosed", ExecutionFieldName)).IsNull();
        await Assert.That(CertumRequests.ExtractHiddenInputValue("<input name=unquoted value='v1' /><input name='execution' value='e2s2'>", ExecutionFieldName)).IsEqualTo("e2s2");
        await Assert.That(CertumRequests.ExtractHiddenInputValue("<input name=\"other\" value=\"1\">", ExecutionFieldName)).IsNull();

        await Assert.That(CertumRequests.ExtractCasErrorMessage("   ")).IsNull();
        await Assert.That(CertumRequests.ExtractCasErrorMessage("<html><head><title>CAS - Failure</title></head></html>")).IsEqualTo("CAS - Failure");
        await Assert.That(CertumRequests.ExtractCasErrorMessage("Plain error body")).IsEqualTo("Plain error body");
        await Assert.That(CertumRequests.ExtractCasErrorMessage("<div class=\"ds-form-message--error\">no span</div><title>   </title>")).IsNull();
        await Assert.That(CertumRequests.ExtractCasErrorMessage("<div class=\"ds-form-message--error\"><span unclosed")).IsNull();
        await Assert.That(CertumRequests.ExtractCasErrorMessage("<title>unclosed")).IsNull();
        await Assert.That(CertumRequests.ExtractCasErrorMessage("<div class=\"ds-form-message--error\"><span>   </span></div>")).IsNull();

        var digest = SHA256.HashData("test"u8);
        var digestHex = Convert.ToHexStringLower(digest);
        _ = Assert.Throws<ProviderRequestException>(() => _ = CertumRequests.ParseSignatureResponse("[{\"not-hex\":\"00\",\"0000\":\"11\"}]"u8, digest));
        _ = Assert.Throws<ProviderRequestException>(() => _ = CertumRequests.ParseSignatureResponse(Encoding.UTF8.GetBytes($"[{{\"{digestHex}\":\"zz-not-hex\"}}]"), digest));
        _ = Assert.Throws<ProviderRequestException>(() => _ = CertumRequests.ParseSignatureResponse("null"u8, digest));
        _ = Assert.Throws<ProviderRequestException>(() => _ = CertumRequests.ParseSignatureResponse("not-json"u8, digest));
    }

    /// <summary>Verifies <see cref="CertumRequests"/> token acquisition and card materialization validation and error branches.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_AcquireTokenAndMaterializeCard_CoverValidationErrors()
    {
        using var http = new StubHttp();
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomTokenBytes));
        var direct = await CertumRequests.AcquireTokenAsync(
            http.ToSettings(),
            new CertumOptions { AccessToken = token },
            TimeProvider.System,
            CancellationToken.None);
        await Assert.That(direct.Value).IsEqualTo(token);

        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.AcquireTokenAsync(http.ToSettings(), new(), TimeProvider.System, CancellationToken.None));
        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.AcquireTokenAsync(http.ToSettings(), new() { Email = "a@b.c" }, TimeProvider.System, CancellationToken.None));

        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateCodeSigningCertificate(rsa);
        var certPemBytes = Encoding.ASCII.GetBytes(cert.ExportCertificatePem());

        http.Add(Route.Post(CardsTasksRoute), Reply.Json("[]"));
        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new(), token, TimeProvider.System, CancellationToken.None));

        http.Add(Route.Post(CardsTasksRoute), Reply.Json("[{\"cardno\":\"\"}]"));
        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new(), token, TimeProvider.System, CancellationToken.None));

        http.Add(Route.Post(CardsTasksRoute), Reply.Json(SingleCardC1Json));
        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new() { CardSerial = "MISSING" }, token, TimeProvider.System, CancellationToken.None));

        var missingChainOpts = new CertumOptions { AdditionalCertificatesPath = "/nonexistent/certum-chain.pem" };
        http.Add(Route.Post(CardsTasksRoute), Reply.Json(SingleCardC1Json));
        http.Add(Route.Post(CardC1CertTasksRoute), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(certPemBytes))));
        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), missingChainOpts, token, TimeProvider.System, CancellationToken.None));

        http.Add(Route.Post(CardsTasksRoute), Reply.Json(SingleCardC1Json));
        http.Add(Route.Post(CardC1CertTasksRoute), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(certPemBytes))));
        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new() { CertificateFingerprint = "not-hex!" }, token, TimeProvider.System, CancellationToken.None));

        var zeroFingerprintOpts = new CertumOptions { CertificateFingerprint = new('0', Sha256HexLength) };
        http.Add(Route.Post(CardsTasksRoute), Reply.Json(SingleCardC1Json));
        http.Add(Route.Post(CardC1CertTasksRoute), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(certPemBytes))));
        _ = await Assert.ThrowsAsync<ProviderConfigurationException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), zeroFingerprintOpts, token, TimeProvider.System, CancellationToken.None));
    }

    /// <summary>Verifies <see cref="CertumRequests.MaterializeCardAsync"/> task failures, SHA-1 thumbprint matching, and additional certificate chain loading.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_MaterializeCard_CoversTaskFailuresAndSha1Thumbprint()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-certum-chain-");
        try
        {
            using var http = new StubHttp();
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateCodeSigningCertificate(rsa);
            var certPemBytes = Encoding.ASCII.GetBytes(cert.ExportCertificatePem());
            var sha1Hex = Convert.ToHexStringLower(cert.GetCertHash(HashAlgorithmName.SHA1));
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomTokenBytes));
            var tempChain = Path.Combine(tempDir.FullName, "chain.pem");
            await File.WriteAllBytesAsync(tempChain, certPemBytes);

            http.Add(Route.Post(CardsTasksRoute), Reply.Json("{\"state\":\"failed\"}", HttpStatusCode.OK));
            _ = await Assert.ThrowsAsync<ProviderRequestException>(
                async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new(), token, TimeProvider.System, CancellationToken.None));

            http.Add(Route.Post(CardsTasksRoute), Reply.Status(HttpStatusCode.BadRequest));
            _ = await Assert.ThrowsAsync<ProviderRequestException>(
                async () => _ = await CertumRequests.MaterializeCardAsync(
                    http.ToSettings(),
                    new() { RetryOptions = ProviderRetryOptions.FastTest },
                    token,
                    TimeProvider.System,
                    CancellationToken.None));

            http.Add(Route.Post(CardsTasksRoute), Reply.Json("{\"atom:link\":\"card/v1/cards/tasks/t-sha1\"}"));
            http.Add(Route.Get("/card/v1/cards/tasks/t-sha1"), Reply.Json(SingleCardC1Json));
            http.Add(Route.Post(CardC1CertTasksRoute), Reply.From((_, _) => Task.FromResult(CreateCertificateMultipartResponse(certPemBytes))));
            var cardSha1 = await CertumRequests.MaterializeCardAsync(
                http.ToSettings(),
                new() { CardSerial = "C-1", CertificateFingerprint = sha1Hex, AdditionalCertificatesPath = tempChain, RetryOptions = ProviderRetryOptions.FastTest },
                token,
                TimeProvider.System,
                CancellationToken.None);
            await Assert.That(cardSha1.Serial).IsEqualTo("C-1");

            http.Add(Route.Post(CardsTasksRoute), Reply.Json("{\"state\":\"done\"}"));
            _ = await Assert.ThrowsAsync<ProviderRequestException>(
                async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new(), token, TimeProvider.System, CancellationToken.None));

            http.Add(Route.Post(CardsTasksRoute), Reply.Text("{not-valid-json"));
            _ = await Assert.ThrowsAsync<ProviderRequestException>(
                async () => _ = await CertumRequests.MaterializeCardAsync(http.ToSettings(), new(), token, TimeProvider.System, CancellationToken.None));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies CAS OAuth login with <see cref="CertumOptions.OtpCode"/> (<c>otpauth://</c> and literal), queryless redirects, and max redirect/poll limits.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CertumRequests_LoginWithCas_CoversOtpCodeAndRedirectBranches()
    {
        using var http = new StubHttp
        {
            { Route.Get(AuthorizeRoute), Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse("https://cloudsign.webnotarius.pl/idp/login", "MalformedCookie"))) },
            {
                Route.Get(LoginRoute),
                Reply.From(static (_, _) => Task.FromResult(CreateHtmlResponse(HttpStatusCode.OK, "<form><input name=><input name=unquoted name=\"execution\" value=\"e1\" /></form>"u8)))
            },
            { Route.Post(LoginRoute), Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse("/idp/step2"))) },
            { Route.Get("/idp/step2"), Reply.From(static (_, _) => Task.FromResult(CreateRequestUriOkResponse("https://cloudsign.webnotarius.pl/redirect?code=OC-FROM-REQ"))) },
            { Route.Post("/idp/" + "oauth2.0/accessToken"), Reply.Json("{\"access_token\":\"AT-1\"}") },
        };

        var otpUriOpts = new CertumOptions
        {
            Email = "otpuri@example.com",
            OtpCode = $"otpauth://totp/Certum:otpuri@example.com?secret={Rfc6238Sha256Base32Secret}",
            RetryOptions = ProviderRetryOptions.FastTest,
        };
        var tok1 = await CertumRequests.AcquireTokenAsync(http.ToSettings(), otpUriOpts, TimeProvider.System, CancellationToken.None);
        await Assert.That(tok1.Value).IsEqualTo("AT-1");

        http.Add(
            Route.Get(AuthorizeRoute),
            Reply.From(static (_, _) => Task.FromResult(CreateHtmlResponse(HttpStatusCode.OK, "<form><input name=unquoted name=\"execution\" value=\"e1\" /></form>"u8))));
        http.Add(Route.Post(LoginRoute), Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse("https://cloudsign.webnotarius.pl/redirect?code=OC-2"))));
        http.Add(Route.Post("/idp/" + "oauth2.0/accessToken"), Reply.Json("{}"));

        var plainOtpOpts = new CertumOptions { Email = "plainotp@example.com", OtpCode = "123456", RetryOptions = ProviderRetryOptions.FastTest };
        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.AcquireTokenAsync(http.ToSettings(), plainOtpOpts, TimeProvider.System, CancellationToken.None));

        for (var i = 0; i < ExcessAuthorizeRedirects; i++)
        {
            http.Add(Route.Get(AuthorizeRoute), Reply.From(static (_, _) => Task.FromResult(CreateRedirectResponse(AuthorizeRoute))));
        }

        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.AcquireTokenAsync(http.ToSettings(), plainOtpOpts, TimeProvider.System, CancellationToken.None));

        http.Add(Route.Post(CardsTasksRoute), Reply.Json("{\"atom:link\":\"/card/v1/cards/tasks/loop\"}"));
        for (var i = 0; i < MaxPollIterations; i++)
        {
            http.Add(Route.Get("/card/v1/cards/tasks/loop"), Reply.Json("{\"atom:link\":\"/card/v1/cards/tasks/loop\"}"));
        }

        _ = await Assert.ThrowsAsync<ProviderRequestException>(
            async () => _ = await CertumRequests.MaterializeCardAsync(
                http.ToSettings(),
                new() { TaskPollDelay = TimeSpan.Zero, RetryOptions = ProviderRetryOptions.FastTest },
                tok1.Value,
                TimeProvider.System,
                CancellationToken.None));
    }

    /// <summary>Creates an HTTP 200 OK response with a populated <see cref="HttpResponseMessage.RequestMessage"/> URI.</summary>
    /// <param name="requestUri">The request URI string.</param>
    /// <returns>The constructed HTTP response.</returns>
    private static HttpResponseMessage CreateRequestUriOkResponse(string requestUri) =>
        new(HttpStatusCode.OK) { RequestMessage = new(HttpMethod.Get, requestUri), Content = new StringContent(string.Empty) };

    /// <summary>Creates a binary <see cref="HttpResponseMessage"/> with status 200 OK.</summary>
    /// <param name="bytes">The binary payload.</param>
    /// <returns>The constructed HTTP response.</returns>
    private static HttpResponseMessage CreateBinaryResponse(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new("application/pkix-cert");
        return new(HttpStatusCode.OK) { Content = content };
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
        response.Headers.Location = new(location, UriKind.RelativeOrAbsolute);
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
