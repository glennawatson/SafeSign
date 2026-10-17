// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Refit.Testing;
using SafeSign.Providers.Csc;
using SafeSign.Providers.DigiCert;
using SafeSign.Providers.EncryptionConsulting;
using SafeSign.Providers.Fortanix;
using SafeSign.Providers.GaraSign;
using SafeSign.Providers.Shared;
using SafeSign.Providers.SignPath;
using SafeSign.Providers.Venafi;
using SafeSign.Signing;

namespace SafeSign.Providers.Tests;

/// <summary>
/// Verifies <see cref="DigiCertKeyLockerProvider"/>, <see cref="CodeSignSecureProvider"/>,
/// <see cref="FortanixDsmProvider"/>, <see cref="GaraSignProvider"/>, <see cref="SignPathProvider"/>,
/// <see cref="CscProvider"/>, and <see cref="VenafiProvider"/> against <see cref="StubHttp"/>.
/// </summary>
public sealed class EnterpriseProviderTests
{
    /// <summary>The RSA key size in bits for test certificates.</summary>
    private const int RsaKeySize = 2048;

    /// <summary>The random secret length in bytes.</summary>
    private const int RandomSecretBytes = 16;

    /// <summary>The expected total GaraSign HTTP requests (authenticate + keystore + initial sign + poll sign).</summary>
    private const int ExpectedTotalGaraSignRequests = 4;

    /// <summary>The synthetic CSC v1 endpoint URL.</summary>
    private const string CscEndpointUrl = "https://csc.example.com/csc/v1";

    /// <summary>The synthetic CSC v1 authorize route.</summary>
    private const string CscAuthorizeRoute = "/csc/v1/credentials/authorize";

    /// <summary>The synthetic CSC v1 signHash route.</summary>
    private const string CscSignHashRoute = "/csc/v1/signatures/signHash";

    /// <summary>The synthetic CSC credential identifier.</summary>
    private const string CscTestCredentialId = "cred-99";

    /// <summary>Verifies that <see cref="DigiCertKeyLockerProvider"/> resolves a certificate by alias and signs a SHA-256 digest.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task DigiCertKeyLockerProvider_FetchesCertificateAndSignsDigest()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("DigiCert KeyLocker payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certBase64 = Convert.ToBase64String(cert.RawData);
        var sigBase64 = Convert.ToBase64String(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Get("/signingmanager/api/v1/certificates"),
                Reply.Json(
                    $$$"""{"items":[{"id":"cert-old","alias":"prod-cert","status":"EXPIRED","cert":"{{{certBase64}}}","account":{"id":"acct-old"},"keypair":{"id":"kp-old"}},"""
                    + $$$"""{"id":"cert-1","alias":"prod-cert","status":"ACTIVE","cert":"{{{certBase64}}}","account":{"id":"acct-1"},"keypair":{"id":"kp-99"}}]}""")
            },
            {
                Route.Post("/signingmanager/api/v1/keypairs/kp-99/sign"),
                Reply.Json($$"""{"signature":"{{sigBase64}}"}""")
            },
        };

        var apiKey = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new DigiCertKeyLockerOptions(apiKey) { CertificateAlias = "prod-cert" };
        var provider = new DigiCertKeyLockerProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Verifies that <see cref="CodeSignSecureProvider"/> exchanges credentials for a token, loads the PEM certificate, and decodes the hex signature.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CodeSignSecureProvider_LogsInFetchesPemCertificateAndSignsDigest()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("CodeSign Secure payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var pemBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(cert.ExportCertificatePem()));
        var sigHex = Convert.ToHexStringLower(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Post("/api/auth/GetLoginToken/"),
                Reply.Json("""{"token":"css-jwt-token"}""")
            },
            {
                Route.Get("/api/certificate_manage/activecerts/"),
                Reply.Json($$"""{"message":"{{pemBase64}}","status":"SUCCESS"}""")
            },
            {
                Route.Post("/api/signing/sign/"),
                Reply.Json($$"""{"result":"{{sigHex}}","status":"SUCCESS"}""")
            },
        };

        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new CodeSignSecureOptions("prod-signing-cert") { Endpoint = new("https://codesignsecure.example.com"), Username = "build-agent", Password = secret };
        var provider = new CodeSignSecureProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Verifies that <see cref="FortanixDsmProvider"/> authenticates a session and signs a SHA-256 digest.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task FortanixDsmProvider_AuthenticatesSessionAndSignsDigest()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-fortanix-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "fortanix.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("Fortanix DSM payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sigBase64 = Convert.ToBase64String(expectedSig);

            using var http = new StubHttp
            {
                {
                    Route.Post("/sys/v1/session/auth"),
                    Reply.Json("""{"access_token":"fortanix-session-token"}""")
                },
                {
                    Route.Post("/crypto/v1/sign"),
                    Reply.Json($$"""{"signature":"{{sigBase64}}"}""")
                },
            };

            var apiKey = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var options = new FortanixDsmOptions("kid-uuid-123", certPath) { ApiKey = apiKey };
            var provider = new FortanixDsmProvider(http.ToSettings(), options, TimeProvider.System);

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="GaraSignProvider"/> authenticates, decodes signed-byte certificate chains, and polls <c>IN_PROGRESS</c> sign operations.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task GaraSignProvider_AuthenticatesLoadsKeystoreAndPollsSignOperation()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("GaraSign payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var certSignedInts = ToSignedIntJsonArray(cert.RawData);
        var sigSignedInts = ToSignedIntJsonArray(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Post("/garasign/authenticate"),
                Reply.Json("""{"sessionToken":"gs-session-1","status":"SUCCESS"}""")
            },
            {
                Route.Post("/garasign/keystore"),
                Reply.Json($$"""{"status":"SUCCESS","keys":[{"name":"release-key","algorithm":"RSA","certChain":[{{certSignedInts}}]}]}""")
            },
            {
                Route.Post("/garasign/sign"),
                Reply.Json("""{"status":"IN_PROGRESS","requestId":"req-77"}""")
            },
            {
                Route.Post("/garasign/sign"),
                Reply.Json($$"""{"status":"SUCCESS","requestId":"req-77","signature":{{sigSignedInts}}}""")
            },
        };

        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new GaraSignOptions("release-key") { Endpoint = new("https://garasign.example.com/garasign"), Username = "signer", Password = secret, PollInterval = TimeSpan.Zero };
        var provider = new GaraSignProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        await Assert.That(http.Requests.Count).IsEqualTo(ExpectedTotalGaraSignRequests);
    }

    /// <summary>Verifies that <see cref="SignPathProvider"/> retrieves policy certificates and submits fast hash signing requests.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignPathProvider_FetchesSigningPolicyAndSubmitsFastSigningRequest()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("SignPath payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certBase64 = Convert.ToBase64String(cert.RawData);
        var sigBase64 = Convert.ToBase64String(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Get("/API/v1/org-1/Cryptoki/MySigningPolicies"),
                Reply.Json($$"""{"signingPolicies":[{"projectSlug":"safesign","signingPolicySlug":"release","certificateBytes":"{{certBase64}}"}]}""")
            },
            {
                Route.Post("/API/v1/org-1/SigningRequests"),
                Reply.Json($$"""{"Signature":"{{sigBase64}}"}""")
            },
        };

        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new SignPathOptions("org-1", "safesign", "release", token);
        var provider = new SignPathProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Verifies that <see cref="CscProvider"/> fetches credentials info, authorizes a SAD token, and signs a digest via <c>signatures/signHash</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CscProvider_AuthorizesCredentialAndSignsHash()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("CSC v1 payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certBase64 = Convert.ToBase64String(cert.RawData);
        var sigBase64 = Convert.ToBase64String(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Post("/csc/v1/credentials/info"),
                Reply.Json($$$"""{"cert":{"certificates":["{{{certBase64}}}"]}}""")
            },
            {
                Route.Post(CscAuthorizeRoute),
                Reply.Json("""{"SAD":"csc-sad-token"}""")
            },
            {
                Route.Post(CscSignHashRoute),
                Reply.Json($$"""{"signatures":["{{sigBase64}}"]}""")
            },
        };

        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new CscOptions(new Uri(CscEndpointUrl), "cred-42", token) { Pin = "1234" };
        var provider = new CscProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Verifies <see cref="CscOptions.FromSettings"/> and <see cref="CscProvider.SignAlgoOid"/>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CscProvider_CoversSettingsAndSignAlgoOids()
    {
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        Dictionary<string, string> opts = new(StringComparer.OrdinalIgnoreCase)
        {
            ["endpoint"] = CscEndpointUrl,
            ["credential-id"] = CscTestCredentialId,
            ["access-token"] = token,
            ["otp-uri"] = "otpauth://totp/CSC:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        };
        var settings = new ProviderSettings(opts, static _ => null);
        var parsed = CscOptions.FromSettings(settings);
        await Assert.That(parsed.CredentialId).IsEqualTo(CscTestCredentialId);
        await Assert.That(parsed.TotpSecret).Contains("otpauth://");
        await Assert.That(parsed.ToString()).Contains("CscOptions");

        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Rsa, HashAlgorithmName.SHA256)).IsEqualTo("1.2.840.113549.1.1.11");
        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Rsa, HashAlgorithmName.SHA384)).IsEqualTo("1.2.840.113549.1.1.12");
        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Rsa, HashAlgorithmName.SHA512)).IsEqualTo("1.2.840.113549.1.1.13");
        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Ecdsa, HashAlgorithmName.SHA256)).IsEqualTo("1.2.840.10045.4.3.2");
        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Ecdsa, HashAlgorithmName.SHA384)).IsEqualTo("1.2.840.10045.4.3.3");
        await Assert.That(CscProvider.SignAlgoOid(PublicKeyKind.Ecdsa, HashAlgorithmName.SHA512)).IsEqualTo("1.2.840.10045.4.3.4");
        _ = Assert.Throws<NotSupportedException>(static () => _ = CscProvider.SignAlgoOid(PublicKeyKind.Rsa, HashAlgorithmName.SHA1));
    }

    /// <summary>Verifies <see cref="CscProvider"/> TOTP/OTP resolution, local certificate loading, and empty credential error branches.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CscProvider_CoversTotpOtpAndLocalCertificate()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-csc-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var tempCertFile = Path.Combine(tempDir.FullName, "csc.pem");
            await File.WriteAllTextAsync(tempCertFile, cert.ExportCertificatePem());
            var digest = SHA256.HashData("CSC TOTP payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sigBase64 = Convert.ToBase64String(expectedSig);
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var endpoint = new Uri(CscEndpointUrl);

            using var http = new StubHttp
            {
                { Route.Post(CscAuthorizeRoute), Reply.Json("""{"SAD":"sad-totp"}""") },
                { Route.Post(CscSignHashRoute), Reply.Json($$"""{"signatures":["{{sigBase64}}"]}""") },
                { Route.Post(CscAuthorizeRoute), Reply.Json("""{"SAD":"sad-otp-uri"}""") },
                { Route.Post(CscSignHashRoute), Reply.Json($$"""{"signatures":["{{sigBase64}}"]}""") },
                { Route.Post(CscAuthorizeRoute), Reply.Json("""{"SAD":"sad-plain-otp"}""") },
                { Route.Post(CscSignHashRoute), Reply.Json($$"""{"signatures":["{{sigBase64}}"]}""") },
                { Route.Post("/csc/v1/credentials/info"), Reply.Json("""{"cert":{"certificates":[]}}""") },
            };

            var totpProvider = new CscProvider(
                http.ToSettings(),
                new CscOptions(endpoint, CscTestCredentialId, token) { CertificateFile = tempCertFile, TotpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" },
                TimeProvider.System);
            await Assert.That(totpProvider.Name).IsEqualTo("csc");
            var sig1 = await totpProvider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
            await Assert.That(CryptographicOperations.FixedTimeEquals(sig1, expectedSig)).IsTrue();

            var otpUriProvider = new CscProvider(
                http.ToSettings(),
                new CscOptions(endpoint, CscTestCredentialId, token) { CertificateFile = tempCertFile, Otp = "otpauth://totp/CSC:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" },
                TimeProvider.System);
            var sig2 = await otpUriProvider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
            await Assert.That(CryptographicOperations.FixedTimeEquals(sig2, expectedSig)).IsTrue();

            var plainOtpProvider = new CscProvider(
                http.ToSettings(),
                new CscOptions(endpoint, CscTestCredentialId, token) { CertificateFile = tempCertFile, Otp = "123456" },
                TimeProvider.System);
            var sig3 = await plainOtpProvider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
            await Assert.That(CryptographicOperations.FixedTimeEquals(sig3, expectedSig)).IsTrue();

            var emptyInfoProvider = new CscProvider(http.ToSettings(), new CscOptions(endpoint, CscTestCredentialId, token), TimeProvider.System);
            _ = await Assert.ThrowsAsync<ProviderRequestException>(async () => _ = await emptyInfoProvider.GetCertificateAsync(CancellationToken.None));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="VenafiProvider"/> authenticates via OAuth, queries <c>getobjects</c>, and signs an RSA DigestInfo via <c>vedhsm/api/sign</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task VenafiProvider_AuthenticatesLoadsCertificateAndSignsDigest()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("Venafi CodeSign Protect payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certBase64 = Convert.ToBase64String(cert.RawData);
        var sigBase64 = Convert.ToBase64String(expectedSig);

        using var http = new StubHttp
        {
            {
                Route.Post("/vedauth/authorize/oauth"),
                Reply.Json("""{"access_token":"venafi-oauth-token"}""")
            },
            {
                Route.Post("/vedhsm/api/getobjects"),
                Reply.Json($$"""{"Success":true,"Certificates":[{"KeyId":"venafi-key-1","Label":"prod-label","Value":"{{certBase64}}"}]}""")
            },
            {
                Route.Post("/vedhsm/api/sign"),
                Reply.Json($$"""{"Success":true,"ResultData":"{{sigBase64}}"}""")
            },
        };

        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new VenafiOptions(new Uri("https://venafi.example.com"), "prod-label") { Username = "venafi-user", Password = secret };
        var provider = new VenafiProvider(http.ToSettings(), options, TimeProvider.System);

        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        await Assert.That(signingCert.Certificate.Thumbprint).IsEqualTo(cert.Thumbprint);

        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Creates a self-signed RSA certificate for testing.</summary>
    /// <param name="rsa">The RSA key pair.</param>
    /// <returns>The self-signed certificate.</returns>
    private static X509Certificate2 CreateSelfSignedRsaCertificate(RSA rsa)
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest("CN=SafeSign Enterprise Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    /// <summary>Formats a byte span as a JSON array of signed 8-bit integers (<c>-128..127</c>).</summary>
    /// <param name="bytes">The bytes to format.</param>
    /// <returns>The JSON array string.</returns>
    private static string ToSignedIntJsonArray(ReadOnlySpan<byte> bytes)
    {
        var parts = new string[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            parts[i] = unchecked((sbyte)bytes[i]).ToString(CultureInfo.InvariantCulture);
        }

        return $"[{string.Join(',', parts)}]";
    }
}
