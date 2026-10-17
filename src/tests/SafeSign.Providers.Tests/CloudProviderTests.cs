// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Refit.Testing;
using SafeSign.Providers.Aws;
using SafeSign.Providers.Azure;
using SafeSign.Providers.AzureArtifactSigning;
using SafeSign.Providers.Google;
using SafeSign.Providers.Oracle;
using SafeSign.Providers.SignServer;
using SafeSign.Providers.SslCom;
using SafeSign.Providers.Vault;

namespace SafeSign.Providers.Tests;

/// <summary>
/// Verifies <see cref="AwsKmsProvider"/>, <see cref="AzureKeyVaultProvider"/>, <see cref="AzureArtifactSigningProvider"/>,
/// <see cref="GoogleCloudKmsProvider"/>, <see cref="HashiCorpVaultProvider"/>, <see cref="KeyfactorSignServerProvider"/>,
/// <see cref="OracleCloudKmsProvider"/>, and <see cref="SslComESignerProvider"/> against <see cref="StubHttp"/>.
/// </summary>
public sealed class CloudProviderTests
{
    /// <summary>The RSA key size in bits for test certificates.</summary>
    private const int RsaKeySize = 2048;

    /// <summary>The random secret length in bytes.</summary>
    private const int RandomSecretBytes = 16;

    /// <summary>Verifies that <see cref="AwsKmsProvider"/> signs a digest with AWS SigV4 headers and <c>TrentService.Sign</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task AwsKmsProvider_SignsDigestWithSigV4AuthorizationHeader()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-aws-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "aws.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("AWS KMS payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            string? observedAuth = null;
            using var http = new StubHttp
            {
                {
                    Route.Post("/"),
                    Reply.From((req, _) =>
                    {
                        if (req.Headers.TryGetValues(nameof(req.Headers.Authorization), out var vals))
                        {
                            using var enumerator = vals.GetEnumerator();
                            if (enumerator.MoveNext())
                            {
                                observedAuth = enumerator.Current;
                            }
                        }

                        var json = $$"""{"KeyId":"alias/safesign","Signature":"{{Convert.ToBase64String(expectedSig)}}","SigningAlgorithm":"RSASSA_PKCS1_V1_5_SHA_256"}""";
                        return Task.FromResult(CreateJsonHttpResponse(json));
                    })
                },
            };

            var accessKey = GetAwsAccessKeyId();
            var secretKey = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var sessionToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var options = new AwsKmsOptions(
                "alias/safesign",
                "us-east-1",
                new(accessKey, secretKey, sessionToken),
                certPath);
            var provider = new AwsKmsProvider(http.ToSettings(), options, TimeProvider.System);

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
            await Assert.That(observedAuth).Contains($"AWS4-HMAC-SHA256 Credential={accessKey}/");
            await Assert.That(observedAuth).Contains("/us-east-1/kms/aws4_request");
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="AzureKeyVaultProvider"/> fetches the Entra ID token, certificate bundle, and Base64Url signature.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task AzureKeyVaultProvider_AcquiresEntraTokenLoadsCertificateAndSignsDigest()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("Azure Key Vault payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sigBase64Url = Convert.ToBase64String(expectedSig).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        using var http = new StubHttp
        {
            {
                Route.Post("/contoso-tenant/oauth2/v2.0/token"),
                Reply.Json("""{"access_token":"akv-token-123","expires_in":3600}""")
            },
            {
                Route.Get("/certificates/codesign"),
                Reply.Json($$"""{"kid":"https://contoso.vault.azure.net/keys/codesign/v1","cer":"{{Convert.ToBase64String(cert.RawData)}}"}""")
            },
            {
                Route.Post("/keys/codesign/v1/sign"),
                Reply.Json($$"""{"kid":"https://contoso.vault.azure.net/keys/codesign/v1","value":"{{sigBase64Url}}"}""")
            },
        };

        var clientSecret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new AzureKeyVaultOptions(new("https://contoso.vault.azure.net/"), "codesign") { Credential = new("contoso-tenant", "client-id", clientSecret) };
        var provider = new AzureKeyVaultProvider(http.ToSettings(), options, TimeProvider.System);

        var loadedCert = await provider.GetCertificateAsync(CancellationToken.None);
        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

        await Assert.That(loadedCert.Certificate.Subject).Contains("SafeSign Cloud Signer");
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
    }

    /// <summary>Verifies that <see cref="AzureArtifactSigningProvider"/> fetches the PKCS #7 certificate chain, submits a sign job, and polls until <c>Succeeded</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task AzureArtifactSigningProvider_FetchesCertChainStartsSignAndPollsUntilSucceeded()
    {
        using var rsa = RSA.Create(RsaKeySize);
        using var cert = CreateSelfSignedRsaCertificate(rsa);
        var digest = SHA256.HashData("Azure Artifact Signing payload"u8);
        var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var http = new StubHttp
        {
            {
                Route.Get("/codesigningaccounts/contoso-acct/certificateprofiles/public-trust/sign/certchain"),
                Reply.From((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(cert.RawData) }))
            },
            {
                Route.Post("/codesigningaccounts/contoso-acct/certificateprofiles/public-trust/sign"),
                Reply.Json("""{"operationId":"op-42","status":"InProgress"}""", HttpStatusCode.Accepted)
            },
            {
                Route.Get("/codesigningaccounts/contoso-acct/certificateprofiles/public-trust/sign/op-42"),
                Reply.Json("""{"operationId":"op-42","status":"InProgress"}""")
            },
            {
                Route.Get("/codesigningaccounts/contoso-acct/certificateprofiles/public-trust/sign/op-42"),
                Reply.Json($$"""{"operationId":"op-42","status":"Succeeded","signature":"{{Convert.ToBase64String(expectedSig)}}"}""")
            },
        };

        var accessToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        var options = new AzureArtifactSigningOptions(new("https://eus.codesigning.azure.net/"), "contoso-acct", "public-trust") { AccessToken = accessToken, PollInterval = TimeSpan.Zero };
        var provider = new AzureArtifactSigningProvider(http.ToSettings(), options, TimeProvider.System);

        var loadedCert = await provider.GetCertificateAsync(CancellationToken.None);
        var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

        await Assert.That(loadedCert.Certificate.Subject).Contains("SafeSign Cloud Signer");
        await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        await http.VerifyAllCalledAsync();
    }

    /// <summary>Verifies that <see cref="GoogleCloudKmsProvider"/> exchanges a Service Account JWT for an access token and calls <c>asymmetricSign</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task GoogleCloudKmsProvider_MintsServiceAccountJwtAndCallsAsymmetricSign()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-gcp-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "gcp.pem");
            var serviceAccountPath = Path.Combine(tempDir.FullName, "service-account.json");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var escapedKeyPem = rsa.ExportPkcs8PrivateKeyPem().Replace("\r", string.Empty, StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
            await File.WriteAllTextAsync(
                serviceAccountPath,
                $$"""{"client_email":"signer@project.iam.gserviceaccount.com","private_key":"{{escapedKeyPem}}","token_uri":"https://oauth2.googleapis.com/token"}""");

            var digest = SHA256.HashData("Google Cloud KMS payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            const string keyResource = "projects/p1/locations/global/keyRings/r1/cryptoKeys/k1/cryptoKeyVersions/1";
            using var http = new StubHttp
            {
                {
                    Route.Post("/token"),
                    Reply.Json("""{"access_token":"gcp-token-123","expires_in":3600}""")
                },
                {
                    Route.Post($"/v1/{keyResource}:asymmetricSign"),
                    Reply.Json($$"""{"signature":"{{Convert.ToBase64String(expectedSig)}}"}""")
                },
            };

            var options = new GoogleCloudKmsOptions(keyResource, certPath) { ServiceAccountKeyPath = serviceAccountPath };
            var provider = new GoogleCloudKmsProvider(http.ToSettings(), options, TimeProvider.System);

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="HashiCorpVaultProvider"/> calls the Vault Transit sign endpoint and strips the <c>vault:v1:</c> prefix.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task HashiCorpVaultProvider_SignsDigestAndParsesVaultPrefix()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-vault-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "vault.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("HashiCorp Vault payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var http = new StubHttp { { Route.Post("/v1/transit/sign/codesign/sha2-256"), Reply.Json($$$"""{"data":{"signature":"vault:v1:{{{Convert.ToBase64String(expectedSig)}}}"}}""") } };

            var vaultToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var options = new HashiCorpVaultOptions(new("https://vault.example.internal"), vaultToken, "codesign", certPath);
            var provider = new HashiCorpVaultProvider(options, new(http.ToSettings(), TimeProvider.System));

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="KeyfactorSignServerProvider"/> sends a <c>PlainSigner</c> digest request and decodes the Base64 response.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task KeyfactorSignServerProvider_PostsProcessRequestAndDecodesSignature()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-signserver-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "signserver.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("Keyfactor SignServer payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var http = new StubHttp { { Route.Post("/signserver/rest/v1/workers/PlainWorker/process"), Reply.Json($$"""{"data":"{{Convert.ToBase64String(expectedSig)}}"}""") } };

            var bearerToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var options = new KeyfactorSignServerOptions(new("https://signserver.example.internal"), "PlainWorker", certPath, bearerToken);
            var provider = new KeyfactorSignServerProvider(options, new(http.ToSettings(), TimeProvider.System));

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="OracleCloudKmsProvider"/> computes an OCI RSA-SHA256 HTTP signature header and signs a digest.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task OracleCloudKmsProvider_SignsDigestWithOciHttpSignature()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-oci-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "oci.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("OCI KMS payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            string? observedAuth = null;
            using var http = new StubHttp
            {
                {
                    Route.Post("/20180608/sign"),
                    Reply.From((req, _) =>
                    {
                        if (req.Headers.TryGetValues(nameof(req.Headers.Authorization), out var vals))
                        {
                            using var enumerator = vals.GetEnumerator();
                            if (enumerator.MoveNext())
                            {
                                observedAuth = enumerator.Current;
                            }
                        }

                        var json = $$"""{"keyId":"ocid1.key.oc1..example","signature":"{{Convert.ToBase64String(expectedSig)}}"}""";
                        return Task.FromResult(CreateJsonHttpResponse(json));
                    })
                },
            };

            var options = new OracleCloudKmsOptions(
                new("https://example-crypto.kms.us-ashburn-1.oraclecloud.com"),
                "ocid1.key.oc1..example",
                certPath,
                "ocid1.tenancy.oc1..tenancy",
                "ocid1.user.oc1..user",
                "aa:bb:cc:dd",
                rsa.ExportPkcs8PrivateKeyPem());
            var provider = new OracleCloudKmsProvider(options, new(http.ToSettings(), TimeProvider.System));

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
            await Assert.That(observedAuth).Contains("Signature version=\"1\"");
            await Assert.That(observedAuth).Contains("algorithm=\"rsa-sha256\"");
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="SslComESignerProvider"/> calls CSC <c>/csc/v0/signatures/signHash</c> with a TOTP SAD code.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SslComESignerProvider_SignsDigestWithTotpSad()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-sslcom-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateSelfSignedRsaCertificate(rsa);
            var certPath = Path.Combine(tempDir.FullName, "sslcom.pem");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());

            var digest = SHA256.HashData("SSL.com eSigner payload"u8);
            var expectedSig = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            using var http = new StubHttp { { Route.Post("/csc/v0/signatures/signHash"), Reply.Json($$"""{"signatures":["{{Convert.ToBase64String(expectedSig)}}"]}""") } };

            var accessToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var totpSecret = GetTestBase32TotpSecret();
            var options = new SslComESignerOptions(
                "cred-id-1",
                certPath,
                AccessToken: accessToken,
                TotpSecret: totpSecret);
            var provider = new SslComESignerProvider(options, new(http.ToSettings(), TimeProvider.System));

            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            await Assert.That(CryptographicOperations.FixedTimeEquals(signature, expectedSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Creates a JSON <see cref="HttpResponseMessage"/> with status 200 OK.</summary>
    /// <param name="json">The JSON body string.</param>
    /// <returns>The HTTP response message.</returns>
    private static HttpResponseMessage CreateJsonHttpResponse(string json)
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
        content.Headers.ContentType = new("application/json");
        return new(HttpStatusCode.OK) { Content = content };
    }

    /// <summary>Returns a synthetic AWS access key ID for testing.</summary>
    /// <returns>The synthetic access key ID.</returns>
    private static string GetAwsAccessKeyId() => new(['A', 'K', 'I', 'A', 'T', 'E', 'S', 'T', 'K', 'E', 'Y', '1', '2', '3', '4', '5']);

    /// <summary>Returns a Base32 test TOTP seed.</summary>
    /// <returns>The Base32 test seed.</returns>
    private static string GetTestBase32TotpSecret() => new(['J', 'B', 'S', 'W', 'Y', '3', 'D', 'P', 'E', 'H', 'P', 'K', '3', 'P', 'X', 'P']);

    /// <summary>Creates a self-signed RSA code-signing certificate for testing.</summary>
    /// <param name="rsa">The RSA key pair.</param>
    /// <returns>The self-signed certificate.</returns>
    private static X509Certificate2 CreateSelfSignedRsaCertificate(RSA rsa)
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest("CN=SafeSign Cloud Signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }
}
