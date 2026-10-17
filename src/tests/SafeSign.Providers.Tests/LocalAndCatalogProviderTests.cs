// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Providers.Local;
using SafeSign.Providers.Store;

namespace SafeSign.Providers.Tests;

/// <summary>Verifies <see cref="ProviderCatalog"/>, <see cref="ProviderSettingsReader"/>, <see cref="LocalCertificateProvider"/>, and <see cref="X509StoreProvider"/>.</summary>
public sealed class LocalAndCatalogProviderTests
{
    /// <summary>The RSA key size in bits for test certificates.</summary>
    private const int RsaKeySize = 2048;

    /// <summary>The random secret length in bytes.</summary>
    private const int RandomSecretBytes = 16;

    /// <summary>The total count of registered providers in <see cref="ProviderCatalog.All"/>.</summary>
    private const int ExpectedTotalProviders = 18;

    /// <summary>The count of working providers in <see cref="ProviderCatalog.All"/>.</summary>
    private const int ExpectedWorkingProviders = 18;

    /// <summary>The count of planned providers in <see cref="ProviderCatalog.All"/>.</summary>
    private const int ExpectedPlannedProviders = 0;

    /// <summary>The serial number bytes for synthetic leaf certificates.</summary>
    private static readonly byte[] LeafSerial = [1, 1, 1, 1];

    /// <summary>Verifies that <see cref="ProviderCatalog.All"/> lists all 18 working providers and looks them up case-insensitively.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ProviderCatalog_RegistersAllEighteenWorkingProviders()
    {
        var all = ProviderCatalog.All;
        var workingCount = 0;
        var plannedCount = 0;
        for (var i = 0; i < all.Length; i++)
        {
            if (all[i].Status == ProviderStatus.Working)
            {
                workingCount++;
            }
            else if (all[i].Status == ProviderStatus.Planned)
            {
                plannedCount++;
            }
        }

        await Assert.That(all.Length).IsEqualTo(ExpectedTotalProviders);
        await Assert.That(workingCount).IsEqualTo(ExpectedWorkingProviders);
        await Assert.That(plannedCount).IsEqualTo(ExpectedPlannedProviders);

        var certum = ProviderCatalog.Find("CERTUM");
        await Assert.That(certum).IsNotNull();
        await Assert.That(certum!.Status).IsEqualTo(ProviderStatus.Working);
        await Assert.That(certum.Create).IsNotNull();

        var artifactSigning = ProviderCatalog.Find("azure-artifact-signing");
        await Assert.That(artifactSigning).IsNotNull();
        await Assert.That(artifactSigning!.Name).IsEqualTo("azure-artifact-signing");
        await Assert.That(artifactSigning.Status).IsEqualTo(ProviderStatus.Working);
        await Assert.That(artifactSigning.Create).IsNotNull();

        var signPath = ProviderCatalog.Find("signpath");
        await Assert.That(signPath).IsNotNull();
        await Assert.That(signPath!.Status).IsEqualTo(ProviderStatus.Working);
        await Assert.That(signPath.Create).IsNotNull();

        await Assert.That(ProviderCatalog.Find("nonexistent")).IsNull();
    }

    /// <summary>Verifies that <see cref="LocalCertificateProvider"/> signs with a PKCS #12 (<c>.pfx</c>) bundle containing a leaf and intermediate certificate.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task LocalCertificateProvider_SignsWithPkcs12BundleAndOrdersChain()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-local-pfx-");
        try
        {
            using var rootRsa = RSA.Create(RsaKeySize);
            using var rootCert = CreateCaCertificate(rootRsa, "CN=SafeSign Test Root CA");
            using var interRsa = RSA.Create(RsaKeySize);
            using var interCert = CreateIntermediateCertificate(interRsa, rootCert, "CN=SafeSign Test Intermediate CA");
            using var leafRsa = RSA.Create(RsaKeySize);
            using var leafCert = CreateLeafCertificate(leafRsa, interCert, "CN=SafeSign Leaf Signer");

            var collection = new X509Certificate2Collection { X509CertificateLoader.LoadCertificate(rootCert.RawData), X509CertificateLoader.LoadCertificate(interCert.RawData), leafCert };

            var pfxPassword = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var pfxPath = Path.Combine(tempDir.FullName, "bundle.pfx");
            await File.WriteAllBytesAsync(pfxPath, collection.Export(X509ContentType.Pkcs12, pfxPassword)!);

            var optionsMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["cert-file"] = pfxPath, ["password"] = pfxPassword };
            var settings = new ProviderSettings(optionsMap, static _ => null);

            var provider = LocalCertificateProvider.FromSettings(settings);
            var signingCert = await provider.GetCertificateAsync(CancellationToken.None);

            await Assert.That(signingCert.Certificate.Subject).Contains("SafeSign Leaf Signer");
            await Assert.That(signingCert.Chain.Length).IsEqualTo(1);
            await Assert.That(signingCert.Chain[0].Subject).Contains("SafeSign Test Intermediate CA");

            var digest = SHA256.HashData("SafeSign local PFX test"u8);
            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            var verified = leafRsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            await Assert.That(verified).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="LocalCertificateProvider"/> signs with an ECDSA P-256 PEM certificate and separate PEM private key.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task LocalCertificateProvider_SignsWithSeparateEcdsaPemKeyAndProducesDerSignature()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-local-pem-");
        try
        {
            var now = TimeProvider.System.GetUtcNow();
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=SafeSign ECDSA Signer", ecdsa, HashAlgorithmName.SHA256);
            using var cert = req.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

            var certPath = Path.Combine(tempDir.FullName, "signer.pem");
            var keyPath = Path.Combine(tempDir.FullName, "signer.key");
            await File.WriteAllTextAsync(certPath, cert.ExportCertificatePem());
            await File.WriteAllTextAsync(keyPath, ecdsa.ExportECPrivateKeyPem());

            var provider = new LocalCertificateProvider(new(certPath, KeyFile: keyPath));
            var digest = SHA256.HashData("SafeSign ECDSA PEM test"u8);
            var signature = await provider.SignDigestAsync(new(digest, HashAlgorithmName.SHA256), CancellationToken.None);

            var verified = ecdsa.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence);
            await Assert.That(verified).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="X509StoreProvider"/> parses settings and rejects missing thumbprint/subject options.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task X509StoreProvider_ValidatesSettingsAndThrowsWhenCertificateNotFound()
    {
        var emptySettings = new ProviderSettings(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase), static _ => null);
        await Assert.That(() => X509StoreProvider.FromSettings(emptySettings)).Throws<ProviderConfigurationException>();

        var storeMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["thumbprint"] = "00112233445566778899AABBCCDDEEFF00112233",
            ["store-name"] = "My",
            ["store-location"] = "CurrentUser",
        };
        var validSettings = new ProviderSettings(storeMap, static _ => null);

        var provider = X509StoreProvider.FromSettings(validSettings);
        await Assert.That(provider.Name).IsEqualTo("store");
        await Assert.That(async () => await provider.GetCertificateAsync(CancellationToken.None)).Throws<ProviderConfigurationException>();
    }

    /// <summary>Creates a self-signed CA certificate for chain testing.</summary>
    /// <param name="rsa">The CA RSA key.</param>
    /// <param name="subject">The distinguished name.</param>
    /// <returns>The self-signed CA certificate.</returns>
    private static X509Certificate2 CreateCaCertificate(RSA rsa, string subject)
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    /// <summary>Creates an intermediate CA certificate issued by <paramref name="issuer"/>.</summary>
    /// <param name="interRsa">The intermediate CA RSA key.</param>
    /// <param name="issuer">The root CA certificate.</param>
    /// <param name="subject">The intermediate CA subject name.</param>
    /// <returns>The intermediate CA certificate with its private key attached.</returns>
    private static X509Certificate2 CreateIntermediateCertificate(RSA interRsa, X509Certificate2 issuer, string subject)
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest(subject, interRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        using var publicInter = request.Create(issuer, now.AddDays(-1), issuer.NotAfter.AddMinutes(-1), LeafSerial);
        return publicInter.CopyWithPrivateKey(interRsa);
    }

    /// <summary>Creates a leaf code-signing certificate issued by <paramref name="issuer"/>.</summary>
    /// <param name="leafRsa">The leaf RSA key.</param>
    /// <param name="issuer">The issuer CA certificate.</param>
    /// <param name="subject">The leaf subject name.</param>
    /// <returns>The leaf certificate with its private key attached.</returns>
    private static X509Certificate2 CreateLeafCertificate(RSA leafRsa, X509Certificate2 issuer, string subject)
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest(subject, leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        using var publicLeaf = request.Create(issuer, now.AddDays(-1), issuer.NotAfter.AddMinutes(-1), LeafSerial);
        return publicLeaf.CopyWithPrivateKey(leafRsa);
    }
}
