// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Refit.Testing;
using SafeSign.Formats;
using SafeSign.Formats.Scripts;
using SafeSign.Providers;
using SafeSign.Providers.Local;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Tests;

/// <summary>Verifies <see cref="SafeSignCli"/> and <see cref="SignRunner"/> end-to-end across subcommands, providers, and file formats.</summary>
public sealed class SafeSignCliTests
{
    /// <summary>The RSA key size in bits for test certificates.</summary>
    private const int RsaKeySize = 2048;

    /// <summary>The random secret length in bytes.</summary>
    private const int RandomSecretBytes = 16;

    /// <summary>The clock skew allowance in minutes for self-signed certificates.</summary>
    private const int CertValidSkewMinutes = -5;

    /// <summary>The <c>--hash</c> CLI option name.</summary>
    private const string HashOptionFlag = "--hash";

    /// <summary>Verifies that <c>safesign providers</c> lists every registered provider in <see cref="ProviderCatalog.All"/>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ProvidersSubcommand_ListsAllCatalogProviders()
    {
        await using var stdout = new StringWriter();
        await using var stderr = new StringWriter();

        var exitCode = await SafeSignCli.RunAsync(["providers"], stdout, stderr, CancellationToken.None);
        var text = stdout.ToString();

        await Assert.That(exitCode).IsEqualTo(0);
        await Assert.That(stderr.ToString()).IsEmpty();

        var allProviders = ProviderCatalog.All;
        for (var i = 0; i < allProviders.Length; i++)
        {
            await Assert.That(text).Contains(allProviders[i].Name);
        }
    }

    /// <summary>Verifies that <c>safesign formats</c> lists every format in <see cref="FormatCatalog.All"/> including out-of-scope Debian packages.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task FormatsSubcommand_ListsAllCatalogFormats()
    {
        await using var stdout = new StringWriter();
        await using var stderr = new StringWriter();

        var exitCode = await SafeSignCli.RunAsync(["formats"], stdout, stderr, CancellationToken.None);
        var text = stdout.ToString();

        await Assert.That(exitCode).IsEqualTo(0);
        await Assert.That(stderr.ToString()).IsEmpty();

        var allFormats = FormatCatalog.All;
        for (var i = 0; i < allFormats.Length; i++)
        {
            await Assert.That(text).Contains(allFormats[i].Id);
        }

        await Assert.That(text).Contains("OutOfScope");
    }

    /// <summary>Verifies that <c>safesign sign</c> signs a PowerShell script using a local PFX certificate bundle.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignSubcommand_WithFileProvider_SignsScriptFilesAndWritesOutput()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-cli-file-");
        try
        {
            var password = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var pfxPath = Path.Combine(tempDir.FullName, "code-signing.pfx");
            using (var rsa = RSA.Create(RsaKeySize))
            using (var cert = CreateCodeSigningCertificate(rsa))
            {
                await File.WriteAllBytesAsync(pfxPath, cert.Export(X509ContentType.Pfx, password));
            }

            var scriptPath = Path.Combine(tempDir.FullName, "deploy.ps1");
            var signedScriptPath = Path.Combine(tempDir.FullName, "deploy-signed.ps1");
            await File.WriteAllTextAsync(scriptPath, "Write-Host 'Hello from SafeSign'\r\n", Encoding.UTF8);

            await using var stdout = new StringWriter();
            await using var stderr = new StringWriter();

            var args = new[]
            {
                "sign",
                scriptPath,
                "--provider",
                "file",
                "--provider-option",
                $"cert-file={pfxPath}",
                $"password={password}",
                "--output",
                signedScriptPath,
                HashOptionFlag,
                "SHA256",
                "--description",
                "SafeSign Deployment Script",
                "--description-url",
                "https://github.com/glennawatson/SafeSign",
            };

            var exitCode = await SafeSignCli.RunAsync(args, stdout, stderr, CancellationToken.None);
            await Assert.That(exitCode).IsEqualTo(0);
            await Assert.That(stderr.ToString()).IsEmpty();
            await Assert.That(stdout.ToString()).Contains(signedScriptPath);

            var signedContent = await File.ReadAllTextAsync(signedScriptPath, Encoding.UTF8);
            await Assert.That(signedContent).Contains("# SIG # Begin signature block");
            await Assert.That(signedContent).Contains("# SIG # End signature block");
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <c>safesign sign</c> signs a script in-place via a cloud provider (<c>digicert-keylocker</c>) backed by <see cref="StubHttp"/>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignSubcommand_WithCloudProviderStubHttp_SignsFileInPlace()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-cli-cloud-");
        try
        {
            using var rsa = RSA.Create(RsaKeySize);
            using var cert = CreateCodeSigningCertificate(rsa);
            var certBase64 = Convert.ToBase64String(cert.RawData);

            const string scriptContent = "WScript.Echo \"SafeSign\"\r\n";
            var scriptPath = Path.Combine(tempDir.FullName, "install.vbs");
            await File.WriteAllTextAsync(scriptPath, scriptContent, Encoding.UTF8);

            var sigBase64 = await ComputeExpectedVbsSignatureBase64Async(tempDir.FullName, cert, scriptContent);

            using var http = new StubHttp
            {
                {
                    Route.Get("/signingmanager/api/v1/certificates"),
                    Reply.Json($$$"""{"items":[{"id":"cert-1","alias":"ci-cert","cert":"{{{certBase64}}}","account":{"id":"acct-1"},"keypair":{"id":"kp-1"}}]}""")
                },
                {
                    Route.Post("/signingmanager/api/v1/keypairs/kp-1/sign"),
                    Reply.Json($$"""{"signature":"{{sigBase64}}"}""")
                },
            };

            var apiKey = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
            var services = new ProviderServices(http.ToSettings(), TimeProvider.System);
            await using var stdout = new StringWriter();
            await using var stderr = new StringWriter();

            var args = new[]
            {
                "sign",
                scriptPath,
                "-p",
                "digicert-keylocker",
                "-o",
                $"api-key={apiKey}",
                "-o",
                "cert-alias=ci-cert",
                HashOptionFlag,
                "SHA384",
            };

            var exitCode = await SafeSignCli.RunAsync(args, stdout, stderr, services, static _ => null, CancellationToken.None);
            await Assert.That(stderr.ToString()).IsEmpty();
            await Assert.That(exitCode).IsEqualTo(0);

            var signedText = await File.ReadAllTextAsync(scriptPath, Encoding.UTF8);
            await Assert.That(signedText).Contains("'' SIG '' Begin signature block");
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <c>safesign sign</c> rejects unknown providers and malformed options with exit code 1.</summary>
    /// <param name="providerName">The provider name to pass.</param>
    /// <param name="optionEntry">The provider option entry to pass.</param>
    /// <param name="hashAlgorithm">The hash algorithm to pass.</param>
    /// <param name="fileName">The test file name.</param>
    /// <param name="expectedErrorFragment">The expected diagnostic substring in standard error.</param>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    [Arguments("unknown-provider", "cert-file=a.pfx", "SHA256", "sample.ps1", "Unknown signing provider")]
    [Arguments("file", "invalid-option-without-equals", "SHA256", "sample.ps1", "Expected 'name=value'")]
    [Arguments("file", "cert-file=a.pfx", "MD5", "sample.ps1", "Unsupported digest algorithm")]
    public async Task SignSubcommand_WithInvalidArguments_ReturnsExitFailure(
        string providerName,
        string optionEntry,
        string hashAlgorithm,
        string fileName,
        string expectedErrorFragment)
    {
        await using var stdout = new StringWriter();
        await using var stderr = new StringWriter();

        var args = new[]
        {
            "sign",
            fileName,
            "--provider",
            providerName,
            "--provider-option",
            optionEntry,
            HashOptionFlag,
            hashAlgorithm,
        };

        var exitCode = await SafeSignCli.RunAsync(args, stdout, stderr, CancellationToken.None);
        await Assert.That(exitCode).IsEqualTo(1);
        await Assert.That(stderr.ToString()).Contains(expectedErrorFragment);
    }

    /// <summary>Computes the expected base64-encoded RSA-SHA384 signature over the VBScript Authenticode signed attributes.</summary>
    /// <param name="tempDir">The temporary directory path.</param>
    /// <param name="cert">The signing certificate with private key.</param>
    /// <param name="scriptContent">The VBScript content.</param>
    /// <returns>The base64-encoded PKCS #1 v1.5 signature.</returns>
    private static async ValueTask<string> ComputeExpectedVbsSignatureBase64Async(string tempDir, X509Certificate2 cert, string scriptContent)
    {
        var pfxPath = Path.Combine(tempDir, "helper.pfx");
        var password = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomSecretBytes));
        await File.WriteAllBytesAsync(pfxPath, cert.Export(X509ContentType.Pfx, password));

        _ = ScriptFileSigner.TryGetFormat(".vbs", out var vbsFormat);
        var fileDigest = SHA384.HashData([.. Encoding.Unicode.GetBytes(scriptContent), .. BitConverter.GetBytes(scriptContent.Length)]);
        var provider = new LocalCertificateProvider(new(pfxPath, password));
        var signingCert = await provider.GetCertificateAsync(CancellationToken.None);
        var session = new SigningSession(provider, signingCert, HashAlgorithmName.SHA384, null, null, null, TimeProvider.System);
        var cmsBytes = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(vbsFormat.SipVersion, vbsFormat.SipGuid), fileDigest),
            CancellationToken.None);

        var signedCms = new SignedCms();
        signedCms.Decode(cmsBytes);
        return Convert.ToBase64String(signedCms.SignerInfos[0].GetSignature());
    }

    /// <summary>Creates a self-signed RSA code-signing certificate with the Code Signing EKU.</summary>
    /// <param name="rsa">The RSA key pair.</param>
    /// <returns>The created <see cref="X509Certificate2"/>.</returns>
    private static X509Certificate2 CreateCodeSigningCertificate(RSA rsa)
    {
        var req = new CertificateRequest("CN=SafeSign CLI Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3")], false));
        var now = TimeProvider.System.GetUtcNow();
        return req.CreateSelfSigned(now.AddMinutes(CertValidSkewMinutes), now.AddDays(1));
    }
}
