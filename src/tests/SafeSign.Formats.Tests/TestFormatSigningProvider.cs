// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Signing;

namespace SafeSign.Formats.Tests;

/// <summary>An in-memory RSA signing provider used across <c>SafeSign.Formats.Tests</c>.</summary>
[DebuggerDisplay("{Name,nq}")]
internal sealed class TestFormatSigningProvider : ISigningProvider, IDisposable
{
    /// <summary>The RSA key size in bits.</summary>
    private const int KeySize = 2048;

    /// <summary>The code signing extended key usage OID.</summary>
    private const string CodeSigningUsage = "1.3.6.1.5.5.7.3.3";

    /// <summary>The RSA key pair.</summary>
    private readonly RSA _key = RSA.Create(KeySize);

    /// <summary>Initializes a new instance of the <see cref="TestFormatSigningProvider"/> class.</summary>
    internal TestFormatSigningProvider()
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest("CN=SafeSign Formats Test Signer, O=SafeSign", _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new(CodeSigningUsage)], critical: false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var withKey = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        Certificate = X509CertificateLoader.LoadCertificate(withKey.RawDataMemory.Span);
    }

    /// <inheritdoc/>
    public string Name => "test-formats-rsa";

    /// <summary>Gets the public signing certificate.</summary>
    internal X509Certificate2 Certificate { get; }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(new SigningCertificate(Certificate, []));

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_key.SignHash(request.Digest.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1));

    /// <inheritdoc/>
    public void Dispose()
    {
        _key.Dispose();
        Certificate.Dispose();
    }

    /// <summary>Creates a <see cref="SigningSession"/> using SHA-256 and this provider.</summary>
    /// <returns>The signing session.</returns>
    internal SigningSession CreateSession() =>
        new(
            this,
            new(Certificate, []),
            HashAlgorithmName.SHA256,
            Timestamp: null,
            Description: "SafeSign Test Package",
            DescriptionUrl: new("https://safesign.example.com"),
            TimeProvider.System);

    /// <summary>Verifies an RSA PKCS #1 v1.5 SHA-256 signature against this provider's key.</summary>
    /// <param name="digest">The SHA-256 digest.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>True when the signature is valid.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal bool VerifySha256Digest(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature) =>
        _key.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}
