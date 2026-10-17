// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing.Tests;

/// <summary>An in-memory RSA key with a self-signed code signing certificate, standing in for a remote provider.</summary>
[DebuggerDisplay("{Name,nq}")]
internal sealed class TestRsaSigningProvider : ISigningProvider, IDisposable
{
    /// <summary>The test key size.</summary>
    private const int KeySize = 3072;

    /// <summary>The code signing extended key usage.</summary>
    private const string CodeSigningUsage = "1.3.6.1.5.5.7.3.3";

    /// <summary>The byte mask used to corrupt a signature byte.</summary>
    private const byte CorruptionMask = 0xFF;

    /// <summary>The key.</summary>
    private readonly RSA _key = RSA.Create(KeySize);

    /// <summary>Initializes a new instance of the <see cref="TestRsaSigningProvider"/> class.</summary>
    internal TestRsaSigningProvider()
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest("CN=SafeSign Test Publisher, O=SafeSign Tests", _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new(CodeSigningUsage)], critical: false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var withKey = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        Certificate = X509CertificateLoader.LoadCertificate(withKey.RawDataMemory.Span);
    }

    /// <inheritdoc/>
    public string Name => "test-rsa";

    /// <summary>Gets the public certificate.</summary>
    internal X509Certificate2 Certificate { get; }

    /// <summary>Gets or sets a value indicating whether the provider returns a corrupted signature.</summary>
    internal bool Corrupt { get; set; }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(new SigningCertificate(Certificate, []));

    /// <inheritdoc/>
    public ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var signature = _key.SignHash(request.Digest.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
        if (Corrupt)
        {
            signature[0] ^= CorruptionMask;
        }

        return ValueTask.FromResult(signature);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _key.Dispose();
        Certificate.Dispose();
    }
}
