// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing.Tests;

/// <summary>An in-memory ECDSA P-256 key with a self-signed code signing certificate.</summary>
[DebuggerDisplay("{Name,nq}")]
internal sealed class TestEcdsaSigningProvider : ISigningProvider, IDisposable
{
    /// <summary>The code signing extended key usage.</summary>
    private const string CodeSigningUsage = "1.3.6.1.5.5.7.3.3";

    /// <summary>The ECDSA key.</summary>
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Initializes a new instance of the <see cref="TestEcdsaSigningProvider"/> class.</summary>
    internal TestEcdsaSigningProvider()
    {
        var now = TimeProvider.System.GetUtcNow();
        var request = new CertificateRequest("CN=SafeSign ECDSA Test Publisher", _key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new(CodeSigningUsage)], critical: false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var withKey = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        Certificate = X509CertificateLoader.LoadCertificate(withKey.RawDataMemory.Span);
    }

    /// <inheritdoc/>
    public string Name => "test-ecdsa";

    /// <summary>Gets the public certificate.</summary>
    internal X509Certificate2 Certificate { get; }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(new SigningCertificate(Certificate, []));

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken) =>
        ValueTask.FromResult(_key.SignHash(request.Digest.Span, DSASignatureFormat.Rfc3279DerSequence));

    /// <inheritdoc/>
    public void Dispose()
    {
        _key.Dispose();
        Certificate.Dispose();
    }
}
