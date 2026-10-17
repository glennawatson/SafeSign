// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Signing;

namespace SafeSign.Benchmarks;

/// <summary>An in-memory RSA-2048 <see cref="ISigningProvider"/> for benchmarks and allocation audits.</summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class BenchmarkSigningProvider : ISigningProvider, IDisposable
{
    /// <summary>The RSA key size in bits.</summary>
    private const int RsaKeySizeBits = 2048;

    /// <summary>The clock skew allowance in minutes for self-signed certificates.</summary>
    private const int CertSkewMinutes = -5;

    /// <summary>The backing RSA key pair.</summary>
    private readonly RSA _rsa;

    /// <summary>The cached <see cref="SigningCertificate"/> wrapper.</summary>
    private readonly SigningCertificate _signingCertificate;

    /// <summary>The atomic disposal flag.</summary>
    private int _disposed;

    /// <summary>Initializes a new instance of the <see cref="BenchmarkSigningProvider"/> class.</summary>
    public BenchmarkSigningProvider()
    {
        var (rsa, cert) = CreateSharedKeyAndCertificate();
        _rsa = rsa;
        _signingCertificate = cert;
    }

    /// <inheritdoc/>
    public string Name => "benchmark-rsa";

    /// <summary>Gets the cached <see cref="SigningCertificate"/> without async overhead.</summary>
    public SigningCertificate SigningCertificate => _signingCertificate;

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(_signingCertificate);

    /// <summary>Releases the signing key and certificate.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _rsa.Dispose();
        _signingCertificate.Certificate.Dispose();
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        var signature = _rsa.SignHash(request.Digest.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
        return ValueTask.FromResult(signature);
    }

    /// <summary>Creates the shared RSA-2048 key and self-signed code-signing certificate.</summary>
    /// <returns>The RSA key and <see cref="SigningCertificate"/>.</returns>
    private static BenchmarkSigningMaterial CreateSharedKeyAndCertificate()
    {
        var rsa = RSA.Create(RsaKeySizeBits);
        var req = new CertificateRequest("CN=SafeSign Benchmark Signer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3")], false));
        var now = TimeProvider.System.GetUtcNow();
        using var fullCert = req.CreateSelfSigned(now.AddMinutes(CertSkewMinutes), now.AddDays(1));
        var certificate = X509CertificateLoader.LoadCertificate(fullCert.RawData);
        return new(rsa, new(certificate, []));
    }
}
