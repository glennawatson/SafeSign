// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Aws;

/// <summary>
/// Signs digests with an asymmetric AWS KMS key through the KMS <c>Sign</c> API (<c>MessageType=DIGEST</c>),
/// authenticated with Signature Version 4. The certificate comes from a local file.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class AwsKmsProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The AWS KMS options.</summary>
    private readonly AwsKmsOptions _options;

    /// <summary>The clock used to date requests.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="AwsKmsProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="time">The clock used to date requests.</param>
    public AwsKmsProvider(RefitSettings http, AwsKmsOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "aws-kms";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(_certificate ??= CertificateFile.Load(_options.CertificatePath));

    /// <inheritdoc/>
    public ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = _certificate ??= CertificateFile.Load(_options.CertificatePath);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        return AwsKmsRequests.SignAsync(_http, _options, kind, request, _time.GetUtcNow(), _time, cancellationToken);
    }
}
