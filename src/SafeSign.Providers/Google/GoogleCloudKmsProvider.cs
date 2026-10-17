// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Google;

/// <summary>
/// Signs digests with a Google Cloud KMS asymmetric key version through <c>asymmetricSign</c>. Authenticates with a
/// service account key (JWT bearer grant) or a pre-acquired access token. The certificate comes from a local file.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class GoogleCloudKmsProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Google Cloud KMS options.</summary>
    private readonly GoogleCloudKmsOptions _options;

    /// <summary>The clock used for token expiry.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached access token.</summary>
    private CachedAccessToken _token;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="GoogleCloudKmsProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="time">The clock used for token expiry.</param>
    /// <exception cref="ProviderConfigurationException">Neither a service account key nor an access token was given.</exception>
    public GoogleCloudKmsProvider(RefitSettings http, GoogleCloudKmsOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.ServiceAccountKeyPath is not { Length: > 0 } && options.AccessToken is not { Length: > 0 })
        {
            throw new ProviderConfigurationException("Google Cloud KMS needs a service account key file or an access token.");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "google-cloud-kms";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken) =>
        ValueTask.FromResult(_certificate ??= CertificateFile.Load(_options.CertificatePath));

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        return await GoogleKmsRequests.SignAsync(_http, _options, request.Digest, request.HashAlgorithm, token, _time, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns the configured token, or a cached or fresh service account token.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The access token.</returns>
    private async ValueTask<string> TokenAsync(CancellationToken cancellationToken)
    {
        if (_options.AccessToken is { Length: > 0 } fixedToken)
        {
            return fixedToken;
        }

        if (!_token.IsUsable(_time.GetUtcNow()))
        {
            var json = await File.ReadAllBytesAsync(_options.ServiceAccountKeyPath!, cancellationToken).ConfigureAwait(false);
            var key = GoogleServiceAccountTokens.ReadKey(json);
            _token = await GoogleServiceAccountTokens.RequestAsync(_http, key, _time, cancellationToken).ConfigureAwait(false);
        }

        return _token.Value;
    }
}
