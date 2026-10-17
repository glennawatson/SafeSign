// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using Refit;
using SafeSign.Providers.Azure;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>
/// Signs digests with an Azure Artifact Signing certificate profile. Retrieves the PKCS #7 certificate chain from
/// <c>/sign/certchain</c> and signs digests via the asynchronous <c>/sign</c> and <c>/sign/{operationId}</c> REST endpoints.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class AzureArtifactSigningProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Azure Artifact Signing options.</summary>
    private readonly AzureArtifactSigningOptions _options;

    /// <summary>The clock used for token expiry and polling delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached Entra ID access token.</summary>
    private CachedAccessToken _token;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="AzureArtifactSigningProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Azure Artifact Signing options.</param>
    /// <param name="time">The clock used for token expiry and polling delays.</param>
    /// <exception cref="ProviderConfigurationException">Neither a credential nor an access token was given.</exception>
    public AzureArtifactSigningProvider(RefitSettings http, AzureArtifactSigningOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.Credential is null && options.AccessToken is not { Length: > 0 })
        {
            throw new ProviderConfigurationException("Azure Artifact Signing needs an Entra ID client credential or an access token.");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "azure-artifact-signing";

    /// <inheritdoc/>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is not null)
        {
            return _certificate;
        }

        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        return _certificate = await AzureArtifactSigningRequests.GetCertificateChainAsync(_http, _options, token, _time, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        return await AzureArtifactSigningRequests.SignAsync(_http, _options, kind, request, token, _time, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns the configured token, or a cached or fresh client-credentials token.</summary>
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
            _token = await EntraIdTokens.RequestAsync(_http, _options.Credential!, AzureArtifactSigningRequests.Scope, _time, cancellationToken).ConfigureAwait(false);
        }

        return _token.Value;
    }
}
