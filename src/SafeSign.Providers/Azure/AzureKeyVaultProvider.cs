// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Azure;

/// <summary>
/// Signs digests with the key behind an Azure Key Vault certificate. The certificate and its key identifier come
/// from Get Certificate; the digest is signed with the key Sign operation.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class AzureKeyVaultProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Azure Key Vault options.</summary>
    private readonly AzureKeyVaultOptions _options;

    /// <summary>The clock used for token expiry.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached Entra ID access token.</summary>
    private CachedAccessToken _token;

    /// <summary>The versioned key identifier (<c>kid</c>) returned by the certificate bundle.</summary>
    private string? _keyId;

    /// <summary>The cached certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="AzureKeyVaultProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="time">The clock used for token expiry.</param>
    /// <exception cref="ProviderConfigurationException">Neither a credential nor an access token was given.</exception>
    public AzureKeyVaultProvider(RefitSettings http, AzureKeyVaultOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.Credential is null && options.AccessToken is not { Length: > 0 })
        {
            throw new ProviderConfigurationException("Azure Key Vault needs an Entra ID client credential or an access token.");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "azure-key-vault";

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The certificate bundle had no certificate data or key identifier.</exception>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is not null)
        {
            return _certificate;
        }

        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var bundle = await AzureKeyVaultRequests.GetCertificateAsync(_http, _options, token, _time, cancellationToken).ConfigureAwait(false);
        if (bundle.Cer.IsEmpty || bundle.Kid is not { Length: > 0 })
        {
            throw new ProviderRequestException($"Key Vault certificate '{_options.CertificateName}' has no certificate data or key identifier.");
        }

        var leaf = X509CertificateLoader.LoadCertificate(bundle.Cer.Span);
        var chain = _options.ChainPath is { Length: > 0 } chainPath
            ? CertificateChainOrder.IssuersOf(CertificateFile.Read(await File.ReadAllBytesAsync(chainPath, cancellationToken).ConfigureAwait(false)), leaf)
            : [];
        _keyId = bundle.Kid;
        return _certificate = new(leaf, chain);
    }

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        return await AzureKeyVaultRequests.SignAsync(_http, _keyId!, kind, request, token, _time, cancellationToken).ConfigureAwait(false);
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
            _token = await EntraIdTokens.RequestAsync(_http, _options.Credential!, AzureKeyVaultRequests.Scope, _time, cancellationToken).ConfigureAwait(false);
        }

        return _token.Value;
    }
}
