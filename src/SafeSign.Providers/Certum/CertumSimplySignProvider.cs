// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Certum;

/// <summary>
/// Signs digests in the cloud through Certum SimplySign (<c>cloudsign.webnotarius.pl</c>) using pure HTTPS
/// (CAS OAuth 2.0 + SCS1_ATOM asynchronous card/certificate/signature tasks), with no PKCS #11 library or
/// SimplySign Desktop GUI required.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class CertumSimplySignProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Certum SimplySign options.</summary>
    private readonly CertumOptions _options;

    /// <summary>The clock used for TOTP generation, token expiry, and task polling.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached OAuth 2.0 bearer access token.</summary>
    private CachedAccessToken _token;

    /// <summary>The cached materialized virtual card and certificate.</summary>
    private CertumMaterializedCard? _card;

    /// <summary>Initializes a new instance of the <see cref="CertumSimplySignProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="time">The clock.</param>
    public CertumSimplySignProvider(RefitSettings http, CertumOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "certum";

    /// <inheritdoc/>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        var card = await GetMaterializedCardAsync(cancellationToken).ConfigureAwait(false);
        return card.SigningCertificate;
    }

    /// <inheritdoc/>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);
        var card = _card ??= await CertumRequests.MaterializeCardAsync(_http, _options, token, _time, cancellationToken).ConfigureAwait(false);
        return await CertumRequests.SignDigestAsync(_http, _options, card, request, token, _time, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns the cached materialized card, fetching it when not yet loaded.</summary>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The materialized card.</returns>
    public async ValueTask<CertumMaterializedCard> GetMaterializedCardAsync(CancellationToken cancellationToken)
    {
        if (_card is { } cached)
        {
            return cached;
        }

        var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);
        var materialized = await CertumRequests.MaterializeCardAsync(_http, _options, token, _time, cancellationToken).ConfigureAwait(false);
        _card = materialized;
        return materialized;
    }

    /// <summary>Returns a usable bearer access token, logging in or refreshing when expired.</summary>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The bearer token string.</returns>
    private async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (_token.IsUsable(_time.GetUtcNow()))
        {
            return _token.Value;
        }

        _token = await CertumRequests.AcquireTokenAsync(_http, _options, _token.RefreshToken, _time, cancellationToken).ConfigureAwait(false);
        return _token.Value;
    }
}
