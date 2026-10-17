// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.SslCom;

/// <summary>Signs digests using the SSL.com eSigner Cloud Signature Consortium (CSC) v1 REST API.</summary>
/// <param name="options">The SSL.com eSigner configuration.</param>
/// <param name="services">The HTTP and clock services.</param>
/// <param name="retry">The optional retry and backoff configuration.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class SslComESignerProvider(
    SslComESignerOptions options,
    ProviderServices services,
    ProviderRetryOptions? retry = null) : ISigningProvider
{
    /// <summary>The default SSL.com eSigner OAuth 2.0 client ID.</summary>
    private const string DefaultClientId = "kaXTRACN8SWsFdR";

    /// <summary>The option and form key for the password.</summary>
    private const string PasswordKey = "password";

    /// <summary>The Refit client for the SSL.com CSC endpoint.</summary>
    private readonly ISslComESignerApi _api = SslComRequests.CreateApi(
        services.Http,
        options.BaseUri ?? SslComRequests.DefaultBaseUri);

    /// <summary>The retry policy.</summary>
    private readonly ProviderRetryOptions _retry = retry ?? ProviderRetryOptions.Default;

    /// <summary>The cached certificate chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>The cached OAuth 2.0 Bearer token.</summary>
    private CachedAccessToken _cachedToken;

    /// <inheritdoc />
    public string Name => "sslcom-esigner";

    /// <summary>Creates an <see cref="SslComESignerProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <param name="services">The HTTP and clock services.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> or <paramref name="services"/> is null.</exception>
    public static SslComESignerProvider FromSettings(ProviderSettings settings, ProviderServices services)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(services);
        var baseUriText = ProviderSettingsReader.Find(settings, "endpoint", "SSLCOM_ENDPOINT");
        var baseUri = baseUriText is not null ? new Uri(baseUriText, UriKind.Absolute) : null;
        var tokenUriText = ProviderSettingsReader.Find(settings, "token-endpoint", "SSLCOM_TOKEN_ENDPOINT");
        var tokenUri = tokenUriText is not null ? new Uri(tokenUriText, UriKind.Absolute) : null;

        return new(
            new(
                ProviderSettingsReader.Require(settings, "credential-id", "SSLCOM_CREDENTIAL_ID"),
                ProviderSettingsReader.Require(settings, "cert-file", "SAFESIGN_CERT_FILE"),
                ProviderSettingsReader.Find(settings, "access-token", "SSLCOM_ACCESS_TOKEN"),
                ProviderSettingsReader.Find(settings, "client-id", "SSLCOM_CLIENT_ID") ?? DefaultClientId,
                ProviderSettingsReader.Find(settings, "username", "SSLCOM_USERNAME"),
                ProviderSettingsReader.Find(settings, PasswordKey, "SSLCOM_PASSWORD"),
                ProviderSettingsReader.Find(settings, "totp-secret", "SSLCOM_TOTP_SECRET"),
                ProviderSettingsReader.Find(settings, "otp", "SSLCOM_OTP"),
                baseUri,
                tokenUri),
            services);
    }

    /// <inheritdoc />
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new(_certificate ??= CertificateFile.Load(options.CertificateFile));
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var cert = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var keyKind = PublicKeyKinds.Of(cert.Certificate);
        var token = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        return await SslComRequests.SignAsync(
            _api,
            options,
            token,
            keyKind,
            request,
            (services.Time, _retry),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Returns a valid OAuth 2.0 Bearer token, requesting one if needed.</summary>
    /// <param name="cancellationToken">Cancels the token request.</param>
    /// <returns>The Bearer token string.</returns>
    /// <exception cref="ProviderConfigurationException">Neither an access token nor username/password is configured.</exception>
    private async ValueTask<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        if (options.AccessToken is { Length: > 0 } explicitToken)
        {
            return explicitToken;
        }

        var now = services.Time.GetUtcNow();
        if (_cachedToken.IsUsable(now))
        {
            return _cachedToken.Value;
        }

        if (options.Username is not { Length: > 0 } username || options.Password is not { Length: > 0 } password)
        {
            throw new ProviderConfigurationException(
                "SSL.com eSigner requires '--provider-option access-token=<token>' or both 'username' and 'password'.");
        }

        var tokenUri = options.OAuthTokenUri ?? SslComRequests.DefaultOAuthTokenUri;
        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["client_id"] = options.ClientId ?? DefaultClientId,
            ["grant_type"] = PasswordKey,
            ["username"] = username,
            [PasswordKey] = password,
        };
        var refreshed = await OAuthTokenClient.RequestAsync(
            services.Http,
            tokenUri,
            form,
            services.Time,
            cancellationToken).ConfigureAwait(false);
        _cachedToken = refreshed;
        return refreshed.Value;
    }
}
