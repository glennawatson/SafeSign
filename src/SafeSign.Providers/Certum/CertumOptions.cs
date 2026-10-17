// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Certum;

/// <summary>
/// Configuration for signing through Certum SimplySign (<c>cloudsign.webnotarius.pl</c>) using either
/// CAS OAuth 2.0 login (email + 6-digit OTP or TOTP seed), a refresh token, or an existing bearer access token.
/// </summary>
[DebuggerDisplay("{Email,nq} @ {Endpoint}")]
public sealed record CertumOptions
{
    /// <summary>Gets the default Certum SimplySign cloud host.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://cloudsign.webnotarius.pl/");

    /// <summary>Gets the default public OAuth 2.0 client identifier used by SimplySign Desktop.</summary>
    public static string DefaultClientId => "44rvDKKEWY53a7xBeF5w";

    /// <summary>Gets the default public OAuth 2.0 client secret used by SimplySign Desktop.</summary>
    public static string DefaultClientSecret => "BRSE2u2nY3p3m77QHTt8";

    /// <summary>Gets the Certum SimplySign account email address (used for CAS login).</summary>
    public string? Email { get; init; }

    /// <summary>Gets a single-use 6-digit OTP code from the SimplySign mobile app (used when <see cref="TotpSecret"/> is not set).</summary>
    public string? OtpCode { get; init; }

    /// <summary>Gets the Base32 TOTP secret or <c>otpauth://</c> URI used to compute 6-digit OTP codes automatically.</summary>
    public string? TotpSecret { get; init; }

    /// <summary>Gets a pre-obtained OAuth 2.0 bearer access token.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets an OAuth 2.0 refresh token used to mint new access tokens without CAS login.</summary>
    public string? RefreshToken { get; init; }

    /// <summary>Gets the optional virtual card serial (<c>cardno</c>) to select when the account holds multiple cards.</summary>
    public string? CardSerial { get; init; }

    /// <summary>Gets an optional path to a PEM, DER, or PKCS #7 file containing intermediate issuer certificates.</summary>
    public string? AdditionalCertificatesPath { get; init; }

    /// <summary>Gets the SimplySign cloud service base URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets the OAuth 2.0 client identifier.</summary>
    public string ClientId { get; init; } = DefaultClientId;

    /// <summary>Gets the OAuth 2.0 client secret.</summary>
    public string ClientSecret { get; init; } = DefaultClientSecret;

    /// <summary>Gets an optional override for the delay between async task polls (used for testing).</summary>
    public TimeSpan? TaskPollDelay { get; init; }

    /// <summary>Gets the exponential backoff, fuzzy jitter, and poll interval policy.</summary>
    public ProviderRetryOptions RetryOptions { get; init; } = ProviderRetryOptions.Default;

    /// <summary>Reads options from <see cref="ProviderSettings"/>.</summary>
    /// <param name="settings">The provider settings and environment lookup.</param>
    /// <returns>The validated options.</returns>
    /// <exception cref="ProviderConfigurationException">No usable authentication method was supplied.</exception>
    public static CertumOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var email = ProviderSettingsReader.Find(settings, "email", "CERTUM_SIMPLYSIGN_EMAIL", "CERTUM_USER_ID");
        var otpCode = ProviderSettingsReader.Find(settings, "otp", "CERTUM_SIMPLYSIGN_OTP");
        var totpSecret = ProviderSettingsReader.Find(settings, "totp-secret", "CERTUM_SIMPLYSIGN_TOTP_SECRET", "CERTUM_OTP_URI");
        var accessToken = ProviderSettingsReader.Find(settings, "access-token", "CERTUM_SIMPLYSIGN_ACCESS_TOKEN");
        var refreshToken = ProviderSettingsReader.Find(settings, "refresh-token", "CERTUM_SIMPLYSIGN_REFRESH_TOKEN");

        if (string.IsNullOrWhiteSpace(accessToken)
            && string.IsNullOrWhiteSpace(refreshToken)
            && (string.IsNullOrWhiteSpace(email) || (string.IsNullOrWhiteSpace(otpCode) && string.IsNullOrWhiteSpace(totpSecret))))
        {
            throw new ProviderConfigurationException(
                "Provider 'certum' requires 'access-token', 'refresh-token', or 'email' with 'totp-secret' or 'otp'.");
        }

        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "CERTUM_SIMPLYSIGN_ENDPOINT");
        return new()
        {
            Email = email,
            OtpCode = otpCode,
            TotpSecret = totpSecret,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            CardSerial = ProviderSettingsReader.Find(settings, "card-serial", "CERTUM_SIMPLYSIGN_CARD_SERIAL"),
            AdditionalCertificatesPath = ProviderSettingsReader.Find(settings, "certificate-chain-path", "CERTUM_SIMPLYSIGN_CERTIFICATE_CHAIN_PATH"),
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            ClientId = ProviderSettingsReader.Find(settings, "client-id", "CERTUM_SIMPLYSIGN_CLIENT_ID") ?? DefaultClientId,
            ClientSecret = ProviderSettingsReader.Find(settings, "client-secret", "CERTUM_SIMPLYSIGN_CLIENT_SECRET") ?? DefaultClientSecret,
        };
    }

    /// <inheritdoc/>
    public override string ToString() => $"CertumOptions {{ Email = {Email}, Endpoint = {Endpoint}, CardSerial = {CardSerial} }}";
}
