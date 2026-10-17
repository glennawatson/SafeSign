// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Csc;

/// <summary>Options for <see cref="CscProvider"/> (Cloud Signature Consortium v1 REST API).</summary>
/// <param name="Endpoint">The CSC v1 base URL (for example, <c>https://service.example.com/csc/v1</c>).</param>
/// <param name="CredentialId">The CSC credential identifier.</param>
/// <param name="AccessToken">The OAuth 2.0 Bearer access token.</param>
[DebuggerDisplay("{CredentialId,nq} at {Endpoint}")]
public sealed record CscOptions(Uri Endpoint, string CredentialId, string AccessToken)
{
    /// <summary>Gets an optional local certificate file path used instead of calling <c>credentials/info</c>.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Gets an optional pre-authorized Signature Activation Data (SAD) token.</summary>
    public string? Sad { get; init; }

    /// <summary>Gets an optional credential PIN for <c>credentials/authorize</c>.</summary>
    public string? Pin { get; init; }

    /// <summary>Gets an optional one-time password for <c>credentials/authorize</c>.</summary>
    public string? Otp { get; init; }

    /// <summary>Gets an optional RFC 6238 TOTP Base32 secret or <c>otpauth://</c> URI used to generate the <c>credentials/authorize</c> OTP.</summary>
    public string? TotpSecret { get; init; }

    /// <summary>Reads <see cref="CscOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static CscOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Require(settings, "endpoint", "CSC_ENDPOINT");
        return new(
            new Uri(endpointText, UriKind.Absolute),
            ProviderSettingsReader.Require(settings, "credential-id", "CSC_CREDENTIAL_ID"),
            ProviderSettingsReader.Require(settings, "access-token", "CSC_ACCESS_TOKEN"))
        {
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "CSC_CERT_FILE"),
            Sad = ProviderSettingsReader.Find(settings, "sad", "CSC_SAD"),
            Pin = ProviderSettingsReader.Find(settings, "pin", "CSC_PIN"),
            Otp = ProviderSettingsReader.Find(settings, "otp", "CSC_OTP"),
            TotpSecret = ProviderSettingsReader.Find(settings, "totp-secret", "otp-uri", "CSC_TOTP_SECRET", "CSC_OTP_URI"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"CscOptions {{ Endpoint = {Endpoint}, CredentialId = {CredentialId}, CertificateFile = {CertificateFile} }}";
}
