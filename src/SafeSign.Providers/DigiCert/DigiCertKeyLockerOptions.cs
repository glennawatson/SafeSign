// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Options for <see cref="DigiCertKeyLockerProvider"/> (DigiCert ONE / DigiCert KeyLocker).</summary>
/// <param name="ApiKey">The DigiCert ONE API key sent in the <c>x-api-key</c> request header.</param>
[DebuggerDisplay("{CertificateAlias ?? CertificateId ?? KeypairId,nq} at {Endpoint}")]
public sealed record DigiCertKeyLockerOptions(string ApiKey)
{
    /// <summary>Gets the default DigiCert ONE client-authenticated endpoint URI.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://clientauth.one.digicert.com");

    /// <summary>Gets the DigiCert ONE endpoint URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets the certificate alias looked up via <c>/signingmanager/api/v1/certificates?alias=...</c>.</summary>
    public string? CertificateAlias { get; init; }

    /// <summary>Gets the certificate identifier looked up via <c>/signingmanager/api/v1/certificates?id=...</c>.</summary>
    public string? CertificateId { get; init; }

    /// <summary>Gets an explicit keypair identifier for <c>/signingmanager/api/v1/keypairs/{keypairId}/sign</c> when not resolved from the certificate item.</summary>
    public string? KeypairId { get; init; }

    /// <summary>Gets an optional local certificate file path used instead of fetching the certificate from DigiCert ONE.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Gets the optional PKCS #12 (<c>.p12</c>/<c>.pfx</c>) client certificate file for mutual TLS authentication.</summary>
    public string? ClientCertificateFile { get; init; }

    /// <summary>Gets the optional password for <see cref="ClientCertificateFile"/>.</summary>
    public string? ClientCertificatePassword { get; init; }

    /// <summary>Reads <see cref="DigiCertKeyLockerOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static DigiCertKeyLockerOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "DIGICERT_ENDPOINT");
        return new(ProviderSettingsReader.Require(settings, "api-key", "DIGICERT_API_KEY"))
        {
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            CertificateAlias = ProviderSettingsReader.Find(settings, "cert-alias", "DIGICERT_CERT_ALIAS"),
            CertificateId = ProviderSettingsReader.Find(settings, "cert-id", "DIGICERT_CERT_ID"),
            KeypairId = ProviderSettingsReader.Find(settings, "keypair-id", "DIGICERT_KEYPAIR_ID"),
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "DIGICERT_CERT_FILE"),
            ClientCertificateFile = ProviderSettingsReader.Find(settings, "client-cert-file", "DIGICERT_CLIENT_CERT_FILE"),
            ClientCertificatePassword = ProviderSettingsReader.Find(settings, "client-cert-password", "DIGICERT_CLIENT_CERT_PASSWORD"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"DigiCertKeyLockerOptions {{ Endpoint = {Endpoint}, CertificateAlias = {CertificateAlias}, CertificateId = {CertificateId} }}";
}
