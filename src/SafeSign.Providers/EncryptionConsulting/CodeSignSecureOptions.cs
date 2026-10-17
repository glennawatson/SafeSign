// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Options for <see cref="CodeSignSecureProvider"/> (Encryption Consulting CodeSign Secure).</summary>
/// <param name="CertificateName">The certificate key name in CodeSign Secure.</param>
[DebuggerDisplay("{CertificateName,nq} at {Endpoint}")]
public sealed record CodeSignSecureOptions(string CertificateName)
{
    /// <summary>Gets the default Encryption Consulting CodeSign Secure endpoint URI.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://codesignsecure.encryptionconsulting.com");

    /// <summary>Gets the CodeSign Secure endpoint URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets the login username used with <c>/api/auth/GetLoginToken/</c>.</summary>
    public string? Username { get; init; }

    /// <summary>Gets the login password/secret used with <c>/api/auth/GetLoginToken/</c>.</summary>
    public string? Password { get; init; }

    /// <summary>Gets a pre-acquired JWT bearer token used instead of <see cref="Username"/> and <see cref="Password"/>.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets an optional local certificate file path used instead of fetching the certificate from CodeSign Secure.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Gets an optional PKCS #12 client certificate file for mutual TLS.</summary>
    public string? ClientCertificateFile { get; init; }

    /// <summary>Gets the optional password for <see cref="ClientCertificateFile"/>.</summary>
    public string? ClientCertificatePassword { get; init; }

    /// <summary>Reads <see cref="CodeSignSecureOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static CodeSignSecureOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "CODESIGNSECURE_ENDPOINT");
        return new(ProviderSettingsReader.Require(settings, "cert-name", "CODESIGNSECURE_CERT_NAME"))
        {
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            Username = ProviderSettingsReader.Find(settings, "username", "CODESIGNSECURE_USERNAME"),
            Password = ProviderSettingsReader.Find(settings, "password", "CODESIGNSECURE_PASSWORD"),
            AccessToken = ProviderSettingsReader.Find(settings, "access-token", "CODESIGNSECURE_ACCESS_TOKEN"),
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "CODESIGNSECURE_CERT_FILE"),
            ClientCertificateFile = ProviderSettingsReader.Find(settings, "client-cert-file", "CODESIGNSECURE_CLIENT_CERT_FILE"),
            ClientCertificatePassword = ProviderSettingsReader.Find(settings, "client-cert-password", "CODESIGNSECURE_CLIENT_CERT_PASSWORD"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"CodeSignSecureOptions {{ Endpoint = {Endpoint}, CertificateName = {CertificateName}, Username = {Username} }}";
}
