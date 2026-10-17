// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Venafi;

/// <summary>Options for <see cref="VenafiProvider"/> (Venafi CodeSign Protect <c>vedhsm</c> REST API).</summary>
/// <param name="Endpoint">The Venafi Trust Protection Platform base URL.</param>
/// <param name="KeyLabel">The Venafi certificate/key environment label.</param>
[DebuggerDisplay("{KeyLabel,nq} at {Endpoint}")]
public sealed record VenafiOptions(Uri Endpoint, string KeyLabel)
{
    /// <summary>Gets an optional explicit Venafi HSM KeyId.</summary>
    public string? KeyId { get; init; }

    /// <summary>Gets an optional pre-acquired OAuth bearer token.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets an optional username for OAuth password grant authentication.</summary>
    public string? Username { get; init; }

    /// <summary>Gets an optional password for OAuth password grant authentication.</summary>
    public string? Password { get; init; }

    /// <summary>Gets an optional local certificate file path.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Reads <see cref="VenafiOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static VenafiOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Require(settings, "endpoint", "VENAFI_ENDPOINT");
        return new(
            new Uri(endpointText, UriKind.Absolute),
            ProviderSettingsReader.Require(settings, "key-label", "VENAFI_KEY_LABEL"))
        {
            KeyId = ProviderSettingsReader.Find(settings, "key-id", "VENAFI_KEY_ID"),
            AccessToken = ProviderSettingsReader.Find(settings, "access-token", "VENAFI_ACCESS_TOKEN"),
            Username = ProviderSettingsReader.Find(settings, "username", "VENAFI_USERNAME"),
            Password = ProviderSettingsReader.Find(settings, "password", "VENAFI_PASSWORD"),
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "VENAFI_CERT_FILE"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"VenafiOptions {{ Endpoint = {Endpoint}, KeyLabel = {KeyLabel}, KeyId = {KeyId} }}";
}
