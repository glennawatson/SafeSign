// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Fortanix;

/// <summary>Options for <see cref="FortanixDsmProvider"/> (Fortanix Data Security Manager REST API).</summary>
/// <param name="KeyId">The Fortanix DSM security object UUID (<c>kid</c>).</param>
/// <param name="CertificateFile">The path to the DER or PEM certificate file.</param>
[DebuggerDisplay("{KeyId,nq} at {Endpoint}")]
public sealed record FortanixDsmOptions(string KeyId, string CertificateFile)
{
    /// <summary>Gets the default Fortanix DSM endpoint URI.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://apps.smartkey.io");

    /// <summary>Gets the Fortanix DSM endpoint URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets the optional Basic Auth API key used for <c>POST /sys/v1/session/auth</c>.</summary>
    public string? ApiKey { get; init; }

    /// <summary>Gets an optional pre-acquired Bearer access token.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Reads <see cref="FortanixDsmOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static FortanixDsmOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "FORTANIX_ENDPOINT");
        return new(
            ProviderSettingsReader.Require(settings, "key-id", "FORTANIX_KEY_ID"),
            ProviderSettingsReader.Require(settings, "cert-file", "FORTANIX_CERT_FILE"))
        {
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            ApiKey = ProviderSettingsReader.Find(settings, "api-key", "FORTANIX_API_KEY"),
            AccessToken = ProviderSettingsReader.Find(settings, "access-token", "FORTANIX_ACCESS_TOKEN"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"FortanixDsmOptions {{ Endpoint = {Endpoint}, KeyId = {KeyId}, CertificateFile = {CertificateFile} }}";
}
