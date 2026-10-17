// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>Options for <see cref="GoogleCloudKmsProvider"/>.</summary>
/// <param name="KeyVersionName">
/// The key version resource name:
/// <c>projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}</c>.
/// </param>
/// <param name="CertificatePath">A PEM, DER, or PKCS #7 file with the certificate for the key and its issuers.</param>
/// <remarks>Set either <see cref="ServiceAccountKeyPath"/> or <see cref="AccessToken"/>.</remarks>
[DebuggerDisplay("{KeyVersionName,nq}")]
public sealed record GoogleCloudKmsOptions(string KeyVersionName, string CertificatePath)
{
    /// <summary>Gets the path of a service account JSON key file (<c>GOOGLE_APPLICATION_CREDENTIALS</c>).</summary>
    public string? ServiceAccountKeyPath { get; init; }

    /// <summary>Gets a pre-acquired OAuth 2.0 access token with the <c>cloudkms</c> scope.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets the API endpoint. Defaults to <c>https://cloudkms.googleapis.com/</c>.</summary>
    public Uri Endpoint { get; init; } = new("https://cloudkms.googleapis.com/");

    /// <summary>Reads <see cref="GoogleCloudKmsOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static GoogleCloudKmsOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint");
        return new(ProviderSettingsReader.Require(settings, "key-version-name"), ProviderSettingsReader.Require(settings, "cert-file"))
        {
            ServiceAccountKeyPath = ProviderSettingsReader.Find(settings, "credentials-file", "GOOGLE_APPLICATION_CREDENTIALS"),
            AccessToken = ProviderSettingsReader.Find(settings, "access-token", "GOOGLE_CLOUD_KMS_ACCESS_TOKEN"),
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : new("https://cloudkms.googleapis.com/"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() => $"GoogleCloudKmsOptions {{ KeyVersionName = {KeyVersionName} }}";
}
