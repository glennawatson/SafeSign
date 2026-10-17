// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Azure;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>Options for <see cref="AzureArtifactSigningProvider"/> (Azure Artifact Signing).</summary>
/// <param name="Endpoint">The regional Azure Artifact Signing endpoint URI, such as <c>https://eus.codesigning.azure.net/</c>.</param>
/// <param name="AccountName">The Azure Artifact Signing account name.</param>
/// <param name="CertificateProfileName">The certificate profile name within the Artifact Signing account.</param>
/// <remarks>Set either <see cref="Credential"/> or <see cref="AccessToken"/>.</remarks>
[DebuggerDisplay("{AccountName,nq}/{CertificateProfileName,nq} at {Endpoint}")]
public sealed record AzureArtifactSigningOptions(Uri Endpoint, string AccountName, string CertificateProfileName)
{
    /// <summary>The default polling interval between sign status checks.</summary>
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>The default timeout for an asynchronous signing operation.</summary>
    private static readonly TimeSpan DefaultPollTimeout = TimeSpan.FromMinutes(2);

    /// <summary>Gets the Entra ID application credential used to request tokens for <c>https://codesigning.azure.net/.default</c>.</summary>
    public EntraIdCredential? Credential { get; init; }

    /// <summary>Gets a pre-acquired access token for <c>https://codesigning.azure.net</c>, used instead of <see cref="Credential"/>.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets the base interval between status polls when waiting for a signing operation to complete.</summary>
    public TimeSpan PollInterval { get; init; } = DefaultPollInterval;

    /// <summary>Gets the maximum duration to wait for a signing operation to complete.</summary>
    public TimeSpan PollTimeout { get; init; } = DefaultPollTimeout;

    /// <summary>Reads <see cref="AzureArtifactSigningOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static AzureArtifactSigningOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var tenantId = ProviderSettingsReader.Find(settings, "tenant-id", "AZURE_TENANT_ID");
        var clientId = ProviderSettingsReader.Find(settings, "client-id", "AZURE_CLIENT_ID");
        var clientSecret = ProviderSettingsReader.Find(settings, "client-secret", "AZURE_CLIENT_SECRET");
        var credential = tenantId is { Length: > 0 } && clientId is { Length: > 0 } && clientSecret is { Length: > 0 }
            ? new EntraIdCredential(tenantId, clientId, clientSecret)
            : null;
        var endpoint = ProviderSettingsReader.Find(settings, "endpoint", "AZURE_ARTIFACT_SIGNING_ENDPOINT")
            ?? ProviderSettingsReader.Require(settings, "endpoint");
        var accountName = ProviderSettingsReader.Find(settings, "account-name", "AZURE_ARTIFACT_SIGNING_ACCOUNT")
            ?? ProviderSettingsReader.Require(settings, "account-name");
        var profileName = ProviderSettingsReader.Find(settings, "profile-name", "AZURE_ARTIFACT_SIGNING_PROFILE")
            ?? ProviderSettingsReader.Find(settings, "certificate-profile-name")
            ?? ProviderSettingsReader.Require(settings, "profile-name");
        return new(new Uri(endpoint), accountName, profileName) { Credential = credential, AccessToken = ProviderSettingsReader.Find(settings, "access-token", "AZURE_ARTIFACT_SIGNING_ACCESS_TOKEN") };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"AzureArtifactSigningOptions {{ Endpoint = {Endpoint}, AccountName = {AccountName}, CertificateProfileName = {CertificateProfileName} }}";
}
