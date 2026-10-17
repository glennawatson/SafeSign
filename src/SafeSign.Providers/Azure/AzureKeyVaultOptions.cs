// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Azure;

/// <summary>Options for <see cref="AzureKeyVaultProvider"/>.</summary>
/// <param name="VaultUri">The vault URI, such as <c>https://contoso.vault.azure.net/</c>.</param>
/// <param name="CertificateName">The Key Vault certificate whose key signs.</param>
/// <remarks>Set either <see cref="Credential"/> or <see cref="AccessToken"/>.</remarks>
[DebuggerDisplay("{CertificateName,nq} in {VaultUri}")]
public sealed record AzureKeyVaultOptions(Uri VaultUri, string CertificateName)
{
    /// <summary>Gets the certificate version, or null for the current version.</summary>
    public string? CertificateVersion { get; init; }

    /// <summary>Gets the application credential used to request tokens.</summary>
    public EntraIdCredential? Credential { get; init; }

    /// <summary>Gets a pre-acquired access token for <c>https://vault.azure.net</c>, used instead of <see cref="Credential"/>.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Gets an optional PEM, DER, or PKCS #7 file with the issuing certificates; Key Vault returns only the leaf.</summary>
    public string? ChainPath { get; init; }

    /// <summary>Reads <see cref="AzureKeyVaultOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static AzureKeyVaultOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var tenantId = ProviderSettingsReader.Find(settings, "tenant-id", "AZURE_TENANT_ID");
        var clientId = ProviderSettingsReader.Find(settings, "client-id", "AZURE_CLIENT_ID");
        var clientSecret = ProviderSettingsReader.Find(settings, "client-secret", "AZURE_CLIENT_SECRET");
        var credential = tenantId is { Length: > 0 } && clientId is { Length: > 0 } && clientSecret is { Length: > 0 }
            ? new EntraIdCredential(tenantId, clientId, clientSecret)
            : null;
        return new(new Uri(ProviderSettingsReader.Require(settings, "vault-uri")), ProviderSettingsReader.Require(settings, "cert-name"))
        {
            CertificateVersion = ProviderSettingsReader.Find(settings, "cert-version"),
            Credential = credential,
            AccessToken = ProviderSettingsReader.Find(settings, "access-token", "AZURE_KEYVAULT_ACCESS_TOKEN"),
            ChainPath = ProviderSettingsReader.Find(settings, "chain-file"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() => $"AzureKeyVaultOptions {{ VaultUri = {VaultUri}, CertificateName = {CertificateName} }}";
}
