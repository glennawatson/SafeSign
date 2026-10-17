// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Vault;

/// <summary>Signs digests with the HashiCorp Vault Transit secret engine.</summary>
/// <param name="options">The Vault configuration.</param>
/// <param name="services">The HTTP and clock services.</param>
/// <param name="retry">The optional retry and backoff configuration.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class HashiCorpVaultProvider(
    HashiCorpVaultOptions options,
    ProviderServices services,
    ProviderRetryOptions? retry = null) : ISigningProvider
{
    /// <summary>The Refit client for the Vault Transit API.</summary>
    private readonly IHashiCorpVaultApi _api = VaultRequests.CreateApi(services.Http, options.Address);

    /// <summary>The retry policy.</summary>
    private readonly ProviderRetryOptions _retry = retry ?? ProviderRetryOptions.Default;

    /// <summary>The cached certificate chain.</summary>
    private SigningCertificate? _certificate;

    /// <inheritdoc />
    public string Name => "hashicorp-vault";

    /// <summary>Creates a <see cref="HashiCorpVaultProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <param name="services">The HTTP and clock services.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> or <paramref name="services"/> is null.</exception>
    /// <exception cref="ProviderConfigurationException">A required option is missing or invalid.</exception>
    public static HashiCorpVaultProvider FromSettings(ProviderSettings settings, ProviderServices services)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(services);
        var addressText = ProviderSettingsReader.Require(settings, "vault-address", "VAULT_ADDR");
        return !Uri.TryCreate(addressText, UriKind.Absolute, out var address)
            ? throw new ProviderConfigurationException($"Invalid HashiCorp Vault address '{addressText}'.")
            : new(
                new(
                    address,
                    ProviderSettingsReader.Require(settings, "vault-token", "VAULT_TOKEN"),
                    ProviderSettingsReader.Require(settings, "key-name", "SAFESIGN_VAULT_KEY"),
                    ProviderSettingsReader.Require(settings, "cert-file", "SAFESIGN_CERT_FILE"),
                    ProviderSettingsReader.Find(settings, "mount-path", "SAFESIGN_VAULT_MOUNT") ?? "transit",
                    ProviderSettingsReader.Find(settings, "vault-namespace", "VAULT_NAMESPACE")),
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
        return await VaultRequests.SignAsync(
            _api,
            options,
            keyKind,
            request,
            services.Time,
            _retry,
            cancellationToken).ConfigureAwait(false);
    }
}
