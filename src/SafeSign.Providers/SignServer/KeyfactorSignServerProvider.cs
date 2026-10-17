// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.SignServer;

/// <summary>Signs digests using a Keyfactor SignServer REST v1 worker.</summary>
/// <param name="options">The SignServer configuration.</param>
/// <param name="services">The HTTP and clock services.</param>
/// <param name="retry">The optional retry and backoff configuration.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class KeyfactorSignServerProvider(
    KeyfactorSignServerOptions options,
    ProviderServices services,
    ProviderRetryOptions? retry = null) : ISigningProvider
{
    /// <summary>The Refit client for the SignServer REST API.</summary>
    private readonly IKeyfactorSignServerApi _api = SignServerRequests.CreateApi(services.Http, options.BaseUri);

    /// <summary>The retry policy.</summary>
    private readonly ProviderRetryOptions _retry = retry ?? ProviderRetryOptions.Default;

    /// <summary>The cached certificate chain.</summary>
    private SigningCertificate? _certificate;

    /// <inheritdoc />
    public string Name => "keyfactor-signserver";

    /// <summary>Creates a <see cref="KeyfactorSignServerProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <param name="services">The HTTP and clock services.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> or <paramref name="services"/> is null.</exception>
    /// <exception cref="ProviderConfigurationException">A required option is missing or invalid.</exception>
    public static KeyfactorSignServerProvider FromSettings(ProviderSettings settings, ProviderServices services)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(services);
        var urlText = ProviderSettingsReader.Require(settings, "endpoint", "SAFESIGN_SIGNSERVER_URL");
        return !Uri.TryCreate(urlText, UriKind.Absolute, out var baseUri)
            ? throw new ProviderConfigurationException($"Invalid Keyfactor SignServer endpoint '{urlText}'.")
            : new(
                new(
                    baseUri,
                    ProviderSettingsReader.Require(settings, "worker", "SAFESIGN_SIGNSERVER_WORKER"),
                    ProviderSettingsReader.Require(settings, "cert-file", "SAFESIGN_CERT_FILE"),
                    ProviderSettingsReader.Find(settings, "token", "SAFESIGN_SIGNSERVER_TOKEN")),
                services);
    }

    /// <inheritdoc />
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new(_certificate ??= CertificateFile.Load(options.CertificateFile));
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken) =>
        await SignServerRequests.SignAsync(_api, options, request, services.Time, _retry, cancellationToken).ConfigureAwait(false);
}
