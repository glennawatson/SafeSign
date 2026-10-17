// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Oracle;

/// <summary>Signs digests using the Oracle Cloud Infrastructure (OCI) KMS cryptographic API.</summary>
/// <param name="options">The OCI KMS options.</param>
/// <param name="services">The HTTP and clock services.</param>
/// <param name="retry">The optional retry and backoff configuration.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class OracleCloudKmsProvider(
    OracleCloudKmsOptions options,
    ProviderServices services,
    ProviderRetryOptions? retry = null) : ISigningProvider
{
    /// <summary>The Refit client for the OCI KMS cryptographic endpoint.</summary>
    private readonly IOracleCloudKmsApi _api = OracleKmsRequests.CreateApi(services.Http, options.CryptoEndpoint);

    /// <summary>The retry policy.</summary>
    private readonly ProviderRetryOptions _retry = retry ?? ProviderRetryOptions.Default;

    /// <summary>The cached certificate chain.</summary>
    private SigningCertificate? _certificate;

    /// <inheritdoc />
    public string Name => "oracle-kms";

    /// <summary>Creates an <see cref="OracleCloudKmsProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <param name="services">The HTTP and clock services.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> or <paramref name="services"/> is null.</exception>
    /// <exception cref="ProviderConfigurationException">A required option is missing or invalid.</exception>
    public static OracleCloudKmsProvider FromSettings(ProviderSettings settings, ProviderServices services)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(services);
        var endpointText = ProviderSettingsReader.Require(settings, "crypto-endpoint", "OCI_KMS_CRYPTO_ENDPOINT");
        if (!Uri.TryCreate(endpointText, UriKind.Absolute, out var endpoint))
        {
            throw new ProviderConfigurationException($"Invalid Oracle Cloud KMS cryptographic endpoint '{endpointText}'.");
        }

        var keyPem = ProviderSettingsReader.Find(settings, "api-key-pem", "OCI_CLI_KEY_CONTENT");
        if (keyPem is null)
        {
            var keyFile = ProviderSettingsReader.Require(settings, "api-key-file", "OCI_CLI_KEY_FILE");
            if (!File.Exists(keyFile))
            {
                throw new ProviderConfigurationException($"Oracle Cloud API private key file '{keyFile}' does not exist.");
            }

            keyPem = File.ReadAllText(keyFile);
        }

        return new(
            new(
                endpoint,
                ProviderSettingsReader.Require(settings, "key-id", "OCI_KMS_KEY_ID"),
                ProviderSettingsReader.Require(settings, "cert-file", "SAFESIGN_CERT_FILE"),
                ProviderSettingsReader.Require(settings, "tenancy-ocid", "OCI_CLI_TENANCY"),
                ProviderSettingsReader.Require(settings, "user-ocid", "OCI_CLI_USER"),
                ProviderSettingsReader.Require(settings, "fingerprint", "OCI_CLI_FINGERPRINT"),
                keyPem,
                ProviderSettingsReader.Find(settings, "key-version-id", "OCI_KMS_KEY_VERSION_ID")),
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
        return await OracleKmsRequests.SignAsync(
            _api,
            options,
            keyKind,
            request,
            services.Time,
            _retry,
            cancellationToken).ConfigureAwait(false);
    }
}
