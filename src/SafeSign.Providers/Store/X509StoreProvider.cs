// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Store;

/// <summary>Signs digests using a certificate and private key stored in a cross-platform <see cref="X509Store"/>.</summary>
/// <param name="options">The store selection options.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class X509StoreProvider(X509StoreOptions options) : ISigningProvider
{
    /// <summary>The length in hex characters of a SHA-256 thumbprint.</summary>
    private const int Sha256ThumbprintLength = 64;

    /// <summary>The cached certificate found in the store.</summary>
    private SigningCertificate? _certificate;

    /// <inheritdoc />
    public string Name => "store";

    /// <summary>Creates an <see cref="X509StoreProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> is null.</exception>
    /// <exception cref="ProviderConfigurationException">Neither <c>thumbprint</c> nor <c>subject-name</c> is set.</exception>
    public static X509StoreProvider FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var thumbprint = ProviderSettingsReader.Find(settings, "thumbprint", "SAFESIGN_CERT_THUMBPRINT");
        var subject = ProviderSettingsReader.Find(settings, "subject-name", "SAFESIGN_CERT_SUBJECT");
        if (thumbprint is null && subject is null)
        {
            throw new ProviderConfigurationException("X.509 store provider requires '--provider-option thumbprint=<hex>' or '--provider-option subject-name=<text>'.");
        }

        var storeName = ProviderSettingsReader.Find(settings, "store-name", "SAFESIGN_STORE_NAME") ?? "My";
        var locationText = ProviderSettingsReader.Find(settings, "store-location", "SAFESIGN_STORE_LOCATION");
        var location = locationText is not null && Enum.TryParse<StoreLocation>(locationText, ignoreCase: true, out var parsed)
            ? parsed
            : StoreLocation.CurrentUser;
        return new(new(thumbprint, subject, storeName, location));
    }

    /// <inheritdoc />
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new(_certificate ??= FindCertificate());
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var cert = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        return LocalKeySigner.Sign(cert.Certificate, in request);
    }

    /// <summary>Locates the matching certificate in the configured <see cref="X509Store"/> and resolves any intermediate certificates in the store.</summary>
    /// <returns>The signing certificate and intermediate chain.</returns>
    /// <exception cref="ProviderConfigurationException">No matching certificate with a private key was found.</exception>
    private SigningCertificate FindCertificate()
    {
        using var store = new X509Store(options.StoreName, options.StoreLocation);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        foreach (var candidate in store.Certificates)
        {
            if (Matches(candidate) && candidate.HasPrivateKey)
            {
                return new(candidate, CertificateChainOrder.IssuersOf([.. store.Certificates], candidate));
            }
        }

        throw new ProviderConfigurationException(
            $"No certificate with a private key matched in X.509 store '{options.StoreLocation}/{options.StoreName}'.");
    }

    /// <summary>Checks whether <paramref name="candidate"/> matches the configured thumbprint or subject name.</summary>
    /// <param name="candidate">The candidate certificate.</param>
    /// <returns>True when matched.</returns>
    private bool Matches(X509Certificate2 candidate)
    {
        if (options.Thumbprint is { Length: > 0 } thumbprint)
        {
            var normalized = thumbprint.Replace(":", string.Empty, StringComparison.Ordinal).Replace(" ", string.Empty, StringComparison.Ordinal);
            var actual = normalized.Length == Sha256ThumbprintLength
                ? candidate.GetCertHashString(HashAlgorithmName.SHA256)
                : candidate.Thumbprint;
            if (!string.Equals(actual, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return options.SubjectName is not { Length: > 0 } subject
            || candidate.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase);
    }
}
