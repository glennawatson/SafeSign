// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Certum;

/// <summary>
/// Resolves issuing intermediate CA certificates dynamically from the leaf certificate's X.509
/// Authority Information Access (AIA) <c>CA Issuers</c> extension (<c>1.3.6.1.5.5.7.48.2</c>) so that
/// leaf-only certificate responses from <c>/card/v1/cards/{serial}/certificates/tasks</c> download their
/// issuing intermediate CA directly from Certum's repository (<c>http://repository.certum.pl/...</c>)
/// instead of embedding hardcoded certificates in the executable.
/// </summary>
internal static class CertumIntermediateCertificates
{
    /// <summary>The maximum number of AIA <c>CA Issuers</c> hops followed when building an intermediate chain.</summary>
    private const int MaxAiaDepth = 4;

    /// <summary>
    /// Downloads and appends the issuing intermediate CA certificate(s) for a leaf-only <paramref name="certificates"/>
    /// list by following the X.509 Authority Information Access (AIA) <c>CA Issuers</c> extension URI.
    /// </summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="certificates">The mutable list of certificates for the card.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    internal static async ValueTask TryAddMatchingIntermediatesAsync(
        RefitSettings http,
        List<X509Certificate2> certificates,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(certificates);
        if (certificates.Count != 1)
        {
            return;
        }

        var current = certificates[0];
        for (var depth = 0; depth < MaxAiaDepth && !CertificateChainOrder.IsSelfIssued(current); depth++)
        {
            if (TryGetCaIssuersUri(current) is not { } issuerUri)
            {
                return;
            }

            var issuer = await TryDownloadIssuerAsync(http, issuerUri, current, cancellationToken).ConfigureAwait(false);
            if (issuer is null)
            {
                return;
            }

            certificates.Add(issuer);
            current = issuer;
        }
    }

    /// <summary>Finds the first HTTP or HTTPS <c>CA Issuers</c> URI in <paramref name="certificate"/>'s AIA extension.</summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The parsed HTTP/HTTPS URI, or <see langword="null"/> when none is present.</returns>
    internal static Uri? TryGetCaIssuersUri(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is not X509AuthorityInformationAccessExtension aia)
            {
                continue;
            }

            foreach (var rawUri in aia.EnumerateCAIssuersUris())
            {
                if (Uri.TryCreate(rawUri, UriKind.Absolute, out var uri)
                    && (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                        || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
                {
                    return uri;
                }
            }
        }

        return null;
    }

    /// <summary>Downloads the certificate file at <paramref name="issuerUri"/> and returns the non-root certificate that issued <paramref name="subject"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="issuerUri">The AIA <c>CA Issuers</c> URI.</param>
    /// <param name="subject">The certificate whose issuer is being resolved.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The matching non-self-issued intermediate certificate, or <see langword="null"/>.</returns>
    private static async ValueTask<X509Certificate2?> TryDownloadIssuerAsync(
        RefitSettings http,
        Uri issuerUri,
        X509Certificate2 subject,
        CancellationToken cancellationToken)
    {
        var api = RestService.ForGenerated<ICertumCloudSignApi>(
            ProviderHttp.Authority(issuerUri),
            ProviderHttp.CreateSettings(CertumJsonContext.Default, http));
        using var response = await api.GetAiaCertificateAsync(
            issuerUri.PathAndQuery.TrimStart('/'),
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var rawBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (rawBytes.Length == 0)
        {
            return null;
        }

        var candidates = CertificateFile.Read(rawBytes);
        X509Certificate2? matched = null;
        foreach (var candidate in candidates)
        {
            if (matched is null
                && !CertificateChainOrder.IsSelfIssued(candidate)
                && candidate.SubjectName.RawData.AsSpan().SequenceEqual(subject.IssuerName.RawData))
            {
                matched = candidate;
            }
            else
            {
                candidate.Dispose();
            }
        }

        return matched;
    }
}
