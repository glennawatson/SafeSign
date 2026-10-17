// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Providers.Certum;

/// <summary>
/// Provides the embedded Certum SimplySign code-signing intermediate CA certificates so that leaf-only
/// certificate responses from <c>/card/v1/cards/{serial}/certificates/tasks</c> automatically include
/// their issuing intermediate CA in the CMS/PKCS #7 certificate bag.
/// </summary>
internal static class CertumIntermediateCertificates
{
    /// <summary>DER-encoded "Certum Code Signing 2021 CA" intermediate certificate (<c>http://repository.certum.pl/ctnca2.cer</c>).</summary>
    private const string CertumCodeSigning2021CaBase64 =
        "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";

    /// <summary>DER-encoded "Certum Extended Validation Code Signing 2021 CA" intermediate certificate.</summary>
    private const string CertumEvCodeSigning2021CaBase64 =
        "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";

    /// <summary>The cached intermediate CA certificates.</summary>
    private static readonly string[] KnownIntermediateBase64 =
    [
        CertumCodeSigning2021CaBase64,
        CertumEvCodeSigning2021CaBase64,
    ];

    /// <summary>
    /// Appends the matching Certum intermediate CA certificate to <paramref name="certificates"/> when only
    /// a leaf certificate is present and its issuer matches one of Certum's SimplySign code-signing CAs.
    /// </summary>
    /// <param name="certificates">The mutable list of certificates for the card.</param>
    internal static void TryAddMatchingIntermediate(List<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        if (certificates.Count != 1)
        {
            return;
        }

        var leaf = certificates[0];
        var issuerRaw = leaf.IssuerName.RawData.AsSpan();
        if (issuerRaw.SequenceEqual(leaf.SubjectName.RawData))
        {
            return;
        }

        foreach (var candidateBase64 in KnownIntermediateBase64)
        {
            var candidate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(candidateBase64));
            if (issuerRaw.SequenceEqual(candidate.SubjectName.RawData))
            {
                certificates.Add(candidate);
                return;
            }

            candidate.Dispose();
        }
    }
}
