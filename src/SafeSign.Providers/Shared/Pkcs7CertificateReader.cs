// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Providers.Shared;

/// <summary>
/// Reads the certificates out of a degenerate PKCS #7 / CMS <c>SignedData</c> (a <c>.p7b</c> bundle), per RFC 5652
/// section 5.1, using only <see cref="AsnReader"/>.
/// </summary>
public static class Pkcs7CertificateReader
{
    /// <summary>The <c>id-signedData</c> content type OID.</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>Tries to read the certificates from a PKCS #7 bundle.</summary>
    /// <param name="data">The DER or BER encoded <c>ContentInfo</c>.</param>
    /// <param name="certificates">The certificates, in file order.</param>
    /// <returns>True when <paramref name="data"/> is a <c>SignedData</c> content info.</returns>
    public static bool TryRead(ReadOnlyMemory<byte> data, out List<X509Certificate2> certificates)
    {
        certificates = [];
        try
        {
            var contentInfo = new AsnReader(data, AsnEncodingRules.BER).ReadSequence();
            if (contentInfo.ReadObjectIdentifier() is not SignedDataOid)
            {
                return false;
            }

            var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
            _ = signedData.ReadEncodedValue(); // version
            _ = signedData.ReadEncodedValue(); // digestAlgorithms
            _ = signedData.ReadEncodedValue(); // encapContentInfo
            Asn1Tag certificatesTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
            if (!signedData.HasData || !signedData.PeekTag().HasSameClassAndValue(certificatesTag))
            {
                return true;
            }

            ReadCertificateSet(signedData.ReadSetOf(certificatesTag), certificates);
            return true;
        }
        catch (AsnContentException)
        {
            certificates.Clear();
            return false;
        }
    }

    /// <summary>Loads each plain X.509 certificate in a <c>CertificateSet</c>, skipping other choices.</summary>
    /// <param name="set">The set reader.</param>
    /// <param name="certificates">Receives the certificates.</param>
    private static void ReadCertificateSet(AsnReader set, List<X509Certificate2> certificates)
    {
        while (set.HasData)
        {
            var isCertificate = set.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence);
            var encoded = set.ReadEncodedValue();
            if (isCertificate)
            {
                certificates.Add(X509CertificateLoader.LoadCertificate(encoded.Span));
            }
        }
    }
}
