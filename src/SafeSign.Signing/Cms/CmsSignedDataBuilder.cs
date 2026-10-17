// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing.Cms;

/// <summary>
/// Builds a CMS <c>SignedData</c> (RFC 5652) whose single signature comes from a remote provider. Only the digest of
/// the signed attributes leaves the machine.
/// </summary>
public static class CmsSignedDataBuilder
{
    /// <summary>The SignedData and SignerInfo version for issuer-and-serial signer identifiers.</summary>
    private const int Version1 = 1;

    /// <summary>The initial capacity in bytes for the DER-encoded signed attributes SET OF.</summary>
    private const int SignedAttributesCapacity = 256;

    /// <summary>The initial capacity in bytes for the outer CMS <c>ContentInfo</c> / <c>SignedData</c>.</summary>
    private const int ContentInfoCapacity = 2_048;

    /// <summary>The context-specific tag of <c>eContent</c>, <c>certificates</c> and <c>signedAttrs</c>.</summary>
    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The context-specific tag of <c>unsignedAttrs</c>.</summary>
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>Signs content and returns the encoded CMS <c>ContentInfo</c>.</summary>
    /// <param name="session">The signing session.</param>
    /// <param name="content">The content and attributes to sign.</param>
    /// <param name="cancellationToken">Cancels the provider and timestamp requests.</param>
    /// <returns>The DER-encoded <c>ContentInfo</c> holding the <c>SignedData</c>.</returns>
    /// <exception cref="CryptographicException">The provider's signature does not verify with the certificate's public key.</exception>
    public static async ValueTask<byte[]> CreateAsync(SigningSession session, CmsSignedContent content, CancellationToken cancellationToken)
    {
        var certificate = session.Certificate.Certificate;
        var signedAttributes = EncodeSignedAttributes(session.DigestAlgorithm, content);

        var hash = new byte[DigestAlgorithms.Length(session.DigestAlgorithm)];
        _ = CryptographicOperations.HashData(session.DigestAlgorithm, signedAttributes, hash);
        var signature = await session.Provider.SignDigestAsync(new(hash, session.DigestAlgorithm), cancellationToken).ConfigureAwait(false);

        // A provider pointed at the wrong key would otherwise produce a file that only fails on the user's machine.
        if (!SignatureAlgorithms.Verify(certificate, hash, signature, session.DigestAlgorithm))
        {
            throw new CryptographicException($"The signature from provider '{session.Provider.Name}' does not match the public key of '{certificate.Subject}'.");
        }

        byte[]? timestamp = null;
        if (content.Timestamp is not CmsTimestampPlacement.None && session.Timestamp is { } authority)
        {
            timestamp = await Rfc3161TimestampClient.RequestAsync(authority, signature, cancellationToken).ConfigureAwait(false);
        }

        return EncodeContentInfo(new(session, content, signedAttributes, signature, timestamp));
    }

    /// <summary>Encodes the signed attributes as the DER <c>SET OF</c> that the signature covers.</summary>
    /// <param name="digest">The digest algorithm.</param>
    /// <param name="content">The content.</param>
    /// <returns>The attributes with a universal SET tag.</returns>
    internal static byte[] EncodeSignedAttributes(HashAlgorithmName digest, CmsSignedContent content)
    {
        Span<byte> messageDigest = stackalloc byte[SHA512.HashSizeInBytes];
        var length = CryptographicOperations.HashData(digest, content.DigestInput.Span, messageDigest);

        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SignedAttributesCapacity);

        // DER sorts SET OF members by encoding when the set is popped, as RFC 5652 requires for signed attributes.
        using (writer.PushSetOf())
        {
            WriteAttribute(writer, CmsAttributes.ContentType(content.ContentTypeOid));
            WriteAttribute(writer, CmsAttributes.MessageDigest(messageDigest[..length]));
            foreach (var attribute in content.SignedAttributes)
            {
                WriteAttribute(writer, attribute);
            }
        }

        return writer.Encode();
    }

    /// <summary>Writes one attribute.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="attribute">The attribute.</param>
    private static void WriteAttribute(AsnWriter writer, CmsAttribute attribute)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(attribute.Oid);
            writer.WriteEncodedValue(attribute.Values.Span);
        }
    }

    /// <summary>Encodes the outer <c>ContentInfo</c> and its <c>SignedData</c>.</summary>
    /// <param name="parts">The signed parts.</param>
    /// <returns>The DER encoding.</returns>
    private static byte[] EncodeContentInfo(CmsSignedParts parts)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: ContentInfoCapacity);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(CmsOids.SignedData);
            using (writer.PushSequence(Context0))
            {
                WriteSignedData(writer, parts);
            }
        }

        return writer.Encode();
    }

    /// <summary>Writes the <c>SignedData</c> body.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="parts">The signed parts.</param>
    private static void WriteSignedData(AsnWriter writer, CmsSignedParts parts)
    {
        var (session, content, _, _, _) = parts;
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version1);
            using (writer.PushSetOf())
            {
                DigestAlgorithms.WriteIdentifier(writer, session.DigestAlgorithm);
            }

            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(content.ContentTypeOid);
                if (!content.EncodedContent.IsEmpty)
                {
                    using (writer.PushSequence(Context0))
                    {
                        writer.WriteEncodedValue(content.EncodedContent.Span);
                    }
                }
            }

            WriteCertificates(writer, session.Certificate);
            using (writer.PushSetOf())
            {
                WriteSignerInfo(writer, parts);
            }
        }
    }

    /// <summary>Writes the signing certificate and its issuers.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="certificate">The certificate and chain.</param>
    private static void WriteCertificates(AsnWriter writer, SigningCertificate certificate)
    {
        using (writer.PushSetOf(Context0))
        {
            writer.WriteEncodedValue(certificate.Certificate.RawDataMemory.Span);
            foreach (var issuer in certificate.Chain)
            {
                writer.WriteEncodedValue(issuer.RawDataMemory.Span);
            }
        }
    }

    /// <summary>Writes the single <c>SignerInfo</c>.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="parts">The signed parts.</param>
    private static void WriteSignerInfo(AsnWriter writer, CmsSignedParts parts)
    {
        var (session, content, signedAttributes, signature, timestamp) = parts;
        var certificate = session.Certificate.Certificate;
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version1);
            WriteIssuerAndSerialNumber(writer, certificate);
            DigestAlgorithms.WriteIdentifier(writer, session.DigestAlgorithm);

            // The signature covers the attributes with a SET tag; on the wire they carry the implicit [0] tag instead.
            var attributes = new AsnReader(signedAttributes, AsnEncodingRules.DER).ReadSetOf();
            using (writer.PushSetOf(Context0))
            {
                while (attributes.HasData)
                {
                    writer.WriteEncodedValue(attributes.ReadEncodedValue().Span);
                }
            }

            SignatureAlgorithms.WriteIdentifier(writer, certificate, session.DigestAlgorithm);
            writer.WriteOctetString(signature);
            if (timestamp is not null)
            {
                var oid = content.Timestamp is CmsTimestampPlacement.Cms ? CmsOids.SignatureTimeStampToken : CmsOids.SpcRfc3161Timestamp;
                using (writer.PushSetOf(Context1))
                {
                    WriteAttribute(writer, CmsAttributes.Single(oid, timestamp));
                }
            }
        }
    }

    /// <summary>Writes the signer identifier.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="certificate">The signing certificate.</param>
    private static void WriteIssuerAndSerialNumber(AsnWriter writer, X509Certificate2 certificate)
    {
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(certificate.IssuerName.RawData);
            writer.WriteInteger(certificate.SerialNumberBytes.Span);
        }
    }
}
