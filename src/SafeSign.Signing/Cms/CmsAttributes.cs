// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing.Cms;

/// <summary>Builds common CMS attributes.</summary>
public static class CmsAttributes
{
    /// <summary>The default initial capacity in bytes for small ASN.1 attribute writers.</summary>
    private const int SmallWriterCapacity = 32;

    /// <summary>The ASN.1 tag/length framing overhead in bytes for a single-value attribute SET.</summary>
    private const int AttributeFramingOverhead = 8;

    /// <summary>The initial capacity in bytes for an RFC 5035 <c>SigningCertificateV2</c> sequence.</summary>
    private const int SigningCertV2Capacity = 48;

    /// <summary>Wraps one already-encoded value as an attribute.</summary>
    /// <param name="oid">The attribute type.</param>
    /// <param name="encodedValue">The DER encoding of the single attribute value.</param>
    /// <returns>The attribute.</returns>
    public static CmsAttribute Single(string oid, ReadOnlySpan<byte> encodedValue)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: encodedValue.Length + AttributeFramingOverhead);
        using (writer.PushSetOf())
        {
            writer.WriteEncodedValue(encodedValue);
        }

        return new(oid, writer.Encode());
    }

    /// <summary>Builds the <c>contentType</c> attribute.</summary>
    /// <param name="contentTypeOid">The encapsulated content type.</param>
    /// <returns>The attribute.</returns>
    public static CmsAttribute ContentType(string contentTypeOid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SmallWriterCapacity);
        using (writer.PushSetOf())
        {
            writer.WriteObjectIdentifier(contentTypeOid);
        }

        return new(CmsOids.ContentType, writer.Encode());
    }

    /// <summary>Builds the <c>messageDigest</c> attribute.</summary>
    /// <param name="digest">The content digest.</param>
    /// <returns>The attribute.</returns>
    public static CmsAttribute MessageDigest(ReadOnlySpan<byte> digest)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: digest.Length + AttributeFramingOverhead);
        using (writer.PushSetOf())
        {
            writer.WriteOctetString(digest);
        }

        return new(CmsOids.MessageDigest, writer.Encode());
    }

    /// <summary>Builds the <c>signingTime</c> attribute.</summary>
    /// <param name="time">The signing time.</param>
    /// <returns>The attribute.</returns>
    public static CmsAttribute SigningTime(DateTimeOffset time)
    {
        // RFC 5652 requires UTCTime for dates from 1950 through 2049.
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SmallWriterCapacity);
        using (writer.PushSetOf())
        {
            writer.WriteUtcTime(time);
        }

        return new(CmsOids.SigningTime, writer.Encode());
    }

    /// <summary>Builds the RFC 5035 <c>SigningCertificateV2</c> attribute with a SHA-256 certificate hash.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The attribute.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static CmsAttribute SigningCertificateV2(X509Certificate2 certificate) =>
        Single(CmsOids.SigningCertificateV2, EncodeSigningCertificateV2Value(certificate));

    /// <summary>Encodes the DER value of an RFC 5035 <c>SigningCertificateV2</c> sequence using the default SHA-256 hash algorithm.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The DER-encoded <c>SigningCertificateV2</c> value.</returns>
    public static byte[] EncodeSigningCertificateV2Value(X509Certificate2 certificate)
    {
        Span<byte> certHash = stackalloc byte[SHA256.HashSizeInBytes];
        _ = SHA256.HashData(certificate.RawDataMemory.Span, certHash);

        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SigningCertV2Capacity);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    // RFC 5035 section 4: HashAlgorithm defaults to id-sha256 and MUST be omitted when default in DER.
                    writer.WriteOctetString(certHash);
                }
            }
        }

        return writer.Encode();
    }
}
