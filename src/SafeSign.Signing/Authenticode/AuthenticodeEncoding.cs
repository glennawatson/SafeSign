// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SafeSign.Signing.Cms;

namespace SafeSign.Signing.Authenticode;

/// <summary>Encodes the Authenticode structures from Microsoft's Windows Authenticode Portable Executable Signature Format.</summary>
public static class AuthenticodeEncoding
{
    /// <summary>The SIP information version Windows writes for MSI and most script SIPs.</summary>
    private const int SipVersion = 1;

    /// <summary>How many reserved zero integers follow the SIP GUID.</summary>
    private const int SipReservedCount = 5;

    /// <summary>The <c>SpcLink</c> choice tag for a file name (<c>file [2] EXPLICIT SpcString</c>).</summary>
    private const int SpcLinkFileTag = 2;

    /// <summary>The byte length of a GUID.</summary>
    private const int GuidLength = 16;

    /// <summary>The initial capacity in bytes for small ASN.1 structures.</summary>
    private const int SmallCapacity = 64;

    /// <summary>The initial capacity in bytes for <c>SpcIndirectDataContent</c> and <c>SpcSpOpusInfo</c>.</summary>
    private const int MediumCapacity = 160;

    /// <summary>Gets the placeholder file name every Authenticode PE signature carries.</summary>
    private static string ObsoleteFileName => "<<<Obsolete>>>";

    /// <summary>Encodes <c>SpcPeImageData</c> with no flags and the obsolete file link Windows expects.</summary>
    /// <returns>The DER value.</returns>
    public static byte[] EncodePeImageData()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SmallCapacity);
        using (writer.PushSequence())
        {
            writer.WriteBitString([]);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, SpcLinkFileTag, isConstructed: true)))
            {
                writer.WriteCharacterString(UniversalTagNumber.BMPString, ObsoleteFileName, new Asn1Tag(TagClass.ContextSpecific, 0));
            }
        }

        return writer.Encode();
    }

    /// <summary>Encodes <c>SpcSipInfo</c> for a subject interface package with version 1.</summary>
    /// <param name="sip">The SIP GUID, such as <c>000C10F1-0000-0000-C000-000000000046</c> for MSI.</param>
    /// <returns>The DER value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] EncodeSipInfo(Guid sip) => EncodeSipInfo(SipVersion, sip);

    /// <summary>Encodes <c>SpcSipInfo</c> for a subject interface package.</summary>
    /// <param name="version">The SIP version the format's verifier expects.</param>
    /// <param name="sip">The SIP GUID.</param>
    /// <returns>The DER value.</returns>
    public static byte[] EncodeSipInfo(int version, Guid sip)
    {
        Span<byte> guid = stackalloc byte[GuidLength];
        _ = sip.TryWriteBytes(guid);
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SmallCapacity);
        using (writer.PushSequence())
        {
            writer.WriteInteger(version);
            writer.WriteOctetString(guid);
            for (var i = 0; i < SipReservedCount; i++)
            {
                writer.WriteInteger(0);
            }
        }

        return writer.Encode();
    }

    /// <summary>Encodes <c>SpcIndirectDataContent</c>.</summary>
    /// <param name="content">The data descriptor and file digest.</param>
    /// <param name="digest">The digest algorithm used for the file digest.</param>
    /// <returns>The DER SEQUENCE.</returns>
    public static byte[] EncodeIndirectData(AuthenticodeContent content, HashAlgorithmName digest)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: MediumCapacity);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(content.DataTypeOid);
                writer.WriteEncodedValue(content.DataValue.Span);
            }

            using (writer.PushSequence())
            {
                DigestAlgorithms.WriteIdentifier(writer, digest);
                writer.WriteOctetString(content.FileDigest.Span);
            }
        }

        return writer.Encode();
    }

    /// <summary>Encodes the <c>SpcSpOpusInfo</c> signed attribute with the optional program name and URL.</summary>
    /// <param name="description">The program name, or null.</param>
    /// <param name="url">The "more information" URL, or null.</param>
    /// <returns>The attribute.</returns>
    public static CmsAttribute EncodeOpusInfo(string? description, Uri? url)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: MediumCapacity);
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            if (description is { Length: > 0 })
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, description, new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }

            if (url is not null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, url.AbsoluteUri, new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
        }

        return new(CmsOids.SpcSpOpusInfo, writer.Encode());
    }

    /// <summary>Encodes the <c>SpcStatementType</c> signed attribute asserting individual code signing.</summary>
    /// <returns>The attribute.</returns>
    public static CmsAttribute EncodeIndividualStatementType()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER, initialCapacity: SmallCapacity);
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(CmsOids.SpcIndividualSpKeyPurpose);
        }

        return new(CmsOids.SpcStatementType, writer.Encode());
    }
}
