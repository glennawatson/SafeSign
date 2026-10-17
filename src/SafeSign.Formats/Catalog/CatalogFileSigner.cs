// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Catalog;

/// <summary>
/// Signs Windows Security Catalog (<c>.cat</c>) files natively by extracting the ASN.1 <c>CertificateTrustList</c>
/// (<c>1.3.6.1.4.1.311.10.1</c>) payload and wrapping it in an Authenticode CMS <c>SignedData</c>.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class CatalogFileSigner : IFileFormatSigner
{
    /// <summary>The ASN.1 Universal SEQUENCE tag byte (<c>0x30</c>).</summary>
    private const byte Asn1SequenceTag = 0x30;

    /// <inheritdoc/>
    public string Name => "CAT";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) =>
        probe.Extension.Equals(".cat", StringComparison.OrdinalIgnoreCase)
        && !probe.Header.IsEmpty
        && probe.Header.Span[0] == Asn1SequenceTag;

    /// <inheritdoc/>
    public ValueTask SignAsync(FileSignRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return SignedFileOutput.WriteAsync(
            request.InputPath,
            request.OutputPath,
            (path, token) => SignPathAsync(path, request.Session, token),
            cancellationToken);
    }

    /// <summary>Extracts the inner <c>CertificateTrustList</c> from a <c>.cat</c> file, signs it, and writes the new PKCS #7 <c>SignedData</c>.</summary>
    /// <param name="path">The catalog file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var ctlBytes = ExtractCatalogTrustList(raw);
        AsnDecoder.ReadSequence(ctlBytes.Span, AsnEncodingRules.BER, out var contentOffset, out var contentLength, out _);

        var signedContent = new CmsSignedContent(
            CmsOids.CertificateTrustList,
            ctlBytes,
            ctlBytes.Slice(contentOffset, contentLength),
            [AuthenticodeEncoding.EncodeOpusInfo(session.Description, session.DescriptionUrl), AuthenticodeEncoding.EncodeIndividualStatementType()],
            CmsTimestampPlacement.Authenticode);

        var signed = await CmsSignedDataBuilder.CreateAsync(session, signedContent, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(path, signed, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Extracts the <c>CertificateTrustList</c> SEQUENCE from either an existing PKCS #7 <c>SignedData</c> catalog or a raw CTL SEQUENCE.</summary>
    /// <param name="catalogBytes">The input <c>.cat</c> bytes.</param>
    /// <returns>The encoded <c>CertificateTrustList</c> SEQUENCE.</returns>
    /// <exception cref="InvalidDataException">The file is not a valid catalog or CTL.</exception>
    private static ReadOnlyMemory<byte> ExtractCatalogTrustList(ReadOnlyMemory<byte> catalogBytes)
    {
        try
        {
            var outer = new AsnReader(catalogBytes, AsnEncodingRules.BER).ReadSequence();
            var firstOid = outer.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier)
                ? outer.ReadObjectIdentifier()
                : null;

            if (firstOid is "1.2.840.113549.1.7.2")
            {
                var explicit0 = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                var signedData = explicit0.ReadSequence();
                _ = signedData.ReadInteger();
                _ = signedData.ReadSetOf();
                var encapContentInfo = signedData.ReadSequence();
                var contentType = encapContentInfo.ReadObjectIdentifier();
                if (!string.Equals(contentType, CmsOids.CertificateTrustList, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"Unexpected catalog eContentType OID '{contentType}'.");
                }

                var encapsulatedContent = encapContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                return encapsulatedContent.ReadEncodedValue();
            }

            return catalogBytes;
        }
        catch (AsnContentException ex)
        {
            throw new InvalidDataException("The catalog file is not valid ASN.1 DER/BER data.", ex);
        }
    }
}
