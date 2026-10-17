// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using SafeSign.Signing.Cms;

namespace SafeSign.Signing.Authenticode;

/// <summary>Produces Authenticode PKCS #7 signatures for any format that describes its digest as an <see cref="AuthenticodeContent"/>.</summary>
public static class AuthenticodeSignatureBuilder
{
    /// <summary>Signs Authenticode content.</summary>
    /// <param name="session">The signing session.</param>
    /// <param name="content">The format's data descriptor and file digest.</param>
    /// <param name="cancellationToken">Cancels the provider and timestamp requests.</param>
    /// <returns>The DER-encoded <c>ContentInfo</c>, ready to embed.</returns>
    public static ValueTask<byte[]> CreateAsync(SigningSession session, AuthenticodeContent content, CancellationToken cancellationToken)
    {
        var indirectData = AuthenticodeEncoding.EncodeIndirectData(content, session.DigestAlgorithm);

        // Authenticode hashes the SEQUENCE's content octets, not its tag and length.
        AsnDecoder.ReadSequence(indirectData, AsnEncodingRules.DER, out var contentOffset, out var contentLength, out _);
        var signed = new CmsSignedContent(
            CmsOids.SpcIndirectData,
            indirectData,
            indirectData.AsMemory(contentOffset, contentLength),
            [AuthenticodeEncoding.EncodeOpusInfo(session.Description, session.DescriptionUrl), AuthenticodeEncoding.EncodeIndividualStatementType()],
            CmsTimestampPlacement.Authenticode);

        return CmsSignedDataBuilder.CreateAsync(session, signed, cancellationToken);
    }
}
