// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Cms;

/// <summary>The content a CMS <c>SignedData</c> signs, and how its signer is decorated.</summary>
/// <param name="ContentTypeOid">The encapsulated content type, such as <see cref="CmsOids.SpcIndirectData"/>.</param>
/// <param name="EncodedContent">
/// The DER value placed inside <c>eContent [0] EXPLICIT</c>: a SEQUENCE for Authenticode, an OCTET STRING for
/// <c>id-data</c>. Empty for a detached signature.
/// </param>
/// <param name="DigestInput">
/// The bytes the <c>messageDigest</c> attribute hashes. For Authenticode this is the content octets of the
/// SEQUENCE without its tag and length; for <c>id-data</c> it is the raw data.
/// </param>
/// <param name="SignedAttributes">Signed attributes beyond <c>contentType</c> and <c>messageDigest</c>, which are always added.</param>
/// <param name="Timestamp">Where the RFC 3161 token goes.</param>
[DebuggerDisplay("{ContentTypeOid,nq} ({EncodedContent.Length} content bytes)")]
public sealed record CmsSignedContent(
    string ContentTypeOid,
    ReadOnlyMemory<byte> EncodedContent,
    ReadOnlyMemory<byte> DigestInput,
    CmsAttribute[] SignedAttributes,
    CmsTimestampPlacement Timestamp);
