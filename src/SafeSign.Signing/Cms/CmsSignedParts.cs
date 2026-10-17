// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Cms;

/// <summary>The pieces of a finished signature, ready to encode.</summary>
/// <param name="Session">The session.</param>
/// <param name="Content">The signed content.</param>
/// <param name="SignedAttributes">The DER signed attributes with a SET tag.</param>
/// <param name="Signature">The provider's signature.</param>
/// <param name="Timestamp">The timestamp token, or null.</param>
[DebuggerDisplay("{Content.ContentTypeOid,nq} ({Signature.Length} byte signature)")]
internal sealed record CmsSignedParts(SigningSession Session, CmsSignedContent Content, byte[] SignedAttributes, byte[] Signature, byte[]? Timestamp);
