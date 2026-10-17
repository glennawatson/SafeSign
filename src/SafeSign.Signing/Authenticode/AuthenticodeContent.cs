// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Authenticode;

/// <summary>What an Authenticode signature vouches for: the format's data descriptor and the file digest.</summary>
/// <param name="DataTypeOid">The <c>SpcAttributeTypeAndOptionalValue</c> type, such as <see cref="Cms.CmsOids.SpcPeImageData"/>.</param>
/// <param name="DataValue">The DER value for <paramref name="DataTypeOid"/>, from <see cref="AuthenticodeEncoding"/>.</param>
/// <param name="FileDigest">The format's Authenticode digest of the file, computed with the session's digest algorithm.</param>
[DebuggerDisplay("{DataTypeOid,nq} ({FileDigest.Length} byte digest)")]
public sealed record AuthenticodeContent(string DataTypeOid, ReadOnlyMemory<byte> DataValue, ReadOnlyMemory<byte> FileDigest);
