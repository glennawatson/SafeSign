// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Pe;

/// <summary>The result of one pass over an unsigned PE image.</summary>
/// <param name="Digest">The Authenticode digest.</param>
/// <param name="ChecksumSum">The running checksum sum over the same bytes, with the checksum field and certificate entry zeroed.</param>
[DebuggerDisplay("{Digest.Length} byte digest")]
public readonly record struct PeDigest(byte[] Digest, ulong ChecksumSum);
