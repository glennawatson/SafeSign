// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.IO.Hashing;
using System.Runtime.CompilerServices;

namespace SafeSign.Formats.Compression;

/// <summary>Computes the standard IEEE 802.3 CRC-32 checksum used by ZIP local and central directory headers.</summary>
internal static class ZipCrc32
{
    /// <summary>Computes the IEEE 802.3 CRC-32 checksum over <paramref name="data"/>.</summary>
    /// <param name="data">The input bytes.</param>
    /// <returns>The 32-bit CRC checksum.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint HashToUInt32(ReadOnlySpan<byte> data) => Crc32.HashToUInt32(data);
}
