// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Formats.Compression;

/// <summary>Computes the standard IEEE 802.3 CRC-32 checksum used by ZIP local and central directory headers.</summary>
internal static class ZipCrc32
{
    /// <summary>The reflected IEEE 802.3 CRC-32 polynomial (<c>0xEDB88320</c>).</summary>
    private const uint Polynomial = 0xEDB88320U;

    /// <summary>The number of bits in a byte.</summary>
    private const int BitsPerByte = 8;

    /// <summary>Computes the IEEE 802.3 CRC-32 checksum over <paramref name="data"/>.</summary>
    /// <param name="data">The input bytes.</param>
    /// <returns>The 32-bit CRC checksum.</returns>
    internal static uint HashToUInt32(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var b in data)
        {
            crc ^= b;
            for (var bit = 0; bit < BitsPerByte; bit++)
            {
                crc = (crc >> 1) ^ (Polynomial & (uint)-(int)(crc & 1U));
            }
        }

        return ~crc;
    }
}
