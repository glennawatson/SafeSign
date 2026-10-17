// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace SafeSign.Signing.Pe;

/// <summary>
/// Computes the PE image checksum. The checksum is a 16-bit end-around-carry sum of the file's little-endian words
/// plus the file length. Because 65536 is congruent to 1 modulo 65535, summing 32-bit words and folding once at the
/// end gives the same result as folding after every 16-bit word, which lets the sum run over SIMD lanes.
/// </summary>
public static class PeChecksum
{
    /// <summary>The mask of the low 16 bits.</summary>
    private const ulong LowWord = 0xFFFF;

    /// <summary>The shift to the high 16 bits.</summary>
    private const int WordBits = 16;

    /// <summary>Adds bytes that start at an even file offset to a running sum.</summary>
    /// <param name="data">The bytes. An odd trailing byte counts as a word with a zero high byte.</param>
    /// <param name="sum">The running sum.</param>
    /// <returns>The new running sum.</returns>
    public static ulong Accumulate(ReadOnlySpan<byte> data, ulong sum)
    {
        var words = MemoryMarshal.Cast<byte, uint>(data[..(data.Length & ~(sizeof(uint) - 1))]);
        var index = 0;
        if (BitConverter.IsLittleEndian && Vector.IsHardwareAccelerated && words.Length >= Vector<uint>.Count)
        {
            var accumulator = Vector<ulong>.Zero;
            for (; index <= words.Length - Vector<uint>.Count; index += Vector<uint>.Count)
            {
                Vector.Widen(new Vector<uint>(words[index..]), out var low, out var high);
                accumulator += low + high;
            }

            sum += Vector.Sum(accumulator);
        }

        for (; index < words.Length; index++)
        {
            sum += BitConverter.IsLittleEndian ? words[index] : BinaryPrimitives.ReverseEndianness(words[index]);
        }

        var tail = data[(words.Length * sizeof(uint))..];
        if (tail.Length >= sizeof(ushort))
        {
            sum += BinaryPrimitives.ReadUInt16LittleEndian(tail);
            tail = tail[sizeof(ushort)..];
        }

        if (!tail.IsEmpty)
        {
            sum += tail[0];
        }

        return sum;
    }

    /// <summary>Folds a running sum to 16 bits and adds the file length.</summary>
    /// <param name="sum">The running sum over every word except the checksum field.</param>
    /// <param name="fileLength">The final file length.</param>
    /// <returns>The value for the optional header's <c>CheckSum</c> field.</returns>
    public static uint Finish(ulong sum, long fileLength)
    {
        while (sum > LowWord)
        {
            sum = (sum & LowWord) + (sum >> WordBits);
        }

        return unchecked((uint)(sum + (ulong)fileLength));
    }
}
