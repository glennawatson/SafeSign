// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using SafeSign.Signing.Pe;

namespace SafeSign.Signing.Tests;

/// <summary>Verifies the SIMD-accelerated PE checksum implementation against a scalar reference.</summary>
public sealed class PeChecksumTests
{
    /// <summary>The 16-bit carry mask.</summary>
    private const ulong WordMask = 0xFFFF;

    /// <summary>The bit shift for a 16-bit word.</summary>
    private const int WordShift = 16;

    /// <summary>The multiplier used to populate deterministic test data.</summary>
    private const int FillMultiplier = 73;

    /// <summary>The additive constant used to populate deterministic test data.</summary>
    private const int FillIncrement = 19;

    /// <summary>Verifies that <see cref="PeChecksum"/> matches the scalar ones'-complement checksum across odd, aligned, and multi-block sizes.</summary>
    /// <param name="length">The payload byte length.</param>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(15)]
    [Arguments(16)]
    [Arguments(31)]
    [Arguments(64)]
    [Arguments(255)]
    [Arguments(4096)]
    [Arguments(65_537)]
    [Arguments(131_075)]
    public async Task AccumulateAndFinish_MatchesScalarReference(int length)
    {
        var data = new byte[length];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = unchecked((byte)((i * FillMultiplier) + FillIncrement));
        }

        var actual = PeChecksum.Finish(PeChecksum.Accumulate(data, 0), data.Length);
        var expected = ComputeScalarChecksum(data);

        await Assert.That(actual).IsEqualTo(expected);
    }

    /// <summary>Computes the scalar 16-bit ones'-complement PE checksum.</summary>
    /// <param name="data">The input bytes.</param>
    /// <returns>The finished PE checksum.</returns>
    private static uint ComputeScalarChecksum(ReadOnlySpan<byte> data)
    {
        ulong sum = 0;
        var index = 0;
        while (index + 1 < data.Length)
        {
            sum += BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(index, sizeof(ushort)));
            sum = (sum & WordMask) + (sum >> WordShift);
            index += sizeof(ushort);
        }

        if (index < data.Length)
        {
            sum += data[index];
            sum = (sum & WordMask) + (sum >> WordShift);
        }

        sum = (sum & WordMask) + (sum >> WordShift);
        return unchecked((uint)(sum + (ulong)data.Length));
    }
}
