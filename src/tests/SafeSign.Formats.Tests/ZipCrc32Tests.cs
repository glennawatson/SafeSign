// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Text;
using SafeSign.Formats.Compression;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies ZIP's IEEE CRC-32 checksum and sliced-input behavior.</summary>
public sealed class ZipCrc32Tests
{
    /// <summary>The reflected IEEE CRC-32 polynomial.</summary>
    private const uint Polynomial = 0xEDB88320U;

    /// <summary>The number of bits in each byte.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The source bytes outside the checksum slice.</summary>
    private const int SlicePadding = 2;

    /// <summary>Verifies standard CRC-32 vectors, including empty input.</summary>
    /// <param name="text">The ASCII checksum input.</param>
    /// <param name="expected">The expected IEEE CRC-32 checksum.</param>
    /// <returns>A task representing the asynchronous test.</returns>
    [Test]
    [Arguments("", 0U)]
    [Arguments("123456789", 0xCBF43926U)]
    public async Task HashToUInt32_KnownVectors_ReturnsIeeeChecksum(string text, uint expected) =>
        await Assert.That(ZipCrc32.HashToUInt32(Encoding.ASCII.GetBytes(text))).IsEqualTo(expected);

    /// <summary>Verifies vector boundaries, odd tails, and offset slices against a scalar reference.</summary>
    /// <param name="length">The checksum slice length.</param>
    /// <param name="cancellationToken">Cancels the test.</param>
    /// <returns>A task representing the asynchronous test.</returns>
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(15)]
    [Arguments(16)]
    [Arguments(31)]
    [Arguments(32)]
    [Arguments(127)]
    [Arguments(128)]
    [Arguments(4097)]
    [Arguments(65_537)]
    public async Task HashToUInt32_SlicedInput_MatchesScalarReference(int length, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = new byte[length + SlicePadding];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)i;
        }

        var input = bytes.AsSpan(1, length);
        await Assert.That(ZipCrc32.HashToUInt32(input)).IsEqualTo(ComputeScalarChecksum(input));
    }

    /// <summary>Computes the IEEE checksum without architecture-specific acceleration.</summary>
    /// <param name="data">The checksum bytes.</param>
    /// <returns>The IEEE CRC-32 checksum.</returns>
    private static uint ComputeScalarChecksum(ReadOnlySpan<byte> data)
    {
        var crc = uint.MaxValue;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < BitsPerByte; bit++)
            {
                crc = (crc >> 1) ^ (Polynomial & (uint)-(int)(crc & 1U));
            }
        }

        return ~crc;
    }
}
