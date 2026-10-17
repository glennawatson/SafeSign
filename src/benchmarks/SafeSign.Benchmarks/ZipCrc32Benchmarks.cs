// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.IO.Compression;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using SafeSign.Formats.Compression;
using SafeSign.Formats.NuGet;

namespace SafeSign.Benchmarks;

/// <summary>Compares ZIP checksum computation against the runtime's managed CPU-accelerated implementation.</summary>
[MemoryDiagnoser]
[EventPipeProfiler(EventPipeProfile.CpuSampling)]
public class ZipCrc32Benchmarks
{
    /// <summary>The checksum payload.</summary>
    private byte[] _data = [];

    /// <summary>The unsigned package used to measure complete signature entry insertion.</summary>
    private byte[] _unsignedPackage = [];

    /// <summary>Gets or sets the payload length, including empty input to expose fixed cost.</summary>
    [Params(0, 1024, 4096, 65_536)]
    public int Length { get; set; }

    /// <summary>Creates deterministic bytes and checks that both implementations agree.</summary>
    /// <exception cref="InvalidDataException">The checksum implementations disagree.</exception>
    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Length];
        for (var i = 0; i < _data.Length; i++)
        {
            _data[i] = (byte)i;
        }

        if (ZipCrc32.HashToUInt32(_data) != System.IO.Hashing.Crc32.HashToUInt32(_data))
        {
            throw new InvalidDataException("The ZIP CRC-32 benchmark implementations disagree.");
        }

        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("payload.bin", CompressionLevel.NoCompression);
            using var stream = entry.Open();
            stream.Write(_data);
        }

        _unsignedPackage = buffer.ToArray();
        var signed = AddSignatureEntry();
        if (!CryptographicOperations.FixedTimeEquals(NuGetSignatureArchive.RemoveSignature(signed), _unsignedPackage))
        {
            throw new InvalidDataException("The ZIP signature benchmark fixture did not round-trip.");
        }
    }

    /// <summary>Computes the checksum using SafeSign's ZIP implementation.</summary>
    /// <returns>The IEEE CRC-32 checksum.</returns>
    [Benchmark(Baseline = true)]
    public uint ZipChecksum() => ZipCrc32.HashToUInt32(_data);

    /// <summary>Computes the checksum using the runtime's cross-platform hashing implementation.</summary>
    /// <returns>The IEEE CRC-32 checksum.</returns>
    [Benchmark]
    public uint RuntimeChecksum() => System.IO.Hashing.Crc32.HashToUInt32(_data);

    /// <summary>Measures complete signature entry insertion, including CRC-32 and owned ZIP output.</summary>
    /// <returns>The ZIP bytes containing the signature entry.</returns>
    [Benchmark]
    public byte[] AddSignatureEntry() => NuGetSignatureArchive.AddSignature(_unsignedPackage, _data, DateTime.UnixEpoch);
}
