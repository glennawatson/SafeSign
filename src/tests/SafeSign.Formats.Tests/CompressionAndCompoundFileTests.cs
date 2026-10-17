// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.IO.Compression;
using SafeSign.Formats.CompoundFile;
using SafeSign.Formats.Compression;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies <see cref="DeflateCodec"/>, <see cref="MemoryStreams"/>, <see cref="CompoundFileReader"/>, and <see cref="CompoundFileWriter"/>.</summary>
public sealed class CompressionAndCompoundFileTests
{
    /// <summary>The test payload size in bytes that spans more than one 64 KiB APPX block.</summary>
    private const int MultiBlockPayloadLength = 100_000;

    /// <summary>The byte length of a stream stored in regular sectors (>= 4096 bytes).</summary>
    private const int RegularSectorStreamLength = 6000;

    /// <summary>The byte length of a stream stored in the mini-stream (&lt; 4096 bytes).</summary>
    private const int MiniStreamLength = 300;

    /// <summary>The prime multiplier used to populate deterministic test bytes.</summary>
    private const int PatternPrime = 31;

    /// <summary>The expected number of root children in the compound file round-trip test.</summary>
    private const int ExpectedRootChildrenCount = 3;

    /// <summary>The expected number of 64 KiB APPX blocks for a 100,000-byte payload.</summary>
    private const int ExpectedAppxBlockCount = 2;

    /// <summary>The synthetic creation timestamp for compound file storage metadata.</summary>
    private const long CreatedTimestamp = 100L;

    /// <summary>The synthetic modification timestamp for compound file storage metadata.</summary>
    private const long ModifiedTimestamp = 200L;

    /// <summary>Verifies that <see cref="DeflateCodec.CompressRaw(ReadOnlySpan{byte}, CompressionLevel)"/> and <see cref="DeflateCodec.DecompressRaw"/> round-trip payloads losslessly.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task DeflateCodec_CompressesAndDecompressesRawDeflatePayloads()
    {
        var original = CreateDeterministicBytes(MultiBlockPayloadLength);
        var compressed = DeflateCodec.CompressRaw(original, CompressionLevel.Fastest);
        var roundTripped = DeflateCodec.DecompressRaw(compressed);

        await Assert.That(compressed.Length).IsLessThan(original.Length);
        await Assert.That(roundTripped.AsSpan().SequenceEqual(original)).IsTrue();
    }

    /// <summary>Verifies that <see cref="DeflateCodec.CompressAppxBlocks"/> emits individually flushed 64 KiB blocks that decompress to the original payload.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task DeflateCodec_CompressAppxBlocks_ProducesValidBlockFlushedDeflateStream()
    {
        var original = CreateDeterministicBytes(MultiBlockPayloadLength);
        var compressed = DeflateCodec.CompressAppxBlocks(original, out var blockHashes, out var blockSizes);
        var decompressed = DeflateCodec.DecompressRaw(compressed);

        await Assert.That(blockHashes.Count).IsEqualTo(ExpectedAppxBlockCount);
        await Assert.That(blockSizes.Count).IsEqualTo(ExpectedAppxBlockCount);
        await Assert.That(decompressed.AsSpan().SequenceEqual(original)).IsTrue();
    }

    /// <summary>Verifies <see cref="MemoryStreams.OpenRead"/>, <see cref="MemoryStreams.OpenFixedWrite"/>, and <see cref="MemoryStreams.OpenWrite"/>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task MemoryStreams_ReadsAndWritesBuffersCorrectly()
    {
        var payload = "SafeSign MemoryStreams verification"u8.ToArray();
        await using var readStream = MemoryStreams.OpenRead(payload);
        var readBack = new byte[payload.Length];
        var bytesRead = await readStream.ReadAsync(readBack, CancellationToken.None);
        await Assert.That(bytesRead).IsEqualTo(payload.Length);
        await Assert.That(readBack.AsSpan().SequenceEqual(payload)).IsTrue();

        var fixedTarget = new byte[payload.Length];
        await using (var fixedWrite = MemoryStreams.OpenFixedWrite(fixedTarget))
        {
            await fixedWrite.WriteAsync(payload, CancellationToken.None);
        }

        await Assert.That(fixedTarget.AsSpan().SequenceEqual(payload)).IsTrue();

        await using var expandable = MemoryStreams.OpenWrite(payload.Length, out var getBytes);
        await expandable.WriteAsync(payload, CancellationToken.None);
        var written = getBytes();
        await Assert.That(written.AsSpan().SequenceEqual(payload)).IsTrue();
    }

    /// <summary>Verifies that <see cref="CompoundFileWriter"/> and <see cref="CompoundFileReader"/> round-trip mini-streams, regular streams, and nested storages.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CompoundFile_WritesAndReadsMiniStreamsRegularStreamsAndSubStorages()
    {
        var miniData = CreateDeterministicBytes(MiniStreamLength);
        var regularData = CreateDeterministicBytes(RegularSectorStreamLength);
        var nestedData = "Nested stream payload"u8.ToArray();

        var subStorage = new CompoundFileEntry(
            "SubStorage",
            new(Guid.NewGuid(), 0, CreatedTimestamp, ModifiedTimestamp),
            ReadOnlyMemory<byte>.Empty,
            [new("NestedStream", default, nestedData, null)]);

        var root = new CompoundFileEntry(
            "Root Entry",
            new(Guid.NewGuid(), 0, 0L, 0L),
            ReadOnlyMemory<byte>.Empty,
            [
                new("MiniStream", default, miniData, null),
                new("RegularStream", default, regularData, null),
                subStorage,
            ]);

        var serialized = CompoundFileWriter.Write(root);
        await Assert.That(CompoundFileFormat.HasSignature(serialized)).IsTrue();

        var parsed = CompoundFileReader.Read(serialized);
        await Assert.That(parsed.Children).IsNotNull();
        await Assert.That(parsed.Children!.Count).IsEqualTo(ExpectedRootChildrenCount);

        var parsedMini = parsed.Children.Find(static e => e.Name == "MiniStream");
        var parsedRegular = parsed.Children.Find(static e => e.Name == "RegularStream");
        var parsedSub = parsed.Children.Find(static e => e.Name == "SubStorage");

        await Assert.That(parsedMini).IsNotNull();
        await Assert.That(parsedMini!.Data.Span.SequenceEqual(miniData)).IsTrue();
        await Assert.That(parsedRegular).IsNotNull();
        await Assert.That(parsedRegular!.Data.Span.SequenceEqual(regularData)).IsTrue();
        await Assert.That(parsedSub).IsNotNull();
        await Assert.That(parsedSub!.Children).IsNotNull();
        await Assert.That(parsedSub.Children![0].Data.Span.SequenceEqual(nestedData)).IsTrue();
    }

    /// <summary>Creates a deterministic byte array of <paramref name="length"/> bytes.</summary>
    /// <param name="length">The array length.</param>
    /// <returns>The populated byte array.</returns>
    private static byte[] CreateDeterministicBytes(int length)
    {
        var buffer = new byte[length];
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i] = (byte)((i * PatternPrime) & byte.MaxValue);
        }

        return buffer;
    }
}
