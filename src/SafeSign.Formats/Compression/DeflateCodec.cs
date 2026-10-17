// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SafeSign.Formats.Compression;

/// <summary>
/// Span-oriented raw Deflate and ZLib compression/decompression using .NET 11's <c>DeflateEncoder</c>,
/// <c>DeflateDecoder</c>, <c>ZLibEncoder</c>, and <c>ZLibDecoder</c> on <c>net11.0</c>, with stream-based
/// <see cref="DeflateStream"/> and <see cref="ZLibStream"/> fallbacks on <c>net10.0</c>.
/// </summary>
public static class DeflateCodec
{
    /// <summary>The fixed 64 KB block size required by the APPX/MSIX block map specification.</summary>
    internal const int AppxBlockSize = 65_536;

    /// <summary>The extra margin added per 64 KB block when sizing a sync-flushed APPX deflate buffer.</summary>
    private const int SyncFlushBlockOverhead = 64;

#if NET11_0_OR_GREATER
    /// <summary>The default scratch chunk size when inflating an unknown-length payload.</summary>
    private const int DefaultChunkSize = 16_384;

    /// <summary>The default ZLib compression level (<c>6</c>).</summary>
    private const int OptimalQuality = 6;

    /// <summary>The maximum ZLib compression level (<c>9</c>).</summary>
    private const int SmallestSizeQuality = 9;

    /// <summary>The initial decompression buffer multiplier.</summary>
    private const int InitialExpandFactor = 2;

    /// <summary>The standard RFC 1951 32 KB window log (<c>15</c>).</summary>
    private const int DefaultWindowLog = 15;
#endif

    /// <summary>Compresses <paramref name="source"/> using raw RFC 1951 Deflate at optimal compression.</summary>
    /// <param name="source">The uncompressed input bytes.</param>
    /// <returns>The raw Deflate-compressed bytes.</returns>
    /// <exception cref="InvalidOperationException">Compression failed.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] CompressRaw(ReadOnlySpan<byte> source) =>
        CompressRaw(source, CompressionLevel.Optimal);

    /// <summary>Compresses <paramref name="source"/> using raw RFC 1951 Deflate.</summary>
    /// <param name="source">The uncompressed input bytes.</param>
    /// <param name="level">The compression level.</param>
    /// <returns>The raw Deflate-compressed bytes.</returns>
    /// <exception cref="InvalidOperationException">Compression failed.</exception>
    public static byte[] CompressRaw(ReadOnlySpan<byte> source, CompressionLevel level)
    {
#if NET11_0_OR_GREATER
        var maxLength = (int)DeflateEncoder.GetMaxCompressedLength(source.Length);
        var rented = ArrayPool<byte>.Shared.Rent(maxLength);
        try
        {
            var quality = level switch
            {
                CompressionLevel.NoCompression => 0,
                CompressionLevel.Fastest => 1,
                CompressionLevel.SmallestSize => SmallestSizeQuality,
                _ => OptimalQuality,
            };
            if (!DeflateEncoder.TryCompress(source, rented, out var written, quality, DefaultWindowLog))
            {
                throw new InvalidOperationException("DeflateEncoder.TryCompress failed to compress buffer.");
            }

            return rented.AsSpan(0, written).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
#else
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, level, leaveOpen: true))
        {
            deflate.Write(source);
        }

        return output.ToArray();
#endif
    }

    /// <summary>Decompresses a raw RFC 1951 Deflate stream into a byte array.</summary>
    /// <param name="compressed">The raw Deflate-compressed bytes.</param>
    /// <returns>The decompressed bytes.</returns>
    /// <exception cref="InvalidDataException">The compressed data is corrupt.</exception>
    public static byte[] DecompressRaw(ReadOnlySpan<byte> compressed)
    {
#if NET11_0_OR_GREATER
        if (compressed.IsEmpty)
        {
            return [];
        }

        using var decoder = new DeflateDecoder();
        var writer = new ArrayBufferWriter<byte>(Math.Max(compressed.Length * InitialExpandFactor, DefaultChunkSize));
        var remaining = compressed;
        while (true)
        {
            var dest = writer.GetSpan(DefaultChunkSize);
            var status = decoder.Decompress(remaining, dest, out var consumed, out var written);
            remaining = remaining[consumed..];
            writer.Advance(written);
            if (status == OperationStatus.Done)
            {
                break;
            }

            if (status == OperationStatus.InvalidData || (status == OperationStatus.NeedMoreData && remaining.IsEmpty && written == 0))
            {
                throw new InvalidDataException("The raw Deflate stream is corrupt or truncated.");
            }
        }

        return writer.WrittenSpan.ToArray();
#else
        if (compressed.IsEmpty)
        {
            return [];
        }

        using var input = new MemoryStream(compressed.ToArray(), writable: false);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
#endif
    }

    /// <summary>Compresses <paramref name="source"/> in 64 KB sync-flushed Deflate blocks and computes the SHA-256 digest of each uncompressed block for <c>AppxBlockMap.xml</c>.</summary>
    /// <param name="source">The uncompressed file bytes.</param>
    /// <param name="blockHashes">Receives the SHA-256 digest of each 64 KB uncompressed block.</param>
    /// <param name="blockCompressedSizes">Receives the compressed byte length of each 64 KB block.</param>
    /// <returns>The concatenated Deflate stream.</returns>
    /// <exception cref="InvalidOperationException">Block compression failed.</exception>
    public static byte[] CompressAppxBlocks(
        ReadOnlySpan<byte> source,
        out List<byte[]> blockHashes,
        out List<int> blockCompressedSizes)
    {
        blockHashes = [];
        blockCompressedSizes = [];
#if NET11_0_OR_GREATER
        return source.IsEmpty
            ? CompressRaw(ReadOnlySpan<byte>.Empty)
            : CompressAppxBlocksNet11(source, blockHashes, blockCompressedSizes);
#else
        return source.IsEmpty
            ? CompressRaw(ReadOnlySpan<byte>.Empty)
            : CompressAppxBlocksNet10(source, blockHashes, blockCompressedSizes);
#endif
    }

#if NET11_0_OR_GREATER
    /// <summary>Compresses 64 KB APPX blocks using .NET 11's <see cref="DeflateEncoder"/>.</summary>
    /// <param name="source">The uncompressed file bytes.</param>
    /// <param name="blockHashes">Receives the SHA-256 digest of each 64 KB block.</param>
    /// <param name="blockCompressedSizes">Receives the compressed byte length of each 64 KB block.</param>
    /// <returns>The concatenated Deflate stream.</returns>
    /// <exception cref="InvalidOperationException">The block buffer was too small for <see cref="DeflateEncoder"/>.</exception>
    private static byte[] CompressAppxBlocksNet11(
        ReadOnlySpan<byte> source,
        List<byte[]> blockHashes,
        List<int> blockCompressedSizes)
    {
        using var encoder = new DeflateEncoder(new ZLibCompressionOptions { CompressionLevel = OptimalQuality });
        var writer = new ArrayBufferWriter<byte>(source.Length + SyncFlushBlockOverhead);
        var maxBlockOut = (int)DeflateEncoder.GetMaxCompressedLength(AppxBlockSize) + SyncFlushBlockOverhead;

        for (var offset = 0; offset < source.Length; offset += AppxBlockSize)
        {
            var length = Math.Min(AppxBlockSize, source.Length - offset);
            var isFinal = offset + length >= source.Length;
            var block = source.Slice(offset, length);
            blockHashes.Add(SHA256.HashData(block));

            var dest = writer.GetSpan(maxBlockOut);
            var status = encoder.Compress(block, dest, out var consumed, out var written, isFinalBlock: isFinal);
            if (consumed != block.Length || (isFinal && status != OperationStatus.Done))
            {
                throw new InvalidOperationException("DeflateEncoder failed to compress 64 KB APPX block.");
            }

            var flushed = 0;
            if (!isFinal)
            {
                _ = encoder.Flush(dest[written..], out flushed);
            }

            var totalBlockBytes = written + flushed;
            writer.Advance(totalBlockBytes);
            blockCompressedSizes.Add(totalBlockBytes);
        }

        return writer.WrittenSpan.ToArray();
    }
#else
    /// <summary>Compresses 64 KB APPX blocks using .NET 10's <see cref="DeflateStream"/> with <see cref="DeflateStream.Flush"/> boundaries.</summary>
    /// <param name="source">The uncompressed file bytes.</param>
    /// <param name="blockHashes">Receives the SHA-256 digest of each 64 KB block.</param>
    /// <param name="blockCompressedSizes">Receives the compressed byte length of each 64 KB block.</param>
    /// <returns>The concatenated Deflate stream.</returns>
    private static byte[] CompressAppxBlocksNet10(
        ReadOnlySpan<byte> source,
        List<byte[]> blockHashes,
        List<int> blockCompressedSizes)
    {
        using var output = new MemoryStream(source.Length + SyncFlushBlockOverhead);
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            var previousPosition = 0L;
            for (var offset = 0; offset < source.Length; offset += AppxBlockSize)
            {
                var length = Math.Min(AppxBlockSize, source.Length - offset);
                var isFinal = offset + length >= source.Length;
                var block = source.Slice(offset, length);
                blockHashes.Add(SHA256.HashData(block));

                deflate.Write(block);
                if (isFinal)
                {
                    continue;
                }

                deflate.Flush();
                var currentPosition = output.Position;
                blockCompressedSizes.Add((int)(currentPosition - previousPosition));
                previousPosition = currentPosition;
            }
        }

        var finalPosition = output.Position;
        var priorSum = 0;
        for (var i = 0; i < blockCompressedSizes.Count; i++)
        {
            priorSum += blockCompressedSizes[i];
        }

        blockCompressedSizes.Add((int)finalPosition - priorSum);
        return output.ToArray();
    }
#endif
}
