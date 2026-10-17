// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace SafeSign.Signing.Pe;

/// <summary>
/// Computes the Authenticode digest of an unsigned PE image: every byte except the <c>CheckSum</c> field, the
/// certificate table directory entry and the certificate table itself. The checksum sum is gathered in the same pass so
/// the file is read once.
/// </summary>
public static class PeAuthenticodeDigest
{
    /// <summary>The read buffer size; large enough to amortise each read, small enough to stay out of the large object heap.</summary>
    private const int BufferSize = 80 * 1024;

    /// <summary>The size of the certificate table directory entry.</summary>
    private const int CertificateEntrySize = 8;

    /// <summary>Hashes an image whose certificate table has already been removed.</summary>
    /// <param name="file">The open image.</param>
    /// <param name="layout">The image layout.</param>
    /// <param name="length">The number of bytes to hash: the file length without any certificate table.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns>The digest and checksum sum.</returns>
    public static async ValueTask<PeDigest> ComputeAsync(
        SafeFileHandle file,
        PeLayout layout,
        long length,
        HashAlgorithmName algorithm,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            var state = new PeHashState(file, hash, buffer);
            var sum = await HashRangeAsync(state, 0, layout.ChecksumOffset, 0, cancellationToken).ConfigureAwait(false);
            sum = await HashRangeAsync(state, layout.ChecksumOffset + sizeof(uint), layout.CertificateEntryOffset, sum, cancellationToken).ConfigureAwait(false);
            sum = await HashRangeAsync(state, layout.CertificateEntryOffset + CertificateEntrySize, length, sum, cancellationToken).ConfigureAwait(false);
            return new(hash.GetHashAndReset(), sum);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Hashes and sums one byte range.</summary>
    /// <param name="state">The file, hash and buffer.</param>
    /// <param name="start">The first offset.</param>
    /// <param name="end">The offset after the last byte.</param>
    /// <param name="sum">The running checksum sum.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns>The new checksum sum.</returns>
    /// <exception cref="EndOfStreamException">The file is shorter than the range.</exception>
    private static async ValueTask<ulong> HashRangeAsync(PeHashState state, long start, long end, ulong sum, CancellationToken cancellationToken)
    {
        var (file, hash, buffer) = state;
        for (var offset = start; offset < end;)
        {
            var wanted = (int)Math.Min(buffer.Length, end - offset);

            // A short read could end mid-word; the checksum folds whole words, so each chunk is filled completely.
            var filled = 0;
            while (filled < wanted)
            {
                var read = await RandomAccess.ReadAsync(file, buffer.AsMemory(filled, wanted - filled), offset + filled, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException($"The image ended at {offset + filled} while hashing up to {end}.");
                }

                filled += read;
            }

            var chunk = buffer.AsSpan(0, filled);
            hash.AppendData(chunk);
            sum = PeChecksum.Accumulate(chunk, sum);
            offset += filled;
        }

        return sum;
    }
}
