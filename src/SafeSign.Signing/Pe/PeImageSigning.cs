// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using Microsoft.Win32.SafeHandles;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Signing.Pe;

/// <summary>Signs an open PE image in place: Windows executables, libraries, drivers and UEFI images.</summary>
public static class PeImageSigning
{
    /// <summary>The certificate table alignment the PE specification requires.</summary>
    private const int Alignment = 8;

    /// <summary>The <c>WIN_CERTIFICATE</c> header size.</summary>
    private const int WinCertificateHeaderSize = 8;

    /// <summary>The <c>WIN_CERT_REVISION_2_0</c> revision.</summary>
    private const ushort Revision2 = 0x0200;

    /// <summary>The <c>WIN_CERT_TYPE_PKCS_SIGNED_DATA</c> certificate type.</summary>
    private const ushort TypePkcsSignedData = 0x0002;

    /// <summary>The number of bytes needed to read <c>e_lfanew</c>.</summary>
    private const int DosHeaderSize = 64;

    /// <summary>Replaces any signature in an open PE image with a new Authenticode signature.</summary>
    /// <param name="file">The image, opened for asynchronous read and write.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the reads, the provider call and the writes.</param>
    /// <returns>A task that completes when the image is signed.</returns>
    /// <exception cref="InvalidDataException">The image is malformed or has data after its certificate table.</exception>
    public static async ValueTask SignAsync(SafeFileHandle file, SigningSession session, CancellationToken cancellationToken)
    {
        var length = RandomAccess.GetLength(file);
        var layout = await ReadLayoutAsync(file, length, cancellationToken).ConfigureAwait(false);
        length = await StripAndPadAsync(file, layout, length, cancellationToken).ConfigureAwait(false);

        var digest = await PeAuthenticodeDigest.ComputeAsync(file, layout, length, session.DigestAlgorithm, cancellationToken).ConfigureAwait(false);
        var signature = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcPeImageData, AuthenticodeEncoding.EncodePeImageData(), digest.Digest),
            cancellationToken).ConfigureAwait(false);

        var certificateTable = BuildCertificateTable(signature);
        if (length + certificateTable.Length > uint.MaxValue)
        {
            throw new InvalidDataException("The signed image would exceed the 4 GiB PE limit.");
        }

        var entry = new byte[Alignment];
        BinaryPrimitives.WriteUInt32LittleEndian(entry, (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(sizeof(uint)), (uint)certificateTable.Length);

        var sum = PeChecksum.Accumulate(certificateTable, PeChecksum.Accumulate(entry, digest.ChecksumSum));
        var checksum = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(checksum, PeChecksum.Finish(sum, length + certificateTable.Length));

        await RandomAccess.WriteAsync(file, certificateTable, length, cancellationToken).ConfigureAwait(false);
        await RandomAccess.WriteAsync(file, entry, layout.CertificateEntryOffset, cancellationToken).ConfigureAwait(false);
        await RandomAccess.WriteAsync(file, checksum, layout.ChecksumOffset, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads and parses the headers.</summary>
    /// <param name="file">The image.</param>
    /// <param name="length">The file length.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    /// <returns>The layout.</returns>
    /// <exception cref="InvalidDataException">The headers are malformed.</exception>
    private static async ValueTask<PeLayout> ReadLayoutAsync(SafeFileHandle file, long length, CancellationToken cancellationToken)
    {
        var dos = new byte[DosHeaderSize];
        var read = await RandomAccess.ReadAsync(file, dos, 0, cancellationToken).ConfigureAwait(false);
        var required = PeLayoutReader.RequiredHeaderLength(dos.AsSpan(0, read));
        if (required > length)
        {
            throw new InvalidDataException("Not a PE image: the headers run past the end of the file.");
        }

        var header = new byte[required];
        read = await RandomAccess.ReadAsync(file, header, 0, cancellationToken).ConfigureAwait(false);
        return PeLayoutReader.Read(header.AsSpan(0, read), length);
    }

    /// <summary>Removes the old certificate table, zeroes the fields the digest skips and pads to the table alignment.</summary>
    /// <param name="file">The image.</param>
    /// <param name="layout">The layout.</param>
    /// <param name="length">The current length.</param>
    /// <param name="cancellationToken">Cancels the writes.</param>
    /// <returns>The length to hash, which is where the new table goes.</returns>
    /// <exception cref="InvalidDataException">Data follows the existing certificate table.</exception>
    private static async ValueTask<long> StripAndPadAsync(SafeFileHandle file, PeLayout layout, long length, CancellationToken cancellationToken)
    {
        if (layout.CertificateTableSize > 0)
        {
            // Data after the table would sit outside both the digest and the table, so Windows rejects such files.
            if (layout.CertificateTableOffset + layout.CertificateTableSize != length)
            {
                throw new InvalidDataException("The existing certificate table is not at the end of the file.");
            }

            length = layout.CertificateTableOffset;
            RandomAccess.SetLength(file, length);
        }

        await RandomAccess.WriteAsync(file, new byte[Alignment], layout.CertificateEntryOffset, cancellationToken).ConfigureAwait(false);
        await RandomAccess.WriteAsync(file, new byte[sizeof(uint)], layout.ChecksumOffset, cancellationToken).ConfigureAwait(false);

        // The padding before the table is covered by the digest, so it is written before hashing.
        var padding = (int)((Alignment - (length % Alignment)) % Alignment);
        if (padding > 0)
        {
            await RandomAccess.WriteAsync(file, new byte[padding], length, cancellationToken).ConfigureAwait(false);
            length += padding;
        }

        return length;
    }

    /// <summary>Wraps a PKCS #7 signature in an aligned <c>WIN_CERTIFICATE</c>.</summary>
    /// <param name="signature">The DER signature.</param>
    /// <returns>The certificate table bytes.</returns>
    private static byte[] BuildCertificateTable(byte[] signature)
    {
        var size = (WinCertificateHeaderSize + signature.Length + Alignment - 1) & ~(Alignment - 1);
        var table = new byte[size];
        BinaryPrimitives.WriteUInt32LittleEndian(table, (uint)size);
        BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(sizeof(uint)), Revision2);
        BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(sizeof(uint) + sizeof(ushort)), TypePkcsSignedData);
        signature.CopyTo(table.AsSpan(WinCertificateHeaderSize));
        return table;
    }
}
