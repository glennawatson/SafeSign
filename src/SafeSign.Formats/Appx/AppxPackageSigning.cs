// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SafeSign.Formats.Compression;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Appx;

/// <summary>
/// Implements the APPX/MSIX composite digest (<c>APPX</c> + <c>AXPC</c> + <c>AXCD</c> + <c>AXCT</c> + <c>AXBM</c> + optional <c>AXCI</c>)
/// and embeds <c>AppxSignature.p7x</c> (<c>PKCX</c> magic + Authenticode PKCS #7 <c>SignedData</c>).
/// </summary>
public static class AppxPackageSigning
{
    /// <summary>The <c>SpcSipInfo</c> version expected by the Windows APPX/MSIX SIP (<c>0x01010000</c>).</summary>
    private const int AppxSipVersion = 0x01010000;

    /// <summary>The byte length of the <c>PKCX</c>, <c>APPX</c>, and <c>AX*</c> 4-byte magic markers.</summary>
    private const int MagicTagLength = 4;

    /// <summary>The number of mandatory 4-byte digest tags in the APPX composite digest (<c>AXPC</c>, <c>AXCD</c>, <c>AXCT</c>, <c>AXBM</c>).</summary>
    private const int MandatoryDigestCount = 4;

    /// <summary>The ZIP End of Central Directory (EOCD) signature (<c>0x06054B50</c>).</summary>
    private const uint EocdSignature = 0x06054B50U;

    /// <summary>The Zip64 End of Central Directory record signature (<c>0x06064B50</c>).</summary>
    private const uint Zip64EocdSignature = 0x06064B50U;

    /// <summary>The Zip64 End of Central Directory locator signature (<c>0x07064B50</c>).</summary>
    private const uint Zip64LocatorSignature = 0x07064B50U;

    /// <summary>The sentinel 32-bit value (<c>0xFFFFFFFF</c>) indicating a Zip64 field override.</summary>
    private const uint Zip64Sentinel32 = 0xFFFFFFFFU;

    /// <summary>The sentinel 16-bit value (<c>0xFFFF</c>) indicating a Zip64 field override.</summary>
    private const ushort Zip64Sentinel16 = 0xFFFF;

    /// <summary>The byte length of a Zip64 End of Central Directory locator record.</summary>
    private const int Zip64LocatorLength = 20;

    /// <summary>The offset of the Zip64 EOCD offset field inside the Zip64 EOCD locator.</summary>
    private const int Zip64LocatorEocdOffsetField = 8;

    /// <summary>The offset of the disk entry count in a Zip64 EOCD record.</summary>
    private const int Zip64EocdDiskEntriesOffset = 24;

    /// <summary>The offset of the total entry count in a Zip64 EOCD record.</summary>
    private const int Zip64EocdTotalEntriesOffset = 32;

    /// <summary>The offset of the central directory byte size in a Zip64 EOCD record.</summary>
    private const int Zip64EocdCentralDirSizeOffset = 40;

    /// <summary>The offset of the central directory start offset in a Zip64 EOCD record.</summary>
    private const int Zip64EocdCentralDirOffsetOffset = 48;

    /// <summary>The ZIP Central Directory File Header signature (<c>0x02014B50</c>).</summary>
    private const uint CentralHeaderSignature = 0x02014B50U;

    /// <summary>The ZIP Local File Header signature (<c>0x04034B50</c>).</summary>
    private const uint LocalHeaderSignature = 0x04034B50U;

    /// <summary>The ZIP version made by value written by APPX packagers (<c>45</c> = 4.5).</summary>
    private const ushort ZipVersionMadeBy = 45;

    /// <summary>The ZIP version needed to extract value (<c>20</c> = 2.0).</summary>
    private const ushort ZipVersionNeeded = 20;

    /// <summary>The ZIP STORED compression method (<c>0</c>).</summary>
    private const ushort ZipMethodStored = 0;

    /// <summary>The ZIP DEFLATED compression method (<c>8</c>).</summary>
    private const ushort ZipMethodDeflated = 8;

    /// <summary>The MS-DOS modification date and time value representing the ZIP epoch date.</summary>
    private const uint DosEpochDateTime = 0x00210000U;

    /// <summary>The minimum size of a ZIP End of Central Directory record.</summary>
    private const int MinEocdLength = 22;

    /// <summary>The fixed size of a ZIP Local File Header.</summary>
    private const int LocalHeaderFixedLength = 30;

    /// <summary>The fixed size of a ZIP Central Directory Header.</summary>
    private const int CentralHeaderFixedLength = 46;

    /// <summary>The offset of the disk entry count in the EOCD record.</summary>
    private const int EocdDiskEntriesOffset = 8;

    /// <summary>The offset of the total entry count in the EOCD record.</summary>
    private const int EocdTotalEntriesOffset = 10;

    /// <summary>The offset of the central directory byte size in the EOCD record.</summary>
    private const int EocdCentralDirSizeOffset = 12;

    /// <summary>The offset of the central directory start offset in the EOCD record.</summary>
    private const int EocdCentralDirOffsetOffset = 16;

    /// <summary>The offset of the version made by field in a Central Directory header.</summary>
    private const int CentralVersionMadeByOffset = 4;

    /// <summary>The offset of the version needed field in a Central Directory header.</summary>
    private const int CentralVersionNeededOffset = 6;

    /// <summary>The offset of the compression method in a Central Directory header.</summary>
    private const int CentralCompressionMethodOffset = 10;

    /// <summary>The offset of the MS-DOS modification time/date in a Central Directory header.</summary>
    private const int CentralModDateTimeOffset = 12;

    /// <summary>The offset of the CRC-32 field in a Central Directory header.</summary>
    private const int CentralCrc32Offset = 16;

    /// <summary>The offset of the compressed size in a Central Directory header.</summary>
    private const int CentralCompressedSizeOffset = 20;

    /// <summary>The offset of the uncompressed size in a Central Directory header.</summary>
    private const int CentralUncompressedSizeOffset = 24;

    /// <summary>The offset of the file name length in a Central Directory header.</summary>
    private const int CentralNameLengthOffset = 28;

    /// <summary>The offset of the extra field length in a Central Directory header.</summary>
    private const int CentralExtraLengthOffset = 30;

    /// <summary>The offset of the comment length in a Central Directory header.</summary>
    private const int CentralCommentLengthOffset = 32;

    /// <summary>The offset of the local header offset in a Central Directory header.</summary>
    private const int CentralLocalHeaderOffset = 42;

    /// <summary>The offset of the version needed field in a Local File Header.</summary>
    private const int LocalVersionNeededOffset = 4;

    /// <summary>The offset of the compression method in a Local File Header.</summary>
    private const int LocalCompressionMethodOffset = 8;

    /// <summary>The offset of the MS-DOS modification time/date in a Local File Header.</summary>
    private const int LocalModDateTimeOffset = 10;

    /// <summary>The offset of the CRC-32 field in a Local File Header.</summary>
    private const int LocalCrc32Offset = 14;

    /// <summary>The offset of the compressed size in a Local File Header.</summary>
    private const int LocalCompressedSizeOffset = 18;

    /// <summary>The offset of the uncompressed size in a Local File Header.</summary>
    private const int LocalUncompressedSizeOffset = 22;

    /// <summary>The offset of the file name length in a Local File Header.</summary>
    private const int LocalNameLengthOffset = 26;

    /// <summary>The offset of the extra field length in a Local File Header.</summary>
    private const int LocalExtraLengthOffset = 28;

    /// <summary>The Windows APPX and MSIX Subject Interface Package unique identifier (wire bytes <c>4BDFC50A-07CE-E24D-B76E-23C839A09FD1</c>).</summary>
    private static readonly Guid AppxSipGuid = new("0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1");

    /// <summary>The Windows APPX/MSIX Bundle Subject Interface Package unique identifier (wire bytes <c>B3585F0F-DEAA-9A4B-A434-95742D92ECEB</c>).</summary>
    private static readonly Guid AppxBundleSipGuid = new("0F5F58B3-AADE-4B9A-A434-95742D92ECEB");

    /// <summary>Gets the ZIP entry name of the embedded APPX/MSIX signature.</summary>
    public static string SignatureEntryName => "AppxSignature.p7x";

    /// <summary>Gets the ZIP entry name of the OPC content types manifest.</summary>
    public static string ContentTypesEntryName => "[Content_Types].xml";

    /// <summary>Gets the ZIP entry name of the APPX block map.</summary>
    public static string BlockMapEntryName => "AppxBlockMap.xml";

    /// <summary>Gets the ZIP entry name of the optional code integrity catalog.</summary>
    public static string CodeIntegrityEntryName => "AppxMetadata/CodeIntegrity.cat";

    /// <summary>Gets the ZIP entry name of the optional APPX/MSIX bundle manifest.</summary>
    public static string BundleManifestEntryName => "AppxMetadata/AppxBundleManifest.xml";

    /// <summary>Signs an APPX/MSIX ZIP payload and returns the signed ZIP bytes containing <c>AppxSignature.p7x</c>.</summary>
    /// <param name="zipBytes">The input ZIP archive bytes.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The signed ZIP archive bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> is null.</exception>
    public static async ValueTask<byte[]> SignZipBytesAsync(
        ReadOnlyMemory<byte> zipBytes,
        SigningSession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        var preparedZip = PrepareUnsignedZip(zipBytes.Span, out var isBundle);
        var compositeDigest = ComputeAppxCompositeDigest(preparedZip, session.DigestAlgorithm);
        var sipGuid = isBundle ? AppxBundleSipGuid : AppxSipGuid;

        var pkcs7 = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(AppxSipVersion, sipGuid), compositeDigest),
            cancellationToken).ConfigureAwait(false);

        var p7x = new byte[MagicTagLength + pkcs7.Length];
        "PKCX"u8.CopyTo(p7x);
        pkcs7.CopyTo(p7x.AsSpan(MagicTagLength));

        return AppendSignatureEntry(preparedZip, p7x);
    }

    /// <summary>Removes any existing <c>AppxSignature.p7x</c> entry and ensures <c>[Content_Types].xml</c> declares the signature part override.</summary>
    /// <param name="zip">The input ZIP archive bytes.</param>
    /// <param name="isBundle">Receives <see langword="true"/> when the archive contains <c>AppxMetadata/AppxBundleManifest.xml</c>.</param>
    /// <returns>The prepared unsigned ZIP bytes.</returns>
    /// <exception cref="InvalidDataException">The package is missing <c>[Content_Types].xml</c> or <c>AppxBlockMap.xml</c>.</exception>
    private static byte[] PrepareUnsignedZip(ReadOnlySpan<byte> zip, out bool isBundle)
    {
        var current = RemoveEntryIfPresent(zip, SignatureEntryName);
        var (centralOffset, centralSize, _, _, _) = LocateCentralDirectory(current);
        var centralDir = current.AsSpan(centralOffset, centralSize);

        _ = ReadUncompressedPart(current, centralDir, BlockMapEntryName, required: true);
        isBundle = ReadUncompressedPart(current, centralDir, BundleManifestEntryName, required: false).Length > 0;

        var contentTypesBytes = ReadUncompressedPart(current, centralDir, ContentTypesEntryName, required: true);
        var xmlText = Encoding.UTF8.GetString(contentTypesBytes);
        if (xmlText.Contains("/AppxSignature.p7x", StringComparison.OrdinalIgnoreCase))
        {
            return current;
        }

        const string closingTag = "</Types>";
        var closeIdx = xmlText.LastIndexOf(closingTag, StringComparison.OrdinalIgnoreCase);
        if (closeIdx < 0)
        {
            return current;
        }

        const string overrideTag = "<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>";
        var updatedXmlBytes = Encoding.UTF8.GetBytes(string.Concat(xmlText.AsSpan(0, closeIdx), overrideTag, xmlText.AsSpan(closeIdx)));
        var withoutOldContentTypes = RemoveEntryIfPresent(current, ContentTypesEntryName);
        return AppendZipEntry(withoutOldContentTypes, ContentTypesEntryName, updatedXmlBytes, compress: true);
    }

    /// <summary>Computes the APPX composite digest (<c>APPX</c> + <c>AXPC</c> + <c>AXCD</c> + <c>AXCT</c> + <c>AXBM</c> + optional <c>AXCI</c>) over the unsigned ZIP archive.</summary>
    /// <param name="zip">The unsigned ZIP archive bytes.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The composite digest bytes.</returns>
    /// <exception cref="InvalidDataException">The ZIP central directory or required APPX parts could not be located.</exception>
    private static byte[] ComputeAppxCompositeDigest(ReadOnlySpan<byte> zip, HashAlgorithmName algorithm)
    {
        var (centralOffset, centralSize, _, _, _) = LocateCentralDirectory(zip);
        var centralDir = zip.Slice(centralOffset, centralSize);

        var axpcDigest = CryptographicOperations.HashData(algorithm, zip[..centralOffset]);
        var axcdDigest = CryptographicOperations.HashData(algorithm, zip[centralOffset..]);
        var axctDigest = CryptographicOperations.HashData(
            algorithm,
            ReadUncompressedPart(zip, centralDir, ContentTypesEntryName, required: true));
        var axbmDigest = CryptographicOperations.HashData(
            algorithm,
            ReadUncompressedPart(zip, centralDir, BlockMapEntryName, required: true));
        var codeIntegrityBytes = ReadUncompressedPart(zip, centralDir, CodeIntegrityEntryName, required: false);
        var axciDigest = codeIntegrityBytes.Length > 0
            ? CryptographicOperations.HashData(algorithm, codeIntegrityBytes)
            : [];

        var hashLen = axpcDigest.Length;
        var totalLength = MagicTagLength
            + (MandatoryDigestCount * (MagicTagLength + hashLen))
            + (axciDigest.Length > 0 ? MagicTagLength + hashLen : 0);
        var composite = new byte[totalLength];
        var span = composite.AsSpan();
        var pos = 0;

        "APPX"u8.CopyTo(span[pos..]);
        pos += MagicTagLength;
        WriteTaggedDigest(span, ref pos, "AXPC"u8, axpcDigest);
        WriteTaggedDigest(span, ref pos, "AXCD"u8, axcdDigest);
        WriteTaggedDigest(span, ref pos, "AXCT"u8, axctDigest);
        WriteTaggedDigest(span, ref pos, "AXBM"u8, axbmDigest);
        if (axciDigest.Length > 0)
        {
            WriteTaggedDigest(span, ref pos, "AXCI"u8, axciDigest);
        }

        return composite;
    }

    /// <summary>Writes a 4-byte tag followed by a digest into <paramref name="destination"/>.</summary>
    /// <param name="destination">The output buffer.</param>
    /// <param name="position">The current write offset, updated in place.</param>
    /// <param name="tag">The 4-byte ASCII tag.</param>
    /// <param name="digest">The digest bytes.</param>
    private static void WriteTaggedDigest(Span<byte> destination, ref int position, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> digest)
    {
        tag.CopyTo(destination[position..]);
        position += tag.Length;
        digest.CopyTo(destination[position..]);
        position += digest.Length;
    }

    /// <summary>Finds a part in the ZIP central directory and returns its uncompressed bytes.</summary>
    /// <param name="zip">The full ZIP archive bytes.</param>
    /// <param name="centralDir">The central directory slice.</param>
    /// <param name="partName">The part name to locate.</param>
    /// <param name="required">Whether to throw if the part is absent.</param>
    /// <returns>The uncompressed part bytes, or an empty array when an optional part is absent.</returns>
    /// <exception cref="InvalidDataException">A required part is missing or its local header is malformed.</exception>
    private static byte[] ReadUncompressedPart(
        ReadOnlySpan<byte> zip,
        ReadOnlySpan<byte> centralDir,
        string partName,
        bool required)
    {
        var step = 0;
        for (var pos = 0; pos + CentralHeaderFixedLength <= centralDir.Length; pos += step)
        {
            var entry = centralDir[pos..];
            var method = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralCompressionMethodOffset..]);
            var compressedSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralCompressedSizeOffset..]);
            var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralNameLengthOffset..]);
            var extraLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralExtraLengthOffset..]);
            var commentLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralCommentLengthOffset..]);
            var localOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralLocalHeaderOffset..]);
            var nameSpan = entry.Slice(CentralHeaderFixedLength, nameLen);

            if (Encoding.UTF8.GetString(nameSpan).Equals(partName, StringComparison.OrdinalIgnoreCase))
            {
                var localHeader = zip[localOffset..];
                if (localHeader.Length < LocalHeaderFixedLength
                    || BinaryPrimitives.ReadUInt32LittleEndian(localHeader) != LocalHeaderSignature)
                {
                    throw new InvalidDataException($"Invalid ZIP local file header for '{partName}'.");
                }

                var localNameLen = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[LocalNameLengthOffset..]);
                var localExtraLen = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[LocalExtraLengthOffset..]);
                var dataStart = localOffset + LocalHeaderFixedLength + localNameLen + localExtraLen;
                var rawSlice = zip.Slice(dataStart, compressedSize);
                return method switch
                {
                    ZipMethodStored => rawSlice.ToArray(),
                    ZipMethodDeflated => DeflateCodec.DecompressRaw(rawSlice),
                    _ => throw new InvalidDataException($"Unsupported ZIP compression method {method} for '{partName}'."),
                };
            }

            step = CentralHeaderFixedLength + nameLen + extraLen + commentLen;
        }

        return required
            ? throw new InvalidDataException($"Required APPX part '{partName}' was not found in the central directory.")
            : [];
    }

    /// <summary>Removes an entry from a ZIP archive at the byte level while preserving all other local file headers byte-for-byte.</summary>
    /// <param name="zip">The input ZIP archive bytes.</param>
    /// <param name="targetEntryName">The entry name to remove.</param>
    /// <returns>The ZIP archive bytes without <paramref name="targetEntryName"/>.</returns>
    private static byte[] RemoveEntryIfPresent(ReadOnlySpan<byte> zip, string targetEntryName)
    {
        var (centralOffset, centralSize, trailerOffset, eocdOffset, isZip64) = LocateCentralDirectory(zip);
        var centralDir = zip.Slice(centralOffset, centralSize);

        var (targetCentralStart, targetCentralLength, targetLocalStart, targetLocalEnd, totalEntries) =
            LocateEntryForRemoval(centralDir, centralOffset, targetEntryName);
        if (targetCentralStart < 0)
        {
            return zip.ToArray();
        }

        var removedLocalLength = targetLocalEnd - targetLocalStart;
        var newCentralOffset = centralOffset - removedLocalLength;
        var newCentralSize = centralSize - targetCentralLength;
        var trailerSlice = zip[trailerOffset..];
        var output = new byte[newCentralOffset + newCentralSize + trailerSlice.Length];

        zip[..targetLocalStart].CopyTo(output);
        zip[targetLocalEnd..centralOffset].CopyTo(output.AsSpan(targetLocalStart));

        var updatedCentral = centralDir.ToArray();
        AdjustCentralDirectoryOffsets(updatedCentral, targetLocalStart, removedLocalLength);
        updatedCentral.AsSpan(0, targetCentralStart).CopyTo(output.AsSpan(newCentralOffset));
        updatedCentral.AsSpan(targetCentralStart + targetCentralLength).CopyTo(output.AsSpan(newCentralOffset + targetCentralStart));

        var newTrailer = output.AsSpan(newCentralOffset + newCentralSize);
        trailerSlice.CopyTo(newTrailer);
        WriteUpdatedTrailer(newTrailer, eocdOffset - trailerOffset, isZip64, totalEntries - 1, newCentralSize, newCentralOffset);
        return output;
    }

    /// <summary>Locates a central directory entry and the byte range of its local file record.</summary>
    /// <param name="centralDir">The central directory slice.</param>
    /// <param name="centralOffset">The byte offset where the central directory starts.</param>
    /// <param name="targetEntryName">The entry name to locate.</param>
    /// <returns>The central header span, local record span, and total central directory entry count.</returns>
    private static (int CentralStart, int CentralLength, int LocalStart, int LocalEnd, int TotalEntries) LocateEntryForRemoval(
        ReadOnlySpan<byte> centralDir,
        int centralOffset,
        string targetEntryName)
    {
        var targetCentralStart = -1;
        var targetCentralLength = 0;
        var targetLocalStart = -1;
        var targetLocalEnd = centralOffset;
        var entryOffsets = new List<int>();
        var step = 0;
        for (var pos = 0; pos + CentralHeaderFixedLength <= centralDir.Length; pos += step)
        {
            var entry = centralDir[pos..];
            var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralNameLengthOffset..]);
            var extraLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralExtraLengthOffset..]);
            var commentLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralCommentLengthOffset..]);
            var localOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralLocalHeaderOffset..]);
            step = CentralHeaderFixedLength + nameLen + extraLen + commentLen;
            entryOffsets.Add(localOffset);

            var name = Encoding.UTF8.GetString(entry.Slice(CentralHeaderFixedLength, nameLen));
            if (!name.Equals(targetEntryName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            targetCentralStart = pos;
            targetCentralLength = step;
            targetLocalStart = localOffset;
        }

        if (targetCentralStart < 0)
        {
            return (-1, 0, -1, centralOffset, entryOffsets.Count);
        }

        for (var i = 0; i < entryOffsets.Count; i++)
        {
            var candidate = entryOffsets[i];
            if (candidate > targetLocalStart && candidate < targetLocalEnd)
            {
                targetLocalEnd = candidate;
            }
        }

        return (targetCentralStart, targetCentralLength, targetLocalStart, targetLocalEnd, entryOffsets.Count);
    }

    /// <summary>Shifts local header offsets in <paramref name="centralDir"/> for entries after <paramref name="removedLocalStart"/>.</summary>
    /// <param name="centralDir">The mutable central directory bytes.</param>
    /// <param name="removedLocalStart">The start offset of the removed local record.</param>
    /// <param name="removedLocalLength">The byte length of the removed local record.</param>
    private static void AdjustCentralDirectoryOffsets(Span<byte> centralDir, int removedLocalStart, int removedLocalLength)
    {
        var step = 0;
        for (var pos = 0; pos + CentralHeaderFixedLength <= centralDir.Length; pos += step)
        {
            var entry = centralDir[pos..];
            var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralNameLengthOffset..]);
            var extraLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralExtraLengthOffset..]);
            var commentLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralCommentLengthOffset..]);
            var localOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralLocalHeaderOffset..]);
            if (localOffset > removedLocalStart)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(entry[CentralLocalHeaderOffset..], (uint)(localOffset - removedLocalLength));
            }

            step = CentralHeaderFixedLength + nameLen + extraLen + commentLen;
        }
    }

    /// <summary>Locates the central directory and EOCD/Zip64 EOCD trailer in <paramref name="zip"/>.</summary>
    /// <param name="zip">The ZIP archive bytes.</param>
    /// <returns>The central directory offset, size, trailer start offset, standard EOCD offset, and whether Zip64 EOCD is present.</returns>
    /// <exception cref="InvalidDataException">The EOCD or Zip64 EOCD record is missing or malformed.</exception>
    private static (int CentralOffset, int CentralSize, int TrailerOffset, int EocdOffset, bool IsZip64) LocateCentralDirectory(ReadOnlySpan<byte> zip)
    {
        var eocdOffset = FindEocdOffset(zip);
        if (eocdOffset >= Zip64LocatorLength
            && BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocdOffset - Zip64LocatorLength)..]) == Zip64LocatorSignature)
        {
            var zip64EocdOffset = (int)BinaryPrimitives.ReadUInt64LittleEndian(zip[(eocdOffset - Zip64LocatorLength + Zip64LocatorEocdOffsetField)..]);
            if (zip64EocdOffset < 0
                || zip64EocdOffset > eocdOffset - Zip64LocatorLength
                || BinaryPrimitives.ReadUInt32LittleEndian(zip[zip64EocdOffset..]) != Zip64EocdSignature)
            {
                throw new InvalidDataException("Invalid Zip64 End of Central Directory record.");
            }

            var centralSize64 = (int)BinaryPrimitives.ReadUInt64LittleEndian(zip[(zip64EocdOffset + Zip64EocdCentralDirSizeOffset)..]);
            var centralOffset64 = (int)BinaryPrimitives.ReadUInt64LittleEndian(zip[(zip64EocdOffset + Zip64EocdCentralDirOffsetOffset)..]);
            return (centralOffset64, centralSize64, zip64EocdOffset, eocdOffset, true);
        }

        var centralSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocdOffset + EocdCentralDirSizeOffset)..]);
        var centralOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocdOffset + EocdCentralDirOffsetOffset)..]);
        return (centralOffset, centralSize, eocdOffset, eocdOffset, false);
    }

    /// <summary>Updates the Zip64 EOCD, Zip64 Locator, and standard EOCD fields in <paramref name="trailer"/>.</summary>
    /// <param name="trailer">The mutable trailer slice starting at either the Zip64 EOCD or the standard EOCD.</param>
    /// <param name="relativeEocdOffset">The offset of the standard EOCD within <paramref name="trailer"/>.</param>
    /// <param name="isZip64">Whether <paramref name="trailer"/> starts with a Zip64 EOCD record.</param>
    /// <param name="totalEntries">The updated entry count.</param>
    /// <param name="centralSize">The updated central directory byte length.</param>
    /// <param name="centralOffset">The updated central directory start offset.</param>
    private static void WriteUpdatedTrailer(
        Span<byte> trailer,
        int relativeEocdOffset,
        bool isZip64,
        int totalEntries,
        int centralSize,
        int centralOffset)
    {
        if (isZip64)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(trailer[Zip64EocdDiskEntriesOffset..], (ulong)totalEntries);
            BinaryPrimitives.WriteUInt64LittleEndian(trailer[Zip64EocdTotalEntriesOffset..], (ulong)totalEntries);
            BinaryPrimitives.WriteUInt64LittleEndian(trailer[Zip64EocdCentralDirSizeOffset..], (ulong)centralSize);
            BinaryPrimitives.WriteUInt64LittleEndian(trailer[Zip64EocdCentralDirOffsetOffset..], (ulong)centralOffset);

            var locatorSpan = trailer[(relativeEocdOffset - Zip64LocatorLength)..];
            BinaryPrimitives.WriteUInt64LittleEndian(locatorSpan[Zip64LocatorEocdOffsetField..], (ulong)(centralOffset + centralSize));
        }

        var eocdSpan = trailer[relativeEocdOffset..];
        if (!isZip64 || BinaryPrimitives.ReadUInt16LittleEndian(eocdSpan[EocdDiskEntriesOffset..]) != Zip64Sentinel16)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(eocdSpan[EocdDiskEntriesOffset..], (ushort)totalEntries);
        }

        if (!isZip64 || BinaryPrimitives.ReadUInt16LittleEndian(eocdSpan[EocdTotalEntriesOffset..]) != Zip64Sentinel16)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(eocdSpan[EocdTotalEntriesOffset..], (ushort)totalEntries);
        }

        if (!isZip64 || BinaryPrimitives.ReadUInt32LittleEndian(eocdSpan[EocdCentralDirSizeOffset..]) != Zip64Sentinel32)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(eocdSpan[EocdCentralDirSizeOffset..], (uint)centralSize);
        }

        if (!isZip64 || BinaryPrimitives.ReadUInt32LittleEndian(eocdSpan[EocdCentralDirOffsetOffset..]) != Zip64Sentinel32)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(eocdSpan[EocdCentralDirOffsetOffset..], (uint)centralOffset);
        }
    }

    /// <summary>Finds the offset of the ZIP End of Central Directory record.</summary>
    /// <param name="zip">The ZIP archive bytes.</param>
    /// <returns>The byte offset of the EOCD record.</returns>
    /// <exception cref="InvalidDataException">No EOCD signature was found.</exception>
    private static int FindEocdOffset(ReadOnlySpan<byte> zip)
    {
        for (var i = zip.Length - MinEocdLength; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip[i..]) == EocdSignature)
            {
                return i;
            }
        }

        throw new InvalidDataException("The package is not a valid ZIP archive (End of Central Directory record not found).");
    }

    /// <summary>Appends <c>AppxSignature.p7x</c> as a deflated entry with zeroed external file attributes.</summary>
    /// <param name="unsignedZip">The unsigned ZIP archive bytes.</param>
    /// <param name="p7xBytes">The <c>PKCX</c>-prefixed signature bytes.</param>
    /// <returns>The signed ZIP archive bytes.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] AppendSignatureEntry(byte[] unsignedZip, byte[] p7xBytes) =>
        AppendZipEntry(unsignedZip, SignatureEntryName, p7xBytes, compress: true);

    /// <summary>Appends a single entry to a ZIP archive at the byte level without modifying existing local file headers.</summary>
    /// <param name="zip">The input ZIP archive bytes.</param>
    /// <param name="entryName">The UTF-8 entry path.</param>
    /// <param name="uncompressedData">The uncompressed entry payload.</param>
    /// <param name="compress">Whether to deflate the payload or store it uncompressed.</param>
    /// <returns>The updated ZIP archive bytes.</returns>
    private static byte[] AppendZipEntry(ReadOnlySpan<byte> zip, string entryName, ReadOnlySpan<byte> uncompressedData, bool compress)
    {
        var (centralOffset, centralSize, trailerOffset, eocdOffset, isZip64) = LocateCentralDirectory(zip);
        var centralCount = isZip64
            ? (int)BinaryPrimitives.ReadUInt64LittleEndian(zip[(trailerOffset + Zip64EocdTotalEntriesOffset)..])
            : BinaryPrimitives.ReadUInt16LittleEndian(zip[(eocdOffset + EocdTotalEntriesOffset)..]);
        var trailerSlice = zip[trailerOffset..];

        var nameBytes = Encoding.UTF8.GetBytes(entryName);
        var crc32 = ZipCrc32.HashToUInt32(uncompressedData);
        var payload = compress
            ? DeflateCodec.CompressRaw(uncompressedData, CompressionLevel.SmallestSize)
            : uncompressedData;
        var method = compress ? ZipMethodDeflated : ZipMethodStored;

        var localEntryLength = LocalHeaderFixedLength + nameBytes.Length + payload.Length;
        var centralEntryLength = CentralHeaderFixedLength + nameBytes.Length;
        var newCentralOffset = centralOffset + localEntryLength;
        var newCentralSize = centralSize + centralEntryLength;

        var output = new byte[newCentralOffset + newCentralSize + trailerSlice.Length];
        zip[..centralOffset].CopyTo(output);

        var localSpan = output.AsSpan(centralOffset, localEntryLength);
        BinaryPrimitives.WriteUInt32LittleEndian(localSpan, LocalHeaderSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(localSpan[LocalVersionNeededOffset..], ZipVersionNeeded);
        BinaryPrimitives.WriteUInt16LittleEndian(localSpan[LocalCompressionMethodOffset..], method);
        BinaryPrimitives.WriteUInt32LittleEndian(localSpan[LocalModDateTimeOffset..], DosEpochDateTime);
        BinaryPrimitives.WriteUInt32LittleEndian(localSpan[LocalCrc32Offset..], crc32);
        BinaryPrimitives.WriteUInt32LittleEndian(localSpan[LocalCompressedSizeOffset..], (uint)payload.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(localSpan[LocalUncompressedSizeOffset..], (uint)uncompressedData.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(localSpan[LocalNameLengthOffset..], (ushort)nameBytes.Length);
        nameBytes.CopyTo(localSpan[LocalHeaderFixedLength..]);
        payload.CopyTo(localSpan[(LocalHeaderFixedLength + nameBytes.Length)..]);

        zip.Slice(centralOffset, centralSize).CopyTo(output.AsSpan(newCentralOffset));
        var centralSpan = output.AsSpan(newCentralOffset + centralSize, centralEntryLength);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan, CentralHeaderSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(centralSpan[CentralVersionMadeByOffset..], ZipVersionMadeBy);
        BinaryPrimitives.WriteUInt16LittleEndian(centralSpan[CentralVersionNeededOffset..], ZipVersionNeeded);
        BinaryPrimitives.WriteUInt16LittleEndian(centralSpan[CentralCompressionMethodOffset..], method);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan[CentralModDateTimeOffset..], DosEpochDateTime);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan[CentralCrc32Offset..], crc32);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan[CentralCompressedSizeOffset..], (uint)payload.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan[CentralUncompressedSizeOffset..], (uint)uncompressedData.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(centralSpan[CentralNameLengthOffset..], (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(centralSpan[CentralLocalHeaderOffset..], (uint)centralOffset);
        nameBytes.CopyTo(centralSpan[CentralHeaderFixedLength..]);

        var newTrailer = output.AsSpan(newCentralOffset + newCentralSize);
        trailerSlice.CopyTo(newTrailer);
        WriteUpdatedTrailer(newTrailer, eocdOffset - trailerOffset, isZip64, centralCount + 1, newCentralSize, newCentralOffset);
        return output;
    }
}
