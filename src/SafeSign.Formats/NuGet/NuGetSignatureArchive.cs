// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeSign.Formats.Compression;

namespace SafeSign.Formats.NuGet;

/// <summary>
/// Inserts and removes the NuGet package signature entry by splicing raw ZIP records, exactly as NuGet's own
/// <c>SignedPackageArchiveIOUtility</c> does.
/// </summary>
/// <remarks>
/// <para>
/// NuGet verifies a signed package by reconstructing the unsigned archive byte-for-byte: it drops the
/// <c>.signature.p7s</c> local entry and central directory header and rewinds the end of central directory counts.
/// Any other byte that differs from the archive that was hashed breaks integrity, so the existing entries are never
/// re-encoded, only copied.
/// </para>
/// <para>
/// The signature entry itself must have a general purpose flag of 0, compression method 0 (stored), equal compressed
/// and uncompressed sizes, and external file attributes of 0 (NU3005). <see cref="System.IO.Compression.ZipArchive"/>
/// writes Unix permission bits (<c>0x81A40000</c>) into the external attributes on Linux and macOS, so it cannot be used.
/// </para>
/// </remarks>
internal static class NuGetSignatureArchive
{
    /// <summary>The local file header signature (<c>PK\x03\x04</c>).</summary>
    private const uint LocalFileHeaderSignature = 0x04034B50;

    /// <summary>The central directory file header signature (<c>PK\x01\x02</c>).</summary>
    private const uint CentralDirectoryHeaderSignature = 0x02014B50;

    /// <summary>The end of central directory record signature (<c>PK\x05\x06</c>).</summary>
    private const uint EndOfCentralDirectorySignature = 0x06054B50;

    /// <summary>The ZIP64 end of central directory locator signature (<c>PK\x06\x07</c>).</summary>
    private const uint Zip64LocatorSignature = 0x07064B50;

    /// <summary>The size of the fixed fields of a local file header.</summary>
    private const int LocalFileHeaderSize = 30;

    /// <summary>The offset of the version needed to extract in a local file header.</summary>
    private const int LocalVersionNeededOffset = 4;

    /// <summary>The offset of the general purpose flag in a local file header, where the shared fields start.</summary>
    private const int LocalCommonFieldsOffset = 6;

    /// <summary>The size of the fixed fields of a central directory header.</summary>
    private const int CentralDirectoryHeaderSize = 46;

    /// <summary>The offset of the version made by in a central directory header.</summary>
    private const int CentralVersionMadeByOffset = 4;

    /// <summary>The offset of the version needed to extract in a central directory header.</summary>
    private const int CentralVersionNeededOffset = 6;

    /// <summary>The offset of the general purpose flag in a central directory header, where the shared fields start.</summary>
    private const int CentralCommonFieldsOffset = 8;

    /// <summary>The offset of the file name length in a central directory header.</summary>
    private const int CentralNameLengthOffset = 28;

    /// <summary>The offset of the extra field length in a central directory header.</summary>
    private const int CentralExtraLengthOffset = 30;

    /// <summary>The offset of the file comment length in a central directory header.</summary>
    private const int CentralCommentLengthOffset = 32;

    /// <summary>The offset of the relative local header offset in a central directory header.</summary>
    private const int CentralLocalHeaderOffset = 42;

    /// <summary>The size of the fixed fields of the end of central directory record.</summary>
    private const int EndOfCentralDirectorySize = 22;

    /// <summary>The offset of this disk's number in the end of central directory record.</summary>
    private const int EndDiskNumberOffset = 4;

    /// <summary>The offset of the central directory's start disk in the end of central directory record.</summary>
    private const int EndDirectoryDiskOffset = 6;

    /// <summary>The offset of this disk's entry count in the end of central directory record.</summary>
    private const int EndDiskEntriesOffset = 8;

    /// <summary>The offset of the total entry count in the end of central directory record.</summary>
    private const int EndTotalEntriesOffset = 10;

    /// <summary>The offset of the central directory size in the end of central directory record.</summary>
    private const int EndDirectorySizeOffset = 12;

    /// <summary>The offset of the central directory offset in the end of central directory record.</summary>
    private const int EndDirectoryOffsetOffset = 16;

    /// <summary>The offset of the comment length in the end of central directory record.</summary>
    private const int EndCommentLengthOffset = 20;

    /// <summary>The size of the ZIP64 end of central directory locator.</summary>
    private const int Zip64LocatorSize = 20;

    /// <summary>The offset of the compression method within the shared header fields.</summary>
    private const int CommonMethodOffset = 2;

    /// <summary>The offset of the MS-DOS time and date within the shared header fields.</summary>
    private const int CommonDosTimeOffset = 4;

    /// <summary>The offset of the CRC-32 within the shared header fields.</summary>
    private const int CommonCrcOffset = 8;

    /// <summary>The offset of the compressed size within the shared header fields.</summary>
    private const int CommonCompressedSizeOffset = 12;

    /// <summary>The offset of the uncompressed size within the shared header fields.</summary>
    private const int CommonUncompressedSizeOffset = 16;

    /// <summary>The offset of the file name length within the shared header fields.</summary>
    private const int CommonNameLengthOffset = 20;

    /// <summary>The offset of the extra field length within the shared header fields.</summary>
    private const int CommonExtraLengthOffset = 22;

    /// <summary>"Version 2.0", used for both version made by (host MS-DOS) and version needed to extract.</summary>
    private const ushort ZipVersion20 = 20;

    /// <summary>The earliest year an MS-DOS timestamp can hold.</summary>
    private const int DosEpochYear = 1980;

    /// <summary>The latest year an MS-DOS timestamp can hold.</summary>
    private const int DosLastYear = 2107;

    /// <summary>The bit position of the year in an MS-DOS date.</summary>
    private const int DosYearShift = 9;

    /// <summary>The bit position of the month in an MS-DOS date.</summary>
    private const int DosMonthShift = 5;

    /// <summary>The bit position of the hour in an MS-DOS time.</summary>
    private const int DosHourShift = 11;

    /// <summary>The bit position of the minute in an MS-DOS time.</summary>
    private const int DosMinuteShift = 5;

    /// <summary>MS-DOS times count seconds in units of two.</summary>
    private const int DosSecondDivisor = 2;

    /// <summary>The bit position of the date in a packed MS-DOS date and time.</summary>
    private const int DosDateShift = 16;

    /// <summary>Gets the signature entry name; NuGet compares it ordinally and case-sensitively.</summary>
    internal static ReadOnlySpan<byte> SignatureEntryName => ".signature.p7s"u8;

    /// <summary>Returns <paramref name="zip"/> without its <c>.signature.p7s</c> entry, or the input unchanged when there is none.</summary>
    /// <param name="zip">The package bytes.</param>
    /// <returns>The unsigned package bytes.</returns>
    /// <exception cref="InvalidDataException">The package is not a valid single-disk ZIP archive.</exception>
    internal static byte[] RemoveSignature(byte[] zip)
    {
        var directory = ReadDirectory(zip);
        if (directory.SignatureIndex < 0)
        {
            return zip;
        }

        var signature = directory.Entries[directory.SignatureIndex];
        var entryEnd = directory.CentralDirectoryOffset;
        foreach (var entry in directory.Entries)
        {
            if (entry.LocalHeaderOffset > signature.LocalHeaderOffset && entry.LocalHeaderOffset < entryEnd)
            {
                entryEnd = entry.LocalHeaderOffset;
            }
        }

        var removedData = entryEnd - signature.LocalHeaderOffset;
        var result = GC.AllocateUninitializedArray<byte>(zip.Length - removedData - signature.HeaderLength);
        var source = zip.AsSpan();
        var destination = result.AsSpan();

        // Local entries before and after the signature entry.
        source[..signature.LocalHeaderOffset].CopyTo(destination);
        var written = signature.LocalHeaderOffset;
        source[entryEnd..directory.CentralDirectoryOffset].CopyTo(destination[written..]);
        written += directory.CentralDirectoryOffset - entryEnd;

        // Central directory without the signature header; offsets past the removed entry move back.
        for (var i = 0; i < directory.Entries.Length; i++)
        {
            if (i == directory.SignatureIndex)
            {
                continue;
            }

            var entry = directory.Entries[i];
            var header = destination.Slice(written, entry.HeaderLength);
            source.Slice(entry.HeaderPosition, entry.HeaderLength).CopyTo(header);
            if (entry.LocalHeaderOffset > signature.LocalHeaderOffset)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(header[CentralLocalHeaderOffset..], (uint)(entry.LocalHeaderOffset - removedData));
            }

            written += entry.HeaderLength;
        }

        WriteEndOfCentralDirectory(
            source[directory.EndOfCentralDirectoryPosition..],
            destination[written..],
            new(-1, directory.CentralDirectorySize - signature.HeaderLength, directory.CentralDirectoryOffset - removedData));
        return result;
    }

    /// <summary>Appends <paramref name="signature"/> as the last local entry and central directory header, copying every other byte.</summary>
    /// <param name="unsignedZip">The unsigned package bytes the signature content hash was computed over.</param>
    /// <param name="signature">The DER-encoded CMS signature.</param>
    /// <param name="modified">The entry's last modified time.</param>
    /// <returns>The signed package bytes.</returns>
    /// <exception cref="InvalidDataException">The package is not a valid single-disk ZIP archive or is already signed.</exception>
    internal static byte[] AddSignature(ReadOnlySpan<byte> unsignedZip, ReadOnlySpan<byte> signature, DateTime modified)
    {
        var directory = ReadDirectory(unsignedZip);
        if (directory.SignatureIndex >= 0)
        {
            throw new InvalidDataException("The package already contains a .signature.p7s entry.");
        }

        if (directory.CentralDirectoryOffset + directory.CentralDirectorySize != directory.EndOfCentralDirectoryPosition)
        {
            throw new InvalidDataException("The package has data between its central directory and end of central directory record.");
        }

        var name = SignatureEntryName;
        var localLength = LocalFileHeaderSize + name.Length + signature.Length;
        var headerLength = CentralDirectoryHeaderSize + name.Length;
        if ((long)unsignedZip.Length + localLength + headerLength > uint.MaxValue || directory.Entries.Length >= ushort.MaxValue - 1)
        {
            throw new InvalidDataException("Signing would push the package past the ZIP32 limits that NuGet requires.");
        }

        var crc = ZipCrc32.HashToUInt32(signature);
        var dosTime = ToDosDateTime(modified);
        var signatureOffset = directory.CentralDirectoryOffset;
        var result = GC.AllocateUninitializedArray<byte>(unsignedZip.Length + localLength + headerLength);
        var destination = result.AsSpan();

        unsignedZip[..signatureOffset].CopyTo(destination);
        var written = signatureOffset;

        var local = destination.Slice(written, LocalFileHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(local, LocalFileHeaderSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(local[LocalVersionNeededOffset..], ZipVersion20);
        WriteCommonFields(local[LocalCommonFieldsOffset..], dosTime, crc, signature.Length);
        written += LocalFileHeaderSize;
        name.CopyTo(destination[written..]);
        written += name.Length;
        signature.CopyTo(destination[written..]);
        written += signature.Length;

        unsignedZip.Slice(directory.CentralDirectoryOffset, directory.CentralDirectorySize).CopyTo(destination[written..]);
        written += directory.CentralDirectorySize;

        var header = destination.Slice(written, CentralDirectoryHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header, CentralDirectoryHeaderSignature);
        BinaryPrimitives.WriteUInt16LittleEndian(header[CentralVersionMadeByOffset..], ZipVersion20);
        BinaryPrimitives.WriteUInt16LittleEndian(header[CentralVersionNeededOffset..], ZipVersion20);
        WriteCommonFields(header[CentralCommonFieldsOffset..], dosTime, crc, signature.Length);

        // File comment length, disk number start, internal attributes and external attributes must all be zero.
        header[CentralCommentLengthOffset..CentralLocalHeaderOffset].Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(header[CentralLocalHeaderOffset..], (uint)signatureOffset);
        written += CentralDirectoryHeaderSize;
        name.CopyTo(destination[written..]);
        written += name.Length;

        WriteEndOfCentralDirectory(
            unsignedZip[directory.EndOfCentralDirectoryPosition..],
            destination[written..],
            new(1, directory.CentralDirectorySize + headerLength, directory.CentralDirectoryOffset + localLength));
        return result;
    }

    /// <summary>Reads the central directory of a single-disk ZIP32 archive.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <returns>The directory layout.</returns>
    /// <exception cref="InvalidDataException">The archive is malformed, spans disks, uses ZIP64, or has two signature entries.</exception>
    internal static ZipDirectory ReadDirectory(ReadOnlySpan<byte> zip)
    {
        var eocd = FindEndOfCentralDirectory(zip);
        var (count, offset, size) = ReadEndOfCentralDirectory(zip, eocd);

        var entries = new ZipDirectoryEntry[count];
        var signatureIndex = -1;
        var position = offset;
        for (var i = 0; i < count; i++)
        {
            entries[i] = ReadEntry(zip, position, offset, i, out var isSignature);
            if (isSignature)
            {
                signatureIndex = signatureIndex < 0
                    ? i
                    : throw new InvalidDataException("The package contains more than one .signature.p7s entry.");
            }

            position += entries[i].HeaderLength;
        }

        return position == offset + size
            ? new(entries, signatureIndex, offset, size, eocd)
            : throw new InvalidDataException("The central directory size does not match its headers.");
    }

    /// <summary>Reads and validates the end of central directory record.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <param name="eocd">The record's offset.</param>
    /// <returns>The entry count and the central directory offset and size.</returns>
    /// <exception cref="InvalidDataException">The archive spans disks, uses ZIP64, or the record is inconsistent.</exception>
    private static (int Count, int Offset, int Size) ReadEndOfCentralDirectory(ReadOnlySpan<byte> zip, int eocd)
    {
        var record = zip[eocd..];
        if (BinaryPrimitives.ReadUInt16LittleEndian(record[EndDiskNumberOffset..]) != 0
            || BinaryPrimitives.ReadUInt16LittleEndian(record[EndDirectoryDiskOffset..]) != 0)
        {
            throw new InvalidDataException("Multi-disk ZIP archives cannot be NuGet packages.");
        }

        var count = BinaryPrimitives.ReadUInt16LittleEndian(record[EndTotalEntriesOffset..]);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(record[EndDirectorySizeOffset..]);
        var offset = BinaryPrimitives.ReadUInt32LittleEndian(record[EndDirectoryOffsetOffset..]);
        var hasZip64Locator = eocd >= Zip64LocatorSize
            && BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocd - Zip64LocatorSize)..]) == Zip64LocatorSignature;
        if (hasZip64Locator || count == ushort.MaxValue || size == uint.MaxValue || offset == uint.MaxValue)
        {
            throw new InvalidDataException("ZIP64 packages cannot be signed; NuGet package signing requires ZIP32 records.");
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(record[EndDiskEntriesOffset..]) == count && (long)offset + size <= eocd
            ? (count, (int)offset, (int)size)
            : throw new InvalidDataException("The end of central directory record is inconsistent with the archive.");
    }

    /// <summary>Reads one central directory header.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <param name="position">The header's offset.</param>
    /// <param name="centralDirectoryOffset">The central directory offset; local headers must precede it.</param>
    /// <param name="index">The header's index, for error messages.</param>
    /// <param name="isSignature">Set when the entry is <c>.signature.p7s</c>.</param>
    /// <returns>The header layout.</returns>
    /// <exception cref="InvalidDataException">The header is corrupt.</exception>
    private static ZipDirectoryEntry ReadEntry(ReadOnlySpan<byte> zip, int position, int centralDirectoryOffset, int index, out bool isSignature)
    {
        var header = zip[position..];
        if (header.Length < CentralDirectoryHeaderSize || BinaryPrimitives.ReadUInt32LittleEndian(header) != CentralDirectoryHeaderSignature)
        {
            throw new InvalidDataException($"Central directory header {index} is missing or corrupt.");
        }

        var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(header[CentralNameLengthOffset..]);
        var length = CentralDirectoryHeaderSize + nameLength
            + BinaryPrimitives.ReadUInt16LittleEndian(header[CentralExtraLengthOffset..])
            + BinaryPrimitives.ReadUInt16LittleEndian(header[CentralCommentLengthOffset..]);
        var localOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[CentralLocalHeaderOffset..]);
        if (localOffset >= centralDirectoryOffset || length > header.Length)
        {
            throw new InvalidDataException($"Central directory header {index} points outside the archive.");
        }

        // Not secret data: FixedTimeEquals is used because it also returns false for a length mismatch.
        isSignature = CryptographicOperations.FixedTimeEquals(header.Slice(CentralDirectoryHeaderSize, nameLength), SignatureEntryName);
        return new(position, length, (int)localOffset);
    }

    /// <summary>Finds the end of central directory record, whose comment must run exactly to the end of the archive.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <returns>The record's offset.</returns>
    /// <exception cref="InvalidDataException">No record was found.</exception>
    private static int FindEndOfCentralDirectory(ReadOnlySpan<byte> zip)
    {
        var lowest = Math.Max(0, zip.Length - EndOfCentralDirectorySize - ushort.MaxValue);
        for (var position = zip.Length - EndOfCentralDirectorySize; position >= lowest; position--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip[position..]) == EndOfCentralDirectorySignature
                && position + EndOfCentralDirectorySize + BinaryPrimitives.ReadUInt16LittleEndian(zip[(position + EndCommentLengthOffset)..]) == zip.Length)
            {
                return position;
            }
        }

        throw new InvalidDataException("The package is not a ZIP archive: no end of central directory record was found.");
    }

    /// <summary>Writes the fields shared by local and central headers, from the general purpose flag to the extra field length.</summary>
    /// <param name="destination">The destination, starting at the general purpose flag.</param>
    /// <param name="dosTime">The MS-DOS time (low word) and date (high word).</param>
    /// <param name="crc">The CRC-32 of the data.</param>
    /// <param name="length">The stored length of the data.</param>
    private static void WriteCommonFields(Span<byte> destination, uint dosTime, uint crc, int length)
    {
        // General purpose flag 0 and compression method 0 (stored), as NU3005 requires.
        BinaryPrimitives.WriteUInt16LittleEndian(destination, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[CommonMethodOffset..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[CommonDosTimeOffset..], dosTime);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[CommonCrcOffset..], crc);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[CommonCompressedSizeOffset..], (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[CommonUncompressedSizeOffset..], (uint)length);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[CommonNameLengthOffset..], (ushort)SignatureEntryName.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[CommonExtraLengthOffset..], 0);
    }

    /// <summary>Copies the end of central directory record and its comment, adjusting the entry counts, size and offset.</summary>
    /// <param name="source">The original record and comment.</param>
    /// <param name="destination">The destination.</param>
    /// <param name="change">The adjustments.</param>
    private static void WriteEndOfCentralDirectory(ReadOnlySpan<byte> source, Span<byte> destination, DirectoryChange change)
    {
        source.CopyTo(destination);
        var count = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(source[EndTotalEntriesOffset..]) + change.EntryDelta);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[EndDiskEntriesOffset..], count);
        BinaryPrimitives.WriteUInt16LittleEndian(destination[EndTotalEntriesOffset..], count);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[EndDirectorySizeOffset..], (uint)change.Size);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[EndDirectoryOffsetOffset..], (uint)change.Offset);
    }

    /// <summary>Converts a time to the packed MS-DOS format, clamped to the years the format can hold.</summary>
    /// <param name="time">The time.</param>
    /// <returns>The time in the low word and the date in the high word.</returns>
    private static uint ToDosDateTime(DateTime time)
    {
        var year = Math.Clamp(time.Year, DosEpochYear, DosLastYear);
        var date = ((year - DosEpochYear) << DosYearShift) | (time.Month << DosMonthShift) | time.Day;
        var clock = (time.Hour << DosHourShift) | (time.Minute << DosMinuteShift) | (time.Second / DosSecondDivisor);
        return ((uint)date << DosDateShift) | (uint)clock;
    }

    /// <summary>The layout of one central directory header.</summary>
    /// <param name="HeaderPosition">The header's offset in the archive.</param>
    /// <param name="HeaderLength">The header's length, including name, extra field and comment.</param>
    /// <param name="LocalHeaderOffset">The offset of the entry's local file header.</param>
    internal readonly record struct ZipDirectoryEntry(int HeaderPosition, int HeaderLength, int LocalHeaderOffset);

    /// <summary>The layout of a ZIP archive's central directory.</summary>
    /// <param name="Entries">The central directory headers in order.</param>
    /// <param name="SignatureIndex">The index of the <c>.signature.p7s</c> header, or -1.</param>
    /// <param name="CentralDirectoryOffset">The offset of the first central directory header.</param>
    /// <param name="CentralDirectorySize">The total size of the central directory headers.</param>
    /// <param name="EndOfCentralDirectoryPosition">The offset of the end of central directory record.</param>
    internal readonly record struct ZipDirectory(
        ZipDirectoryEntry[] Entries,
        int SignatureIndex,
        int CentralDirectoryOffset,
        int CentralDirectorySize,
        int EndOfCentralDirectoryPosition);

    /// <summary>The changes to apply to the end of central directory record.</summary>
    /// <param name="EntryDelta">The change in entry count.</param>
    /// <param name="Size">The new central directory size.</param>
    /// <param name="Offset">The new central directory offset.</param>
    private readonly record struct DirectoryChange(int EntryDelta, int Size, int Offset);
}
