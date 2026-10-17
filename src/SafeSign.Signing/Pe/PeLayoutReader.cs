// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;

namespace SafeSign.Signing.Pe;

/// <summary>Reads the PE/COFF header fields Authenticode depends on (Microsoft PE Format specification).</summary>
public static class PeLayoutReader
{
    /// <summary>The DOS header's <c>e_lfanew</c> offset.</summary>
    private const int NewHeaderPointerOffset = 0x3C;

    /// <summary>The size of the PE signature plus the COFF file header.</summary>
    private const int SignatureAndCoffSize = 24;

    /// <summary>The optional header's <c>CheckSum</c> offset.</summary>
    private const int ChecksumFieldOffset = 64;

    /// <summary>The data directory offset in a PE32 optional header.</summary>
    private const int Pe32DirectoryOffset = 96;

    /// <summary>The data directory offset in a PE32+ optional header.</summary>
    private const int Pe32PlusDirectoryOffset = 112;

    /// <summary>The certificate table's index in the data directory.</summary>
    private const int CertificateDirectoryIndex = 4;

    /// <summary>The size of one data directory entry.</summary>
    private const int DirectoryEntrySize = 8;

    /// <summary>The <c>NumberOfRvaAndSizes</c> offset, four bytes before the directory.</summary>
    private const int DirectoryCountBackOffset = 4;

    /// <summary>The PE32 optional header magic.</summary>
    private const ushort Pe32Magic = 0x10B;

    /// <summary>The PE32+ optional header magic.</summary>
    private const ushort Pe32PlusMagic = 0x20B;

    /// <summary>The "MZ" DOS signature.</summary>
    private const ushort DosSignature = 0x5A4D;

    /// <summary>The "PE\0\0" signature.</summary>
    private const uint PeSignature = 0x00004550;

    /// <summary>Gets how many header bytes <see cref="Read"/> needs to see, given the first 64 bytes.</summary>
    /// <param name="dosHeader">At least the first 64 bytes of the file.</param>
    /// <returns>The number of leading bytes that hold every field <see cref="Read"/> reads.</returns>
    /// <exception cref="InvalidDataException">The file is not a PE image.</exception>
    public static int RequiredHeaderLength(ReadOnlySpan<byte> dosHeader)
    {
        if (dosHeader.Length < NewHeaderPointerOffset + sizeof(int) || BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != DosSignature)
        {
            throw new InvalidDataException("Not a PE image: the MZ signature is missing.");
        }

        var newHeader = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[NewHeaderPointerOffset..]);
        return newHeader + SignatureAndCoffSize + Pe32PlusDirectoryOffset + ((CertificateDirectoryIndex + 1) * DirectoryEntrySize);
    }

    /// <summary>Parses the layout from the file's leading bytes.</summary>
    /// <param name="header">The file's first <see cref="RequiredHeaderLength"/> bytes or more.</param>
    /// <param name="fileLength">The file length, used to bounds-check the certificate table.</param>
    /// <returns>The layout.</returns>
    /// <exception cref="InvalidDataException">The headers are malformed or the certificate table is not at the end of the file.</exception>
    public static PeLayout Read(ReadOnlySpan<byte> header, long fileLength)
    {
        var required = RequiredHeaderLength(header);
        var newHeader = BinaryPrimitives.ReadInt32LittleEndian(header[NewHeaderPointerOffset..]);

        // The checksum folds 16-bit words, so every range boundary must fall on an even offset.
        if (newHeader <= 0 || (newHeader & 1) != 0 || header.Length < required)
        {
            throw new InvalidDataException("Not a PE image: e_lfanew points outside the headers or is misaligned.");
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(header[newHeader..]) != PeSignature)
        {
            throw new InvalidDataException("Not a PE image: the PE signature is missing.");
        }

        var optionalHeader = newHeader + SignatureAndCoffSize;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(header[optionalHeader..]);
        var directory = magic switch
        {
            Pe32Magic => optionalHeader + Pe32DirectoryOffset,
            Pe32PlusMagic => optionalHeader + Pe32PlusDirectoryOffset,
            _ => throw new InvalidDataException($"Unsupported optional header magic 0x{magic:X4}."),
        };

        if (BinaryPrimitives.ReadUInt32LittleEndian(header[(directory - DirectoryCountBackOffset)..]) <= CertificateDirectoryIndex)
        {
            throw new InvalidDataException("The PE image has no certificate table directory entry.");
        }

        var entry = directory + (CertificateDirectoryIndex * DirectoryEntrySize);
        long tableOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[entry..]);
        long tableSize = BinaryPrimitives.ReadUInt32LittleEndian(header[(entry + sizeof(uint))..]);
        if (tableSize > 0 && tableOffset + tableSize > fileLength)
        {
            throw new InvalidDataException("The certificate table runs past the end of the file.");
        }

        return new(optionalHeader + ChecksumFieldOffset, entry, tableOffset, tableSize, magic == Pe32PlusMagic);
    }
}
