// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;

namespace SafeSign.Formats.CompoundFile;

/// <summary>Parses and encodes the 128-byte directory entries of MS-CFB section 2.6.</summary>
internal static class CompoundFileDirectoryParser
{
    /// <summary>The length of the name field in bytes.</summary>
    private const int NameFieldSize = 64;

    /// <summary>The offset of the name length.</summary>
    private const int NameLengthOffset = 64;

    /// <summary>The offset of the object type.</summary>
    private const int TypeOffset = 66;

    /// <summary>The offset of the red-black colour.</summary>
    private const int ColorOffset = 67;

    /// <summary>The offset of the left sibling.</summary>
    private const int LeftOffset = 68;

    /// <summary>The offset of the right sibling.</summary>
    private const int RightOffset = 72;

    /// <summary>The offset of the child.</summary>
    private const int ChildOffset = 76;

    /// <summary>The offset of the class identifier.</summary>
    private const int ClsidOffset = 80;

    /// <summary>The length of the class identifier.</summary>
    private const int ClsidSize = 16;

    /// <summary>The offset of the state bits.</summary>
    private const int StateOffset = 96;

    /// <summary>The offset of the creation time.</summary>
    private const int CreatedOffset = 100;

    /// <summary>The offset of the modification time.</summary>
    private const int ModifiedOffset = 108;

    /// <summary>The offset of the starting sector.</summary>
    private const int StartOffset = 116;

    /// <summary>The offset of the stream size.</summary>
    private const int SizeOffset = 120;

    /// <summary>The colour value for black nodes.</summary>
    private const byte Black = 1;

    /// <summary>Parses every directory entry in the directory chain.</summary>
    /// <param name="directory">The directory chain's bytes.</param>
    /// <param name="version3">True when only the low 32 bits of stream sizes are meaningful.</param>
    /// <returns>The entries, unused ones included.</returns>
    internal static CompoundFileDirectoryRecord[] Parse(ReadOnlySpan<byte> directory, bool version3)
    {
        var records = new CompoundFileDirectoryRecord[directory.Length / CompoundFileFormat.DirectoryEntrySize];
        for (var i = 0; i < records.Length; i++)
        {
            records[i] = ParseEntry(directory.Slice(i * CompoundFileFormat.DirectoryEntrySize, CompoundFileFormat.DirectoryEntrySize), version3);
        }

        return records;
    }

    /// <summary>Encodes one directory entry, coloured black as MS-CFB section 2.6.4 permits.</summary>
    /// <param name="destination">The 128-byte destination.</param>
    /// <param name="record">The entry.</param>
    internal static void Write(Span<byte> destination, in CompoundFileDirectoryRecord record)
    {
        destination[..CompoundFileFormat.DirectoryEntrySize].Clear();
        var name = record.Name.AsSpan();
        for (var i = 0; i < name.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(destination[(i * sizeof(char))..], name[i]);
        }

        if (record.Kind is not CompoundFileEntryKind.Unknown)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(destination[NameLengthOffset..], (ushort)((name.Length + 1) * sizeof(char)));
            destination[ColorOffset] = Black;
        }

        destination[TypeOffset] = (byte)record.Kind;
        BinaryPrimitives.WriteUInt32LittleEndian(destination[LeftOffset..], record.Left);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[RightOffset..], record.Right);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[ChildOffset..], record.Child);
        _ = record.Metadata.Clsid.TryWriteBytes(destination.Slice(ClsidOffset, ClsidSize));
        BinaryPrimitives.WriteUInt32LittleEndian(destination[StateOffset..], record.Metadata.StateBits);
        BinaryPrimitives.WriteInt64LittleEndian(destination[CreatedOffset..], record.Metadata.CreationTime);
        BinaryPrimitives.WriteInt64LittleEndian(destination[ModifiedOffset..], record.Metadata.ModifiedTime);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[StartOffset..], record.StartSector);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[SizeOffset..], record.Size);
    }

    /// <summary>Parses one directory entry.</summary>
    /// <param name="entry">The 128 entry bytes.</param>
    /// <param name="version3">True when only the low 32 bits of the size are meaningful.</param>
    /// <returns>The entry.</returns>
    private static CompoundFileDirectoryRecord ParseEntry(ReadOnlySpan<byte> entry, bool version3)
    {
        var nameBytes = Math.Clamp(BinaryPrimitives.ReadUInt16LittleEndian(entry[NameLengthOffset..]) - sizeof(char), 0, NameFieldSize - sizeof(char));
        var nameField = entry[..nameBytes];

        // Reads code units one by one so names with unpaired surrogates round-trip exactly.
        var name = new string('\0', nameBytes / sizeof(char));
        var chars = new char[name.Length];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(nameField[(i * sizeof(char))..]);
        }

        var size = BinaryPrimitives.ReadUInt64LittleEndian(entry[SizeOffset..]);
        var metadata = new CompoundFileMetadata(
            new(entry.Slice(ClsidOffset, ClsidSize)),
            BinaryPrimitives.ReadUInt32LittleEndian(entry[StateOffset..]),
            BinaryPrimitives.ReadInt64LittleEndian(entry[CreatedOffset..]),
            BinaryPrimitives.ReadInt64LittleEndian(entry[ModifiedOffset..]));
        return new(
            new(chars),
            (CompoundFileEntryKind)entry[TypeOffset],
            BinaryPrimitives.ReadUInt32LittleEndian(entry[LeftOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(entry[RightOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(entry[ChildOffset..]),
            metadata,
            BinaryPrimitives.ReadUInt32LittleEndian(entry[StartOffset..]),
            version3 ? (uint)size : size);
    }
}
