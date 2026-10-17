// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Binary;

namespace SafeSign.Formats.CompoundFile;

/// <summary>Reads a compound file into an entry tree, following MS-CFB.</summary>
internal static class CompoundFileReader
{
    /// <summary>The byte order mark every compound file header carries.</summary>
    private const ushort ByteOrderMark = 0xFFFE;

    /// <summary>The header offset of the major version.</summary>
    private const int MajorVersionOffset = 26;

    /// <summary>The header offset of the byte order mark.</summary>
    private const int ByteOrderOffset = 28;

    /// <summary>The header offset of the sector shift.</summary>
    private const int SectorShiftOffset = 30;

    /// <summary>The header offset of the FAT sector count.</summary>
    private const int FatCountOffset = 44;

    /// <summary>The header offset of the first directory sector.</summary>
    private const int FirstDirectoryOffset = 48;

    /// <summary>The header offset of the mini stream cutoff.</summary>
    private const int CutoffOffset = 56;

    /// <summary>The header offset of the first mini FAT sector.</summary>
    private const int FirstMiniFatOffset = 60;

    /// <summary>The header offset of the first DIFAT sector.</summary>
    private const int FirstDifatOffset = 68;

    /// <summary>The header offset of the DIFAT sector count.</summary>
    private const int DifatCountOffset = 72;

    /// <summary>The header offset of the first of the 109 header DIFAT entries.</summary>
    private const int HeaderDifatOffset = 76;

    /// <summary>The version 3 sector shift.</summary>
    private const int Version3SectorShift = 9;

    /// <summary>The version 4 sector shift.</summary>
    private const int Version4SectorShift = 12;

    /// <summary>The major version whose stream sizes only use the low 32 bits.</summary>
    private const int Version3 = 3;

    /// <summary>Reads a compound file.</summary>
    /// <param name="file">The file content.</param>
    /// <returns>The root storage.</returns>
    /// <exception cref="InvalidDataException">The content is not a well-formed compound file.</exception>
    internal static CompoundFileEntry Read(ReadOnlyMemory<byte> file)
    {
        var header = ReadHeader(file.Span);
        var fat = ReadFat(file.Span, in header);
        var entries = CompoundFileDirectoryParser.Parse(ReadChain(file.Span, in header, fat, header.FirstDirectorySector), header.MajorVersion == Version3);
        if (entries.Length == 0 || entries[0].Kind is not CompoundFileEntryKind.Root)
        {
            throw new InvalidDataException("The compound file has no root storage entry.");
        }

        var miniFat = ToSectorIds(ReadChain(file.Span, in header, fat, header.FirstMiniFatSector));
        var miniStream = Truncate(ReadChain(file.Span, in header, fat, entries[0].StartSector), entries[0].Size);
        var image = new CompoundFileImage(file, header, fat, miniFat, miniStream, entries);
        var visited = new bool[entries.Length];
        visited[0] = true;
        return new(entries[0].Name, entries[0].Metadata, ReadOnlyMemory<byte>.Empty, ReadChildren(image, entries[0].Child, visited));
    }

    /// <summary>Validates and parses the header.</summary>
    /// <param name="file">The file content.</param>
    /// <returns>The header.</returns>
    /// <exception cref="InvalidDataException">The header signature, byte order mark, or sector shift is invalid.</exception>
    private static CompoundFileHeader ReadHeader(ReadOnlySpan<byte> file)
    {
        if (file.Length < CompoundFileFormat.HeaderSize || !CompoundFileFormat.HasSignature(file) || BinaryPrimitives.ReadUInt16LittleEndian(file[ByteOrderOffset..]) != ByteOrderMark)
        {
            throw new InvalidDataException("The file is not a compound file.");
        }

        int shift = BinaryPrimitives.ReadUInt16LittleEndian(file[SectorShiftOffset..]);
        if (shift is not (Version3SectorShift or Version4SectorShift))
        {
            throw new InvalidDataException($"The compound file sector shift {shift} is not valid.");
        }

        return new(
            BinaryPrimitives.ReadUInt16LittleEndian(file[MajorVersionOffset..]),
            shift,
            BinaryPrimitives.ReadUInt32LittleEndian(file[FatCountOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(file[FirstDirectoryOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(file[CutoffOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(file[FirstMiniFatOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(file[FirstDifatOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(file[DifatCountOffset..]));
    }

    /// <summary>Collects the FAT sector locations from the header and DIFAT chain, then reads the FAT.</summary>
    /// <param name="file">The file content.</param>
    /// <param name="header">The header.</param>
    /// <returns>The FAT entries.</returns>
    private static uint[] ReadFat(ReadOnlySpan<byte> file, in CompoundFileHeader header)
    {
        var fatSectors = new List<uint>();
        for (var i = 0; i < CompoundFileFormat.HeaderDifatCount && fatSectors.Count < header.FatSectorCount; i++)
        {
            fatSectors.Add(BinaryPrimitives.ReadUInt32LittleEndian(file[(HeaderDifatOffset + (i * sizeof(uint)))..]));
        }

        var perSector = (header.SectorSize / sizeof(uint)) - 1;
        var difat = header.FirstDifatSector;
        for (var n = 0U; n < header.DifatSectorCount && difat <= CompoundFileFormat.MaxRegularSector; n++)
        {
            var sector = SectorSpan(file, in header, difat);
            for (var i = 0; i < perSector && fatSectors.Count < header.FatSectorCount; i++)
            {
                fatSectors.Add(BinaryPrimitives.ReadUInt32LittleEndian(sector[(i * sizeof(uint))..]));
            }

            difat = BinaryPrimitives.ReadUInt32LittleEndian(sector[(perSector * sizeof(uint))..]);
        }

        var entriesPerSector = header.SectorSize / sizeof(uint);
        var fat = new uint[fatSectors.Count * entriesPerSector];
        for (var s = 0; s < fatSectors.Count; s++)
        {
            var sector = SectorSpan(file, in header, fatSectors[s]);
            for (var i = 0; i < entriesPerSector; i++)
            {
                fat[(s * entriesPerSector) + i] = BinaryPrimitives.ReadUInt32LittleEndian(sector[(i * sizeof(uint))..]);
            }
        }

        return fat;
    }

    /// <summary>Reads the children of a storage by walking its red-black tree in order.</summary>
    /// <param name="image">The parsed file.</param>
    /// <param name="node">The tree node to start from.</param>
    /// <param name="visited">Entries already reached, to reject cycles.</param>
    /// <returns>The children.</returns>
    /// <exception cref="InvalidDataException">The directory tree contains out-of-range indices or cycles.</exception>
    private static List<CompoundFileEntry> ReadChildren(CompoundFileImage image, uint node, bool[] visited)
    {
        var children = new List<CompoundFileEntry>();
        var pending = new Stack<uint>();
        var current = node;
        while (current != CompoundFileFormat.Free || pending.Count > 0)
        {
            while (current != CompoundFileFormat.Free)
            {
                if (current >= image.Entries.Length || visited[current])
                {
                    throw new InvalidDataException("The compound file directory tree is malformed.");
                }

                visited[current] = true;
                pending.Push(current);
                current = image.Entries[current].Left;
            }

            var index = pending.Pop();
            ref readonly var record = ref image.Entries[index];
            AddChild(image, in record, visited, children);
            current = record.Right;
        }

        return children;
    }

    /// <summary>Converts one directory record into an entry and adds it.</summary>
    /// <param name="image">The parsed file.</param>
    /// <param name="record">The record.</param>
    /// <param name="visited">Entries already reached.</param>
    /// <param name="children">The list to add to.</param>
    /// <exception cref="InvalidDataException">The directory record has an unexpected kind.</exception>
    private static void AddChild(CompoundFileImage image, in CompoundFileDirectoryRecord record, bool[] visited, List<CompoundFileEntry> children)
    {
        switch (record.Kind)
        {
            case CompoundFileEntryKind.Stream:
            {
                children.Add(new(record.Name, record.Metadata, ReadStream(image, in record), null));
                break;
            }

            case CompoundFileEntryKind.Storage:
            {
                children.Add(new(record.Name, record.Metadata, ReadOnlyMemory<byte>.Empty, ReadChildren(image, record.Child, visited)));
                break;
            }

            default:
            {
                throw new InvalidDataException($"The compound file entry '{record.Name}' has an unexpected type.");
            }
        }
    }

    /// <summary>Reads a stream from the mini stream or the regular sectors.</summary>
    /// <param name="image">The parsed file.</param>
    /// <param name="record">The stream's directory record.</param>
    /// <returns>The stream content.</returns>
    /// <exception cref="InvalidDataException">The stream is truncated.</exception>
    private static byte[] ReadStream(CompoundFileImage image, in CompoundFileDirectoryRecord record)
    {
        if (record.Size == 0)
        {
            return [];
        }

        var header = image.Header;
        var data = record.Size < header.MiniStreamCutoff
            ? ReadMiniChain(image, record.StartSector)
            : ReadChain(image.File.Span, in header, image.Fat, record.StartSector);
        if ((ulong)data.Length < record.Size)
        {
            throw new InvalidDataException($"The compound file stream '{record.Name}' is truncated.");
        }

        return Truncate(data, record.Size);
    }

    /// <summary>Concatenates a regular sector chain.</summary>
    /// <param name="file">The file content.</param>
    /// <param name="header">The header.</param>
    /// <param name="fat">The FAT.</param>
    /// <param name="start">The first sector.</param>
    /// <returns>The chain's bytes.</returns>
    /// <exception cref="InvalidDataException">The sector chain is out of bounds or cyclic.</exception>
    private static byte[] ReadChain(ReadOnlySpan<byte> file, in CompoundFileHeader header, uint[] fat, uint start)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var sector = start;
        for (var steps = 0; sector <= CompoundFileFormat.MaxRegularSector; steps++)
        {
            if (sector >= fat.Length || steps > fat.Length)
            {
                throw new InvalidDataException("The compound file sector chain is malformed.");
            }

            buffer.Write(SectorSpan(file, in header, sector));
            sector = fat[sector];
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Concatenates a mini sector chain.</summary>
    /// <param name="image">The parsed file.</param>
    /// <param name="start">The first mini sector.</param>
    /// <returns>The chain's bytes.</returns>
    /// <exception cref="InvalidDataException">The mini sector chain is out of bounds or cyclic.</exception>
    private static byte[] ReadMiniChain(CompoundFileImage image, uint start)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var sector = start;
        for (var steps = 0; sector <= CompoundFileFormat.MaxRegularSector; steps++)
        {
            var offset = (long)sector * CompoundFileFormat.MiniSectorSize;
            if (sector >= image.MiniFat.Length || steps > image.MiniFat.Length || offset + CompoundFileFormat.MiniSectorSize > image.MiniStream.Length)
            {
                throw new InvalidDataException("The compound file mini sector chain is malformed.");
            }

            buffer.Write(image.MiniStream.AsSpan((int)offset, CompoundFileFormat.MiniSectorSize));
            sector = image.MiniFat[sector];
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Gets one sector, tolerating a short final sector.</summary>
    /// <param name="file">The file content.</param>
    /// <param name="header">The header.</param>
    /// <param name="sector">The sector number.</param>
    /// <returns>The sector's bytes.</returns>
    /// <exception cref="InvalidDataException">The sector lies past the end of the file.</exception>
    private static ReadOnlySpan<byte> SectorSpan(ReadOnlySpan<byte> file, in CompoundFileHeader header, uint sector)
    {
        var offset = ((long)sector + 1) << header.SectorShift;
        if (offset >= file.Length)
        {
            throw new InvalidDataException($"The compound file sector {sector} lies beyond the end of the file.");
        }

        return file.Slice((int)offset, (int)Math.Min(header.SectorSize, file.Length - offset));
    }

    /// <summary>Reinterprets bytes as little-endian sector numbers.</summary>
    /// <param name="bytes">The table bytes.</param>
    /// <returns>The sector numbers.</returns>
    private static uint[] ToSectorIds(byte[] bytes)
    {
        var ids = new uint[bytes.Length / sizeof(uint)];
        for (var i = 0; i < ids.Length; i++)
        {
            ids[i] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i * sizeof(uint)));
        }

        return ids;
    }

    /// <summary>Cuts a chain's bytes down to the stream size.</summary>
    /// <param name="data">The chain's bytes.</param>
    /// <param name="size">The stream size.</param>
    /// <returns>The stream bytes.</returns>
    private static byte[] Truncate(byte[] data, ulong size) => (ulong)data.Length <= size ? data : data.AsSpan(0, (int)size).ToArray();
}
