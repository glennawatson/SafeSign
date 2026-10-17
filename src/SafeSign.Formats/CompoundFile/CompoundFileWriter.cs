// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;

namespace SafeSign.Formats.CompoundFile;

/// <summary>Serializes a <see cref="CompoundFileEntry"/> tree into an MS-CFB version 3 (512-byte sector) compound file.</summary>
internal static class CompoundFileWriter
{
    /// <summary>The MS-CFB minor version value (0x003E).</summary>
    private const ushort MinorVersion = 0x003E;

    /// <summary>The MS-CFB version 3 major version value.</summary>
    private const ushort MajorVersion3 = 3;

    /// <summary>The MS-CFB little-endian byte order mark.</summary>
    private const ushort ByteOrderMark = 0xFFFE;

    /// <summary>The sector shift for 512-byte sectors (2^9 = 512).</summary>
    private const ushort SectorShiftV3 = 9;

    /// <summary>The mini sector shift for 64-byte mini sectors (2^6 = 64).</summary>
    private const ushort MiniSectorShift = 6;

    /// <summary>The number of 128-byte directory entries per 512-byte sector.</summary>
    private const int DirectoryEntriesPerSector = CompoundFileFormat.HeaderSize / CompoundFileFormat.DirectoryEntrySize;

    /// <summary>The number of 32-bit FAT entries per 512-byte sector.</summary>
    private const int FatEntriesPerSector = CompoundFileFormat.HeaderSize / sizeof(uint);

    /// <summary>The header offset of the minor version field.</summary>
    private const int MinorVersionOffset = 24;

    /// <summary>The header offset of the major version field.</summary>
    private const int MajorVersionOffset = 26;

    /// <summary>The header offset of the byte order mark.</summary>
    private const int ByteOrderOffset = 28;

    /// <summary>The header offset of the sector shift field.</summary>
    private const int SectorShiftOffset = 30;

    /// <summary>The header offset of the mini sector shift field.</summary>
    private const int MiniSectorShiftOffset = 32;

    /// <summary>The header offset of the FAT sector count.</summary>
    private const int FatCountOffset = 44;

    /// <summary>The header offset of the first directory sector.</summary>
    private const int FirstDirectoryOffset = 48;

    /// <summary>The header offset of the mini stream cutoff size.</summary>
    private const int CutoffOffset = 56;

    /// <summary>The header offset of the first mini FAT sector.</summary>
    private const int FirstMiniFatOffset = 60;

    /// <summary>The header offset of the mini FAT sector count.</summary>
    private const int MiniFatCountOffset = 64;

    /// <summary>The header offset of the first DIFAT sector.</summary>
    private const int FirstDifatOffset = 68;

    /// <summary>The header offset of the DIFAT sector count.</summary>
    private const int DifatCountOffset = 72;

    /// <summary>The header offset of the 109 header DIFAT entries.</summary>
    private const int HeaderDifatOffset = 76;

    /// <summary>Serializes <paramref name="root"/> into an MS-CFB version 3 compound file byte array.</summary>
    /// <param name="root">The root storage entry.</param>
    /// <returns>The compound file bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="root"/> is null.</exception>
    /// <exception cref="InvalidDataException"><paramref name="root"/> is not a storage.</exception>
    internal static byte[] Write(CompoundFileEntry root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (root.Children is null)
        {
            throw new InvalidDataException("The compound file root entry must be a storage.");
        }

        List<CompoundFileDirectoryRecord> dirRecords = [];
        List<byte[]> sectorBuffers = [];
        List<uint> fat = [];
        List<uint> miniFat = [];
        List<byte> miniStream = [];

        FlattenTree(root, dirRecords, sectorBuffers, fat, miniFat, miniStream);

        var miniStreamBytes = miniStream.ToArray();
        var rootStartSector = miniStreamBytes.Length > 0
            ? AppendRegularChain(miniStreamBytes, sectorBuffers, fat)
            : CompoundFileFormat.EndOfChain;

        var r0 = dirRecords[0];
        dirRecords[0] = r0 with { StartSector = rootStartSector, Size = (ulong)miniStreamBytes.Length };

        var miniFatBytes = EncodeUInt32Table(miniFat, PadCount(miniFat.Count, FatEntriesPerSector));
        var firstMiniFatSector = miniFatBytes.Length > 0
            ? AppendRegularChain(miniFatBytes, sectorBuffers, fat)
            : CompoundFileFormat.EndOfChain;
        var miniFatSectorCount = (uint)(miniFatBytes.Length / CompoundFileFormat.HeaderSize);

        var paddedDirCount = PadCount(dirRecords.Count, DirectoryEntriesPerSector);
        var dirBytes = new byte[paddedDirCount * CompoundFileFormat.DirectoryEntrySize];
        for (var i = 0; i < dirRecords.Count; i++)
        {
            var r = dirRecords[i];
            CompoundFileDirectoryParser.Write(dirBytes.AsSpan(i * CompoundFileFormat.DirectoryEntrySize, CompoundFileFormat.DirectoryEntrySize), in r);
        }

        var firstDirSector = AppendRegularChain(dirBytes, sectorBuffers, fat);
        var fatSectorIndices =AppendFatAndDifatSectors(sectorBuffers, fat, out var firstDifatSector, out var difatSectorCount);

        var output = new byte[(1 + sectorBuffers.Count) * CompoundFileFormat.HeaderSize];
        WriteHeader(output.AsSpan(0, CompoundFileFormat.HeaderSize), firstDirSector, firstMiniFatSector, miniFatSectorCount, firstDifatSector, difatSectorCount, fatSectorIndices);
        for (var i = 0; i < sectorBuffers.Count; i++)
        {
            sectorBuffers[i].CopyTo(output.AsSpan((i + 1) * CompoundFileFormat.HeaderSize, CompoundFileFormat.HeaderSize));
        }

        return output;
    }

    /// <summary>Flattens the entry tree into directory records, allocating mini-stream and regular sectors for stream entries.</summary>
    /// <param name="root">The root entry.</param>
    /// <param name="dirRecords">The output list of directory records.</param>
    /// <param name="sectorBuffers">The regular 512-byte sector buffers.</param>
    /// <param name="fat">The regular FAT table.</param>
    /// <param name="miniFat">The mini-FAT table.</param>
    /// <param name="miniStream">The accumulated mini-stream bytes.</param>
    private static void FlattenTree(
        CompoundFileEntry root,
        List<CompoundFileDirectoryRecord> dirRecords,
        List<byte[]> sectorBuffers,
        List<uint> fat,
        List<uint> miniFat,
        List<byte> miniStream)
    {
        dirRecords.Add(new(
            root.Name.Length > 0 ? root.Name : "Root Entry",
            CompoundFileEntryKind.Root,
            CompoundFileFormat.Free,
            CompoundFileFormat.Free,
            CompoundFileFormat.Free,
            root.Metadata,
            CompoundFileFormat.EndOfChain,
            0));

        var rootChild = BuildSubtree(root.Children!, dirRecords, sectorBuffers, fat, miniFat, miniStream);
        var r0 = dirRecords[0];
        dirRecords[0] = r0 with { Child = rootChild };
    }

    /// <summary>Sorts a storage's children by <see cref="CompoundFileFormat.CompareNames"/> and builds a balanced binary search tree.</summary>
    /// <param name="children">The child entries of the storage.</param>
    /// <param name="dirRecords">The directory records list.</param>
    /// <param name="sectorBuffers">The regular sector buffers.</param>
    /// <param name="fat">The FAT entries.</param>
    /// <param name="miniFat">The mini-FAT entries.</param>
    /// <param name="miniStream">The mini-stream buffer.</param>
    /// <returns>The root directory index of the sibling tree, or <see cref="CompoundFileFormat.Free"/> when empty.</returns>
    private static uint BuildSubtree(
        List<CompoundFileEntry> children,
        List<CompoundFileDirectoryRecord> dirRecords,
        List<byte[]> sectorBuffers,
        List<uint> fat,
        List<uint> miniFat,
        List<byte> miniStream)
    {
        if (children.Count == 0)
        {
            return CompoundFileFormat.Free;
        }

        List<CompoundFileEntry> sorted = [.. children];
        sorted.Sort(static (a, b) => CompoundFileFormat.CompareNames(a.Name, b.Name));
        return BuildBalancedNode((sorted, 0, sorted.Count - 1), dirRecords, sectorBuffers, fat, miniFat, miniStream);
    }

    /// <summary>Recursively constructs a balanced sibling BST node and its storage children.</summary>
    /// <param name="range">The sorted child list and inclusive slice bounds.</param>
    /// <param name="dirRecords">The directory records list.</param>
    /// <param name="sectorBuffers">The regular sector buffers.</param>
    /// <param name="fat">The FAT entries.</param>
    /// <param name="miniFat">The mini-FAT entries.</param>
    /// <param name="miniStream">The mini-stream buffer.</param>
    /// <returns>The directory index of the created node, or <see cref="CompoundFileFormat.Free"/>.</returns>
    private static uint BuildBalancedNode(
        (List<CompoundFileEntry> Sorted, int Low, int High) range,
        List<CompoundFileDirectoryRecord> dirRecords,
        List<byte[]> sectorBuffers,
        List<uint> fat,
        List<uint> miniFat,
        List<byte> miniStream)
    {
        if (range.Low > range.High)
        {
            return CompoundFileFormat.Free;
        }

        var mid = (range.Low + range.High) >>> 1;
        var entry = range.Sorted[mid];
        var myIndex = (uint)dirRecords.Count;
        dirRecords.Add(default);

        var leftIndex = BuildBalancedNode((range.Sorted, range.Low, mid - 1), dirRecords, sectorBuffers, fat, miniFat, miniStream);
        var rightIndex = BuildBalancedNode((range.Sorted, mid + 1, range.High), dirRecords, sectorBuffers, fat, miniFat, miniStream);

        if (entry.Children is { } subChildren)
        {
            var childIndex = BuildSubtree(subChildren, dirRecords, sectorBuffers, fat, miniFat, miniStream);
            dirRecords[(int)myIndex] = new(
                entry.Name,
                CompoundFileEntryKind.Storage,
                leftIndex,
                rightIndex,
                childIndex,
                entry.Metadata,
                0,
                0);
            return myIndex;
        }

        var span = entry.Data.Span;
        var startSector = AllocateStreamSectors(span, sectorBuffers, fat, miniFat, miniStream);

        dirRecords[(int)myIndex] = new(
            entry.Name,
            CompoundFileEntryKind.Stream,
            leftIndex,
            rightIndex,
            CompoundFileFormat.Free,
            entry.Metadata,
            startSector,
            (ulong)span.Length);
        return myIndex;
    }

    /// <summary>Allocates either mini-sectors or regular sectors for a stream payload.</summary>
    /// <param name="span">The stream bytes.</param>
    /// <param name="sectorBuffers">The regular sector buffers.</param>
    /// <param name="fat">The regular FAT entries.</param>
    /// <param name="miniFat">The mini-FAT entries.</param>
    /// <param name="miniStream">The mini-stream buffer.</param>
    /// <returns>The first sector index, or <see cref="CompoundFileFormat.EndOfChain"/> for empty streams.</returns>
    private static uint AllocateStreamSectors(
        ReadOnlySpan<byte> span,
        List<byte[]> sectorBuffers,
        List<uint> fat,
        List<uint> miniFat,
        List<byte> miniStream)
    {
        if (span.IsEmpty)
        {
            return CompoundFileFormat.EndOfChain;
        }

        return span.Length < CompoundFileFormat.MiniStreamCutoff
            ? AppendMiniChain(span, miniFat, miniStream)
            : AppendRegularChain(span, sectorBuffers, fat);
    }

    /// <summary>Appends a stream to the 64-byte mini stream and updates the mini-FAT.</summary>
    /// <param name="data">The stream data (<c>&lt; 4096</c> bytes).</param>
    /// <param name="miniFat">The mini-FAT entries.</param>
    /// <param name="miniStream">The mini-stream byte list.</param>
    /// <returns>The starting mini-sector index.</returns>
    private static uint AppendMiniChain(ReadOnlySpan<byte> data, List<uint> miniFat, List<byte> miniStream)
    {
        var sectorCount = (data.Length + CompoundFileFormat.MiniSectorSize - 1) / CompoundFileFormat.MiniSectorSize;
        var firstSector = (uint)miniFat.Count;
        for (var i = 0; i < sectorCount; i++)
        {
            var next = i + 1 < sectorCount ? firstSector + (uint)i + 1U : CompoundFileFormat.EndOfChain;
            miniFat.Add(next);
            var offset = i * CompoundFileFormat.MiniSectorSize;
            var chunkLen = Math.Min(CompoundFileFormat.MiniSectorSize, data.Length - offset);
            for (var b = 0; b < chunkLen; b++)
            {
                miniStream.Add(data[offset + b]);
            }

            for (var b = chunkLen; b < CompoundFileFormat.MiniSectorSize; b++)
            {
                miniStream.Add(0);
            }
        }

        return firstSector;
    }

    /// <summary>Appends a byte buffer across 512-byte regular sectors and updates the FAT.</summary>
    /// <param name="data">The stream or table bytes.</param>
    /// <param name="sectorBuffers">The regular 512-byte sector list.</param>
    /// <param name="fat">The FAT entry list.</param>
    /// <returns>The starting regular sector index.</returns>
    private static uint AppendRegularChain(ReadOnlySpan<byte> data, List<byte[]> sectorBuffers, List<uint> fat)
    {
        var sectorCount = (data.Length + CompoundFileFormat.HeaderSize - 1) / CompoundFileFormat.HeaderSize;
        var firstSector = (uint)sectorBuffers.Count;
        for (var i = 0; i < sectorCount; i++)
        {
            var sector = new byte[CompoundFileFormat.HeaderSize];
            var offset = i * CompoundFileFormat.HeaderSize;
            var chunkLen = Math.Min(CompoundFileFormat.HeaderSize, data.Length - offset);
            data.Slice(offset, chunkLen).CopyTo(sector);
            sectorBuffers.Add(sector);
            var next = i + 1 < sectorCount ? firstSector + (uint)i + 1U : CompoundFileFormat.EndOfChain;
            fat.Add(next);
        }

        return firstSector;
    }

    /// <summary>Allocates FAT and optional DIFAT sectors so the FAT covers all sectors including itself.</summary>
    /// <param name="sectorBuffers">The regular 512-byte sector buffers.</param>
    /// <param name="fat">The FAT entries.</param>
    /// <param name="firstDifatSector">Receives the first DIFAT sector index or <see cref="CompoundFileFormat.EndOfChain"/>.</param>
    /// <param name="difatSectorCount">Receives the DIFAT sector count.</param>
    /// <returns>The ordered list of FAT sector indices.</returns>
    private static List<uint> AppendFatAndDifatSectors(
        List<byte[]> sectorBuffers,
        List<uint> fat,
        out uint firstDifatSector,
        out uint difatSectorCount)
    {
        const int difatLinksPerSector = FatEntriesPerSector - 1;
        var fatSectors = 1;
        var difatSectors = 0;
        while (true)
        {
            var neededFat = (fat.Count + fatSectors + difatSectors + FatEntriesPerSector - 1) / FatEntriesPerSector;
            var neededDifat = neededFat <= CompoundFileFormat.HeaderDifatCount
                ? 0
                : (neededFat - CompoundFileFormat.HeaderDifatCount + difatLinksPerSector - 1) / difatLinksPerSector;
            if (neededFat == fatSectors && neededDifat == difatSectors)
            {
                break;
            }

            fatSectors = neededFat;
            difatSectors = neededDifat;
        }

        List<uint> fatSectorIndices = [];
        for (var i = 0; i < fatSectors; i++)
        {
            fatSectorIndices.Add((uint)sectorBuffers.Count);
            sectorBuffers.Add(new byte[CompoundFileFormat.HeaderSize]);
            fat.Add(CompoundFileFormat.FatSector);
        }

        firstDifatSector = CompoundFileFormat.EndOfChain;
        difatSectorCount = (uint)difatSectors;
        if (difatSectors > 0)
        {
            firstDifatSector = AppendDifatChain(sectorBuffers, fat, fatSectorIndices, difatSectors);
        }

        while (fat.Count < fatSectors * FatEntriesPerSector)
        {
            fat.Add(CompoundFileFormat.Free);
        }

        var fatBytes = EncodeUInt32Table(fat, fat.Count);
        for (var i = 0; i < fatSectors; i++)
        {
            fatBytes.AsSpan(i * CompoundFileFormat.HeaderSize, CompoundFileFormat.HeaderSize)
                .CopyTo(sectorBuffers[(int)fatSectorIndices[i]]);
        }

        return fatSectorIndices;
    }

    /// <summary>Appends DIFAT sectors for FAT sector indices beyond the first 109 stored in the header.</summary>
    /// <param name="sectorBuffers">The regular 512-byte sector buffers.</param>
    /// <param name="fat">The FAT entries.</param>
    /// <param name="fatSectorIndices">All FAT sector indices.</param>
    /// <param name="difatSectors">The number of DIFAT sectors to write.</param>
    /// <returns>The index of the first DIFAT sector.</returns>
    private static uint AppendDifatChain(
        List<byte[]> sectorBuffers,
        List<uint> fat,
        List<uint> fatSectorIndices,
        int difatSectors)
    {
        const int perSector = FatEntriesPerSector - 1;
        var firstDifat = (uint)sectorBuffers.Count;
        var fatListPos = CompoundFileFormat.HeaderDifatCount;
        for (var d = 0; d < difatSectors; d++)
        {
            var mySector = (uint)sectorBuffers.Count;
            var buffer = new byte[CompoundFileFormat.HeaderSize];
            buffer.AsSpan().Fill(0xFF);
            for (var slot = 0; slot < perSector && fatListPos < fatSectorIndices.Count; slot++, fatListPos++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(slot * sizeof(uint)), fatSectorIndices[fatListPos]);
            }

            var nextDifat = d + 1 < difatSectors ? mySector + 1U : CompoundFileFormat.EndOfChain;
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(perSector * sizeof(uint)), nextDifat);
            sectorBuffers.Add(buffer);
            fat.Add(CompoundFileFormat.DifatSector);
        }

        return firstDifat;
    }

    /// <summary>Writes the 512-byte MS-CFB v3 header.</summary>
    /// <param name="header">The 512-byte header span.</param>
    /// <param name="firstDirSector">The first directory sector index.</param>
    /// <param name="firstMiniFatSector">The first mini-FAT sector index.</param>
    /// <param name="miniFatSectorCount">The number of mini-FAT sectors.</param>
    /// <param name="firstDifatSector">The first DIFAT sector index.</param>
    /// <param name="difatSectorCount">The number of DIFAT sectors.</param>
    /// <param name="fatSectorIndices">The indices of all FAT sectors.</param>
    private static void WriteHeader(
        Span<byte> header,
        uint firstDirSector,
        uint firstMiniFatSector,
        uint miniFatSectorCount,
        uint firstDifatSector,
        uint difatSectorCount,
        List<uint> fatSectorIndices)
    {
        header.Clear();
        CompoundFileFormat.Signature.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header[MinorVersionOffset..], MinorVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[MajorVersionOffset..], MajorVersion3);
        BinaryPrimitives.WriteUInt16LittleEndian(header[ByteOrderOffset..], ByteOrderMark);
        BinaryPrimitives.WriteUInt16LittleEndian(header[SectorShiftOffset..], SectorShiftV3);
        BinaryPrimitives.WriteUInt16LittleEndian(header[MiniSectorShiftOffset..], MiniSectorShift);
        BinaryPrimitives.WriteUInt32LittleEndian(header[FatCountOffset..], (uint)fatSectorIndices.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(header[FirstDirectoryOffset..], firstDirSector);
        BinaryPrimitives.WriteUInt32LittleEndian(header[CutoffOffset..], CompoundFileFormat.MiniStreamCutoff);
        BinaryPrimitives.WriteUInt32LittleEndian(header[FirstMiniFatOffset..], firstMiniFatSector);
        BinaryPrimitives.WriteUInt32LittleEndian(header[MiniFatCountOffset..], miniFatSectorCount);
        BinaryPrimitives.WriteUInt32LittleEndian(header[FirstDifatOffset..], firstDifatSector);
        BinaryPrimitives.WriteUInt32LittleEndian(header[DifatCountOffset..], difatSectorCount);

        header[HeaderDifatOffset..].Fill(0xFF);
        var headerCount = Math.Min(CompoundFileFormat.HeaderDifatCount, fatSectorIndices.Count);
        for (var i = 0; i < headerCount; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(header[(HeaderDifatOffset + (i * sizeof(uint)))..], fatSectorIndices[i]);
        }
    }

    /// <summary>Encodes a list of 32-bit sector numbers into a little-endian byte buffer padded with <see cref="CompoundFileFormat.Free"/>.</summary>
    /// <param name="values">The sector numbers.</param>
    /// <param name="paddedCount">The total number of 32-bit entries to write.</param>
    /// <returns>The encoded bytes.</returns>
    private static byte[] EncodeUInt32Table(List<uint> values, int paddedCount)
    {
        if (values.Count == 0)
        {
            return [];
        }

        var bytes = new byte[paddedCount * sizeof(uint)];
        bytes.AsSpan().Fill(0xFF);
        for (var i = 0; i < values.Count; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i * sizeof(uint)), values[i]);
        }

        return bytes;
    }

    /// <summary>Rounds <paramref name="count"/> up to the next multiple of <paramref name="perSector"/>.</summary>
    /// <param name="count">The item count.</param>
    /// <param name="perSector">The items per sector.</param>
    /// <returns>The padded count.</returns>
    private static int PadCount(int count, int perSector) =>
        count == 0 ? 0 : ((count + perSector - 1) / perSector) * perSector;
}
