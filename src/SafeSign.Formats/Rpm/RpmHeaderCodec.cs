// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace SafeSign.Formats.Rpm;

/// <summary>Reads and writes RPM header sections (<c>0x8E 0xAD 0xE8 0x01</c>) and lead structures.</summary>
public static class RpmHeaderCodec
{
    /// <summary>The length of the RPM lead before the signature header.</summary>
    internal const int LeadLength = 96;

    /// <summary>The signature header is padded to this alignment before the main header.</summary>
    internal const int SignatureAlignment = 8;

    /// <summary>The obsolete header image region tag.</summary>
    internal const int RegionImage = 61;

    /// <summary>The signature header region tag.</summary>
    internal const int RegionSignatures = 62;

    /// <summary>The main header region tag.</summary>
    internal const int RegionImmutable = 63;

    /// <summary>The char value type.</summary>
    internal const int TypeChar = 1;

    /// <summary>The int8 value type.</summary>
    internal const int TypeInt8 = 2;

    /// <summary>The int16 value type.</summary>
    internal const int TypeInt16 = 3;

    /// <summary>The int32 value type.</summary>
    internal const int TypeInt32 = 4;

    /// <summary>The int64 value type.</summary>
    internal const int TypeInt64 = 5;

    /// <summary>The string value type.</summary>
    internal const int TypeString = 6;

    /// <summary>The binary value type.</summary>
    internal const int TypeBinary = 7;

    /// <summary>The string array value type.</summary>
    internal const int TypeStringArray = 8;

    /// <summary>The length of a header index entry, and of the magic and counts before the index.</summary>
    private const int IndexEntryLength = 16;

    /// <summary>Where a header stores its entry count.</summary>
    private const int EntryCountOffset = 8;

    /// <summary>Where a header stores its data store length.</summary>
    private const int StoreLengthOffset = 12;

    /// <summary>Where an index entry stores its type.</summary>
    private const int TypeOffset = 4;

    /// <summary>Where an index entry stores its data offset.</summary>
    private const int DataOffset = 8;

    /// <summary>Where an index entry stores its value count.</summary>
    private const int CountOffset = 12;

    /// <summary>Gets the 4-byte RPM lead magic (<c>0xED 0xAB 0xEE 0xDB</c>).</summary>
    public static ReadOnlySpan<byte> LeadMagic => [0xED, 0xAB, 0xEE, 0xDB];

    /// <summary>Gets the eight bytes that start every header: magic, version 1 and four reserved bytes.</summary>
    public static ReadOnlySpan<byte> HeaderMagic => [0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];

    /// <summary>Checks whether <paramref name="header"/> begins with the RPM lead magic.</summary>
    /// <param name="header">The leading bytes of a file.</param>
    /// <returns><see langword="true"/> when <paramref name="header"/> starts with the RPM lead magic.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool HasLeadMagic(ReadOnlySpan<byte> header) => header.StartsWith(LeadMagic);

    /// <summary>Gets the padding that aligns a length to <paramref name="alignment"/>.</summary>
    /// <param name="length">The length so far.</param>
    /// <param name="alignment">The alignment.</param>
    /// <returns>The number of zero bytes to add.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int Pad(int length, int alignment) => (alignment - (length % alignment)) % alignment;

    /// <summary>Gets the byte length of the RPM header starting at <paramref name="start"/>.</summary>
    /// <param name="file">The package bytes.</param>
    /// <param name="start">The header offset.</param>
    /// <returns>The header length in bytes.</returns>
    public static int HeaderLength(ReadOnlySpan<byte> file, int start) =>
        IndexEntryLength
        + (BinaryPrimitives.ReadInt32BigEndian(file[(start + EntryCountOffset)..]) * IndexEntryLength)
        + BinaryPrimitives.ReadInt32BigEndian(file[(start + StoreLengthOffset)..]);

    /// <summary>Reads an RPM header's entries, excluding its region tag which is regenerated on write.</summary>
    /// <param name="header">The header bytes.</param>
    /// <returns>The entries keyed by tag number.</returns>
    public static SortedDictionary<int, RpmHeaderEntry> ReadHeader(ReadOnlySpan<byte> header)
    {
        var count = BinaryPrimitives.ReadInt32BigEndian(header[EntryCountOffset..]);
        var store = header[(IndexEntryLength + (count * IndexEntryLength))..];
        var entries = new SortedDictionary<int, RpmHeaderEntry>();
        for (var i = 0; i < count; i++)
        {
            var index = header.Slice(IndexEntryLength + (i * IndexEntryLength), IndexEntryLength);
            var tag = BinaryPrimitives.ReadInt32BigEndian(index);
            var type = BinaryPrimitives.ReadInt32BigEndian(index[TypeOffset..]);
            var offset = BinaryPrimitives.ReadInt32BigEndian(index[DataOffset..]);
            var values = BinaryPrimitives.ReadInt32BigEndian(index[CountOffset..]);
            if (tag is RegionImage or RegionSignatures or RegionImmutable)
            {
                continue;
            }

            var data = store[offset..];
            var length = type switch
            {
                TypeChar or TypeInt8 or TypeBinary => values,
                TypeInt16 => values * sizeof(short),
                TypeInt32 => values * sizeof(int),
                TypeInt64 => values * sizeof(long),
                TypeString => data.IndexOf((byte)0) + 1,
                _ => StringsLength(data, values),
            };
            entries[tag] = new(type, values, data[..length].ToArray());
        }

        return entries;
    }

    /// <summary>Writes entries as an RPM header whose region tag covers all entries.</summary>
    /// <param name="entries">The entries keyed by tag number.</param>
    /// <param name="region">The region tag (<see cref="RegionSignatures"/> or <see cref="RegionImmutable"/>).</param>
    /// <returns>The serialized header bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="entries"/> is null.</exception>
    public static byte[] WriteHeader(SortedDictionary<int, RpmHeaderEntry> entries, int region)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var store = new ArrayBufferWriter<byte>();
        List<RpmHeaderIndexEntry> index = [];
        foreach (var (tag, entry) in entries)
        {
            var alignment = entry.Type switch
            {
                TypeInt16 => sizeof(short),
                TypeInt32 => sizeof(int),
                TypeInt64 => sizeof(long),
                _ => 1,
            };
            var padding = Pad(store.WrittenCount, alignment);
            store.GetSpan(padding)[..padding].Clear();
            store.Advance(padding);
            index.Add(new(tag, entry.Type, store.WrittenCount, entry.Count));
            store.Write(entry.Data.Span);
        }

        var regionOffset = store.WrittenCount;
        var total = index.Count + 1;
        WriteIndexEntry(store.GetSpan(IndexEntryLength), new(region, TypeBinary, -(total * IndexEntryLength), IndexEntryLength));
        store.Advance(IndexEntryLength);

        var bytes = new byte[IndexEntryLength + (total * IndexEntryLength) + store.WrittenCount];
        HeaderMagic.CopyTo(bytes);
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(EntryCountOffset), total);
        BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(StoreLengthOffset), store.WrittenCount);
        WriteIndexEntry(bytes.AsSpan(IndexEntryLength), new(region, TypeBinary, regionOffset, IndexEntryLength));
        for (var i = 0; i < index.Count; i++)
        {
            WriteIndexEntry(bytes.AsSpan(IndexEntryLength + ((i + 1) * IndexEntryLength)), index[i]);
        }

        store.WrittenSpan.CopyTo(bytes.AsSpan((total + 1) * IndexEntryLength));
        return bytes;
    }

    /// <summary>Decodes a string array entry.</summary>
    /// <param name="entry">The string array entry.</param>
    /// <returns>The decoded strings.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string[] DecodeStrings(RpmHeaderEntry entry) =>
        Encoding.UTF8.GetString(entry.Data.Span).Split('\0')[..entry.Count];

    /// <summary>Creates a NUL-terminated string entry.</summary>
    /// <param name="value">The string value.</param>
    /// <returns>The header entry.</returns>
    public static RpmHeaderEntry CreateString(string value) =>
        new(TypeString, 1, Encoding.UTF8.GetBytes($"{value}\0"));

    /// <summary>Creates a NUL-terminated string array entry.</summary>
    /// <param name="values">The string values.</param>
    /// <returns>The header entry.</returns>
    public static RpmHeaderEntry CreateStringArray(ReadOnlySpan<string> values)
    {
        var builder = new StringBuilder();
        for (var i = 0; i < values.Length; i++)
        {
            _ = builder.Append(values[i]).Append('\0');
        }

        return new(TypeStringArray, values.Length, Encoding.UTF8.GetBytes(builder.ToString()));
    }

    /// <summary>Creates a 32-bit big-endian integer entry.</summary>
    /// <param name="value">The integer value.</param>
    /// <returns>The header entry.</returns>
    public static RpmHeaderEntry CreateInt32(int value)
    {
        var data = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(data, value);
        return new(TypeInt32, 1, data);
    }

    /// <summary>Measures a run of NUL-terminated strings.</summary>
    /// <param name="data">The store slice starting at the first string.</param>
    /// <param name="count">The number of strings.</param>
    /// <returns>The total byte length.</returns>
    private static int StringsLength(ReadOnlySpan<byte> data, int count)
    {
        var length = 0;
        for (var i = 0; i < count; i++)
        {
            length += data[length..].IndexOf((byte)0) + 1;
        }

        return length;
    }

    /// <summary>Writes one big-endian header index entry.</summary>
    /// <param name="target">Receives the 16-byte entry.</param>
    /// <param name="entry">The index entry fields.</param>
    private static void WriteIndexEntry(Span<byte> target, RpmHeaderIndexEntry entry)
    {
        BinaryPrimitives.WriteInt32BigEndian(target, entry.Tag);
        BinaryPrimitives.WriteInt32BigEndian(target[TypeOffset..], entry.Type);
        BinaryPrimitives.WriteInt32BigEndian(target[DataOffset..], entry.Offset);
        BinaryPrimitives.WriteInt32BigEndian(target[CountOffset..], entry.Count);
    }
}
