// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;

namespace SafeSign.Formats.CompoundFile;

/// <summary>Fixed values from the Compound File Binary format specification (MS-CFB).</summary>
internal static class CompoundFileFormat
{
    /// <summary>The header length, which is also the version 3 sector length.</summary>
    internal const int HeaderSize = 512;

    /// <summary>The length of one directory entry.</summary>
    internal const int DirectoryEntrySize = 128;

    /// <summary>The number of FAT sector locations held in the header.</summary>
    internal const int HeaderDifatCount = 109;

    /// <summary>The mini sector length.</summary>
    internal const int MiniSectorSize = 64;

    /// <summary>Streams shorter than this live in the mini stream.</summary>
    internal const int MiniStreamCutoff = 4096;

    /// <summary>The longest entry name in UTF-16 code units, excluding the terminator.</summary>
    internal const int MaxNameLength = 31;

    /// <summary>The highest regular sector number; larger values are markers.</summary>
    internal const uint MaxRegularSector = 0xFFFFFFFA;

    /// <summary>Marks a sector holding DIFAT entries.</summary>
    internal const uint DifatSector = 0xFFFFFFFC;

    /// <summary>Marks a sector holding FAT entries.</summary>
    internal const uint FatSector = 0xFFFFFFFD;

    /// <summary>Ends a sector chain.</summary>
    internal const uint EndOfChain = 0xFFFFFFFE;

    /// <summary>Marks an unallocated sector, and an absent sibling or child in the directory.</summary>
    internal const uint Free = 0xFFFFFFFF;

    /// <summary>Gets the eight-byte file signature.</summary>
    internal static ReadOnlySpan<byte> Signature => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    /// <summary>Checks whether bytes start with the compound file signature.</summary>
    /// <param name="header">The leading bytes of a file.</param>
    /// <returns>True when the signature matches.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool HasSignature(ReadOnlySpan<byte> header) => header.StartsWith(Signature);

    /// <summary>Orders sibling names the way MS-CFB section 2.6.4 requires: shorter first, then by upper-cased code unit.</summary>
    /// <param name="left">The first name.</param>
    /// <param name="right">The second name.</param>
    /// <returns>A negative, zero or positive comparison result.</returns>
    internal static int CompareNames(string left, string right)
    {
        if (left.Length != right.Length)
        {
            return left.Length.CompareTo(right.Length);
        }

        for (var i = 0; i < left.Length; i++)
        {
            var comparison = char.ToUpperInvariant(left[i]).CompareTo(char.ToUpperInvariant(right[i]));
            if (comparison != 0)
            {
                return comparison;
            }
        }

        return 0;
    }
}
