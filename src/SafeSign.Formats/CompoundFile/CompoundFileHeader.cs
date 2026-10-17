// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.CompoundFile;

/// <summary>The compound file header fields the reader needs (MS-CFB section 2.2).</summary>
/// <param name="MajorVersion">The major version, 3 or 4.</param>
/// <param name="SectorShift">The sector size as a power of two.</param>
/// <param name="FatSectorCount">The number of FAT sectors.</param>
/// <param name="FirstDirectorySector">The first directory sector.</param>
/// <param name="MiniStreamCutoff">The stream size below which streams live in the mini stream.</param>
/// <param name="FirstMiniFatSector">The first mini FAT sector.</param>
/// <param name="FirstDifatSector">The first DIFAT sector.</param>
/// <param name="DifatSectorCount">The number of DIFAT sectors.</param>
[DebuggerDisplay("v{MajorVersion} sector 2^{SectorShift}")]
internal readonly record struct CompoundFileHeader(
    int MajorVersion,
    int SectorShift,
    uint FatSectorCount,
    uint FirstDirectorySector,
    uint MiniStreamCutoff,
    uint FirstMiniFatSector,
    uint FirstDifatSector,
    uint DifatSectorCount)
{
    /// <summary>Gets the sector length in bytes.</summary>
    internal int SectorSize => 1 << SectorShift;
}
