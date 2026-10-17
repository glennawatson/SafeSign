// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.CompoundFile;

/// <summary>One raw directory entry as stored in a compound file (MS-CFB section 2.6).</summary>
/// <param name="Name">The entry name.</param>
/// <param name="Kind">The entry type.</param>
/// <param name="Left">The left sibling entry, or <see cref="CompoundFileFormat.Free"/>.</param>
/// <param name="Right">The right sibling entry, or <see cref="CompoundFileFormat.Free"/>.</param>
/// <param name="Child">The root of the child tree, or <see cref="CompoundFileFormat.Free"/>.</param>
/// <param name="Metadata">The class identifier, state bits and times.</param>
/// <param name="StartSector">The first sector of the stream.</param>
/// <param name="Size">The stream length.</param>
[DebuggerDisplay("{Name,nq} ({Kind}, {Size} bytes)")]
internal readonly record struct CompoundFileDirectoryRecord(
    string Name,
    CompoundFileEntryKind Kind,
    uint Left,
    uint Right,
    uint Child,
    CompoundFileMetadata Metadata,
    uint StartSector,
    ulong Size);
