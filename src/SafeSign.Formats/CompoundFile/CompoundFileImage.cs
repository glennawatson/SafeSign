// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.CompoundFile;

/// <summary>A parsed compound file's allocation tables, ready for reading streams.</summary>
/// <param name="File">The whole file.</param>
/// <param name="Header">The header.</param>
/// <param name="Fat">The file allocation table.</param>
/// <param name="MiniFat">The mini stream allocation table.</param>
/// <param name="MiniStream">The mini stream content.</param>
/// <param name="Entries">The directory entries.</param>
[DebuggerDisplay("{Entries.Length} entries")]
internal sealed record CompoundFileImage(
    ReadOnlyMemory<byte> File,
    CompoundFileHeader Header,
    uint[] Fat,
    uint[] MiniFat,
    byte[] MiniStream,
    CompoundFileDirectoryRecord[] Entries);
