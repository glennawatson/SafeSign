// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.CompoundFile;

/// <summary>A storage or stream in a compound file, with its children when it is a storage.</summary>
/// <param name="Name">The entry name, at most 31 UTF-16 code units.</param>
/// <param name="Metadata">The class identifier, state bits and times.</param>
/// <param name="Data">The stream content; empty for storages.</param>
/// <param name="Children">The entries a storage holds, or null when this entry is a stream.</param>
[DebuggerDisplay("{Name,nq}")]
internal sealed record CompoundFileEntry(
    string Name,
    CompoundFileMetadata Metadata,
    ReadOnlyMemory<byte> Data,
    List<CompoundFileEntry>? Children)
{
    /// <summary>Gets a value indicating whether this entry is a storage rather than a stream.</summary>
    internal bool IsStorage => Children is not null;
}
