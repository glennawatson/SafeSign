// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Formats.CompoundFile;

/// <summary>The object type of a compound file directory entry (MS-CFB section 2.6.1).</summary>
internal enum CompoundFileEntryKind
{
    /// <summary>An unused or unknown entry.</summary>
    Unknown = 0,

    /// <summary>A storage, which holds other entries.</summary>
    Storage = 1,

    /// <summary>A stream, which holds bytes.</summary>
    Stream = 2,

    /// <summary>The root storage.</summary>
    Root = 5,
}
