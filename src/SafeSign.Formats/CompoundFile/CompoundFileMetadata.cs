// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.CompoundFile;

/// <summary>The directory entry fields a compound file carries alongside an entry's name and data.</summary>
/// <param name="Clsid">The storage class identifier.</param>
/// <param name="StateBits">The user-defined state bits.</param>
/// <param name="CreationTime">The creation time as a Windows FILETIME.</param>
/// <param name="ModifiedTime">The modification time as a Windows FILETIME.</param>
[DebuggerDisplay("{Clsid}")]
internal readonly record struct CompoundFileMetadata(Guid Clsid, uint StateBits, long CreationTime, long ModifiedTime);
