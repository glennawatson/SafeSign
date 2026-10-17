// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Appx;

/// <summary>Locates an APPX archive's central directory and ZIP trailer records.</summary>
/// <param name="CentralOffset">The central directory offset in bytes.</param>
/// <param name="CentralSize">The central directory length in bytes.</param>
/// <param name="TrailerOffset">The ZIP trailer's start offset in bytes.</param>
/// <param name="EocdOffset">The standard end of central directory record's offset in bytes.</param>
/// <param name="IsZip64">True when the archive contains a ZIP64 end of central directory record.</param>
[DebuggerDisplay("Central = {CentralOffset}, Size = {CentralSize}, ZIP64 = {IsZip64}")]
internal readonly record struct AppxCentralDirectoryLayout(
    int CentralOffset,
    int CentralSize,
    int TrailerOffset,
    int EocdOffset,
    bool IsZip64);
