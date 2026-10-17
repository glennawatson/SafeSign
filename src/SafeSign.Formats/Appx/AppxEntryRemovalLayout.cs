// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Appx;

/// <summary>Identifies an APPX entry's central header and local record for removal.</summary>
/// <param name="CentralStart">The central header offset, or -1 when the entry is absent.</param>
/// <param name="CentralLength">The central header length in bytes.</param>
/// <param name="LocalStart">The local record offset, or -1 when the entry is absent.</param>
/// <param name="LocalEnd">The exclusive end offset of the local record.</param>
/// <param name="TotalEntries">The number of central directory entries.</param>
[DebuggerDisplay("Central = {CentralStart}, Local = {LocalStart}..{LocalEnd}")]
internal readonly record struct AppxEntryRemovalLayout(
    int CentralStart,
    int CentralLength,
    int LocalStart,
    int LocalEnd,
    int TotalEntries);
