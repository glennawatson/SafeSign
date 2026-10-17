// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.NuGet;

/// <summary>Contains the validated ZIP32 central directory counts and location.</summary>
/// <param name="Count">The number of directory entries.</param>
/// <param name="Offset">The central directory offset in bytes.</param>
/// <param name="Size">The central directory length in bytes.</param>
[DebuggerDisplay("Count = {Count}, Offset = {Offset}, Size = {Size}")]
internal readonly record struct ZipEndOfCentralDirectory(int Count, int Offset, int Size);
