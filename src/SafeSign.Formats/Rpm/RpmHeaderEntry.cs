// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Rpm;

/// <summary>Represents a single entry in an RPM header structure.</summary>
/// <param name="Type">The RPM tag value type.</param>
/// <param name="Count">The number of values stored in <paramref name="Data"/>.</param>
/// <param name="Data">The raw big-endian entry data bytes.</param>
[DebuggerDisplay("Type = {Type}, Count = {Count}, Length = {Data.Length}")]
public readonly record struct RpmHeaderEntry(int Type, int Count, ReadOnlyMemory<byte> Data);
