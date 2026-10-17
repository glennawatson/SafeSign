// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Rpm;

/// <summary>Contains the fields written into one RPM header index record.</summary>
/// <param name="Tag">The RPM tag number.</param>
/// <param name="Type">The value type identifier.</param>
/// <param name="Offset">The value's offset in the header data store.</param>
/// <param name="Count">The number of values.</param>
[DebuggerDisplay("Tag = {Tag}, Type = {Type}, Offset = {Offset}, Count = {Count}")]
internal readonly record struct RpmHeaderIndexEntry(int Tag, int Type, int Offset, int Count);
