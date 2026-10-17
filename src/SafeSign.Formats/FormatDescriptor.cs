// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats;

/// <summary>Describes a file format known to SafeSign, its supported extensions, and its implementation status.</summary>
/// <param name="Id">The short CLI identifier (for example, <c>pe</c>, <c>msi</c>, <c>rpm</c>).</param>
/// <param name="Name">The display name of the format.</param>
/// <param name="Status">Whether native signing is implemented or out of scope.</param>
/// <param name="Extensions">The file extensions associated with the format.</param>
/// <param name="Summary">A human-readable summary of how the format is signed or why it is out of scope.</param>
[DebuggerDisplay("{Id,nq} ({Status})")]
public sealed record FormatDescriptor(
    string Id,
    string Name,
    FormatStatus Status,
    string[] Extensions,
    string Summary);
