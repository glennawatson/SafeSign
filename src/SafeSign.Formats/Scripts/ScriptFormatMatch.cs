// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Scripts;

/// <summary>Contains the script format resolved from a file extension.</summary>
/// <param name="Matched">True when the extension identifies a supported script format.</param>
/// <param name="Format">The resolved format, or its default value when unsupported.</param>
[DebuggerDisplay("Matched = {Matched}, Marker = {Format.BeginMarker,nq}")]
internal readonly record struct ScriptFormatMatch(bool Matched, ScriptFormat Format);
