// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text;

namespace SafeSign.Formats.Scripts;

/// <summary>Identifies a script's text encoding and byte order mark length.</summary>
/// <param name="Encoding">The encoding used to decode and preserve the script text.</param>
/// <param name="PreambleLength">The byte order mark length in bytes.</param>
[DebuggerDisplay("{Encoding.WebName,nq}, Preamble = {PreambleLength}")]
internal readonly record struct ScriptEncoding(Encoding Encoding, int PreambleLength);
