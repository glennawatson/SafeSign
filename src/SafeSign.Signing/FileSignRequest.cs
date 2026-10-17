// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing;

/// <summary>A request to sign one file.</summary>
/// <param name="InputPath">The file to sign.</param>
/// <param name="OutputPath">Where to write the signed file. It may equal <paramref name="InputPath"/>.</param>
/// <param name="Session">The signing session.</param>
[DebuggerDisplay("{InputPath,nq} -> {OutputPath,nq}")]
public sealed record FileSignRequest(string InputPath, string OutputPath, SigningSession Session);
