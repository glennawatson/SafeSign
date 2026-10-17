// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Rpm;

/// <summary>Contains hex-encoded IMA file signatures and their maximum raw byte length.</summary>
/// <param name="Signatures">The signatures in file-digest order, with empty strings for unsigned entries.</param>
/// <param name="Longest">The maximum raw IMA signature length in bytes.</param>
[DebuggerDisplay("Signatures = {Signatures.Length}, Longest = {Longest}")]
internal readonly record struct RpmFileDigestSignatures(string[] Signatures, int Longest);
