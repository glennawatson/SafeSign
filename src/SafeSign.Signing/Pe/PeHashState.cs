// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace SafeSign.Signing.Pe;

/// <summary>The resources one hashing pass shares.</summary>
/// <param name="File">The open image.</param>
/// <param name="Hash">The incremental hash.</param>
/// <param name="Buffer">The pooled read buffer.</param>
[DebuggerDisplay("{Buffer.Length} byte buffer")]
internal readonly record struct PeHashState(SafeFileHandle File, IncrementalHash Hash, byte[] Buffer);
