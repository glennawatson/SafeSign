// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>A Cloud KMS <c>Digest</c>: exactly one member is set, base64 encoded.</summary>
/// <param name="Sha256">A SHA-256 digest.</param>
/// <param name="Sha384">A SHA-384 digest.</param>
/// <param name="Sha512">A SHA-512 digest.</param>
[DebuggerDisplay("Digest")]
public sealed record GoogleKmsDigest(string? Sha256, string? Sha384, string? Sha512);
