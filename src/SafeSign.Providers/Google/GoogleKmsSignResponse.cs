// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>The <c>asymmetricSign</c> reply.</summary>
/// <param name="Signature">The signature, base64: PKCS #1 v1.5 for RSA, DER for ECDSA.</param>
/// <param name="Name">The key version that signed.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed record GoogleKmsSignResponse(ReadOnlyMemory<byte> Signature, string? Name);
