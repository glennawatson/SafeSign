// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;

namespace SafeSign.Signing;

/// <summary>A digest for a provider to sign.</summary>
/// <param name="Digest">The digest bytes.</param>
/// <param name="HashAlgorithm">The algorithm that produced <paramref name="Digest"/>.</param>
[DebuggerDisplay("{HashAlgorithm.Name,nq} digest ({Digest.Length} bytes)")]
public readonly record struct SignDigestRequest(ReadOnlyMemory<byte> Digest, HashAlgorithmName HashAlgorithm);
