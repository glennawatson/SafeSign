// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Fortanix;

/// <summary>Represents a Fortanix DSM <c>POST /crypto/v1/sign</c> request payload.</summary>
/// <param name="Key">The target security object reference.</param>
/// <param name="HashAlg">The hash algorithm name (<c>SHA256</c>, <c>SHA384</c>, <c>SHA512</c>).</param>
/// <param name="Hash">The Base64-encoded digest bytes.</param>
/// <param name="Mode">The optional RSA signature padding mode.</param>
[DebuggerDisplay("{HashAlg,nq}")]
public sealed record FortanixSignPayload(
    [property: JsonPropertyName("key")] FortanixKeyObject Key,
    [property: JsonPropertyName("hash_alg")] string HashAlg,
    [property: JsonPropertyName("hash")] string Hash,
    [property: JsonPropertyName("mode")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] FortanixRsaMode? Mode);
