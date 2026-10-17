// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Vault;

/// <summary>Request payload for the HashiCorp Vault Transit <c>sign</c> endpoint.</summary>
/// <param name="Input">The base64-encoded prehashed digest.</param>
/// <param name="Prehashed">Whether <paramref name="Input"/> is already hashed.</param>
/// <param name="SignatureAlgorithm">The RSA padding scheme (<c>pkcs1v15</c> or <c>pss</c>), or null for ECDSA.</param>
/// <param name="MarshalingAlgorithm">The ECDSA signature encoding (<c>asn1</c> for DER), or null for RSA.</param>
[DebuggerDisplay("Prehashed = {Prehashed}, SigAlg = {SignatureAlgorithm}")]
public sealed record VaultSignRequest(
    [property: JsonPropertyName("input")] string Input,
    [property: JsonPropertyName("prehashed")] bool Prehashed,
    [property: JsonPropertyName("signature_algorithm")] string? SignatureAlgorithm,
    [property: JsonPropertyName("marshaling_algorithm")] string? MarshalingAlgorithm);
