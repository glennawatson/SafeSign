// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a Venafi <c>POST /vedhsm/api/sign</c> request payload.</summary>
/// <param name="KeyId">The HSM KeyId.</param>
/// <param name="Mechanism">The PKCS #11 mechanism identifier (<c>1</c> for <c>CKM_RSA_PKCS</c>, <c>4161</c> for <c>CKM_ECDSA</c>).</param>
/// <param name="Data">The Base64-encoded input data (ASN.1 DigestInfo for RSA, or raw digest for ECDSA).</param>
[DebuggerDisplay("KeyId = {KeyId,nq}, Mechanism = {Mechanism}")]
public sealed record VenafiSignRequest(
    [property: JsonPropertyName("KeyId")] string KeyId,
    [property: JsonPropertyName("Mechanism")] int Mechanism,
    [property: JsonPropertyName("Data")] string Data);
