// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a certificate object returned by Venafi <c>/vedhsm/api/getobjects</c>.</summary>
/// <param name="KeyId">The associated HSM KeyId.</param>
/// <param name="Label">The certificate label.</param>
/// <param name="Value">The Base64-encoded DER certificate bytes.</param>
[DebuggerDisplay("{Label,nq} ({KeyId,nq})")]
public sealed record VenafiCertificateObject(
    [property: JsonPropertyName("KeyId")] string? KeyId,
    [property: JsonPropertyName("Label")] string? Label,
    [property: JsonPropertyName("Value")] string? Value);
