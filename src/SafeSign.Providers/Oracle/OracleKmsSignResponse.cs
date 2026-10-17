// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Oracle;

/// <summary>Response payload returned by OCI KMS <c>POST /20180608/sign</c>.</summary>
/// <param name="KeyId">The key OCID used to sign.</param>
/// <param name="KeyVersionId">The key version OCID used to sign.</param>
/// <param name="Signature">The base64-encoded signature bytes.</param>
[DebuggerDisplay("KeyId = {KeyId}")]
public sealed record OracleKmsSignResponse(
    [property: JsonPropertyName("keyId")] string? KeyId,
    [property: JsonPropertyName("keyVersionId")] string? KeyVersionId,
    [property: JsonPropertyName("signature")] string? Signature);
