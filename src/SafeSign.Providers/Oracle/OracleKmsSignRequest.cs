// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Oracle;

/// <summary>Request payload for OCI KMS <c>POST /20180608/sign</c>.</summary>
/// <param name="KeyId">The OCI KMS key OCID.</param>
/// <param name="KeyVersionId">The optional key version OCID.</param>
/// <param name="Message">The base64-encoded digest.</param>
/// <param name="MessageType">The message type (<c>DIGEST</c>).</param>
/// <param name="SigningAlgorithm">The OCI signing algorithm identifier.</param>
[DebuggerDisplay("KeyId = {KeyId}, Alg = {SigningAlgorithm}")]
public sealed record OracleKmsSignRequest(
    [property: JsonPropertyName("keyId")] string KeyId,
    [property: JsonPropertyName("keyVersionId")] string? KeyVersionId,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("messageType")] string MessageType,
    [property: JsonPropertyName("signingAlgorithm")] string SigningAlgorithm);
