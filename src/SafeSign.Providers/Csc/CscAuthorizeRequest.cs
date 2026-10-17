// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Csc;

/// <summary>Represents a CSC <c>POST /credentials/authorize</c> request payload.</summary>
/// <param name="CredentialId">The credential identifier.</param>
/// <param name="NumSignatures">The number of signatures requested.</param>
/// <param name="Hash">The array of Base64-encoded hash digests to authorize.</param>
/// <param name="Pin">The optional credential PIN.</param>
/// <param name="Otp">The optional one-time password.</param>
[DebuggerDisplay("{CredentialId,nq}")]
public sealed record CscAuthorizeRequest(
    [property: JsonPropertyName("credentialID")] string CredentialId,
    [property: JsonPropertyName("numSignatures")] int NumSignatures,
    [property: JsonPropertyName("hash")] string[] Hash,
    [property: JsonPropertyName("PIN")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Pin,
    [property: JsonPropertyName("OTP")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Otp);
