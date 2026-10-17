// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Csc;

/// <summary>Represents a CSC v1 <c>POST /signatures/signHash</c> request payload.</summary>
/// <param name="CredentialId">The credential identifier.</param>
/// <param name="Sad">The Signature Activation Data (SAD) token.</param>
/// <param name="Hash">The array of Base64-encoded hash digests to sign.</param>
/// <param name="HashAlgo">The hash algorithm OID.</param>
/// <param name="SignAlgo">The signature algorithm OID.</param>
[DebuggerDisplay("{CredentialId,nq} ({SignAlgo,nq})")]
public sealed record CscSignHashRequest(
    [property: JsonPropertyName("credentialID")] string CredentialId,
    [property: JsonPropertyName("SAD")] string Sad,
    [property: JsonPropertyName("hash")] string[] Hash,
    [property: JsonPropertyName("hashAlgo")] string HashAlgo,
    [property: JsonPropertyName("signAlgo")] string SignAlgo);
