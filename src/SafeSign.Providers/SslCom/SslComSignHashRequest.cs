// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SslCom;

/// <summary>Request payload for the SSL.com eSigner CSC <c>POST /csc/v0/signatures/signHash</c> endpoint.</summary>
/// <param name="CredentialId">The eSigner credential ID.</param>
/// <param name="Sad">The Signature Activation Data or TOTP code.</param>
/// <param name="Hashes">The array of base64-encoded digests to sign.</param>
/// <param name="SignAlgo">The OID of the signature algorithm.</param>
[DebuggerDisplay("CredentialId = {CredentialId}, SignAlgo = {SignAlgo}")]
public sealed record SslComSignHashRequest(
    [property: JsonPropertyName("credentialID")] string CredentialId,
    [property: JsonPropertyName("SAD")] string Sad,
    [property: JsonPropertyName("hash")] string[] Hashes,
    [property: JsonPropertyName("signAlgo")] string SignAlgo);
