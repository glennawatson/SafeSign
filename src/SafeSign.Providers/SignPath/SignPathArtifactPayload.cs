// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignPath;

/// <summary>Represents the SignPath hash signing artifact payload serialized into the <c>Artifact</c> multipart field.</summary>
/// <param name="SignatureAlgorithm">The signature algorithm name (<c>RsaPkcs1</c> or <c>Ecdsa</c>).</param>
/// <param name="RsaHashAlgorithm">The hash algorithm OID for RSA signatures.</param>
/// <param name="Base64EncodedHash">The Base64-encoded hash digest.</param>
[DebuggerDisplay("{SignatureAlgorithm,nq}")]
public sealed record SignPathArtifactPayload(
    [property: JsonPropertyName("SignatureAlgorithm")] string SignatureAlgorithm,
    [property: JsonPropertyName("RsaHashAlgorithm")][property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RsaHashAlgorithm,
    [property: JsonPropertyName("Base64EncodedHash")] string Base64EncodedHash);
