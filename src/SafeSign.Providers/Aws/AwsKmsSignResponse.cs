// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Aws;

/// <summary>The KMS <c>Sign</c> reply.</summary>
/// <param name="KeyId">The key ARN that signed.</param>
/// <param name="Signature">The signature: PKCS #1 v1.5 for RSA, DER <c>Ecdsa-Sig-Value</c> for ECDSA.</param>
/// <param name="SigningAlgorithm">The algorithm used.</param>
[DebuggerDisplay("{SigningAlgorithm,nq} by {KeyId,nq}")]
public sealed record AwsKmsSignResponse(string? KeyId, ReadOnlyMemory<byte> Signature, string? SigningAlgorithm);
