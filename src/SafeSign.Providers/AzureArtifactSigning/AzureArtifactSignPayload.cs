// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>Request body for the Azure Artifact Signing <c>StartSign</c> REST endpoint.</summary>
/// <param name="SignatureAlgorithm">The signature algorithm, such as <c>RS256</c>, <c>RS384</c>, <c>RS512</c>, <c>ES256</c>, <c>ES384</c>, or <c>ES512</c>.</param>
/// <param name="Digest">The standard Base64-encoded digest to sign.</param>
[DebuggerDisplay("{SignatureAlgorithm,nq}")]
public sealed record AzureArtifactSignPayload(string SignatureAlgorithm, string Digest);
