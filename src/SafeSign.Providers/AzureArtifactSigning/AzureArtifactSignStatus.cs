// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>Response body from the Azure Artifact Signing <c>StartSign</c> and <c>GetSignStatus</c> REST endpoints.</summary>
/// <param name="OperationId">The unique operation identifier assigned to the signing request.</param>
/// <param name="Status">The operation status (<c>NotStarted</c>, <c>InProgress</c>, <c>Running</c>, <c>Succeeded</c>, <c>Failed</c>, <c>Canceled</c>, or <c>TimedOut</c>).</param>
/// <param name="Signature">The standard Base64-encoded raw signature when <paramref name="Status"/> is <c>Succeeded</c>.</param>
/// <param name="SigningCertificate">The optional Base64-encoded leaf signing certificate returned when <paramref name="Status"/> is <c>Succeeded</c>.</param>
[DebuggerDisplay("{Status,nq} ({OperationId,nq})")]
public sealed record AzureArtifactSignStatus(
    string? OperationId,
    string? Status,
    string? Signature,
    string? SigningCertificate);
