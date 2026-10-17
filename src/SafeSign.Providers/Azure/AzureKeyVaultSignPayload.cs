// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Azure;

/// <summary>A Key Vault <c>KeySignParameters</c> body, or the <c>KeyOperationResult</c> reply.</summary>
/// <param name="Alg">The JSON Web Algorithm, such as <c>RS256</c>; null in replies.</param>
/// <param name="Value">The digest (request) or signature (reply), base64url without padding.</param>
[DebuggerDisplay("{Alg,nq}")]
public sealed record AzureKeyVaultSignPayload(string? Alg, string Value);
