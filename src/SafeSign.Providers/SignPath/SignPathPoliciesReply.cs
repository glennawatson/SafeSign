// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignPath;

/// <summary>Represents the signing policies response from SignPath <c>Cryptoki/MySigningPolicies</c>.</summary>
/// <param name="SigningPolicies">The signing policies accessible to the authenticated user.</param>
[DebuggerDisplay("Count = {SigningPolicies?.Length ?? 0}")]
public sealed record SignPathPoliciesReply(
    [property: JsonPropertyName("signingPolicies")] SignPathPolicyItem[]? SigningPolicies);
