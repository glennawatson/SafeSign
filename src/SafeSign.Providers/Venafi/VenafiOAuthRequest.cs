// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a Venafi <c>POST /vedauth/authorize/oauth</c> token request payload.</summary>
/// <param name="ClientId">The OAuth client ID (<c>VenafiCodeSignClient</c>).</param>
/// <param name="Scope">The OAuth scope (<c>codesignclient</c>).</param>
/// <param name="Username">The username.</param>
/// <param name="Password">The password.</param>
[DebuggerDisplay("{Username,nq}")]
public sealed record VenafiOAuthRequest(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("password")] string Password);
