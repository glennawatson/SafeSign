// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a Venafi <c>POST /vedauth/authorize/oauth</c> token response.</summary>
/// <param name="AccessToken">The OAuth access token.</param>
[DebuggerDisplay("{AccessToken}")]
public sealed record VenafiOAuthReply(
    [property: JsonPropertyName("access_token")] string? AccessToken);
