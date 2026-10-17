// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Shared;

/// <summary>An OAuth 2.0 token endpoint reply (RFC 6749 section 5.1).</summary>
/// <param name="AccessToken">The access token.</param>
/// <param name="ExpiresIn">The lifetime in seconds, when given.</param>
[DebuggerDisplay("OAuth token, expires in {ExpiresIn}s")]
public sealed record OAuthTokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("expires_in")] long? ExpiresIn)
{
    /// <inheritdoc/>
    public override string ToString() => $"OAuthTokenResponse {{ ExpiresIn = {ExpiresIn} }}";
}
