// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Certum;

/// <summary>The OAuth 2.0 token reply from <c>/idp/oauth2.0/accessToken</c>.</summary>
/// <param name="AccessToken">The bearer access token.</param>
/// <param name="TokenType">The token type (<c>bearer</c>).</param>
/// <param name="ExpiresIn">The lifetime in seconds (typically 1800).</param>
/// <param name="RefreshToken">The refresh token, when issued.</param>
[DebuggerDisplay("Certum token, expires in {ExpiresIn}s")]
public sealed record CertumTokenResponse(
    [property: JsonPropertyName("access_token")] string? AccessToken,
    [property: JsonPropertyName("token_type")] string? TokenType,
    [property: JsonPropertyName("expires_in")] long? ExpiresIn,
    [property: JsonPropertyName("refresh_token")] string? RefreshToken)
{
    /// <inheritdoc/>
    public override string ToString() => $"CertumTokenResponse {{ TokenType = {TokenType}, ExpiresIn = {ExpiresIn} }}";
}
