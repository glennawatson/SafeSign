// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Shared;

/// <summary>The OAuth 2.0 form-encoded token endpoint surface (RFC 6749 section 4.4 and RFC 7523).</summary>
public interface IOAuthTokenApi
{
    /// <summary>Submits a form-encoded OAuth 2.0 token request.</summary>
    /// <param name="path">The endpoint path on the authority host.</param>
    /// <param name="form">The form fields (<c>grant_type</c>, <c>client_id</c>, etc.).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The token response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<OAuthTokenResponse>> RequestTokenAsync(
        string path,
        [Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, string> form,
        CancellationToken cancellationToken);
}
