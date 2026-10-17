// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Azure;

/// <summary>
/// Acquires Entra ID tokens with the OAuth 2.0 client credentials grant
/// (https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow).
/// </summary>
internal static class EntraIdTokens
{
    /// <summary>Requests an app-only token for a resource scope such as <c>https://vault.azure.net/.default</c>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="credential">The application credential.</param>
    /// <param name="scope">The <c>.default</c> scope of the resource.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token.</returns>
    internal static ValueTask<CachedAccessToken> RequestAsync(
        RefitSettings http,
        EntraIdCredential credential,
        string scope,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        Uri endpoint = new(credential.AuthorityHost, $"{Uri.EscapeDataString(credential.TenantId)}/oauth2/v2.0/token");
        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = credential.ClientId,
            ["client_secret"] = credential.ClientSecret,
            ["scope"] = scope,
        };
        return OAuthTokenClient.RequestAsync(http, endpoint, form, time, cancellationToken);
    }
}
