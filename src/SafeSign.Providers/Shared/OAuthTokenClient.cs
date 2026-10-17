// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Shared;

/// <summary>Requests OAuth 2.0 access tokens with a form-encoded token request (RFC 6749 section 4.4 and RFC 7523).</summary>
public static class OAuthTokenClient
{
    /// <summary>The lifetime in seconds assumed when the reply has no <c>expires_in</c>.</summary>
    private const int DefaultLifetimeSeconds = 300;

    /// <summary>Posts a token request through Refit and returns the token with its expiry.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="tokenEndpoint">The token endpoint.</param>
    /// <param name="form">The form fields, such as <c>grant_type</c>, <c>client_id</c>, and <c>scope</c>.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token.</returns>
    /// <exception cref="ProviderRequestException">The endpoint failed or returned no token.</exception>
    public static async ValueTask<CachedAccessToken> RequestAsync(
        RefitSettings http,
        Uri tokenEndpoint,
        Dictionary<string, string> form,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        ArgumentNullException.ThrowIfNull(form);
        ArgumentNullException.ThrowIfNull(time);
        var api = RestService.ForGenerated<IOAuthTokenApi>(ProviderHttp.Authority(tokenEndpoint), ProviderHttp.CreateSettings(OAuthJsonContext.Default, http));
        var path = tokenEndpoint.PathAndQuery.TrimStart('/');
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.RequestTokenAsync(path, form, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {tokenEndpoint}");
        if (reply.AccessToken is not { Length: > 0 })
        {
            throw new ProviderRequestException($"{tokenEndpoint} returned no access_token.");
        }

        var seconds = reply.ExpiresIn ?? DefaultLifetimeSeconds;
        return new(reply.AccessToken, time.GetUtcNow().AddSeconds(seconds));
    }
}
