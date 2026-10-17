// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Venafi;

/// <summary>Refit client for the Venafi CodeSign Protect (<c>vedauth</c> and <c>vedhsm</c>) REST API.</summary>
public interface IVenafiApi
{
    /// <summary>Acquires an OAuth bearer token from Venafi.</summary>
    /// <param name="request">The OAuth token request.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The OAuth token response.</returns>
    [Post("/vedauth/authorize/oauth")]
    Task<IApiResponse<VenafiOAuthReply>> AuthorizeAsync(
        [Body] VenafiOAuthRequest request,
        CancellationToken cancellationToken);

    /// <summary>Retrieves certificate objects and HSM key identifiers from Venafi.</summary>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The getobjects filter request.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The getobjects response.</returns>
    [Post("/vedhsm/api/getobjects")]
    Task<IApiResponse<VenafiGetObjectsReply>> GetObjectsAsync(
        [Header("Authorization")] string authorization,
        [Body] VenafiGetObjectsRequest request,
        CancellationToken cancellationToken);

    /// <summary>Signs data using a Venafi HSM key.</summary>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The sign request payload.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response.</returns>
    [Post("/vedhsm/api/sign")]
    Task<IApiResponse<VenafiSignReply>> SignAsync(
        [Header("Authorization")] string authorization,
        [Body] VenafiSignRequest request,
        CancellationToken cancellationToken);
}
