// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.SignServer;

/// <summary>Refit client for the Keyfactor SignServer REST v1 API.</summary>
public interface IKeyfactorSignServerApi
{
    /// <summary>Invokes a SignServer worker to sign a precomputed digest.</summary>
    /// <param name="worker">The worker name or ID.</param>
    /// <param name="authorization">The optional <c>Authorization</c> header value.</param>
    /// <param name="request">The process request body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The worker process response.</returns>
    [Post("/signserver/rest/v1/workers/{worker}/process")]
    Task<IApiResponse<SignServerSignResponse>> ProcessAsync(
        string worker,
        [Header("Authorization")] string? authorization,
        [Body] SignServerSignRequest request,
        CancellationToken cancellationToken);
}
