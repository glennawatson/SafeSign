// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Fortanix;

/// <summary>Refit client for the Fortanix Data Security Manager (DSM) REST API.</summary>
public interface IFortanixDsmApi
{
    /// <summary>Authenticates a session via <c>POST /sys/v1/session/auth</c> using a Basic Auth API key.</summary>
    /// <param name="authorization">The <c>Basic &lt;api-key&gt;</c> header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The session authentication reply.</returns>
    [Post("/sys/v1/session/auth")]
    Task<IApiResponse<FortanixAuthReply>> AuthenticateAsync(
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);

    /// <summary>Signs a digest via <c>POST /crypto/v1/sign</c> using a Fortanix DSM security object.</summary>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="payload">The sign request payload.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response.</returns>
    [Post("/crypto/v1/sign")]
    Task<IApiResponse<FortanixSignReply>> SignAsync(
        [Header("Authorization")] string authorization,
        [Body] FortanixSignPayload payload,
        CancellationToken cancellationToken);
}
