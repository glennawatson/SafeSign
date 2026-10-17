// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.SslCom;

/// <summary>Refit client for the SSL.com eSigner Cloud Signature Consortium (CSC) v0 API.</summary>
public interface ISslComESignerApi
{
    /// <summary>Signs one or more precomputed digests via <c>POST /csc/v0/signatures/signHash</c>.</summary>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The CSC <c>signHash</c> request body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The CSC <c>signHash</c> response containing base64 signatures.</returns>
    [Post("/csc/v0/signatures/signHash")]
    Task<IApiResponse<SslComSignHashResponse>> SignHashAsync(
        [Header("Authorization")] string authorization,
        [Body] SslComSignHashRequest request,
        CancellationToken cancellationToken);
}
