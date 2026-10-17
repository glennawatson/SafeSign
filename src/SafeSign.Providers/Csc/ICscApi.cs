// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;
using SafeSign.Providers.SslCom;

namespace SafeSign.Providers.Csc;

/// <summary>Refit client for the Cloud Signature Consortium (CSC) v1 REST API.</summary>
public interface ICscApi
{
    /// <summary>Retrieves credential details and certificate chain from a CSC service.</summary>
    /// <param name="path">The relative path to <c>credentials/info</c>.</param>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The credentials info request.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The credentials info response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<CscCredentialsInfoReply>> GetCredentialsInfoAsync(
        [Query(Format = "U")] string path,
        [Header("Authorization")] string authorization,
        [Body] CscCredentialsInfoRequest request,
        CancellationToken cancellationToken);

    /// <summary>Authorizes a credential and obtains a Signature Activation Data (SAD) token.</summary>
    /// <param name="path">The relative path to <c>credentials/authorize</c>.</param>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The authorize request.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The authorize response containing the SAD token.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<CscAuthorizeReply>> AuthorizeAsync(
        [Query(Format = "U")] string path,
        [Header("Authorization")] string authorization,
        [Body] CscAuthorizeRequest request,
        CancellationToken cancellationToken);

    /// <summary>Signs one or more hashes using the CSC <c>signatures/signHash</c> endpoint.</summary>
    /// <param name="path">The relative path to <c>signatures/signHash</c>.</param>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="request">The signHash request payload.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The signHash response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<SslComSignHashResponse>> SignHashAsync(
        [Query(Format = "U")] string path,
        [Header("Authorization")] string authorization,
        [Body] CscSignHashRequest request,
        CancellationToken cancellationToken);
}
