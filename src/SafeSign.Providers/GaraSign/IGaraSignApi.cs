// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.GaraSign;

/// <summary>The Garantir GaraSign REST surface (<c>/authenticate</c>, <c>/keystore</c>, and <c>/sign</c>).</summary>
public interface IGaraSignApi
{
    /// <summary>Authenticates with GaraSign and obtains a <c>sessionToken</c>.</summary>
    /// <param name="path">The relative path to <c>authenticate</c>.</param>
    /// <param name="form">The form-urlencoded parameters (<c>api_version</c>, <c>username</c>, <c>password</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The authentication response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<GaraSignAuthReply>> AuthenticateAsync(
        string path,
        [Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, string> form,
        CancellationToken cancellationToken);

    /// <summary>Retrieves the keys and certificate chains in the GaraSign keystore.</summary>
    /// <param name="path">The relative path to <c>keystore</c>.</param>
    /// <param name="form">The form-urlencoded parameters (<c>api_version</c> and <c>session_token</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The keystore response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<GaraSignKeystoreReply>> GetKeystoreAsync(
        string path,
        [Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, string> form,
        CancellationToken cancellationToken);

    /// <summary>Submits or polls a digest signing operation on GaraSign.</summary>
    /// <param name="path">The relative path to <c>sign</c>.</param>
    /// <param name="form">The form-urlencoded parameters.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response.</returns>
    [Post("/{**path}")]
    Task<IApiResponse<GaraSignSignReply>> SignAsync(
        string path,
        [Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, string> form,
        CancellationToken cancellationToken);
}
