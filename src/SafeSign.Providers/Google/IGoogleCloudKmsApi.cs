// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Google;

/// <summary>The Google Cloud KMS REST API v1 surface for <c>cryptoKeyVersions.asymmetricSign</c>.</summary>
public interface IGoogleCloudKmsApi
{
    /// <summary>Signs a digest with an asymmetric key version in Google Cloud KMS.</summary>
    /// <param name="keyVersionName">The key version resource path (<c>projects/.../cryptoKeyVersions/...</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="request">The <c>asymmetricSign</c> request payload.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The <c>asymmetricSign</c> response containing the signature.</returns>
    [Post("/v1/{**keyVersionName}:asymmetricSign")]
    Task<IApiResponse<GoogleKmsSignResponse>> AsymmetricSignAsync(
        string keyVersionName,
        [Header("Authorization")] string authorization,
        [Body] GoogleKmsSignRequest request,
        CancellationToken cancellationToken);
}
