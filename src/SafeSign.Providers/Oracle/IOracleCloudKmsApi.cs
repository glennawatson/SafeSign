// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Oracle;

/// <summary>Refit client for the Oracle Cloud Infrastructure (OCI) KMS cryptographic <c>sign</c> endpoint.</summary>
public interface IOracleCloudKmsApi
{
    /// <summary>Signs a digest using OCI KMS <c>POST /20180608/sign</c>.</summary>
    /// <param name="date">The RFC 1123 <c>date</c> header.</param>
    /// <param name="contentSha256">The base64 SHA-256 of the body (<c>x-content-sha256</c>).</param>
    /// <param name="authorization">The OCI RSA-SHA256 HTTP signature header.</param>
    /// <param name="body">The pre-serialized JSON body content.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The OCI KMS sign response.</returns>
    [Post("/20180608/sign")]
    Task<IApiResponse<OracleKmsSignResponse>> SignAsync(
        [Header("date")] string date,
        [Header("x-content-sha256")] string contentSha256,
        [Header("Authorization")] string authorization,
        [Body] HttpContent body,
        CancellationToken cancellationToken);
}
