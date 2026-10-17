// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Aws;

/// <summary>The AWS KMS HTTP JSON 1.1 protocol surface (<c>TrentService.Sign</c>).</summary>
public interface IAwsKmsApi
{
    /// <summary>Submits a SigV4-authenticated KMS request.</summary>
    /// <param name="path">The endpoint path on the KMS host.</param>
    /// <param name="amzDate">The <c>X-Amz-Date</c> header value.</param>
    /// <param name="amzTarget">The <c>X-Amz-Target</c> header value.</param>
    /// <param name="authorization">The <c>Authorization</c> SigV4 header value.</param>
    /// <param name="securityToken">The optional <c>X-Amz-Security-Token</c> header value.</param>
    /// <param name="payload">The <c>application/x-amz-json-1.1</c> payload.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The raw HTTP response.</returns>
    [Post("/{**path}")]
    Task<HttpResponseMessage> SendAsync(
        string path,
        [Header("x-amz-date")] string amzDate,
        [Header("x-amz-target")] string amzTarget,
        [Header("Authorization")] string authorization,
        [Header("x-amz-security-token")] string? securityToken,
        [Body] HttpContent payload,
        CancellationToken cancellationToken);
}
