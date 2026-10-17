// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Azure;

/// <summary>The Azure Key Vault data-plane REST surface for certificate retrieval and key digest signing.</summary>
public interface IAzureKeyVaultApi
{
    /// <summary>Retrieves a certificate bundle from Azure Key Vault.</summary>
    /// <param name="path">The certificate path (<c>certificates/{name}</c> or <c>certificates/{name}/{version}</c>).</param>
    /// <param name="apiVersion">The Key Vault API version (<c>7.4</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The certificate bundle response.</returns>
    [Get("/{**path}")]
    Task<IApiResponse<AzureKeyVaultCertificateBundle>> GetCertificateAsync(
        string path,
        [Query][AliasAs("api-version")] string apiVersion,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);

    /// <summary>Signs a digest with a Key Vault key.</summary>
    /// <param name="keyPath">The versioned key path (<c>keys/{name}/{version}</c>).</param>
    /// <param name="apiVersion">The Key Vault API version (<c>7.4</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="payload">The sign request body (<c>alg</c> and <c>value</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response carrying the base64url signature in <c>value</c>.</returns>
    [Post("/{**keyPath}/sign")]
    Task<IApiResponse<AzureKeyVaultSignPayload>> SignAsync(
        string keyPath,
        [Query][AliasAs("api-version")] string apiVersion,
        [Header("Authorization")] string authorization,
        [Body] AzureKeyVaultSignPayload payload,
        CancellationToken cancellationToken);
}
