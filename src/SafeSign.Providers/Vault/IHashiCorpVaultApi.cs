// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Vault;

/// <summary>Refit client for the HashiCorp Vault Transit secret engine <c>sign</c> endpoint.</summary>
public interface IHashiCorpVaultApi
{
    /// <summary>Signs a prehashed digest using a Vault Transit key.</summary>
    /// <param name="mount">The Transit secret engine mount path.</param>
    /// <param name="keyName">The key name inside the Transit mount.</param>
    /// <param name="hashAlgorithm">The Vault hash algorithm slug (<c>sha2-256</c>, <c>sha2-384</c>, <c>sha2-512</c>).</param>
    /// <param name="token">The <c>X-Vault-Token</c> header value.</param>
    /// <param name="vaultNamespace">The optional <c>X-Vault-Namespace</c> header value.</param>
    /// <param name="request">The sign request body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The Vault sign response envelope.</returns>
    [Post("/v1/{mount}/sign/{keyName}/{hashAlgorithm}")]
    Task<IApiResponse<VaultSignResponse>> SignAsync(
        string mount,
        string keyName,
        string hashAlgorithm,
        [Header("X-Vault-Token")] string token,
        [Header("X-Vault-Namespace")] string? vaultNamespace,
        [Body] VaultSignRequest request,
        CancellationToken cancellationToken);
}
