// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.DigiCert;

/// <summary>The DigiCert ONE / KeyLocker Signing Manager REST surface for certificate lookup and digest signing.</summary>
public interface IDigiCertKeyLockerApi
{
    /// <summary>Finds certificates in DigiCert ONE Signing Manager by identifier or alias.</summary>
    /// <param name="id">The optional certificate identifier filter.</param>
    /// <param name="alias">The optional certificate alias filter.</param>
    /// <param name="apiKey">The DigiCert ONE API key (<c>x-api-key</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The certificate list response.</returns>
    [Get("/signingmanager/api/v1/certificates")]
    Task<IApiResponse<DigiCertCertificatesReply>> GetCertificatesAsync(
        [Query] string? id,
        [Query] string? alias,
        [Header("x-api-key")] string apiKey,
        CancellationToken cancellationToken);

    /// <summary>Signs a digest using a DigiCert ONE keypair.</summary>
    /// <param name="keypairId">The keypair identifier.</param>
    /// <param name="apiKey">The DigiCert ONE API key (<c>x-api-key</c>).</param>
    /// <param name="payload">The sign request body (<c>account</c>, <c>sig_alg</c>, and <c>hash</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response containing the Base64 signature.</returns>
    [Post("/signingmanager/api/v1/keypairs/{keypairId}/sign")]
    Task<IApiResponse<DigiCertSignReply>> SignAsync(
        string keypairId,
        [Header("x-api-key")] string apiKey,
        [Body] DigiCertSignPayload payload,
        CancellationToken cancellationToken);
}
