// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>The Azure Artifact Signing data-plane REST surface for certificate chain retrieval and digest signing.</summary>
public interface IAzureArtifactSigningApi
{
    /// <summary>Retrieves the PKCS #7 certificate chain for a certificate profile.</summary>
    /// <param name="accountName">The Azure Artifact Signing account name.</param>
    /// <param name="certificateProfileName">The certificate profile name.</param>
    /// <param name="apiVersion">The API version (<c>2022-06-15-preview</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The raw HTTP response containing the binary PKCS #7 certificate bundle.</returns>
    [Get("/codesigningaccounts/{accountName}/certificateprofiles/{certificateProfileName}/sign/certchain")]
    [Headers("Accept: application/pkcs7-mime, application/x-x509-ca-cert, application/json")]
    Task<HttpResponseMessage> GetCertificateChainAsync(
        string accountName,
        string certificateProfileName,
        [Query][AliasAs("api-version")] string apiVersion,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);

    /// <summary>Submits a digest signing operation for a certificate profile.</summary>
    /// <param name="accountName">The Azure Artifact Signing account name.</param>
    /// <param name="certificateProfileName">The certificate profile name.</param>
    /// <param name="apiVersion">The API version (<c>2022-06-15-preview</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="payload">The sign request body (<c>signatureAlgorithm</c> and <c>digest</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The initial signing operation status response.</returns>
    [Post("/codesigningaccounts/{accountName}/certificateprofiles/{certificateProfileName}/sign")]
    Task<IApiResponse<AzureArtifactSignStatus>> StartSignAsync(
        string accountName,
        string certificateProfileName,
        [Query][AliasAs("api-version")] string apiVersion,
        [Header("Authorization")] string authorization,
        [Body] AzureArtifactSignPayload payload,
        CancellationToken cancellationToken);

    /// <summary>Polls the status of an in-progress signing operation.</summary>
    /// <param name="accountName">The Azure Artifact Signing account name.</param>
    /// <param name="certificateProfileName">The certificate profile name.</param>
    /// <param name="operationId">The operation identifier returned by <see cref="StartSignAsync"/>.</param>
    /// <param name="apiVersion">The API version (<c>2022-06-15-preview</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The current signing operation status response.</returns>
    [Get("/codesigningaccounts/{accountName}/certificateprofiles/{certificateProfileName}/sign/{operationId}")]
    Task<IApiResponse<AzureArtifactSignStatus>> GetSignStatusAsync(
        string accountName,
        string certificateProfileName,
        string operationId,
        [Query][AliasAs("api-version")] string apiVersion,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);
}
