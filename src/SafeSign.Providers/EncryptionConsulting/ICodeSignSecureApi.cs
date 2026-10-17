// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>The Encryption Consulting CodeSign Secure REST surface for authentication, certificate retrieval, and digest signing.</summary>
public interface ICodeSignSecureApi
{
    /// <summary>Exchanges user credentials for a JWT bearer token.</summary>
    /// <param name="payload">The login request body (<c>user</c>, <c>code</c>, and <c>identityType</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The login response containing the JWT token.</returns>
    [Post("/api/auth/GetLoginToken/")]
    Task<IApiResponse<CodeSignSecureLoginReply>> GetLoginTokenAsync(
        [Body] CodeSignSecureLoginPayload payload,
        CancellationToken cancellationToken);

    /// <summary>Retrieves the active certificate bundle for a key alias.</summary>
    /// <param name="key">The certificate key alias.</param>
    /// <param name="authorization">The <c>Bearer</c> JWT header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The certificate response containing the Base64 PEM dump in <c>message</c>.</returns>
    [Get("/api/certificate_manage/activecerts/")]
    Task<IApiResponse<CodeSignSecureCertReply>> GetActiveCertificateAsync(
        [Query] string key,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);

    /// <summary>Signs a hexadecimal digest with a named certificate key.</summary>
    /// <param name="authorization">The <c>Bearer</c> JWT header.</param>
    /// <param name="payload">The sign request body (<c>certificate_name</c> and <c>hash</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The raw HTTP response whose body is the hexadecimal signature string.</returns>
    [Post("/api/signing/sign/")]
    Task<HttpResponseMessage> SignAsync(
        [Header("Authorization")] string authorization,
        [Body] CodeSignSecureSignPayload payload,
        CancellationToken cancellationToken);
}
