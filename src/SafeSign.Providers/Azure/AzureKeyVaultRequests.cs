// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Azure;

/// <summary>
/// Calls the Key Vault data plane through <see cref="IAzureKeyVaultApi"/>: Get Certificate
/// (https://learn.microsoft.com/rest/api/keyvault/certificates/get-certificate/get-certificate) and Sign
/// (https://learn.microsoft.com/rest/api/keyvault/keys/sign/sign).
/// </summary>
public static class AzureKeyVaultRequests
{
    /// <summary>Gets the Key Vault REST API version.</summary>
    public static string ApiVersion => "7.4";

    /// <summary>Gets the token scope for Key Vault.</summary>
    public static string Scope => "https://vault.azure.net/.default";

    /// <summary>Fetches the certificate bundle.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="token">The access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The bundle.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<AzureKeyVaultCertificateBundle> GetCertificateAsync(
        RefitSettings http,
        AzureKeyVaultOptions options,
        string token,
        CancellationToken cancellationToken) =>
        GetCertificateAsync(http, options, token, TimeProvider.System, cancellationToken);

    /// <summary>Fetches the certificate bundle with retry and exponential backoff.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="token">The access token.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The bundle.</returns>
    public static async ValueTask<AzureKeyVaultCertificateBundle> GetCertificateAsync(
        RefitSettings http,
        AzureKeyVaultOptions options,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        var api = RestService.ForGenerated<IAzureKeyVaultApi>(ProviderHttp.Authority(options.VaultUri), ProviderHttp.CreateSettings(AzureKeyVaultJsonContext.Default, http));
        var path = options.CertificateVersion is { Length: > 0 } version
            ? $"certificates/{Uri.EscapeDataString(options.CertificateName)}/{Uri.EscapeDataString(version)}"
            : $"certificates/{Uri.EscapeDataString(options.CertificateName)}";
        var authorization = ProviderHttp.Bearer(token);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetCertificateAsync(path, ApiVersion, authorization, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        return ProviderHttp.Unwrap(response, $"GET {options.VaultUri}{path}");
    }

    /// <summary>Signs a digest with the key identified by <paramref name="keyId"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="keyId">The versioned key identifier (<c>kid</c>).</param>
    /// <param name="kind">The key family.</param>
    /// <param name="request">The digest signing request.</param>
    /// <param name="token">The access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The PKCS #1 v1.5 or DER ECDSA signature.</returns>
    /// <exception cref="ProviderRequestException">The reply carried no signature.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<byte[]> SignAsync(
        RefitSettings http,
        string keyId,
        PublicKeyKind kind,
        SignDigestRequest request,
        string token,
        CancellationToken cancellationToken) =>
        SignAsync(http, keyId, kind, request, token, TimeProvider.System, cancellationToken);

    /// <summary>Signs a digest with the key identified by <paramref name="keyId"/> with retry and exponential backoff.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="keyId">The versioned key identifier (<c>kid</c>).</param>
    /// <param name="kind">The key family.</param>
    /// <param name="request">The digest signing request.</param>
    /// <param name="token">The access token.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The PKCS #1 v1.5 or DER ECDSA signature.</returns>
    /// <exception cref="ProviderRequestException">The reply carried no signature.</exception>
    public static async ValueTask<byte[]> SignAsync(
        RefitSettings http,
        string keyId,
        PublicKeyKind kind,
        SignDigestRequest request,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(time);
        var keyUri = new Uri(keyId);
        var api = RestService.ForGenerated<IAzureKeyVaultApi>(ProviderHttp.Authority(keyUri), ProviderHttp.CreateSettings(AzureKeyVaultJsonContext.Default, http));
        AzureKeyVaultSignPayload body = new(Algorithm(kind, request.HashAlgorithm), Base64Url.EncodeToString(request.Digest.Span));
        var keyPath = keyUri.AbsolutePath.Trim('/');
        var authorization = ProviderHttp.Bearer(token);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(keyPath, ApiVersion, authorization, body, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {keyId}/sign");
        if (reply.Value is not { Length: > 0 })
        {
            throw new ProviderRequestException("Azure Key Vault returned no signature.");
        }

        var signature = Base64Url.DecodeFromChars(reply.Value);
        return kind == PublicKeyKind.Ecdsa ? EcdsaSignatureEncoding.IeeeP1363ToDer(signature) : signature;
    }

    /// <summary>Maps the key family and digest to a JSON Web Algorithm name.</summary>
    /// <param name="kind">The key family.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <returns>The algorithm name.</returns>
    /// <exception cref="NotSupportedException">The combination is not supported.</exception>
    public static string Algorithm(PublicKeyKind kind, HashAlgorithmName hash) => (kind, hash.Name) switch
    {
        (PublicKeyKind.Rsa, "SHA256") => "RS256",
        (PublicKeyKind.Rsa, "SHA384") => "RS384",
        (PublicKeyKind.Rsa, "SHA512") => "RS512",
        (PublicKeyKind.Ecdsa, "SHA256") => "ES256",
        (PublicKeyKind.Ecdsa, "SHA384") => "ES384",
        (PublicKeyKind.Ecdsa, "SHA512") => "ES512",
        _ => throw new NotSupportedException($"Azure Key Vault cannot sign a {hash.Name} digest with a {kind} key."),
    };
}
