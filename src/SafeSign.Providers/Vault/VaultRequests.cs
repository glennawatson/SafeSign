// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Vault;

/// <summary>Executes HashiCorp Vault Transit signing requests via <see cref="IHashiCorpVaultApi"/> with retry and backoff.</summary>
public static class VaultRequests
{
    /// <summary>Creates a Refit <see cref="IHashiCorpVaultApi"/> client backed by <see cref="VaultJsonContext"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="baseAddress">The Vault server base address.</param>
    /// <returns>The Refit API client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IHashiCorpVaultApi CreateApi(RefitSettings http, Uri baseAddress) =>
        RestService.ForGenerated<IHashiCorpVaultApi>(
            ProviderHttp.Authority(baseAddress),
            ProviderHttp.CreateSettings(VaultJsonContext.Default, http));

    /// <summary>Signs a digest using the HashiCorp Vault Transit secret engine.</summary>
    /// <param name="api">The Vault Refit client.</param>
    /// <param name="options">The Vault configuration.</param>
    /// <param name="keyKind">The public key family.</param>
    /// <param name="request">The digest to sign.</param>
    /// <param name="clock">The clock used for retry backoff.</param>
    /// <param name="retry">The retry options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The raw signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Any reference argument is null.</exception>
    /// <exception cref="ProviderRequestException">The Vault Transit endpoint returned an error or omitted the signature.</exception>
    public static async Task<byte[]> SignAsync(
        IHashiCorpVaultApi api,
        HashiCorpVaultOptions options,
        PublicKeyKind keyKind,
        SignDigestRequest request,
        TimeProvider clock,
        ProviderRetryOptions retry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(retry);

        var hashSlug = MapHashAlgorithm(request.HashAlgorithm);
        var payload = new VaultSignRequest(
            Convert.ToBase64String(request.Digest.Span),
            Prehashed: true,
            SignatureAlgorithm: keyKind == PublicKeyKind.Rsa ? "pkcs1v15" : null,
            MarshalingAlgorithm: keyKind == PublicKeyKind.Ecdsa ? "asn1" : null);

        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(
                options.MountPath.Trim('/'),
                options.KeyName,
                hashSlug,
                options.Token,
                options.Namespace,
                payload,
                ct),
            retry,
            clock,
            cancellationToken).ConfigureAwait(false);
        var body = ProviderHttp.Unwrap(response, "HashiCorp Vault Transit sign");

        var signatureText = body.Data?.Signature;
        if (string.IsNullOrEmpty(signatureText))
        {
            throw new ProviderRequestException("HashiCorp Vault Transit sign response did not include a signature.");
        }

        var lastColon = signatureText.LastIndexOf(':');
        var base64Part = lastColon >= 0 ? signatureText[(lastColon + 1)..] : signatureText;
        return Convert.FromBase64String(base64Part);
    }

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to a Vault Transit hash algorithm slug.</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The Vault slug.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    private static string MapHashAlgorithm(HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            "SHA256" => "sha2-256",
            "SHA384" => "sha2-384",
            "SHA512" => "sha2-512",
            var name => throw new NotSupportedException($"HashiCorp Vault Transit does not support digest algorithm '{name}'."),
        };
}
