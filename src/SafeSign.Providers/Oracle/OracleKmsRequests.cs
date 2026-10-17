// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Oracle;

/// <summary>Executes Oracle Cloud KMS cryptographic signing requests via <see cref="IOracleCloudKmsApi"/> with retry and backoff.</summary>
public static class OracleKmsRequests
{
    /// <summary>The OCI KMS sign endpoint path.</summary>
    private const string SignPath = "/20180608/sign";

    /// <summary>Creates a Refit <see cref="IOracleCloudKmsApi"/> client backed by <see cref="OracleJsonContext"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="baseAddress">The OCI KMS cryptographic endpoint URI.</param>
    /// <returns>The Refit API client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IOracleCloudKmsApi CreateApi(RefitSettings http, Uri baseAddress) =>
        RestService.ForGenerated<IOracleCloudKmsApi>(
            ProviderHttp.Authority(baseAddress),
            ProviderHttp.CreateSettings(OracleJsonContext.Default, http));

    /// <summary>Signs a digest using Oracle Cloud KMS <c>POST /20180608/sign</c>.</summary>
    /// <param name="api">The OCI KMS Refit client.</param>
    /// <param name="options">The OCI KMS options.</param>
    /// <param name="keyKind">The public key family.</param>
    /// <param name="request">The digest to sign.</param>
    /// <param name="clock">The clock used for HTTP signature timestamps and retry backoff.</param>
    /// <param name="retry">The retry options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The raw signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Any reference argument is null.</exception>
    /// <exception cref="ProviderRequestException">OCI KMS returned an error or omitted the signature.</exception>
    public static async Task<byte[]> SignAsync(
        IOracleCloudKmsApi api,
        OracleCloudKmsOptions options,
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

        var signingAlgorithm = MapAlgorithm(keyKind, request.HashAlgorithm);
        var payload = new OracleKmsSignRequest(
            options.KeyId,
            options.KeyVersionId,
            Convert.ToBase64String(request.Digest.Span),
            "DIGEST",
            signingAlgorithm);
        var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(payload, OracleJsonContext.Default.OracleKmsSignRequest);

        using var response = await ProviderRetry.ExecuteAsync(
            async ct =>
            {
                var headers = OracleHttpSignature.SignPost(
                    options,
                    SignPath,
                    bodyBytes,
                    clock.GetUtcNow());
                using var content = ProviderHttp.Bytes(bodyBytes, "application/json");
                content.Headers.ContentLength = bodyBytes.Length;
                return await api.SignAsync(headers.DateHeader, headers.ContentSha256Base64, headers.AuthorizationHeader, content, ct).ConfigureAwait(false);
            },
            retry,
            clock,
            cancellationToken).ConfigureAwait(false);
        var body = ProviderHttp.Unwrap(response, "Oracle Cloud KMS sign");

        var signature = body.Signature;
        return string.IsNullOrEmpty(signature)
            ? throw new ProviderRequestException("Oracle Cloud KMS sign response did not include a signature.")
            : Convert.FromBase64String(signature);
    }

    /// <summary>Maps a key kind and hash algorithm to an OCI KMS <c>signingAlgorithm</c> string.</summary>
    /// <param name="keyKind">The key family.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The OCI signing algorithm identifier.</returns>
    /// <exception cref="NotSupportedException">The key kind and hash algorithm combination is not supported.</exception>
    private static string MapAlgorithm(PublicKeyKind keyKind, HashAlgorithmName hashAlgorithm) =>
        new ProviderSignatureAlgorithm(keyKind, hashAlgorithm.Name) switch
        {
            (PublicKeyKind.Rsa, "SHA256") => "SHA_256_RSA_PKCS_V1_5",
            (PublicKeyKind.Rsa, "SHA384") => "SHA_384_RSA_PKCS_V1_5",
            (PublicKeyKind.Rsa, "SHA512") => "SHA_512_RSA_PKCS_V1_5",
            (PublicKeyKind.Ecdsa, "SHA256") => "ECDSA_SHA_256",
            (PublicKeyKind.Ecdsa, "SHA384") => "ECDSA_SHA_384",
            (PublicKeyKind.Ecdsa, "SHA512") => "ECDSA_SHA_512",
            (_, var name) => throw new NotSupportedException($"Oracle Cloud KMS does not support {keyKind} with digest '{name}'."),
        };
}
