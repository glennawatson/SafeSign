// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Google;

/// <summary>
/// Calls <c>cryptoKeyVersions.asymmetricSign</c> through <see cref="IGoogleCloudKmsApi"/>
/// (https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign).
/// </summary>
public static class GoogleKmsRequests
{
    /// <summary>Signs a digest.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <param name="token">The access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The signature (PKCS #1 v1.5 for RSA, DER for ECDSA).</returns>
    /// <exception cref="ProviderRequestException">The reply carried no signature.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<byte[]> SignAsync(
        RefitSettings http,
        GoogleCloudKmsOptions options,
        ReadOnlyMemory<byte> digest,
        HashAlgorithmName hash,
        string token,
        CancellationToken cancellationToken) =>
        SignAsync(http, options, digest, hash, token, TimeProvider.System, cancellationToken);

    /// <summary>Signs a digest with retry and exponential backoff.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="digest">The digest.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <param name="token">The access token.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The signature (PKCS #1 v1.5 for RSA, DER for ECDSA).</returns>
    /// <exception cref="ProviderRequestException">The reply carried no signature.</exception>
    public static async ValueTask<byte[]> SignAsync(
        RefitSettings http,
        GoogleCloudKmsOptions options,
        ReadOnlyMemory<byte> digest,
        HashAlgorithmName hash,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        var api = RestService.ForGenerated<IGoogleCloudKmsApi>(ProviderHttp.Authority(options.Endpoint), ProviderHttp.CreateSettings(GoogleJsonContext.Default, http));
        var keyVersionName = options.KeyVersionName.TrimStart('/');
        var path = $"v1/{keyVersionName}:asymmetricSign";
        GoogleKmsSignRequest body = new(Digest(digest.Span, hash));
        var authorization = ProviderHttp.Bearer(token);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.AsymmetricSignAsync(keyVersionName, authorization, body, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {options.Endpoint}{path}");
        return reply.Signature.IsEmpty ? throw new ProviderRequestException("Google Cloud KMS returned no signature.") : reply.Signature.ToArray();
    }

    /// <summary>Builds the <c>Digest</c> union for the hash algorithm.</summary>
    /// <param name="digest">The digest.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <returns>The digest object.</returns>
    /// <exception cref="NotSupportedException">The algorithm is not SHA-256, SHA-384, or SHA-512.</exception>
    public static GoogleKmsDigest Digest(ReadOnlySpan<byte> digest, HashAlgorithmName hash)
    {
        var encoded = Convert.ToBase64String(digest);
        return hash.Name switch
        {
            "SHA256" => new(encoded, null, null),
            "SHA384" => new(null, encoded, null),
            "SHA512" => new(null, null, encoded),
            _ => throw new NotSupportedException($"Google Cloud KMS cannot sign a {hash.Name} digest."),
        };
    }
}
