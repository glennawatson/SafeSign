// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.SignServer;

/// <summary>Executes Keyfactor SignServer REST signing requests via <see cref="IKeyfactorSignServerApi"/> with retry and backoff.</summary>
public static class SignServerRequests
{
    /// <summary>Creates a Refit <see cref="IKeyfactorSignServerApi"/> client backed by <see cref="SignServerJsonContext"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="baseAddress">The SignServer base address.</param>
    /// <returns>The Refit API client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IKeyfactorSignServerApi CreateApi(RefitSettings http, Uri baseAddress) =>
        RestService.ForGenerated<IKeyfactorSignServerApi>(
            ProviderHttp.Authority(baseAddress),
            ProviderHttp.CreateSettings(SignServerJsonContext.Default, http));

    /// <summary>Signs a digest using Keyfactor SignServer REST v1.</summary>
    /// <param name="api">The SignServer Refit client.</param>
    /// <param name="options">The SignServer options.</param>
    /// <param name="request">The digest to sign.</param>
    /// <param name="clock">The clock used for retry backoff.</param>
    /// <param name="retry">The retry options.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The raw signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Any reference argument is null.</exception>
    /// <exception cref="ProviderRequestException">SignServer returned an error or omitted the signature.</exception>
    public static async Task<byte[]> SignAsync(
        IKeyfactorSignServerApi api,
        KeyfactorSignServerOptions options,
        SignDigestRequest request,
        TimeProvider clock,
        ProviderRetryOptions retry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(retry);

        var digestAlg = MapDigestAlgorithm(request.HashAlgorithm);
        var payload = new SignServerSignRequest(
            Convert.ToBase64String(request.Digest.Span),
            "BASE64",
            new("true", digestAlg));
        var auth = options.BearerToken is { Length: > 0 } token ? ProviderHttp.Bearer(token) : null;

        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.ProcessAsync(options.Worker, auth, payload, ct),
            retry,
            clock,
            cancellationToken).ConfigureAwait(false);
        var body = ProviderHttp.Unwrap(response, "Keyfactor SignServer process");

        var data = body.Data;
        return string.IsNullOrEmpty(data)
            ? throw new ProviderRequestException("Keyfactor SignServer process response did not include signature data.")
            : Convert.FromBase64String(data);
    }

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to a SignServer digest algorithm name.</summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The SignServer algorithm string.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    private static string MapDigestAlgorithm(HashAlgorithmName algorithm) =>
        algorithm.Name switch
        {
            "SHA256" => "SHA-256",
            "SHA384" => "SHA-384",
            "SHA512" => "SHA-512",
            var name => throw new NotSupportedException($"Keyfactor SignServer does not support digest algorithm '{name}'."),
        };
}
