// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>Calls the Azure Artifact Signing data plane through <see cref="IAzureArtifactSigningApi"/> (<c>GetSignCertificateChain</c>, <c>StartSign</c>, and <c>GetSignStatus</c>).</summary>
public static class AzureArtifactSigningRequests
{
    /// <summary>Gets the Azure Artifact Signing REST API version.</summary>
    public static string ApiVersion => "2022-06-15-preview";

    /// <summary>Gets the Entra ID OAuth 2.0 token scope for Azure Artifact Signing.</summary>
    public static string Scope => "https://codesigning.azure.net/.default";

    /// <summary>Fetches and orders the PKCS #7 certificate chain for the configured certificate profile.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Azure Artifact Signing options.</param>
    /// <param name="token">The access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The ordered leaf certificate and issuer chain.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<SigningCertificate> GetCertificateChainAsync(
        RefitSettings http,
        AzureArtifactSigningOptions options,
        string token,
        CancellationToken cancellationToken) =>
        GetCertificateChainAsync(http, options, token, TimeProvider.System, cancellationToken);

    /// <summary>Fetches and orders the PKCS #7 certificate chain with retry and exponential backoff.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Azure Artifact Signing options.</param>
    /// <param name="token">The access token.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The ordered leaf certificate and issuer chain.</returns>
    /// <exception cref="ProviderRequestException">The certificate chain request failed or returned no certificates.</exception>
    public static async ValueTask<SigningCertificate> GetCertificateChainAsync(
        RefitSettings http,
        AzureArtifactSigningOptions options,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        var api = RestService.ForGenerated<IAzureArtifactSigningApi>(
            ProviderHttp.Authority(options.Endpoint),
            ProviderHttp.CreateSettings(AzureArtifactSigningJsonContext.Default, http));
        var authorization = ProviderHttp.Bearer(token);
        using var response = await ProviderRetry.ExecuteHttpAsync(
            ct => api.GetCertificateChainAsync(options.AccountName, options.CertificateProfileName, ApiVersion, authorization, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        var operation = $"GET {options.Endpoint}codesigningaccounts/{options.AccountName}/certificateprofiles/{options.CertificateProfileName}/sign/certchain";
        var raw = await ProviderHttp.ReadBytesAsync(response, operation, cancellationToken).ConfigureAwait(false);
        if (raw.Length == 0)
        {
            throw new ProviderRequestException($"{operation} returned an empty certificate chain.");
        }

        var certificates = CertificateFile.Read(raw);
        return CertificateChainOrder.Arrange(certificates, $"{options.AccountName}/{options.CertificateProfileName}");
    }

    /// <summary>Submits a digest signing operation and polls until completion.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Azure Artifact Signing options.</param>
    /// <param name="kind">The public key family of the signing certificate.</param>
    /// <param name="request">The digest signing request.</param>
    /// <param name="token">The access token.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The PKCS #1 v1.5 RSA or DER ECDSA signature bytes.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<byte[]> SignAsync(
        RefitSettings http,
        AzureArtifactSigningOptions options,
        PublicKeyKind kind,
        SignDigestRequest request,
        string token,
        CancellationToken cancellationToken) =>
        SignAsync(http, options, kind, request, token, TimeProvider.System, cancellationToken);

    /// <summary>Submits a digest signing operation and polls until completion with retry and exponential backoff.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Azure Artifact Signing options.</param>
    /// <param name="kind">The public key family of the signing certificate.</param>
    /// <param name="request">The digest signing request.</param>
    /// <param name="token">The access token.</param>
    /// <param name="time">The clock used for retry delays and polling timeouts.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The PKCS #1 v1.5 RSA or DER ECDSA signature bytes.</returns>
    /// <exception cref="ProviderRequestException">The signing operation failed, timed out, or returned no signature.</exception>
    public static async ValueTask<byte[]> SignAsync(
        RefitSettings http,
        AzureArtifactSigningOptions options,
        PublicKeyKind kind,
        SignDigestRequest request,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        var api = RestService.ForGenerated<IAzureArtifactSigningApi>(
            ProviderHttp.Authority(options.Endpoint),
            ProviderHttp.CreateSettings(AzureArtifactSigningJsonContext.Default, http));
        var authorization = ProviderHttp.Bearer(token);
        AzureArtifactSignPayload payload = new(Algorithm(kind, request.HashAlgorithm), Convert.ToBase64String(request.Digest.Span));
        using var startResponse = await ProviderRetry.ExecuteAsync(
            ct => api.StartSignAsync(options.AccountName, options.CertificateProfileName, ApiVersion, authorization, payload, ct),
            time,
            cancellationToken).ConfigureAwait(false);
        var startOp = $"POST {options.Endpoint}codesigningaccounts/{options.AccountName}/certificateprofiles/{options.CertificateProfileName}/sign";
        var status = ProviderHttp.Unwrap(startResponse, startOp);
        var retryHint = ProviderRetry.TryGetRetryAfter(startResponse.Headers, time.GetUtcNow());
        var completed = await PollUntilCompletedAsync(api, options, authorization, status, retryHint, time, cancellationToken).ConfigureAwait(false);
        if (completed.Signature is not { Length: > 0 })
        {
            throw new ProviderRequestException("Azure Artifact Signing completed without returning a signature.");
        }

        var signature = Convert.FromBase64String(completed.Signature);
        return kind == PublicKeyKind.Ecdsa ? EcdsaSignatureEncoding.IeeeP1363ToDer(signature) : signature;
    }

    /// <summary>Maps the key family and digest algorithm to an Azure Artifact Signing signature algorithm identifier.</summary>
    /// <param name="kind">The key family.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <returns>The signature algorithm name (<c>RS256</c>, <c>RS384</c>, <c>RS512</c>, <c>ES256</c>, <c>ES384</c>, or <c>ES512</c>).</returns>
    /// <exception cref="NotSupportedException">The combination is not supported.</exception>
    public static string Algorithm(PublicKeyKind kind, HashAlgorithmName hash) => (kind, hash.Name) switch
    {
        (PublicKeyKind.Rsa, "SHA256") => "RS256",
        (PublicKeyKind.Rsa, "SHA384") => "RS384",
        (PublicKeyKind.Rsa, "SHA512") => "RS512",
        (PublicKeyKind.Ecdsa, "SHA256") => "ES256",
        (PublicKeyKind.Ecdsa, "SHA384") => "ES384",
        (PublicKeyKind.Ecdsa, "SHA512") => "ES512",
        _ => throw new NotSupportedException($"Azure Artifact Signing cannot sign a {hash.Name} digest with a {kind} key."),
    };

    /// <summary>Polls <see cref="IAzureArtifactSigningApi.GetSignStatusAsync"/> until the signing operation reaches a terminal state.</summary>
    /// <param name="api">The Refit API client.</param>
    /// <param name="options">The provider options.</param>
    /// <param name="authorization">The bearer authorization header.</param>
    /// <param name="initial">The initial status returned by <c>StartSign</c>.</param>
    /// <param name="initialHint">An optional <c>Retry-After</c> header delay from the <c>StartSign</c> response.</param>
    /// <param name="time">The clock used for delays and timeout tracking.</param>
    /// <param name="cancellationToken">Cancels the polling loop.</param>
    /// <returns>The succeeded <see cref="AzureArtifactSignStatus"/>.</returns>
    /// <exception cref="ProviderRequestException">The signing operation failed or exceeded <see cref="AzureArtifactSigningOptions.PollTimeout"/>.</exception>
    private static async ValueTask<AzureArtifactSignStatus> PollUntilCompletedAsync(
        IAzureArtifactSigningApi api,
        AzureArtifactSigningOptions options,
        string authorization,
        AzureArtifactSignStatus initial,
        TimeSpan? initialHint,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var current = initial;
        var hint = initialHint;
        var deadline = time.GetUtcNow() + options.PollTimeout;
        var maxPollDelay = options.PollTimeout > options.PollInterval ? options.PollTimeout : options.PollInterval;
        var pollRetryOptions = ProviderRetryOptions.Default with { InitialDelay = options.PollInterval, MaxDelay = maxPollDelay };

        while (!string.Equals(current.Status, "Succeeded", StringComparison.OrdinalIgnoreCase))
        {
            if (IsTerminalFailure(current.Status))
            {
                throw new ProviderRequestException(
                    $"Azure Artifact Signing operation '{current.OperationId}' ended with status '{current.Status}'.");
            }

            if (current.OperationId is not { Length: > 0 } operationId)
            {
                throw new ProviderRequestException("Azure Artifact Signing returned a non-terminal status without an operationId.");
            }

            if (time.GetUtcNow() >= deadline)
            {
                throw new ProviderRequestException(
                    $"Azure Artifact Signing operation '{operationId}' timed out after {options.PollTimeout}.");
            }

            var delay = ProviderRetry.ComputePollDelay(pollRetryOptions, hint ?? options.PollInterval);
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, time, cancellationToken).ConfigureAwait(false);
            }

            using var pollResponse = await ProviderRetry.ExecuteAsync(
                ct => api.GetSignStatusAsync(options.AccountName, options.CertificateProfileName, operationId, ApiVersion, authorization, ct),
                time,
                cancellationToken).ConfigureAwait(false);
            var pollOp = $"GET {options.Endpoint}codesigningaccounts/{options.AccountName}/certificateprofiles/{options.CertificateProfileName}/sign/{operationId}";
            current = ProviderHttp.Unwrap(pollResponse, pollOp);
            hint = ProviderRetry.TryGetRetryAfter(pollResponse.Headers, time.GetUtcNow());
        }

        return current;
    }

    /// <summary>Determines whether an Azure Artifact Signing status string represents a terminal failure.</summary>
    /// <param name="status">The status string.</param>
    /// <returns>True for <c>Failed</c>, <c>Canceled</c>, <c>Cancelled</c>, or <c>TimedOut</c>.</returns>
    private static bool IsTerminalFailure(string? status) =>
        string.Equals(status, "Failed", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "Canceled", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "Cancelled", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "TimedOut", StringComparison.OrdinalIgnoreCase);
}
