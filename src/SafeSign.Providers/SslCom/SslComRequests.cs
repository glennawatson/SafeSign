// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Certum;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.SslCom;

/// <summary>Executes SSL.com eSigner CSC signing requests via <see cref="ISslComESignerApi"/> with retry and backoff.</summary>
public static class SslComRequests
{
    /// <summary>Gets the default SSL.com eSigner CSC base URI.</summary>
    public static Uri DefaultBaseUri { get; } = new("https://ds.ssl.com");

    /// <summary>Gets the default SSL.com OAuth 2.0 token endpoint URI.</summary>
    public static Uri DefaultOAuthTokenUri { get; } = new("https://login.ssl.com/oauth2/token");

    /// <summary>Creates a Refit <see cref="ISslComESignerApi"/> client backed by <see cref="SslComJsonContext"/>.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="baseAddress">The CSC endpoint base URI.</param>
    /// <returns>The Refit API client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ISslComESignerApi CreateApi(RefitSettings http, Uri baseAddress) =>
        RestService.ForGenerated<ISslComESignerApi>(
            ProviderHttp.Authority(baseAddress),
            ProviderHttp.CreateSettings(SslComJsonContext.Default, http));

    /// <summary>Signs a digest using the SSL.com eSigner CSC <c>signHash</c> endpoint.</summary>
    /// <param name="api">The SSL.com CSC Refit client.</param>
    /// <param name="options">The SSL.com eSigner options.</param>
    /// <param name="bearerToken">The active OAuth 2.0 Bearer token.</param>
    /// <param name="keyKind">The public key family.</param>
    /// <param name="request">The digest to sign.</param>
    /// <param name="execution">The clock and retry policy.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The raw signature bytes.</returns>
    /// <exception cref="ArgumentNullException">Any reference argument is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="bearerToken"/> is null or empty.</exception>
    /// <exception cref="ProviderRequestException">The CSC endpoint returned an error or omitted the signature.</exception>
    public static async Task<byte[]> SignAsync(
        ISslComESignerApi api,
        SslComESignerOptions options,
        string bearerToken,
        PublicKeyKind keyKind,
        SignDigestRequest request,
        (TimeProvider Clock, ProviderRetryOptions Retry) execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(api);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(bearerToken);
        ArgumentNullException.ThrowIfNull(execution.Clock);
        ArgumentNullException.ThrowIfNull(execution.Retry);

        var signAlgoOid = MapSignAlgoOid(keyKind, request.HashAlgorithm);
        var sad = ResolveSad(options, execution.Clock);
        var payload = new SslComSignHashRequest(
            options.CredentialId,
            sad,
            [Convert.ToBase64String(request.Digest.Span)],
            signAlgoOid);

        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignHashAsync(ProviderHttp.Bearer(bearerToken), payload, ct),
            execution.Retry,
            execution.Clock,
            cancellationToken).ConfigureAwait(false);
        var body = ProviderHttp.Unwrap(response, "SSL.com eSigner CSC signHash");

        return body.Signatures is not [var firstSignature, ..] || string.IsNullOrEmpty(firstSignature)
            ? throw new ProviderRequestException("SSL.com eSigner CSC signHash response did not include a signature.")
            : Convert.FromBase64String(firstSignature);
    }

    /// <summary>Resolves the Signature Activation Data (SAD) or one-time password from <paramref name="options"/>.</summary>
    /// <param name="options">The SSL.com options.</param>
    /// <param name="clock">The clock used for TOTP generation.</param>
    /// <returns>The SAD / OTP string.</returns>
    /// <exception cref="ProviderConfigurationException">Neither <c>otp</c> nor <c>totp-secret</c> is configured.</exception>
    private static string ResolveSad(SslComESignerOptions options, TimeProvider clock)
    {
        if (options.Otp is { Length: > 0 } otp)
        {
            return otp.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
                ? CertumTotp.Parse(otp, CertumTotpAlgorithm.Sha1).GenerateCode(clock.GetUtcNow())
                : otp;
        }

        return options.TotpSecret is { Length: > 0 } secret
            ? CertumTotp.Parse(secret, CertumTotpAlgorithm.Sha1).GenerateCode(clock.GetUtcNow())
            : throw new ProviderConfigurationException(
                "SSL.com eSigner requires '--provider-option totp-secret=<base32|otpauth>' or '--provider-option otp=<code>'.");
    }

    /// <summary>Maps a key kind and hash algorithm to the CSC <c>signAlgo</c> OID.</summary>
    /// <param name="keyKind">The key family.</param>
    /// <param name="hashAlgorithm">The digest algorithm.</param>
    /// <returns>The signature algorithm OID.</returns>
    /// <exception cref="NotSupportedException">The key kind and hash algorithm combination is not supported.</exception>
    private static string MapSignAlgoOid(PublicKeyKind keyKind, HashAlgorithmName hashAlgorithm) =>
        (keyKind, hashAlgorithm.Name) switch
        {
            (PublicKeyKind.Rsa, "SHA256") => "1.2.840.113549.1.1.11",
            (PublicKeyKind.Rsa, "SHA384") => "1.2.840.113549.1.1.12",
            (PublicKeyKind.Rsa, "SHA512") => "1.2.840.113549.1.1.13",
            (PublicKeyKind.Ecdsa, "SHA256") => "1.2.840.10045.4.3.2",
            (PublicKeyKind.Ecdsa, "SHA384") => "1.2.840.10045.4.3.3",
            (PublicKeyKind.Ecdsa, "SHA512") => "1.2.840.10045.4.3.4",
            (_, var name) => throw new NotSupportedException($"SSL.com eSigner does not support {keyKind} with digest '{name}'."),
        };
}
