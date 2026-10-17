// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.Certum;
using SafeSign.Providers.Shared;
using SafeSign.Providers.SignPath;
using SafeSign.Signing;

namespace SafeSign.Providers.Csc;

/// <summary>
/// Signs digests via any Cloud Signature Consortium (CSC) v1 compliant Remote Signing Service Provider (RSSP),
/// including Entrust Signing Automation Service, Sectigo, GlobalSign, SwissSign, and CertEurope.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class CscProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The CSC options.</summary>
    private readonly CscOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="CscProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The CSC options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    public CscProvider(RefitSettings http, CscOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "csc";

    /// <summary>Maps a key family and hash algorithm to the CSC <c>signAlgo</c> OID.</summary>
    /// <param name="kind">The public key family.</param>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The signature algorithm OID.</returns>
    /// <exception cref="NotSupportedException">The combination is not supported.</exception>
    public static string SignAlgoOid(PublicKeyKind kind, HashAlgorithmName hash) => (kind, hash.Name) switch
    {
        (PublicKeyKind.Rsa, "SHA256") => "1.2.840.113549.1.1.11",
        (PublicKeyKind.Rsa, "SHA384") => "1.2.840.113549.1.1.12",
        (PublicKeyKind.Rsa, "SHA512") => "1.2.840.113549.1.1.13",
        (PublicKeyKind.Ecdsa, "SHA256") => "1.2.840.10045.4.3.2",
        (PublicKeyKind.Ecdsa, "SHA384") => "1.2.840.10045.4.3.3",
        (PublicKeyKind.Ecdsa, "SHA512") => "1.2.840.10045.4.3.4",
        _ => throw new NotSupportedException($"CSC does not support {kind} with digest '{hash.Name}'."),
    };

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The CSC <c>credentials/info</c> endpoint returned no certificates.</exception>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is not null)
        {
            return _certificate;
        }

        if (_options.CertificateFile is { Length: > 0 } certPath)
        {
            return _certificate = CertificateFile.Load(certPath);
        }

        var api = CreateClient();
        var path = CombinePath("credentials/info");
        CscCredentialsInfoRequest request = new(_options.CredentialId, "chain");
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetCredentialsInfoAsync(path, ProviderHttp.Bearer(_options.AccessToken), request, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}/{path}");
        if (reply.Cert?.Certificates is not { Length: > 0 } certStrings)
        {
            throw new ProviderRequestException($"CSC service returned no certificates for credential '{_options.CredentialId}'.");
        }

        List<X509Certificate2> certs = [with(capacity: certStrings.Length)];
        for (var i = 0; i < certStrings.Length; i++)
        {
            certs.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certStrings[i])));
        }

        var leaf = certs[0];
        return _certificate = new(leaf, CertificateChainOrder.IssuersOf(certs, leaf));
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The CSC <c>credentials/authorize</c> or <c>signatures/signHash</c> call failed.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var hashBase64 = Convert.ToBase64String(request.Digest.Span);
        var auth = ProviderHttp.Bearer(_options.AccessToken);
        var api = CreateClient();

        var sad = _options.Sad;
        if (sad is not { Length: > 0 })
        {
            var authPath = CombinePath("credentials/authorize");
            CscAuthorizeRequest authRequest = new(_options.CredentialId, 1, [hashBase64], _options.Pin, ResolveOtp());
            using var authResponse = await ProviderRetry.ExecuteAsync(
                ct => api.AuthorizeAsync(authPath, auth, authRequest, ct),
                _time,
                cancellationToken).ConfigureAwait(false);
            var authReply = ProviderHttp.Unwrap(authResponse, $"POST {_options.Endpoint}/{authPath}");
            sad = authReply.Sad is { Length: > 0 } sadValue
                ? sadValue
                : throw new ProviderRequestException("CSC credentials/authorize returned no SAD token.");
        }

        var signPath = CombinePath("signatures/signHash");
        CscSignHashRequest signRequest = new(
            _options.CredentialId,
            sad,
            [hashBase64],
            SignPathProvider.HashOid(request.HashAlgorithm),
            SignAlgoOid(kind, request.HashAlgorithm));
        using var signResponse = await ProviderRetry.ExecuteAsync(
            ct => api.SignHashAsync(signPath, auth, signRequest, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var signReply = ProviderHttp.Unwrap(signResponse, $"POST {_options.Endpoint}/{signPath}");
        return signReply.Signatures is [var firstSig, ..] && firstSig.Length > 0
            ? Convert.FromBase64String(firstSig)
            : throw new ProviderRequestException("CSC signatures/signHash returned no signature.");
    }

    /// <summary>Resolves the optional OTP code from <see cref="CscOptions.TotpSecret"/> or <see cref="CscOptions.Otp"/>.</summary>
    /// <returns>The OTP string, or <see langword="null"/> when neither is configured.</returns>
    private string? ResolveOtp()
    {
        if (_options.TotpSecret is { Length: > 0 } secret)
        {
            return CertumTotp.Parse(secret, CertumTotpAlgorithm.Sha1).GenerateCode(_time.GetUtcNow());
        }

        if (_options.Otp is { Length: > 0 } otp)
        {
            return otp.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
                ? CertumTotp.Parse(otp, CertumTotpAlgorithm.Sha1).GenerateCode(_time.GetUtcNow())
                : otp;
        }

        return null;
    }

    /// <summary>Combines the base path of <see cref="CscOptions.Endpoint"/> with a relative route.</summary>
    /// <param name="route">The relative route.</param>
    /// <returns>The combined relative path without a leading slash.</returns>
    private string CombinePath(string route)
    {
        var basePath = _options.Endpoint.AbsolutePath.Trim('/');
        return basePath.Length > 0 ? $"{basePath}/{route}" : route;
    }

    /// <summary>Creates a source-generated Refit client for <see cref="ICscApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ICscApi CreateClient() =>
        RestService.ForGenerated<ICscApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(CscJsonContext.Default, _http));
}
