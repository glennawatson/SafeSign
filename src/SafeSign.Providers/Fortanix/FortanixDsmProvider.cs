// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Fortanix;

/// <summary>Signs digests via Fortanix Data Security Manager (DSM) (<c>POST /sys/v1/session/auth</c> and <c>POST /crypto/v1/sign</c>).</summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class FortanixDsmProvider : ISigningProvider
{
    /// <summary>An empty dictionary used to serialize <c>{"PKCS1_V15":{}}</c>.</summary>
    private static readonly Dictionary<string, string> EmptyMode = [with(comparer: StringComparer.Ordinal)];

    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Fortanix DSM options.</summary>
    private readonly FortanixDsmOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>The cached session access token.</summary>
    private string? _accessToken;

    /// <summary>Initializes a new instance of the <see cref="FortanixDsmProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Fortanix DSM options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <exception cref="ProviderConfigurationException">Neither an API key nor an access token was provided.</exception>
    public FortanixDsmProvider(RefitSettings http, FortanixDsmOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.ApiKey is not { Length: > 0 } && options.AccessToken is not { Length: > 0 })
        {
            throw new ProviderConfigurationException(
                "Fortanix DSM requires 'api-key' (FORTANIX_API_KEY) or 'access-token' (FORTANIX_ACCESS_TOKEN).");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "fortanix-dsm";

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to a Fortanix DSM <c>hash_alg</c> value.</summary>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The Fortanix DSM hash algorithm name.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    public static string HashAlg(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => "SHA256",
        "SHA384" => "SHA384",
        "SHA512" => "SHA512",
        _ => throw new NotSupportedException($"Fortanix DSM does not support digest algorithm '{hash.Name}'."),
    };

    /// <inheritdoc/>
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new(_certificate ??= CertificateFile.Load(_options.CertificateFile));
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The signing request failed or returned no signature.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var api = CreateClient();

        FortanixSignPayload payload = new(
            new(_options.KeyId),
            HashAlg(request.HashAlgorithm),
            Convert.ToBase64String(request.Digest.Span),
            kind == PublicKeyKind.Rsa ? new FortanixRsaMode(EmptyMode) : null);

        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(ProviderHttp.Bearer(token), payload, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}crypto/v1/sign");
        return reply.Signature is { Length: > 0 } sigBase64
            ? Convert.FromBase64String(sigBase64)
            : throw new ProviderRequestException("Fortanix DSM returned no signature.");
    }

    /// <summary>Returns the configured or freshly authenticated Fortanix DSM bearer token.</summary>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The bearer token.</returns>
    /// <exception cref="ProviderRequestException">Session authentication returned no token.</exception>
    private async ValueTask<string> TokenAsync(CancellationToken cancellationToken)
    {
        if (_options.AccessToken is { Length: > 0 } fixedToken)
        {
            return fixedToken;
        }

        if (_accessToken is { Length: > 0 })
        {
            return _accessToken;
        }

        var api = CreateClient();
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.AuthenticateAsync($"Basic {_options.ApiKey}", ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}sys/v1/session/auth");
        return reply.AccessToken is { Length: > 0 } token
            ? (_accessToken = token)
            : throw new ProviderRequestException("Fortanix DSM session authentication returned no access token.");
    }

    /// <summary>Creates a source-generated Refit client for <see cref="IFortanixDsmApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private IFortanixDsmApi CreateClient() =>
        RestService.ForGenerated<IFortanixDsmApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(FortanixJsonContext.Default, _http));
}
