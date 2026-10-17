// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.DigiCert;

/// <summary>
/// Signs digests via DigiCert ONE / DigiCert KeyLocker (<c>/signingmanager/api/v1/certificates</c> and
/// <c>/signingmanager/api/v1/keypairs/{keypairId}/sign</c>) using <c>x-api-key</c> and mutual TLS.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class DigiCertKeyLockerProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The DigiCert KeyLocker options.</summary>
    private readonly DigiCertKeyLockerOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>The resolved keypair identifier.</summary>
    private string? _keypairId;

    /// <summary>The resolved account reference.</summary>
    private DigiCertAccountRef? _account;

    /// <summary>Initializes a new instance of the <see cref="DigiCertKeyLockerProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The DigiCert KeyLocker options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <exception cref="ProviderConfigurationException">Neither a certificate identifier/alias nor a keypair identifier with a local certificate was given.</exception>
    public DigiCertKeyLockerProvider(RefitSettings http, DigiCertKeyLockerOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.CertificateAlias is not { Length: > 0 }
            && options.CertificateId is not { Length: > 0 }
            && (options.KeypairId is not { Length: > 0 } || options.CertificateFile is not { Length: > 0 }))
        {
            throw new ProviderConfigurationException(
                "DigiCert KeyLocker requires 'cert-alias' or 'cert-id' (or both 'keypair-id' and 'cert-file').");
        }

        _http = http;
        _options = options;
        _time = time;
        _keypairId = options.KeypairId;
    }

    /// <inheritdoc/>
    public string Name => "digicert-keylocker";

    /// <summary>Maps a key family and hash algorithm to a DigiCert ONE JCA signature algorithm name.</summary>
    /// <param name="kind">The public key family.</param>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The JCA signature algorithm string.</returns>
    /// <exception cref="NotSupportedException">The combination is not supported.</exception>
    public static string Algorithm(PublicKeyKind kind, HashAlgorithmName hash) => (kind, hash.Name) switch
    {
        (PublicKeyKind.Rsa, "SHA256") => "SHA256withRSA",
        (PublicKeyKind.Rsa, "SHA384") => "SHA384withRSA",
        (PublicKeyKind.Rsa, "SHA512") => "SHA512withRSA",
        (PublicKeyKind.Ecdsa, "SHA256") => "SHA256withECDSA",
        (PublicKeyKind.Ecdsa, "SHA384") => "SHA384withECDSA",
        (PublicKeyKind.Ecdsa, "SHA512") => "SHA512withECDSA",
        _ => throw new NotSupportedException($"DigiCert KeyLocker cannot sign a {hash.Name} digest with a {kind} key."),
    };

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The certificate lookup returned no certificate or keypair identifier.</exception>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is not null)
        {
            return _certificate;
        }

        if (_options.CertificateFile is { Length: > 0 } localCert && _keypairId is { Length: > 0 })
        {
            return _certificate = CertificateFile.Load(localCert);
        }

        var api = CreateClient();
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetCertificatesAsync(_options.CertificateId, _options.CertificateAlias, _options.ApiKey, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"GET {_options.Endpoint}signingmanager/api/v1/certificates");
        if (reply.Items is not { Length: > 0 } items || items[0].Cert is not { Length: > 0 } certBase64)
        {
            throw new ProviderRequestException("DigiCert KeyLocker returned no matching active certificate.");
        }

        var item = items[0];
        _keypairId ??= item.Keypair?.Id ?? throw new ProviderRequestException("DigiCert KeyLocker certificate entry had no keypair id.");
        _account = item.Account is { Id.Length: > 0 } acct ? new DigiCertAccountRef(acct.Id, null) : null;
        return _certificate = BuildSigningCertificate(certBase64, item.Chain);
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The signing request returned no signature.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var api = CreateClient();
        DigiCertSignPayload payload = new(_account, Algorithm(kind, request.HashAlgorithm), Convert.ToBase64String(request.Digest.Span));
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(_keypairId!, _options.ApiKey, payload, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}signingmanager/api/v1/keypairs/{_keypairId}/sign");
        return reply.Signature is { Length: > 0 } sigBase64
            ? Convert.FromBase64String(sigBase64)
            : throw new ProviderRequestException("DigiCert KeyLocker returned no signature.");
    }

    /// <summary>Builds a <see cref="SigningCertificate"/> from the Base64 leaf and chain items.</summary>
    /// <param name="leafBase64">The Base64-encoded DER leaf certificate.</param>
    /// <param name="chainItems">The optional issuer chain items.</param>
    /// <returns>The arranged <see cref="SigningCertificate"/>.</returns>
    private static SigningCertificate BuildSigningCertificate(string leafBase64, DigiCertChainItem[]? chainItems)
    {
        var leaf = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(leafBase64));
        if (chainItems is not { Length: > 0 })
        {
            return new(leaf, []);
        }

        List<X509Certificate2> all = [leaf];
        for (var i = 0; i < chainItems.Length; i++)
        {
            if (chainItems[i].Blob is { Length: > 0 } blob)
            {
                all.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(blob)));
            }
        }

        return new(leaf, CertificateChainOrder.IssuersOf(all, leaf));
    }

    /// <summary>Creates a source-generated Refit client for <see cref="IDigiCertKeyLockerApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private IDigiCertKeyLockerApi CreateClient() =>
        RestService.ForGenerated<IDigiCertKeyLockerApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(
                DigiCertJsonContext.Default,
                _http,
                _options.ClientCertificateFile,
                _options.ClientCertificatePassword));
}
