// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Venafi;

/// <summary>
/// Signs digests via Venafi CodeSign Protect (<c>POST /vedauth/authorize/oauth</c>,
/// <c>POST /vedhsm/api/getobjects</c>, and <c>POST /vedhsm/api/sign</c>).
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class VenafiProvider : ISigningProvider
{
    /// <summary>The PKCS #11 mechanism constant for <c>CKM_RSA_PKCS</c>.</summary>
    private const int CkmRsaPkcs = 1;

    /// <summary>The PKCS #11 mechanism constant for <c>CKM_ECDSA</c>.</summary>
    private const int CkmEcdsa = 4161;

    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The Venafi options.</summary>
    private readonly VenafiOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>The resolved HSM KeyId.</summary>
    private string? _keyId;

    /// <summary>The cached OAuth access token.</summary>
    private string? _accessToken;

    /// <summary>Initializes a new instance of the <see cref="VenafiProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Venafi options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <exception cref="ProviderConfigurationException">Neither an access token nor username/password credentials were provided.</exception>
    public VenafiProvider(RefitSettings http, VenafiOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.AccessToken is not { Length: > 0 }
            && (options.Username is not { Length: > 0 } || options.Password is not { Length: > 0 }))
        {
            throw new ProviderConfigurationException(
                "Venafi CodeSign Protect requires 'access-token' (VENAFI_ACCESS_TOKEN) or both 'username' and 'password'.");
        }

        _http = http;
        _options = options;
        _time = time;
        _keyId = options.KeyId;
    }

    /// <inheritdoc/>
    public string Name => "venafi-codesign";

    /// <summary>Encodes a hash digest into an RFC 8017 §9.2 ASN.1 DER <c>DigestInfo</c> structure for <c>CKM_RSA_PKCS</c>.</summary>
    /// <param name="digest">The hash digest bytes.</param>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The DER-encoded <c>DigestInfo</c> bytes.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    public static byte[] EncodeRsaDigestInfo(ReadOnlySpan<byte> digest, HashAlgorithmName hash)
    {
        var prefix = hash.Name switch
        {
            "SHA256" => [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            "SHA384" => [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            "SHA512" => (ReadOnlySpan<byte>)[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
            _ => throw new NotSupportedException($"Venafi CodeSign Protect does not support digest algorithm '{hash.Name}'."),
        };

        var result = new byte[prefix.Length + digest.Length];
        prefix.CopyTo(result);
        digest.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">Venafi <c>getobjects</c> returned no certificates or KeyId.</exception>
    public async ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is not null)
        {
            return _certificate;
        }

        if (_options.CertificateFile is { Length: > 0 } certPath && _keyId is { Length: > 0 })
        {
            return _certificate = CertificateFile.Load(certPath);
        }

        await LoadObjectsAsync(cancellationToken).ConfigureAwait(false);
        return _certificate!;
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">Venafi <c>sign</c> failed or returned no signature.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        if (_keyId is not { Length: > 0 })
        {
            await LoadObjectsAsync(cancellationToken).ConfigureAwait(false);
        }

        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var dataToSign = kind == PublicKeyKind.Rsa
            ? EncodeRsaDigestInfo(request.Digest.Span, request.HashAlgorithm)
            : request.Digest.ToArray();

        VenafiSignRequest signRequest = new(
            _keyId!,
            kind == PublicKeyKind.Rsa ? CkmRsaPkcs : CkmEcdsa,
            Convert.ToBase64String(dataToSign));
        var api = CreateClient();
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(ProviderHttp.Bearer(token), signRequest, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}vedhsm/api/sign");
        if (!reply.Success || reply.ResultData is not { Length: > 0 } sigBase64)
        {
            throw new ProviderRequestException("Venafi CodeSign Protect returned no signature.");
        }

        var rawSignature = Convert.FromBase64String(sigBase64);
        return kind == PublicKeyKind.Ecdsa
            ? EcdsaSignatureEncoding.IeeeP1363ToDer(rawSignature)
            : rawSignature;
    }

    /// <summary>Loads the certificate chain and HSM KeyId from <c>POST /vedhsm/api/getobjects</c>.</summary>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ProviderRequestException">Venafi returned no matching certificates or KeyId.</exception>
    private async ValueTask LoadObjectsAsync(CancellationToken cancellationToken)
    {
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var api = CreateClient();
        VenafiGetObjectsRequest request = new([0], [1], true, [_options.KeyLabel]);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetObjectsAsync(ProviderHttp.Bearer(token), request, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}vedhsm/api/getobjects");
        if (!reply.Success || reply.Certificates is not { Length: > 0 } certObjects)
        {
            throw new ProviderRequestException($"Venafi CodeSign Protect returned no certificates for label '{_options.KeyLabel}'.");
        }

        List<X509Certificate2> certs = [with(capacity: certObjects.Length)];
        for (var i = 0; i < certObjects.Length; i++)
        {
            var obj = certObjects[i];
            if (_keyId is not { Length: > 0 } && obj.KeyId is { Length: > 0 } kid)
            {
                _keyId = kid;
            }

            if (obj.Value is { Length: > 0 } certBase64)
            {
                certs.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64)));
            }
        }

        if (_keyId is not { Length: > 0 })
        {
            throw new ProviderRequestException($"Venafi CodeSign Protect returned no KeyId for label '{_options.KeyLabel}'.");
        }

        if (_options.CertificateFile is { Length: > 0 } certPath)
        {
            _certificate = CertificateFile.Load(certPath);
            return;
        }

        if (certs.Count == 0)
        {
            throw new ProviderRequestException($"Venafi CodeSign Protect returned empty certificate data for label '{_options.KeyLabel}'.");
        }

        var leaf = certs[0];
        _certificate = new(leaf, CertificateChainOrder.IssuersOf(certs, leaf));
    }

    /// <summary>Returns the configured or freshly exchanged Venafi OAuth bearer token.</summary>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The bearer token.</returns>
    /// <exception cref="ProviderRequestException">OAuth authentication returned no access token.</exception>
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
        VenafiOAuthRequest request = new("VenafiCodeSignClient", "codesignclient", _options.Username!, _options.Password!);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.AuthorizeAsync(request, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}vedauth/authorize/oauth");
        return reply.AccessToken is { Length: > 0 } token
            ? (_accessToken = token)
            : throw new ProviderRequestException("Venafi OAuth authentication returned no access token.");
    }

    /// <summary>Creates a source-generated Refit client for <see cref="IVenafiApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private IVenafiApi CreateClient() =>
        RestService.ForGenerated<IVenafiApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(VenafiJsonContext.Default, _http));
}
