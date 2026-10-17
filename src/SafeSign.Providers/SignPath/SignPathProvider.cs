// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.SignPath;

/// <summary>
/// Signs digests via SignPath.io (<c>GET /v1/{organizationId}/Cryptoki/MySigningPolicies</c> and
/// <c>POST /v1/{organizationId}/SigningRequests</c> with <c>IsFastSigningRequest=true</c>).
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class SignPathProvider : ISigningProvider
{
    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The SignPath options.</summary>
    private readonly SignPathOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="SignPathProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The SignPath options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    public SignPathProvider(RefitSettings http, SignPathOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "signpath";

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to its ASN.1 hash OID string.</summary>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The hash algorithm OID.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    public static string HashOid(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => SafeSign.Signing.Cms.CmsOids.Sha256,
        "SHA384" => SafeSign.Signing.Cms.CmsOids.Sha384,
        "SHA512" => SafeSign.Signing.Cms.CmsOids.Sha512,
        _ => throw new NotSupportedException($"SignPath does not support digest algorithm '{hash.Name}'."),
    };

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">No matching policy certificate was returned by SignPath.</exception>
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
        var path = CombinePath($"v1/{Uri.EscapeDataString(_options.OrganizationId)}/Cryptoki/MySigningPolicies");
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetSigningPoliciesAsync(path, ProviderHttp.Bearer(_options.ApiToken), ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"GET {_options.Endpoint}/{path}");
        var policies = reply.SigningPolicies ?? [];
        for (var i = 0; i < policies.Length; i++)
        {
            var policy = policies[i];
            if (!string.Equals(policy.ProjectSlug, _options.ProjectSlug, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(policy.PolicySlug, _options.PolicySlug, StringComparison.OrdinalIgnoreCase)
                || policy.CertificateBytes is not { Length: > 0 } certBase64)
            {
                continue;
            }

            var leaf = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64));
            return _certificate = new(leaf, []);
        }

        throw new ProviderRequestException(
            $"SignPath returned no certificate for project '{_options.ProjectSlug}' and policy '{_options.PolicySlug}'.");
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">SignPath returned no signature.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var hashOid = HashOid(request.HashAlgorithm);
        SignPathArtifactPayload payload = new(
            kind == PublicKeyKind.Rsa ? "RsaPkcs1" : "Ecdsa",
            kind == PublicKeyKind.Rsa ? hashOid : null,
            Convert.ToBase64String(request.Digest.Span));
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payload, SignPathJsonContext.Default.SignPathArtifactPayload);

        var api = CreateClient();
        var path = CombinePath($"v1/{Uri.EscapeDataString(_options.OrganizationId)}/SigningRequests");
        var auth = ProviderHttp.Bearer(_options.ApiToken);
        using var response = await ProviderRetry.ExecuteAsync(
            ct =>
            {
                ByteArrayPart artifact = new(jsonBytes, "Artifact.data", "application/octet-stream");
                return api.SignAsync(path, auth, _options.ProjectSlug, _options.PolicySlug, "true", artifact, ct);
            },
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}/{path}");
        return reply.Signature is { Length: > 0 } sigBase64
            ? Convert.FromBase64String(sigBase64)
            : throw new ProviderRequestException("SignPath returned no signature.");
    }

    /// <summary>Combines the base path of <see cref="SignPathOptions.Endpoint"/> with a relative route.</summary>
    /// <param name="route">The relative route.</param>
    /// <returns>The combined relative path without a leading slash.</returns>
    private string CombinePath(string route)
    {
        var basePath = _options.Endpoint.AbsolutePath.Trim('/');
        return basePath.Length > 0 ? $"{basePath}/{route}" : route;
    }

    /// <summary>Creates a source-generated Refit client for <see cref="ISignPathApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ISignPathApi CreateClient() =>
        RestService.ForGenerated<ISignPathApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(SignPathJsonContext.Default, _http));
}
