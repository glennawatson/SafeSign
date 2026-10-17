// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Refit;
using SafeSign.Providers.DigiCert;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.GaraSign;

/// <summary>
/// Signs digests via Garantir GaraSign (<c>POST /authenticate</c>, <c>POST /keystore</c>, and <c>POST /sign</c>)
/// with support for <c>IN_PROGRESS</c> approval polling.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class GaraSignProvider : ISigningProvider
{
    /// <summary>The GaraSign REST API version.</summary>
    private const string ApiVersion = "1.0";

    /// <summary>The form field name for the API version.</summary>
    private const string ApiVersionKey = "api_version";

    /// <summary>The form field name for the session token.</summary>
    private const string SessionTokenKey = "session_token";

    /// <summary>The status string returned on successful GaraSign operations.</summary>
    private const string SuccessStatus = "SUCCESS";

    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The GaraSign options.</summary>
    private readonly GaraSignOptions _options;

    /// <summary>The clock used for retry and poll delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached GaraSign session token.</summary>
    private string? _sessionToken;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="GaraSignProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The GaraSign options.</param>
    /// <param name="time">The clock used for retry and poll delays.</param>
    /// <exception cref="ProviderConfigurationException">No session token, username/password, or client certificate was configured.</exception>
    public GaraSignProvider(RefitSettings http, GaraSignOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.SessionToken is not { Length: > 0 }
            && options.ClientCertificateFile is not { Length: > 0 }
            && (options.Username is not { Length: > 0 } || options.Password is not { Length: > 0 }))
        {
            throw new ProviderConfigurationException(
                "GaraSign requires 'session-token', 'client-cert-file', or both 'username' and 'password'.");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "garasign";

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The keystore request failed or did not contain the configured key.</exception>
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

        var sessionToken = await SessionTokenAsync(cancellationToken).ConfigureAwait(false);
        var api = CreateClient();
        var path = CombinePath("keystore");
        Dictionary<string, string> form = new(StringComparer.Ordinal) { [ApiVersionKey] = ApiVersion, [SessionTokenKey] = sessionToken };
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetKeystoreAsync(path, form, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}/keystore");
        if (!string.Equals(reply.Status, SuccessStatus, StringComparison.OrdinalIgnoreCase) || reply.Keys is null)
        {
            throw new ProviderRequestException($"GaraSign keystore lookup failed ({reply.Status}): {reply.Message}");
        }

        var matched = FindKey(reply.Keys, _options.KeyName)
            ?? throw new ProviderRequestException($"GaraSign keystore does not contain key '{_options.KeyName}'.");
        if (matched.CertChain is not { Length: > 0 } rawChain)
        {
            throw new ProviderRequestException($"GaraSign key '{_options.KeyName}' returned an empty certificate chain.");
        }

        List<X509Certificate2> certs = [with(capacity: rawChain.Length)];
        for (var i = 0; i < rawChain.Length; i++)
        {
            certs.Add(X509CertificateLoader.LoadCertificate(DecodeSignedByteArray(rawChain[i])));
        }

        var leaf = certs[0];
        return _certificate = new(leaf, CertificateChainOrder.IssuersOf(certs, leaf));
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The signing request failed, timed out, or returned no signature.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var sessionToken = await SessionTokenAsync(cancellationToken).ConfigureAwait(false);
        var kind = PublicKeyKinds.Of(certificate.Certificate);
        var scheme = DigiCertKeyLockerProvider.Algorithm(kind, request.HashAlgorithm);
        var api = CreateClient();
        var path = CombinePath("sign");

        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            [ApiVersionKey] = ApiVersion,
            [SessionTokenKey] = sessionToken,
            ["key_name"] = _options.KeyName,
            ["signature_scheme"] = scheme,
            ["data_to_sign"] = Convert.ToBase64String(request.Digest.Span),
        };
        using var initialResponse = await ProviderRetry.ExecuteAsync(
            ct => api.SignAsync(path, form, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var current = ProviderHttp.Unwrap(initialResponse, $"POST {_options.Endpoint}/sign");
        var completed = await PollIfInProgressAsync(api, path, sessionToken, current, cancellationToken).ConfigureAwait(false);
        return completed.Signature is { Length: > 0 } sigNumbers
            ? DecodeSignedByteArray(sigNumbers)
            : throw new ProviderRequestException("GaraSign completed without returning signature bytes.");
    }

    /// <summary>Converts a GaraSign JSON integer array (<c>-128..127</c>) into a <see cref="byte"/> array.</summary>
    /// <param name="signedBytes">The signed integer array.</param>
    /// <returns>The decoded byte array.</returns>
    private static byte[] DecodeSignedByteArray(int[] signedBytes)
    {
        var result = new byte[signedBytes.Length];
        for (var i = 0; i < signedBytes.Length; i++)
        {
            result[i] = unchecked((byte)signedBytes[i]);
        }

        return result;
    }

    /// <summary>Finds a key item by name in the GaraSign keystore response.</summary>
    /// <param name="keys">The keystore items.</param>
    /// <param name="keyName">The target key name.</param>
    /// <returns>The matching key item, or <see langword="null"/>.</returns>
    private static GaraSignKeyItem? FindKey(GaraSignKeyItem[] keys, string keyName)
    {
        for (var i = 0; i < keys.Length; i++)
        {
            if (string.Equals(keys[i].Name, keyName, StringComparison.OrdinalIgnoreCase))
            {
                return keys[i];
            }
        }

        return null;
    }

    /// <summary>Polls <c>POST /sign</c> while <paramref name="initial"/> has status <c>IN_PROGRESS</c>.</summary>
    /// <param name="api">The Refit API client.</param>
    /// <param name="path">The relative path to <c>sign</c>.</param>
    /// <param name="sessionToken">The GaraSign session token.</param>
    /// <param name="initial">The initial sign reply.</param>
    /// <param name="cancellationToken">Cancels the polling loop.</param>
    /// <returns>The succeeded <see cref="GaraSignSignReply"/>.</returns>
    /// <exception cref="ProviderRequestException">The sign operation failed or timed out.</exception>
    private async ValueTask<GaraSignSignReply> PollIfInProgressAsync(
        IGaraSignApi api,
        string path,
        string sessionToken,
        GaraSignSignReply initial,
        CancellationToken cancellationToken)
    {
        var current = initial;
        var deadline = _time.GetUtcNow() + _options.PollTimeout;
        while (string.Equals(current.Status, "IN_PROGRESS", StringComparison.OrdinalIgnoreCase))
        {
            if (current.RequestId is not { Length: > 0 } requestId)
            {
                throw new ProviderRequestException("GaraSign returned IN_PROGRESS without a requestId.");
            }

            if (_time.GetUtcNow() >= deadline)
            {
                throw new ProviderRequestException($"GaraSign signing operation '{requestId}' timed out after {_options.PollTimeout}.");
            }

            if (_options.PollInterval > TimeSpan.Zero)
            {
                await Task.Delay(_options.PollInterval, _time, cancellationToken).ConfigureAwait(false);
            }

            Dictionary<string, string> pollForm = new(StringComparer.Ordinal) { [ApiVersionKey] = ApiVersion, [SessionTokenKey] = sessionToken, ["request_id"] = requestId };
            using var pollResponse = await ProviderRetry.ExecuteAsync(
                ct => api.SignAsync(path, pollForm, ct),
                _time,
                cancellationToken).ConfigureAwait(false);
            current = ProviderHttp.Unwrap(pollResponse, $"POST {_options.Endpoint}/sign (poll {requestId})");
        }

        return string.Equals(current.Status, SuccessStatus, StringComparison.OrdinalIgnoreCase)
            ? current
            : throw new ProviderRequestException($"GaraSign signing failed ({current.Status}): {current.Message}");
    }

    /// <summary>Returns the configured or freshly authenticated GaraSign session token.</summary>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The session token.</returns>
    /// <exception cref="ProviderRequestException">Authentication failed.</exception>
    private async ValueTask<string> SessionTokenAsync(CancellationToken cancellationToken)
    {
        if (_options.SessionToken is { Length: > 0 } fixedToken)
        {
            return fixedToken;
        }

        if (_sessionToken is { Length: > 0 })
        {
            return _sessionToken;
        }

        var api = CreateClient();
        var path = CombinePath("authenticate");
        Dictionary<string, string> form = new(StringComparer.Ordinal) { [ApiVersionKey] = ApiVersion };
        if (_options.Username is { Length: > 0 } user)
        {
            form["username"] = user;
        }

        if (_options.Password is { Length: > 0 } password)
        {
            form["password"] = password;
        }

        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.AuthenticateAsync(path, form, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}/authenticate");
        return string.Equals(reply.Status, SuccessStatus, StringComparison.OrdinalIgnoreCase) && reply.SessionToken is { Length: > 0 } token
            ? (_sessionToken = token)
            : throw new ProviderRequestException($"GaraSign authentication failed ({reply.Status}): {reply.Message}");
    }

    /// <summary>Combines the base path of <see cref="GaraSignOptions.Endpoint"/> with a relative action name.</summary>
    /// <param name="action">The action path segment.</param>
    /// <returns>The combined relative path without a leading slash.</returns>
    private string CombinePath(string action)
    {
        var basePath = _options.Endpoint.AbsolutePath.Trim('/');
        return basePath.Length > 0 ? $"{basePath}/{action}" : action;
    }

    /// <summary>Creates a source-generated Refit client for <see cref="IGaraSignApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private IGaraSignApi CreateClient() =>
        RestService.ForGenerated<IGaraSignApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(
                GaraSignJsonContext.Default,
                _http,
                _options.ClientCertificateFile,
                _options.ClientCertificatePassword));
}
