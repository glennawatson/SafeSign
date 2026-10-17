// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>
/// Signs digests via Encryption Consulting CodeSign Secure (<c>/api/auth/GetLoginToken/</c>,
/// <c>/api/certificate_manage/activecerts/</c>, and <c>/api/signing/sign/</c>).
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class CodeSignSecureProvider : ISigningProvider
{
    /// <summary>The default identity type for CodeSign Secure user credential login.</summary>
    private const int DefaultIdentityType = 1;

    /// <summary>The Refit transport settings.</summary>
    private readonly RefitSettings _http;

    /// <summary>The CodeSign Secure options.</summary>
    private readonly CodeSignSecureOptions _options;

    /// <summary>The clock used for retry delays.</summary>
    private readonly TimeProvider _time;

    /// <summary>The cached JWT bearer token.</summary>
    private string? _token;

    /// <summary>The cached signing certificate and chain.</summary>
    private SigningCertificate? _certificate;

    /// <summary>Initializes a new instance of the <see cref="CodeSignSecureProvider"/> class.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The CodeSign Secure options.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <exception cref="ProviderConfigurationException">Neither an access token nor username/password credentials were provided.</exception>
    public CodeSignSecureProvider(RefitSettings http, CodeSignSecureOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        if (options.AccessToken is not { Length: > 0 }
            && (options.Username is not { Length: > 0 } || options.Password is not { Length: > 0 }))
        {
            throw new ProviderConfigurationException(
                "Encryption Consulting CodeSign Secure requires 'access-token' or both 'username' and 'password'.");
        }

        _http = http;
        _options = options;
        _time = time;
    }

    /// <inheritdoc/>
    public string Name => "encryption-consulting";

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The certificate lookup returned no PEM certificate.</exception>
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

        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var api = CreateClient();
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetActiveCertificateAsync(_options.CertificateName, ProviderHttp.Bearer(token), ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"GET {_options.Endpoint}api/certificate_manage/activecerts/?key={_options.CertificateName}");
        if (reply.Message is not { Length: > 0 } messageBase64)
        {
            throw new ProviderRequestException($"CodeSign Secure returned no certificate for '{_options.CertificateName}'.");
        }

        var decodedPem = Convert.FromBase64String(messageBase64);
        return _certificate = CertificateChainOrder.Arrange(CertificateFile.Read(decodedPem), _options.CertificateName);
    }

    /// <inheritdoc/>
    /// <exception cref="ProviderRequestException">The sign response was empty or not valid hexadecimal.</exception>
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        _ = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenAsync(cancellationToken).ConfigureAwait(false);
        var api = CreateClient();
        CodeSignSecureSignPayload payload = new(_options.CertificateName, Convert.ToHexStringLower(request.Digest.Span));
        using var response = await ProviderRetry.ExecuteHttpAsync(
            ct => api.SignAsync(ProviderHttp.Bearer(token), payload, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var raw = await ProviderHttp.ReadBytesAsync(response, $"POST {_options.Endpoint}api/signing/sign/", cancellationToken).ConfigureAwait(false);
        var hex = ExtractSignatureHex(raw);
        if (hex.IsEmpty)
        {
            throw new ProviderRequestException("CodeSign Secure returned an empty signature response.");
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException ex)
        {
            throw new ProviderRequestException($"CodeSign Secure returned a non-hexadecimal signature payload: {ex.Message}", ex);
        }
    }

    /// <summary>Extracts the hexadecimal signature string from either a JSON object (<c>{"result":"..."}</c>) or a quoted hex literal.</summary>
    /// <param name="raw">The raw HTTP response bytes.</param>
    /// <returns>The trimmed hexadecimal signature span.</returns>
    /// <exception cref="ProviderRequestException">The JSON payload could not be parsed.</exception>
    private static ReadOnlySpan<char> ExtractSignatureHex(ReadOnlySpan<byte> raw)
    {
        var trimmedBytes = raw.TrimStart(" \t\r\n"u8);
        if (trimmedBytes.StartsWith("{"u8))
        {
            try
            {
                var reply = JsonSerializer.Deserialize(trimmedBytes, CodeSignSecureJsonContext.Default.CodeSignSecureSignReply);
                return reply?.Result is { Length: > 0 } result ? result.AsSpan().Trim() : ReadOnlySpan<char>.Empty;
            }
            catch (JsonException ex)
            {
                throw new ProviderRequestException($"CodeSign Secure returned malformed JSON: {ex.Message}", ex);
            }
        }

        return Encoding.ASCII.GetString(raw).AsSpan().Trim().Trim('"');
    }

    /// <summary>Returns the configured or freshly exchanged JWT bearer token.</summary>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The JWT bearer token.</returns>
    /// <exception cref="ProviderRequestException">The login endpoint returned no token.</exception>
    private async ValueTask<string> TokenAsync(CancellationToken cancellationToken)
    {
        if (_options.AccessToken is { Length: > 0 } fixedToken)
        {
            return fixedToken;
        }

        if (_token is { Length: > 0 })
        {
            return _token;
        }

        var api = CreateClient();
        CodeSignSecureLoginPayload payload = new(_options.Username!, _options.Password!, DefaultIdentityType);
        using var response = await ProviderRetry.ExecuteAsync(
            ct => api.GetLoginTokenAsync(payload, ct),
            _time,
            cancellationToken).ConfigureAwait(false);
        var reply = ProviderHttp.Unwrap(response, $"POST {_options.Endpoint}api/auth/GetLoginToken/");
        return reply.Token is { Length: > 0 } token
            ? (_token = token)
            : throw new ProviderRequestException("CodeSign Secure login succeeded without returning a token.");
    }

    /// <summary>Creates a source-generated Refit client for <see cref="ICodeSignSecureApi"/>.</summary>
    /// <returns>The Refit client.</returns>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private ICodeSignSecureApi CreateClient() =>
        RestService.ForGenerated<ICodeSignSecureApi>(
            ProviderHttp.Authority(_options.Endpoint),
            ProviderHttp.CreateSettings(
                CodeSignSecureJsonContext.Default,
                _http,
                _options.ClientCertificateFile,
                _options.ClientCertificatePassword));
}
