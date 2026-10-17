// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Certum;

/// <summary>Executes Certum SimplySign CAS OAuth 2.0 login and SCS1_ATOM card, certificate, and signature tasks through <see cref="ICertumCloudSignApi"/>.</summary>
public static class CertumRequests
{
    /// <summary>The default token lifetime in seconds when <c>expires_in</c> is omitted.</summary>
    private const int DefaultTokenLifetimeSeconds = 1800;

    /// <summary>The maximum number of redirect hops followed during CAS login.</summary>
    private const int MaxLoginRedirects = 20;

    /// <summary>The maximum number of SCS1_ATOM task polls before timing out.</summary>
    private const int MaxTaskPolls = 120;

    /// <summary>The lowest HTTP status code treated as an error in SCS1_ATOM task polling.</summary>
    private const int MinErrorStatusCode = 400;

    /// <summary>The maximum number of error response bytes quoted in an exception message.</summary>
    private const int MaxErrorPreviewBytes = 512;

    /// <summary>The default and minimum poll delay in milliseconds when <c>ping-after</c> is omitted or small.</summary>
    private const int MinPollDelayMilliseconds = 200;

    /// <summary>The maximum poll delay in milliseconds for SCS1_ATOM tasks.</summary>
    private const int MaxPollDelayMilliseconds = 2000;

    /// <summary>The length of the <c>&lt;input</c> tag prefix.</summary>
    private const int InputTagPrefixLength = 6;

    /// <summary>The query parameter name for OAuth 2.0 authorization codes.</summary>
    private const string CodeQueryParameter = "code";

    /// <summary>Acquires a SimplySign OAuth 2.0 bearer access token using the configured credentials.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The cached access token and its expiry.</returns>
    /// <exception cref="ProviderConfigurationException">No valid credentials were provided.</exception>
    /// <exception cref="ProviderRequestException">The CAS IdP or OAuth token endpoint rejected the login.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<CachedAccessToken> AcquireTokenAsync(
        RefitSettings http,
        CertumOptions options,
        TimeProvider time,
        CancellationToken cancellationToken) =>
        AcquireTokenAsync(http, options, null, time, cancellationToken);

    /// <summary>
    /// Acquires or refreshes a SimplySign OAuth 2.0 bearer access token, preferring <paramref name="cachedRefreshToken"/>
    /// when a previous CAS login returned a reusable <c>RT-...</c> refresh token.
    /// </summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="cachedRefreshToken">An optional refresh token from an earlier token exchange.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The cached access token, its expiry, and any refresh token.</returns>
    /// <exception cref="ProviderConfigurationException">No valid credentials were provided.</exception>
    /// <exception cref="ProviderRequestException">The CAS IdP or OAuth token endpoint rejected the login.</exception>
    public static async ValueTask<CachedAccessToken> AcquireTokenAsync(
        RefitSettings http,
        CertumOptions options,
        string? cachedRefreshToken,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);

        if (options.AccessToken is { Length: > 0 } directToken)
        {
            return new(directToken, DateTimeOffset.MaxValue);
        }

        var api = CreateApi(options.Endpoint, http);
        var refreshToken = cachedRefreshToken is { Length: > 0 } ? cachedRefreshToken : options.RefreshToken;
        if (refreshToken is { Length: > 0 })
        {
            using var refreshResponse = await ProviderRetry.ExecuteAsync(
                ct => api.RefreshTokenAsync(
                    options.ClientId,
                    options.ClientSecret,
                    refreshToken,
                    "refresh_token",
                    ct),
                options.RetryOptions,
                time,
                cancellationToken).ConfigureAwait(false);
            var refreshReply = ProviderHttp.Unwrap(refreshResponse, "POST /idp/oauth2.0/accessToken (refresh_token)");
            return ToCachedToken(refreshReply, refreshToken, time);
        }

        if (options.Email is not { Length: > 0 } email)
        {
            throw new ProviderConfigurationException("Certum SimplySign login requires an account email address.");
        }

        if (options.TotpSecret is not { Length: > 0 } && options.OtpCode is not { Length: > 0 })
        {
            throw new ProviderConfigurationException("Certum SimplySign login requires either TotpSecret or OtpCode.");
        }

        return await LoginWithCasAsync(api, options, email, time, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Materializes the SimplySign virtual card and its signing certificate.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="token">The bearer access token.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The materialized card, raw PEM bytes, and <see cref="SigningCertificate"/>.</returns>
    /// <exception cref="ProviderConfigurationException">The requested card or chain file does not exist.</exception>
    /// <exception cref="ProviderRequestException">No card or certificate was returned by the service.</exception>
    public static async ValueTask<CertumMaterializedCard> MaterializeCardAsync(
        RefitSettings http,
        CertumOptions options,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(token);
        ArgumentNullException.ThrowIfNull(time);

        var api = CreateApi(options.Endpoint, http);
        var authorization = ProviderHttp.Bearer(token);

        var initialCards = await ProviderRetry.ExecuteHttpAsync(
            async ct =>
            {
                using var emptyJson = ProviderHttp.Bytes([], "application/json");
                return await api.StartListCardsTaskAsync(authorization, emptyJson, ct).ConfigureAwait(false);
            },
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var cardsBody = await RunTaskAsync(api, options, token, initialCards, time, cancellationToken).ConfigureAwait(false);

        var cards = DeserializeJson(cardsBody, CertumJsonContext.Default.CertumCardInfoArray, "POST /card/v1/cards/tasks");
        var serial = SelectCardSerial(cards, options.CardSerial);

        var initialCerts = await ProviderRetry.ExecuteHttpAsync(
            async ct =>
            {
                using var emptyJson = ProviderHttp.Bytes([], "application/json");
                return await api.StartListCertificatesTaskAsync(serial, authorization, emptyJson, ct).ConfigureAwait(false);
            },
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var certMultipartBody = await RunTaskAsync(api, options, token, initialCerts, time, cancellationToken).ConfigureAwait(false);

        var certificatePem = CertumMultipart.ExtractCertificatePart(certMultipartBody);
        var certificates = CertificateFile.Read(certificatePem);
        if (options.AdditionalCertificatesPath is { Length: > 0 } chainPath)
        {
            if (!File.Exists(chainPath))
            {
                throw new ProviderConfigurationException($"Certum certificate chain file '{chainPath}' does not exist.");
            }

            var chainBytes = await File.ReadAllBytesAsync(chainPath, cancellationToken).ConfigureAwait(false);
            certificates.AddRange(CertificateFile.Read(chainBytes));
        }

        CertumIntermediateCertificates.TryAddMatchingIntermediate(certificates);
        var signingCertificate = CertificateChainOrder.Arrange(certificates, $"Certum card '{serial}'");
        return new(serial, certificatePem, signingCertificate);
    }

    /// <summary>Signs a digest on the SimplySign cloud HSM using the SCS1_ATOM signature task endpoint.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="card">The materialized card and PEM certificate.</param>
    /// <param name="request">The digest signing request.</param>
    /// <param name="token">The bearer access token.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The raw signature bytes.</returns>
    /// <exception cref="ProviderRequestException">The signature task failed or returned no signature for the digest.</exception>
    public static async ValueTask<byte[]> SignDigestAsync(
        RefitSettings http,
        CertumOptions options,
        CertumMaterializedCard card,
        SignDigestRequest request,
        string token,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(card);
        ArgumentException.ThrowIfNullOrEmpty(token);
        ArgumentNullException.ThrowIfNull(time);

        var digestType = DigestType(request.HashAlgorithm);
        var digestHex = Convert.ToHexStringLower(request.Digest.Span);
        var api = CreateApi(options.Endpoint, http);

        var initialResponse = await ProviderRetry.ExecuteHttpAsync(
            async ct =>
            {
                using var form = CertumMultipart.CreateSignatureForm(digestHex, digestType, card.CertificatePem);
                return await api.StartSignatureTaskAsync(
                    card.Serial,
                    ProviderHttp.Bearer(token),
                    form,
                    ct).ConfigureAwait(false);
            },
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var resultBody = await RunTaskAsync(api, options, token, initialResponse, time, cancellationToken).ConfigureAwait(false);

        return ParseSignatureResponse(resultBody, request.Digest.Span);
    }

    /// <summary>Parses the JSON array returned by a completed signature task and decodes the signature matching <paramref name="expectedDigest"/>.</summary>
    /// <param name="responseBytes">The raw JSON response bytes.</param>
    /// <param name="expectedDigest">The requested digest bytes.</param>
    /// <returns>The decoded signature bytes.</returns>
    /// <exception cref="ProviderRequestException">The JSON could not be parsed or contained no signature for <paramref name="expectedDigest"/>.</exception>
    public static byte[] ParseSignatureResponse(ReadOnlySpan<byte> responseBytes, ReadOnlySpan<byte> expectedDigest)
    {
        var items = DeserializeJson(responseBytes, CertumJsonContext.Default.DictionaryStringStringArray, "Certum signature task");
        foreach (var map in items)
        {
            if (TryFindHexSignature(map, expectedDigest, out var signature))
            {
                return signature;
            }
        }

        throw new ProviderRequestException("Certum signature task returned no signature for the requested digest.");
    }

    /// <summary>Extracts the value of a hidden HTML <c>&lt;input&gt;</c> element by its <c>name</c> attribute.</summary>
    /// <param name="html">The HTML document text.</param>
    /// <param name="fieldName">The input <c>name</c> attribute to find (for example <c>execution</c>).</param>
    /// <returns>The <c>value</c> attribute, or <see langword="null"/> when not present.</returns>
    public static string? ExtractHiddenInputValue(ReadOnlySpan<char> html, string fieldName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        var remaining = html;
        while (!remaining.IsEmpty)
        {
            var start = remaining.IndexOf("<input", StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                return null;
            }

            remaining = remaining[(start + InputTagPrefixLength)..];
            var end = remaining.IndexOf('>');
            if (end < 0)
            {
                return null;
            }

            var tag = remaining[..end];
            remaining = remaining[(end + 1)..];
            var nameValue = ExtractQuotedAttribute(tag, "name=");
            if (nameValue is not null && nameValue.Equals(fieldName, StringComparison.Ordinal))
            {
                return ExtractQuotedAttribute(tag, "value=") ?? string.Empty;
            }
        }

        return null;
    }

    /// <summary>Maps a hash algorithm name to the Certum <c>digesttype</c> string.</summary>
    /// <param name="hash">The hash algorithm.</param>
    /// <returns>The Certum digest type string.</returns>
    /// <exception cref="NotSupportedException">The hash algorithm is not supported.</exception>
    public static string DigestType(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => "SHA256",
        "SHA384" => "SHA384",
        "SHA512" => "SHA512",
        _ => throw new NotSupportedException($"Certum SimplySign does not support {hash.Name} digests."),
    };

    /// <summary>Extracts a human-readable error message from a Certum CAS HTML or plain-text error response.</summary>
    /// <param name="responseText">The response body text.</param>
    /// <returns>The extracted error message, or <see langword="null"/> when none could be found.</returns>
    public static string? ExtractCasErrorMessage(ReadOnlySpan<char> responseText)
    {
        var trimmed = responseText.Trim();
        if (trimmed.IsEmpty)
        {
            return null;
        }

        if (ExtractFirstSpanAfterMarker(trimmed, "ds-form-message--error") is { Length: > 0 } formError)
        {
            return formError;
        }

        if (ExtractElementText(trimmed, "<title>", "</title>") is { Length: > 0 } titleText)
        {
            return titleText;
        }

        if (!trimmed.StartsWith("<", StringComparison.Ordinal))
        {
            var previewLen = Math.Min(trimmed.Length, MaxErrorPreviewBytes);
            return trimmed[..previewLen].ToString();
        }

        return null;
    }

    /// <summary>Resolves the 6-digit OTP code from either <see cref="CertumOptions.TotpSecret"/> or <see cref="CertumOptions.OtpCode"/>.</summary>
    /// <param name="options">The Certum options.</param>
    /// <param name="time">The clock.</param>
    /// <returns>The 6-digit OTP string.</returns>
    /// <exception cref="ProviderConfigurationException">Neither TOTP secret nor OTP code was configured.</exception>
    private static string ResolveOtpCode(CertumOptions options, TimeProvider time)
    {
        if (options.TotpSecret is { Length: > 0 } secret)
        {
            return CertumTotp.Parse(secret).GenerateCode(time.GetUtcNow());
        }

        if (options.OtpCode is { Length: > 0 } otpCode)
        {
            return otpCode;
        }

        throw new ProviderConfigurationException("Certum SimplySign login requires either TotpSecret or OtpCode.");
    }

    /// <summary>Creates a source-generated <see cref="ICertumCloudSignApi"/> client.</summary>
    /// <param name="endpoint">The SimplySign endpoint.</param>
    /// <param name="http">The base Refit settings.</param>
    /// <returns>The generated client.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ICertumCloudSignApi CreateApi(Uri endpoint, RefitSettings http) =>
        RestService.ForGenerated<ICertumCloudSignApi>(ProviderHttp.Authority(endpoint), ProviderHttp.CreateSettings(CertumJsonContext.Default, http));

    /// <summary>Performs the CAS OAuth 2.0 authorization-code login flow.</summary>
    /// <param name="api">The Certum Refit client.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="email">The account email.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The bearer access token and expiry.</returns>
    /// <exception cref="ProviderRequestException">The login page or authorization code could not be obtained.</exception>
    private static async ValueTask<CachedAccessToken> LoginWithCasAsync(
        ICertumCloudSignApi api,
        CertumOptions options,
        string email,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var authority = ProviderHttp.Authority(options.Endpoint);
        var scope = $"{authority}/idp/oauth2.0/profile";
        var redirectUri = $"{authority}/redirect";
        Dictionary<string, string> cookies = [with(StringComparer.OrdinalIgnoreCase)];

        var authorizeResponse = await ProviderRetry.ExecuteHttpAsync(
            ct => api.AuthorizeAsync(CodeQueryParameter, options.ClientId, redirectUri, scope, string.Empty, ct),
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var (loginHtml, loginUri) = await FollowToLoginPageAsync(api, options, authorizeResponse, cookies, time, cancellationToken).ConfigureAwait(false);

        var execution = ExtractHiddenInputValue(loginHtml, "execution")
            ?? throw new ProviderRequestException(
                $"Certum CAS login page at '{loginUri?.GetLeftPart(UriPartial.Path) ?? "/idp/login"}' did not contain a hidden 'execution' input.");
        var lt = ExtractHiddenInputValue(loginHtml, "lt") ?? string.Empty;
        var service = loginUri is not null ? ExtractQueryParameter(loginUri, "service") : null;
        var otp = ResolveOtpCode(options, time);

        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["username"] = email,
            ["password"] = otp,
            ["execution"] = execution,
            ["_eventId"] = "submit",
            ["geolocation"] = string.Empty,
            ["submit"] = "LOGIN",
            ["lt"] = lt,
        };

        var loginResponse = await ProviderRetry.ExecuteHttpAsync(
            ct => api.SubmitLoginAsync(service, FormatCookieHeader(cookies), form, ct),
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var authorizationCode = await RecoverAuthorizationCodeAsync(api, options, loginResponse, loginUri, cookies, time, cancellationToken).ConfigureAwait(false);

        using var tokenResponse = await ProviderRetry.ExecuteAsync(
            ct => api.ExchangeAuthorizationCodeAsync(
                options.ClientId,
                options.ClientSecret,
                scope,
                authorizationCode,
                redirectUri,
                "authorization_code",
                ct),
            options.RetryOptions,
            time,
            cancellationToken).ConfigureAwait(false);
        var tokenReply = ProviderHttp.Unwrap(tokenResponse, "POST /idp/oauth2.0/accessToken");
        return ToCachedToken(tokenReply, null, time);
    }

    /// <summary>Follows redirects from <c>/idp/oauth2.0/authorize</c> until the CAS login HTML page is reached.</summary>
    /// <param name="api">The Certum Refit client.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="initial">The initial authorize response.</param>
    /// <param name="cookies">Accumulates session cookies across redirect hops.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The login HTML and the URI that served it.</returns>
    /// <exception cref="ProviderRequestException">Too many redirects occurred.</exception>
    private static async ValueTask<(string Html, Uri? LoginUri)> FollowToLoginPageAsync(
        ICertumCloudSignApi api,
        CertumOptions options,
        HttpResponseMessage initial,
        Dictionary<string, string> cookies,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var current = initial;
        var lastUri = current.RequestMessage?.RequestUri;
        try
        {
            for (var hop = 0; hop < MaxLoginRedirects; hop++)
            {
                CollectCookies(current, cookies);
                if (!IsRedirect(current.StatusCode) || current.Headers.Location is not { } location)
                {
                    var bytes = await ProviderHttp.ReadBytesAsync(current, "GET /idp/login", cancellationToken).ConfigureAwait(false);
                    return (Encoding.UTF8.GetString(bytes), lastUri ?? current.RequestMessage?.RequestUri);
                }

                var target = location.IsAbsoluteUri ? location : new Uri(options.Endpoint, location);
                lastUri = target;
                current.Dispose();
                var cookieHeader = FormatCookieHeader(cookies);
                var nextPath = target.AbsolutePath.TrimStart('/');
                var nextQuery = ParseQueryParameters(target);
                current = await ProviderRetry.ExecuteHttpAsync(
                    ct => api.FollowLoginGetAsync(nextPath, nextQuery, cookieHeader, ct),
                    options.RetryOptions,
                    time,
                    cancellationToken).ConfigureAwait(false);
            }

            throw new ProviderRequestException("Certum CAS authorize exceeded the maximum redirect count.");
        }
        finally
        {
            current.Dispose();
        }
    }

    /// <summary>Follows redirects from <c>POST /idp/login</c> until a URL carrying <c>?code=...</c> is observed.</summary>
    /// <param name="api">The Certum Refit client.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="initial">The response from <c>POST /idp/login</c>.</param>
    /// <param name="loginUri">The login page URI that received the POST.</param>
    /// <param name="cookies">Accumulates session cookies across redirect hops.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the HTTP requests.</param>
    /// <returns>The OAuth 2.0 authorization code.</returns>
    /// <exception cref="ProviderRequestException">No authorization code was found in the redirect chain.</exception>
    private static async ValueTask<string> RecoverAuthorizationCodeAsync(
        ICertumCloudSignApi api,
        CertumOptions options,
        HttpResponseMessage initial,
        Uri? loginUri,
        Dictionary<string, string> cookies,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var current = initial;
        var lastUri = current.RequestMessage?.RequestUri ?? loginUri;
        var hops = 0;
        try
        {
            for (; hops < MaxLoginRedirects; hops++)
            {
                CollectCookies(current, cookies);
                if (TryExtractCodeFromResponse(current, options.Endpoint, out var authorizationCode, out var nextTarget))
                {
                    return authorizationCode;
                }

                if (nextTarget is null)
                {
                    break;
                }

                lastUri = nextTarget;
                current.Dispose();
                var cookieHeader = FormatCookieHeader(cookies);
                var nextPath = nextTarget.AbsolutePath.TrimStart('/');
                var nextQuery = ParseQueryParameters(nextTarget);
                current = await ProviderRetry.ExecuteHttpAsync(
                    ct => api.FollowLoginGetAsync(nextPath, nextQuery, cookieHeader, ct),
                    options.RetryOptions,
                    time,
                    cancellationToken).ConfigureAwait(false);
            }

            throw await BuildCasLoginFailureAsync(current, lastUri, hops, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            current.Dispose();
        }
    }

    /// <summary>Builds a detailed <see cref="ProviderRequestException"/> when CAS login does not produce an authorization code.</summary>
    /// <param name="response">The final HTTP response from CAS.</param>
    /// <param name="lastUri">The last target URI requested.</param>
    /// <param name="hops">The number of redirect hops followed after <c>POST /idp/login</c>.</param>
    /// <param name="cancellationToken">Cancels reading the response body.</param>
    /// <returns>The constructed <see cref="ProviderRequestException"/>.</returns>
    private static async ValueTask<ProviderRequestException> BuildCasLoginFailureAsync(
        HttpResponseMessage response,
        Uri? lastUri,
        int hops,
        CancellationToken cancellationToken)
    {
        var bodyBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var bodyText = Encoding.UTF8.GetString(bodyBytes);
        var casMessage = ExtractCasErrorMessage(bodyText);
        var statusText = $"{(int)response.StatusCode} {response.ReasonPhrase}".Trim();
        var uriText = (response.RequestMessage?.RequestUri ?? lastUri)?.GetLeftPart(UriPartial.Path) ?? "/idp/login";
        var serverDetail = casMessage is { Length: > 0 } ? $" Server message: \"{casMessage}\"." : string.Empty;
        var message = $"Certum CAS login at '{uriText}' failed after {hops} redirect hop(s) with HTTP {statusText} "
            + $"and did not return an OAuth authorization code.{serverDetail} "
            + "Verify that CERTUM_USER_ID (email) and CERTUM_OTP_URI / OTP code are valid and that the system clock is synchronized.";
        return new(message, response.StatusCode);
    }

    /// <summary>Inspects a login response for an OAuth <c>code</c> query parameter or next redirect target.</summary>
    /// <param name="response">The current HTTP response.</param>
    /// <param name="baseEndpoint">The base endpoint URI.</param>
    /// <param name="authorizationCode">Receives the authorization code when found.</param>
    /// <param name="nextTarget">Receives the next redirect URI to follow when no code was found yet.</param>
    /// <returns>True when <paramref name="authorizationCode"/> was found.</returns>
    private static bool TryExtractCodeFromResponse(
        HttpResponseMessage response,
        Uri baseEndpoint,
        out string authorizationCode,
        out Uri? nextTarget)
    {
        authorizationCode = string.Empty;
        nextTarget = null;
        if (response.RequestMessage?.RequestUri is { } requestUri
            && ExtractQueryParameter(requestUri, CodeQueryParameter) is { Length: > 0 } fromRequest)
        {
            authorizationCode = fromRequest;
            return true;
        }

        if (response.Headers.Location is not { } location)
        {
            return false;
        }

        var target = location.IsAbsoluteUri ? location : new Uri(baseEndpoint, location);
        if (ExtractQueryParameter(target, CodeQueryParameter) is { Length: > 0 } fromLocation)
        {
            authorizationCode = fromLocation;
            return true;
        }

        if (IsRedirect(response.StatusCode))
        {
            nextTarget = target;
        }

        return false;
    }

    /// <summary>Drives an SCS1_ATOM asynchronous task loop, polling <c>atom:link</c> until the final result payload arrives.</summary>
    /// <param name="api">The Certum Refit client.</param>
    /// <param name="options">The Certum options.</param>
    /// <param name="token">The bearer access token.</param>
    /// <param name="initial">The initial task response.</param>
    /// <param name="time">The clock used for poll delays.</param>
    /// <param name="cancellationToken">Cancels polling.</param>
    /// <returns>The final result bytes.</returns>
    /// <exception cref="ProviderRequestException">The task failed or did not complete within the poll limit.</exception>
    private static async ValueTask<byte[]> RunTaskAsync(
        ICertumCloudSignApi api,
        CertumOptions options,
        string token,
        HttpResponseMessage initial,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var current = initial;
        try
        {
            for (var poll = 0; poll < MaxTaskPolls; poll++)
            {
                var (body, nextPoll) = await InspectTaskResponseAsync(current, options.Endpoint, time, cancellationToken).ConfigureAwait(false);
                if (nextPoll is null)
                {
                    return body;
                }

                var (pollPath, delay) = ResolvePollStep(options, nextPoll.Value);
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, time, cancellationToken).ConfigureAwait(false);
                }

                current.Dispose();
                var authorization = ProviderHttp.Bearer(token);
                current = await ProviderRetry.ExecuteHttpAsync(
                    ct => api.PollTaskAsync(pollPath, authorization, ct),
                    options.RetryOptions,
                    time,
                    cancellationToken).ConfigureAwait(false);
            }

            throw new ProviderRequestException($"Certum cloud task did not complete after {MaxTaskPolls} polls.");
        }
        finally
        {
            current.Dispose();
        }
    }

    /// <summary>Reads a task HTTP response and determines whether it is the final payload or requires another poll.</summary>
    /// <param name="response">The HTTP response.</param>
    /// <param name="baseEndpoint">The base endpoint URI.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels reading the body.</param>
    /// <returns>The response bytes and an optional next poll descriptor.</returns>
    /// <exception cref="ProviderRequestException">The HTTP status or task state indicates failure.</exception>
    private static async ValueTask<(byte[] Body, (string Path, TimeSpan? SuggestedDelay)? NextPoll)> InspectTaskResponseAsync(
        HttpResponseMessage response,
        Uri baseEndpoint,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode >= MinErrorStatusCode)
        {
            var preview = Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, MaxErrorPreviewBytes)));
            throw new ProviderRequestException(
                $"Certum task failed with {(int)response.StatusCode} {response.ReasonPhrase}: {preview}",
                response.StatusCode);
        }

        var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
        if (mediaType.Contains("multipart", StringComparison.OrdinalIgnoreCase)
            || !TryReadTaskStatus(body, out var taskStatus))
        {
            return (body, null);
        }

        if (string.Equals(taskStatus.State, "failed", StringComparison.OrdinalIgnoreCase))
        {
            var preview = Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, MaxErrorPreviewBytes)));
            throw new ProviderRequestException($"Certum cloud task failed: {preview}");
        }

        if (taskStatus.AtomLink is not { Length: > 0 } atomLink)
        {
            return (body, null);
        }

        var suggestedDelay = taskStatus.PingAfter is { } pingAfter
            ? TimeSpan.FromMilliseconds(pingAfter)
            : ProviderRetry.TryGetRetryAfter(response.Headers, time.GetUtcNow());
        return (body, (NormalizeTaskPath(baseEndpoint, atomLink), suggestedDelay));
    }

    /// <summary>Computes the poll path and fuzzy-jittered delay for the next SCS1_ATOM poll iteration.</summary>
    /// <param name="options">The Certum options.</param>
    /// <param name="pollStep">The path and provider-suggested delay.</param>
    /// <returns>The path and delay.</returns>
    private static (string Path, TimeSpan Delay) ResolvePollStep(CertumOptions options, (string Path, TimeSpan? SuggestedDelay) pollStep)
    {
        if (options.TaskPollDelay is { } fixedDelay)
        {
            return (pollStep.Path, fixedDelay);
        }

        var rawMs = pollStep.SuggestedDelay?.TotalMilliseconds ?? MinPollDelayMilliseconds;
        var clampedMs = Math.Clamp(rawMs, MinPollDelayMilliseconds, MaxPollDelayMilliseconds);
        var delay = ProviderRetry.ComputePollDelay(options.RetryOptions, TimeSpan.FromMilliseconds(clampedMs));
        return (pollStep.Path, delay);
    }

    /// <summary>Tries to read a JSON body as a <see cref="CertumTaskStatus"/> object when the root JSON token is an object.</summary>
    /// <param name="body">The response bytes.</param>
    /// <param name="status">Receives the parsed task status.</param>
    /// <returns>True when the body was a JSON object and deserialized to <see cref="CertumTaskStatus"/>.</returns>
    private static bool TryReadTaskStatus(ReadOnlySpan<byte> body, out CertumTaskStatus status)
    {
        status = null!;
        var trimmed = body.TrimStart(" \t\r\n"u8);
        if (!trimmed.StartsWith("{"u8))
        {
            return false;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize(trimmed, CertumJsonContext.Default.CertumTaskStatus);
            if (parsed is null)
            {
                return false;
            }

            status = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Converts an absolute or relative <c>atom:link</c> into a root-relative path for <see cref="ICertumCloudSignApi.PollTaskAsync"/>.</summary>
    /// <param name="baseEndpoint">The base endpoint.</param>
    /// <param name="atomLink">The <c>atom:link</c> value.</param>
    /// <returns>The trimmed relative path and query.</returns>
    private static string NormalizeTaskPath(Uri baseEndpoint, string atomLink)
    {
        if (Uri.TryCreate(atomLink, UriKind.Absolute, out var absolute))
        {
            return absolute.PathAndQuery.TrimStart('/');
        }

        var resolved = new Uri(baseEndpoint, atomLink);
        return resolved.PathAndQuery.TrimStart('/');
    }

    /// <summary>Selects the desired card serial from the card list.</summary>
    /// <param name="cards">The cards returned by SimplySign.</param>
    /// <param name="requestedSerial">The optional serial requested by the caller.</param>
    /// <returns>The selected card serial.</returns>
    /// <exception cref="ProviderConfigurationException">The requested card serial was not found.</exception>
    /// <exception cref="ProviderRequestException">No cards or valid card serials were returned.</exception>
    private static string SelectCardSerial(CertumCardInfo[] cards, string? requestedSerial)
    {
        if (cards.Length == 0)
        {
            throw new ProviderRequestException("Certum SimplySign returned no virtual cards for this account.");
        }

        if (requestedSerial is { Length: > 0 })
        {
            foreach (var card in cards)
            {
                if (string.Equals(card.CardNumber, requestedSerial, StringComparison.OrdinalIgnoreCase))
                {
                    return card.CardNumber!;
                }
            }

            throw new ProviderConfigurationException($"Certum SimplySign card '{requestedSerial}' was not found on the account.");
        }

        foreach (var card in cards)
        {
            if (card.CardNumber is { Length: > 0 } serial)
            {
                return serial;
            }
        }

        throw new ProviderRequestException("Certum SimplySign card list did not contain a valid 'cardno'.");
    }

    /// <summary>Looks up a digest in a signature dictionary using constant-time byte comparison and decodes its hex signature.</summary>
    /// <param name="map">The hex-digest-to-hex-signature map.</param>
    /// <param name="expectedDigest">The requested digest bytes.</param>
    /// <param name="signature">Receives the decoded signature bytes.</param>
    /// <returns>True when a matching digest entry was found.</returns>
    /// <exception cref="ProviderRequestException">The signature value was not valid hexadecimal.</exception>
    private static bool TryFindHexSignature(Dictionary<string, string> map, ReadOnlySpan<byte> expectedDigest, out byte[] signature)
    {
        foreach (var entry in map)
        {
            byte[] candidateDigest;
            try
            {
                candidateDigest = Convert.FromHexString(entry.Key);
            }
            catch (FormatException)
            {
                continue;
            }

            if (!CryptographicOperations.FixedTimeEquals(candidateDigest, expectedDigest))
            {
                continue;
            }

            try
            {
                signature = Convert.FromHexString(entry.Value);
                return true;
            }
            catch (FormatException ex)
            {
                throw new ProviderRequestException("Certum signature task returned non-hex signature data.", ex);
            }
        }

        signature = [];
        return false;
    }

    /// <summary>Deserializes a UTF-8 JSON buffer using source-generated metadata.</summary>
    /// <typeparam name="T">The target type.</typeparam>
    /// <param name="utf8Json">The UTF-8 JSON bytes.</param>
    /// <param name="typeInfo">The JSON type info.</param>
    /// <param name="operation">The operation name for error reporting.</param>
    /// <returns>The deserialized value.</returns>
    /// <exception cref="ProviderRequestException">The payload is null or invalid JSON.</exception>
    private static T DeserializeJson<T>(ReadOnlySpan<byte> utf8Json, JsonTypeInfo<T> typeInfo, string operation)
    {
        try
        {
            return JsonSerializer.Deserialize(utf8Json, typeInfo)
                ?? throw new ProviderRequestException($"{operation} returned a null JSON payload.");
        }
        catch (JsonException ex)
        {
            throw new ProviderRequestException($"{operation} returned invalid JSON: {ex.Message}", ex);
        }
    }

    /// <summary>Converts a <see cref="CertumTokenResponse"/> to a <see cref="CachedAccessToken"/>.</summary>
    /// <param name="reply">The token reply.</param>
    /// <param name="fallbackRefreshToken">The refresh token used for the request when the reply omits a new one.</param>
    /// <param name="time">The clock.</param>
    /// <returns>The cached token.</returns>
    /// <exception cref="ProviderRequestException">The reply carried no access token.</exception>
    private static CachedAccessToken ToCachedToken(CertumTokenResponse reply, string? fallbackRefreshToken, TimeProvider time)
    {
        if (reply.AccessToken is not { Length: > 0 } accessToken)
        {
            throw new ProviderRequestException("Certum OAuth token endpoint returned no access_token.");
        }

        var lifetime = reply.ExpiresIn ?? DefaultTokenLifetimeSeconds;
        var refreshToken = reply.RefreshToken is { Length: > 0 } returnedRefresh ? returnedRefresh : fallbackRefreshToken;
        return new(accessToken, time.GetUtcNow().AddSeconds(lifetime), refreshToken);
    }

    /// <summary>Checks whether an HTTP status code is a 3xx redirect.</summary>
    /// <param name="statusCode">The HTTP status code.</param>
    /// <returns>True for 301, 302, 303, 307, or 308.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;

    /// <summary>Records any <c>Set-Cookie</c> headers from <paramref name="response"/>.</summary>
    /// <param name="response">The HTTP response.</param>
    /// <param name="cookies">The cookie dictionary to update.</param>
    private static void CollectCookies(HttpResponseMessage response, Dictionary<string, string> cookies)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return;
        }

        foreach (var raw in values)
        {
            var semi = raw.IndexOf(';', StringComparison.Ordinal);
            var pair = semi >= 0 ? raw.AsSpan(0, semi) : raw.AsSpan();
            var eq = pair.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            var name = pair[..eq].Trim().ToString();
            var value = pair[(eq + 1)..].Trim();
            if (value.IsEmpty
                || value is "\"\""
                || raw.Contains("Max-Age=0", StringComparison.OrdinalIgnoreCase))
            {
                _ = cookies.Remove(name);
                continue;
            }

            cookies[name] = value.ToString();
        }
    }

    /// <summary>Formats accumulated cookies as a <c>Cookie</c> request header value.</summary>
    /// <param name="cookies">The cookie map.</param>
    /// <returns>The header value, or <see langword="null"/> when empty.</returns>
    private static string? FormatCookieHeader(Dictionary<string, string> cookies)
    {
        if (cookies.Count == 0)
        {
            return null;
        }

        StringBuilder builder = new();
        foreach (var entry in cookies)
        {
            if (builder.Length > 0)
            {
                _ = builder.Append("; ");
            }

            _ = builder.Append(entry.Key).Append('=').Append(entry.Value);
        }

        return builder.ToString();
    }

    /// <summary>Parses all query parameters from a <see cref="Uri"/> into a dictionary, or <see langword="null"/> when empty.</summary>
    /// <param name="uri">The URI to inspect.</param>
    /// <returns>The unescaped query parameter map, or <see langword="null"/>.</returns>
    private static Dictionary<string, string>? ParseQueryParameters(Uri uri)
    {
        var query = uri.Query.AsSpan().TrimStart('?');
        if (query.IsEmpty)
        {
            return null;
        }

        Dictionary<string, string> parameters = [with(StringComparer.Ordinal)];
        while (!query.IsEmpty)
        {
            var amp = query.IndexOf('&');
            var part = amp >= 0 ? query[..amp] : query;
            query = amp >= 0 ? query[(amp + 1)..] : ReadOnlySpan<char>.Empty;
            var eq = part.IndexOf('=');
            if (eq > 0)
            {
                parameters[Uri.UnescapeDataString(part[..eq])] = Uri.UnescapeDataString(part[(eq + 1)..]);
            }
        }

        return parameters.Count > 0 ? parameters : null;
    }

    /// <summary>Extracts a query parameter value from a <see cref="Uri"/>.</summary>
    /// <param name="uri">The URI to inspect.</param>
    /// <param name="parameterName">The parameter name.</param>
    /// <returns>The unescaped value, or <see langword="null"/> when absent.</returns>
    private static string? ExtractQueryParameter(Uri uri, string parameterName)
    {
        var query = uri.Query.AsSpan().TrimStart('?');
        while (!query.IsEmpty)
        {
            var amp = query.IndexOf('&');
            var part = amp >= 0 ? query[..amp] : query;
            query = amp >= 0 ? query[(amp + 1)..] : ReadOnlySpan<char>.Empty;
            var eq = part.IndexOf('=');
            if (eq > 0 && part[..eq].Equals(parameterName, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(part[(eq + 1)..]);
            }
        }

        return null;
    }

    /// <summary>Extracts a quoted attribute value (such as <c>name="..."</c> or <c>value='...'</c>) from an HTML tag slice.</summary>
    /// <param name="tag">The tag interior.</param>
    /// <param name="attributePrefix">The attribute name followed by <c>=</c> (for example <c>name=</c>).</param>
    /// <returns>The unquoted attribute value, or <see langword="null"/> when absent.</returns>
    private static string? ExtractQuotedAttribute(ReadOnlySpan<char> tag, string attributePrefix)
    {
        var remaining = tag;
        while (!remaining.IsEmpty)
        {
            var idx = remaining.IndexOf(attributePrefix, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                return null;
            }

            var afterPrefix = remaining[(idx + attributePrefix.Length)..];
            if (IsAttributeBoundary(remaining, idx) && TryExtractQuotedValue(afterPrefix, out var value))
            {
                return value;
            }

            remaining = afterPrefix;
        }

        return null;
    }

    /// <summary>Determines whether <paramref name="index"/> is preceded by a valid HTML attribute boundary.</summary>
    /// <param name="text">The tag interior.</param>
    /// <param name="index">The candidate attribute start index.</param>
    /// <returns>True when the character before <paramref name="index"/> is a boundary.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsAttributeBoundary(ReadOnlySpan<char> text, int index) =>
        index == 0 || char.IsWhiteSpace(text[index - 1]) || text[index - 1] is '"' or '\'';

    /// <summary>Extracts a single- or double-quoted value starting at the beginning of <paramref name="afterEquals"/>.</summary>
    /// <param name="afterEquals">The slice immediately following <c>=</c>.</param>
    /// <param name="value">Receives the unquoted attribute value when present.</param>
    /// <returns>True when <paramref name="afterEquals"/> starts with a quoted string.</returns>
    private static bool TryExtractQuotedValue(ReadOnlySpan<char> afterEquals, out string value)
    {
        var trimmed = afterEquals.TrimStart();
        if (trimmed.IsEmpty || trimmed[0] is not ('"' or '\''))
        {
            value = string.Empty;
            return false;
        }

        var quote = trimmed[0];
        var valueSlice = trimmed[1..];
        var close = valueSlice.IndexOf(quote);
        value = close >= 0 ? valueSlice[..close].ToString() : valueSlice.ToString();
        return true;
    }

    /// <summary>Extracts the decoded text of the first <c>&lt;span&gt;</c> element after <paramref name="marker"/>.</summary>
    /// <param name="html">The HTML text to search.</param>
    /// <param name="marker">The marker substring preceding the span.</param>
    /// <returns>The decoded span text, or <see langword="null"/> when not found.</returns>
    private static string? ExtractFirstSpanAfterMarker(ReadOnlySpan<char> html, string marker)
    {
        var markerIdx = html.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIdx < 0)
        {
            return null;
        }

        var afterMarker = html[markerIdx..];
        var spanStart = afterMarker.IndexOf("<span", StringComparison.OrdinalIgnoreCase);
        if (spanStart < 0)
        {
            return null;
        }

        var afterSpan = afterMarker[spanStart..];
        var closeBracket = afterSpan.IndexOf('>');
        if (closeBracket < 0)
        {
            return null;
        }

        var contentSlice = afterSpan[(closeBracket + 1)..];
        var endSpan = contentSlice.IndexOf("</span>", StringComparison.OrdinalIgnoreCase);
        var rawMessage = (endSpan >= 0 ? contentSlice[..endSpan] : contentSlice).Trim();
        return rawMessage.IsEmpty ? null : WebUtility.HtmlDecode(rawMessage.ToString()).Trim();
    }

    /// <summary>Extracts the decoded text between <paramref name="openTag"/> and <paramref name="closeTag"/>.</summary>
    /// <param name="html">The HTML text to search.</param>
    /// <param name="openTag">The opening tag.</param>
    /// <param name="closeTag">The closing tag.</param>
    /// <returns>The decoded inner text, or <see langword="null"/> when not found.</returns>
    private static string? ExtractElementText(ReadOnlySpan<char> html, string openTag, string closeTag)
    {
        var startIdx = html.IndexOf(openTag, StringComparison.OrdinalIgnoreCase);
        if (startIdx < 0)
        {
            return null;
        }

        var afterOpen = html[(startIdx + openTag.Length)..];
        var endIdx = afterOpen.IndexOf(closeTag, StringComparison.OrdinalIgnoreCase);
        if (endIdx <= 0)
        {
            return null;
        }

        var decoded = WebUtility.HtmlDecode(afterOpen[..endIdx].Trim().ToString()).Trim();
        return decoded.Length > 0 ? decoded : null;
    }
}
