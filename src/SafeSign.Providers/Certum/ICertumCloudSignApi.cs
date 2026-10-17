// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.Certum;

/// <summary>
/// The Certum SimplySign (<c>cloudsign.webnotarius.pl</c>) REST surface for CAS OAuth 2.0 login and
/// SCS1_ATOM asynchronous card, certificate, and digest-signing tasks.
/// </summary>
public interface ICertumCloudSignApi
{
    /// <summary>Starts the CAS OAuth 2.0 authorization-code flow at <c>/idp/oauth2.0/authorize</c>.</summary>
    /// <param name="responseType">Always <c>code</c>.</param>
    /// <param name="clientId">The OAuth 2.0 client identifier.</param>
    /// <param name="redirectUri">The OAuth 2.0 redirect URI.</param>
    /// <param name="scope">The OAuth 2.0 scope.</param>
    /// <param name="apiKey">Empty string for public desktop login.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The HTTP response (either the login page or a 302 redirect to it).</returns>
    [Get("/idp/oauth2.0/authorize")]
    Task<HttpResponseMessage> AuthorizeAsync(
        [Query][AliasAs("response_type")] string responseType,
        [Query][AliasAs("client_id")] string clientId,
        [Query][AliasAs("redirect_uri")] string redirectUri,
        [Query][AliasAs("scope")] string scope,
        [Query][AliasAs("api_key")] string apiKey,
        CancellationToken cancellationToken);

    /// <summary>Follows a relative or root-relative GET URL during CAS login redirects.</summary>
    /// <param name="path">The relative path without query string.</param>
    /// <param name="query">Optional query string parameters from the redirect target.</param>
    /// <param name="cookie">Optional <c>Cookie</c> header carrying CAS session cookies across hops.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The HTTP response.</returns>
    [Get("/{**path}")]
    Task<HttpResponseMessage> FollowLoginGetAsync(
        string path,
        [Query] Dictionary<string, string>? query,
        [Header("Cookie")] string? cookie,
        CancellationToken cancellationToken);

    /// <summary>Submits the CAS login form (email + 6-digit OTP) to <c>/idp/login</c>.</summary>
    /// <param name="service">The optional CAS <c>service</c> query parameter from the login page URL.</param>
    /// <param name="cookie">Optional <c>Cookie</c> header carrying CAS session cookies.</param>
    /// <param name="form">The form fields (<c>username</c>, <c>password</c>, <c>execution</c>, <c>_eventId</c>, <c>submit</c>, <c>lt</c>, <c>geolocation</c>).</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The HTTP response (redirect chain carrying <c>?code=...</c>).</returns>
    [Post("/idp/login")]
    Task<HttpResponseMessage> SubmitLoginAsync(
        [Query][AliasAs("service")] string? service,
        [Header("Cookie")] string? cookie,
        [Body(BodySerializationMethod.UrlEncoded)] Dictionary<string, string> form,
        CancellationToken cancellationToken);

    /// <summary>Exchanges an authorization code for a bearer access token at <c>/idp/oauth2.0/accessToken</c>.</summary>
    /// <param name="clientId">The OAuth 2.0 client identifier.</param>
    /// <param name="clientSecret">The OAuth 2.0 client secret.</param>
    /// <param name="scope">The OAuth 2.0 scope.</param>
    /// <param name="code">The authorization code recovered from the CAS redirect.</param>
    /// <param name="redirectUri">The OAuth 2.0 redirect URI.</param>
    /// <param name="grantType">Always <c>authorization_code</c>.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The token response.</returns>
    [Post("/idp/oauth2.0/accessToken")]
    Task<IApiResponse<CertumTokenResponse>> ExchangeAuthorizationCodeAsync(
        [Query][AliasAs("client_id")] string clientId,
        [Query][AliasAs("client_secret")] string clientSecret,
        [Query][AliasAs("scope")] string scope,
        [Query][AliasAs("code")] string code,
        [Query][AliasAs("redirect_uri")] string redirectUri,
        [Query][AliasAs("grant_type")] string grantType,
        CancellationToken cancellationToken);

    /// <summary>Exchanges a refresh token for a new bearer access token at <c>/idp/oauth2.0/accessToken</c>.</summary>
    /// <param name="clientId">The OAuth 2.0 client identifier.</param>
    /// <param name="clientSecret">The OAuth 2.0 client secret.</param>
    /// <param name="refreshToken">The OAuth 2.0 refresh token.</param>
    /// <param name="grantType">Always <c>refresh_token</c>.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The token response.</returns>
    [Post("/idp/oauth2.0/accessToken")]
    Task<IApiResponse<CertumTokenResponse>> RefreshTokenAsync(
        [Query][AliasAs("client_id")] string clientId,
        [Query][AliasAs("client_secret")] string clientSecret,
        [Query][AliasAs("refresh_token")] string refreshToken,
        [Query][AliasAs("grant_type")] string grantType,
        CancellationToken cancellationToken);

    /// <summary>Starts an asynchronous task to list virtual cards (<c>POST /card/v1/cards/tasks</c>).</summary>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="payload">An empty <c>application/json</c> body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The initial task response.</returns>
    [Headers("Accept: multipart/form-data, application/json")]
    [Post("/card/v1/cards/tasks")]
    Task<HttpResponseMessage> StartListCardsTaskAsync(
        [Header("Authorization")] string authorization,
        [Body] HttpContent payload,
        CancellationToken cancellationToken);

    /// <summary>Starts an asynchronous task to fetch certificates for a card (<c>POST /card/v1/cards/{serial}/certificates/tasks</c>).</summary>
    /// <param name="serial">The virtual card serial number (<c>cardno</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="payload">An empty <c>application/json</c> body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The initial task response.</returns>
    [Headers("Accept: multipart/form-data, application/json")]
    [Post("/card/v1/cards/{serial}/certificates/tasks")]
    Task<HttpResponseMessage> StartListCertificatesTaskAsync(
        string serial,
        [Header("Authorization")] string authorization,
        [Body] HttpContent payload,
        CancellationToken cancellationToken);

    /// <summary>Starts an asynchronous SCS1_ATOM signature task (<c>POST /card/v1/cards/{serial}/certificates/signature</c>).</summary>
    /// <param name="serial">The virtual card serial number (<c>cardno</c>).</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="form">The multipart form containing the <c>req</c> JSON part and the <c>certificate</c> PEM part.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The initial task response.</returns>
    [Headers("Accept: multipart/form-data, application/json")]
    [Post("/card/v1/cards/{serial}/certificates/signature")]
    Task<HttpResponseMessage> StartSignatureTaskAsync(
        string serial,
        [Header("Authorization")] string authorization,
        [Body] MultipartFormDataContent form,
        CancellationToken cancellationToken);

    /// <summary>Polls or fetches the result of an SCS1_ATOM task via its <c>atom:link</c> path.</summary>
    /// <param name="path">The relative path from <c>atom:link</c>.</param>
    /// <param name="authorization">The <c>Bearer</c> access token header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The poll or final result response.</returns>
    [Headers("Accept: multipart/form-data, application/json")]
    [Get("/{**path}")]
    Task<HttpResponseMessage> PollTaskAsync(
        string path,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);
}
