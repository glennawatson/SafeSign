// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.SslCom;

/// <summary>Configuration for <see cref="SslComESignerProvider"/> (SSL.com eSigner Cloud Signature Consortium v1 API).</summary>
/// <param name="CredentialId">The SSL.com eSigner credential ID.</param>
/// <param name="CertificateFile">The public certificate file path.</param>
/// <param name="AccessToken">The optional pre-acquired OAuth 2.0 Bearer token.</param>
/// <param name="ClientId">The optional OAuth 2.0 client ID when acquiring tokens dynamically.</param>
/// <param name="Username">The optional SSL.com username for OAuth 2.0 password grant.</param>
/// <param name="Password">The optional SSL.com password for OAuth 2.0 password grant.</param>
/// <param name="TotpSecret">The optional RFC 6238 TOTP base32 secret or <c>otpauth://</c> URI used to compute the eSigner OTP / SAD.</param>
/// <param name="Otp">The optional one-time password or SAD when <paramref name="TotpSecret"/> is omitted.</param>
/// <param name="BaseUri">The optional CSC service base URI (defaults to <c>https://ds.ssl.com</c>).</param>
/// <param name="OAuthTokenUri">The optional OAuth 2.0 token endpoint URI (defaults to <c>https://login.ssl.com/oauth2/token</c>).</param>
[DebuggerDisplay("CredentialId = {CredentialId}, BaseUri = {BaseUri}")]
public sealed record SslComESignerOptions(
    string CredentialId,
    string CertificateFile,
    string? AccessToken = null,
    string? ClientId = null,
    string? Username = null,
    string? Password = null,
    string? TotpSecret = null,
    string? Otp = null,
    Uri? BaseUri = null,
    Uri? OAuthTokenUri = null);
