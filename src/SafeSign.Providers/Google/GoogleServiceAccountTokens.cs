// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Refit;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Google;

/// <summary>
/// Exchanges a service account key for an access token with a signed JWT bearer assertion
/// (https://developers.google.com/identity/protocols/oauth2/service-account#httprest).
/// </summary>
public static class GoogleServiceAccountTokens
{
    /// <summary>The assertion lifetime in seconds; Google allows at most one hour.</summary>
    private const int AssertionLifetimeSeconds = 3600;

    /// <summary>Gets the OAuth scope for Cloud KMS.</summary>
    public static string Scope => "https://www.googleapis.com/auth/cloudkms";

    /// <summary>Gets the default token endpoint when the key file names none.</summary>
    public static string DefaultTokenUri => "https://oauth2.googleapis.com/token";

    /// <summary>Reads a service account JSON key.</summary>
    /// <param name="json">The key file contents.</param>
    /// <returns>The key.</returns>
    /// <exception cref="ProviderConfigurationException">The file is not a service account key.</exception>
    public static GoogleServiceAccountKey ReadKey(ReadOnlySpan<byte> json)
    {
        var key = JsonSerializer.Deserialize(json, GoogleServiceAccountJsonContext.Default.GoogleServiceAccountKey);
        return key is { ClientEmail.Length: > 0, PrivateKey.Length: > 0 }
            ? key
            : throw new ProviderConfigurationException("The Google credentials file is not a service account key (client_email and private_key are required).");
    }

    /// <summary>Builds and signs the RS256 JWT assertion.</summary>
    /// <param name="key">The service account key.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The compact JWT.</returns>
    public static string CreateAssertion(GoogleServiceAccountKey key, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(key);
        var issuedAt = now.ToUnixTimeSeconds();
        GoogleJwtHeader jwtHeader = new("RS256", "JWT", key.PrivateKeyId);
        var header = JsonSerializer.SerializeToUtf8Bytes(jwtHeader, GoogleJsonContext.Default.GoogleJwtHeader);
        GoogleJwtClaims claims = new(key.ClientEmail, Scope, key.TokenUri ?? DefaultTokenUri, issuedAt, issuedAt + AssertionLifetimeSeconds);
        var payload = JsonSerializer.SerializeToUtf8Bytes(claims, GoogleJsonContext.Default.GoogleJwtClaims);
        var signingInput = $"{Base64Url.EncodeToString(header)}.{Base64Url.EncodeToString(payload)}";
        using var rsa = RSA.Create();
        rsa.ImportFromPem(key.PrivateKey);
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>Requests an access token for the service account.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="key">The service account key.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token.</returns>
    public static ValueTask<CachedAccessToken> RequestAsync(RefitSettings http, GoogleServiceAccountKey key, TimeProvider time, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(time);
        Dictionary<string, string> form = new(StringComparer.Ordinal) { ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer", ["assertion"] = CreateAssertion(key, time.GetUtcNow()) };
        return OAuthTokenClient.RequestAsync(http, new(key.TokenUri ?? DefaultTokenUri), form, time, cancellationToken);
    }
}
