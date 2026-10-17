// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SafeSign.Providers.Oracle;

/// <summary>Builds OCI (Oracle Cloud Infrastructure) RSA-SHA256 HTTP request signatures (<c>Signature version="1",...</c>).</summary>
public static class OracleHttpSignature
{
    /// <summary>The list of HTTP headers signed by <see cref="SignPost"/>.</summary>
    private const string SignedHeaders = "(request-target) date host x-content-sha256 content-type content-length";

    /// <summary>Computes the <c>Authorization</c> header value, RFC 1123 <c>date</c>, and <c>x-content-sha256</c> for an OCI POST request.</summary>
    /// <param name="options">The OCI KMS options containing tenancy, user, fingerprint, and RSA private key.</param>
    /// <param name="pathAndQuery">The request path and query (for example <c>/20180608/sign</c>).</param>
    /// <param name="bodyBytes">The serialized UTF-8 JSON request body.</param>
    /// <param name="now">The current UTC timestamp.</param>
    /// <returns>The date, body digest, and authorization headers.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="pathAndQuery"/> is null or empty.</exception>
    public static OracleHttpSignatureHeaders SignPost(
        OracleCloudKmsOptions options,
        string pathAndQuery,
        ReadOnlySpan<byte> bodyBytes,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(pathAndQuery);

        var dateHeader = now.UtcDateTime.ToString("r", CultureInfo.InvariantCulture);
        Span<byte> bodyHash = stackalloc byte[SHA256.HashSizeInBytes];
        _ = SHA256.HashData(bodyBytes, bodyHash);
        var contentSha256 = Convert.ToBase64String(bodyHash);
        var host = options.CryptoEndpoint.IsDefaultPort
            ? options.CryptoEndpoint.Host
            : $"{options.CryptoEndpoint.Host}:{options.CryptoEndpoint.Port}";

        var prefix = $"(request-target): post {pathAndQuery}\ndate: {dateHeader}\nhost: {host}\n";
        var signingString = $"{prefix}x-content-sha256: {contentSha256}\ncontent-type: application/json\ncontent-length: {bodyBytes.Length}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(options.PrivateKeyPem);
        var sigBytes = rsa.SignData(
            Encoding.ASCII.GetBytes(signingString),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var sigBase64 = Convert.ToBase64String(sigBytes);
        var keyId = $"{options.TenancyOcid}/{options.UserOcid}/{options.KeyFingerprint}";
        var authorization = $"Signature version=\"1\",keyId=\"{keyId}\",algorithm=\"rsa-sha256\",headers=\"{SignedHeaders}\",signature=\"{sigBase64}\"";
        return new(dateHeader, contentSha256, authorization);
    }
}
