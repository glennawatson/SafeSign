// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace SafeSign.Providers.Aws;

/// <summary>
/// AWS Signature Version 4 request signing, implemented from the AWS General Reference
/// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
/// </summary>
public static class AwsSigV4
{
    /// <summary>Gets the algorithm identifier.</summary>
    public static string Algorithm => "AWS4-HMAC-SHA256";

    /// <summary>Formats a time as the <c>x-amz-date</c> value (<c>yyyyMMddTHHmmssZ</c>).</summary>
    /// <param name="timestamp">The time.</param>
    /// <returns>The formatted time.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string FormatAmzDate(DateTimeOffset timestamp) =>
        timestamp.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

    /// <summary>Builds the <c>Authorization</c> header value.</summary>
    /// <param name="input">The request.</param>
    /// <returns>The header value.</returns>
    public static string CreateAuthorization(in AwsSigV4Input input)
    {
        var signature = Convert.ToHexStringLower(HMACSHA256.HashData(SigningKey(input), Encoding.UTF8.GetBytes(StringToSign(input))));
        return $"{Algorithm} Credential={input.Credentials.AccessKeyId}/{Scope(input)}, SignedHeaders={SignedHeaders(input)}, Signature={signature}";
    }

    /// <summary>Builds the canonical request (task 1).</summary>
    /// <param name="input">The request.</param>
    /// <returns>The canonical request.</returns>
    public static string CanonicalRequest(in AwsSigV4Input input)
    {
        var builder = new StringBuilder();
        _ = builder.Append(input.Method).Append('\n')
            .Append(input.Uri.AbsolutePath).Append('\n')
            .Append(CanonicalQuery(input.Uri)).Append('\n');
        foreach (var header in SortedHeaders(input))
        {
            _ = builder.Append(header.Key).Append(':').Append(header.Value.Trim()).Append('\n');
        }

        return builder.Append('\n').Append(SignedHeaders(input)).Append('\n').Append(input.PayloadHash).ToString();
    }

    /// <summary>Builds the string to sign (task 2).</summary>
    /// <param name="input">The request.</param>
    /// <returns>The string to sign.</returns>
    public static string StringToSign(in AwsSigV4Input input)
    {
        var canonicalHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalRequest(input))));
        return $"{Algorithm}\n{FormatAmzDate(input.Timestamp)}\n{Scope(input)}\n{canonicalHash}";
    }

    /// <summary>Derives the signing key (task 3).</summary>
    /// <param name="input">The request.</param>
    /// <returns>The signing key.</returns>
    public static byte[] SigningKey(in AwsSigV4Input input)
    {
        var dateKey = HMACSHA256.HashData(Encoding.UTF8.GetBytes($"AWS4{input.Credentials.SecretAccessKey}"), Encoding.UTF8.GetBytes(ShortDate(input)));
        var regionKey = HMACSHA256.HashData(dateKey, Encoding.UTF8.GetBytes(input.Region));
        var serviceKey = HMACSHA256.HashData(regionKey, Encoding.UTF8.GetBytes(input.Service));
        return HMACSHA256.HashData(serviceKey, "aws4_request"u8);
    }

    /// <summary>Gets the credential scope.</summary>
    /// <param name="input">The request.</param>
    /// <returns>The scope.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string Scope(in AwsSigV4Input input) => $"{ShortDate(input)}/{input.Region}/{input.Service}/aws4_request";

    /// <summary>Gets the <c>yyyyMMdd</c> date of the request.</summary>
    /// <param name="input">The request.</param>
    /// <returns>The date.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string ShortDate(in AwsSigV4Input input) =>
        input.Timestamp.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

    /// <summary>Gets the signed header names, sorted and joined with semicolons.</summary>
    /// <param name="input">The request.</param>
    /// <returns>The signed headers list.</returns>
    private static string SignedHeaders(in AwsSigV4Input input)
    {
        var sorted = SortedHeaders(input);
        if (sorted.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (var i = 0; i < sorted.Length; i++)
        {
            if (i > 0)
            {
                _ = builder.Append(';');
            }

            _ = builder.Append(sorted[i].Key);
        }

        return builder.ToString();
    }

    /// <summary>Sorts the headers by name, ordinally.</summary>
    /// <param name="input">The request.</param>
    /// <returns>The sorted headers.</returns>
    private static KeyValuePair<string, string>[] SortedHeaders(in AwsSigV4Input input)
    {
        var headers = new KeyValuePair<string, string>[input.Headers.Count];
        for (var i = 0; i < headers.Length; i++)
        {
            headers[i] = input.Headers[i];
        }

        Array.Sort(headers, static (left, right) => string.CompareOrdinal(left.Key, right.Key));
        return headers;
    }

    /// <summary>Sorts the already-encoded query parameters by name.</summary>
    /// <param name="uri">The URI.</param>
    /// <returns>The canonical query string.</returns>
    private static string CanonicalQuery(Uri uri)
    {
        var query = uri.Query.TrimStart('?');
        if (query.Length == 0)
        {
            return string.Empty;
        }

        var parameters = query.Split('&');
        Array.Sort(parameters, StringComparer.Ordinal);
        return string.Join('&', parameters);
    }
}
