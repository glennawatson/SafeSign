// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Refit;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Aws;

/// <summary>Builds and sends KMS <c>Sign</c> requests through <see cref="IAwsKmsApi"/>.</summary>
public static class AwsKmsRequests
{
    /// <summary>Gets the AWS JSON 1.1 media type.</summary>
    private static string ContentType => "application/x-amz-json-1.1";

    /// <summary>Gets the <c>X-Amz-Target</c> value for <c>Sign</c>.</summary>
    private static string SignTarget => "TrentService.Sign";

    /// <summary>Gets the SigV4 signing name for KMS.</summary>
    private static string Service => "kms";

    /// <summary>Signs a digest with KMS.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="kind">The key family, from the certificate.</param>
    /// <param name="request">The digest.</param>
    /// <param name="now">The request time.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="ProviderRequestException">AWS KMS returned an error or an empty signature.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<byte[]> SignAsync(
        RefitSettings http,
        AwsKmsOptions options,
        PublicKeyKind kind,
        SignDigestRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        SignAsync(http, options, kind, request, now, TimeProvider.System, cancellationToken);

    /// <summary>Signs a digest with KMS using exponential backoff and fuzzy jitter.</summary>
    /// <param name="http">The Refit transport settings.</param>
    /// <param name="options">The options.</param>
    /// <param name="kind">The key family, from the certificate.</param>
    /// <param name="request">The digest.</param>
    /// <param name="now">The request time.</param>
    /// <param name="time">The clock used for retry delays.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="ProviderRequestException">AWS KMS returned an error or an empty signature.</exception>
    public static async ValueTask<byte[]> SignAsync(
        RefitSettings http,
        AwsKmsOptions options,
        PublicKeyKind kind,
        SignDigestRequest request,
        DateTimeOffset now,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        var endpoint = options.Endpoint ?? new Uri($"https://kms.{options.Region}.amazonaws.com/");
        var body = new AwsKmsSignRequest(options.KeyId, request.Digest, "DIGEST", SigningAlgorithm(kind, request.HashAlgorithm));
        var payload = JsonSerializer.SerializeToUtf8Bytes(body, AwsKmsJsonContext.Default.AwsKmsSignRequest);
        var amzDate = AwsSigV4.FormatAmzDate(now);

        List<KeyValuePair<string, string>> headers =
        [
            new("content-type", ContentType),
            new("host", endpoint.Authority),
            new("x-amz-date", amzDate),
            new("x-amz-target", SignTarget),
        ];
        var sessionToken = options.Credentials.SessionToken is { Length: > 0 } token ? token : null;
        if (sessionToken is not null)
        {
            headers.Add(new("x-amz-security-token", sessionToken));
        }

        var input = new AwsSigV4Input("POST", endpoint, headers, Convert.ToHexStringLower(SHA256.HashData(payload)), options.Region, Service, options.Credentials, now);
        var authorization = AwsSigV4.CreateAuthorization(input);

        var api = RestService.ForGenerated<IAwsKmsApi>(ProviderHttp.Authority(endpoint), ProviderHttp.CreateSettings(AwsKmsJsonContext.Default, http));
        var path = endpoint.PathAndQuery.TrimStart('/');
        using var response = await ProviderRetry.ExecuteHttpAsync(
            async ct =>
            {
                using var content = ProviderHttp.Bytes(payload, ContentType);
                return await api.SendAsync(
                    path,
                    amzDate,
                    SignTarget,
                    authorization,
                    sessionToken,
                    content,
                    ct).ConfigureAwait(false);
            },
            time,
            cancellationToken).ConfigureAwait(false);
        var reply = await ProviderHttp.ReadJsonAsync(response, AwsKmsJsonContext.Default.AwsKmsSignResponse, $"POST {endpoint}", cancellationToken).ConfigureAwait(false);
        return reply.Signature.IsEmpty ? throw new ProviderRequestException("AWS KMS returned no signature.") : reply.Signature.ToArray();
    }

    /// <summary>Maps the key family and digest to a KMS signing algorithm.</summary>
    /// <param name="kind">The key family.</param>
    /// <param name="hash">The digest algorithm.</param>
    /// <returns>The KMS algorithm name.</returns>
    /// <exception cref="NotSupportedException">The key family and digest algorithm combination is not supported.</exception>
    public static string SigningAlgorithm(PublicKeyKind kind, HashAlgorithmName hash) => (kind, hash.Name) switch
    {
        (PublicKeyKind.Rsa, "SHA256") => "RSASSA_PKCS1_V1_5_SHA_256",
        (PublicKeyKind.Rsa, "SHA384") => "RSASSA_PKCS1_V1_5_SHA_384",
        (PublicKeyKind.Rsa, "SHA512") => "RSASSA_PKCS1_V1_5_SHA_512",
        (PublicKeyKind.Ecdsa, "SHA256") => "ECDSA_SHA_256",
        (PublicKeyKind.Ecdsa, "SHA384") => "ECDSA_SHA_384",
        (PublicKeyKind.Ecdsa, "SHA512") => "ECDSA_SHA_512",
        _ => throw new NotSupportedException($"AWS KMS cannot sign a {hash.Name} digest with a {kind} key."),
    };
}
