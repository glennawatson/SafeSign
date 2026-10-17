// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace SafeSign.Signing.Cms;

/// <summary>Requests RFC 3161 timestamp tokens through a Refit client and checks them before use.</summary>
public static class Rfc3161TimestampClient
{
    /// <summary>The nonce length; 64 bits is enough to bind the response to this request.</summary>
    private const int NonceLength = 8;

    /// <summary>Gets the request media type from RFC 3161 section 3.4.</summary>
    private static string QueryMediaType => "application/timestamp-query";

    /// <summary>Gets the response media type from RFC 3161 section 3.4.</summary>
    private static string ReplyMediaType => "application/timestamp-reply";

    /// <summary>Timestamps a signature value.</summary>
    /// <param name="settings">The authority, digest algorithm, and Refit transport.</param>
    /// <param name="signature">The signature value the token vouches for.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token as an encoded CMS <c>ContentInfo</c>.</returns>
    /// <exception cref="CryptographicException">The authority's reply is not a valid token for this request.</exception>
    public static async ValueTask<byte[]> RequestAsync(
        TimestampSettings settings,
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken)
    {
        var hash = new byte[DigestAlgorithms.Length(settings.DigestAlgorithm)];
        _ = CryptographicOperations.HashData(settings.DigestAlgorithm, signature.Span, hash);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var request = Rfc3161TimestampRequest.CreateFromHash(hash, settings.DigestAlgorithm, nonce: nonce, requestSignerCertificates: true);

        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new(QueryMediaType);
        var path = settings.Authority.PathAndQuery.TrimStart('/');
        using var response = await settings.Api.TimestampAsync(path, content, cancellationToken).ConfigureAwait(false);
        _ = response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentType?.MediaType is { } mediaType
            && !string.Equals(mediaType, ReplyMediaType, StringComparison.OrdinalIgnoreCase))
        {
            throw new CryptographicException($"Timestamp authority {settings.Authority} answered with '{mediaType}', not '{ReplyMediaType}'.");
        }

        var reply = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

        // ProcessResponse checks the status, the nonce and the message imprint against this request.
        var token = request.ProcessResponse(reply, out _);
        if (!token.VerifySignatureForHash(hash, settings.DigestAlgorithm, out _))
        {
            throw new CryptographicException($"The token from {settings.Authority} does not verify against its own signing certificate.");
        }

        return token.AsSignedCms().Encode();
    }
}
