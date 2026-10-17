// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using System.Text.Json;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Certum;

/// <summary>Builds and parses <c>multipart/form-data</c> bodies for Certum SimplySign certificate and signature tasks.</summary>
public static class CertumMultipart
{
    /// <summary>The minimum length of a multipart boundary line (<c>--</c>).</summary>
    private const int MinBoundaryLength = 2;

    /// <summary>The length of a double CRLF header separator (<c>\r\n\r\n</c>).</summary>
    private const int DoubleCrLfLength = 4;

    /// <summary>The length of an LF-only double newline separator (<c>\n\n</c>).</summary>
    private const int DoubleLfLength = 2;

    /// <summary>Extracts the raw bytes of the <c>certificate</c> part from a <c>multipart/form-data</c> response body.</summary>
    /// <param name="body">The raw multipart body bytes.</param>
    /// <returns>The trimmed body bytes of the <c>certificate</c> part.</returns>
    /// <exception cref="ProviderRequestException">The body is not valid multipart or does not contain a <c>certificate</c> part.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] ExtractCertificatePart(ReadOnlySpan<byte> body) =>
        ExtractPart(body, "name=\"certificate\""u8);

    /// <summary>Extracts the raw bytes of a part whose headers contain <paramref name="headerNeedle"/> from a <c>multipart/form-data</c> body.</summary>
    /// <param name="body">The raw multipart body bytes.</param>
    /// <param name="headerNeedle">The UTF-8 header substring to match (for example <c>"name=\"certificate\""u8</c>).</param>
    /// <returns>The trimmed body bytes of the matching part.</returns>
    /// <exception cref="ProviderRequestException">The body is not valid multipart or does not contain the requested part.</exception>
    public static byte[] ExtractPart(ReadOnlySpan<byte> body, ReadOnlySpan<byte> headerNeedle)
    {
        var firstLineEnd = body.IndexOf((byte)'\n');
        var delimiter = firstLineEnd >= 0 ? TrimCrlf(body[..firstLineEnd]) : ReadOnlySpan<byte>.Empty;
        if (delimiter.Length < MinBoundaryLength || !delimiter.StartsWith("--"u8))
        {
            throw new ProviderRequestException("Certum multipart response does not start with a boundary line.");
        }

        var remaining = body[(firstLineEnd + 1)..];
        while (!remaining.IsEmpty)
        {
            var nextBoundary = remaining.IndexOf(delimiter);
            var chunk = TrimCrlf(nextBoundary >= 0 ? remaining[..nextBoundary] : remaining);
            if (TryExtractChunkBody(chunk, headerNeedle, out var content))
            {
                return content.ToArray();
            }

            if (nextBoundary < 0)
            {
                break;
            }

            remaining = remaining[(nextBoundary + delimiter.Length)..];
        }

        throw new ProviderRequestException("Certum multipart response did not contain the requested part.");
    }

    /// <summary>Builds the <c>multipart/form-data</c> request body for <c>POST /card/v1/cards/{serial}/certificates/signature</c>.</summary>
    /// <param name="digestHex">The lower-case hex digest to sign.</param>
    /// <param name="digestType">The Certum digest type (<c>SHA256</c>, <c>SHA384</c>, or <c>SHA512</c>).</param>
    /// <param name="certificatePem">The exact PEM certificate bytes returned when materializing the card.</param>
    /// <returns>The multipart form content ready to send.</returns>
    public static MultipartFormDataContent CreateSignatureForm(string digestHex, string digestType, ReadOnlyMemory<byte> certificatePem)
    {
        ArgumentException.ThrowIfNullOrEmpty(digestHex);
        ArgumentException.ThrowIfNullOrEmpty(digestType);
        CertumSignRequest request = new([digestHex], digestType);
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(request, CertumJsonContext.Default.CertumSignRequest);

        MultipartFormDataContent form = [];

        ByteArrayContent reqPart = new(jsonBytes);
        reqPart.Headers.ContentType = new("application/json");
        reqPart.Headers.ContentDisposition = new("form-data") { Name = "\"req\"" };
        form.Add(reqPart);

        ByteArrayContent certPart = new(certificatePem.ToArray());
        certPart.Headers.ContentType = new("application/octet-stream");
        certPart.Headers.ContentDisposition = new("form-data") { Name = "\"certificate\"", FileName = "\"blob\"" };
        form.Add(certPart);

        return form;
    }

    /// <summary>Attempts to extract the payload of a single multipart chunk if its headers contain <paramref name="headerNeedle"/>.</summary>
    /// <param name="chunk">The trimmed multipart chunk.</param>
    /// <param name="headerNeedle">The UTF-8 header substring to match.</param>
    /// <param name="content">Receives the trimmed body slice when matched.</param>
    /// <returns>True when the chunk matched <paramref name="headerNeedle"/>.</returns>
    private static bool TryExtractChunkBody(ReadOnlySpan<byte> chunk, ReadOnlySpan<byte> headerNeedle, out ReadOnlySpan<byte> content)
    {
        content = ReadOnlySpan<byte>.Empty;
        if (chunk.IsEmpty || chunk.SequenceEqual("--"u8))
        {
            return false;
        }

        var separatorLength = DoubleCrLfLength;
        var headerEnd = chunk.IndexOf("\r\n\r\n"u8);
        if (headerEnd < 0)
        {
            separatorLength = DoubleLfLength;
            headerEnd = chunk.IndexOf("\n\n"u8);
        }

        if (headerEnd < 0 || chunk[..headerEnd].IndexOf(headerNeedle) < 0)
        {
            return false;
        }

        content = TrimCrlf(chunk[(headerEnd + separatorLength)..]);
        return true;
    }

    /// <summary>Trims leading and trailing CR/LF bytes from a span.</summary>
    /// <param name="span">The input span.</param>
    /// <returns>The trimmed slice.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<byte> TrimCrlf(ReadOnlySpan<byte> span) =>
        span.Trim("\r\n"u8);
}
