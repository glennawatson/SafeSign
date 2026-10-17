// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Appx;

/// <summary>
/// Signs Dynamics 365 Business Central extension packages (<c>.navx</c>) natively by hashing the 40-byte
/// <c>NAVX</c> header plus inner package content and appending the <c>NXSB</c> Authenticode signature block.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class NavxFileSigner : IFileFormatSigner
{
    /// <summary>The length of the Dynamics 365 <c>NAVX</c> package header in bytes.</summary>
    internal const int NavxHeaderLength = 40;

    /// <summary>The offset of the 32-bit inner package content size field in the <c>NAVX</c> header.</summary>
    internal const int ContentSizeOffset = 28;

    /// <summary>The offset of the second <c>NAVX</c> magic marker at the end of the 40-byte header.</summary>
    internal const int SecondMagicOffset = 36;

    /// <summary>The <c>SpcSipInfo</c> version expected by the Dynamics 365 <c>NAVX</c> SIP (<c>1</c>).</summary>
    private const int NavxSipVersion = 1;

    /// <summary>The byte length of the <c>NAVX</c> and <c>NXSB</c> 4-byte magic markers.</summary>
    private const int MagicLength = 4;

    /// <summary>The total framing overhead of a <c>NXSB</c> signature block (<c>NXSB</c> + offset + <c>NXSB</c> = 12 bytes).</summary>
    private const int SignatureBlockOverhead = 12;

    /// <summary>The Dynamics 365 <c>NAVX</c> Subject Interface Package unique identifier (raw wire bytes <c>12341234-F804-0000-781D-123412341234</c>).</summary>
    private static readonly Guid NavxSipGuid = new("34123412-04F8-0000-781D-123412341234");

    /// <inheritdoc/>
    public string Name => "NAVX";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe)
    {
        var span = probe.Header.Span;
        return probe.Extension.Equals(".navx", StringComparison.OrdinalIgnoreCase)
            && span.Length >= NavxHeaderLength
            && span.StartsWith("NAVX"u8)
            && span[SecondMagicOffset..].StartsWith("NAVX"u8);
    }

    /// <inheritdoc/>
    public ValueTask SignAsync(FileSignRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return SignedFileOutput.WriteAsync(
            request.InputPath,
            request.OutputPath,
            (path, token) => SignPathAsync(path, request.Session, token),
            cancellationToken);
    }

    /// <summary>Signs a <c>.navx</c> package at <paramref name="path"/> in place.</summary>
    /// <param name="path">The <c>.navx</c> file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="InvalidDataException">The <c>.navx</c> header is truncated or invalid.</exception>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        if (raw.Length < NavxHeaderLength
            || !raw.AsSpan().StartsWith("NAVX"u8)
            || !raw.AsSpan(SecondMagicOffset).StartsWith("NAVX"u8))
        {
            throw new InvalidDataException("The file does not have a valid 40-byte Dynamics 365 NAVX header.");
        }

        var contentSize = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(ContentSizeOffset));
        if (contentSize < 0 || NavxHeaderLength + contentSize > raw.Length)
        {
            throw new InvalidDataException("The NAVX header content size is invalid or exceeds the file length.");
        }

        var signatureOffset = NavxHeaderLength + contentSize;
        var digest = CryptographicOperations.HashData(session.DigestAlgorithm, raw.AsSpan(0, signatureOffset));
        var pkcs7 = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(NavxSipVersion, NavxSipGuid), digest),
            cancellationToken).ConfigureAwait(false);

        var output = new byte[signatureOffset + pkcs7.Length + SignatureBlockOverhead];
        raw.AsSpan(0, signatureOffset).CopyTo(output);
        "NXSB"u8.CopyTo(output.AsSpan(signatureOffset));
        pkcs7.CopyTo(output.AsSpan(signatureOffset + MagicLength));
        BinaryPrimitives.WriteInt32LittleEndian(output.AsSpan(signatureOffset + MagicLength + pkcs7.Length), signatureOffset);
        "NXSB"u8.CopyTo(output.AsSpan(signatureOffset + MagicLength + pkcs7.Length + sizeof(int)));

        await File.WriteAllBytesAsync(path, output, cancellationToken).ConfigureAwait(false);
    }
}
