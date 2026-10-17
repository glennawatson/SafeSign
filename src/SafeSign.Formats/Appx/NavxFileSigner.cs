// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using SafeSign.Signing;

namespace SafeSign.Formats.Appx;

/// <summary>
/// Signs Dynamics 365 Business Central extension packages (<c>.navx</c>) natively by preserving the 40-byte
/// <c>NAVX</c> header, signing the embedded OPC/APPX ZIP archive with <c>AppxSignature.p7x</c>, and updating
/// the package length in the <c>NAVX</c> header.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class NavxFileSigner : IFileFormatSigner
{
    /// <summary>The length of the Dynamics 365 <c>NAVX</c> package header in bytes.</summary>
    internal const int NavxHeaderLength = 40;

    /// <summary>The offset of the <c>NAVX</c> magic marker within the 40-byte header.</summary>
    private const int MagicOffset = 4;

    /// <summary>The offset of the 32-bit inner OPC/APPX package size field in the <c>NAVX</c> header.</summary>
    private const int PackageSizeOffset = 12;

    /// <inheritdoc/>
    public string Name => "NAVX";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe)
    {
        var span = probe.Header.Span;
        return probe.Extension.Equals(".navx", StringComparison.OrdinalIgnoreCase)
            && span.Length >= NavxHeaderLength
            && span[MagicOffset..].StartsWith("NAVX"u8);
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
        if (raw.Length <= NavxHeaderLength || !raw.AsSpan(MagicOffset).StartsWith("NAVX"u8))
        {
            throw new InvalidDataException("The file does not have a valid 40-byte Dynamics 365 NAVX header.");
        }

        var signedZip = await AppxPackageSigning.SignZipBytesAsync(
            raw.AsMemory(NavxHeaderLength),
            session,
            cancellationToken).ConfigureAwait(false);

        var output = new byte[NavxHeaderLength + signedZip.Length];
        raw.AsSpan(0, NavxHeaderLength).CopyTo(output);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(PackageSizeOffset), (uint)signedZip.Length);
        signedZip.CopyTo(output.AsSpan(NavxHeaderLength));

        await File.WriteAllBytesAsync(path, output, cancellationToken).ConfigureAwait(false);
    }
}
