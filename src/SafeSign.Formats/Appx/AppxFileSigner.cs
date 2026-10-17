// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using SafeSign.Signing;

namespace SafeSign.Formats.Appx;

/// <summary>Signs Windows APPX and MSIX packages (<c>.appx</c>, <c>.msix</c>, <c>.appxbundle</c>, <c>.msixbundle</c>) natively.</summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class AppxFileSigner : IFileFormatSigner
{
    /// <inheritdoc/>
    public string Name => "APPX/MSIX";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe)
    {
        var ext = probe.Extension;
        return (ext.Equals(".appx", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msix", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".appxbundle", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msixbundle", StringComparison.OrdinalIgnoreCase))
            && probe.Header.Span.StartsWith("PK\u0003\u0004"u8);
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

    /// <summary>Signs an APPX/MSIX package file at <paramref name="path"/> in place.</summary>
    /// <param name="path">The package file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var signed = await AppxPackageSigning.SignZipBytesAsync(raw, session, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(path, signed, cancellationToken).ConfigureAwait(false);
    }
}
