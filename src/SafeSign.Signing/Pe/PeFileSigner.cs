// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace SafeSign.Signing.Pe;

/// <summary>Signs PE images (<c>.exe</c>, <c>.dll</c>, <c>.sys</c>, <c>.efi</c> and other MZ files) with an embedded Authenticode signature.</summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class PeFileSigner : IFileFormatSigner
{
    /// <inheritdoc/>
    public string Name => "PE";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) => probe.Header.Span.StartsWith("MZ"u8);

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask SignAsync(FileSignRequest request, CancellationToken cancellationToken) =>
        SignedFileOutput.WriteAsync(
            request.InputPath,
            request.OutputPath,
            (path, token) => SignPathAsync(path, request.Session, token),
            cancellationToken);

    /// <summary>Opens a file and signs it in place.</summary>
    /// <param name="path">The file.</param>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>A task that completes when the file is signed.</returns>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous);
        await PeImageSigning.SignAsync(file, session, cancellationToken).ConfigureAwait(false);
    }
}
