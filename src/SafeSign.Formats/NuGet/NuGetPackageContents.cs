// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.IO.Compression;
using SafeSign.Signing;
using SafeSign.Signing.Pe;

namespace SafeSign.Formats.NuGet;

/// <summary>
/// Authenticode signs the managed and native libraries inside a NuGet package. A package signature only protects the
/// download; Windows features such as Smart App Control judge each extracted <c>.dll</c> by its own signature.
/// </summary>
internal static class NuGetPackageContents
{
    /// <summary>
    /// Signs every unsigned PE image (<c>.dll</c> and <c>.exe</c>) in an unsigned package and returns the updated package.
    /// Images that already carry a signature, such as third-party binaries, are left untouched.
    /// </summary>
    /// <param name="unsignedZip">The package bytes without a <c>.signature.p7s</c> entry.</param>
    /// <param name="session">The signing session used for the package signature too.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>The package with signed contents, or <paramref name="unsignedZip"/> itself when nothing needed signing.</returns>
    internal static async ValueTask<byte[]> SignPeFilesAsync(byte[] unsignedZip, SigningSession session, CancellationToken cancellationToken)
    {
        var stream = new MemoryStream(unsignedZip.Length);
        await stream.WriteAsync(unsignedZip, cancellationToken).ConfigureAwait(false);

        var signedAny = false;
        await using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            // Snapshot first: replacing an entry changes the archive's entry list.
            var candidates = new List<ZipArchiveEntry>();
            foreach (var candidate in archive.Entries)
            {
                if (IsPeCandidate(candidate.FullName))
                {
                    candidates.Add(candidate);
                }
            }

            foreach (var entry in candidates)
            {
                var content = await ReadEntryAsync(entry, cancellationToken).ConfigureAwait(false);
                if (!IsUnsignedPe(content))
                {
                    continue;
                }

                var signed = await SignImageAsync(content, session, cancellationToken).ConfigureAwait(false);
                var name = entry.FullName;
                var modified = entry.LastWriteTime;
                entry.Delete();

                var replacement = archive.CreateEntry(name, CompressionLevel.Optimal);
                replacement.LastWriteTime = modified;
                var target = await replacement.OpenAsync(cancellationToken).ConfigureAwait(false);
                await using (target.ConfigureAwait(false))
                {
                    await target.WriteAsync(signed, cancellationToken).ConfigureAwait(false);
                }

                signedAny = true;
            }
        }

        return signedAny ? stream.ToArray() : unsignedZip;
    }

    /// <summary>Decides from the entry name whether it might be a PE image.</summary>
    /// <param name="fullName">The entry path.</param>
    /// <returns>True for <c>.dll</c> and <c>.exe</c> entries.</returns>
    private static bool IsPeCandidate(string fullName) =>
        fullName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
        || fullName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>Reads a whole entry into memory.</summary>
    /// <param name="entry">The entry.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The uncompressed entry bytes.</returns>
    private static async ValueTask<byte[]> ReadEntryAsync(ZipArchiveEntry entry, CancellationToken cancellationToken)
    {
        var source = await entry.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using (source.ConfigureAwait(false))
        {
            var buffer = new MemoryStream();
            await source.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
            return buffer.ToArray();
        }
    }

    /// <summary>Decides whether the bytes are a well-formed PE image with no certificate table.</summary>
    /// <param name="content">The entry bytes.</param>
    /// <returns>True when the image can be signed and is not already signed.</returns>
    private static bool IsUnsignedPe(byte[] content)
    {
        try
        {
            var required = PeLayoutReader.RequiredHeaderLength(content);
            return required > 0 && required <= content.Length && PeLayoutReader.Read(content, content.Length).CertificateTableSize == 0;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>Signs an in-memory PE image through a temporary file, which the PE signer needs for random access.</summary>
    /// <param name="content">The unsigned image.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>The signed image.</returns>
    private static async ValueTask<byte[]> SignImageAsync(byte[] content, SigningSession session, CancellationToken cancellationToken)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.safesign");
        try
        {
            await File.WriteAllBytesAsync(path, content, cancellationToken).ConfigureAwait(false);
            using (var file = File.OpenHandle(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None, FileOptions.Asynchronous))
            {
                await PeImageSigning.SignAsync(file, session, cancellationToken).ConfigureAwait(false);
            }

            return await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
