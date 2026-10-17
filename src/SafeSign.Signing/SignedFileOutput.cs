// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Signing;

/// <summary>Writes a signed file beside its destination first, so a failure never leaves a half-signed output.</summary>
public static class SignedFileOutput
{
    /// <summary>Copies the input to a temporary file next to the output, lets the caller sign it, then moves it into place.</summary>
    /// <param name="inputPath">The file to sign.</param>
    /// <param name="outputPath">The destination, which may equal <paramref name="inputPath"/>.</param>
    /// <param name="sign">Signs the temporary file at the given path.</param>
    /// <param name="cancellationToken">Cancels the copy and the signing.</param>
    /// <returns>A task that completes when the output is in place.</returns>
    public static async ValueTask WriteAsync(
        string inputPath,
        string outputPath,
        Func<string, CancellationToken, ValueTask> sign,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var directory = Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? Directory.GetCurrentDirectory();
        var temporary = Path.Combine(directory, $".{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.safesign");
        try
        {
            File.Copy(inputPath, temporary, overwrite: true);
            await sign(temporary, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, outputPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
