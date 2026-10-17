// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Signing;

/// <summary>Signs one file format natively, embedding the signature where the format's own verifiers look for it.</summary>
public interface IFileFormatSigner
{
    /// <summary>Gets the format's display name, such as <c>PE</c> or <c>MSI</c>.</summary>
    string Name { get; }

    /// <summary>Decides from the file name and leading bytes whether this signer handles the file.</summary>
    /// <param name="probe">The file name and its first bytes.</param>
    /// <returns>True when this signer handles the file.</returns>
    bool CanSign(FileProbe probe);

    /// <summary>Signs a file, replacing any existing signature, and writes the result.</summary>
    /// <param name="request">The input, the output and the signing session.</param>
    /// <param name="cancellationToken">Cancels the work.</param>
    /// <returns>A task that completes when the signed file is written.</returns>
    ValueTask SignAsync(FileSignRequest request, CancellationToken cancellationToken);
}
