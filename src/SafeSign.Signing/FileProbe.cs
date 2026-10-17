// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing;

/// <summary>What a format signer sees when deciding whether it handles a file.</summary>
/// <param name="Path">The file path.</param>
/// <param name="Header">The file's first bytes, up to <see cref="HeaderLength"/>.</param>
[DebuggerDisplay("{Path,nq} ({Header.Length} header bytes)")]
public readonly record struct FileProbe(string Path, ReadOnlyMemory<byte> Header)
{
    /// <summary>One page is enough for every format's magic number and header.</summary>
    private const int ProbeLength = 4096;

    /// <summary>Gets how many leading bytes a probe carries.</summary>
    public static int HeaderLength => ProbeLength;

    /// <summary>Gets the file extension of <see cref="Path"/>, including the leading period.</summary>
    public string Extension => System.IO.Path.GetExtension(Path);
}
