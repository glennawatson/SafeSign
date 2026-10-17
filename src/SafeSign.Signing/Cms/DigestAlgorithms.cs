// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SafeSign.Signing.Cms;

/// <summary>Maps digest algorithms to their identifiers and hashes with them.</summary>
public static class DigestAlgorithms
{
    /// <summary>Gets the object identifier of a digest algorithm.</summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The OID.</returns>
    /// <exception cref="NotSupportedException">The algorithm is not SHA-256, SHA-384 or SHA-512.</exception>
    public static string Oid(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        nameof(HashAlgorithmName.SHA256) => CmsOids.Sha256,
        nameof(HashAlgorithmName.SHA384) => CmsOids.Sha384,
        nameof(HashAlgorithmName.SHA512) => CmsOids.Sha512,
        _ => throw new NotSupportedException($"Digest algorithm '{algorithm.Name}' is not supported; use SHA256, SHA384 or SHA512."),
    };

    /// <summary>Gets the digest length of an algorithm in bytes.</summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The length.</returns>
    /// <exception cref="NotSupportedException">The algorithm is not SHA-256, SHA-384 or SHA-512.</exception>
    public static int Length(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        nameof(HashAlgorithmName.SHA256) => SHA256.HashSizeInBytes,
        nameof(HashAlgorithmName.SHA384) => SHA384.HashSizeInBytes,
        nameof(HashAlgorithmName.SHA512) => SHA512.HashSizeInBytes,
        _ => throw new NotSupportedException($"Digest algorithm '{algorithm.Name}' is not supported; use SHA256, SHA384 or SHA512."),
    };

    /// <summary>Parses a digest algorithm name as written on a command line.</summary>
    /// <param name="name">The name, such as <c>sha256</c>.</param>
    /// <returns>The algorithm.</returns>
    /// <exception cref="NotSupportedException">The name is not SHA-256, SHA-384 or SHA-512.</exception>
    public static HashAlgorithmName Parse(string name) => name.ToUpperInvariant().Replace("-", string.Empty, StringComparison.Ordinal) switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Digest algorithm '{name}' is not supported; use sha256, sha384 or sha512."),
    };

    /// <summary>Writes an <c>AlgorithmIdentifier</c> with NULL parameters, the form Authenticode verifiers expect.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    public static void WriteIdentifier(AsnWriter writer, HashAlgorithmName algorithm)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid(algorithm));
            writer.WriteNull();
        }
    }
}
