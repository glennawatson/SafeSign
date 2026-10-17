// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Formats.Asn1;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SafeSign.Formats.Compression;
using SafeSign.Signing;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.NuGet;

/// <summary>
/// Signs NuGet packages (<c>.nupkg</c>) natively according to the NuGet Package Signature Specification by
/// embedding an Author Primary Signature (<c>1.3.6.1.4.1.311.60.3.1</c>) with <c>SigningCertificateV2</c> at
/// <c>.signature.p7s</c>.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class NuGetFileSigner : IFileFormatSigner
{
    /// <summary>Extra capacity reserved for ZIP central directory overhead when adding an entry.</summary>
    private const int ZipMetadataSlack = 256;

    /// <summary>Gets the ZIP entry path for the NuGet package signature.</summary>
    public static string SignatureEntryPath => ".signature.p7s";

    /// <summary>Gets the OID for a NuGet Author Primary Signature (<c>id-cti-ets-proofOfOrigin</c> / <c>1.3.6.1.4.1.311.60.3.1</c>).</summary>
    public static string AuthorPrimarySignatureOid => "1.3.6.1.4.1.311.60.3.1";

    /// <inheritdoc/>
    public string Name => "NuGet";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) =>
        (probe.Extension.Equals(".nupkg", StringComparison.OrdinalIgnoreCase)
            || probe.Extension.Equals(".snupkg", StringComparison.OrdinalIgnoreCase))
        && probe.Header.Span.StartsWith("PK\u0003\u0004"u8);

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

    /// <summary>Strips any existing <c>.signature.p7s</c>, computes the NuGet archive hash, builds the CMS signature, and writes <c>.signature.p7s</c>.</summary>
    /// <param name="path">The <c>.nupkg</c> file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var rawBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var unsignedZip = StripExistingSignature(rawBytes);

        var hashOid = GetHashOid(session.DigestAlgorithm);
        var archiveHash = CryptographicOperations.HashData(session.DigestAlgorithm, unsignedZip);
        var signatureContentText = $"Version:1\n\n{hashOid}:{Convert.ToBase64String(archiveHash)}\n\n";
        var signatureContentBytes = Encoding.UTF8.GetBytes(signatureContentText);

        var contentWriter = new AsnWriter(AsnEncodingRules.DER);
        contentWriter.WriteOctetString(signatureContentBytes);
        var encodedOctetString = contentWriter.Encode();

        var signedAttributes = new CmsAttribute[]
        {
            CmsAttributes.SigningTime(TimeProvider.System.GetUtcNow()),
            EncodeAuthorCommitmentAttribute(),
            CmsAttributes.SigningCertificateV2(session.Certificate.Certificate),
        };

        var cmsContent = new CmsSignedContent(
            CmsOids.Data,
            encodedOctetString,
            signatureContentBytes,
            signedAttributes,
            CmsTimestampPlacement.Cms);

        var p7sBytes = await CmsSignedDataBuilder.CreateAsync(session, cmsContent, cancellationToken).ConfigureAwait(false);
        var signedZip = AppendSignatureEntry(unsignedZip, p7sBytes);
        await File.WriteAllBytesAsync(path, signedZip, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes any existing <c>.signature.p7s</c> entry from a ZIP archive.</summary>
    /// <param name="zipBytes">The input ZIP archive bytes.</param>
    /// <returns>The unsigned ZIP archive bytes.</returns>
    private static byte[] StripExistingSignature(byte[] zipBytes)
    {
        using var stream = MemoryStreams.OpenWrite(zipBytes.Length, out var getBytes);
        stream.Write(zipBytes);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            for (var i = archive.Entries.Count - 1; i >= 0; i--)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(archive.Entries[i].FullName, ".signature.p7s"))
                {
                    archive.Entries[i].Delete();
                }
            }
        }

        return getBytes();
    }

    /// <summary>Appends an uncompressed <c>.signature.p7s</c> entry to <paramref name="unsignedZip"/>.</summary>
    /// <param name="unsignedZip">The unsigned ZIP archive bytes.</param>
    /// <param name="p7sBytes">The DER-encoded CMS signature bytes.</param>
    /// <returns>The signed ZIP archive bytes.</returns>
    private static byte[] AppendSignatureEntry(byte[] unsignedZip, byte[] p7sBytes)
    {
        using var stream = MemoryStreams.OpenWrite(unsignedZip.Length + p7sBytes.Length + ZipMetadataSlack, out var getBytes);
        stream.Write(unsignedZip);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            var entry = archive.CreateEntry(SignatureEntryPath, CompressionLevel.NoCompression);
            using var entryStream = entry.Open();
            entryStream.Write(p7sBytes);
        }

        return getBytes();
    }

    /// <summary>Encodes the <c>commitment-type-indication</c> signed attribute asserting <see cref="AuthorPrimarySignatureOid"/>.</summary>
    /// <returns>The encoded <see cref="CmsAttribute"/>.</returns>
    private static CmsAttribute EncodeAuthorCommitmentAttribute()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(AuthorPrimarySignatureOid);
        }

        return CmsAttributes.Single(CmsOids.CommitmentTypeIndication, writer.Encode());
    }

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to its NuGet hash algorithm OID.</summary>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The OID string.</returns>
    /// <exception cref="NotSupportedException">The digest algorithm is not SHA-256, SHA-384, or SHA-512.</exception>
    private static string GetHashOid(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA256" => CmsOids.Sha256,
        "SHA384" => CmsOids.Sha384,
        "SHA512" => CmsOids.Sha512,
        _ => throw new NotSupportedException($"NuGet package signing does not support digest algorithm '{algorithm.Name}'."),
    };
}
