// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeSign.Formats.Compression;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Appx;

/// <summary>
/// Implements the APPX/MSIX/NAVX composite digest (<c>AXPC</c> / <c>AXCI</c> / <c>AXBM</c> / <c>AXCD</c>) and embeds
/// <c>AppxSignature.p7x</c> (<c>PKCX</c> magic + Authenticode PKCS #7 <c>SignedData</c>).
/// </summary>
public static class AppxPackageSigning
{
    /// <summary>The <c>SpcSipInfo</c> version expected by the Windows APPX/MSIX SIP (<c>0x01000000</c>).</summary>
    private const int AppxSipVersion = 0x01000000;

    /// <summary>The byte length of the <c>PKCX</c> header prefix.</summary>
    private const int PkcxMagicLength = 4;

    /// <summary>Extra capacity reserved for ZIP central directory overhead when adding an entry.</summary>
    private const int ZipMetadataSlack = 256;

    /// <summary>The ZIP End of Central Directory (EOCD) signature (<c>0x06054B50</c>).</summary>
    private const uint EocdSignature = 0x06054B50;

    /// <summary>The ZIP Local File Header signature (<c>0x04034B50</c>).</summary>
    private const uint LocalHeaderSignature = 0x04034B50;

    /// <summary>The minimum size of a ZIP End of Central Directory record.</summary>
    private const int MinEocdLength = 22;

    /// <summary>The fixed size of a ZIP Local File Header.</summary>
    private const int LocalHeaderFixedLength = 30;

    /// <summary>The fixed size of a ZIP Central Directory Header.</summary>
    private const int CentralHeaderFixedLength = 46;

    /// <summary>The offset of the central directory byte size in the EOCD record.</summary>
    private const int EocdCentralDirSizeOffset = 12;

    /// <summary>The offset of the central directory start offset in the EOCD record.</summary>
    private const int EocdCentralDirOffsetOffset = 16;

    /// <summary>The offset of the compressed size in a Central Directory header.</summary>
    private const int CentralCompressedSizeOffset = 20;

    /// <summary>The offset of the file name length in a Central Directory header.</summary>
    private const int CentralNameLengthOffset = 28;

    /// <summary>The offset of the extra field length in a Central Directory header.</summary>
    private const int CentralExtraLengthOffset = 30;

    /// <summary>The offset of the comment length in a Central Directory header.</summary>
    private const int CentralCommentLengthOffset = 32;

    /// <summary>The offset of the local header offset in a Central Directory header.</summary>
    private const int CentralLocalHeaderOffset = 42;

    /// <summary>The offset of the file name length in a Local File Header.</summary>
    private const int LocalNameLengthOffset = 26;

    /// <summary>The offset of the extra field length in a Local File Header.</summary>
    private const int LocalExtraLengthOffset = 28;

    /// <summary>The Windows APPX and MSIX Subject Interface Package unique identifier.</summary>
    private static readonly Guid AppxSipGuid = new("4BDFC50A-07CE-4FB2-B76E-23C839A09FD1");

    /// <summary>Gets the ZIP entry name of the embedded APPX/MSIX signature.</summary>
    public static string SignatureEntryName => "AppxSignature.p7x";

    /// <summary>Gets the ZIP entry name of the OPC content types manifest.</summary>
    public static string ContentTypesEntryName => "[Content_Types].xml";

    /// <summary>Gets the ZIP entry name of the APPX block map.</summary>
    public static string BlockMapEntryName => "AppxBlockMap.xml";

    /// <summary>Gets the ZIP entry name of the optional code integrity catalog.</summary>
    public static string CodeIntegrityEntryName => "AppxMetadata/CodeIntegrity.cat";

    /// <summary>Signs an APPX/MSIX/NAVX ZIP payload and returns the signed ZIP bytes containing <c>AppxSignature.p7x</c>.</summary>
    /// <param name="zipBytes">The input ZIP archive bytes.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The signed ZIP archive bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="session"/> is null.</exception>
    public static async ValueTask<byte[]> SignZipBytesAsync(
        ReadOnlyMemory<byte> zipBytes,
        SigningSession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        var preparedZip = PrepareUnsignedZip(zipBytes);
        var compositeDigest = ComputeAppxCompositeDigest(preparedZip, session.DigestAlgorithm);

        var pkcs7 = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(AppxSipVersion, AppxSipGuid), compositeDigest),
            cancellationToken).ConfigureAwait(false);

        var p7x = new byte[PkcxMagicLength + pkcs7.Length];
        "PKCX"u8.CopyTo(p7x);
        pkcs7.CopyTo(p7x.AsSpan(PkcxMagicLength));

        return AppendSignatureEntry(preparedZip, p7x);
    }

    /// <summary>Removes any existing <c>AppxSignature.p7x</c> entry and ensures <c>[Content_Types].xml</c> declares the signature part override.</summary>
    /// <param name="zipBytes">The input ZIP archive bytes.</param>
    /// <returns>The prepared unsigned ZIP bytes.</returns>
    private static byte[] PrepareUnsignedZip(ReadOnlyMemory<byte> zipBytes)
    {
        using var stream = MemoryStreams.OpenWrite(zipBytes.Length, out var getBytes);
        stream.Write(zipBytes.Span);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            for (var i = archive.Entries.Count - 1; i >= 0; i--)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(archive.Entries[i].FullName, "AppxSignature.p7x"))
                {
                    archive.Entries[i].Delete();
                }
            }

            EnsureContentTypesIncludesSignature(archive);
        }

        return getBytes();
    }

    /// <summary>Ensures <c>[Content_Types].xml</c> exists and contains the <c>/AppxSignature.p7x</c> content-type override.</summary>
    /// <param name="archive">The ZIP archive opened in update mode.</param>
    /// <exception cref="InvalidDataException">The package is missing <c>[Content_Types].xml</c> or <c>AppxBlockMap.xml</c>.</exception>
    private static void EnsureContentTypesIncludesSignature(ZipArchive archive)
    {
        _ = archive.GetEntry(BlockMapEntryName)
            ?? throw new InvalidDataException($"The package does not contain '{BlockMapEntryName}'.");

        var contentTypesEntry = archive.GetEntry(ContentTypesEntryName)
            ?? throw new InvalidDataException($"The package does not contain '{ContentTypesEntryName}'.");

        string xmlText;
        using (var reader = new StreamReader(contentTypesEntry.Open(), Encoding.UTF8))
        {
            xmlText = reader.ReadToEnd();
        }

        if (xmlText.Contains("/AppxSignature.p7x", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        const string closingTag = "</Types>";
        var closeIdx = xmlText.LastIndexOf(closingTag, StringComparison.OrdinalIgnoreCase);
        if (closeIdx < 0)
        {
            return;
        }

        const string overrideTag = "<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>";
        var updatedXml = string.Concat(xmlText.AsSpan(0, closeIdx), overrideTag, xmlText.AsSpan(closeIdx));
        contentTypesEntry.Delete();
        var replacement = archive.CreateEntry(ContentTypesEntryName, CompressionLevel.Optimal);
        using var writerStream = replacement.Open();
        writerStream.Write(Encoding.UTF8.GetBytes(updatedXml));
    }

    /// <summary>Computes the APPX composite digest (<c>AXPC</c> + <c>AXCI</c> + <c>AXBM</c> + <c>AXCD</c>) over the unsigned ZIP archive.</summary>
    /// <param name="zip">The unsigned ZIP archive bytes.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The composite digest bytes.</returns>
    /// <exception cref="InvalidDataException">The ZIP central directory or required APPX parts could not be located.</exception>
    private static byte[] ComputeAppxCompositeDigest(ReadOnlySpan<byte> zip, HashAlgorithmName algorithm)
    {
        var eocdOffset = FindEocdOffset(zip);
        var centralSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocdOffset + EocdCentralDirSizeOffset)..]);
        var centralOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip[(eocdOffset + EocdCentralDirOffsetOffset)..]);
        var centralDir = zip.Slice(centralOffset, centralSize);

        var axpcDigest = HashRawPart(zip, centralDir, ContentTypesEntryName, algorithm, required: true);
        var axciDigest = CryptographicOperations.HashData(algorithm, centralDir);
        var axbmDigest = HashRawPart(zip, centralDir, BlockMapEntryName, algorithm, required: true);
        var axcdDigest = HashRawPart(zip, centralDir, CodeIntegrityEntryName, algorithm, required: false);

        using var composite = IncrementalHash.CreateHash(algorithm);
        composite.AppendData("AXPC"u8);
        composite.AppendData(axpcDigest);
        composite.AppendData("AXCI"u8);
        composite.AppendData(axciDigest);
        composite.AppendData("AXBM"u8);
        composite.AppendData(axbmDigest);
        composite.AppendData("AXCD"u8);
        composite.AppendData(axcdDigest);
        return composite.GetHashAndReset();
    }

    /// <summary>Finds a part in the ZIP central directory and hashes its raw compressed bytes in the archive.</summary>
    /// <param name="zip">The full ZIP archive bytes.</param>
    /// <param name="centralDir">The central directory slice.</param>
    /// <param name="partName">The part name to locate.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <param name="required">Whether to throw if the part is absent.</param>
    /// <returns>The digest of the raw compressed part data, or an empty array when an optional part is absent.</returns>
    /// <exception cref="InvalidDataException">A required part is missing or its local header is malformed.</exception>
    private static byte[] HashRawPart(
        ReadOnlySpan<byte> zip,
        ReadOnlySpan<byte> centralDir,
        string partName,
        HashAlgorithmName algorithm,
        bool required)
    {
        var step = 0;
        for (var pos = 0; pos + CentralHeaderFixedLength <= centralDir.Length; pos += step)
        {
            var entry = centralDir[pos..];
            var compressedSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralCompressedSizeOffset..]);
            var nameLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralNameLengthOffset..]);
            var extraLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralExtraLengthOffset..]);
            var commentLen = BinaryPrimitives.ReadUInt16LittleEndian(entry[CentralCommentLengthOffset..]);
            var localOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(entry[CentralLocalHeaderOffset..]);
            var nameSpan = entry.Slice(CentralHeaderFixedLength, nameLen);

            if (Encoding.UTF8.GetString(nameSpan).Equals(partName, StringComparison.OrdinalIgnoreCase))
            {
                var localHeader = zip[localOffset..];
                if (localHeader.Length < LocalHeaderFixedLength
                    || BinaryPrimitives.ReadUInt32LittleEndian(localHeader) != LocalHeaderSignature)
                {
                    throw new InvalidDataException($"Invalid ZIP local file header for '{partName}'.");
                }

                var localNameLen = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[LocalNameLengthOffset..]);
                var localExtraLen = BinaryPrimitives.ReadUInt16LittleEndian(localHeader[LocalExtraLengthOffset..]);
                var dataStart = localOffset + LocalHeaderFixedLength + localNameLen + localExtraLen;
                return CryptographicOperations.HashData(algorithm, zip.Slice(dataStart, compressedSize));
            }

            step = CentralHeaderFixedLength + nameLen + extraLen + commentLen;
        }

        return required
            ? throw new InvalidDataException($"Required APPX part '{partName}' was not found in the central directory.")
            : [];
    }

    /// <summary>Finds the offset of the ZIP End of Central Directory record.</summary>
    /// <param name="zip">The ZIP archive bytes.</param>
    /// <returns>The byte offset of the EOCD record.</returns>
    /// <exception cref="InvalidDataException">No EOCD signature was found.</exception>
    private static int FindEocdOffset(ReadOnlySpan<byte> zip)
    {
        for (var i = zip.Length - MinEocdLength; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip[i..]) == EocdSignature)
            {
                return i;
            }
        }

        throw new InvalidDataException("The package is not a valid ZIP archive (End of Central Directory record not found).");
    }

    /// <summary>Appends <c>AppxSignature.p7x</c> to the unsigned ZIP archive.</summary>
    /// <param name="unsignedZip">The unsigned ZIP archive bytes.</param>
    /// <param name="p7xBytes">The <c>PKCX</c>-prefixed signature bytes.</param>
    /// <returns>The signed ZIP archive bytes.</returns>
    private static byte[] AppendSignatureEntry(byte[] unsignedZip, byte[] p7xBytes)
    {
        using var stream = MemoryStreams.OpenWrite(unsignedZip.Length + p7xBytes.Length + ZipMetadataSlack, out var getBytes);
        stream.Write(unsignedZip);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Update, leaveOpen: true))
        {
            var entry = archive.CreateEntry(SignatureEntryName, CompressionLevel.Optimal);
            using var entryStream = entry.Open();
            entryStream.Write(p7xBytes);
        }

        return getBytes();
    }
}
