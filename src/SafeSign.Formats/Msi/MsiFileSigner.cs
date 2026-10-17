// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SafeSign.Formats.CompoundFile;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Msi;

/// <summary>
/// Signs Windows Installer (<c>.msi</c>, <c>.msp</c>, <c>.mst</c>) OLE Compound Files natively by writing
/// <c>\u0005MsiDigitalSignatureEx</c> and <c>\u0005DigitalSignature</c> into the root storage.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class MsiFileSigner : IFileFormatSigner
{
    /// <summary>The stream name for the extended MSI metadata pre-hash (<c>\x05MsiDigitalSignatureEx</c>).</summary>
    internal const string DigitalSignatureExStreamName = "\u0005MsiDigitalSignatureEx";

    /// <summary>The stream name for the PKCS #7 Authenticode signature (<c>\x05DigitalSignature</c>).</summary>
    internal const string DigitalSignatureStreamName = "\u0005DigitalSignature";

    /// <summary>The byte length of a GUID.</summary>
    private const int GuidByteLength = 16;

    /// <summary>The byte length of the storage metadata block hashed by <c>\x05MsiDigitalSignatureEx</c>.</summary>
    private const int MetadataBlockLength = 36;

    /// <summary>The offset of the creation time within the 36-byte metadata block.</summary>
    private const int MetadataCreatedOffset = 20;

    /// <summary>The offset of the modified time within the 36-byte metadata block.</summary>
    private const int MetadataModifiedOffset = 28;

    /// <summary>The Windows Installer Subject Interface Package unique identifier.</summary>
    private static readonly Guid MsiSipGuid = new("000C10F1-0000-0000-C000-000000000046");

    /// <inheritdoc/>
    public string Name => "MSI";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe)
    {
        var ext = probe.Extension;
        return (ext.Equals(".msi", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".msp", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".mst", StringComparison.OrdinalIgnoreCase))
            && CompoundFileFormat.HasSignature(probe.Header.Span);
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

    /// <summary>Signs an MSI compound file in place.</summary>
    /// <param name="path">The file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="InvalidDataException">The MSI compound file has no root storage.</exception>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var inputBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var root = CompoundFileReader.Read(inputBytes);
        var children = root.Children ?? throw new InvalidDataException("The MSI compound file has no root storage.");

        RemoveExistingSignatures(children);

        var extendedDigest = ComputeMsiDigitalSignatureEx(root, session.DigestAlgorithm);
        children.Add(new(DigitalSignatureExStreamName, default, extendedDigest, null));

        var fileDigest = ComputeAuthenticodeDigest(root, session.DigestAlgorithm);
        var signature = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(MsiSipGuid), fileDigest),
            cancellationToken).ConfigureAwait(false);

        children.Add(new(DigitalSignatureStreamName, default, signature, null));
        var signedBytes = CompoundFileWriter.Write(root);
        await File.WriteAllBytesAsync(path, signedBytes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes any existing <c>\x05DigitalSignature</c> and <c>\x05MsiDigitalSignatureEx</c> streams from <paramref name="children"/>.</summary>
    /// <param name="children">The root storage children.</param>
    private static void RemoveExistingSignatures(List<CompoundFileEntry> children)
    {
        for (var i = children.Count - 1; i >= 0; i--)
        {
            var name = children[i].Name;
            if (CompoundFileFormat.CompareNames(name, DigitalSignatureStreamName) == 0
                || CompoundFileFormat.CompareNames(name, DigitalSignatureExStreamName) == 0)
            {
                children.RemoveAt(i);
            }
        }
    }

    /// <summary>Computes the <c>\x05MsiDigitalSignatureEx</c> pre-hash over storage/stream metadata.</summary>
    /// <param name="root">The root storage.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The metadata pre-hash bytes.</returns>
    private static byte[] ComputeMsiDigitalSignatureEx(CompoundFileEntry root, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        HashEntryMetadata(hash, root, isRoot: true);
        return hash.GetHashAndReset();
    }

    /// <summary>Recursively hashes entry names and metadata in <see cref="CompoundFileFormat.CompareNames"/> order for <c>\x05MsiDigitalSignatureEx</c>.</summary>
    /// <param name="hash">The incremental hash.</param>
    /// <param name="entry">The entry.</param>
    /// <param name="isRoot">True for the root storage.</param>
    private static void HashEntryMetadata(IncrementalHash hash, CompoundFileEntry entry, bool isRoot)
    {
        if (!isRoot)
        {
            const int maxNameByteLength = 64;
            Span<byte> nameBuffer = stackalloc byte[maxNameByteLength];
            var nameBytes = nameBuffer[..(entry.Name.Length * sizeof(char))];
            for (var i = 0; i < entry.Name.Length; i++)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(nameBytes[(i * sizeof(char))..], entry.Name[i]);
            }

            hash.AppendData(nameBytes);
        }

        if (entry.Children is { } children)
        {
            Span<byte> meta = stackalloc byte[MetadataBlockLength];
            _ = entry.Metadata.Clsid.TryWriteBytes(meta[..GuidByteLength]);
            BinaryPrimitives.WriteUInt32LittleEndian(meta[GuidByteLength..], entry.Metadata.StateBits);
            BinaryPrimitives.WriteInt64LittleEndian(meta[MetadataCreatedOffset..], entry.Metadata.CreationTime);
            BinaryPrimitives.WriteInt64LittleEndian(meta[MetadataModifiedOffset..], entry.Metadata.ModifiedTime);
            hash.AppendData(meta);

            List<CompoundFileEntry> sorted = [.. children];
            sorted.Sort(static (a, b) => CompoundFileFormat.CompareNames(a.Name, b.Name));
            for (var i = 0; i < sorted.Count; i++)
            {
                var child = sorted[i];
                if (CompoundFileFormat.CompareNames(child.Name, DigitalSignatureStreamName) != 0
                    && CompoundFileFormat.CompareNames(child.Name, DigitalSignatureExStreamName) != 0)
                {
                    HashEntryMetadata(hash, child, isRoot: false);
                }
            }

            return;
        }

        Span<byte> sizeBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(sizeBytes, (uint)entry.Data.Length);
        hash.AppendData(sizeBytes);
    }

    /// <summary>Computes the Authenticode digest over the MSI storage tree (including <c>\x05MsiDigitalSignatureEx</c>, excluding <c>\x05DigitalSignature</c>).</summary>
    /// <param name="root">The root storage.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The Authenticode file digest.</returns>
    private static byte[] ComputeAuthenticodeDigest(CompoundFileEntry root, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        HashStorageStreams(hash, root);
        return hash.GetHashAndReset();
    }

    /// <summary>Recursively hashes stream contents and storage CLSIDs in <see cref="CompoundFileFormat.CompareNames"/> order.</summary>
    /// <param name="hash">The incremental hash.</param>
    /// <param name="storage">The storage entry.</param>
    private static void HashStorageStreams(IncrementalHash hash, CompoundFileEntry storage)
    {
        if (storage.Children is { } children)
        {
            List<CompoundFileEntry> sorted = [.. children];
            sorted.Sort(static (a, b) => CompoundFileFormat.CompareNames(a.Name, b.Name));
            for (var i = 0; i < sorted.Count; i++)
            {
                var child = sorted[i];
                if (CompoundFileFormat.CompareNames(child.Name, DigitalSignatureStreamName) == 0)
                {
                    continue;
                }

                if (child.Children is not null)
                {
                    HashStorageStreams(hash, child);
                }
                else if (!child.Data.IsEmpty)
                {
                    hash.AppendData(child.Data.Span);
                }
            }
        }

        Span<byte> clsid = stackalloc byte[GuidByteLength];
        _ = storage.Metadata.Clsid.TryWriteBytes(clsid);
        hash.AppendData(clsid);
    }
}
