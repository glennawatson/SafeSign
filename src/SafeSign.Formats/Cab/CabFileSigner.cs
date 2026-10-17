// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;

namespace SafeSign.Formats.Cab;

/// <summary>
/// Signs Microsoft Cabinet (<c>.cab</c>) archives natively by setting <c>cfhdrRESERVE_PRESENT</c> (<c>0x0004</c>),
/// writing the 24-byte Authenticode cabinet reserve header (<c>cbCFHeader = 20</c>), adjusting folder and file offsets,
/// and appending the 8-byte-aligned PKCS #7 <c>SignedData</c> structure.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class CabFileSigner : IFileFormatSigner
{
    /// <summary>The base size of <c>CFHEADER</c> without optional fields.</summary>
    private const int BaseHeaderSize = 36;

    /// <summary>The size of one <c>CFFOLDER</c> entry without per-folder reserve bytes.</summary>
    private const int FolderEntrySize = 8;

    /// <summary>The <c>CFHEADER.flags</c> bit for <c>cfhdrPREV_CABINET</c>.</summary>
    private const ushort FlagPrevCabinet = 0x0001;

    /// <summary>The <c>CFHEADER.flags</c> bit for <c>cfhdrNEXT_CABINET</c>.</summary>
    private const ushort FlagNextCabinet = 0x0002;

    /// <summary>The <c>CFHEADER.flags</c> bit for <c>cfhdrRESERVE_PRESENT</c>.</summary>
    private const ushort FlagReservePresent = 0x0004;

    /// <summary>The size of the <c>cbCFHeader</c>/<c>cbCFFolder</c>/<c>cbCFData</c> descriptor field.</summary>
    private const int ReserveSizesFieldLength = 4;

    /// <summary>The 20-byte Authenticode <c>abReserve</c> payload length (<c>0x0014</c>).</summary>
    private const ushort CabReservePayloadSize = 20;

    /// <summary>The total bytes added to <c>CFHEADER</c> when enabling the Authenticode reserve area (4 + 20 = 24).</summary>
    private const int TotalReserveAddition = ReserveSizesFieldLength + CabReservePayloadSize;

    /// <summary>The 32-bit little-endian header value at the start of <c>abReserve</c> (<c>00 00 10 00</c>).</summary>
    private const uint ReserveHeaderMagic = 0x00100000U;

    /// <summary>The byte alignment of the appended Authenticode PKCS #7 signature.</summary>
    private const int SignatureAlignment = 8;

    /// <summary>The number of trailing bytes in <c>abReserve</c> included in the Authenticode digest (bytes 56..59).</summary>
    private const int TrailingReserveHashBytes = 4;

    /// <summary>The offset of <c>cbCabinet</c> in <c>CFHEADER</c>.</summary>
    private const int OffsetCbCabinet = 8;

    /// <summary>The offset of <c>coffFiles</c> in <c>CFHEADER</c>.</summary>
    private const int OffsetCoffFiles = 16;

    /// <summary>The offset of <c>cFolders</c> in <c>CFHEADER</c>.</summary>
    private const int OffsetCFolders = 26;

    /// <summary>The offset of <c>flags</c> in <c>CFHEADER</c>.</summary>
    private const int OffsetFlags = 30;

    /// <summary>The offset of <c>iCabinet</c> in <c>CFHEADER</c> (skipped by the Authenticode digest).</summary>
    private const int OffsetICabinet = 34;

    /// <summary>The <c>SpcLink</c> context-specific choice tag for a file link.</summary>
    private const int SpcLinkFileTag = 2;

    /// <summary>The byte length of the <c>MSCF</c> signature magic.</summary>
    private const int SignatureMagicLength = 4;

    /// <summary>The offset of <c>cbCFFolder</c> relative to the reserve sizes field.</summary>
    private const int FolderReserveOffset = 2;

    /// <summary>The offset of <c>cbCFData</c> relative to the reserve sizes field.</summary>
    private const int DataReserveOffset = 3;

    /// <summary>Gets the <c>SPC_CAB_DATA_OBJID</c> object identifier (<c>1.3.6.1.4.1.311.2.1.25</c>).</summary>
    public static string SpcCabDataOid => "1.3.6.1.4.1.311.2.1.25";

    /// <inheritdoc/>
    public string Name => "CAB";

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) => probe.Header.Span.StartsWith("MSCF"u8);

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

    /// <summary>Signs a cabinet file at <paramref name="path"/> in place.</summary>
    /// <param name="path">The cabinet file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var raw = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var prepared = PrepareUnsignedWithReserve(raw);
        var digest = ComputeAuthenticodeDigest(prepared, session.DigestAlgorithm);
        var signature = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(SpcCabDataOid, EncodeCabDataValue(), digest),
            cancellationToken).ConfigureAwait(false);

        var padding = (SignatureAlignment - (signature.Length % SignatureAlignment)) % SignatureAlignment;
        var paddedSigLength = signature.Length + padding;
        var sigOffset = (uint)prepared.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(prepared.AsSpan(BaseHeaderSize + ReserveSizesFieldLength + sizeof(uint)), sigOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(prepared.AsSpan(BaseHeaderSize + ReserveSizesFieldLength + sizeof(ulong)), (uint)paddedSigLength);

        var output = new byte[prepared.Length + paddedSigLength];
        prepared.CopyTo(output, 0);
        signature.CopyTo(output, prepared.Length);
        await File.WriteAllBytesAsync(path, output, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Ensures the cabinet has the 24-byte Authenticode reserve block and strips any trailing signature.</summary>
    /// <param name="cab">The input cabinet bytes.</param>
    /// <returns>The unsigned cabinet bytes with the 24-byte reserve header in place.</returns>
    /// <exception cref="InvalidDataException">The cabinet header is malformed or uses unsupported multi-cabinet chaining.</exception>
    private static byte[] PrepareUnsignedWithReserve(ReadOnlySpan<byte> cab)
    {
        if (cab.Length < BaseHeaderSize || !cab.StartsWith("MSCF"u8))
        {
            throw new InvalidDataException("The file is not a valid Microsoft Cabinet (MSCF) archive.");
        }

        var cabinetSize = BinaryPrimitives.ReadUInt32LittleEndian(cab[OffsetCbCabinet..]);
        var filesOffset = BinaryPrimitives.ReadUInt32LittleEndian(cab[OffsetCoffFiles..]);
        var folderCount = BinaryPrimitives.ReadUInt16LittleEndian(cab[OffsetCFolders..]);
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(cab[OffsetFlags..]);

        if ((flags & (FlagPrevCabinet | FlagNextCabinet)) != 0)
        {
            throw new InvalidDataException("Multi-volume chained cabinet archives are not supported for Authenticode signing.");
        }

        if ((flags & FlagReservePresent) != 0)
        {
            var headerReserveSize = BinaryPrimitives.ReadUInt16LittleEndian(cab[BaseHeaderSize..]);
            var folderReserveSize = cab[BaseHeaderSize + FolderReserveOffset];
            var dataReserveSize = cab[BaseHeaderSize + DataReserveOffset];
            if (headerReserveSize != CabReservePayloadSize || folderReserveSize != 0 || dataReserveSize != 0)
            {
                throw new InvalidDataException("The cabinet contains a non-Authenticode custom reserve area.");
            }

            if (cabinetSize > (uint)cab.Length)
            {
                throw new InvalidDataException("The cabinet header cbCabinet exceeds the file length.");
            }

            var stripped = cab[..(int)cabinetSize].ToArray();
            stripped.AsSpan(BaseHeaderSize + ReserveSizesFieldLength, CabReservePayloadSize).Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(stripped.AsSpan(BaseHeaderSize + ReserveSizesFieldLength), ReserveHeaderMagic);
            return stripped;
        }

        var unsignedSlice = cab[..Math.Min(cab.Length, (int)cabinetSize)];
        var expanded = new byte[unsignedSlice.Length + TotalReserveAddition];
        unsignedSlice[..BaseHeaderSize].CopyTo(expanded);
        BinaryPrimitives.WriteUInt16LittleEndian(expanded.AsSpan(BaseHeaderSize), CabReservePayloadSize);
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(BaseHeaderSize + ReserveSizesFieldLength), ReserveHeaderMagic);
        unsignedSlice[BaseHeaderSize..].CopyTo(expanded.AsSpan(BaseHeaderSize + TotalReserveAddition));

        var newCabinetSize = (uint)expanded.Length;
        var newFilesOffset = filesOffset + TotalReserveAddition;
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(OffsetCbCabinet), newCabinetSize);
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(OffsetCoffFiles), newFilesOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(expanded.AsSpan(OffsetFlags), (ushort)(flags | FlagReservePresent));

        const int foldersStart = BaseHeaderSize + TotalReserveAddition;
        for (var i = 0; i < folderCount; i++)
        {
            var folderOffset = foldersStart + (i * FolderEntrySize);
            var folderDataStart = BinaryPrimitives.ReadUInt32LittleEndian(expanded.AsSpan(folderOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(folderOffset), folderDataStart + TotalReserveAddition);
        }

        return expanded;
    }

    /// <summary>Computes the Authenticode digest over a cabinet with its 24-byte reserve header.</summary>
    /// <param name="cab">The cabinet bytes up to <c>cbCabinet</c>.</param>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The Authenticode digest.</returns>
    private static byte[] ComputeAuthenticodeDigest(ReadOnlySpan<byte> cab, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);

        // Authenticode CAB hashing hashes MSCF (0..3), skips reserved1 (4..7), hashes cbCabinet..setID (8..33),
        // skips iCabinet (34..35) and the reserve header through byte 55 (36..55), hashes the last 4 bytes of
        // abReserve (56..59), and hashes the remaining folders, files, and data blocks (60..cbCabinet).
        hash.AppendData(cab[..SignatureMagicLength]);
        hash.AppendData(cab.Slice(OffsetCbCabinet, OffsetICabinet - OffsetCbCabinet));
        hash.AppendData(cab.Slice(BaseHeaderSize + TotalReserveAddition - TrailingReserveHashBytes, TrailingReserveHashBytes));
        hash.AppendData(cab[(BaseHeaderSize + TotalReserveAddition)..]);
        return hash.GetHashAndReset();
    }

    /// <summary>Encodes the <c>SpcCabData</c> (<c>SpcLink</c> obsolete file moniker) structure.</summary>
    /// <returns>The DER-encoded <c>SpcLink</c>.</returns>
    private static byte[] EncodeCabDataValue()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, SpcLinkFileTag, isConstructed: true)))
        {
            writer.WriteCharacterString(UniversalTagNumber.BMPString, "<<<Obsolete>>>", new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        return writer.Encode();
    }
}
