// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Signing;

namespace SafeSign.Formats.Rpm;

/// <summary>
/// Signs Red Hat Package Manager (<c>.rpm</c>) archives natively with IMA v2 file signatures
/// (<c>RPMTAG_FILESIGNATURES</c> <c>5090</c> and <c>RPMTAG_FILESIGNATURELENGTH</c> <c>5091</c>)
/// and recomputes the Signature Header digests (<c>SHA256</c>, <c>SHA1</c>, <c>MD5</c>, <c>SIZE</c>).
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class RpmFileSigner : IFileFormatSigner
{
    /// <summary>The file digests tag (<c>RPMTAG_FILEDIGESTS</c>).</summary>
    internal const int TagFileDigests = 1035;

    /// <summary>The IMA file signatures tag (<c>RPMTAG_FILESIGNATURES</c>).</summary>
    internal const int TagFileSignatures = 5090;

    /// <summary>The tag holding the longest file signature's byte length (<c>RPMTAG_FILESIGNATURELENGTH</c>).</summary>
    internal const int TagFileSignatureLength = 5091;

    /// <summary>The file digest algorithm tag (<c>RPMTAG_FILEDIGESTALGO</c>).</summary>
    internal const int TagFileDigestAlgo = 5011;

    /// <summary>The file digest algorithm value for SHA-256.</summary>
    internal const int DigestAlgoSha256 = 8;

    /// <summary>The signature header tag for the header and payload size.</summary>
    internal const int TagSize = 1000;

    /// <summary>The signature header tag for the legacy header and payload MD5.</summary>
    internal const int TagMd5 = 1004;

    /// <summary>The signature header tag for the header SHA-1.</summary>
    internal const int TagSha1 = 269;

    /// <summary>The signature header tag for the header SHA-256.</summary>
    internal const int TagSha256 = 273;

    /// <summary>The signature header tag for an OpenPGP DSA header signature.</summary>
    private const int TagDsa = 267;

    /// <summary>The signature header tag for an OpenPGP RSA header signature.</summary>
    private const int TagRsa = 268;

    /// <summary>The signature header tag for a legacy PGP header and payload signature.</summary>
    private const int TagPgp = 1002;

    /// <summary>The signature header tag for a legacy GPG header and payload signature.</summary>
    private const int TagGpg = 1005;

    /// <summary>The byte length of the IMA key identifier (last 4 bytes of Subject Key Identifier).</summary>
    private const int KeyIdLength = 4;

    /// <summary>The IMA extended attribute type for a digital signature (<c>EVM_IMA_XATTR_DIGSIG</c>).</summary>
    private const byte ImaSignatureType = 3;

    /// <summary>The IMA signature format version.</summary>
    private const byte ImaVersion = 2;

    /// <summary>The IMA hash algorithm identifier for SHA-256 (<c>HASH_ALGO_SHA256</c>).</summary>
    private const byte ImaSha256 = 4;

    /// <summary>The bits in a byte, for writing the 16-bit big-endian signature size.</summary>
    private const int BitsPerByte = 8;

    /// <inheritdoc/>
    public string Name => "RPM";

    /// <summary>Gets the OpenPGP signature tags that become stale when the main header is updated.</summary>
    private static ReadOnlySpan<int> StaleSignatureTags => [TagDsa, TagRsa, TagPgp, TagGpg];

    /// <summary>Computes the 4-byte IMA v2 key identifier (the last 4 bytes of the SHA-1 of the public key).</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The 4-byte IMA key identifier.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    public static byte[] ComputeKeyId(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var keyHash = HashSha1(certificate.PublicKey.EncodedKeyValue.RawData);
        return keyHash[^KeyIdLength..];
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) =>
        probe.Extension.Equals(".rpm", StringComparison.OrdinalIgnoreCase)
        && RpmHeaderCodec.HasLeadMagic(probe.Header.Span);

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

    /// <summary>Signs all SHA-256 file digests in an RPM package and updates its headers in place.</summary>
    /// <param name="path">The RPM path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="InvalidDataException"><paramref name="path"/> is not a valid RPM package with SHA-256 file digests.</exception>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        var file = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        if (file.Length < RpmHeaderCodec.LeadLength || !RpmHeaderCodec.HasLeadMagic(file))
        {
            throw new InvalidDataException($"'{path}' is not a valid RPM package.");
        }

        var signatureLength = RpmHeaderCodec.HeaderLength(file, RpmHeaderCodec.LeadLength);
        var headerStart = RpmHeaderCodec.LeadLength
            + signatureLength
            + RpmHeaderCodec.Pad(signatureLength, RpmHeaderCodec.SignatureAlignment);
        var headerLength = RpmHeaderCodec.HeaderLength(file, headerStart);
        var payload = file.AsMemory(headerStart + headerLength);
        var signatureHeader = RpmHeaderCodec.ReadHeader(file.AsSpan(RpmHeaderCodec.LeadLength, signatureLength));
        var mainHeader = RpmHeaderCodec.ReadHeader(file.AsSpan(headerStart, headerLength));

        if (!mainHeader.TryGetValue(TagFileDigestAlgo, out var algo)
            || BinaryPrimitives.ReadInt32BigEndian(algo.Data.Span) != DigestAlgoSha256)
        {
            throw new InvalidDataException($"'{path}' does not record SHA-256 file digests (RPMTAG_FILEDIGESTALGO = 8).");
        }

        var keyId = ComputeKeyId(session.Certificate.Certificate);
        var (signatures, longest) = await SignFileDigestsAsync(mainHeader, keyId, session, cancellationToken).ConfigureAwait(false);
        mainHeader[TagFileSignatures] = RpmHeaderCodec.CreateStringArray(signatures);
        mainHeader[TagFileSignatureLength] = RpmHeaderCodec.CreateInt32(longest);
        var headerBytes = RpmHeaderCodec.WriteHeader(mainHeader, RpmHeaderCodec.RegionImmutable);

        UpdateSignatureHeader(signatureHeader, headerBytes, payload.Span);
        var signatureBytes = RpmHeaderCodec.WriteHeader(signatureHeader, RpmHeaderCodec.RegionSignatures);
        var paddingBytes = new byte[RpmHeaderCodec.Pad(signatureBytes.Length, RpmHeaderCodec.SignatureAlignment)];

        using var handle = File.OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
        await RandomAccess.WriteAsync(
            handle,
            [file.AsMemory(0, RpmHeaderCodec.LeadLength), signatureBytes, paddingBytes, headerBytes, payload],
            fileOffset: 0,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs each regular file's SHA-256 digest into an IMA v2 hex signature string.</summary>
    /// <param name="mainHeader">The parsed main RPM header.</param>
    /// <param name="keyId">The 4-byte IMA key identifier.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The hex-encoded IMA signatures and the maximum raw IMA signature byte length.</returns>
    private static async ValueTask<(string[] Signatures, int Longest)> SignFileDigestsAsync(
        SortedDictionary<int, RpmHeaderEntry> mainHeader,
        byte[] keyId,
        SigningSession session,
        CancellationToken cancellationToken)
    {
        if (!mainHeader.TryGetValue(TagFileDigests, out var digestEntry))
        {
            return ([], 0);
        }

        var digests = RpmHeaderCodec.DecodeStrings(digestEntry);
        var signatures = new string[digests.Length];
        var longest = 0;
        var digestBytes = new byte[SHA256.HashSizeInBytes];
        for (var i = 0; i < digests.Length; i++)
        {
            if (digests[i].Length == 0)
            {
                signatures[i] = string.Empty;
                continue;
            }

            _ = Convert.FromHexString(digests[i], digestBytes, out _, out _);
            var rawSignature = await session.Provider.SignDigestAsync(
                new(digestBytes, HashAlgorithmName.SHA256),
                cancellationToken).ConfigureAwait(false);

            byte[] ima =
            [
                ImaSignatureType,
                ImaVersion,
                ImaSha256,
                .. keyId,
                (byte)(rawSignature.Length >> BitsPerByte),
                (byte)rawSignature.Length,
                .. rawSignature,
            ];
            signatures[i] = Convert.ToHexStringLower(ima);
            longest = Math.Max(longest, ima.Length);
        }

        return (signatures, longest);
    }

    /// <summary>Removes stale OpenPGP header signatures and recomputes the Signature Header digests and size.</summary>
    /// <param name="signatureHeader">The parsed signature header.</param>
    /// <param name="headerBytes">The serialized main header bytes.</param>
    /// <param name="payload">The compressed CPIO payload bytes.</param>
    private static void UpdateSignatureHeader(
        SortedDictionary<int, RpmHeaderEntry> signatureHeader,
        ReadOnlySpan<byte> headerBytes,
        ReadOnlySpan<byte> payload)
    {
        foreach (var stale in StaleSignatureTags)
        {
            _ = signatureHeader.Remove(stale);
        }

        signatureHeader[TagSha256] = RpmHeaderCodec.CreateString(Convert.ToHexStringLower(SHA256.HashData(headerBytes)));
        if (signatureHeader.ContainsKey(TagSha1))
        {
            var sha1 = HashSha1(headerBytes);
            signatureHeader[TagSha1] = RpmHeaderCodec.CreateString(Convert.ToHexStringLower(sha1));
        }

        if (signatureHeader.ContainsKey(TagMd5))
        {
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            md5.AppendData(headerBytes);
            md5.AppendData(payload);
            signatureHeader[TagMd5] = new(RpmHeaderCodec.TypeBinary, MD5.HashSizeInBytes, md5.GetHashAndReset());
        }

        signatureHeader[TagSize] = RpmHeaderCodec.CreateInt32(headerBytes.Length + payload.Length);
    }

    /// <summary>Computes a SHA-1 digest used only by the RPM format's legacy key identifier and header fields.</summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The 20-byte SHA-1 digest.</returns>
    private static byte[] HashSha1(ReadOnlySpan<byte> data)
    {
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        sha1.AppendData(data);
        return sha1.GetHashAndReset();
    }
}
