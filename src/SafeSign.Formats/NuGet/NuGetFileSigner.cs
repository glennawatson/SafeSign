// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SafeSign.Signing;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.NuGet;

/// <summary>
/// Signs NuGet packages (<c>.nupkg</c>) natively according to the NuGet Package Signature Specification by
/// embedding an Author Primary Signature (<c>1.2.840.113549.1.9.16.6.1</c>) with <c>SigningCertificateV2</c> at
/// <c>.signature.p7s</c>. Unsigned <c>.dll</c> and <c>.exe</c> files inside the package are Authenticode signed first.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class NuGetFileSigner : IFileFormatSigner
{
    /// <summary>Gets the ZIP entry path for the NuGet package signature.</summary>
    public static string SignatureEntryPath => ".signature.p7s";

    /// <summary>Gets the OID for a NuGet Author Primary Signature (<c>id-cti-ets-proofOfOrigin</c> / <c>1.2.840.113549.1.9.16.6.1</c>).</summary>
    public static string AuthorPrimarySignatureOid => "1.2.840.113549.1.9.16.6.1";

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

    /// <summary>
    /// Builds the NuGet signature content: <c>Version:1</c>, a section break, <c>{hash-oid}-Hash:{base64}</c> and a
    /// section break, each line ending in LF, UTF-8 without a BOM (NuGet <c>SignatureContent</c> / <c>KeyPairFileWriter</c>).
    /// </summary>
    /// <param name="algorithm">The package digest algorithm.</param>
    /// <param name="archiveHash">The hash of the unsigned package.</param>
    /// <returns>The encoded content.</returns>
    /// <exception cref="NotSupportedException">The digest algorithm is not SHA-256, SHA-384, or SHA-512.</exception>
    internal static byte[] CreateSignatureContent(HashAlgorithmName algorithm, ReadOnlySpan<byte> archiveHash)
    {
        var prefix = GetHashPrefix(algorithm);
        var suffix = "\n\n"u8;
        var base64Length = Base64.GetMaxEncodedToUtf8Length(archiveHash.Length);
        var content = GC.AllocateUninitializedArray<byte>(prefix.Length + base64Length + suffix.Length);
        prefix.CopyTo(content);
        _ = Base64.EncodeToUtf8(archiveHash, content.AsSpan(prefix.Length, base64Length), out _, out _);
        suffix.CopyTo(content.AsSpan(prefix.Length + base64Length));
        return content;
    }

    /// <summary>Strips any existing <c>.signature.p7s</c>, computes the NuGet archive hash, builds the CMS signature, and writes <c>.signature.p7s</c>.</summary>
    /// <param name="path">The <c>.nupkg</c> file path.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="NotSupportedException">The signing key is not RSA, or the digest is not SHA-256, SHA-384 or SHA-512.</exception>
    private static async ValueTask SignPathAsync(string path, SigningSession session, CancellationToken cancellationToken)
    {
        // NuGet's signing specification only allows SHA256RSA, SHA384RSA and SHA512RSA; fail before the provider is called.
        var certificate = session.Certificate.Certificate;
        if (!string.Equals(certificate.PublicKey.Oid.Value, CmsOids.RsaEncryption, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"NuGet package signatures require an RSA signing certificate; '{certificate.Subject}' has a {certificate.PublicKey.Oid.FriendlyName} key.");
        }

        _ = GetHashPrefix(session.DigestAlgorithm);
        var unsignedZip = NuGetSignatureArchive.RemoveSignature(await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));

        // The DLLs are signed before the archive hash is taken, so the package signature covers the signed files.
        if (session.SignPackageContents)
        {
            unsignedZip = await NuGetPackageContents.SignPeFilesAsync(unsignedZip, session, cancellationToken).ConfigureAwait(false);
        }

        var signatureContentBytes = CreateSignatureContent(session.DigestAlgorithm, CryptographicOperations.HashData(session.DigestAlgorithm, unsignedZip));

        var contentWriter = new AsnWriter(AsnEncodingRules.DER);
        contentWriter.WriteOctetString(signatureContentBytes);
        var encodedOctetString = contentWriter.Encode();

        var now = session.Time.GetUtcNow();
        var signedAttributes = new CmsAttribute[]
        {
            CmsAttributes.SigningTime(now),
            EncodeAuthorCommitmentAttribute(),
            CmsAttributes.SigningCertificateV2(certificate),
        };

        var cmsContent = new CmsSignedContent(
            CmsOids.Data,
            encodedOctetString,
            signatureContentBytes,
            signedAttributes,
            CmsTimestampPlacement.Cms);

        var p7sBytes = await CmsSignedDataBuilder.CreateAsync(session, cmsContent, cancellationToken).ConfigureAwait(false);
        var signedZip = NuGetSignatureArchive.AddSignature(unsignedZip, p7sBytes, TimeZoneInfo.ConvertTime(now, session.Time.LocalTimeZone).DateTime);
        await File.WriteAllBytesAsync(path, signedZip, cancellationToken).ConfigureAwait(false);
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

    /// <summary>Maps a <see cref="HashAlgorithmName"/> to its UTF-8 NuGet signature content prefix.</summary>
    /// <param name="algorithm">The digest algorithm.</param>
    /// <returns>The UTF-8 prefix ending in <c>-Hash:</c>.</returns>
    /// <exception cref="NotSupportedException">The digest algorithm is not SHA-256, SHA-384, or SHA-512.</exception>
    private static ReadOnlySpan<byte> GetHashPrefix(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA256" => "Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:"u8,
        "SHA384" => "Version:1\n\n2.16.840.1.101.3.4.2.2-Hash:"u8,
        "SHA512" => "Version:1\n\n2.16.840.1.101.3.4.2.3-Hash:"u8,
        _ => throw new NotSupportedException($"NuGet package signing does not support digest algorithm '{algorithm.Name}'."),
    };
}
