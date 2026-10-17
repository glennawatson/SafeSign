// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using SafeSign.Signing.Cms;
using SafeSign.Signing.Pe;

namespace SafeSign.Signing.Tests;

/// <summary>Verifies end-to-end PE32 and PE32+ Authenticode signing, digest calculation, checksum updates, and signature replacement.</summary>
public sealed class PeSigningTests
{
    /// <summary>The size of the WIN_CERTIFICATE header.</summary>
    private const int WinCertificateHeaderSize = 8;

    /// <summary>The offset of wRevision in WIN_CERTIFICATE.</summary>
    private const int RevisionOffset = 4;

    /// <summary>The offset of wCertificateType in WIN_CERTIFICATE.</summary>
    private const int CertificateTypeOffset = 6;

    /// <summary>The expected WIN_CERTIFICATE revision (2.0).</summary>
    private const ushort WinCertificateRevision2 = 0x0200;

    /// <summary>The expected WIN_CERTIFICATE PKCS#7 signed data type.</summary>
    private const ushort WinCertificateTypePkcsSignedData = 0x0002;

    /// <summary>The required 8-byte alignment for the certificate table.</summary>
    private const int CertificateAlignment = 8;

    /// <summary>Signs both PE32 and PE32+ images and validates the embedded PKCS#7 Authenticode signature, digest, and PE checksum.</summary>
    /// <param name="isPe32Plus">Whether to test a 64-bit PE32+ image.</param>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SignAsync_ProducesValidAuthenticodeSignatureAndChecksum(bool isPe32Plus)
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-pe-");
        try
        {
            var inputPath = Path.Combine(tempDir.FullName, "sample.exe");
            var outputPath = Path.Combine(tempDir.FullName, "sample-signed.exe");
            await File.WriteAllBytesAsync(inputPath, TestPeImages.Create(isPe32Plus));

            using var provider = new TestRsaSigningProvider();
            var cert = await provider.GetCertificateAsync(CancellationToken.None);
            var session = new SigningSession(provider, cert, HashAlgorithmName.SHA256, null, "SafeSign Test App", new Uri("https://example.test/safesign"), TimeProvider.System);

            var signer = new PeFileSigner();
            var header = await File.ReadAllBytesAsync(inputPath);
            await Assert.That(signer.CanSign(new(inputPath, header))).IsTrue();

            await signer.SignAsync(new(inputPath, outputPath, session), CancellationToken.None);

            var signedBytes = await File.ReadAllBytesAsync(outputPath);
            var layout = PeLayoutReader.Read(signedBytes, signedBytes.Length);
            await Assert.That(layout.IsPe32Plus).IsEqualTo(isPe32Plus);
            await Assert.That(layout.CertificateTableOffset > 0).IsTrue();
            await Assert.That(layout.CertificateTableOffset % CertificateAlignment).IsEqualTo(0);

            var certRecord = signedBytes.AsMemory((int)layout.CertificateTableOffset, (int)layout.CertificateTableSize);
            var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(certRecord.Span);
            var revision = BinaryPrimitives.ReadUInt16LittleEndian(certRecord.Span[RevisionOffset..]);
            var certificateType = BinaryPrimitives.ReadUInt16LittleEndian(certRecord.Span[CertificateTypeOffset..]);

            await Assert.That(recordLength).IsEqualTo((uint)layout.CertificateTableSize);
            await Assert.That(revision).IsEqualTo(WinCertificateRevision2);
            await Assert.That(certificateType).IsEqualTo(WinCertificateTypePkcsSignedData);

            var pkcs7 = certRecord[WinCertificateHeaderSize..].ToArray();
            var signedCms = new SignedCms();
            signedCms.Decode(pkcs7);
            signedCms.CheckSignature(verifySignatureOnly: true);

            await Assert.That(signedCms.ContentInfo.ContentType.Value).IsEqualTo(CmsOids.SpcIndirectData);

            var embeddedDigest = ExtractIndirectDataDigest(signedCms.ContentInfo.Content);
            using var handle = File.OpenHandle(outputPath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.Asynchronous);
            var recomputed = await PeAuthenticodeDigest.ComputeAsync(handle, layout, layout.CertificateTableOffset, HashAlgorithmName.SHA256, CancellationToken.None);
            await Assert.That(CryptographicOperations.FixedTimeEquals(embeddedDigest, recomputed.Digest)).IsTrue();

            var entryBytes = signedBytes.AsSpan((int)layout.CertificateEntryOffset, CertificateAlignment);
            var sumWithTable = PeChecksum.Accumulate(certRecord.Span, PeChecksum.Accumulate(entryBytes, recomputed.ChecksumSum));
            var expectedChecksum = PeChecksum.Finish(sumWithTable, signedBytes.Length);
            var storedChecksum = BinaryPrimitives.ReadUInt32LittleEndian(signedBytes.AsSpan((int)layout.ChecksumOffset, sizeof(uint)));
            await Assert.That(storedChecksum).IsEqualTo(expectedChecksum);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that re-signing an already signed PE image in place replaces the previous signature and preserves the Authenticode digest.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignAsync_ReSigningInPlace_ReplacesPreviousSignature()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-pe-resign-");
        try
        {
            var path = Path.Combine(tempDir.FullName, "app.dll");
            await File.WriteAllBytesAsync(path, TestPeImages.Create(isPe32Plus: true));

            using var firstProvider = new TestRsaSigningProvider();
            var firstCert = await firstProvider.GetCertificateAsync(CancellationToken.None);
            var firstSession = new SigningSession(firstProvider, firstCert, HashAlgorithmName.SHA256, null, null, null, TimeProvider.System);

            var signer = new PeFileSigner();
            await signer.SignAsync(new(path, path, firstSession), CancellationToken.None);

            using var secondProvider = new TestEcdsaSigningProvider();
            var secondCert = await secondProvider.GetCertificateAsync(CancellationToken.None);
            var secondSession = new SigningSession(secondProvider, secondCert, HashAlgorithmName.SHA256, null, "Second Sign", null, TimeProvider.System);

            await signer.SignAsync(new(path, path, secondSession), CancellationToken.None);

            var signedBytes = await File.ReadAllBytesAsync(path);
            var layout = PeLayoutReader.Read(signedBytes, signedBytes.Length);
            var pkcs7 = signedBytes.AsSpan((int)layout.CertificateTableOffset + WinCertificateHeaderSize, (int)layout.CertificateTableSize - WinCertificateHeaderSize).ToArray();

            var signedCms = new SignedCms();
            signedCms.Decode(pkcs7);
            signedCms.CheckSignature(verifySignatureOnly: true);
            await Assert.That(signedCms.Certificates.Count).IsEqualTo(1);
            await Assert.That(signedCms.Certificates[0].Thumbprint).IsEqualTo(secondProvider.Certificate.Thumbprint);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that a corrupted signature from a provider is rejected before writing the signed file.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignAsync_WithCorruptedProviderSignature_ThrowsCryptographicException()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-pe-corrupt-");
        try
        {
            var inputPath = Path.Combine(tempDir.FullName, "bad.exe");
            var outputPath = Path.Combine(tempDir.FullName, "bad-signed.exe");
            await File.WriteAllBytesAsync(inputPath, TestPeImages.Create(isPe32Plus: true));

            using var provider = new TestRsaSigningProvider { Corrupt = true };
            var cert = await provider.GetCertificateAsync(CancellationToken.None);
            var session = new SigningSession(provider, cert, HashAlgorithmName.SHA256, null, null, null, TimeProvider.System);

            var signer = new PeFileSigner();
            await Assert.That(async () => await signer.SignAsync(new(inputPath, outputPath, session), CancellationToken.None))
                .Throws<CryptographicException>();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Extracts the file digest OCTET STRING from an encoded SpcIndirectDataContent ASN.1 structure.</summary>
    /// <param name="encodedIndirectData">The DER-encoded SpcIndirectDataContent.</param>
    /// <returns>The extracted digest bytes.</returns>
    private static byte[] ExtractIndirectDataDigest(byte[] encodedIndirectData)
    {
        var reader = new AsnReader(encodedIndirectData, AsnEncodingRules.DER);
        var root = reader.ReadSequence();
        _ = root.ReadSequence();
        var digestInfo = root.ReadSequence();
        _ = digestInfo.ReadSequence();
        return digestInfo.ReadOctetString();
    }
}
