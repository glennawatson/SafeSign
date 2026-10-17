// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using SafeSign.Formats.Cab;
using SafeSign.Formats.Catalog;
using SafeSign.Formats.CompoundFile;
using SafeSign.Formats.Msi;
using SafeSign.Signing;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies <see cref="MsiFileSigner"/>, <see cref="CabFileSigner"/>, and <see cref="CatalogFileSigner"/>.</summary>
public sealed class MsiCabCatalogTests
{
    /// <summary>The base size of a Cabinet <c>CFHEADER</c> without reserve bytes.</summary>
    private const int CabBaseHeaderSize = 36;

    /// <summary>The size of one <c>CFFOLDER</c> entry.</summary>
    private const int CabFolderEntrySize = 8;

    /// <summary>The offset of <c>cbCabinet</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetSize = 8;

    /// <summary>The offset of <c>coffFiles</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetFiles = 16;

    /// <summary>The offset of <c>versionMinor</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetVersionMinor = 24;

    /// <summary>The offset of <c>versionMajor</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetVersionMajor = 25;

    /// <summary>The offset of <c>cFolders</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetFolderCount = 26;

    /// <summary>The offset of <c>cFiles</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetFileCount = 28;

    /// <summary>The offset of <c>flags</c> in <c>CFHEADER</c>.</summary>
    private const int CabOffsetFlags = 30;

    /// <summary>The <c>cfhdrRESERVE_PRESENT</c> flag bit (<c>0x0004</c>).</summary>
    private const ushort CabFlagReservePresent = 0x0004;

    /// <summary>The Cabinet format major version (<c>1</c>).</summary>
    private const byte CabVersionMajor = 1;

    /// <summary>The Cabinet format minor version (<c>3</c>).</summary>
    private const byte CabVersionMinor = 3;

    /// <summary>The byte offset of the signature offset inside a signed Cabinet header.</summary>
    private const int CabSignedOffsetPosition = 44;

    /// <summary>The byte offset of the signature length inside a signed Cabinet header.</summary>
    private const int CabSignedLengthPosition = 48;

    /// <summary>The synthetic creation timestamp for MSI root storage metadata.</summary>
    private const long CreatedTimestamp = 100L;

    /// <summary>The synthetic modification timestamp for MSI root storage metadata.</summary>
    private const long ModifiedTimestamp = 200L;

    /// <summary>Verifies that <see cref="MsiFileSigner"/> embeds <c>\x05MsiDigitalSignatureEx</c> and <c>\x05DigitalSignature</c> and supports re-signing.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task MsiFileSigner_SignsAndReSignsCompoundFileStreams()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-msi-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var msiPath = Path.Combine(tempDir.FullName, "sample.msi");

            var root = new CompoundFileEntry(
                "Root Entry",
                new(new("000C1084-0000-0000-C000-000000000046"), 0, CreatedTimestamp, ModifiedTimestamp),
                ReadOnlyMemory<byte>.Empty,
                [
                    new("\u0005SummaryInformation", default, "MSI summary stream"u8.ToArray(), null),
                    new("Data.cab", default, "Embedded cabinet payload"u8.ToArray(), null),
                ]);
            await File.WriteAllBytesAsync(msiPath, CompoundFileWriter.Write(root));

            var signer = new MsiFileSigner();
            await signer.SignAsync(new(msiPath, msiPath, session), CancellationToken.None);

            // Re-sign the already signed MSI to verify existing signature removal.
            await signer.SignAsync(new(msiPath, msiPath, session), CancellationToken.None);

            var signedRoot = CompoundFileReader.Read(await File.ReadAllBytesAsync(msiPath));
            await Assert.That(signedRoot.Children).IsNotNull();

            var sigEx = signedRoot.Children!.Find(static c => c.Name == MsiFileSigner.DigitalSignatureExStreamName);
            var sig = signedRoot.Children.Find(static c => c.Name == MsiFileSigner.DigitalSignatureStreamName);

            await Assert.That(sigEx).IsNotNull();
            await Assert.That(sigEx!.Data.Length).IsEqualTo(SHA256.HashSizeInBytes);
            await Assert.That(sig).IsNotNull();
            await Assert.That(IsSignedDataContentInfo(sig!.Data)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="CabFileSigner"/> adds the 20-byte reserve area, appends the Authenticode PKCS #7 signature, and supports re-signing.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CabFileSigner_SignsAndReSignsCabinetWithReserveHeader()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-cab-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var cabPath = Path.Combine(tempDir.FullName, "sample.cab");
            await File.WriteAllBytesAsync(cabPath, CreateMinimalCabinet());

            var signer = new CabFileSigner();
            await signer.SignAsync(new(cabPath, cabPath, session), CancellationToken.None);
            await signer.SignAsync(new(cabPath, cabPath, session), CancellationToken.None);

            var signedBytes = await File.ReadAllBytesAsync(cabPath);
            var flags = BinaryPrimitives.ReadUInt16LittleEndian(signedBytes.AsSpan(CabOffsetFlags));
            var sigOffset = BinaryPrimitives.ReadUInt32LittleEndian(signedBytes.AsSpan(CabSignedOffsetPosition));
            var sigLength = BinaryPrimitives.ReadUInt32LittleEndian(signedBytes.AsSpan(CabSignedLengthPosition));

            await Assert.That((flags & CabFlagReservePresent) != 0).IsTrue();
            await Assert.That((int)(sigOffset + sigLength)).IsEqualTo(signedBytes.Length);
            await Assert.That(IsSignedDataContentInfo(signedBytes.AsMemory((int)sigOffset, (int)sigLength))).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="CatalogFileSigner"/> wraps a <c>CertificateTrustList</c> in an Authenticode PKCS #7 <c>SignedData</c> and supports re-signing.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task CatalogFileSigner_WrapsAndReSignsCertificateTrustList()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-cat-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var catPath = Path.Combine(tempDir.FullName, "sample.cat");
            await File.WriteAllBytesAsync(catPath, CreateMinimalCertificateTrustList());

            var signer = new CatalogFileSigner();
            await signer.SignAsync(new(catPath, catPath, session), CancellationToken.None);
            await signer.SignAsync(new(catPath, catPath, session), CancellationToken.None);

            var signedBytes = await File.ReadAllBytesAsync(catPath);
            await Assert.That(IsSignedDataContentInfo(signedBytes)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Checks whether <paramref name="data"/> is a DER-encoded CMS <c>ContentInfo</c> with <c>id-signedData</c>.</summary>
    /// <param name="data">The encoded CMS bytes.</param>
    /// <returns>True when the outer SEQUENCE begins with <see cref="CmsOids.SignedData"/>.</returns>
    private static bool IsSignedDataContentInfo(ReadOnlyMemory<byte> data)
    {
        var seq = new AsnReader(data, AsnEncodingRules.BER).ReadSequence();
        var oid = seq.ReadObjectIdentifier();
        return string.Equals(oid, "1.2.840.113549.1.7.2", StringComparison.Ordinal);
    }

    /// <summary>Builds a minimal valid uncompressed single-folder Microsoft Cabinet archive.</summary>
    /// <returns>The unsigned cabinet bytes.</returns>
    private static byte[] CreateMinimalCabinet()
    {
        var payload = "SafeSign cabinet payload"u8;
        const int totalLength = 96;
        var cab = new byte[totalLength];
        "MSCF"u8.CopyTo(cab);
        BinaryPrimitives.WriteUInt32LittleEndian(cab.AsSpan(CabOffsetSize), totalLength);
        BinaryPrimitives.WriteUInt32LittleEndian(cab.AsSpan(CabOffsetFiles), CabBaseHeaderSize + CabFolderEntrySize);
        cab[CabOffsetVersionMinor] = CabVersionMinor;
        cab[CabOffsetVersionMajor] = CabVersionMajor;
        BinaryPrimitives.WriteUInt16LittleEndian(cab.AsSpan(CabOffsetFolderCount), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(cab.AsSpan(CabOffsetFileCount), 1);

        // CFFOLDER entry at offset 36: coffCabStart = 56, cCFData = 1
        const uint dataOffset = 56;
        BinaryPrimitives.WriteUInt32LittleEndian(cab.AsSpan(CabBaseHeaderSize), dataOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(cab.AsSpan(CabBaseHeaderSize + sizeof(uint)), 1);
        payload.CopyTo(cab.AsSpan((int)dataOffset));
        return cab;
    }

    /// <summary>Builds a minimal ASN.1 DER <c>CertificateTrustList</c> SEQUENCE.</summary>
    /// <returns>The DER-encoded CTL bytes.</returns>
    private static byte[] CreateMinimalCertificateTrustList()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.6.1.4.1.311.12.1.1");
            }

            writer.WriteOctetString("cat-list-id"u8);
            writer.WriteGeneralizedTime(DateTimeOffset.UnixEpoch, omitFractionalSeconds: true);
        }

        return writer.Encode();
    }
}
