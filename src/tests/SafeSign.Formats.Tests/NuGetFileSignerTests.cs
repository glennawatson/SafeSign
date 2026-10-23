// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SafeSign.Formats.Compression;
using SafeSign.Formats.NuGet;
using SafeSign.Signing;
using SafeSign.Signing.Pe;

namespace SafeSign.Formats.Tests;

/// <summary>
/// Checks <see cref="NuGetFileSigner"/> against the rules NuGet's <c>SignedPackageArchiveIOUtility</c> and
/// <c>SignatureContent</c> enforce (NU3005, NU3000 and the package integrity check).
/// </summary>
public sealed class NuGetFileSignerTests
{
    /// <summary>The initial capacity for synthetic packages.</summary>
    private const int InitialZipBufferCapacity = 4096;

    /// <summary>The size of the fixed fields of a central directory header.</summary>
    private const int CentralHeaderSize = 46;

    /// <summary>The size of the fixed fields of a local file header.</summary>
    private const int LocalHeaderSize = 30;

    /// <summary>The ZIP "version 2.0" value NuGet itself writes for the signature entry.</summary>
    private const ushort ZipVersion20 = 20;

    /// <summary>The Unix permission bits <see cref="ZipArchive"/> writes on Linux and macOS, which NU3005 rejects.</summary>
    private const uint UnixRegularFileAttributes = 0x81A40000;

    /// <summary>The length of the fake assembly content in the sample package.</summary>
    private const int SampleAssemblyLength = 2048;

    /// <summary>The file name used for packages written to a temporary folder.</summary>
    private const string PackageFileName = "Sample.1.0.0.nupkg";

    /// <summary>The entry path of the DLL in the package built around a real PE image.</summary>
    private const string SampleDllPath = "lib/net10.0/Sample.dll";

    /// <summary>Central directory header: version made by.</summary>
    private const int CdVersionMadeBy = 4;

    /// <summary>Central directory header: version needed to extract.</summary>
    private const int CdVersionNeeded = 6;

    /// <summary>Central directory header: general purpose flag.</summary>
    private const int CdFlags = 8;

    /// <summary>Central directory header: compression method.</summary>
    private const int CdMethod = 10;

    /// <summary>Central directory header: compressed size.</summary>
    private const int CdCompressedSize = 20;

    /// <summary>Central directory header: uncompressed size.</summary>
    private const int CdUncompressedSize = 24;

    /// <summary>Central directory header: extra field length.</summary>
    private const int CdExtraLength = 30;

    /// <summary>Central directory header: internal file attributes.</summary>
    private const int CdInternalAttributes = 36;

    /// <summary>Central directory header: external file attributes.</summary>
    private const int CdExternalAttributes = 38;

    /// <summary>Local file header: general purpose flag.</summary>
    private const int LfhFlags = 6;

    /// <summary>Local file header: compression method.</summary>
    private const int LfhMethod = 8;

    /// <summary>Local file header: compressed size.</summary>
    private const int LfhCompressedSize = 18;

    /// <summary>Local file header: uncompressed size.</summary>
    private const int LfhUncompressedSize = 22;

    /// <summary>Local file header: extra field length.</summary>
    private const int LfhExtraLength = 28;

    /// <summary>Verifies every signature entry header field NU3005 checks, in both the central directory and the local header.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignatureEntry_HasTheHeaderFieldsNuGetRequires()
    {
        using var provider = new TestFormatSigningProvider();
        var (unsigned, signed) = await SignSampleAsync(provider.CreateSession());

        var directory = NuGetSignatureArchive.ReadDirectory(signed);
        await Assert.That(directory.SignatureIndex).IsEqualTo(directory.Entries.Length - 1);

        var entry = directory.Entries[directory.SignatureIndex];
        var central = signed.AsSpan(entry.HeaderPosition, CentralHeaderSize).ToArray();
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdVersionMadeBy))).IsEqualTo(ZipVersion20);
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdVersionNeeded))).IsEqualTo(ZipVersion20);
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdFlags))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdMethod))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(CdCompressedSize))).IsEqualTo(BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(CdUncompressedSize)));
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdExtraLength))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(central.AsSpan(CdInternalAttributes))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(central.AsSpan(CdExternalAttributes))).IsEqualTo(0U);

        // The signature's local entry is the last one, directly before the central directory.
        var local = signed.AsSpan(entry.LocalHeaderOffset, LocalHeaderSize).ToArray();
        await Assert.That(entry.LocalHeaderOffset).IsEqualTo(FindCentralDirectoryOffset(unsigned));
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(local.AsSpan(LfhFlags))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(local.AsSpan(LfhMethod))).IsEqualTo((ushort)0);
        await Assert.That(BinaryPrimitives.ReadUInt32LittleEndian(local.AsSpan(LfhCompressedSize))).IsEqualTo(BinaryPrimitives.ReadUInt32LittleEndian(local.AsSpan(LfhUncompressedSize)));
        await Assert.That(BinaryPrimitives.ReadUInt16LittleEndian(local.AsSpan(LfhExtraLength))).IsEqualTo((ushort)0);
    }

    /// <summary>Verifies the input really carries Unix attributes, so the test above would catch a ZipArchive regression.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SamplePackage_FromZipArchive_CarriesUnixAttributesOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var sample = CreateSamplePackage();
        var directory = NuGetSignatureArchive.ReadDirectory(sample);
        var attributes = BinaryPrimitives.ReadUInt32LittleEndian(sample.AsSpan(directory.Entries[0].HeaderPosition + CdExternalAttributes));
        await Assert.That(attributes).IsEqualTo(UnixRegularFileAttributes);
    }

    /// <summary>Verifies that removing the signature the way NuGet does gives back the exact bytes that were hashed.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task RemovingSignature_ReconstructsTheUnsignedPackageExactly()
    {
        using var provider = new TestFormatSigningProvider();
        var (unsigned, signed) = await SignSampleAsync(provider.CreateSession());

        await Assert.That(CryptographicOperations.FixedTimeEquals(NuGetSignatureArchive.RemoveSignature(signed), unsigned)).IsTrue();
    }

    /// <summary>Verifies the signature content format NuGet's <c>SignatureContent.Load</c> parses, and the hash it compares.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task SignatureContent_UsesTheNuGetKeyPairFormatAndHashesTheUnsignedPackage()
    {
        using var provider = new TestFormatSigningProvider();
        var (unsigned, signed) = await SignSampleAsync(provider.CreateSession());

        var cms = new SignedCms();
        cms.Decode(ReadEntry(signed, NuGetFileSigner.SignatureEntryPath));
        cms.CheckSignature(verifySignatureOnly: true);

        var expected = $"Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:{Convert.ToBase64String(SHA256.HashData(unsigned))}\n\n";
        await Assert.That(Encoding.UTF8.GetString(cms.ContentInfo.Content)).IsEqualTo(expected);
        await Assert.That(cms.ContentInfo.Content[0]).IsEqualTo((byte)'V');
        await Assert.That(cms.SignerInfos.Count).IsEqualTo(1);
        await Assert.That(cms.SignerInfos[0].SignerIdentifier.Type).IsEqualTo(SubjectIdentifierType.IssuerAndSerialNumber);
    }

    /// <summary>Verifies that re-signing replaces the old signature rather than adding a second one.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task Resigning_ReplacesTheSignatureAndKeepsThePackageBytes()
    {
        using var provider = new TestFormatSigningProvider();
        var session = provider.CreateSession();
        var tempDir = Directory.CreateTempSubdirectory("safesign-nupkg-resign-");
        try
        {
            var unsigned = CreateSamplePackage();
            var path = Path.Combine(tempDir.FullName, PackageFileName);
            await File.WriteAllBytesAsync(path, unsigned);

            var signer = new NuGetFileSigner();
            await signer.SignAsync(new(path, path, session), CancellationToken.None);
            await signer.SignAsync(new(path, path, session), CancellationToken.None);
            var signed = await File.ReadAllBytesAsync(path);

            var directory = NuGetSignatureArchive.ReadDirectory(signed);
            await Assert.That(directory.Entries.Length).IsEqualTo(NuGetSignatureArchive.ReadDirectory(unsigned).Entries.Length + 1);
            await Assert.That(CryptographicOperations.FixedTimeEquals(NuGetSignatureArchive.RemoveSignature(signed), unsigned)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that removing a signature that is not the last local entry still produces a consistent archive.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task RemoveSignature_HandlesASignatureInTheMiddleOfTheArchive()
    {
        await using var stream = MemoryStreams.OpenWrite(InitialZipBufferCapacity, out var getBytes);
        await using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "a.txt", "first");
            WriteEntry(archive, NuGetFileSigner.SignatureEntryPath, "not really a signature");
            WriteEntry(archive, "b.txt", "second");
        }

        var stripped = NuGetSignatureArchive.RemoveSignature(getBytes());

        await Assert.That(NuGetSignatureArchive.ReadDirectory(stripped).SignatureIndex).IsEqualTo(-1);
        await Assert.That(Encoding.UTF8.GetString(ReadEntry(stripped, "b.txt"))).IsEqualTo("second");
        await Assert.That(Encoding.UTF8.GetString(ReadEntry(stripped, "a.txt"))).IsEqualTo("first");
    }

    /// <summary>Verifies that a package with two signature entries is refused, as NuGet does.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ReadDirectory_RejectsTwoSignatureEntries()
    {
        await using var stream = MemoryStreams.OpenWrite(InitialZipBufferCapacity, out var getBytes);
        await using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, NuGetFileSigner.SignatureEntryPath, "one");
            WriteEntry(archive, NuGetFileSigner.SignatureEntryPath, "two");
        }

        var bytes = getBytes();
        await Assert.That(() => NuGetSignatureArchive.ReadDirectory(bytes)).Throws<InvalidDataException>();
    }

    /// <summary>Verifies that bytes which are not a ZIP archive are refused.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ReadDirectory_RejectsNonZipData()
    {
        var bytes = new byte[64];
        await Assert.That(() => NuGetSignatureArchive.ReadDirectory(bytes)).Throws<InvalidDataException>();
    }

    /// <summary>Verifies that an ECDSA certificate is refused before the provider is asked to sign, since NuGet only accepts RSA.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task Sign_WithEcdsaCertificate_IsRefused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=SafeSign ECDSA", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(TimeProvider.System.GetUtcNow().AddDays(-1), TimeProvider.System.GetUtcNow().AddDays(1));
        using var provider = new TestFormatSigningProvider();
        var session = provider.CreateSession() with { Certificate = new(certificate, []) };

        await Assert.That(async () => await SignSampleAsync(session)).Throws<NotSupportedException>();
    }

    /// <summary>Verifies the DLL inside a package is Authenticode signed and the package signature still covers the signed bytes.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task Sign_SignsTheUnsignedDllInsideThePackage()
    {
        using var provider = new TestFormatSigningProvider();
        var dll = await ReadUnsignedDllAsync();

        var signed = await SignPackageAsync(CreatePackageWithDll(dll), provider.CreateSession());

        var signedDll = ReadEntry(signed, SampleDllPath);
        await Assert.That(PeLayoutReader.Read(signedDll, signedDll.Length).CertificateTableSize).IsGreaterThan(0);

        var unsignedZip = NuGetSignatureArchive.RemoveSignature(signed);
        var cms = new SignedCms();
        cms.Decode(ReadEntry(signed, NuGetFileSigner.SignatureEntryPath));
        var expected = $"Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:{Convert.ToBase64String(SHA256.HashData(unsignedZip))}\n\n";
        await Assert.That(Encoding.UTF8.GetString(cms.ContentInfo.Content)).IsEqualTo(expected);
    }

    /// <summary>Verifies that opting out leaves the DLL inside the package exactly as it was.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task Sign_WithPackageContentsOptOut_LeavesTheDllUnsigned()
    {
        using var provider = new TestFormatSigningProvider();
        var dll = await ReadUnsignedDllAsync();

        var signed = await SignPackageAsync(CreatePackageWithDll(dll), provider.CreateSession() with { SignPackageContents = false });

        await Assert.That(CryptographicOperations.FixedTimeEquals(ReadEntry(signed, SampleDllPath), dll)).IsTrue();
    }

    /// <summary>Verifies that a DLL which already carries a signature is not re-signed, so third-party signatures survive.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task Resign_LeavesAnAlreadySignedDllUntouched()
    {
        using var provider = new TestFormatSigningProvider();
        var session = provider.CreateSession();
        var first = await SignPackageAsync(CreatePackageWithDll(await ReadUnsignedDllAsync()), session);
        var firstDll = ReadEntry(first, SampleDllPath);

        var second = await SignPackageAsync(first, session);

        await Assert.That(CryptographicOperations.FixedTimeEquals(ReadEntry(second, SampleDllPath), firstDll)).IsTrue();
    }

    /// <summary>Reads a real, unsigned PE image: the assembly under test.</summary>
    /// <returns>The image bytes.</returns>
    private static Task<byte[]> ReadUnsignedDllAsync() => File.ReadAllBytesAsync(typeof(NuGetFileSigner).Assembly.Location);

    /// <summary>Creates a package whose only library is the given DLL.</summary>
    /// <param name="dll">The DLL bytes.</param>
    /// <returns>The package bytes.</returns>
    private static byte[] CreatePackageWithDll(byte[] dll)
    {
        using var stream = MemoryStreams.OpenWrite(InitialZipBufferCapacity, out var getBytes);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "Sample.nuspec", "<package />");
            using var entryStream = archive.CreateEntry(SampleDllPath, CompressionLevel.Optimal).Open();
            entryStream.Write(dll);
        }

        return getBytes();
    }

    /// <summary>Signs package bytes through <see cref="NuGetFileSigner"/> using a temporary file.</summary>
    /// <param name="package">The package bytes.</param>
    /// <param name="session">The signing session.</param>
    /// <returns>The signed package bytes.</returns>
    private static async Task<byte[]> SignPackageAsync(byte[] package, SigningSession session)
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-nupkg-contents-");
        try
        {
            var path = Path.Combine(tempDir.FullName, PackageFileName);
            await File.WriteAllBytesAsync(path, package);
            await new NuGetFileSigner().SignAsync(new(path, path, session), CancellationToken.None);
            return await File.ReadAllBytesAsync(path);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Signs a fresh sample package and returns the unsigned and signed bytes.</summary>
    /// <param name="session">The signing session.</param>
    /// <returns>The unsigned and signed package bytes.</returns>
    private static async Task<SignedNuGetSample> SignSampleAsync(SigningSession session)
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-nupkg-");
        try
        {
            var unsigned = CreateSamplePackage();
            var path = Path.Combine(tempDir.FullName, PackageFileName);
            await File.WriteAllBytesAsync(path, unsigned);
            await new NuGetFileSigner().SignAsync(new(path, path, session), CancellationToken.None);
            return new(unsigned, await File.ReadAllBytesAsync(path));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Creates a package the way <c>dotnet pack</c> does on this OS, through <see cref="ZipArchive"/>.</summary>
    /// <returns>The package bytes.</returns>
    private static byte[] CreateSamplePackage()
    {
        using var stream = MemoryStreams.OpenWrite(InitialZipBufferCapacity, out var getBytes);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "_rels/.rels", "<Relationships />");
            WriteEntry(archive, "Sample.nuspec", "<package />");
            WriteEntry(archive, "lib/net10.0/Sample.dll", new('x', SampleAssemblyLength));
            WriteEntry(archive, "[Content_Types].xml", "<Types />");
        }

        return getBytes();
    }

    /// <summary>Writes a deflated UTF-8 text entry.</summary>
    /// <param name="archive">The archive.</param>
    /// <param name="name">The entry name.</param>
    /// <param name="content">The text.</param>
    private static void WriteEntry(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }

    /// <summary>Reads an entry's bytes.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <param name="name">The entry name.</param>
    /// <returns>The entry bytes.</returns>
    /// <exception cref="FileNotFoundException">The entry does not exist.</exception>
    private static byte[] ReadEntry(byte[] zip, string name)
    {
        using var archive = new ZipArchive(MemoryStreams.OpenRead(zip), ZipArchiveMode.Read);
        var entry = archive.GetEntry(name) ?? throw new FileNotFoundException(name);
        using var entryStream = entry.Open();
        using var copy = MemoryStreams.OpenWrite((int)entry.Length, out var getBytes);
        entryStream.CopyTo(copy);
        return getBytes();
    }

    /// <summary>Reads the central directory offset from the end of central directory record.</summary>
    /// <param name="zip">The archive bytes.</param>
    /// <returns>The offset.</returns>
    private static int FindCentralDirectoryOffset(byte[] zip) => NuGetSignatureArchive.ReadDirectory(zip).CentralDirectoryOffset;

    /// <summary>The package bytes before and after signing.</summary>
    /// <param name="Unsigned">The original package bytes.</param>
    /// <param name="Signed">The signed package bytes.</param>
    private readonly record struct SignedNuGetSample(byte[] Unsigned, byte[] Signed);
}
