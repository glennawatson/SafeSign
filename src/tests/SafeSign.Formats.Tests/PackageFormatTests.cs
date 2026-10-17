// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.IO.Compression;
using SafeSign.Formats.Appx;
using SafeSign.Formats.Compression;
using SafeSign.Formats.NuGet;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies <see cref="NuGetFileSigner"/>, <see cref="AppxFileSigner"/>, and <see cref="NavxFileSigner"/>.</summary>
public sealed class PackageFormatTests
{
    /// <summary>The initial capacity for synthetic ZIP test archives.</summary>
    private const int InitialZipBufferCapacity = 4096;

    /// <summary>The offset of the <c>NAVX</c> magic marker in a Dynamics 365 extension header.</summary>
    private const int NavxMagicOffset = 4;

    /// <summary>The offset of the inner ZIP length field in a Dynamics 365 <c>NAVX</c> header.</summary>
    private const int NavxPackageSizeOffset = 12;

    /// <summary>Verifies that <see cref="NuGetFileSigner"/> writes <c>.signature.p7s</c> and supports re-signing an already signed <c>.nupkg</c>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task NuGetFileSigner_EmbedsAndReplacesPrimarySignatureEntry()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-nupkg-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var nupkgPath = Path.Combine(tempDir.FullName, "SafeSign.Sample.1.0.0.nupkg");
            await File.WriteAllBytesAsync(nupkgPath, CreateSampleZipPackage("SafeSign.Sample.nuspec", "<package />"));

            var signer = new NuGetFileSigner();
            await signer.SignAsync(new(nupkgPath, nupkgPath, session), CancellationToken.None);
            await signer.SignAsync(new(nupkgPath, nupkgPath, session), CancellationToken.None);

            var sigBytes = ReadZipEntryBytes(await File.ReadAllBytesAsync(nupkgPath), NuGetFileSigner.SignatureEntryPath);

            await Assert.That(sigBytes).IsNotNull();
            await Assert.That(sigBytes!.Length).IsGreaterThan(0);
            await Assert.That(sigBytes[0]).IsEqualTo((byte)0x30);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="AppxFileSigner"/> generates <c>AppxBlockMap.xml</c>, <c>[Content_Types].xml</c>, and <c>AppxSignature.p7x</c> with the <c>PKCX</c> header.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task AppxFileSigner_GeneratesBlockMapContentTypesAndPkcxSignature()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-msix-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var msixPath = Path.Combine(tempDir.FullName, "sample.msix");
            await File.WriteAllBytesAsync(msixPath, CreateSampleZipPackage("AppxManifest.xml", "<Package />"));

            var signer = new AppxFileSigner();
            await signer.SignAsync(new(msixPath, msixPath, session), CancellationToken.None);
            await signer.SignAsync(new(msixPath, msixPath, session), CancellationToken.None);

            var msixBytes = await File.ReadAllBytesAsync(msixPath);
            await Assert.That(ReadZipEntryBytes(msixBytes, "AppxBlockMap.xml")).IsNotNull();
            await Assert.That(ReadZipEntryBytes(msixBytes, "[Content_Types].xml")).IsNotNull();

            var p7xBytes = ReadZipEntryBytes(msixBytes, AppxPackageSigning.SignatureEntryName);
            await Assert.That(p7xBytes).IsNotNull();
            await Assert.That(p7xBytes.AsSpan().StartsWith("PKCX"u8)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="NavxFileSigner"/> preserves the 40-byte <c>NAVX</c> header, signs the inner OPC package, and updates the package size field.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task NavxFileSigner_PreservesNavxHeaderAndSignsEmbeddedPackage()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-navx-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var navxPath = Path.Combine(tempDir.FullName, "extension.navx");

            var innerZip = CreateSampleZipPackage("NavxManifest.xml", "<App />");
            var navxBytes = new byte[NavxFileSigner.NavxHeaderLength + innerZip.Length];
            "NAVX"u8.CopyTo(navxBytes.AsSpan(NavxMagicOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(navxBytes.AsSpan(NavxPackageSizeOffset), (uint)innerZip.Length);
            innerZip.CopyTo(navxBytes.AsSpan(NavxFileSigner.NavxHeaderLength));
            await File.WriteAllBytesAsync(navxPath, navxBytes);

            var signer = new NavxFileSigner();
            await signer.SignAsync(new(navxPath, navxPath, session), CancellationToken.None);

            var signedNavx = await File.ReadAllBytesAsync(navxPath);
            var recordedZipSize = BinaryPrimitives.ReadUInt32LittleEndian(signedNavx.AsSpan(NavxPackageSizeOffset));
            await Assert.That(signedNavx.AsSpan(NavxMagicOffset).StartsWith("NAVX"u8)).IsTrue();
            await Assert.That((int)recordedZipSize).IsEqualTo(signedNavx.Length - NavxFileSigner.NavxHeaderLength);

            var p7xBytes = ReadZipEntryBytes(signedNavx.AsMemory(NavxFileSigner.NavxHeaderLength), AppxPackageSigning.SignatureEntryName);
            await Assert.That(p7xBytes).IsNotNull();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Reads an entry's uncompressed bytes from an in-memory ZIP archive, or returns <see langword="null"/> when missing.</summary>
    /// <param name="zipBytes">The ZIP archive bytes.</param>
    /// <param name="entryName">The entry path.</param>
    /// <returns>The entry bytes, or <see langword="null"/>.</returns>
    private static byte[]? ReadZipEntryBytes(ReadOnlyMemory<byte> zipBytes, string entryName)
    {
        using var stream = MemoryStreams.OpenRead(zipBytes);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        var entry = archive.GetEntry(entryName);
        if (entry is null)
        {
            return null;
        }

        using var entryStream = entry.Open();
        using var copy = MemoryStreams.OpenWrite((int)entry.Length, out var getBytes);
        entryStream.CopyTo(copy);
        return getBytes();
    }

    /// <summary>Creates a sample ZIP archive containing <paramref name="entryName"/> plus <c>AppxBlockMap.xml</c> and <c>[Content_Types].xml</c>.</summary>
    /// <param name="entryName">The primary manifest entry path.</param>
    /// <param name="content">The primary manifest text.</param>
    /// <returns>The serialized ZIP archive bytes.</returns>
    private static byte[] CreateSampleZipPackage(string entryName, string content)
    {
        using var stream = MemoryStreams.OpenWrite(InitialZipBufferCapacity, out var getBytes);
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteZipEntryText(archive, entryName, content);
            WriteZipEntryText(archive, "AppxBlockMap.xml", "<BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\" />");
            WriteZipEntryText(archive, "[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>");
        }

        return getBytes();
    }

    /// <summary>Writes a UTF-8 text entry into <paramref name="archive"/>.</summary>
    /// <param name="archive">The target ZIP archive.</param>
    /// <param name="entryName">The entry path.</param>
    /// <param name="content">The text content.</param>
    private static void WriteZipEntryText(ZipArchive archive, string entryName, string content)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Fastest);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }
}
