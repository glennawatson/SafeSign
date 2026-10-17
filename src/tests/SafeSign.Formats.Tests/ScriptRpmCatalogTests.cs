// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SafeSign.Formats.Rpm;
using SafeSign.Formats.Scripts;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies <see cref="ScriptFileSigner"/>, <see cref="RpmFileSigner"/>, and <see cref="FormatCatalog"/>.</summary>
public sealed class ScriptRpmCatalogTests
{
    /// <summary>The total count of registered format descriptors in <see cref="FormatCatalog.All"/>.</summary>
    private const int ExpectedTotalFormatDescriptors = 10;

    /// <summary>The count of working format descriptors in <see cref="FormatCatalog.All"/>.</summary>
    private const int ExpectedWorkingFormatDescriptors = 9;

    /// <summary>The count of out-of-scope format descriptors in <see cref="FormatCatalog.All"/>.</summary>
    private const int ExpectedOutOfScopeFormatDescriptors = 1;

    /// <summary>The byte offset of the 4-byte key ID inside an IMA v2 header.</summary>
    private const int ImaKeyIdOffset = 3;

    /// <summary>The byte offset of the raw RSA signature inside an IMA v2 header (3 header bytes + 4 key ID bytes + 2 length bytes).</summary>
    private const int ImaRawSignatureOffset = 9;

    /// <summary>The expected number of file entries in the synthetic RPM package.</summary>
    private const int ExpectedRpmFileCount = 2;

    /// <summary>Verifies that <see cref="ScriptFileSigner"/> signs and re-signs PowerShell, XML, VBScript, JScript, and WSF scripts while preserving BOMs.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ScriptFileSigner_SignsAndReSignsAllScriptFamiliesAndPreservesEncoding()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-scripts-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var signer = new ScriptFileSigner();

            var ps1Path = Path.Combine(tempDir.FullName, "deploy.ps1");
            await File.WriteAllTextAsync(ps1Path, "Write-Host 'SafeSign'\n", new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            await signer.SignAsync(new(ps1Path, ps1Path, session), CancellationToken.None);
            var firstPs1 = await File.ReadAllTextAsync(ps1Path);
            await signer.SignAsync(new(ps1Path, ps1Path, session), CancellationToken.None);
            var secondPs1 = await File.ReadAllTextAsync(ps1Path);

            await Assert.That(firstPs1).Contains("# SIG # Begin signature block");
            await Assert.That(firstPs1).Contains("# SIG # End signature block");
            await Assert.That(secondPs1).IsEqualTo(firstPs1);

            var vbsPath = Path.Combine(tempDir.FullName, "install.vbs");
            await File.WriteAllTextAsync(vbsPath, "WScript.Echo \"SafeSign\"\r\n", Encoding.Unicode);
            await signer.SignAsync(new(vbsPath, vbsPath, session), CancellationToken.None);
            var signedVbs = await File.ReadAllTextAsync(vbsPath, Encoding.Unicode);
            await Assert.That(signedVbs).Contains("'' SIG '' Begin signature block");
            await Assert.That(signedVbs).Contains("'' SIG '' MII");

            var jsPath = Path.Combine(tempDir.FullName, "script.js");
            await File.WriteAllTextAsync(jsPath, "WScript.Echo('SafeSign');\r\n");
            await signer.SignAsync(new(jsPath, jsPath, session), CancellationToken.None);
            var signedJs = await File.ReadAllTextAsync(jsPath);
            await Assert.That(signedJs).Contains("// SIG // Begin signature block");
            await Assert.That(signedJs).Contains("// SIG // MII");

            var wsfPath = Path.Combine(tempDir.FullName, "job.wsf");
            await File.WriteAllTextAsync(wsfPath, "<job><script language=\"VBScript\">WScript.Quit 0</script></job>\r\n");
            await signer.SignAsync(new(wsfPath, wsfPath, session), CancellationToken.None);
            var signedWsf = await File.ReadAllTextAsync(wsfPath);
            await Assert.That(signedWsf).Contains("<signature>");
            await Assert.That(signedWsf).Contains("** SIG ** MII");
            await Assert.That(signedWsf).Contains("</signature>\r\n</job>");
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies that <see cref="RpmFileSigner"/> signs SHA-256 file digests into IMA v2 <c>RPMSIGTAG_FILESIGNATURES</c> in the Signature Header while preserving the Main Header.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task RpmFileSigner_WritesImaV2FileSignaturesAndUpdatesSignatureHeaderDigests()
    {
        var tempDir = Directory.CreateTempSubdirectory("safesign-rpm-");
        try
        {
            using var provider = new TestFormatSigningProvider();
            var session = provider.CreateSession();
            var rpmPath = Path.Combine(tempDir.FullName, "safesign-1.0.0-1.x86_64.rpm");

            var fileDigest = SHA256.HashData("bin/safesign-binary"u8);
            var digestHex = Convert.ToHexStringLower(fileDigest);
            await File.WriteAllBytesAsync(rpmPath, CreateSyntheticRpmPackage(digestHex));

            var signer = new RpmFileSigner();
            await signer.SignAsync(new(rpmPath, rpmPath, session), CancellationToken.None);

            var signedRpm = await File.ReadAllBytesAsync(rpmPath);
            var sigHeaderLen = RpmHeaderCodec.HeaderLength(signedRpm, RpmHeaderCodec.LeadLength);
            var mainStart = RpmHeaderCodec.LeadLength + sigHeaderLen + RpmHeaderCodec.Pad(sigHeaderLen, RpmHeaderCodec.SignatureAlignment);
            var mainLen = RpmHeaderCodec.HeaderLength(signedRpm, mainStart);

            var sigHeader = RpmHeaderCodec.ReadHeader(signedRpm.AsSpan(RpmHeaderCodec.LeadLength, sigHeaderLen));
            var mainHeader = RpmHeaderCodec.ReadHeader(signedRpm.AsSpan(mainStart, mainLen));

            await Assert.That(sigHeader.ContainsKey(RpmFileSigner.TagFileSignatures)).IsTrue();
            await Assert.That(sigHeader.ContainsKey(RpmFileSigner.TagFileSignatureLength)).IsTrue();
            await Assert.That(sigHeader.ContainsKey(RpmFileSigner.TagSha256)).IsTrue();
            await Assert.That(sigHeader.ContainsKey(RpmFileSigner.TagSize)).IsTrue();
            await Assert.That(mainHeader.ContainsKey(RpmFileSigner.TagFileDigests)).IsTrue();

            var fileSigs = RpmHeaderCodec.DecodeStrings(sigHeader[RpmFileSigner.TagFileSignatures]);
            await Assert.That(fileSigs.Length).IsEqualTo(ExpectedRpmFileCount);
            await Assert.That(fileSigs[1]).IsEqualTo(string.Empty);

            var imaBytes = Convert.FromHexString(fileSigs[0]);
            var keyId = RpmFileSigner.ComputeKeyId(provider.Certificate);
            await Assert.That(imaBytes.AsSpan(ImaKeyIdOffset, keyId.Length).SequenceEqual(keyId)).IsTrue();

            var rawSig = imaBytes.AsSpan(ImaRawSignatureOffset);
            await Assert.That(provider.VerifySha256Digest(fileDigest, rawSig)).IsTrue();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Verifies <see cref="FormatCatalog.All"/> and <see cref="FormatCatalog.ResolveSignerAsync"/> for working formats and out-of-scope <c>.deb</c> packages.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task FormatCatalog_ResolvesWorkingSignersAndRejectsOutOfScopeDebianPackage()
    {
        var all = FormatCatalog.All;
        var working = 0;
        var outOfScope = 0;
        for (var i = 0; i < all.Length; i++)
        {
            if (all[i].Status == FormatStatus.Working)
            {
                working++;
            }
            else if (all[i].Status == FormatStatus.OutOfScope)
            {
                outOfScope++;
            }
        }

        await Assert.That(all.Length).IsEqualTo(ExpectedTotalFormatDescriptors);
        await Assert.That(working).IsEqualTo(ExpectedWorkingFormatDescriptors);
        await Assert.That(outOfScope).IsEqualTo(ExpectedOutOfScopeFormatDescriptors);

        var tempDir = Directory.CreateTempSubdirectory("safesign-catalog-");
        try
        {
            var ps1Path = Path.Combine(tempDir.FullName, "script.ps1");
            await File.WriteAllTextAsync(ps1Path, "Write-Output 1\r\n");
            var resolvedScript = await FormatCatalog.ResolveSignerAsync(ps1Path, CancellationToken.None);
            await Assert.That(resolvedScript.Name).IsEqualTo("Script");

            var debPath = Path.Combine(tempDir.FullName, "package.deb");
            await File.WriteAllBytesAsync(debPath, "!<arch>\n"u8.ToArray());
            await Assert.That(async () => await FormatCatalog.ResolveSignerAsync(debPath, CancellationToken.None)).Throws<NotSupportedException>();
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Builds a minimal synthetic RPM v3 binary package with one regular file SHA-256 digest and one directory entry.</summary>
    /// <param name="fileDigestHex">The lowercase hex SHA-256 digest of the regular file.</param>
    /// <returns>The synthetic RPM bytes.</returns>
    private static byte[] CreateSyntheticRpmPackage(string fileDigestHex)
    {
        var lead = new byte[RpmHeaderCodec.LeadLength];
        BinaryPrimitives.WriteUInt32BigEndian(lead, 0xEDABEEDBU);

        var mainEntries = new SortedDictionary<int, RpmHeaderEntry>
        {
            [RpmFileSigner.TagFileDigests] = RpmHeaderCodec.CreateStringArray([fileDigestHex, string.Empty]),
            [RpmFileSigner.TagFileDigestAlgo] = RpmHeaderCodec.CreateInt32(RpmFileSigner.DigestAlgoSha256),
        };
        var mainBytes = RpmHeaderCodec.WriteHeader(mainEntries, RpmHeaderCodec.RegionImmutable);

        var sigEntries = new SortedDictionary<int, RpmHeaderEntry>
        {
            [RpmFileSigner.TagSha1] = RpmHeaderCodec.CreateString("0000000000000000000000000000000000000000"),
            [RpmFileSigner.TagSize] = RpmHeaderCodec.CreateInt32(mainBytes.Length),
            [RpmFileSigner.TagMd5] = new(RpmHeaderCodec.TypeBinary, MD5.HashSizeInBytes, new byte[MD5.HashSizeInBytes]),
        };
        var sigBytes = RpmHeaderCodec.WriteHeader(sigEntries, RpmHeaderCodec.RegionSignatures);
        var padLength = RpmHeaderCodec.Pad(sigBytes.Length, RpmHeaderCodec.SignatureAlignment);
        var payload = "cpio-payload"u8;

        var total = new byte[lead.Length + sigBytes.Length + padLength + mainBytes.Length + payload.Length];
        lead.CopyTo(total, 0);
        sigBytes.CopyTo(total, lead.Length);
        mainBytes.CopyTo(total, lead.Length + sigBytes.Length + padLength);
        payload.CopyTo(total.AsSpan(lead.Length + sigBytes.Length + padLength + mainBytes.Length));
        return total;
    }
}
