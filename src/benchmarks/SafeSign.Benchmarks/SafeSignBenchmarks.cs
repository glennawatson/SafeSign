// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using SafeSign.Formats.Scripts;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;
using SafeSign.Signing.Pe;

namespace SafeSign.Benchmarks;

/// <summary>Speed and allocation benchmarks for SafeSign's core cryptographic, PE checksum, digest, and signing hot paths.</summary>
[MemoryDiagnoser]
[DebuggerDisplay("SafeSignBenchmarks")]
public class SafeSignBenchmarks
{
    /// <summary>The 64 KiB PE32+ image buffer.</summary>
    private byte[] _executableImage = [];

    /// <summary>The parsed layout of <see cref="_executableImage"/>.</summary>
    private PeLayout _executableLayout;

    /// <summary>The precomputed SHA-256 digest of <see cref="_executableImage"/>.</summary>
    private byte[] _sampleDigest = [];

    /// <summary>The precomputed Authenticode content descriptor.</summary>
    private AuthenticodeContent? _authenticodeContent;

    /// <summary>The in-memory RSA-2048 signing provider.</summary>
    private BenchmarkSigningProvider? _provider;

    /// <summary>The reusable signing session.</summary>
    private SigningSession? _session;

    /// <summary>Temporary directory for file-backed benchmarks.</summary>
    private DirectoryInfo? _tempDir;

    /// <summary>Path to the 64 KiB PE32+ file on disk.</summary>
    private string _executableFilePath = string.Empty;

    /// <summary>Path to the signed PE32+ destination file on disk.</summary>
    private string _executableSignedPath = string.Empty;

    /// <summary>Path to the PowerShell script file on disk.</summary>
    private string _scriptFilePath = string.Empty;

    /// <summary>Path to the signed PowerShell script destination file on disk.</summary>
    private string _scriptSignedPath = string.Empty;

    /// <summary>The reusable <see cref="PeFileSigner"/> instance.</summary>
    private PeFileSigner _executableSigner = new();

    /// <summary>The reusable <see cref="ScriptFileSigner"/> instance.</summary>
    private ScriptFileSigner _scriptSigner = new();

    /// <summary>Initializes benchmark fixtures before running BenchmarkDotNet or the allocation audit.</summary>
    [GlobalSetup]
    public void Setup()
    {
        _executableImage = BenchmarkPeImage.CreatePe32Plus64KiB();
        _executableLayout = PeLayoutReader.Read(_executableImage, _executableImage.Length);
        _sampleDigest = SHA256.HashData(_executableImage);
        _authenticodeContent = new(CmsOids.SpcPeImageData, AuthenticodeEncoding.EncodePeImageData(), _sampleDigest);
        _provider = new();
        _session = new(
            _provider,
            _provider.SigningCertificate,
            HashAlgorithmName.SHA256,
            null,
            "SafeSign Benchmark",
            new("https://github.com/glennawatson/SafeSign"),
            TimeProvider.System);

        _tempDir = Directory.CreateTempSubdirectory("safesign-bench-");
        _executableFilePath = Path.Combine(_tempDir.FullName, "bench.exe");
        _executableSignedPath = Path.Combine(_tempDir.FullName, "bench-signed.exe");
        File.WriteAllBytes(_executableFilePath, _executableImage);

        _scriptFilePath = Path.Combine(_tempDir.FullName, "bench.ps1");
        _scriptSignedPath = Path.Combine(_tempDir.FullName, "bench-signed.ps1");
        File.WriteAllText(_scriptFilePath, "Write-Host 'SafeSign Benchmark Payload'\r\n");

        _executableSigner = new();
        _scriptSigner = new();
    }

    /// <summary>Cleans up temporary files after the benchmark run.</summary>
    [GlobalCleanup]
    public void Cleanup()
    {
        _provider = null;
        if (_tempDir is { Exists: true })
        {
            _tempDir.Delete(recursive: true);
        }
    }

    /// <summary>Measures the zero-allocation SIMD <see cref="PeChecksum"/> over a 64 KiB PE32+ image.</summary>
    /// <returns>The computed 32-bit PE checksum.</returns>
    [Benchmark]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint PeChecksum_64KiB()
    {
        var sum = PeChecksum.Accumulate(_executableImage, 0);
        return PeChecksum.Finish(sum, _executableImage.Length);
    }

    /// <summary>Measures zero-allocation <see cref="PeLayoutReader.Read"/> parsing of a PE32+ header.</summary>
    /// <returns>The parsed <see cref="PeLayout"/>.</returns>
    [Benchmark]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public PeLayout PeLayoutReader_Read() => PeLayoutReader.Read(_executableImage, _executableImage.Length);

    /// <summary>Measures streaming Authenticode PE digest + checksum computation over a 64 KiB PE32+ file.</summary>
    /// <returns>The computed <see cref="PeDigest"/>.</returns>
    [Benchmark]
    public async ValueTask<PeDigest> PeAuthenticodeDigest_64KiB()
    {
        using var handle = File.OpenHandle(_executableFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.Asynchronous);
        return await PeAuthenticodeDigest.ComputeAsync(handle, _executableLayout, _executableImage.Length, HashAlgorithmName.SHA256, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Measures building and signing a DER-encoded Authenticode PKCS #7 <c>SignedData</c> structure.</summary>
    /// <returns>The encoded CMS <c>ContentInfo</c> bytes.</returns>
    [Benchmark]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask<byte[]> AuthenticodeSignature_Build() =>
        AuthenticodeSignatureBuilder.CreateAsync(_session!, _authenticodeContent!, CancellationToken.None);

    /// <summary>Measures end-to-end PE32+ executable signing via <see cref="PeFileSigner"/>.</summary>
    /// <returns>A task representing the asynchronous sign operation.</returns>
    [Benchmark]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask SignPeExecutable_64KiB() =>
        _executableSigner.SignAsync(new(_executableFilePath, _executableSignedPath, _session!), CancellationToken.None);

    /// <summary>Measures end-to-end PowerShell script signing via <see cref="ScriptFileSigner"/>.</summary>
    /// <returns>A task representing the asynchronous sign operation.</returns>
    [Benchmark]
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ValueTask SignPowerShellScript() =>
        _scriptSigner.SignAsync(new(_scriptFilePath, _scriptSignedPath, _session!), CancellationToken.None);
}
