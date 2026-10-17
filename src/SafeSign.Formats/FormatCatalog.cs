// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using SafeSign.Formats.Appx;
using SafeSign.Formats.Cab;
using SafeSign.Formats.Catalog;
using SafeSign.Formats.Msi;
using SafeSign.Formats.NuGet;
using SafeSign.Formats.Rpm;
using SafeSign.Formats.Scripts;
using SafeSign.Signing;
using SafeSign.Signing.Pe;

namespace SafeSign.Formats;

/// <summary>Provides the catalog of file formats and resolves the matching <see cref="IFileFormatSigner"/> for a target file.</summary>
public static class FormatCatalog
{
    /// <summary>The maximum number of leading file bytes read when probing a file's magic header.</summary>
    private const int ProbeHeaderLength = 64;

    /// <summary>Gets all known format descriptors, distinguishing working X.509/CMS/IMA formats from out-of-scope OpenPGP formats.</summary>
    public static FormatDescriptor[] All { get; } =
    [
        new(
            "pe",
            "Windows Portable Executable & UEFI",
            FormatStatus.Working,
            [".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".efi"],
            "Native Authenticode PE signature (WIN_CERTIFICATE in Certificate Table data directory 4, recalculated PE checksum)."),
        new(
            "msi",
            "Windows Installer Compound File",
            FormatStatus.Working,
            [".msi", ".msp", ".mst"],
            "Native OLE Compound File Authenticode signature (\\x05MsiDigitalSignatureEx and \\x05DigitalSignature streams)."),
        new(
            "cab",
            "Microsoft Cabinet Archive",
            FormatStatus.Working,
            [".cab"],
            "Native Cabinet Authenticode signature (CFHEADER reserve header with SPC_CAB_DATA_OBJID)."),
        new(
            "cat",
            "Windows Security Catalog",
            FormatStatus.Working,
            [".cat"],
            "Native PKCS #7 SignedData wrapping the ASN.1 CertificateTrustList (1.3.6.1.4.1.311.10.1)."),
        new(
            "appx",
            "Windows App Package / Bundle",
            FormatStatus.Working,
            [".appx", ".msix", ".appxbundle", ".msixbundle"],
            "Native AppxSignature.p7x (PKCX + Authenticode SPC_SIPINFO_OBJID over AXPC/AXCI/AXBM/AXCD composite digest)."),
        new(
            "navx",
            "Dynamics 365 Business Central Extension",
            FormatStatus.Working,
            [".navx"],
            "Native NAVX header + OPC package with AppxSignature.p7x (PKCX + Authenticode SPC_SIPINFO_OBJID)."),
        new(
            "nupkg",
            "NuGet Package",
            FormatStatus.Working,
            [".nupkg", ".snupkg"],
            "Native NuGet v1 Author Primary Signature (.signature.p7s with commitment-type-indication and SigningCertificateV2)."),
        new(
            "script",
            "Windows & PowerShell Scripts",
            FormatStatus.Working,
            [".ps1", ".psm1", ".psd1", ".ps1xml", ".cdxml", ".psc1", ".vbs", ".vbe", ".js", ".wsf"],
            "Native Authenticode comment signature block (# SIG # / '' SIG '' / // SIG // / <!-- SIG # --> over UTF-16LE digest)."),
        new(
            "rpm",
            "Red Hat Package Manager",
            FormatStatus.Working,
            [".rpm"],
            "Native RPM IMA v2 file signatures (RPMTAG_FILESIGNATURES 5090 / 5091) with updated Signature Header SHA-256/SHA-1/MD5/SIZE."),
        new(
            "deb",
            "Debian Binary Package",
            FormatStatus.OutOfScope,
            [".deb", ".udeb"],
            "Out of scope: native Debian package signing (debsigs _gpgorigin and APT InRelease/Release.gpg) requires OpenPGP (RFC 4880) rather than X.509/CMS."),
    ];

    /// <summary>Gets the ordered list of working file format signers.</summary>
    public static IFileFormatSigner[] Signers { get; } =
    [
        new PeFileSigner(),
        new MsiFileSigner(),
        new CabFileSigner(),
        new CatalogFileSigner(),
        new NavxFileSigner(),
        new AppxFileSigner(),
        new NuGetFileSigner(),
        new RpmFileSigner(),
        new ScriptFileSigner(),
    ];

    /// <summary>Probes <paramref name="path"/> and returns the matching <see cref="IFileFormatSigner"/>.</summary>
    /// <param name="path">The file path to inspect.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The matching <see cref="IFileFormatSigner"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> is null, empty, or whitespace.</exception>
    /// <exception cref="FileNotFoundException"><paramref name="path"/> does not exist.</exception>
    /// <exception cref="NotSupportedException">The file format is out of scope or unrecognized.</exception>
    public static async ValueTask<IFileFormatSigner> ResolveSignerAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"The file '{path}' does not exist.", path);
        }

        var extension = Path.GetExtension(path);
        if (extension.Equals(".deb", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".udeb", StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException(
                $"Debian packages ('{extension}') are out of scope: native Debian signing requires OpenPGP (RFC 4880) signatures rather than X.509/CMS.");
        }

        var buffer = new byte[ProbeHeaderLength];
        int bytesRead;
        using (var handle = File.OpenHandle(path))
        {
            bytesRead = await RandomAccess.ReadAsync(handle, buffer, fileOffset: 0, cancellationToken).ConfigureAwait(false);
        }

        var probe = new FileProbe(path, buffer.AsMemory(0, bytesRead));
        for (var i = 0; i < Signers.Length; i++)
        {
            var signer = Signers[i];
            if (signer.CanSign(probe))
            {
                return signer;
            }
        }

        throw new NotSupportedException($"No supported X.509/CMS/IMA file format signer matched '{path}' (extension '{extension}').");
    }
}
