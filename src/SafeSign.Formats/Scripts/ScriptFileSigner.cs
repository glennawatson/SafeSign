// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using SafeSign.Signing;
using SafeSign.Signing.Authenticode;
using SafeSign.Signing.Cms;

namespace SafeSign.Formats.Scripts;

/// <summary>
/// Signs Windows and PowerShell script files (<c>.ps1</c>, <c>.psm1</c>, <c>.psd1</c>, <c>.ps1xml</c>,
/// <c>.vbs</c>, <c>.vbe</c>, <c>.js</c>, <c>.wsf</c>) with native Authenticode comment signature blocks.
/// </summary>
[DebuggerDisplay("{Name,nq}")]
public sealed class ScriptFileSigner : IFileFormatSigner
{
    /// <summary>The PowerShell SIP version (<c>0x00010000</c>).</summary>
    private const int PowerShellSipVersion = 0x00010000;

    /// <summary>The Windows Script Host SIP version (<c>1</c>).</summary>
    private const int WshSipVersion = 1;

    /// <summary>The base64 line width inside a script signature block.</summary>
    private const int Base64LineWidth = 64;

    /// <summary>The byte length of a UTF-8 byte order mark.</summary>
    private const int Utf8BomLength = 3;

    /// <summary>The byte length of a UTF-16 byte order mark.</summary>
    private const int Utf16BomLength = 2;

    /// <summary>Extra capacity reserved for signature block markers and newlines.</summary>
    private const int SignatureFramingCapacity = 256;

    /// <summary>The PowerShell SIP GUID for PowerShell scripts and XML files.</summary>
    private static readonly Guid PowerShellSipGuid = new("603BCC1F-4B59-4E08-B724-D2C6297EF351");

    /// <summary>The VBScript SIP GUID for Windows Script Host VBScript files.</summary>
    private static readonly Guid VbScriptSipGuid = new("1629F04E-2799-4DB5-8FE5-ACE10F17EBAB");

    /// <summary>The JScript SIP GUID for Windows Script Host JScript files.</summary>
    private static readonly Guid JScriptSipGuid = new("06C9E010-38CE-11D4-A2A3-00104BD35090");

    /// <summary>The Windows Script File SIP GUID for Windows Script Host package files.</summary>
    private static readonly Guid WsfSipGuid = new("1A610570-38CE-11D4-A2A3-00104BD35090");

    /// <summary>Cached UTF-8 encoding without a byte order mark.</summary>
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>Cached UTF-16 little-endian encoding without a byte order mark.</summary>
    private static readonly UnicodeEncoding Utf16LeNoBom = new(bigEndian: false, byteOrderMark: false);

    /// <summary>Cached UTF-16 big-endian encoding without a byte order mark.</summary>
    private static readonly UnicodeEncoding Utf16BeNoBom = new(bigEndian: true, byteOrderMark: false);

    /// <inheritdoc/>
    public string Name => "Script";

    /// <summary>Gets the 3-byte UTF-8 byte order mark.</summary>
    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    /// <summary>Gets the 2-byte UTF-16 little-endian byte order mark.</summary>
    private static ReadOnlySpan<byte> Utf16LeBom => [0xFF, 0xFE];

    /// <summary>Gets the 2-byte UTF-16 big-endian byte order mark.</summary>
    private static ReadOnlySpan<byte> Utf16BeBom => [0xFE, 0xFF];

    /// <summary>Attempts to resolve the <see cref="ScriptFormat"/> for a file extension.</summary>
    /// <param name="extension">The file extension including leading period.</param>
    /// <param name="format">Receives the matching <see cref="ScriptFormat"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="extension"/> is a supported script extension.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="extension"/> is null.</exception>
    public static bool TryGetFormat(string extension, out ScriptFormat format)
    {
        ArgumentNullException.ThrowIfNull(extension);
        (var matched, format) = extension.ToUpperInvariant() switch
        {
            ".PS1" or ".PSM1" or ".PSD1" => (true, new ScriptFormat(
                PowerShellSipGuid,
                PowerShellSipVersion,
                "# SIG # Begin signature block",
                "# SIG # End signature block",
                "# ",
                string.Empty)),
            ".PS1XML" or ".CDXML" or ".PSC1" => (true, new ScriptFormat(
                PowerShellSipGuid,
                PowerShellSipVersion,
                "<!-- SIG # Begin signature block -->",
                "<!-- SIG # End signature block -->",
                "<!-- ",
                " -->")),
            ".VBS" or ".VBE" => (true, new ScriptFormat(
                VbScriptSipGuid,
                WshSipVersion,
                "'' SIG '' Begin signature block",
                "'' SIG '' End signature block",
                "'' ",
                string.Empty)),
            ".JS" => (true, new ScriptFormat(
                JScriptSipGuid,
                WshSipVersion,
                "// SIG // Begin signature block",
                "// SIG // End signature block",
                "// ",
                string.Empty)),
            ".WSF" => (true, new ScriptFormat(
                WsfSipGuid,
                WshSipVersion,
                "<!-- SIG # Begin signature block -->",
                "<!-- SIG # End signature block -->",
                "<!-- ",
                " -->")),
            _ => (false, default),
        };
        return matched;
    }

    /// <summary>Formats and appends the base64 Authenticode signature block to <paramref name="unsignedScript"/>.</summary>
    /// <param name="unsignedScript">The unsigned script ending with <c>\r\n</c>.</param>
    /// <param name="format">The script format.</param>
    /// <param name="cmsSignature">The DER-encoded Authenticode PKCS #7 signature.</param>
    /// <returns>The complete signed script text.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="unsignedScript"/> is null.</exception>
    public static string AppendSignatureBlock(string unsignedScript, in ScriptFormat format, ReadOnlySpan<byte> cmsSignature)
    {
        ArgumentNullException.ThrowIfNull(unsignedScript);
        var base64 = Convert.ToBase64String(cmsSignature);
        var builder = new StringBuilder(unsignedScript.Length + base64.Length + SignatureFramingCapacity);
        _ = builder.Append(unsignedScript);
        _ = builder.Append(format.BeginMarker).Append("\r\n");
        for (var offset = 0; offset < base64.Length; offset += Base64LineWidth)
        {
            var count = Math.Min(Base64LineWidth, base64.Length - offset);
            _ = builder.Append(format.LinePrefix)
                .Append(base64, offset, count)
                .Append(format.LineSuffix)
                .Append("\r\n");
        }

        _ = builder.Append(format.EndMarker).Append("\r\n");
        return builder.ToString();
    }

    /// <inheritdoc/>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanSign(FileProbe probe) => TryGetFormat(probe.Extension, out _);

    /// <inheritdoc/>
    public ValueTask SignAsync(FileSignRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryGetFormat(Path.GetExtension(request.InputPath), out var format))
        {
            throw new InvalidDataException($"Unsupported script extension for '{request.InputPath}'.");
        }

        return SignedFileOutput.WriteAsync(
            request.InputPath,
            request.OutputPath,
            (path, token) => SignPathAsync(path, format, request.Session, token),
            cancellationToken);
    }

    /// <summary>Signs a script file in place.</summary>
    /// <param name="path">The script path.</param>
    /// <param name="format">The script format metadata.</param>
    /// <param name="session">The signing session.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    private static async ValueTask SignPathAsync(
        string path,
        ScriptFormat format,
        SigningSession session,
        CancellationToken cancellationToken)
    {
        var rawBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var (encoding, preambleLength) = DetectEncoding(rawBytes);
        var scriptText = encoding.GetString(rawBytes.AsSpan(preambleLength));
        var unsignedScript = StripExistingSignatureBlock(scriptText, in format);

        var utf16Bytes = Encoding.Unicode.GetBytes(unsignedScript);
        var digest = CryptographicOperations.HashData(session.DigestAlgorithm, utf16Bytes);
        var cmsSignature = await AuthenticodeSignatureBuilder.CreateAsync(
            session,
            new(CmsOids.SpcSipInfo, AuthenticodeEncoding.EncodeSipInfo(format.SipVersion, format.SipGuid), digest),
            cancellationToken).ConfigureAwait(false);

        var signedText = AppendSignatureBlock(unsignedScript, in format, cmsSignature);
        var bodyBytes = encoding.GetBytes(signedText);
        var output = new byte[preambleLength + bodyBytes.Length];
        rawBytes.AsSpan(0, preambleLength).CopyTo(output);
        bodyBytes.CopyTo(output.AsSpan(preambleLength));
        await File.WriteAllBytesAsync(path, output, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Detects the text encoding and BOM length of <paramref name="bytes"/>.</summary>
    /// <param name="bytes">The raw file bytes.</param>
    /// <returns>The text encoding and byte order mark length.</returns>
    private static (Encoding Encoding, int PreambleLength) DetectEncoding(ReadOnlySpan<byte> bytes)
    {
        if (bytes.StartsWith(Utf8Bom))
        {
            return (Utf8NoBom, Utf8BomLength);
        }

        if (bytes.StartsWith(Utf16LeBom))
        {
            return (Utf16LeNoBom, Utf16BomLength);
        }

        return bytes.StartsWith(Utf16BeBom)
            ? (Utf16BeNoBom, Utf16BomLength)
            : (Utf8NoBom, 0);
    }

    /// <summary>Strips any existing Authenticode comment signature block and ensures a trailing <c>\r\n</c>.</summary>
    /// <param name="scriptText">The decoded script text.</param>
    /// <param name="format">The script format.</param>
    /// <returns>The unsigned script text ending with <c>\r\n</c>.</returns>
    private static string StripExistingSignatureBlock(string scriptText, in ScriptFormat format)
    {
        var beginIndex = scriptText.LastIndexOf(format.BeginMarker, StringComparison.Ordinal);
        if (beginIndex >= 0)
        {
            var endIndex = scriptText.IndexOf(format.EndMarker, beginIndex, StringComparison.Ordinal);
            if (endIndex > beginIndex)
            {
                scriptText = scriptText[..beginIndex];
            }
        }

        if (scriptText.EndsWith("\r\n", StringComparison.Ordinal))
        {
            return scriptText;
        }

        return scriptText.EndsWith('\n')
            ? $"{scriptText.AsSpan(0, scriptText.Length - 1)}\r\n"
            : $"{scriptText}\r\n";
    }
}
