// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign;

/// <summary>Raw command-line arguments captured for the <c>sign</c> subcommand.</summary>
/// <param name="Files">The file paths to sign.</param>
/// <param name="ProviderName">The <c>--provider</c> identifier.</param>
/// <param name="ProviderOptionEntries">The <c>name=value</c> entries supplied via <c>--provider-option</c>.</param>
/// <param name="OutputPath">An optional destination file path when signing a single input file.</param>
/// <param name="DigestAlgorithm">The file digest algorithm name (<c>SHA256</c>, <c>SHA384</c>, or <c>SHA512</c>).</param>
/// <param name="TimestampUrl">An optional RFC 3161 timestamp authority URL.</param>
/// <param name="TimestampDigestAlgorithm">The RFC 3161 timestamp digest algorithm name (<c>SHA256</c>, <c>SHA384</c>, or <c>SHA512</c>).</param>
/// <param name="Description">An optional program description embedded in Authenticode signatures.</param>
/// <param name="DescriptionUrl">An optional program information URL embedded in Authenticode signatures.</param>
/// <param name="SkipPackageContents">True to sign only the package itself and leave the DLLs and EXEs inside it as they are.</param>
[DebuggerDisplay("{ProviderName,nq} ({Files.Length} files)")]
public sealed record SignCommandInput(
    string[] Files,
    string ProviderName,
    string[] ProviderOptionEntries,
    string? OutputPath,
    string DigestAlgorithm,
    string? TimestampUrl,
    string TimestampDigestAlgorithm,
    string? Description,
    string? DescriptionUrl,
    bool SkipPackageContents = false);
