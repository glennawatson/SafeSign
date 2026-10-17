// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;

namespace SafeSign.Signing;

/// <summary>Everything a file format needs to produce a signature, resolved once per run.</summary>
/// <param name="Provider">The key provider.</param>
/// <param name="Certificate">The signing certificate and chain, fetched once from <paramref name="Provider"/>.</param>
/// <param name="DigestAlgorithm">The file and signature digest algorithm.</param>
/// <param name="Timestamp">The timestamp authority, or null to leave signatures untimestamped.</param>
/// <param name="Description">The optional program name written into Authenticode signatures.</param>
/// <param name="DescriptionUrl">The optional "more information" URL written into Authenticode signatures.</param>
/// <param name="Time">The clock for signing-time attributes.</param>
[DebuggerDisplay("{Provider.Name,nq} {DigestAlgorithm.Name,nq}")]
public sealed record SigningSession(
    ISigningProvider Provider,
    SigningCertificate Certificate,
    HashAlgorithmName DigestAlgorithm,
    TimestampSettings? Timestamp,
    string? Description,
    Uri? DescriptionUrl,
    TimeProvider Time);
