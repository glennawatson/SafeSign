// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Signing;

namespace SafeSign.Providers.Certum;

/// <summary>A materialized SimplySign cloud card together with its raw PEM certificate and parsed <see cref="SigningCertificate"/>.</summary>
/// <param name="Serial">The card serial number (<c>cardno</c>).</param>
/// <param name="CertificatePem">The exact PEM certificate bytes returned by the card endpoint, required by the signature endpoint.</param>
/// <param name="SigningCertificate">The parsed leaf certificate and issuer chain.</param>
[DebuggerDisplay("{Serial,nq}")]
public sealed record CertumMaterializedCard(
    string Serial,
    ReadOnlyMemory<byte> CertificatePem,
    SigningCertificate SigningCertificate);
