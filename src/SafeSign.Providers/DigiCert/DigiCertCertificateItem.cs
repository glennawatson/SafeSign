// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>A certificate entry returned by <c>GET /signingmanager/api/v1/certificates</c>.</summary>
/// <param name="Id">The certificate identifier.</param>
/// <param name="Alias">The certificate alias.</param>
/// <param name="Cert">The Base64-encoded DER leaf X.509 certificate.</param>
/// <param name="Account">The account owning the certificate.</param>
/// <param name="Keypair">The associated keypair metadata.</param>
/// <param name="Chain">The optional issuer certificate chain.</param>
[DebuggerDisplay("{Alias ?? Id,nq}")]
public sealed record DigiCertCertificateItem(
    string? Id,
    string? Alias,
    string? Cert,
    DigiCertAccountRef? Account,
    DigiCertKeypairRef? Keypair,
    DigiCertChainItem[]? Chain);
