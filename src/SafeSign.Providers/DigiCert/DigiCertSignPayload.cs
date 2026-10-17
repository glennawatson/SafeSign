// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Request body for <c>POST /signingmanager/api/v1/keypairs/{keypairId}/sign</c>.</summary>
/// <param name="Account">The optional account reference.</param>
/// <param name="SigAlg">The JCA signature algorithm name, such as <c>SHA256withRSA</c> or <c>SHA256withECDSA</c>.</param>
/// <param name="Hash">The Base64-encoded raw digest bytes.</param>
[DebuggerDisplay("{SigAlg,nq}")]
public sealed record DigiCertSignPayload(DigiCertAccountRef? Account, string SigAlg, string Hash);
