// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Keypair metadata returned by <c>GET /signingmanager/api/v1/keypairs/{keypairId}</c>.</summary>
/// <param name="Id">The keypair identifier.</param>
/// <param name="Account">The account owning the keypair.</param>
[DebuggerDisplay("{Id,nq}")]
public sealed record DigiCertKeypairDetailReply(
    string? Id,
    DigiCertAccountRef? Account);
