// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Response body from <c>POST /signingmanager/api/v1/keypairs/{keypairId}/sign</c>.</summary>
/// <param name="Id">The signing operation identifier.</param>
/// <param name="Signature">The Base64-encoded raw signature bytes.</param>
[DebuggerDisplay("{Id,nq}")]
public sealed record DigiCertSignReply(string? Id, string? Signature);
