// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Response envelope from <c>GET /signingmanager/api/v1/certificates</c>.</summary>
/// <param name="Items">The matching certificate items.</param>
[DebuggerDisplay("Count = {Items?.Length ?? 0}")]
public sealed record DigiCertCertificatesReply(DigiCertCertificateItem[]? Items);
