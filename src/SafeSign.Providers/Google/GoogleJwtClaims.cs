// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>The JWT claim set for the service account bearer assertion (RFC 7523).</summary>
/// <param name="Iss">The service account email.</param>
/// <param name="Scope">The requested scopes.</param>
/// <param name="Aud">The token endpoint.</param>
/// <param name="Iat">Issued-at, in Unix seconds.</param>
/// <param name="Exp">Expiry, in Unix seconds.</param>
[DebuggerDisplay("{Iss,nq} -> {Aud,nq}")]
public sealed record GoogleJwtClaims(string Iss, string Scope, string Aud, long Iat, long Exp);
