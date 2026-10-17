// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>The JOSE header of the service account bearer assertion.</summary>
/// <param name="Alg">Always <c>RS256</c>.</param>
/// <param name="Typ">Always <c>JWT</c>.</param>
/// <param name="Kid">The service account key ID, when known.</param>
[DebuggerDisplay("{Alg,nq} {Kid,nq}")]
public sealed record GoogleJwtHeader(string Alg, string Typ, string? Kid);
