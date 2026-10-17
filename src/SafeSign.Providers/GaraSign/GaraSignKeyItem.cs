// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.GaraSign;

/// <summary>A key entry returned by GaraSign <c>POST /keystore</c>.</summary>
/// <param name="Name">The key alias.</param>
/// <param name="Algorithm">The key family (<c>RSA</c> or <c>EC</c>).</param>
/// <param name="CertChain">The DER certificate chain encoded as arrays of signed 8-bit integer values.</param>
[DebuggerDisplay("{Name,nq} ({Algorithm,nq})")]
public sealed record GaraSignKeyItem(
    string? Name,
    string? Algorithm,
    int[][]? CertChain);
