// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.GaraSign;

/// <summary>Response body from GaraSign <c>POST /sign</c>.</summary>
/// <param name="Signature">The raw signature bytes encoded as an array of signed 8-bit integer values.</param>
/// <param name="RequestId">The signing request identifier used when polling <c>IN_PROGRESS</c> operations.</param>
/// <param name="Status">The operation status (<c>SUCCESS</c>, <c>IN_PROGRESS</c>, or <c>FAILURE</c>).</param>
/// <param name="Message">An optional diagnostic message.</param>
[DebuggerDisplay("{Status,nq} ({RequestId,nq})")]
public sealed record GaraSignSignReply(
    int[]? Signature,
    string? RequestId,
    string? Status,
    string? Message);
