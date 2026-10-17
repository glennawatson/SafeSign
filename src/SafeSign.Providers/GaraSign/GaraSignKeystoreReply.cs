// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.GaraSign;

/// <summary>Response body from GaraSign <c>POST /keystore</c>.</summary>
/// <param name="Keys">The keys available in the GaraSign keystore.</param>
/// <param name="RequestId">The request identifier.</param>
/// <param name="Status">The operation status (<c>SUCCESS</c> or <c>FAILURE</c>).</param>
/// <param name="Message">An optional diagnostic error message.</param>
[DebuggerDisplay("{Status,nq} (Keys = {Keys?.Length ?? 0})")]
public sealed record GaraSignKeystoreReply(
    GaraSignKeyItem[]? Keys,
    string? RequestId,
    string? Status,
    string? Message);
