// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Response returned by <c>POST /api/signing/sign/</c>.</summary>
/// <param name="Result">The hexadecimal signature string.</param>
/// <param name="Status">The status string (for example <c>SUCCESS</c>).</param>
/// <param name="Message">An optional diagnostic message.</param>
[DebuggerDisplay("{Status}: {Message}")]
public sealed record CodeSignSecureSignReply(
    string? Result,
    string? Status,
    string? Message);
