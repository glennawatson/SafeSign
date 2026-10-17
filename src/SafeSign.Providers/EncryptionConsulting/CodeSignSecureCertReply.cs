// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Response body from <c>GET /api/certificate_manage/activecerts/?key={alias}</c>.</summary>
/// <param name="Message">The Base64-encoded PEM certificate dump.</param>
[DebuggerDisplay("MessageLength = {Message?.Length ?? 0}")]
public sealed record CodeSignSecureCertReply(string? Message);
