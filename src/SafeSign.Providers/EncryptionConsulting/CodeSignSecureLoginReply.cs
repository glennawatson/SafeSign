// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Response body from <c>POST /api/auth/GetLoginToken/</c>.</summary>
/// <param name="Token">The issued JWT bearer token.</param>
[DebuggerDisplay("Token = {Token is not null}")]
public sealed record CodeSignSecureLoginReply(string? Token);
