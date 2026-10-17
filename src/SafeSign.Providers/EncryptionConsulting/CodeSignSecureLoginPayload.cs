// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Request body for <c>POST /api/auth/GetLoginToken/</c>.</summary>
/// <param name="User">The login username.</param>
/// <param name="Code">The login secret/password.</param>
/// <param name="IdentityType">The identity type (<c>1</c> for standard user credentials).</param>
[DebuggerDisplay("{User,nq}")]
public sealed record CodeSignSecureLoginPayload(string User, string Code, int IdentityType);
