// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Fortanix;

/// <summary>Represents the Fortanix DSM <c>POST /sys/v1/session/auth</c> response.</summary>
/// <param name="AccessToken">The session bearer access token.</param>
[DebuggerDisplay("{AccessToken}")]
public sealed record FortanixAuthReply(
    [property: JsonPropertyName("access_token")] string? AccessToken);
