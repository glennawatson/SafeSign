// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Fortanix;

/// <summary>Represents a Fortanix DSM <c>POST /crypto/v1/sign</c> response.</summary>
/// <param name="Signature">The Base64-encoded signature bytes.</param>
[DebuggerDisplay("{Signature}")]
public sealed record FortanixSignReply(
    [property: JsonPropertyName("signature")] string? Signature);
