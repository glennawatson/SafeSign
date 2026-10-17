// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Csc;

/// <summary>Represents a CSC <c>credentials/authorize</c> response.</summary>
/// <param name="Sad">The Signature Activation Data (SAD) token.</param>
[DebuggerDisplay("{Sad}")]
public sealed record CscAuthorizeReply(
    [property: JsonPropertyName("SAD")] string? Sad);
