// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Certum;

/// <summary>An entry in the virtual card list returned by <c>POST /card/v1/cards/tasks</c>.</summary>
/// <param name="CardNumber">The card serial number (<c>cardno</c>) used in per-card URLs.</param>
/// <param name="Label">The human-readable card label.</param>
/// <param name="Profile">The card profile identifier.</param>
/// <param name="PinRequired">Whether a separate PIN is required (<c>false</c> on SimplySign cloud cards).</param>
/// <param name="ValidThru">The card expiration string.</param>
[DebuggerDisplay("{CardNumber,nq} ({Label,nq})")]
public sealed record CertumCardInfo(
    [property: JsonPropertyName("cardno")] string? CardNumber,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("profile")] string? Profile,
    [property: JsonPropertyName("pinrequired")] bool PinRequired,
    [property: JsonPropertyName("validthru")] string? ValidThru);
