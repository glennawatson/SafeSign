// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Certum;

/// <summary>An asynchronous SCS1_ATOM task status envelope returned by <c>cloudsign.webnotarius.pl</c>.</summary>
/// <param name="AtomLink">The poll or result URL to follow while the task is running or ready.</param>
/// <param name="PingAfter">The suggested poll delay in milliseconds.</param>
/// <param name="State">The task state (for example <c>failed</c> when rejected).</param>
[DebuggerDisplay("{State,nq} -> {AtomLink,nq}")]
public sealed record CertumTaskStatus(
    [property: JsonPropertyName("atom:link")] string? AtomLink,
    [property: JsonPropertyName("ping-after")] int? PingAfter,
    [property: JsonPropertyName("state")] string? State);
