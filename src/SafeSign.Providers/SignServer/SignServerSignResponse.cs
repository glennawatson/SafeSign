// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignServer;

/// <summary>Response returned by Keyfactor SignServer REST <c>POST /signserver/rest/v1/workers/{worker}/process</c>.</summary>
/// <param name="Data">The base64-encoded signature bytes.</param>
/// <param name="ArchiveId">The optional archive identifier.</param>
[DebuggerDisplay("ArchiveId = {ArchiveId}")]
public sealed record SignServerSignResponse(
    [property: JsonPropertyName("data")] string? Data,
    [property: JsonPropertyName("archiveId")] string? ArchiveId);
