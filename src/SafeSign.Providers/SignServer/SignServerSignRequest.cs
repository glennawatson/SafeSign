// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignServer;

/// <summary>Request payload for Keyfactor SignServer REST <c>POST /signserver/rest/v1/workers/{worker}/process</c>.</summary>
/// <param name="Data">The base64-encoded digest bytes.</param>
/// <param name="Encoding">The payload encoding (<c>BASE64</c>).</param>
/// <param name="MetaData">The worker metadata specifying client-side hashing and digest algorithm.</param>
[DebuggerDisplay("Encoding = {Encoding}")]
public sealed record SignServerSignRequest(
    [property: JsonPropertyName("data")] string Data,
    [property: JsonPropertyName("encoding")] string Encoding,
    [property: JsonPropertyName("metaData")] SignServerMetaData MetaData);
