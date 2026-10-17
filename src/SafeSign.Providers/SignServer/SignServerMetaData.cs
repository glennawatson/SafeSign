// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignServer;

/// <summary>Worker metadata sent to the Keyfactor SignServer REST <c>process</c> endpoint.</summary>
/// <param name="ClientSideHashing">Indicates whether <c>data</c> is already a precomputed hash (<c>true</c>).</param>
/// <param name="UsingCliSuppliedHashDigestAlgorithm">The digest algorithm name when <paramref name="ClientSideHashing"/> is <c>true</c>.</param>
[DebuggerDisplay("ClientSideHashing = {ClientSideHashing}, Alg = {UsingCliSuppliedHashDigestAlgorithm}")]
public sealed record SignServerMetaData(
    [property: JsonPropertyName("USING_CLIENTSUPPLIED_HASH")] string ClientSideHashing,
    [property: JsonPropertyName("CLIENTSIDE_HASHDIGESTALGORITHM")] string UsingCliSuppliedHashDigestAlgorithm);
