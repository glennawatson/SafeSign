// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a Venafi <c>/vedhsm/api/getobjects</c> response.</summary>
/// <param name="Success">Whether the operation succeeded.</param>
/// <param name="Certificates">The array of matching certificate objects.</param>
[DebuggerDisplay("Success = {Success}, Count = {Certificates?.Length ?? 0}")]
public sealed record VenafiGetObjectsReply(
    [property: JsonPropertyName("Success")] bool Success,
    [property: JsonPropertyName("Certificates")] VenafiCertificateObject[]? Certificates);
