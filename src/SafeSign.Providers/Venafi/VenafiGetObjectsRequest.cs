// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Represents a Venafi <c>POST /vedhsm/api/getobjects</c> request payload.</summary>
/// <param name="EnvironmentFilter">The environment filter array.</param>
/// <param name="ObjectTypeFilter">The object type filter array (<c>1</c> for certificates).</param>
/// <param name="IncludeChains">Whether certificate chains should be included.</param>
/// <param name="LabelFilter">The certificate label filter array.</param>
[DebuggerDisplay("Labels = {LabelFilter.Length}")]
public sealed record VenafiGetObjectsRequest(
    [property: JsonPropertyName("EnvironmentFilter")] int[] EnvironmentFilter,
    [property: JsonPropertyName("ObjectTypeFilter")] int[] ObjectTypeFilter,
    [property: JsonPropertyName("IncludeChains")] bool IncludeChains,
    [property: JsonPropertyName("LabelFilter")] string[] LabelFilter);
