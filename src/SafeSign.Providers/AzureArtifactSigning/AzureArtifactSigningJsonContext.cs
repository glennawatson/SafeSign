// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.AzureArtifactSigning;

/// <summary>Source-generated JSON metadata for the Azure Artifact Signing REST API (camelCase members).</summary>
[DebuggerDisplay("AzureArtifactSigningJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AzureArtifactSignPayload))]
[JsonSerializable(typeof(AzureArtifactSignStatus))]
public sealed partial class AzureArtifactSigningJsonContext : JsonSerializerContext;
