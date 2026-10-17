// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Azure;

/// <summary>Source-generated JSON metadata for the Key Vault REST API (camelCase members).</summary>
[DebuggerDisplay("AzureKeyVaultJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AzureKeyVaultCertificateBundle))]
[JsonSerializable(typeof(AzureKeyVaultSignPayload))]
public sealed partial class AzureKeyVaultJsonContext : JsonSerializerContext;
