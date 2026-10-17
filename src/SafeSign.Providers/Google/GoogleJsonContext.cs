// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Google;

/// <summary>Source-generated JSON metadata for Cloud KMS and the JWT assertion (camelCase members).</summary>
[DebuggerDisplay("GoogleJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(GoogleKmsSignRequest))]
[JsonSerializable(typeof(GoogleKmsSignResponse))]
[JsonSerializable(typeof(GoogleJwtHeader))]
[JsonSerializable(typeof(GoogleJwtClaims))]
public sealed partial class GoogleJsonContext : JsonSerializerContext;
