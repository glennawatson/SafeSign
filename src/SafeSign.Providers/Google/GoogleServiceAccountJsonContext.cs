// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Google;

/// <summary>Source-generated JSON metadata for service account key files (snake_case members).</summary>
[DebuggerDisplay("GoogleServiceAccountJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
[JsonSerializable(typeof(GoogleServiceAccountKey))]
public sealed partial class GoogleServiceAccountJsonContext : JsonSerializerContext;
