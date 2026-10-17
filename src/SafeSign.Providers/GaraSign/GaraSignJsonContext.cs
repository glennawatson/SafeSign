// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.GaraSign;

/// <summary>Source-generated JSON metadata for the Garantir GaraSign REST API (camelCase members).</summary>
[DebuggerDisplay("GaraSignJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(GaraSignAuthReply))]
[JsonSerializable(typeof(GaraSignKeyItem))]
[JsonSerializable(typeof(GaraSignKeystoreReply))]
[JsonSerializable(typeof(GaraSignSignReply))]
public sealed partial class GaraSignJsonContext : JsonSerializerContext;
