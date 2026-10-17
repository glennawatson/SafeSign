// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignServer;

/// <summary>Source-generated JSON serializer context for Keyfactor SignServer REST payloads.</summary>
[DebuggerDisplay("{GetType().Name,nq}")]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(SignServerMetaData))]
[JsonSerializable(typeof(SignServerSignRequest))]
[JsonSerializable(typeof(SignServerSignResponse))]
public sealed partial class SignServerJsonContext : JsonSerializerContext;
