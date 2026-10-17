// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Oracle;

/// <summary>Source-generated JSON serializer context for Oracle Cloud KMS payloads.</summary>
[DebuggerDisplay("{GetType().Name,nq}")]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(OracleKmsSignRequest))]
[JsonSerializable(typeof(OracleKmsSignResponse))]
public sealed partial class OracleJsonContext : JsonSerializerContext;
