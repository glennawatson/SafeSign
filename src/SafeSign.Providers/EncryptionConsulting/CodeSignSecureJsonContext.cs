// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Source-generated JSON metadata for the Encryption Consulting CodeSign Secure REST API (camelCase members).</summary>
[DebuggerDisplay("CodeSignSecureJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CodeSignSecureLoginPayload))]
[JsonSerializable(typeof(CodeSignSecureLoginReply))]
[JsonSerializable(typeof(CodeSignSecureCertReply))]
[JsonSerializable(typeof(CodeSignSecureSignPayload))]
[JsonSerializable(typeof(CodeSignSecureSignReply))]
public sealed partial class CodeSignSecureJsonContext : JsonSerializerContext;
