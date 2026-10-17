// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.DigiCert;

/// <summary>Source-generated JSON metadata for the DigiCert ONE Signing Manager REST API (snake_case members).</summary>
[DebuggerDisplay("DigiCertJsonContext")]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(DigiCertKeypairRef))]
[JsonSerializable(typeof(DigiCertAccountRef))]
[JsonSerializable(typeof(DigiCertChainItem))]
[JsonSerializable(typeof(DigiCertCertificateItem))]
[JsonSerializable(typeof(DigiCertCertificatesReply))]
[JsonSerializable(typeof(DigiCertKeypairDetailReply))]
[JsonSerializable(typeof(DigiCertSignPayload))]
[JsonSerializable(typeof(DigiCertSignReply))]
public sealed partial class DigiCertJsonContext : JsonSerializerContext;
