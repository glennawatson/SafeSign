// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace SafeSign.Providers.Venafi;

/// <summary>Source-generated JSON serialization context for Venafi CodeSign Protect DTOs.</summary>
[JsonSerializable(typeof(VenafiOAuthRequest))]
[JsonSerializable(typeof(VenafiOAuthReply))]
[JsonSerializable(typeof(VenafiGetObjectsRequest))]
[JsonSerializable(typeof(VenafiCertificateObject))]
[JsonSerializable(typeof(VenafiGetObjectsReply))]
[JsonSerializable(typeof(VenafiSignRequest))]
[JsonSerializable(typeof(VenafiSignReply))]
internal sealed partial class VenafiJsonContext : JsonSerializerContext;
