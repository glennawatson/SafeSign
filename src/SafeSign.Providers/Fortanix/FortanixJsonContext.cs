// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace SafeSign.Providers.Fortanix;

/// <summary>Source-generated JSON serialization context for Fortanix DSM DTOs.</summary>
[JsonSerializable(typeof(FortanixAuthReply))]
[JsonSerializable(typeof(FortanixKeyObject))]
[JsonSerializable(typeof(FortanixRsaMode))]
[JsonSerializable(typeof(FortanixSignPayload))]
[JsonSerializable(typeof(FortanixSignReply))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class FortanixJsonContext : JsonSerializerContext;
