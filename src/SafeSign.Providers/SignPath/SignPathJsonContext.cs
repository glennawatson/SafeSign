// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignPath;

/// <summary>Source-generated JSON serialization context for SignPath DTOs.</summary>
[JsonSerializable(typeof(SignPathPolicyItem))]
[JsonSerializable(typeof(SignPathPoliciesReply))]
[JsonSerializable(typeof(SignPathArtifactPayload))]
[JsonSerializable(typeof(SignPathSignReply))]
internal sealed partial class SignPathJsonContext : JsonSerializerContext;
