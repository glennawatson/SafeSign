// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Vault;

/// <summary>Inner <c>data</c> object returned by the HashiCorp Vault Transit <c>sign</c> endpoint.</summary>
/// <param name="Signature">The Vault-prefixed signature string (<c>vault:v1:&lt;base64&gt;</c>).</param>
[DebuggerDisplay("{Signature,nq}")]
public sealed record VaultSignData([property: JsonPropertyName("signature")] string? Signature);
