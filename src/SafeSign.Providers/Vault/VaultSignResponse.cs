// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Vault;

/// <summary>Envelope returned by the HashiCorp Vault Transit <c>sign</c> endpoint.</summary>
/// <param name="Data">The inner response data.</param>
[DebuggerDisplay("{Data}")]
public sealed record VaultSignResponse([property: JsonPropertyName("data")] VaultSignData? Data);
