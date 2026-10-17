// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Fortanix;

/// <summary>Specifies the RSA PKCS #1 v1.5 signature padding mode in Fortanix DSM.</summary>
/// <param name="Pkcs1V15">The empty PKCS #1 v1.5 configuration dictionary.</param>
[DebuggerDisplay("PKCS1_V15")]
public sealed record FortanixRsaMode(
    [property: JsonPropertyName("PKCS1_V15")] Dictionary<string, string> Pkcs1V15);
