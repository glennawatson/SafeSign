// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Csc;

/// <summary>Represents the certificate container inside a CSC <c>credentials/info</c> response.</summary>
/// <param name="Certificates">The array of Base64-encoded DER certificates.</param>
[DebuggerDisplay("Count = {Certificates?.Length ?? 0}")]
public sealed record CscCertificateData(
    [property: JsonPropertyName("certificates")] string[]? Certificates);
