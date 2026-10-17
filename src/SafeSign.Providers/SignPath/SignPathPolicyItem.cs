// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SignPath;

/// <summary>Represents a policy entry returned by SignPath <c>Cryptoki/MySigningPolicies</c>.</summary>
/// <param name="ProjectSlug">The project slug.</param>
/// <param name="PolicySlug">The policy slug.</param>
/// <param name="CertificateBytes">The Base64-encoded DER certificate bytes.</param>
[DebuggerDisplay("{ProjectSlug,nq}/{PolicySlug,nq}")]
public sealed record SignPathPolicyItem(
    [property: JsonPropertyName("projectSlug")] string? ProjectSlug,
    [property: JsonPropertyName("signingPolicySlug")] string? PolicySlug,
    [property: JsonPropertyName("certificateBytes")] string? CertificateBytes);
