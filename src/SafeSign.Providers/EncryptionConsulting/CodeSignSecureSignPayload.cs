// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.EncryptionConsulting;

/// <summary>Request body for <c>POST /api/signing/sign/</c>.</summary>
/// <param name="CertificateName">The certificate key alias in CodeSign Secure.</param>
/// <param name="Hash">The lowercase hexadecimal digest to sign.</param>
[DebuggerDisplay("{CertificateName,nq}")]
public sealed record CodeSignSecureSignPayload(
    [property: JsonPropertyName("certificate_name")] string CertificateName,
    string Hash);
