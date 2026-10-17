// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Csc;

/// <summary>Represents a CSC <c>POST /credentials/info</c> request payload.</summary>
/// <param name="CredentialId">The credential identifier.</param>
/// <param name="Certificates">The certificate chain mode (<c>chain</c>).</param>
[DebuggerDisplay("{CredentialId,nq}")]
public sealed record CscCredentialsInfoRequest(
    [property: JsonPropertyName("credentialID")] string CredentialId,
    [property: JsonPropertyName("certificates")] string Certificates);
