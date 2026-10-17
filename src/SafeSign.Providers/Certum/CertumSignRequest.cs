// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Certum;

/// <summary>The JSON <c>req</c> part of a SimplySign <c>POST /card/v1/cards/{serial}/certificates/signature</c> multipart request.</summary>
/// <param name="Digests">The hex-encoded digests to sign.</param>
/// <param name="DigestType">The digest algorithm name (<c>SHA256</c>, <c>SHA384</c>, or <c>SHA512</c>).</param>
[DebuggerDisplay("{DigestType,nq} ({Digests.Length})")]
public sealed record CertumSignRequest(
    [property: JsonPropertyName("digests")] string[] Digests,
    [property: JsonPropertyName("digesttype")] string DigestType);
