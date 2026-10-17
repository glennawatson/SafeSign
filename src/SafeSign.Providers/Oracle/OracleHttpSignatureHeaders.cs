// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Oracle;

/// <summary>The HTTP headers produced by an OCI request signature.</summary>
/// <param name="DateHeader">The RFC 1123 request date.</param>
/// <param name="ContentSha256Base64">The Base64-encoded SHA-256 body digest.</param>
/// <param name="AuthorizationHeader">The OCI signature authorization value.</param>
[DebuggerDisplay("{DateHeader,nq}")]
public readonly record struct OracleHttpSignatureHeaders(
    string DateHeader,
    string ContentSha256Base64,
    string AuthorizationHeader);
