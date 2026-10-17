// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>An issuer certificate entry inside a DigiCert ONE certificate item's <c>chain</c> list.</summary>
/// <param name="CertType">The certificate role (<c>intermediate</c> or <c>root</c>).</param>
/// <param name="Blob">The Base64-encoded DER X.509 certificate.</param>
[DebuggerDisplay("{CertType,nq}")]
public sealed record DigiCertChainItem(string? CertType, string? Blob);
