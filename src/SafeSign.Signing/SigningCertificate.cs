// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing;

/// <summary>A signing certificate and the intermediate certificates that chain it to a root.</summary>
/// <param name="Certificate">The end-entity code signing certificate. It carries no private key.</param>
/// <param name="Chain">The issuing certificates, nearest issuer first. Self-signed roots are left out.</param>
[DebuggerDisplay("{Certificate.Subject,nq} (+{Chain.Length} issuers)")]
public sealed record SigningCertificate(X509Certificate2 Certificate, X509Certificate2[] Chain);
