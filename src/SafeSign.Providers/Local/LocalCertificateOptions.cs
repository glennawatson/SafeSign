// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Local;

/// <summary>Configuration for <see cref="LocalCertificateProvider"/>.</summary>
/// <param name="CertificateFile">The path to a PKCS #12 (<c>.pfx</c>/<c>.p12</c>), PEM, DER, or PKCS #7 certificate file.</param>
/// <param name="Password">The optional password for an encrypted PKCS #12 or PEM key file.</param>
/// <param name="KeyFile">The optional PEM private key file when <paramref name="CertificateFile"/> is a public certificate.</param>
[DebuggerDisplay("Cert = {CertificateFile,nq}")]
public sealed record LocalCertificateOptions(string CertificateFile, string? Password = null, string? KeyFile = null);
