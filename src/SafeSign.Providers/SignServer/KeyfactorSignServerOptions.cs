// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.SignServer;

/// <summary>Configuration for <see cref="KeyfactorSignServerProvider"/>.</summary>
/// <param name="BaseUri">The Keyfactor SignServer base URI (for example <c>https://signserver.example.com</c>).</param>
/// <param name="Worker">The worker name or ID configured on SignServer (for example <c>PlainSigner</c>).</param>
/// <param name="CertificateFile">The public certificate file path.</param>
/// <param name="BearerToken">The optional Bearer token for REST authentication.</param>
[DebuggerDisplay("BaseUri = {BaseUri}, Worker = {Worker}")]
public sealed record KeyfactorSignServerOptions(
    Uri BaseUri,
    string Worker,
    string CertificateFile,
    string? BearerToken = null);
