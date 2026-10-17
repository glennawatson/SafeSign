// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Vault;

/// <summary>Configuration for <see cref="HashiCorpVaultProvider"/>.</summary>
/// <param name="Address">The Vault server base URI (for example <c>https://vault.example.com:8200</c>).</param>
/// <param name="Token">The Vault authentication token.</param>
/// <param name="KeyName">The Transit secret engine key name.</param>
/// <param name="CertificateFile">The public certificate file path.</param>
/// <param name="MountPath">The Transit mount path (defaults to <c>transit</c>).</param>
/// <param name="Namespace">The optional Vault Enterprise namespace.</param>
[DebuggerDisplay("Address = {Address}, Mount = {MountPath}, Key = {KeyName}")]
public sealed record HashiCorpVaultOptions(
    Uri Address,
    string Token,
    string KeyName,
    string CertificateFile,
    string MountPath = "transit",
    string? Namespace = null);
