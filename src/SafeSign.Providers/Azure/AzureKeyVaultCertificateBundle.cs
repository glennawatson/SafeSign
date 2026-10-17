// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Azure;

/// <summary>The parts of a Key Vault <c>CertificateBundle</c> SafeSign reads.</summary>
/// <param name="Kid">The identifier of the key backing the certificate, including its version.</param>
/// <param name="Cer">The DER certificate, base64 in JSON.</param>
[DebuggerDisplay("{Kid,nq}")]
public sealed record AzureKeyVaultCertificateBundle(string? Kid, ReadOnlyMemory<byte> Cer);
