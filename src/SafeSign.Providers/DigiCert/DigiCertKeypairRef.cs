// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Keypair reference embedded inside a DigiCert ONE certificate item.</summary>
/// <param name="Id">The keypair identifier.</param>
/// <param name="Alias">The keypair alias.</param>
[DebuggerDisplay("{Id,nq}")]
public sealed record DigiCertKeypairRef(string? Id, string? Alias);
