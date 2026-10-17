// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.DigiCert;

/// <summary>Account reference embedded in DigiCert ONE certificate and sign payloads.</summary>
/// <param name="Id">The DigiCert ONE account identifier.</param>
/// <param name="Name">The optional account name.</param>
[DebuggerDisplay("{Id,nq}")]
public sealed record DigiCertAccountRef(string? Id, string? Name);
