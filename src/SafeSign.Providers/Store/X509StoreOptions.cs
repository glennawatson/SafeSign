// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Providers.Store;

/// <summary>Configuration for <see cref="X509StoreProvider"/>.</summary>
/// <param name="Thumbprint">The optional SHA-1 or SHA-256 certificate thumbprint.</param>
/// <param name="SubjectName">The optional subject substring or common name when <paramref name="Thumbprint"/> is omitted.</param>
/// <param name="StoreName">The X.509 store name (defaults to <c>My</c>).</param>
/// <param name="StoreLocation">The X.509 store location (defaults to <see cref="StoreLocation.CurrentUser"/>).</param>
[DebuggerDisplay("Store = {StoreLocation}/{StoreName}, Thumbprint = {Thumbprint}")]
public sealed record X509StoreOptions(
    string? Thumbprint,
    string? SubjectName = null,
     string StoreName = "My",
    StoreLocation StoreLocation = StoreLocation.CurrentUser);
