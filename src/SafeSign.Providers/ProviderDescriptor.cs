// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Signing;

namespace SafeSign.Providers;

/// <summary>A provider entry in <see cref="ProviderCatalog"/>.</summary>
/// <param name="Name">The name passed to <c>--provider</c>.</param>
/// <param name="DisplayName">The vendor and product name.</param>
/// <param name="Status">Whether it can sign today.</param>
/// <param name="Summary">How it authenticates and which options it reads, or why it is not implemented.</param>
/// <param name="Create">Builds the provider, or null when <paramref name="Status"/> is <see cref="ProviderStatus.Planned"/>.</param>
[DebuggerDisplay("{Name,nq} ({Status})")]
public sealed record ProviderDescriptor(
    string Name,
    string DisplayName,
    ProviderStatus Status,
    string Summary,
    Func<ProviderSettings, ProviderServices, ISigningProvider>? Create);
