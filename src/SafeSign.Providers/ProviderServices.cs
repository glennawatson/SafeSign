// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using Refit;

namespace SafeSign.Providers;

/// <summary>Shared services a provider factory may use.</summary>
/// <param name="Http">The Refit transport settings.</param>
/// <param name="Time">The clock.</param>
[DebuggerDisplay("ProviderServices")]
public sealed record ProviderServices(RefitSettings Http, TimeProvider Time)
{
    /// <summary>Initializes a new instance of the <see cref="ProviderServices"/> class with default Refit settings and the system clock.</summary>
    public ProviderServices()
        : this(new RefitSettings(), TimeProvider.System)
    {
    }
}
