// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers;

/// <summary>Whether a provider can sign today.</summary>
public enum ProviderStatus
{
    /// <summary>Implemented end to end against the provider's API.</summary>
    Working = 0,

    /// <summary>Listed so users can see it, but not implemented. The descriptor says why.</summary>
    Planned = 1,
}
