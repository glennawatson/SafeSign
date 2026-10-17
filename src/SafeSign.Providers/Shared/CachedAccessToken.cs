// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace SafeSign.Providers.Shared;

/// <summary>A bearer token, the time it stops being usable, and an optional OAuth 2.0 refresh token.</summary>
/// <param name="Value">The token.</param>
/// <param name="ExpiresAt">When it expires.</param>
/// <param name="RefreshToken">An optional refresh token returned alongside the access token.</param>
[DebuggerDisplay("Access token, expires {ExpiresAt}")]
public readonly record struct CachedAccessToken(string Value, DateTimeOffset ExpiresAt, string? RefreshToken)
{
    /// <summary>How many seconds before expiry a token is refreshed.</summary>
    private const int RefreshMarginSeconds = 60;

    /// <summary>Initializes a new instance of the <see cref="CachedAccessToken"/> struct without a refresh token.</summary>
    /// <param name="value">The token.</param>
    /// <param name="expiresAt">When it expires.</param>
    public CachedAccessToken(string value, DateTimeOffset expiresAt)
        : this(value, expiresAt, null)
    {
    }

    /// <inheritdoc/>
    public override string ToString() => $"CachedAccessToken {{ ExpiresAt = {ExpiresAt} }}";

    /// <summary>Gets whether the token can still be sent at <paramref name="now"/>.</summary>
    /// <param name="now">The current time.</param>
    /// <returns>True when the token is set and not near expiry.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool IsUsable(DateTimeOffset now) => Value is { Length: > 0 } && now < ExpiresAt.AddSeconds(-RefreshMarginSeconds);
}
