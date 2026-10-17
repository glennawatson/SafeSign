// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Shared;

/// <summary>Configures exponential backoff, fuzzy jitter, and provider-hint handling for transient HTTP retries and task polling.</summary>
/// <param name="MaxRetries">The maximum number of retry attempts after the initial request fails.</param>
/// <param name="InitialDelay">The initial backoff or minimum poll delay before the first retry.</param>
/// <param name="MaxDelay">The upper bound on any computed backoff or provider-suggested delay.</param>
/// <param name="BackoffMultiplier">The exponential growth factor applied on each subsequent retry attempt.</param>
/// <param name="JitterRatio">The fractional random jitter factor in <c>[0.0, 1.0]</c> applied to fuzz delays.</param>
[DebuggerDisplay("MaxRetries = {MaxRetries}, InitialDelay = {InitialDelay}, MaxDelay = {MaxDelay}, Jitter = {JitterRatio}")]
public sealed record ProviderRetryOptions(
    int MaxRetries,
    TimeSpan InitialDelay,
    TimeSpan MaxDelay,
    double BackoffMultiplier,
    double JitterRatio)
{
    /// <summary>The default retry count for transient HTTP failures.</summary>
    private const int DefaultMaxRetries = 3;

    /// <summary>The default initial backoff delay in milliseconds.</summary>
    private const int DefaultInitialDelayMilliseconds = 200;

    /// <summary>The default maximum backoff delay in milliseconds.</summary>
    private const int DefaultMaxDelayMilliseconds = 15_000;

    /// <summary>The maximum delay in milliseconds for fast in-memory tests.</summary>
    private const int FastTestMaxDelayMilliseconds = 50;

    /// <summary>The default exponential multiplier between attempts.</summary>
    private const double DefaultBackoffMultiplier = 2.0;

    /// <summary>The default fuzzy jitter ratio (±25%).</summary>
    private const double DefaultJitterRatio = 0.25;

    /// <summary>Gets the default retry policy with exponential backoff and ±25% fuzzy jitter.</summary>
    public static ProviderRetryOptions Default { get; } = new(
        DefaultMaxRetries,
        TimeSpan.FromMilliseconds(DefaultInitialDelayMilliseconds),
        TimeSpan.FromMilliseconds(DefaultMaxDelayMilliseconds),
        DefaultBackoffMultiplier,
        DefaultJitterRatio);

    /// <summary>Gets a retry policy with zero delay for fast in-memory testing.</summary>
    public static ProviderRetryOptions FastTest { get; } = new(
        DefaultMaxRetries,
        TimeSpan.Zero,
        TimeSpan.FromMilliseconds(FastTestMaxDelayMilliseconds),
        DefaultBackoffMultiplier,
        0.0);
}
