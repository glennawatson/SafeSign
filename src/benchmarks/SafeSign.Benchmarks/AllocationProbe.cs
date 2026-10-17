// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;

namespace SafeSign.Benchmarks;

/// <summary>
/// Measures the managed bytes allocated on the current thread while running a synchronous or asynchronous operation,
/// keeping the minimum across multiple warmed-up attempts to filter out one-off tier-up Jitting events.
/// </summary>
public static class AllocationProbe
{
    /// <summary>The default number of measurement attempts after warmup.</summary>
    private const int DefaultAttempts = 5;

    /// <summary>Runs <paramref name="work"/> several times after warmup and returns the minimum allocated bytes.</summary>
    /// <param name="work">The synchronous workload to measure.</param>
    /// <returns>The smallest number of bytes allocated by a single invocation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="work"/> is null.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static long Minimum(Action work) => Minimum(work, DefaultAttempts);

    /// <summary>Runs <paramref name="work"/> <paramref name="attempts"/> times and returns the minimum allocated bytes.</summary>
    /// <param name="work">The synchronous workload to measure.</param>
    /// <param name="attempts">The number of attempts, at least 1.</param>
    /// <returns>The smallest number of bytes allocated by a single invocation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="work"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="attempts"/> is less than 1.</exception>
    public static long Minimum(Action work, int attempts)
    {
        ArgumentNullException.ThrowIfNull(work);
        ArgumentOutOfRangeException.ThrowIfLessThan(attempts, 1);

        work();
        var smallest = long.MaxValue;
        for (var attempt = 0; attempt < attempts && smallest > 0; attempt++)
        {
            var before = GC.GetAllocatedBytesForCurrentThread();
            work();
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            smallest = Math.Min(smallest, allocated);
        }

        return smallest;
    }

    /// <summary>Runs <paramref name="work"/> several times after warmup and returns the minimum allocated bytes.</summary>
    /// <param name="work">The asynchronous workload to measure.</param>
    /// <returns>The smallest number of bytes allocated by a single invocation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="work"/> is null.</exception>
    public static async ValueTask<long> MinimumAsync(Func<ValueTask> work)
    {
        ArgumentNullException.ThrowIfNull(work);

        await work().ConfigureAwait(false);
        var smallest = long.MaxValue;
        for (var attempt = 0; attempt < DefaultAttempts && smallest > 0; attempt++)
        {
            var before = GC.GetTotalAllocatedBytes(precise: true);
            await work().ConfigureAwait(false);
            var allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
            smallest = Math.Min(smallest, allocated);
        }

        return smallest;
    }
}
