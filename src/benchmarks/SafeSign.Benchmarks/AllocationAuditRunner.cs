// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text.Json;

namespace SafeSign.Benchmarks;

/// <summary>
/// Measures thread allocations for synchronous benchmarks and process-wide allocations for asynchronous benchmarks, then verifies them
/// against <c>allocations-explained.json</c>. Fails if any benchmark lacks an explanation or exceeds its budget.
/// </summary>
public static class AllocationAuditRunner
{
    /// <summary>The exit code when all allocations are within budget and justified.</summary>
    private const int ExitSuccess = 0;

    /// <summary>The exit code when an allocation is unexplained or exceeds its budget.</summary>
    private const int ExitFailure = 1;

    /// <summary>Runs the allocation audit across all <see cref="SafeSignBenchmarks"/> operations.</summary>
    /// <param name="explainedJsonPath">Path to <c>allocations-explained.json</c>.</param>
    /// <param name="output">Receives the allocation report.</param>
    /// <param name="error">Receives failure diagnostics.</param>
    /// <returns>The exit code (<c>0</c> when all allocations are explained and within budget, <c>1</c> otherwise).</returns>
    /// <exception cref="ArgumentNullException">Any parameter is null.</exception>
    /// <exception cref="FileNotFoundException"><paramref name="explainedJsonPath"/> does not exist.</exception>
    public static async Task<int> RunAsync(string explainedJsonPath, TextWriter output, TextWriter error)
    {
        ArgumentNullException.ThrowIfNull(explainedJsonPath);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        if (!File.Exists(explainedJsonPath))
        {
            throw new FileNotFoundException($"Allocation justification file '{explainedJsonPath}' was not found.", explainedJsonPath);
        }

        ExplainedAllocation[] explained;
        await using (var stream = File.OpenRead(explainedJsonPath))
        {
            explained = await JsonSerializer.DeserializeAsync(stream, AllocationJsonContext.Default.ExplainedAllocationArray, CancellationToken.None).ConfigureAwait(false) ?? [];
        }

        var measurements = await MeasureAllAsync().ConfigureAwait(false);
        var failures = 0;
        for (var i = 0; i < measurements.Length; i++)
        {
            var (name, bytes) = measurements[i];
            var entry = FindExplanation(explained, name);
            if (entry is null)
            {
                failures++;
                await error.WriteLineAsync($"UNEXPLAINED {name}: allocated {bytes} B/op with no entry in allocations-explained.json.").ConfigureAwait(false);
                continue;
            }

            var status = bytes <= entry.MaxBytesPerOperation ? "OK" : "EXCEEDED";
            if (bytes > entry.MaxBytesPerOperation)
            {
                failures++;
            }

            var line = string.Create(
                CultureInfo.InvariantCulture,
                $"[{status}] {name}: {bytes:N0} B/op (budget <= {entry.MaxBytesPerOperation:N0} B/op) in {entry.Site}\n  Justification: {entry.Reason}");
            await output.WriteLineAsync(line).ConfigureAwait(false);
        }

        var summary = failures == 0
            ? "All benchmark allocations are within budget and justified."
            : $"{failures} benchmark allocation problem(s) detected.";
        await output.WriteLineAsync(summary).ConfigureAwait(false);
        return failures == 0 ? ExitSuccess : ExitFailure;
    }

    /// <summary>Runs all benchmark operations under <see cref="AllocationProbe"/> and returns their minimum allocations.</summary>
    /// <returns>The measured benchmark names and allocated byte counts.</returns>
    private static async ValueTask<BenchmarkAllocation[]> MeasureAllAsync()
    {
        var benchmarks = new SafeSignBenchmarks();
        benchmarks.Setup();
        try
        {
            return
            [
                new(nameof(SafeSignBenchmarks.PeChecksum_64KiB), AllocationProbe.Minimum(() => _ = benchmarks.PeChecksum_64KiB())),
                new(nameof(SafeSignBenchmarks.PeLayoutReader_Read), AllocationProbe.Minimum(() => _ = benchmarks.PeLayoutReader_Read())),
                new(
                    nameof(SafeSignBenchmarks.PeAuthenticodeDigest_64KiB),
                    await AllocationProbe.MinimumAsync(async () => _ = await benchmarks.PeAuthenticodeDigest_64KiB().ConfigureAwait(false)).ConfigureAwait(false)),
                new(
                    nameof(SafeSignBenchmarks.AuthenticodeSignature_Build),
                    await AllocationProbe.MinimumAsync(async () => _ = await benchmarks.AuthenticodeSignature_Build().ConfigureAwait(false)).ConfigureAwait(false)),
                new(nameof(SafeSignBenchmarks.SignPeExecutable_64KiB), await AllocationProbe.MinimumAsync(() => benchmarks.SignPeExecutable_64KiB()).ConfigureAwait(false)),
                new(nameof(SafeSignBenchmarks.SignPowerShellScript), await AllocationProbe.MinimumAsync(() => benchmarks.SignPowerShellScript()).ConfigureAwait(false)),
            ];
        }
        finally
        {
            benchmarks.Cleanup();
        }
    }

    /// <summary>Finds the matching <see cref="ExplainedAllocation"/> for a benchmark name.</summary>
    /// <param name="explained">The loaded explanations.</param>
    /// <param name="benchmarkName">The benchmark name.</param>
    /// <returns>The matching <see cref="ExplainedAllocation"/>, or null if not found.</returns>
    private static ExplainedAllocation? FindExplanation(ExplainedAllocation[] explained, string benchmarkName)
    {
        for (var i = 0; i < explained.Length; i++)
        {
            if (string.Equals(explained[i].Benchmark, benchmarkName, StringComparison.Ordinal))
            {
                return explained[i];
            }
        }

        return null;
    }
}
