// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using BenchmarkDotNet.Running;

namespace SafeSign.Benchmarks;

/// <summary>Entry point for BenchmarkDotNet speed benchmarks and the <c>--alloc</c> allocation audit harness.</summary>
public static class Program
{
    /// <summary>Runs either the <c>--alloc</c> allocation justification harness or BenchmarkDotNet.</summary>
    /// <param name="args">Command-line arguments (<c>--alloc [explained.json]</c> or BenchmarkDotNet arguments).</param>
    /// <returns>The process exit code.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="args"/> is null.</exception>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var allocIndex = Array.IndexOf(args, "--alloc");
        if (allocIndex >= 0)
        {
            var explainedPath = allocIndex + 1 < args.Length
                ? args[allocIndex + 1]
                : Path.Combine(AppContext.BaseDirectory, "allocations-explained.json");
            return await AllocationAuditRunner.RunAsync(explainedPath, Console.Out, Console.Error).ConfigureAwait(false);
        }

        _ = await BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).RunAsync(args).ConfigureAwait(false);
        return 0;
    }
}
