// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Benchmarks;

/// <summary>Describes an expected and justified allocation budget for a benchmarked SafeSign operation.</summary>
/// <param name="Benchmark">The benchmark identifier.</param>
/// <param name="Site">The primary allocating method or component.</param>
/// <param name="MaxBytesPerOperation">The maximum allowed bytes allocated per operation.</param>
/// <param name="Reason">Why the allocation is required and why pooling or elision was accepted or rejected.</param>
[DebuggerDisplay("{Benchmark,nq}: <= {MaxBytesPerOperation} B/op ({Site,nq})")]
public sealed record ExplainedAllocation(
    string Benchmark,
    string Site,
    long MaxBytesPerOperation,
    string Reason);
