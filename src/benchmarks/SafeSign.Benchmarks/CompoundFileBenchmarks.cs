// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using SafeSign.Formats.CompoundFile;

namespace SafeSign.Benchmarks;

/// <summary>Measures compound file serialization and parsing across mini-stream, regular-sector, and DIFAT sizes.</summary>
[MemoryDiagnoser]
[EventPipeProfiler(EventPipeProfile.GcVerbose)]
public class CompoundFileBenchmarks
{
    /// <summary>The deterministic payload multiplier.</summary>
    private const int PayloadMultiplier = 31;

    /// <summary>The deterministic payload addend.</summary>
    private const int PayloadAddend = 17;

    /// <summary>The number of streams in the mini-stream workload.</summary>
    private const int MiniStreamCount = 128;

    /// <summary>The input storage tree.</summary>
    private CompoundFileEntry? _root;

    /// <summary>The serialized input for parsing.</summary>
    private byte[] _serialized = [];

    /// <summary>Gets or sets the payload length of each stream.</summary>
    [Params(300, 4097, 1_048_576, 16_777_216)]
    public int StreamLength { get; set; }

    /// <summary>Creates deterministic stream data and validates the parsing fixture.</summary>
    /// <exception cref="InvalidDataException">The fixture did not round-trip.</exception>
    [GlobalSetup]
    public void Setup()
    {
        var data = new byte[StreamLength];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)((i * PayloadMultiplier) + PayloadAddend);
        }

        var count = StreamLength < CompoundFileFormat.MiniStreamCutoff ? MiniStreamCount : 1;
        List<CompoundFileEntry> children = [with(capacity: count)];
        for (var i = 0; i < count; i++)
        {
            children.Add(new($"Stream{i:D4}", default, data, null));
        }

        _root = new("Root Entry", default, ReadOnlyMemory<byte>.Empty, children);
        _serialized = CompoundFileWriter.Write(_root, CancellationToken.None);
        var parsed = CompoundFileReader.Read(_serialized);
        if (parsed.Children?.Count != count || parsed.Children.Exists(e => !e.Data.Span.SequenceEqual(data)))
        {
            throw new InvalidDataException("The compound file benchmark fixture did not round-trip.");
        }
    }

    /// <summary>Serializes the complete storage tree, including sector allocation and output copying.</summary>
    /// <returns>The serialized compound file bytes.</returns>
    [Benchmark]
    public byte[] Write() => CompoundFileWriter.Write(_root!, CancellationToken.None);

    /// <summary>Parses the complete file and materializes its stream payloads.</summary>
    /// <returns>The parsed root storage.</returns>
    [Benchmark]
    public object Read() => CompoundFileReader.Read(_serialized);
}
