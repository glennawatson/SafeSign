// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using SafeSign.Formats.CompoundFile;

namespace SafeSign.Formats.Tests;

/// <summary>Verifies compound file sector padding, deterministic layout, and input ownership.</summary>
public sealed class CompoundFileWriterTests
{
    /// <summary>The deterministic payload multiplier.</summary>
    private const int PayloadMultiplier = 31;

    /// <summary>The deterministic payload addend.</summary>
    private const int PayloadAddend = 17;

    /// <summary>The number of small streams in the layout cases.</summary>
    private const int MiniStreamCount = 128;

    /// <summary>The deterministic root storage name.</summary>
    private const string RootName = "Root Entry";

    /// <summary>The source buffer padding outside the sliced stream.</summary>
    private const int SourcePadding = 2;

    /// <summary>Verifies exact serialized layouts across mini-sector, regular-sector, and DIFAT boundaries.</summary>
    /// <param name="length">The stream payload length.</param>
    /// <param name="expectedHash">The SHA-256 of the deterministic serialized file.</param>
    /// <param name="cancellationToken">Cancels the test.</param>
    /// <returns>A task representing the asynchronous test.</returns>
    [Test]
    [Arguments(0, "0F15A2F5A587EF5AB96F51667919F903C17D7E19C0D9C84CB2D87EA702F638EB")]
    [Arguments(1, "418C2D62B8FFE64D89F790E439728D494CCADC9FC841671D707CEFA4172CB86C")]
    [Arguments(63, "6EECB2F6D5AD7A499F2D25DC753A6394277C12A26043E7C460656C9BB0C46B4C")]
    [Arguments(64, "F13BAE1A14C3358C38CA0992364A3D2CEBA63B29CBA4F922E7DB0A3406D0F91E")]
    [Arguments(65, "3AEC1288B8535847AA25F2C20B356D6014F93CE408794C4E3A678A88FC108761")]
    [Arguments(300, "A26DDE63A9CE78B46A170874B01C5122F983283A8465225A5170157962FBAB4F")]
    [Arguments(4095, "7EBB0506C48294F9ACBAF9BB67C235EDBDE88DECB2159EB1003FA53CE5C52132")]
    [Arguments(4096, "0A14578EEE1ABC6024D27F61A41F805CC21D5C3C680ADC7E78AEAE53956D123E")]
    [Arguments(4097, "EDE14732512724F28F226B4185FCF4FC4FEED56461807CEC547869A8B4B23E4B")]
    [Arguments(1_048_576, "3270E3B190044FCE51526140F7260AD5BCFD9E93797684ED4CE087EFE1AFE33A")]
    [Arguments(16_777_216, "DA8C068959B022AF5EE402C9CD9694C126655E2CEAF9F22A66DB0BB70086762F")]
    public async Task Write_SectorBoundaries_PreservesExactLayout(int length, string expectedHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var data = CreatePayload(length);
        var count = length < CompoundFileFormat.MiniStreamCutoff ? MiniStreamCount : 1;
        List<CompoundFileEntry> children = [with(capacity: count)];
        for (var i = 0; i < count; i++)
        {
            children.Add(new($"Stream{i:D4}", default, data, null));
        }

        var root = new CompoundFileEntry(RootName, default, ReadOnlyMemory<byte>.Empty, children);
        var serialized = CompoundFileWriter.Write(root, cancellationToken);
        await Assert.That(Convert.ToHexString(SHA256.HashData(serialized))).IsEqualTo(expectedHash);
        var parsed = CompoundFileReader.Read(serialized);
        await Assert.That(parsed.Children!.Count).IsEqualTo(count);
        foreach (var child in parsed.Children)
        {
            await Assert.That(child.Data.Span.SequenceEqual(data)).IsTrue();
        }
    }

    /// <summary>Verifies sliced source memory is copied into independent output without reordering source children.</summary>
    /// <param name="length">The stream payload length.</param>
    /// <param name="cancellationToken">Cancels the test.</param>
    /// <returns>A task representing the asynchronous test.</returns>
    [Test]
    [Arguments(65)]
    [Arguments(4097)]
    public async Task Write_SlicedMemory_PreservesInputAndOutputOwnership(int length, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var data = CreatePayload(length);
        var backing = new byte[length + SourcePadding];
        data.CopyTo(backing.AsSpan(1));
        var first = new CompoundFileEntry("Zulu", default, backing.AsMemory(1, length), null);
        var second = new CompoundFileEntry("Alpha", default, ReadOnlyMemory<byte>.Empty, []);
        List<CompoundFileEntry> children = [first, second];
        var root = new CompoundFileEntry(RootName, default, ReadOnlyMemory<byte>.Empty, children);

        var serialized = CompoundFileWriter.Write(root, cancellationToken);
        backing.AsSpan().Fill(byte.MaxValue);
        var parsed = CompoundFileReader.Read(serialized);
        await Assert.That(children[0]).IsSameReferenceAs(first);
        await Assert.That(children[1]).IsSameReferenceAs(second);
        var stream = parsed.Children!.Find(static e => e.Name == "Zulu");
        await Assert.That(stream).IsNotNull();
        await Assert.That(stream!.Data.Span.SequenceEqual(data)).IsTrue();
    }

    /// <summary>Verifies cancellation is observed before serialization allocates sector storage.</summary>
    /// <returns>A task representing the asynchronous test.</returns>
    [Test]
    public async Task Write_CanceledToken_ThrowsOperationCanceledException()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var root = new CompoundFileEntry(RootName, default, ReadOnlyMemory<byte>.Empty, []);
        await Assert.That(() => CompoundFileWriter.Write(root, cancellation.Token)).Throws<OperationCanceledException>();
    }

    /// <summary>Creates deterministic bytes for layout comparisons.</summary>
    /// <param name="length">The payload length.</param>
    /// <returns>The payload bytes.</returns>
    private static byte[] CreatePayload(int length)
    {
        var bytes = new byte[length];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)((i * PayloadMultiplier) + PayloadAddend);
        }

        return bytes;
    }
}
