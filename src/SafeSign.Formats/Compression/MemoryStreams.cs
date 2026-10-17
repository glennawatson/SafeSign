// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;

namespace SafeSign.Formats.Compression;

/// <summary>
/// Creates read-only and growable memory-backed streams using .NET 11's <c>ReadOnlyMemoryStream</c> and
/// <c>WritableMemoryStream</c> on <c>net11.0</c>, with <see cref="MemoryStream"/> fallbacks on <c>net10.0</c>.
/// </summary>
public static class MemoryStreams
{
    /// <summary>Creates a read-only stream over <paramref name="memory"/> without copying.</summary>
    /// <param name="memory">The source bytes.</param>
    /// <returns>A readable stream over <paramref name="memory"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Stream OpenRead(ReadOnlyMemory<byte> memory)
    {
#if NET11_0_OR_GREATER
        return new ReadOnlyMemoryStream(memory);
#else
        return System.Runtime.InteropServices.MemoryMarshal.TryGetArray(memory, out var segment) && segment.Array is not null
            ? new MemoryStream(segment.Array, segment.Offset, segment.Count, writable: false)
            : new MemoryStream(memory.ToArray(), writable: false);
#endif
    }

    /// <summary>Creates a fixed-capacity writable stream over <paramref name="destination"/> without copying.</summary>
    /// <param name="destination">The destination memory buffer.</param>
    /// <returns>A writable stream over <paramref name="destination"/>.</returns>
    /// <exception cref="NotSupportedException">The memory buffer is not backed by an array on <c>net10.0</c>.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Stream OpenFixedWrite(Memory<byte> destination)
    {
#if NET11_0_OR_GREATER
        return new WritableMemoryStream(destination);
#else
        return System.Runtime.InteropServices.MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)destination, out var segment) && segment.Array is not null
            ? new MemoryStream(segment.Array, segment.Offset, segment.Count, writable: true)
            : throw new NotSupportedException("Fixed-buffer MemoryStream on net10.0 requires an array-backed Memory<byte>.");
#endif
    }

    /// <summary>Creates a growable writable stream and returns a reader for its accumulated bytes.</summary>
    /// <param name="initialCapacity">The initial buffer capacity in bytes.</param>
    /// <param name="getBytes">A delegate that extracts the written bytes from the returned stream.</param>
    /// <returns>A writable memory stream.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Stream OpenWrite(int initialCapacity, out Func<byte[]> getBytes)
    {
        var stream = new MemoryStream(initialCapacity);
        getBytes = stream.ToArray;
        return stream;
    }
}
