// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;

namespace SafeSign.Signing.Tests;

/// <summary>Builds minimal valid PE32 and PE32+ executable images for signing tests.</summary>
internal static class TestPeImages
{
    /// <summary>The DOS MZ signature.</summary>
    private const ushort DosMagic = 0x5A4D;

    /// <summary>The offset of e_lfanew in the DOS header.</summary>
    private const int PePointerOffset = 0x3C;

    /// <summary>The offset where the PE header starts.</summary>
    private const int PeHeaderStart = 0x80;

    /// <summary>The PE signature.</summary>
    private const uint PeSignature = 0x00004550;

    /// <summary>The x86 machine type.</summary>
    private const ushort MachineI386 = 0x014C;

    /// <summary>The x64 machine type.</summary>
    private const ushort MachineAmd64 = 0x8664;

    /// <summary>The PE32 optional header magic.</summary>
    private const ushort Pe32Magic = 0x010B;

    /// <summary>The PE32+ optional header magic.</summary>
    private const ushort Pe32PlusMagic = 0x020B;

    /// <summary>The offset of NumberOfSections in the COFF file header.</summary>
    private const int CoffSectionCountOffset = 2;

    /// <summary>The offset of SizeOfOptionalHeader in the COFF file header.</summary>
    private const int CoffOptionalHeaderSizeOffset = 16;

    /// <summary>The size of the COFF file header.</summary>
    private const int CoffHeaderSize = 20;

    /// <summary>The size of a PE32 optional header with 16 data directories.</summary>
    private const ushort Pe32OptionalHeaderSize = 224;

    /// <summary>The size of a PE32+ optional header with 16 data directories.</summary>
    private const ushort Pe32PlusOptionalHeaderSize = 240;

    /// <summary>The number of data directories in a standard optional header.</summary>
    private const uint DataDirectoryCount = 16;

    /// <summary>The offset of NumberOfRvaAndSizes in a PE32 optional header.</summary>
    private const int Pe32RvaCountOffset = 92;

    /// <summary>The offset of NumberOfRvaAndSizes in a PE32+ optional header.</summary>
    private const int Pe32PlusRvaCountOffset = 108;

    /// <summary>The total size of the synthetic test PE image.</summary>
    private const int ImageSize = 4096;

    /// <summary>The offset where section data begins.</summary>
    private const int SectionDataOffset = 512;

    /// <summary>The prime multiplier used to fill synthetic section payload bytes.</summary>
    private const int PayloadMultiplier = 31;

    /// <summary>Creates a synthetic PE32 (32-bit) or PE32+ (64-bit) image in memory.</summary>
    /// <param name="isPe32Plus">Whether to create a 64-bit PE32+ header.</param>
    /// <returns>The synthetic PE image bytes.</returns>
    internal static byte[] Create(bool isPe32Plus)
    {
        var buffer = new byte[ImageSize];
        var span = buffer.AsSpan();

        BinaryPrimitives.WriteUInt16LittleEndian(span, DosMagic);
        BinaryPrimitives.WriteInt32LittleEndian(span[PePointerOffset..], PeHeaderStart);

        BinaryPrimitives.WriteUInt32LittleEndian(span[PeHeaderStart..], PeSignature);
        var coff = span[(PeHeaderStart + sizeof(uint))..];
        BinaryPrimitives.WriteUInt16LittleEndian(coff, isPe32Plus ? MachineAmd64 : MachineI386);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[CoffSectionCountOffset..], 1);
        var optionalSize = isPe32Plus ? Pe32PlusOptionalHeaderSize : Pe32OptionalHeaderSize;
        BinaryPrimitives.WriteUInt16LittleEndian(coff[CoffOptionalHeaderSizeOffset..], optionalSize);

        var optional = coff[CoffHeaderSize..];
        BinaryPrimitives.WriteUInt16LittleEndian(optional, isPe32Plus ? Pe32PlusMagic : Pe32Magic);
        var rvaCountOffset = isPe32Plus ? Pe32PlusRvaCountOffset : Pe32RvaCountOffset;
        BinaryPrimitives.WriteUInt32LittleEndian(optional[rvaCountOffset..], DataDirectoryCount);

        for (var i = SectionDataOffset; i < buffer.Length; i++)
        {
            buffer[i] = unchecked((byte)(i * PayloadMultiplier));
        }

        return buffer;
    }
}
