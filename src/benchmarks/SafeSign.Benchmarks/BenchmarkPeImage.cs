// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;

namespace SafeSign.Benchmarks;

/// <summary>Creates deterministic minimal PE32+ images for speed and allocation benchmarks.</summary>
internal static class BenchmarkPeImage
{
    /// <summary>The size of the generated PE32+ image in bytes (64 KiB).</summary>
    private const int ImageSizeBytes = 65_536;

    /// <summary>The MZ header magic (<c>0x5A4D</c>).</summary>
    private const ushort MzMagic = 0x5A4D;

    /// <summary>The offset of <c>e_lfanew</c> in the DOS header.</summary>
    private const int LfaNewOffset = 0x3C;

    /// <summary>The offset of the PE header.</summary>
    private const int PeHeaderOffset = 0x80;

    /// <summary>The PE signature (<c>PE\0\0</c>).</summary>
    private const uint PeSignature = 0x00004550;

    /// <summary>The AMD64 COFF machine identifier.</summary>
    private const ushort MachineAmd64 = 0x8664;

    /// <summary>The COFF characteristics for an executable image.</summary>
    private const ushort ExecutableCharacteristics = 0x0022;

    /// <summary>The size of a PE32+ Optional Header.</summary>
    private const ushort OptionalHeader64Size = 240;

    /// <summary>The PE32+ Optional Header magic (<c>0x20B</c>).</summary>
    private const ushort Pe32PlusMagic = 0x020B;

    /// <summary>The size of the COFF File Header.</summary>
    private const int CoffHeaderSize = 20;

    /// <summary>The offset of <c>NumberOfSections</c> inside the COFF File Header.</summary>
    private const int CoffNumberOfSectionsOffset = 2;

    /// <summary>The offset of <c>SizeOfOptionalHeader</c> inside the COFF File Header.</summary>
    private const int CoffSizeOfOptionalHeaderOffset = 16;

    /// <summary>The offset of <c>Characteristics</c> inside the COFF File Header.</summary>
    private const int CoffCharacteristicsOffset = 18;

    /// <summary>The offset of <c>NumberOfRvaAndSizes</c> inside a PE32+ Optional Header.</summary>
    private const int NumberOfRvaAndSizesOffset = 108;

    /// <summary>The number of data directories in a standard Optional Header.</summary>
    private const uint StandardDataDirectories = 16;

    /// <summary>The offset of <c>SizeOfHeaders</c> inside the Optional Header.</summary>
    private const int SizeOfHeadersOffset = 60;

    /// <summary>The total size of the headers region.</summary>
    private const uint HeadersRegionSize = 0x200;

    /// <summary>Multiplier for deterministic payload byte generation.</summary>
    private const int PayloadMultiplier = 31;

    /// <summary>Additive constant for deterministic payload byte generation.</summary>
    private const int PayloadAddend = 17;

    /// <summary>Creates a deterministic 64 KiB PE32+ executable image.</summary>
    /// <returns>The raw PE32+ image bytes.</returns>
    internal static byte[] CreatePe32Plus64KiB()
    {
        var image = new byte[ImageSizeBytes];
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0, sizeof(ushort)), MzMagic);
        BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(LfaNewOffset, sizeof(int)), PeHeaderOffset);

        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(PeHeaderOffset, sizeof(uint)), PeSignature);
        var coff = image.AsSpan(PeHeaderOffset + sizeof(uint), CoffHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(coff[..sizeof(ushort)], MachineAmd64);
        BinaryPrimitives.WriteUInt16LittleEndian(coff.Slice(CoffNumberOfSectionsOffset, sizeof(ushort)), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(coff.Slice(CoffSizeOfOptionalHeaderOffset, sizeof(ushort)), OptionalHeader64Size);
        BinaryPrimitives.WriteUInt16LittleEndian(coff.Slice(CoffCharacteristicsOffset, sizeof(ushort)), ExecutableCharacteristics);

        var optional = image.AsSpan(PeHeaderOffset + sizeof(uint) + CoffHeaderSize, OptionalHeader64Size);
        BinaryPrimitives.WriteUInt16LittleEndian(optional[..sizeof(ushort)], Pe32PlusMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(optional.Slice(SizeOfHeadersOffset, sizeof(uint)), HeadersRegionSize);
        BinaryPrimitives.WriteUInt32LittleEndian(optional.Slice(NumberOfRvaAndSizesOffset, sizeof(uint)), StandardDataDirectories);

        for (var i = (int)HeadersRegionSize; i < image.Length; i++)
        {
            image[i] = (byte)((i * PayloadMultiplier) + PayloadAddend);
        }

        return image;
    }
}
