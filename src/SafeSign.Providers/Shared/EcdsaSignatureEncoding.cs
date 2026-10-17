// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Security.Cryptography;

namespace SafeSign.Providers.Shared;

/// <summary>Converts ECDSA signatures between the IEEE P1363 <c>r||s</c> layout and the DER <c>Ecdsa-Sig-Value</c>.</summary>
public static class EcdsaSignatureEncoding
{
    /// <summary>Re-encodes an IEEE P1363 signature as a DER <c>SEQUENCE { r INTEGER, s INTEGER }</c>.</summary>
    /// <param name="signature">The fixed-width <c>r||s</c> signature.</param>
    /// <returns>The DER-encoded signature.</returns>
    /// <exception cref="CryptographicException">The input is empty or has an odd length.</exception>
    public static byte[] IeeeP1363ToDer(ReadOnlySpan<byte> signature)
    {
        if (signature.IsEmpty || (signature.Length & 1) != 0)
        {
            throw new CryptographicException("An IEEE P1363 ECDSA signature must be a non-empty, even number of bytes.");
        }

        var half = signature.Length >> 1;
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(TrimLeadingZeros(signature[..half]));
            writer.WriteIntegerUnsigned(TrimLeadingZeros(signature[half..]));
        }

        return writer.Encode();
    }

    /// <summary>Drops leading zero bytes so the integer is minimally encoded, keeping at least one byte.</summary>
    /// <param name="value">The big-endian unsigned integer.</param>
    /// <returns>The trimmed integer.</returns>
    private static ReadOnlySpan<byte> TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        var start = value.IndexOfAnyExcept((byte)0);
        return start < 0 ? value[^1..] : value[start..];
    }
}
