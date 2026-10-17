// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SafeSign.Providers.Certum;

/// <summary>
/// Generates RFC 6238 Time-Based One-Time Passwords for Certum SimplySign. Certum SimplySign uses
/// HMAC-SHA-256, 6 digits, and a 30-second period by default unless overridden by an <c>otpauth://</c> URI.
/// </summary>
[DebuggerDisplay("{Algorithm}, {Digits} digits, {PeriodSeconds}s")]
public sealed class CertumTotp
{
    /// <summary>The minimum supported number of OTP digits.</summary>
    private const int MinDigits = 6;

    /// <summary>The number of OTP digits for 7-digit codes.</summary>
    private const int SevenDigits = 7;

    /// <summary>The maximum supported number of OTP digits.</summary>
    private const int MaxDigits = 8;

    /// <summary>The default Certum TOTP time step in seconds.</summary>
    private const int DefaultPeriodSeconds = 30;

    /// <summary>The number of bits per Base32 character.</summary>
    private const int BitsPerBase32Char = 5;

    /// <summary>The number of bits per decoded byte.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The Base32 alphabet offset where digits <c>2</c>–<c>7</c> begin.</summary>
    private const int Base32DigitOffset = 26;

    /// <summary>The byte length of the 64-bit big-endian TOTP counter.</summary>
    private const int CounterByteLength = 8;

    /// <summary>The maximum HMAC digest byte length (HMAC-SHA-512).</summary>
    private const int MaxMacByteLength = 64;

    /// <summary>The RFC 4226 dynamic truncation offset mask.</summary>
    private const int OffsetMask = 0x0F;

    /// <summary>The RFC 4226 highest-byte sign-bit mask.</summary>
    private const uint HighByteMask = 0x7FU;

    /// <summary>Offset to the third byte of the 4-byte dynamic truncation window.</summary>
    private const int ThirdByteOffset = 2;

    /// <summary>Offset to the fourth byte of the 4-byte dynamic truncation window.</summary>
    private const int FourthByteOffset = 3;

    /// <summary>Bit shift for the most significant byte in RFC 4226 dynamic truncation.</summary>
    private const int Shift24 = 24;

    /// <summary>Bit shift for the second byte in RFC 4226 dynamic truncation.</summary>
    private const int Shift16 = 16;

    /// <summary>Bit shift for the third byte in RFC 4226 dynamic truncation.</summary>
    private const int Shift8 = 8;

    /// <summary>Modulus for 6-digit OTP codes.</summary>
    private const uint Modulus6Digits = 1_000_000U;

    /// <summary>Modulus for 7-digit OTP codes.</summary>
    private const uint Modulus7Digits = 10_000_000U;

    /// <summary>Modulus for 8-digit OTP codes.</summary>
    private const uint Modulus8Digits = 100_000_000U;

    /// <summary>The decoded secret bytes.</summary>
    private readonly byte[] _secret;

    /// <summary>Initializes a new instance of the <see cref="CertumTotp"/> class with Certum defaults (HMAC-SHA-256, 6 digits, 30s).</summary>
    /// <param name="secret">The raw decoded secret key bytes.</param>
    public CertumTotp(byte[] secret)
        : this(secret, CertumTotpAlgorithm.Sha256, MinDigits, DefaultPeriodSeconds)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="CertumTotp"/> class.</summary>
    /// <param name="secret">The raw decoded secret key bytes.</param>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="digits">The number of decimal digits (6 to 8).</param>
    /// <param name="periodSeconds">The time step in seconds.</param>
    /// <exception cref="ProviderConfigurationException">Any parameter is out of range.</exception>
    public CertumTotp(byte[] secret, CertumTotpAlgorithm algorithm, int digits, int periodSeconds)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
        {
            throw new ProviderConfigurationException("Certum TOTP secret must not be empty.");
        }

        if (digits is < MinDigits or > MaxDigits)
        {
            throw new ProviderConfigurationException("Certum TOTP digits must be between 6 and 8.");
        }

        if (periodSeconds <= 0)
        {
            throw new ProviderConfigurationException("Certum TOTP period must be positive.");
        }

        _secret = [.. secret];
        Algorithm = algorithm;
        Digits = digits;
        PeriodSeconds = periodSeconds;
    }

    /// <summary>Gets the HMAC digest algorithm.</summary>
    public CertumTotpAlgorithm Algorithm { get; }

    /// <summary>Gets the number of digits in each generated code.</summary>
    public int Digits { get; }

    /// <summary>Gets the time-step period in seconds.</summary>
    public int PeriodSeconds { get; }

    /// <summary>
    /// Parses either a full <c>otpauth://totp/...</c> URI or a bare RFC 4648 Base32 secret string,
    /// defaulting to HMAC-SHA-256, 6 digits, and a 30-second period.
    /// </summary>
    /// <param name="input">The <c>otpauth://</c> URI or Base32 secret.</param>
    /// <returns>The parsed <see cref="CertumTotp"/> generator.</returns>
    /// <exception cref="ProviderConfigurationException">The input is malformed or carries no valid Base32 secret.</exception>
    public static CertumTotp Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ProviderConfigurationException("Certum TOTP seed must not be empty.");
        }

        var trimmed = input.Trim();
        return trimmed.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase)
            ? ParseOtpAuthUri(trimmed)
            : new(DecodeBase32(trimmed));
    }

    /// <summary>Decodes an RFC 4648 Base32 string, ignoring whitespace and <c>=</c> padding.</summary>
    /// <param name="base32">The Base32 string.</param>
    /// <returns>The decoded bytes.</returns>
    /// <exception cref="ProviderConfigurationException">The string contains invalid Base32 characters or decodes to zero bytes.</exception>
    public static byte[] DecodeBase32(ReadOnlySpan<char> base32)
    {
        List<byte> output = [with(capacity: (base32.Length * BitsPerBase32Char) / BitsPerByte)];
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var ch in base32)
        {
            if (char.IsWhiteSpace(ch) || ch == '=')
            {
                continue;
            }

            var value = DecodeBase32Char(ch);
            buffer = (buffer << BitsPerBase32Char) | value;
            bitsLeft += BitsPerBase32Char;
            if (bitsLeft < BitsPerByte)
            {
                continue;
            }

            bitsLeft -= BitsPerByte;
            output.Add((byte)(buffer >> bitsLeft));
        }

        return output.Count == 0
            ? throw new ProviderConfigurationException("TOTP secret decoded to zero bytes.")
            : [.. output];
    }

    /// <summary>Generates the TOTP code for the given point in time.</summary>
    /// <param name="timestamp">The timestamp to evaluate.</param>
    /// <returns>The zero-padded decimal OTP code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string GenerateCode(DateTimeOffset timestamp) =>
        GenerateCode(timestamp.ToUnixTimeSeconds());

    /// <summary>Generates the TOTP code for the given Unix time in seconds.</summary>
    /// <param name="unixTimeSeconds">Seconds since the Unix epoch.</param>
    /// <returns>The zero-padded decimal OTP code.</returns>
    /// <exception cref="InvalidOperationException">The configured algorithm is unknown.</exception>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 6238 TOTP standard mandates HMAC-SHA1 support when algorithm=SHA1 is specified.")]
    public string GenerateCode(long unixTimeSeconds)
    {
        Span<byte> counterBytes = stackalloc byte[CounterByteLength];
        BinaryPrimitives.WriteUInt64BigEndian(counterBytes, (ulong)(unixTimeSeconds / PeriodSeconds));

        Span<byte> macBuffer = stackalloc byte[MaxMacByteLength];
        var macLength = Algorithm switch
        {
            CertumTotpAlgorithm.Sha1 => HMACSHA1.HashData(_secret, counterBytes, macBuffer),
            CertumTotpAlgorithm.Sha256 => HMACSHA256.HashData(_secret, counterBytes, macBuffer),
            CertumTotpAlgorithm.Sha512 => HMACSHA512.HashData(_secret, counterBytes, macBuffer),
            _ => throw new InvalidOperationException($"Unsupported TOTP algorithm {Algorithm}."),
        };

        var digest = macBuffer[..macLength];
        var offset = digest[^1] & OffsetMask;
        var binaryCode = ((digest[offset] & HighByteMask) << Shift24)
            | ((uint)digest[offset + 1] << Shift16)
            | ((uint)digest[offset + ThirdByteOffset] << Shift8)
            | digest[offset + FourthByteOffset];
        var modulus = Digits switch
        {
            MinDigits => Modulus6Digits,
            SevenDigits => Modulus7Digits,
            _ => Modulus8Digits,
        };
        return (binaryCode % modulus).ToString($"D{Digits}", CultureInfo.InvariantCulture);
    }

    /// <summary>Parses an <c>otpauth://</c> URI into a <see cref="CertumTotp"/> instance.</summary>
    /// <param name="uri">The trimmed URI string.</param>
    /// <returns>The parsed <see cref="CertumTotp"/>.</returns>
    /// <exception cref="ProviderConfigurationException">The URI is missing a secret or has invalid parameters.</exception>
    private static CertumTotp ParseOtpAuthUri(string uri)
    {
        var algorithm = CertumTotpAlgorithm.Sha256;
        var digits = MinDigits;
        var periodSeconds = DefaultPeriodSeconds;
        var secretBase32 = string.Empty;

        var queryIndex = uri.IndexOf('?', StringComparison.Ordinal);
        var query = queryIndex >= 0 ? uri.AsSpan(queryIndex + 1) : ReadOnlySpan<char>.Empty;
        while (!query.IsEmpty)
        {
            var amp = query.IndexOf('&');
            var pair = amp >= 0 ? query[..amp] : query;
            query = amp >= 0 ? query[(amp + 1)..] : ReadOnlySpan<char>.Empty;
            ApplyQueryParameter(pair, ref secretBase32, ref algorithm, ref digits, ref periodSeconds);
        }

        return string.IsNullOrWhiteSpace(secretBase32)
            ? throw new ProviderConfigurationException("The otpauth URI does not contain a 'secret' parameter.")
            : new(DecodeBase32(secretBase32), algorithm, digits, periodSeconds);
    }

    /// <summary>Applies a single <c>key=value</c> query parameter from an <c>otpauth://</c> URI.</summary>
    /// <param name="pair">The <c>key=value</c> slice.</param>
    /// <param name="secretBase32">Receives the <c>secret</c> parameter.</param>
    /// <param name="algorithm">Receives the <c>algorithm</c> parameter.</param>
    /// <param name="digitCount">Receives the <c>digits</c> parameter.</param>
    /// <param name="periodSeconds">Receives the <c>period</c> parameter.</param>
    /// <exception cref="ProviderConfigurationException">A parameter value is invalid.</exception>
    private static void ApplyQueryParameter(
        ReadOnlySpan<char> pair,
        ref string secretBase32,
        ref CertumTotpAlgorithm algorithm,
        ref int digitCount,
        ref int periodSeconds)
    {
        var eq = pair.IndexOf('=');
        if (eq <= 0)
        {
            return;
        }

        var key = pair[..eq];
        var value = Uri.UnescapeDataString(pair[(eq + 1)..]);
        if (key.Equals("secret", StringComparison.OrdinalIgnoreCase))
        {
            secretBase32 = value;
        }
        else if (key.Equals(nameof(algorithm), StringComparison.OrdinalIgnoreCase))
        {
            algorithm = ParseAlgorithm(value);
        }
        else if (key.Equals("digits", StringComparison.OrdinalIgnoreCase))
        {
            digitCount = ParsePositiveInt(value, "digits");
        }
        else if (key.Equals("period", StringComparison.OrdinalIgnoreCase))
        {
            periodSeconds = ParsePositiveInt(value, "period");
        }
    }

    /// <summary>Parses a TOTP algorithm name.</summary>
    /// <param name="value">The algorithm query value.</param>
    /// <returns>The parsed <see cref="CertumTotpAlgorithm"/>.</returns>
    /// <exception cref="ProviderConfigurationException">The algorithm name is not supported.</exception>
    private static CertumTotpAlgorithm ParseAlgorithm(string value) => value.ToUpperInvariant() switch
    {
        "SHA1" => CertumTotpAlgorithm.Sha1,
        "SHA256" => CertumTotpAlgorithm.Sha256,
        "SHA512" => CertumTotpAlgorithm.Sha512,
        _ => throw new ProviderConfigurationException($"Unsupported TOTP algorithm '{value}'."),
    };

    /// <summary>Parses an integer parameter from an <c>otpauth://</c> URI.</summary>
    /// <param name="value">The parameter string.</param>
    /// <param name="parameterName">The parameter name for error reporting.</param>
    /// <returns>The parsed integer.</returns>
    /// <exception cref="ProviderConfigurationException">The value is not a valid integer.</exception>
    private static int ParsePositiveInt(string value, string parameterName) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new ProviderConfigurationException($"Invalid {parameterName} '{value}' in otpauth URI.");

    /// <summary>Maps a single Base32 character to its 5-bit value.</summary>
    /// <param name="ch">The character.</param>
    /// <returns>The 5-bit integer value (0–31).</returns>
    /// <exception cref="ProviderConfigurationException">The character is not in the RFC 4648 Base32 alphabet.</exception>
    private static int DecodeBase32Char(char ch) => ch switch
    {
        >= 'A' and <= 'Z' => ch - 'A',
        >= 'a' and <= 'z' => ch - 'a',
        >= '2' and <= '7' => ch - '2' + Base32DigitOffset,
        _ => throw new ProviderConfigurationException($"Secret contains an invalid Base32 character '{ch}'."),
    };
}
