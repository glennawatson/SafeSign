// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Pe;

/// <summary>The offsets in a PE image that Authenticode signing reads and rewrites.</summary>
/// <param name="ChecksumOffset">The file offset of the optional header's <c>CheckSum</c> field.</param>
/// <param name="CertificateEntryOffset">The file offset of the certificate table's data directory entry.</param>
/// <param name="CertificateTableOffset">The certificate table's file offset, or zero when unsigned.</param>
/// <param name="CertificateTableSize">The certificate table's size in bytes, or zero when unsigned.</param>
/// <param name="IsPe32Plus">True for PE32+ (64-bit and UEFI images), false for PE32.</param>
[DebuggerDisplay("checksum @{ChecksumOffset}, certificates @{CertificateTableOffset} ({CertificateTableSize} bytes)")]
public readonly record struct PeLayout(
    long ChecksumOffset,
    long CertificateEntryOffset,
    long CertificateTableOffset,
    long CertificateTableSize,
    bool IsPe32Plus);
