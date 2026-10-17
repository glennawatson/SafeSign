// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Certum;

/// <summary>The HMAC digest algorithm used by a Certum SimplySign TOTP credential (RFC 6238).</summary>
public enum CertumTotpAlgorithm
{
    /// <summary>HMAC-SHA-256 (Certum SimplySign default).</summary>
    Sha256 = 0,

    /// <summary>HMAC-SHA-512 digest algorithm.</summary>
    Sha512 = 1,
}
