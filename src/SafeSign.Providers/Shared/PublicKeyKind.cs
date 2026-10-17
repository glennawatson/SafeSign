// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Shared;

/// <summary>The key families SafeSign signs with.</summary>
public enum PublicKeyKind
{
    /// <summary>An RSA key, signed with PKCS #1 v1.5.</summary>
    Rsa = 0,

    /// <summary>An elliptic curve key, signed with ECDSA.</summary>
    Ecdsa = 1,
}
