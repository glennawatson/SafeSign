// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Providers.Shared;

/// <summary>Works out the key family from a certificate's public key algorithm.</summary>
public static class PublicKeyKinds
{
    /// <summary>The <c>rsaEncryption</c> OID.</summary>
    private const string RsaOid = "1.2.840.113549.1.1.1";

    /// <summary>The <c>id-ecPublicKey</c> OID.</summary>
    private const string EcOid = "1.2.840.10045.2.1";

    /// <summary>Gets the key family of a certificate.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The key family.</returns>
    /// <exception cref="NotSupportedException">The key is neither RSA nor EC.</exception>
    public static PublicKeyKind Of(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return certificate.GetKeyAlgorithm() switch
        {
            RsaOid => PublicKeyKind.Rsa,
            EcOid => PublicKeyKind.Ecdsa,
            var oid => throw new NotSupportedException($"Certificate key algorithm {oid} is not supported; use an RSA or ECDSA key."),
        };
    }
}
