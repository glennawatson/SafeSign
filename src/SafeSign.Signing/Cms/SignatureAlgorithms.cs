// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SafeSign.Signing.Cms;

/// <summary>Chooses the signature algorithm identifier for a certificate's key and checks provider signatures.</summary>
internal static class SignatureAlgorithms
{
    /// <summary>Gets the RSA public key algorithm identifier.</summary>
    private static string RsaKey => "1.2.840.113549.1.1.1";

    /// <summary>Gets the elliptic curve public key algorithm identifier.</summary>
    private static string EcKey => "1.2.840.10045.2.1";

    /// <summary>Writes the <c>signatureAlgorithm</c> for the certificate's key.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="digest">The digest algorithm.</param>
    /// <exception cref="NotSupportedException">The key is neither RSA nor ECDSA.</exception>
    internal static void WriteIdentifier(AsnWriter writer, X509Certificate2 certificate, HashAlgorithmName digest)
    {
        using (writer.PushSequence())
        {
            switch (certificate.PublicKey.Oid.Value)
            {
                case var rsa when string.Equals(rsa, RsaKey, StringComparison.Ordinal):
                {
                    // Authenticode verifiers accept rsaEncryption here on every Windows version; the digest is named separately.
                    writer.WriteObjectIdentifier(CmsOids.RsaEncryption);
                    writer.WriteNull();
                    break;
                }

                case var ec when string.Equals(ec, EcKey, StringComparison.Ordinal):
                {
                    writer.WriteObjectIdentifier(EcdsaOid(digest));
                    break;
                }

                default:
                {
                    throw new NotSupportedException($"Signing keys of type {certificate.PublicKey.Oid.FriendlyName} are not supported; use RSA or ECDSA.");
                }
            }
        }
    }

    /// <summary>Checks a provider's signature against the certificate's public key before it is embedded.</summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="hash">The signed digest.</param>
    /// <param name="signature">The provider's signature.</param>
    /// <param name="digest">The digest algorithm.</param>
    /// <returns>True when the signature verifies.</returns>
    internal static bool Verify(X509Certificate2 certificate, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName digest)
    {
        if (certificate.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
            {
                return rsa.VerifyHash(hash, signature, digest, RSASignaturePadding.Pkcs1);
            }
        }

        if (certificate.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
            {
                return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
            }
        }

        return false;
    }

    /// <summary>Gets the ECDSA signature algorithm for a digest.</summary>
    /// <param name="digest">The digest algorithm.</param>
    /// <returns>The OID.</returns>
    private static string EcdsaOid(HashAlgorithmName digest) => digest.Name switch
    {
        nameof(HashAlgorithmName.SHA384) => CmsOids.EcdsaWithSha384,
        nameof(HashAlgorithmName.SHA512) => CmsOids.EcdsaWithSha512,
        _ => CmsOids.EcdsaWithSha256,
    };
}
