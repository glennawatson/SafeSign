// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Signing;

namespace SafeSign.Providers.Shared;

/// <summary>Signs a digest with a certificate's own private key.</summary>
public static class LocalKeySigner
{
    /// <summary>Signs a digest with PKCS #1 v1.5 (RSA) or DER ECDSA.</summary>
    /// <param name="certificate">A certificate that has its private key.</param>
    /// <param name="request">The digest.</param>
    /// <returns>The signature.</returns>
    /// <exception cref="ProviderConfigurationException">The certificate has no usable private key.</exception>
    public static byte[] Sign(X509Certificate2 certificate, in SignDigestRequest request)
    {
        using (var rsa = certificate.GetRSAPrivateKey())
        {
            if (rsa is not null)
            {
                return rsa.SignHash(request.Digest.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
            }
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        return ecdsa is not null
            ? ecdsa.SignHash(request.Digest.Span, DSASignatureFormat.Rfc3279DerSequence)
            : throw new ProviderConfigurationException($"Certificate '{certificate.Subject}' has no RSA or ECDSA private key.");
    }
}
