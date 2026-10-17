// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Signing;

/// <summary>
/// A key that signs digests on behalf of SafeSign. The private key never leaves the provider: SafeSign hashes
/// locally and sends only the digest.
/// </summary>
public interface ISigningProvider
{
    /// <summary>Gets the provider's catalog name, such as <c>certum</c> or <c>aws-kms</c>.</summary>
    string Name { get; }

    /// <summary>Fetches the signing certificate and the issuing chain the provider knows about.</summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The certificate and chain.</returns>
    ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken);

    /// <summary>Signs a digest that SafeSign has already computed.</summary>
    /// <param name="request">The digest and the algorithm that produced it.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>
    /// For RSA keys, the PKCS #1 v1.5 signature. For ECDSA keys, the DER-encoded <c>Ecdsa-Sig-Value</c>
    /// (convert IEEE P1363 <c>r||s</c> output before returning).
    /// </returns>
    ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken);
}
