// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SafeSign.Signing;

namespace SafeSign.Providers.Shared;

/// <summary>
/// Loads a public certificate and its issuers from a PEM, DER, or PKCS #7 file. Used by key services (cloud KMS,
/// Vault Transit) that hold the key but not the certificate.
/// </summary>
public static class CertificateFile
{
    /// <summary>Loads the certificate file and arranges the leaf and chain.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The signing certificate.</returns>
    /// <exception cref="ProviderConfigurationException">The file does not exist or holds no end-entity certificate.</exception>
    public static SigningCertificate Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new ProviderConfigurationException($"Certificate file '{path}' does not exist.");
        }

        return CertificateChainOrder.Arrange(Read(File.ReadAllBytes(path)), path);
    }

    /// <summary>Reads every certificate in a PEM, DER, or PKCS #7 blob.</summary>
    /// <param name="data">The file contents.</param>
    /// <returns>The certificates in file order.</returns>
    public static List<X509Certificate2> Read(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.AsSpan().IndexOf("-----BEGIN "u8) >= 0)
        {
            return ReadPem(Encoding.ASCII.GetString(data));
        }

        return Pkcs7CertificateReader.TryRead(data, out var bundle) ? bundle : [X509CertificateLoader.LoadCertificate(data)];
    }

    /// <summary>Reads <c>CERTIFICATE</c> and <c>PKCS7</c> PEM blocks.</summary>
    /// <param name="text">The PEM text.</param>
    /// <returns>The certificates in file order.</returns>
    private static List<X509Certificate2> ReadPem(string text)
    {
        List<X509Certificate2> certificates = [];
        var remaining = text.AsSpan();
        while (PemEncoding.TryFind(remaining, out var fields))
        {
            var label = remaining[fields.Label];
            var der = Convert.FromBase64String(remaining[fields.Base64Data].ToString());
            if (label.SequenceEqual("CERTIFICATE"))
            {
                certificates.Add(X509CertificateLoader.LoadCertificate(der));
            }
            else if (label.SequenceEqual("PKCS7") && Pkcs7CertificateReader.TryRead(der, out var bundle))
            {
                certificates.AddRange(bundle);
            }

            remaining = remaining[fields.Location.End..];
        }

        return certificates;
    }
}
