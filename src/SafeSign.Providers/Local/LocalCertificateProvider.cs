// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeSign.Providers.Shared;
using SafeSign.Signing;

namespace SafeSign.Providers.Local;

/// <summary>Signs digests using a local PKCS #12 (<c>.pfx</c>/<c>.p12</c>) bundle or a PEM/DER certificate paired with a PEM private key.</summary>
/// <param name="options">The local certificate and key options.</param>
[DebuggerDisplay("{Name,nq}")]
public sealed class LocalCertificateProvider(LocalCertificateOptions options) : ISigningProvider
{
    /// <summary>The cached certificate and private-key bundle.</summary>
    private SigningCertificate? _certificate;

    /// <inheritdoc />
    public string Name => "file";

    /// <summary>Creates a <see cref="LocalCertificateProvider"/> from CLI/environment settings.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The configured provider.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="settings"/> is null.</exception>
    public static LocalCertificateProvider FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new(new(
            ProviderSettingsReader.Require(settings, "cert-file", "SAFESIGN_CERT_FILE"),
            ProviderSettingsReader.Find(settings, "password", "SAFESIGN_CERT_PASSWORD"),
            ProviderSettingsReader.Find(settings, "key-file", "SAFESIGN_KEY_FILE")));
    }

    /// <inheritdoc />
    public ValueTask<SigningCertificate> GetCertificateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return new(_certificate ??= LoadCertificate());
    }

    /// <inheritdoc />
    public async ValueTask<byte[]> SignDigestAsync(SignDigestRequest request, CancellationToken cancellationToken)
    {
        var cert = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        return LocalKeySigner.Sign(cert.Certificate, in request);
    }

    /// <summary>Loads the certificate and private key from disk.</summary>
    /// <returns>The arranged <see cref="SigningCertificate"/> with its private key attached to the leaf certificate.</returns>
    /// <exception cref="ProviderConfigurationException">The certificate file is missing or does not contain a private key.</exception>
    private SigningCertificate LoadCertificate()
    {
        if (!File.Exists(options.CertificateFile))
        {
            throw new ProviderConfigurationException($"Certificate file '{options.CertificateFile}' does not exist.");
        }

        if (options.KeyFile is { Length: > 0 } keyPath)
        {
            return LoadSeparatePemKey(keyPath);
        }

        var rawBytes = File.ReadAllBytes(options.CertificateFile);
        if (rawBytes.AsSpan().IndexOf("-----BEGIN "u8) >= 0)
        {
            return LoadInlinePemKey(File.ReadAllText(options.CertificateFile));
        }

        var collection = X509CertificateLoader.LoadPkcs12Collection(
            rawBytes,
            options.Password,
            ProviderHttp.Pkcs12StorageFlags);
        List<X509Certificate2> certificates = [.. collection];
        var arranged = CertificateChainOrder.Arrange(certificates, options.CertificateFile);
        return !arranged.Certificate.HasPrivateKey
            ? throw new ProviderConfigurationException($"PKCS #12 file '{options.CertificateFile}' does not contain a private key for '{arranged.Certificate.Subject}'.")
            : arranged;
    }

    /// <summary>Combines a certificate chain file with a separate PEM private key file.</summary>
    /// <param name="keyPath">The path to the PEM private key file.</param>
    /// <returns>The arranged signing certificate with its private key attached.</returns>
    /// <exception cref="ProviderConfigurationException">The key file does not exist.</exception>
    private SigningCertificate LoadSeparatePemKey(string keyPath)
    {
        if (!File.Exists(keyPath))
        {
            throw new ProviderConfigurationException($"Private key file '{keyPath}' does not exist.");
        }

        var arranged = CertificateFile.Load(options.CertificateFile);
        var keyPem = File.ReadAllText(keyPath);
        var withKey = AttachPemPrivateKey(arranged.Certificate, keyPem);
        return new(withKey, arranged.Chain);
    }

    /// <summary>Loads a PEM bundle that contains both certificate blocks and a private key block.</summary>
    /// <param name="pemText">The full PEM text.</param>
    /// <returns>The arranged signing certificate with its private key attached.</returns>
    private SigningCertificate LoadInlinePemKey(string pemText)
    {
        var arranged = CertificateFile.Load(options.CertificateFile);
        var withKey = AttachPemPrivateKey(arranged.Certificate, pemText);
        return new(withKey, arranged.Chain);
    }

    /// <summary>Attaches a PEM private key to <paramref name="leaf"/>.</summary>
    /// <param name="leaf">The public leaf certificate.</param>
    /// <param name="keyPem">The PEM text containing the private key.</param>
    /// <returns>A new <see cref="X509Certificate2"/> instance with the private key attached.</returns>
    private X509Certificate2 AttachPemPrivateKey(X509Certificate2 leaf, string keyPem)
    {
        if (PublicKeyKinds.Of(leaf) == PublicKeyKind.Rsa)
        {
            using var rsa = RSA.Create();
            if (options.Password is { Length: > 0 } pwd)
            {
                rsa.ImportFromEncryptedPem(keyPem, pwd);
            }
            else
            {
                rsa.ImportFromPem(keyPem);
            }

            return leaf.CopyWithPrivateKey(rsa);
        }

        using var ecdsa = ECDsa.Create();
        if (options.Password is { Length: > 0 } password)
        {
            ecdsa.ImportFromEncryptedPem(keyPem, password);
        }
        else
        {
            ecdsa.ImportFromPem(keyPem);
        }

        return leaf.CopyWithPrivateKey(ecdsa);
    }
}
