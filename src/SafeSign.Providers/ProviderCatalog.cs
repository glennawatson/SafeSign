// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using SafeSign.Providers.Aws;
using SafeSign.Providers.Azure;
using SafeSign.Providers.AzureArtifactSigning;
using SafeSign.Providers.Certum;
using SafeSign.Providers.Csc;
using SafeSign.Providers.DigiCert;
using SafeSign.Providers.EncryptionConsulting;
using SafeSign.Providers.Fortanix;
using SafeSign.Providers.GaraSign;
using SafeSign.Providers.Google;
using SafeSign.Providers.Local;
using SafeSign.Providers.Oracle;
using SafeSign.Providers.SignPath;
using SafeSign.Providers.SignServer;
using SafeSign.Providers.SslCom;
using SafeSign.Providers.Store;
using SafeSign.Providers.Vault;
using SafeSign.Providers.Venafi;

namespace SafeSign.Providers;

/// <summary>Every provider SafeSign knows about, working or planned, looked up by its <c>--provider</c> name.</summary>
public static class ProviderCatalog
{
    /// <summary>Gets every provider, in display order.</summary>
    public static ProviderDescriptor[] All { get; } =
    [
        new(
            "certum",
            "Certum SimplySign Cloud",
            ProviderStatus.Working,
            "Signs via Certum SimplySign Cloud (cloudsign.webnotarius.pl CAS OAuth 2.0 + SCS1_ATOM REST API). Options: username, totp-secret (or otp), card-serial, cert-sha256, endpoint.",
            static (settings, services) => new CertumSimplySignProvider(services.Http, CertumOptions.FromSettings(settings), services.Time)),
        new(
            "file",
            "Local Certificate File (PKCS #12 / PEM)",
            ProviderStatus.Working,
            "Signs with a local .pfx/.p12 bundle or a PEM/DER certificate paired with a PEM private key. Options: cert-file, password, key-file.",
            static (settings, _) => LocalCertificateProvider.FromSettings(settings)),
        new(
            "store",
            "X.509 Certificate Store",
            ProviderStatus.Working,
            "Signs with a certificate and private key in the OS X509Store. Options: thumbprint, subject-name, store-name, store-location.",
            static (settings, _) => X509StoreProvider.FromSettings(settings)),
        new(
            "aws-kms",
            "AWS Key Management Service (KMS)",
            ProviderStatus.Working,
            "Signs via AWS KMS TrentService.Sign with AWS SigV4. Options: key-id, region, cert-file, access-key-id, secret-access-key, session-token, endpoint.",
            static (settings, services) => new AwsKmsProvider(services.Http, AwsKmsOptions.FromSettings(settings), services.Time)),
        new(
            "azure-key-vault",
            "Azure Key Vault",
            ProviderStatus.Working,
            "Signs via Azure Key Vault REST API v7.5 with Entra ID OAuth 2.0. Options: vault-uri, cert-name, cert-version, tenant-id, client-id, client-secret, access-token, chain-file.",
            static (settings, services) => new AzureKeyVaultProvider(services.Http, AzureKeyVaultOptions.FromSettings(settings), services.Time)),
        new(
            "azure-artifact-signing",
            "Azure Artifact Signing",
            ProviderStatus.Working,
            "Signs via Azure Artifact Signing REST API v2022-06-15-preview with Entra ID OAuth 2.0. Options: endpoint, account-name, profile-name, tenant-id, client-id, client-secret, access-token.",
            static (settings, services) => new AzureArtifactSigningProvider(services.Http, AzureArtifactSigningOptions.FromSettings(settings), services.Time)),
        new(
            "digicert-keylocker",
            "DigiCert ONE / KeyLocker",
            ProviderStatus.Working,
            "Signs via DigiCert ONE KeyLocker (/signingmanager/api/v1/certificates and /keypairs/{id}/sign). Options: api-key, cert-alias, cert-id, keypair-id, cert-file, client-cert-file, endpoint.",
            static (settings, services) => new DigiCertKeyLockerProvider(services.Http, DigiCertKeyLockerOptions.FromSettings(settings), services.Time)),
        new(
            "encryption-consulting",
            "Encryption Consulting CodeSign Secure",
            ProviderStatus.Working,
            "Signs via Encryption Consulting CodeSign Secure (/api/auth/GetLoginToken/, /api/signing/sign/). Options: endpoint, cert-name, access-token, username, password.",
            static (settings, services) => new CodeSignSecureProvider(services.Http, CodeSignSecureOptions.FromSettings(settings), services.Time)),
        new(
            "fortanix-dsm",
            "Fortanix Data Security Manager (DSM)",
            ProviderStatus.Working,
            "Signs via Fortanix DSM REST API (/sys/v1/session/auth and /crypto/v1/sign). Options: key-id, cert-file, api-key (or access-token), endpoint.",
            static (settings, services) => new FortanixDsmProvider(services.Http, FortanixDsmOptions.FromSettings(settings), services.Time)),
        new(
            "garasign",
            "Garantir GaraSign",
            ProviderStatus.Working,
            "Signs via Garantir GaraSign (/authenticate, /keystore, /sign) with approval polling. Options: endpoint, key-name, session-token, username, password, cert-file, client-cert-file.",
            static (settings, services) => new GaraSignProvider(services.Http, GaraSignOptions.FromSettings(settings), services.Time)),
        new(
            "google-cloud-kms",
            "Google Cloud KMS",
            ProviderStatus.Working,
            "Signs via Google Cloud KMS v1 asymmetricSign with RFC 7523 Service Account JWT auth. Options: key-version-name, cert-file, credentials-file (or access-token).",
            static (settings, services) => new GoogleCloudKmsProvider(services.Http, GoogleCloudKmsOptions.FromSettings(settings), services.Time)),
        new(
            "hashicorp-vault",
            "HashiCorp Vault Transit",
            ProviderStatus.Working,
            "Signs via HashiCorp Vault Transit (/v1/{mount}/sign/{key}/{hash}). Options: vault-address, vault-token, key-name, cert-file, mount-path, vault-namespace.",
            HashiCorpVaultProvider.FromSettings),
        new(
            "keyfactor-signserver",
            "Keyfactor SignServer",
            ProviderStatus.Working,
            "Signs via Keyfactor SignServer REST v1 (/signserver/rest/v1/workers/{worker}/process). Options: endpoint, worker, cert-file, token.",
            KeyfactorSignServerProvider.FromSettings),
        new(
            "oracle-kms",
            "Oracle Cloud Infrastructure (OCI) KMS",
            ProviderStatus.Working,
            "Signs via OCI KMS (/20180608/sign) with OCI RSA-SHA256 HTTP signatures. Options: crypto-endpoint, key-id, cert-file, tenancy-ocid, user-ocid, fingerprint, api-key-file.",
            OracleCloudKmsProvider.FromSettings),
        new(
            "signpath",
            "SignPath.io",
            ProviderStatus.Working,
            "Signs via SignPath REST API v1 (/v1/{orgId}/Cryptoki/MySigningPolicies and /SigningRequests). Options: organization-id, project-slug, policy-slug, api-token, cert-file, endpoint.",
            static (settings, services) => new SignPathProvider(services.Http, SignPathOptions.FromSettings(settings), services.Time)),
        new(
            "sslcom-esigner",
            "SSL.com eSigner (CSC v1)",
            ProviderStatus.Working,
            "Signs via SSL.com eSigner CSC API (/csc/v0/signatures/signHash) with OAuth 2.0 and TOTP. Options: credential-id, cert-file, totp-secret (or otp), access-token.",
            SslComESignerProvider.FromSettings),
        new(
            "csc",
            "Cloud Signature Consortium (CSC v1 — Entrust, Sectigo, GlobalSign, SwissSign)",
            ProviderStatus.Working,
            "Signs via any CSC v1 compliant RSSP (/credentials/info, /credentials/authorize, /signatures/signHash). Options: endpoint, credential-id, access-token, cert-file, sad, pin, otp.",
            static (settings, services) => new CscProvider(services.Http, CscOptions.FromSettings(settings), services.Time)),
        new(
            "venafi-codesign",
            "Venafi CodeSign Protect",
            ProviderStatus.Working,
            "Signs via Venafi CodeSign Protect vedhsm REST API (/vedauth/authorize/oauth, /vedhsm/api/sign). Options: endpoint, key-label, key-id, access-token, username, password.",
            static (settings, services) => new VenafiProvider(services.Http, VenafiOptions.FromSettings(settings), services.Time)),
    ];

    /// <summary>Finds a provider by name.</summary>
    /// <param name="name">The <c>--provider</c> name.</param>
    /// <returns>The descriptor, or null when no provider has that name.</returns>
    public static ProviderDescriptor? Find(string name)
    {
        for (var i = 0; i < All.Length; i++)
        {
            var descriptor = All[i];
            if (string.Equals(descriptor.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return descriptor;
            }
        }

        return null;
    }
}
