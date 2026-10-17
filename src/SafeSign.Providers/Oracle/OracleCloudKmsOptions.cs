// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Oracle;

/// <summary>Configuration for <see cref="OracleCloudKmsProvider"/>.</summary>
/// <param name="CryptoEndpoint">The OCI KMS cryptographic endpoint URI (for example <c>https://&lt;vault-prefix&gt;-crypto.kms.us-ashburn-1.oraclecloud.com</c>).</param>
/// <param name="KeyId">The OCI KMS key OCID.</param>
/// <param name="CertificateFile">The public certificate file path.</param>
/// <param name="TenancyOcid">The OCI tenancy OCID.</param>
/// <param name="UserOcid">The OCI user OCID.</param>
/// <param name="KeyFingerprint">The OCI API signing key fingerprint.</param>
/// <param name="PrivateKeyPem">The OCI API RSA private key PEM text.</param>
/// <param name="KeyVersionId">The optional OCI KMS key version OCID.</param>
[DebuggerDisplay("Endpoint = {CryptoEndpoint}, KeyId = {KeyId}")]
public sealed record OracleCloudKmsOptions(
    Uri CryptoEndpoint,
    string KeyId,
    string CertificateFile,
    string TenancyOcid,
    string UserOcid,
    string KeyFingerprint,
    string PrivateKeyPem,
    string? KeyVersionId = null);
