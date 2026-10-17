// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Signing.Cms;

/// <summary>Object identifiers used by CMS, Authenticode and RFC 3161.</summary>
public static class CmsOids
{
    /// <summary>Gets pKCS #7 data.</summary>
    public static string Data => "1.2.840.113549.1.7.1";

    /// <summary>Gets pKCS #7 signed data.</summary>
    public static string SignedData => "1.2.840.113549.1.7.2";

    /// <summary>Gets the content-type signed attribute.</summary>
    public static string ContentType => "1.2.840.113549.1.9.3";

    /// <summary>Gets the message-digest signed attribute.</summary>
    public static string MessageDigest => "1.2.840.113549.1.9.4";

    /// <summary>Gets the signing-time signed attribute.</summary>
    public static string SigningTime => "1.2.840.113549.1.9.5";

    /// <summary>Gets the CMS signature timestamp token unsigned attribute (RFC 3161 appendix A).</summary>
    public static string SignatureTimeStampToken => "1.2.840.113549.1.9.16.2.14";

    /// <summary>Gets the ESS signing-certificate-v2 signed attribute (RFC 5035).</summary>
    public static string SigningCertificateV2 => "1.2.840.113549.1.9.16.2.47";

    /// <summary>Gets the CAdES commitment-type-indication signed attribute.</summary>
    public static string CommitmentTypeIndication => "1.2.840.113549.1.9.16.2.16";

    /// <summary>Gets rSA encryption, used as the RSA signature algorithm in Authenticode.</summary>
    public static string RsaEncryption => "1.2.840.113549.1.1.1";

    /// <summary>Gets eCDSA with SHA-256.</summary>
    public static string EcdsaWithSha256 => "1.2.840.10045.4.3.2";

    /// <summary>Gets eCDSA with SHA-384.</summary>
    public static string EcdsaWithSha384 => "1.2.840.10045.4.3.3";

    /// <summary>Gets eCDSA with SHA-512.</summary>
    public static string EcdsaWithSha512 => "1.2.840.10045.4.3.4";

    /// <summary>Gets the SHA-256 digest algorithm.</summary>
    public static string Sha256 => "2.16.840.1.101.3.4.2.1";

    /// <summary>Gets the SHA-384 digest algorithm.</summary>
    public static string Sha384 => "2.16.840.1.101.3.4.2.2";

    /// <summary>Gets the SHA-512 digest algorithm.</summary>
    public static string Sha512 => "2.16.840.1.101.3.4.2.3";

    /// <summary>Gets the Authenticode indirect data content type (<c>SPC_INDIRECT_DATA_OBJID</c>).</summary>
    public static string SpcIndirectData => "1.3.6.1.4.1.311.2.1.4";

    /// <summary>Gets the Authenticode statement-type signed attribute.</summary>
    public static string SpcStatementType => "1.3.6.1.4.1.311.2.1.11";

    /// <summary>Gets the Authenticode publisher information signed attribute.</summary>
    public static string SpcSpOpusInfo => "1.3.6.1.4.1.311.2.1.12";

    /// <summary>Gets individual code signing, the statement type SafeSign asserts.</summary>
    public static string SpcIndividualSpKeyPurpose => "1.3.6.1.4.1.311.2.1.21";

    /// <summary>Gets the PE image data type (<c>SPC_PE_IMAGE_DATAOBJ</c>).</summary>
    public static string SpcPeImageData => "1.3.6.1.4.1.311.2.1.15";

    /// <summary>Gets the SIP information type used by MSI, scripts and other SIP-hashed formats.</summary>
    public static string SpcSipInfo => "1.3.6.1.4.1.311.2.1.30";

    /// <summary>Gets the Authenticode nested signature unsigned attribute.</summary>
    public static string SpcNestedSignature => "1.3.6.1.4.1.311.2.4.1";

    /// <summary>Gets the Authenticode RFC 3161 timestamp unsigned attribute (<c>SPC_RFC3161_OBJID</c>).</summary>
    public static string SpcRfc3161Timestamp => "1.3.6.1.4.1.311.3.3.1";

    /// <summary>Gets the certificate trust list content type used by catalog files.</summary>
    public static string CertificateTrustList => "1.3.6.1.4.1.311.10.1";
}
