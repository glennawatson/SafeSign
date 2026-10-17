// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Aws;

/// <summary>Options for <see cref="AwsKmsProvider"/>.</summary>
/// <param name="KeyId">The KMS key ID, key ARN, alias name, or alias ARN.</param>
/// <param name="Region">The AWS region, such as <c>us-east-1</c>.</param>
/// <param name="Credentials">The access keys.</param>
/// <param name="CertificatePath">
/// A PEM, DER, or PKCS #7 file with the certificate issued for the KMS key and its issuers. KMS stores keys, not
/// certificates.
/// </param>
[DebuggerDisplay("{KeyId,nq} ({Region,nq})")]
public sealed record AwsKmsOptions(string KeyId, string Region, AwsCredentials Credentials, string CertificatePath)
{
    /// <summary>Gets an endpoint override, such as a VPC or FIPS endpoint. Defaults to <c>https://kms.{Region}.amazonaws.com/</c>.</summary>
    public Uri? Endpoint { get; init; }

    /// <summary>Reads <see cref="AwsKmsOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static AwsKmsOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var credentials = new AwsCredentials(
            ProviderSettingsReader.Require(settings, "access-key-id", "AWS_ACCESS_KEY_ID"),
            ProviderSettingsReader.Require(settings, "secret-access-key", "AWS_SECRET_ACCESS_KEY"),
            ProviderSettingsReader.Find(settings, "session-token", "AWS_SESSION_TOKEN"));
        var region = ProviderSettingsReader.Require(settings, "region", "AWS_REGION", "AWS_DEFAULT_REGION");
        var keyId = ProviderSettingsReader.Require(settings, "key-id");
        var certPath = ProviderSettingsReader.Require(settings, "cert-file");
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "AWS_ENDPOINT_URL_KMS");
        return new(keyId, region, credentials, certPath) { Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : null };
    }
}
