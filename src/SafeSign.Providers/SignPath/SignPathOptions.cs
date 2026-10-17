// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.SignPath;

/// <summary>Options for <see cref="SignPathProvider"/> (SignPath.io REST API).</summary>
/// <param name="OrganizationId">The SignPath organization ID (GUID).</param>
/// <param name="ProjectSlug">The SignPath project slug.</param>
/// <param name="PolicySlug">The SignPath signing policy slug.</param>
/// <param name="ApiToken">The SignPath API bearer token.</param>
[DebuggerDisplay("{ProjectSlug,nq}/{PolicySlug,nq} at {Endpoint}")]
public sealed record SignPathOptions(
    string OrganizationId,
    string ProjectSlug,
    string PolicySlug,
    string ApiToken)
{
    /// <summary>Gets the default SignPath API endpoint URI.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://app.signpath.io/API");

    /// <summary>Gets the SignPath API endpoint URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets an optional local certificate file path used instead of fetching the policy certificate from SignPath.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Reads <see cref="SignPathOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static SignPathOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "SIGNPATH_ENDPOINT");
        return new(
            ProviderSettingsReader.Require(settings, "organization-id", "SIGNPATH_ORGANIZATION_ID"),
            ProviderSettingsReader.Require(settings, "project-slug", "SIGNPATH_PROJECT_SLUG"),
            ProviderSettingsReader.Require(settings, "policy-slug", "SIGNPATH_POLICY_SLUG"),
            ProviderSettingsReader.Require(settings, "api-token", "SIGNPATH_API_TOKEN"))
        {
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "SIGNPATH_CERT_FILE"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"SignPathOptions {{ Endpoint = {Endpoint}, OrganizationId = {OrganizationId}, ProjectSlug = {ProjectSlug}, PolicySlug = {PolicySlug} }}";
}
