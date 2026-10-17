// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.GaraSign;

/// <summary>Options for <see cref="GaraSignProvider"/> (Garantir GaraSign).</summary>
/// <param name="KeyName">The GaraSign key alias (<c>key_name</c>).</param>
[DebuggerDisplay("{KeyName,nq} at {Endpoint}")]
public sealed record GaraSignOptions(string KeyName)
{
    /// <summary>The default polling interval between sign status checks.</summary>
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>The default timeout for an asynchronous signing operation.</summary>
    private static readonly TimeSpan DefaultPollTimeout = TimeSpan.FromHours(1);

    /// <summary>Gets the default Garantir GaraSign REST endpoint URI.</summary>
    public static Uri DefaultEndpoint { get; } = new("https://garasign.com:8443/CodeSigningRestService");

    /// <summary>Gets the GaraSign REST service endpoint URI.</summary>
    public Uri Endpoint { get; init; } = DefaultEndpoint;

    /// <summary>Gets the optional username for <c>/authenticate</c>.</summary>
    public string? Username { get; init; }

    /// <summary>Gets the optional password for <c>/authenticate</c>.</summary>
    public string? Password { get; init; }

    /// <summary>Gets a pre-acquired session token used instead of calling <c>/authenticate</c>.</summary>
    public string? SessionToken { get; init; }

    /// <summary>Gets an optional local certificate file path used instead of calling <c>/keystore</c>.</summary>
    public string? CertificateFile { get; init; }

    /// <summary>Gets an optional PKCS #12 client certificate file for mutual TLS.</summary>
    public string? ClientCertificateFile { get; init; }

    /// <summary>Gets the optional password for <see cref="ClientCertificateFile"/>.</summary>
    public string? ClientCertificatePassword { get; init; }

    /// <summary>Gets the polling interval when <c>/sign</c> returns <c>IN_PROGRESS</c>.</summary>
    public TimeSpan PollInterval { get; init; } = DefaultPollInterval;

    /// <summary>Gets the maximum duration to wait when <c>/sign</c> returns <c>IN_PROGRESS</c>.</summary>
    public TimeSpan PollTimeout { get; init; } = DefaultPollTimeout;

    /// <summary>Reads <see cref="GaraSignOptions"/> from <c>--provider-option</c> key/value pairs and environment variables.</summary>
    /// <param name="settings">The provider settings.</param>
    /// <returns>The parsed options.</returns>
    public static GaraSignOptions FromSettings(ProviderSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpointText = ProviderSettingsReader.Find(settings, "endpoint", "GARASIGN_ENDPOINT");
        return new(ProviderSettingsReader.Require(settings, "key-name", "GARASIGN_KEY_NAME"))
        {
            Endpoint = endpointText is { Length: > 0 } ? new Uri(endpointText) : DefaultEndpoint,
            Username = ProviderSettingsReader.Find(settings, "username", "GARASIGN_USERNAME"),
            Password = ProviderSettingsReader.Find(settings, "password", "GARASIGN_PASSWORD"),
            SessionToken = ProviderSettingsReader.Find(settings, "session-token", "GARASIGN_SESSION_TOKEN"),
            CertificateFile = ProviderSettingsReader.Find(settings, "cert-file", "GARASIGN_CERT_FILE"),
            ClientCertificateFile = ProviderSettingsReader.Find(settings, "client-cert-file", "GARASIGN_CLIENT_CERT_FILE"),
            ClientCertificatePassword = ProviderSettingsReader.Find(settings, "client-cert-password", "GARASIGN_CLIENT_CERT_PASSWORD"),
        };
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"GaraSignOptions {{ Endpoint = {Endpoint}, KeyName = {KeyName}, Username = {Username} }}";
}
