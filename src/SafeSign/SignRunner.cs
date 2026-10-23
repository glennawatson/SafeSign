// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Refit;
using SafeSign.Formats;
using SafeSign.Providers;
using SafeSign.Providers.Shared;
using SafeSign.Signing;
using SafeSign.Signing.Cms;

namespace SafeSign;

/// <summary>Executes the <c>sign</c> command against the configured provider and file format signers.</summary>
public static class SignRunner
{
    /// <summary>The exit code returned when signing succeeds.</summary>
    internal const int ExitSuccess = 0;

    /// <summary>The exit code returned when command validation or signing fails.</summary>
    internal const int ExitFailure = 1;

    /// <summary>Validates <paramref name="input"/>, resolves the signing provider and certificate, and signs all target files.</summary>
    /// <param name="input">The parsed <c>sign</c> command input.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <param name="environment">Reads environment variables when provider options fall back to the environment.</param>
    /// <param name="output">Receives progress messages.</param>
    /// <param name="error">Receives error messages.</param>
    /// <param name="cancellationToken">Cancels the signing run.</param>
    /// <returns>The process exit code (<c>0</c> for success, <c>1</c> for failure).</returns>
    /// <exception cref="ArgumentNullException">Any required parameter is null.</exception>
    public static async Task<int> ExecuteAsync(
        SignCommandInput input,
        ProviderServices services,
        Func<string, string?> environment,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);

        try
        {
            return await ExecuteCoreAsync(input, services, environment, output, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("error: Signing was canceled.".AsMemory(), CancellationToken.None).ConfigureAwait(false);
            return ExitFailure;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException
            or IOException or FormatException or CryptographicException or HttpRequestException or ApiException
            or ProviderConfigurationException or ProviderRequestException)
        {
            await error.WriteLineAsync($"error: {ex.Message}".AsMemory(), CancellationToken.None).ConfigureAwait(false);
            return ExitFailure;
        }
    }

    /// <summary>Parses a digest algorithm name (<c>SHA256</c>, <c>SHA384</c>, or <c>SHA512</c>).</summary>
    /// <param name="name">The algorithm name.</param>
    /// <param name="optionName">The CLI option name for diagnostics.</param>
    /// <returns>The resolved <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not a supported SHA-2 digest algorithm.</exception>
    internal static HashAlgorithmName ParseDigestAlgorithm(string name, string optionName)
    {
        if (string.Equals(name, "SHA256", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SHA-256", StringComparison.OrdinalIgnoreCase))
        {
            return HashAlgorithmName.SHA256;
        }

        if (string.Equals(name, "SHA384", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SHA-384", StringComparison.OrdinalIgnoreCase))
        {
            return HashAlgorithmName.SHA384;
        }

        if (string.Equals(name, "SHA512", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "SHA-512", StringComparison.OrdinalIgnoreCase))
        {
            return HashAlgorithmName.SHA512;
        }

        throw new ArgumentException($"Unsupported digest algorithm '{name}' for {optionName}. Expected SHA256, SHA384, or SHA512.", nameof(name));
    }

    /// <summary>Parses <c>name=value</c> option entries into a case-insensitive dictionary.</summary>
    /// <param name="entries">The raw <c>name=value</c> strings.</param>
    /// <returns>The parsed option dictionary.</returns>
    /// <exception cref="ArgumentException">An entry does not follow the <c>name=value</c> format.</exception>
    internal static Dictionary<string, string> ParseProviderOptions(string[] entries)
    {
        Dictionary<string, string> options = [with(capacity: entries.Length, comparer: StringComparer.OrdinalIgnoreCase)];
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            var separator = entry.IndexOf('=', StringComparison.Ordinal);
            if (separator <= 0)
            {
                throw new ArgumentException($"Invalid '--provider-option' value '{entry}'. Expected 'name=value'.", nameof(entries));
            }

            var key = entry[..separator].Trim();
            var value = entry[(separator + 1)..];
            if (key.Length == 0)
            {
                throw new ArgumentException($"Invalid '--provider-option' value '{entry}'. Option name must not be empty.", nameof(entries));
            }

            options[key] = value;
        }

        return options;
    }

    /// <summary>Runs the validated signing pipeline and throws on domain errors.</summary>
    /// <param name="input">The parsed <c>sign</c> command input.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <param name="environment">Reads environment variables.</param>
    /// <param name="output">Receives progress messages.</param>
    /// <param name="cancellationToken">Cancels the signing run.</param>
    /// <returns>The process exit code.</returns>
    /// <exception cref="ArgumentException">An input argument is invalid.</exception>
    /// <exception cref="NotSupportedException">The provider or file format is not supported.</exception>
    /// <exception cref="FileNotFoundException">A target file does not exist.</exception>
    private static async Task<int> ExecuteCoreAsync(
        SignCommandInput input,
        ProviderServices services,
        Func<string, string?> environment,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (input.Files.Length == 0)
        {
            throw new ArgumentException("At least one file path must be specified.", nameof(input));
        }

        if (!string.IsNullOrWhiteSpace(input.OutputPath) && input.Files.Length > 1)
        {
            throw new ArgumentException("The '--output' option can only be used when signing a single file.", nameof(input));
        }

        var digestAlgorithm = ParseDigestAlgorithm(input.DigestAlgorithm, "--hash");
        var timestampSettings = CreateTimestampSettings(input.TimestampUrl, input.TimestampDigestAlgorithm, services);
        var descriptionUrl = ParseOptionalAbsoluteUri(input.DescriptionUrl, "--description-url");
        var descriptor = ResolveProviderDescriptor(input.ProviderName);
        var settings = new ProviderSettings(ParseProviderOptions(input.ProviderOptionEntries), environment);

        var provider = descriptor.Create!(settings, services);
        try
        {
            var certificate = await provider.GetCertificateAsync(cancellationToken).ConfigureAwait(false);
            var session = new SigningSession(
                provider,
                certificate,
                digestAlgorithm,
                timestampSettings,
                string.IsNullOrWhiteSpace(input.Description) ? null : input.Description,
                descriptionUrl,
                services.Time,
                !input.SkipPackageContents);

            for (var i = 0; i < input.Files.Length; i++)
            {
                var inputPath = input.Files[i];
                var outputPath = string.IsNullOrWhiteSpace(input.OutputPath) ? inputPath : input.OutputPath!;
                var signer = await FormatCatalog.ResolveSignerAsync(inputPath, cancellationToken).ConfigureAwait(false);
                await signer.SignAsync(new(inputPath, outputPath, session), cancellationToken).ConfigureAwait(false);
                var message = $"Signed '{outputPath}' ({signer.Name}, {provider.Name}, {digestAlgorithm.Name}).";
                await output.WriteLineAsync(message.AsMemory(), cancellationToken).ConfigureAwait(false);
            }

            return ExitSuccess;
        }
        finally
        {
            if (provider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    /// <summary>Resolves a working <see cref="ProviderDescriptor"/> by name.</summary>
    /// <param name="providerName">The provider name.</param>
    /// <returns>The matching <see cref="ProviderDescriptor"/>.</returns>
    /// <exception cref="ArgumentException">No provider with <paramref name="providerName"/> exists.</exception>
    /// <exception cref="NotSupportedException">The provider is not working.</exception>
    private static ProviderDescriptor ResolveProviderDescriptor(string providerName)
    {
        var descriptor = ProviderCatalog.Find(providerName)
            ?? throw new ArgumentException(
                $"Unknown signing provider '{providerName}'. Run 'safesign providers' to list available providers.",
                nameof(providerName));

        if (descriptor.Status != ProviderStatus.Working || descriptor.Create is null)
        {
            throw new NotSupportedException(
                $"Signing provider '{descriptor.Name}' ({descriptor.DisplayName}) is not available: {descriptor.Summary}");
        }

        return descriptor;
    }

    /// <summary>Creates optional RFC 3161 <see cref="TimestampSettings"/> when <paramref name="timestampUrl"/> is supplied.</summary>
    /// <param name="timestampUrl">The optional timestamp URL.</param>
    /// <param name="timestampHash">The timestamp digest algorithm name.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <returns>The <see cref="TimestampSettings"/>, or null if <paramref name="timestampUrl"/> is omitted.</returns>
    /// <exception cref="ArgumentException">The URL or digest algorithm is invalid.</exception>
    private static TimestampSettings? CreateTimestampSettings(
        string? timestampUrl,
        string timestampHash,
        ProviderServices services)
    {
        var uri = ParseOptionalAbsoluteUri(timestampUrl, "--timestamp-url");
        if (uri is null)
        {
            return null;
        }

        var digestAlgorithm = ParseDigestAlgorithm(timestampHash, "--timestamp-hash");
        var api = RestService.ForGenerated<IRfc3161TimestampApi>(uri.GetLeftPart(UriPartial.Authority), services.Http);
        return new(uri, digestAlgorithm, api);
    }

    /// <summary>Parses an optional absolute HTTP/HTTPS URI.</summary>
    /// <param name="rawUri">The raw URI string.</param>
    /// <param name="optionName">The CLI option name for diagnostics.</param>
    /// <returns>The parsed <see cref="Uri"/>, or null if <paramref name="rawUri"/> is null or whitespace.</returns>
    /// <exception cref="ArgumentException"><paramref name="rawUri"/> is not an absolute HTTP/HTTPS URI.</exception>
    private static Uri? ParseOptionalAbsoluteUri(string? rawUri, string optionName)
    {
        if (string.IsNullOrWhiteSpace(rawUri))
        {
            return null;
        }

        if (!Uri.TryCreate(rawUri, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException($"Invalid {optionName} '{rawUri}'. Expected an absolute http:// or https:// URL.", nameof(rawUri));
        }

        return uri;
    }
}
