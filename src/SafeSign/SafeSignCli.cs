// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.CommandLine;
using System.Runtime.CompilerServices;
using SafeSign.Formats;
using SafeSign.Providers;

namespace SafeSign;

/// <summary>Builds and invokes the <c>safesign</c> command-line interface.</summary>
public static class SafeSignCli
{
    /// <summary>The default SHA-2 digest algorithm name.</summary>
    private const string DefaultHashAlgorithm = "SHA256";

    /// <summary>Parses and executes <paramref name="args"/> using default Refit and environment services.</summary>
    /// <param name="args">The command-line arguments.</param>
    /// <param name="output">Receives standard output.</param>
    /// <param name="error">Receives standard error.</param>
    /// <param name="cancellationToken">Cancels the command.</param>
    /// <returns>The process exit code.</returns>
    /// <exception cref="ArgumentNullException">Any parameter is null.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken) =>
        RunAsync(args, output, error, new(), Environment.GetEnvironmentVariable, cancellationToken);

    /// <summary>Parses and executes <paramref name="args"/> using custom <paramref name="services"/> and <paramref name="environment"/>.</summary>
    /// <param name="args">The command-line arguments.</param>
    /// <param name="output">Receives standard output.</param>
    /// <param name="error">Receives standard error.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <param name="environment">Reads environment variables.</param>
    /// <param name="cancellationToken">Cancels the command.</param>
    /// <returns>The process exit code.</returns>
    /// <exception cref="ArgumentNullException">Any parameter is null.</exception>
    public static Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        ProviderServices services,
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);

        var rootCommand = BuildRootCommand(output, error, services, environment);
        var parseResult = rootCommand.Parse(args);
        var invocationConfig = new InvocationConfiguration { Output = output, Error = error, EnableDefaultExceptionHandler = false };
        return parseResult.InvokeAsync(invocationConfig, cancellationToken);
    }

    /// <summary>Builds the root <c>safesign</c> command and its <c>sign</c>, <c>providers</c>, and <c>formats</c> subcommands.</summary>
    /// <param name="output">Receives standard output.</param>
    /// <param name="error">Receives standard error.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <param name="environment">Reads environment variables.</param>
    /// <returns>The configured <see cref="RootCommand"/>.</returns>
    private static RootCommand BuildRootCommand(
        TextWriter output,
        TextWriter error,
        ProviderServices services,
        Func<string, string?> environment)
    {
        var root = new RootCommand("Cross-platform code signing tool for executables, installers, packages, and scripts.");
        root.Subcommands.Add(BuildSignCommand(output, error, services, environment));
        root.Subcommands.Add(BuildProvidersCommand(output));
        root.Subcommands.Add(BuildFormatsCommand(output));
        return root;
    }

    /// <summary>Builds the <c>sign</c> subcommand.</summary>
    /// <param name="output">Receives standard output.</param>
    /// <param name="error">Receives standard error.</param>
    /// <param name="services">The Refit and clock services.</param>
    /// <param name="environment">Reads environment variables.</param>
    /// <returns>The configured <c>sign</c> <see cref="Command"/>.</returns>
    private static Command BuildSignCommand(
        TextWriter output,
        TextWriter error,
        ProviderServices services,
        Func<string, string?> environment)
    {
        var filesArgument = new Argument<string[]>("files") { Description = "One or more files to sign.", Arity = ArgumentArity.OneOrMore };
        var providerOption = new Option<string>("--provider", "-p") { Description = "The signing provider name (run 'safesign providers' to list).", Required = true };
        var providerOptionsOption = new Option<string[]>("--provider-option", "-o") { Description = "Provider option in 'name=value' form.", AllowMultipleArgumentsPerToken = true };
        var outputOption = new Option<string?>("--output") { Description = "Optional output file path when signing a single input file (defaults to in-place)." };
        var hashOption = new Option<string>("--hash", "-f") { Description = "File digest: SHA256, SHA384, or SHA512.", DefaultValueFactory = static _ => DefaultHashAlgorithm };
        var timestampUrlOption = new Option<string?>("--timestamp-url", "-t") { Description = "Optional RFC 3161 timestamp authority URL." };
        var timestampHashOption = new Option<string>("--timestamp-hash") { Description = "RFC 3161 digest: SHA256, SHA384, or SHA512.", DefaultValueFactory = static _ => DefaultHashAlgorithm };
        var descriptionOption = new Option<string?>("--description", "-d") { Description = "Optional program name embedded in Authenticode signatures." };
        var descriptionUrlOption = new Option<string?>("--description-url", "-u") { Description = "Optional 'more information' URL embedded in Authenticode signatures." };

        var command = new Command("sign", "Sign one or more files using the specified signing provider.")
        {
            filesArgument,
            providerOption,
            providerOptionsOption,
            outputOption,
            hashOption,
            timestampUrlOption,
            timestampHashOption,
            descriptionOption,
            descriptionUrlOption,
        };

        command.SetAction((parseResult, cancellationToken) =>
        {
            var input = new SignCommandInput(
                parseResult.GetValue(filesArgument) ?? [],
                parseResult.GetValue(providerOption) ?? string.Empty,
                parseResult.GetValue(providerOptionsOption) ?? [],
                parseResult.GetValue(outputOption),
                parseResult.GetValue(hashOption) ?? DefaultHashAlgorithm,
                parseResult.GetValue(timestampUrlOption),
                parseResult.GetValue(timestampHashOption) ?? DefaultHashAlgorithm,
                parseResult.GetValue(descriptionOption),
                parseResult.GetValue(descriptionUrlOption));

            return SignRunner.ExecuteAsync(input, services, environment, output, error, cancellationToken);
        });

        return command;
    }

    /// <summary>Builds the <c>providers</c> subcommand that prints <see cref="ProviderCatalog.All"/>.</summary>
    /// <param name="output">Receives standard output.</param>
    /// <returns>The configured <c>providers</c> <see cref="Command"/>.</returns>
    private static Command BuildProvidersCommand(TextWriter output)
    {
        var command = new Command("providers", "List all supported and planned signing providers.");
        command.SetAction(async (_, cancellationToken) =>
        {
            var providers = ProviderCatalog.All;
            for (var i = 0; i < providers.Length; i++)
            {
                var p = providers[i];
                await output.WriteLineAsync($"{p.Name} [{p.Status}] {p.DisplayName}".AsMemory(), cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync($"  {p.Summary}".AsMemory(), cancellationToken).ConfigureAwait(false);
            }

            return SignRunner.ExitSuccess;
        });

        return command;
    }

    /// <summary>Builds the <c>formats</c> subcommand that prints <see cref="FormatCatalog.All"/>.</summary>
    /// <param name="output">Receives standard output.</param>
    /// <returns>The configured <c>formats</c> <see cref="Command"/>.</returns>
    private static Command BuildFormatsCommand(TextWriter output)
    {
        var command = new Command("formats", "List all supported and out-of-scope file formats.");
        command.SetAction(async (_, cancellationToken) =>
        {
            var formats = FormatCatalog.All;
            for (var i = 0; i < formats.Length; i++)
            {
                var f = formats[i];
                var extensions = string.Join(", ", f.Extensions);
                await output.WriteLineAsync($"{f.Id} [{f.Status}] {f.Name} ({extensions})".AsMemory(), cancellationToken).ConfigureAwait(false);
                await output.WriteLineAsync($"  {f.Summary}".AsMemory(), cancellationToken).ConfigureAwait(false);
            }

            return SignRunner.ExitSuccess;
        });

        return command;
    }
}
