// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers;

/// <summary>Reads provider options, preferring an explicit option over its environment variables.</summary>
public static class ProviderSettingsReader
{
    /// <summary>Reads an option or the first set environment variable.</summary>
    /// <param name="settings">The settings.</param>
    /// <param name="option">The option name.</param>
    /// <param name="environmentVariables">Environment variables to try in order.</param>
    /// <returns>The value, or null when neither is set.</returns>
    public static string? Find(ProviderSettings settings, string option, params ReadOnlySpan<string> environmentVariables)
    {
        if (settings.Options.TryGetValue(option, out var value) && value.Length > 0)
        {
            return value;
        }

        foreach (var name in environmentVariables)
        {
            if (settings.Options.TryGetValue(name, out var aliasValue) && aliasValue.Length > 0)
            {
                return aliasValue;
            }

            if (settings.Environment(name) is { Length: > 0 } fromEnvironment)
            {
                return fromEnvironment;
            }
        }

        return null;
    }

    /// <summary>Reads a required option or the first set environment variable.</summary>
    /// <param name="settings">The settings.</param>
    /// <param name="option">The option name.</param>
    /// <param name="environmentVariables">Environment variables to try in order.</param>
    /// <returns>The value.</returns>
    /// <exception cref="ProviderConfigurationException">Neither the option nor any variable is set.</exception>
    public static string Require(ProviderSettings settings, string option, params ReadOnlySpan<string> environmentVariables)
    {
        if (Find(settings, option, environmentVariables) is { } value)
        {
            return value;
        }

        var hint = environmentVariables.IsEmpty ? string.Empty : $" or set {string.Join(" / ", environmentVariables.ToArray())}";
        throw new ProviderConfigurationException($"Missing provider option '{option}'. Pass --provider-option {option}=<value>{hint}.");
    }
}
