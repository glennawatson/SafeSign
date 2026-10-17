// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers;

/// <summary>A provider is missing an option, or an option is invalid.</summary>
public sealed class ProviderConfigurationException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="ProviderConfigurationException"/> class.</summary>
    public ProviderConfigurationException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="ProviderConfigurationException"/> class.</summary>
    /// <param name="message">The message.</param>
    public ProviderConfigurationException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="ProviderConfigurationException"/> class.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The cause.</param>
    public ProviderConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
