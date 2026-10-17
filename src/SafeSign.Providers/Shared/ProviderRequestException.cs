// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Net;

namespace SafeSign.Providers.Shared;

/// <summary>A signing service rejected a request or answered with something SafeSign could not read.</summary>
[DebuggerDisplay("{StatusCode} {Message,nq}")]
public sealed class ProviderRequestException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="ProviderRequestException"/> class.</summary>
    public ProviderRequestException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="ProviderRequestException"/> class.</summary>
    /// <param name="message">The message.</param>
    public ProviderRequestException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="ProviderRequestException"/> class.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The cause.</param>
    public ProviderRequestException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="ProviderRequestException"/> class.</summary>
    /// <param name="message">The message.</param>
    /// <param name="statusCode">The HTTP status the service returned.</param>
    public ProviderRequestException(string message, HttpStatusCode statusCode)
        : base(message) => StatusCode = statusCode;

    /// <summary>Initializes a new instance of the <see cref="ProviderRequestException"/> class.</summary>
    /// <param name="message">The message.</param>
    /// <param name="statusCode">The HTTP status the service returned.</param>
    /// <param name="innerException">The cause.</param>
    public ProviderRequestException(string message, HttpStatusCode statusCode, Exception innerException)
        : base(message, innerException) => StatusCode = statusCode;

    /// <summary>Gets the HTTP status the service returned, when there was one.</summary>
    public HttpStatusCode? StatusCode { get; }
}
