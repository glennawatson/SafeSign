// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Security.Cryptography;
using Refit;
using SafeSign.Signing.Cms;

namespace SafeSign.Signing;

/// <summary>An RFC 3161 timestamp authority and its generated Refit transport.</summary>
/// <param name="Authority">The authority's URL.</param>
/// <param name="DigestAlgorithm">The digest algorithm for the timestamp request.</param>
/// <param name="Api">The Refit timestamp client bound to the authority's origin.</param>
[DebuggerDisplay("{Authority} {DigestAlgorithm.Name,nq}")]
public sealed record TimestampSettings(Uri Authority, HashAlgorithmName DigestAlgorithm, IRfc3161TimestampApi Api)
{
    /// <summary>Initializes a new instance of the <see cref="TimestampSettings"/> class using a source-generated Refit client for <paramref name="authority"/>.</summary>
    /// <param name="authority">The authority's URL.</param>
    /// <param name="digestAlgorithm">The digest algorithm for the timestamp request.</param>
    public TimestampSettings(Uri authority, HashAlgorithmName digestAlgorithm)
        : this(authority, digestAlgorithm, RestService.ForGenerated<IRfc3161TimestampApi>(authority.GetLeftPart(UriPartial.Authority)))
    {
    }
}
