// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Signing.Cms;

/// <summary>The RFC 3161 HTTP timestamp protocol surface (RFC 3161 section 3.4).</summary>
public interface IRfc3161TimestampApi
{
    /// <summary>Submits a DER-encoded <c>TimeStampReq</c> (<c>application/timestamp-query</c>) to the timestamp authority.</summary>
    /// <param name="path">The endpoint path on the authority host.</param>
    /// <param name="request">The <c>application/timestamp-query</c> body.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The HTTP response carrying the <c>application/timestamp-reply</c> body.</returns>
    [Post("/{**path}")]
    Task<HttpResponseMessage> TimestampAsync(string path, [Body] HttpContent request, CancellationToken cancellationToken);
}
