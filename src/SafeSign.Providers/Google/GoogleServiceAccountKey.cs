// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>The fields of a Google service account JSON key that SafeSign uses.</summary>
/// <param name="ClientEmail">The service account email (JWT issuer).</param>
/// <param name="PrivateKey">The PEM PKCS #8 RSA private key.</param>
/// <param name="PrivateKeyId">The key ID, sent as the JWT <c>kid</c>.</param>
/// <param name="TokenUri">The OAuth 2.0 token endpoint.</param>
[DebuggerDisplay("{ClientEmail,nq}")]
public sealed record GoogleServiceAccountKey(string ClientEmail, string PrivateKey, string? PrivateKeyId, string? TokenUri)
{
    /// <inheritdoc/>
    public override string ToString() => $"GoogleServiceAccountKey {{ ClientEmail = {ClientEmail} }}";
}
