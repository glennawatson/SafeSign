// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Azure;

/// <summary>A Microsoft Entra ID application (service principal) that authenticates with a client secret.</summary>
/// <param name="TenantId">The directory (tenant) ID (<c>AZURE_TENANT_ID</c>).</param>
/// <param name="ClientId">The application (client) ID (<c>AZURE_CLIENT_ID</c>).</param>
/// <param name="ClientSecret">The client secret (<c>AZURE_CLIENT_SECRET</c>).</param>
[DebuggerDisplay("{ClientId,nq} in {TenantId,nq}")]
public sealed record EntraIdCredential(string TenantId, string ClientId, string ClientSecret)
{
    /// <summary>Gets the authority host. Defaults to the public cloud, <c>https://login.microsoftonline.com/</c>.</summary>
    public Uri AuthorityHost { get; init; } = new("https://login.microsoftonline.com/");

    /// <inheritdoc/>
    public override string ToString() => $"EntraIdCredential {{ TenantId = {TenantId}, ClientId = {ClientId} }}";
}
