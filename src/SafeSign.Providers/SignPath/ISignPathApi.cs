// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using Refit;

namespace SafeSign.Providers.SignPath;

/// <summary>Refit client for the SignPath REST API.</summary>
public interface ISignPathApi
{
    /// <summary>Retrieves the signing policies accessible to the authenticated user.</summary>
    /// <param name="path">The relative path to <c>Cryptoki/MySigningPolicies</c>.</param>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The signing policies reply.</returns>
    [Get("/{**path}")]
    Task<IApiResponse<SignPathPoliciesReply>> GetSigningPoliciesAsync(
        [Query(Format = "U")] string path,
        [Header("Authorization")] string authorization,
        CancellationToken cancellationToken);

    /// <summary>Submits a fast hash signing request to SignPath.</summary>
    /// <param name="path">The relative path to <c>SigningRequests</c>.</param>
    /// <param name="authorization">The <c>Bearer &lt;token&gt;</c> header.</param>
    /// <param name="projectSlug">The project slug.</param>
    /// <param name="signingPolicySlug">The signing policy slug.</param>
    /// <param name="isFastSigningRequest">Whether this is a fast signing request (<c>true</c>).</param>
    /// <param name="artifact">The hash signing payload attachment.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The sign response.</returns>
    [Multipart]
    [Post("/{**path}")]
    Task<IApiResponse<SignPathSignReply>> SignAsync(
        [Query(Format = "U")] string path,
        [Header("Authorization")] string authorization,
        [AliasAs("ProjectSlug")] string projectSlug,
        [AliasAs("SigningPolicySlug")] string signingPolicySlug,
        [AliasAs("IsFastSigningRequest")] string isFastSigningRequest,
        [AliasAs("Artifact")] ByteArrayPart artifact,
        CancellationToken cancellationToken);
}
