// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Aws;

/// <summary>AWS access keys, as used for Signature Version 4.</summary>
/// <param name="AccessKeyId">The access key ID (<c>AWS_ACCESS_KEY_ID</c>).</param>
/// <param name="SecretAccessKey">The secret access key (<c>AWS_SECRET_ACCESS_KEY</c>).</param>
/// <param name="SessionToken">The session token for temporary credentials (<c>AWS_SESSION_TOKEN</c>), or null.</param>
[DebuggerDisplay("{AccessKeyId,nq}")]
public sealed record AwsCredentials(string AccessKeyId, string SecretAccessKey, string? SessionToken)
{
    /// <inheritdoc/>
    public override string ToString() => $"AwsCredentials {{ AccessKeyId = {AccessKeyId} }}";
}
