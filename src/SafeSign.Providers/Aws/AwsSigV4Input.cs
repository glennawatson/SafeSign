// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Aws;

/// <summary>The inputs to a Signature Version 4 signature.</summary>
/// <param name="Method">The HTTP method.</param>
/// <param name="Uri">The request URI; its path and query must already be URI-encoded.</param>
/// <param name="Headers">The headers to sign, lower-case names, in any order. Must include <c>host</c> and <c>x-amz-date</c>.</param>
/// <param name="PayloadHash">The lower-case hex SHA-256 of the body.</param>
/// <param name="Region">The region.</param>
/// <param name="Service">The service signing name, such as <c>kms</c>.</param>
/// <param name="Credentials">The access keys.</param>
/// <param name="Timestamp">The request time; must match <c>x-amz-date</c>.</param>
[DebuggerDisplay("{Method,nq} {Uri}")]
public readonly record struct AwsSigV4Input(
    string Method,
    Uri Uri,
    List<KeyValuePair<string, string>> Headers,
    string PayloadHash,
    string Region,
    string Service,
    AwsCredentials Credentials,
    DateTimeOffset Timestamp);
