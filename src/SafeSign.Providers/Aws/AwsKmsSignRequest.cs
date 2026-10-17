// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Aws;

/// <summary>The KMS <c>Sign</c> request body (https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).</summary>
/// <param name="KeyId">The key.</param>
/// <param name="Message">The digest, sent base64 encoded.</param>
/// <param name="MessageType">Always <c>DIGEST</c>.</param>
/// <param name="SigningAlgorithm">The KMS signing algorithm, such as <c>RSASSA_PKCS1_V1_5_SHA_256</c>.</param>
[DebuggerDisplay("{SigningAlgorithm,nq} with {KeyId,nq}")]
public sealed record AwsKmsSignRequest(string KeyId, ReadOnlyMemory<byte> Message, string MessageType, string SigningAlgorithm);
