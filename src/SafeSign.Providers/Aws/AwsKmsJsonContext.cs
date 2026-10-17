// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Aws;

/// <summary>Source-generated JSON metadata for the KMS <c>Sign</c> action (AWS JSON 1.1, PascalCase members).</summary>
[DebuggerDisplay("AwsKmsJsonContext")]
[JsonSerializable(typeof(AwsKmsSignRequest))]
[JsonSerializable(typeof(AwsKmsSignResponse))]
public sealed partial class AwsKmsJsonContext : JsonSerializerContext;
