// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.Certum;

/// <summary>Source-generated JSON metadata for Certum SimplySign OAuth and SCS1_ATOM payloads.</summary>
[DebuggerDisplay("CertumJsonContext")]
[JsonSerializable(typeof(CertumTokenResponse))]
[JsonSerializable(typeof(CertumTaskStatus))]
[JsonSerializable(typeof(CertumCardInfo[]))]
[JsonSerializable(typeof(CertumSignRequest))]
[JsonSerializable(typeof(Dictionary<string, string>[]))]
public sealed partial class CertumJsonContext : JsonSerializerContext;
