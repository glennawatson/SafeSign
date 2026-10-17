// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;
using SafeSign.Providers.SslCom;

namespace SafeSign.Providers.Csc;

/// <summary>Source-generated JSON serialization context for CSC v1 DTOs.</summary>
[JsonSerializable(typeof(CscCredentialsInfoRequest))]
[JsonSerializable(typeof(CscCertificateData))]
[JsonSerializable(typeof(CscCredentialsInfoReply))]
[JsonSerializable(typeof(CscAuthorizeRequest))]
[JsonSerializable(typeof(CscAuthorizeReply))]
[JsonSerializable(typeof(CscSignHashRequest))]
[JsonSerializable(typeof(SslComSignHashResponse))]
internal sealed partial class CscJsonContext : JsonSerializerContext;
