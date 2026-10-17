// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SafeSign.Providers.SslCom;

/// <summary>Response returned by the SSL.com eSigner CSC <c>POST /csc/v0/signatures/signHash</c> endpoint.</summary>
/// <param name="Signatures">The base64-encoded signatures corresponding to the input hashes.</param>
[DebuggerDisplay("Count = {Signatures?.Length ?? 0}")]
public sealed record SslComSignHashResponse(
    [property: JsonPropertyName("signatures")] string[]? Signatures);
