// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers.Google;

/// <summary>The <c>asymmetricSign</c> request body.</summary>
/// <param name="Digest">The digest to sign.</param>
[DebuggerDisplay("asymmetricSign")]
public sealed record GoogleKmsSignRequest(GoogleKmsDigest Digest);
