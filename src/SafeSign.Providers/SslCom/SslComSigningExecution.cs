// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.SslCom;

/// <summary>The clock and retry policy used by an SSL.com signing operation.</summary>
/// <param name="Clock">The clock used for TOTP generation and retry delays.</param>
/// <param name="Retry">The retry and backoff policy.</param>
[DebuggerDisplay("SSL.com signing execution ({Retry})")]
public readonly record struct SslComSigningExecution(TimeProvider Clock, ProviderRetryOptions Retry);
