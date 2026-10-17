// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Providers;

/// <summary>
/// The provider options given on the command line (<c>--provider-option name=value</c>) and the environment the
/// provider may fall back to.
/// </summary>
/// <param name="Options">The explicit options, keyed case-insensitively.</param>
/// <param name="Environment">Reads an environment variable; returns null when it is unset.</param>
[DebuggerDisplay("{Options.Count} options")]
public sealed record ProviderSettings(Dictionary<string, string> Options, Func<string, string?> Environment);
