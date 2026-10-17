// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Certum;

/// <summary>The task poll path and resolved delay.</summary>
/// <param name="Path">The normalized task poll path.</param>
/// <param name="Delay">The delay to apply before polling.</param>
internal readonly record struct CertumPollStep(string Path, TimeSpan Delay);
