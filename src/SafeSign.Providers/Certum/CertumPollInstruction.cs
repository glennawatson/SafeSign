// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Certum;

/// <summary>The next task poll path and the provider's optional delay hint.</summary>
/// <param name="Path">The normalized task poll path.</param>
/// <param name="SuggestedDelay">The provider's delay hint, or null when absent.</param>
internal readonly record struct CertumPollInstruction(string Path, TimeSpan? SuggestedDelay);
