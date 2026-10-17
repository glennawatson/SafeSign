// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Certum;

/// <summary>The CAS login HTML and the URI that served it.</summary>
/// <param name="Html">The login page HTML.</param>
/// <param name="LoginUri">The final login URI, or null when unavailable.</param>
internal readonly record struct CertumLoginPage(string Html, Uri? LoginUri);
