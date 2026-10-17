// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Shared;

/// <summary>The key family and digest name used to select a provider's signature algorithm.</summary>
/// <param name="Kind">The public key family.</param>
/// <param name="DigestName">The digest name, or null for an unspecified algorithm.</param>
internal readonly record struct ProviderSignatureAlgorithm(PublicKeyKind Kind, string? DigestName);
