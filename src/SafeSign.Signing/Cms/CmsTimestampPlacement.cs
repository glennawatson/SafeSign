// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Signing.Cms;

/// <summary>Where an RFC 3161 timestamp token goes in the signer's unsigned attributes.</summary>
public enum CmsTimestampPlacement
{
    /// <summary>No timestamp, even when the session names an authority.</summary>
    None = 0,

    /// <summary>The Authenticode attribute (<c>1.3.6.1.4.1.311.3.3.1</c>) that Windows reads.</summary>
    Authenticode = 1,

    /// <summary>The CMS <c>id-aa-signatureTimeStampToken</c> attribute, used by NuGet and other CMS consumers.</summary>
    Cms = 2,
}
