// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Formats;

/// <summary>Indicates whether a file format has a working native X.509/CMS/IMA implementation or is out of scope.</summary>
public enum FormatStatus
{
    /// <summary>Native format signing is implemented and verified.</summary>
    Working = 0,

    /// <summary>Native format signing requires OpenPGP/GPG rather than X.509/CMS and is out of scope.</summary>
    OutOfScope = 1,
}
