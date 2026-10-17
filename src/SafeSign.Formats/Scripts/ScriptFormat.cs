// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Formats.Scripts;

/// <summary>Describes the Subject Interface Package (SIP) metadata and comment-block framing for a script format.</summary>
/// <param name="SipGuid">The Windows Subject Interface Package GUID.</param>
/// <param name="SipVersion">The SIP version written into <c>SpcSipInfo</c>.</param>
/// <param name="BeginMarker">The comment line that starts the Authenticode signature block.</param>
/// <param name="EndMarker">The comment line that ends the Authenticode signature block.</param>
/// <param name="LinePrefix">The prefix prepended to each 64-character base64 signature line.</param>
/// <param name="LineSuffix">The suffix appended to each 64-character base64 signature line.</param>
/// <param name="IsByteOrderMarkSigned">Whether a present byte order mark (<c>\uFEFF</c>) is included in the UTF-16LE digest and lacks the 4-byte WSH insertion-point trailer.</param>
/// <param name="InsertionAnchor">An optional closing tag before which the signature block is inserted (for example, <c>&lt;/job&gt;</c> in <c>.wsf</c> files).</param>
[DebuggerDisplay("{BeginMarker,nq}")]
public readonly record struct ScriptFormat(
    Guid SipGuid,
    int SipVersion,
    string BeginMarker,
    string EndMarker,
    string LinePrefix,
    string LineSuffix,
    bool IsByteOrderMarkSigned = true,
    string? InsertionAnchor = null);
