// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace SafeSign.Signing.Cms;

/// <summary>A CMS attribute: its type and the DER encoding of its <c>SET OF AttributeValue</c>.</summary>
/// <param name="Oid">The attribute type.</param>
/// <param name="Values">The DER <c>SET OF</c> holding the attribute's values.</param>
[DebuggerDisplay("{Oid,nq} ({Values.Length} bytes)")]
public readonly record struct CmsAttribute(string Oid, ReadOnlyMemory<byte> Values);
