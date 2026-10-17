// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Formats.CompoundFile;

/// <summary>The sorted children and inclusive bounds of a compound file sibling subtree.</summary>
/// <param name="Sorted">The sorted storage children.</param>
/// <param name="Low">The first child index.</param>
/// <param name="High">The last child index.</param>
internal readonly record struct CompoundFileSiblingRange(List<CompoundFileEntry> Sorted, int Low, int High);
