// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using SafeSign.Signing;

namespace SafeSign.Benchmarks;

/// <summary>The owned key and certificate used by a benchmark signing provider.</summary>
/// <param name="Rsa">The RSA signing key.</param>
/// <param name="Certificate">The public signing certificate.</param>
internal readonly record struct BenchmarkSigningMaterial(RSA Rsa, SigningCertificate Certificate);
