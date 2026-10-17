// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

namespace SafeSign.Providers.Certum;

/// <summary>The task response bytes and an optional instruction to poll again.</summary>
/// <param name="Body">The response body bytes.</param>
/// <param name="NextPoll">The next poll instruction, or null for the final payload.</param>
internal readonly record struct CertumTaskResponse(byte[] Body, CertumPollInstruction? NextPoll);
