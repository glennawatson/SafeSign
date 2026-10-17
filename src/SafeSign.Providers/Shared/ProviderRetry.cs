// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Refit;

namespace SafeSign.Providers.Shared;

/// <summary>
/// Executes provider HTTP requests and polling loops with exponential backoff, fuzzy jitter, and awareness of
/// provider-supplied retry headers (<c>Retry-After</c>, <c>x-ms-retry-after-ms</c>, <c>retry-after-ms</c>) and
/// task poll intervals (such as Certum SimplySign's <c>ping-after</c>).
/// </summary>
public static class ProviderRetry
{
    /// <summary>The integer resolution used when sampling cryptographically random jitter values in <c>[0.0, 1.0)</c>.</summary>
    private const int SampleResolution = 1_000_000;

    /// <summary>Maps a <c>[0.0, 1.0]</c> sample into a symmetric <c>[-1.0, +1.0]</c> offset.</summary>
    private const double SymmetricRangeScale = 2.0;

    /// <summary>Executes a Refit <see cref="IApiResponse{T}"/> request using <see cref="ProviderRetryOptions.Default"/>.</summary>
    /// <typeparam name="T">The response content type.</typeparam>
    /// <param name="action">The asynchronous Refit call.</param>
    /// <param name="time">The clock used for delays and <c>Retry-After</c> date calculations.</param>
    /// <param name="cancellationToken">Cancels the request or retry delay.</param>
    /// <returns>The final <see cref="IApiResponse{T}"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<IApiResponse<T>> ExecuteAsync<T>(
        Func<CancellationToken, Task<IApiResponse<T>>> action,
        TimeProvider time,
        CancellationToken cancellationToken) =>
        ExecuteAsync(action, ProviderRetryOptions.Default, time, cancellationToken);

    /// <summary>Executes a Refit <see cref="IApiResponse{T}"/> request with exponential backoff and fuzzy jitter.</summary>
    /// <typeparam name="T">The response content type.</typeparam>
    /// <param name="action">The asynchronous Refit call.</param>
    /// <param name="options">The retry and backoff options.</param>
    /// <param name="time">The clock used for delays and <c>Retry-After</c> date calculations.</param>
    /// <param name="cancellationToken">Cancels the request or retry delay.</param>
    /// <returns>The final <see cref="IApiResponse{T}"/>.</returns>
    public static async ValueTask<IApiResponse<T>> ExecuteAsync<T>(
        Func<CancellationToken, Task<IApiResponse<T>>> action,
        ProviderRetryOptions options,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);

        var attempt = 0;
        while (true)
        {
            IApiResponse<T> response;
            try
            {
                response = await action(cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException) when (attempt < options.MaxRetries && !cancellationToken.IsCancellationRequested)
            {
                var delay = ComputeBackoffDelay(options, attempt, null);
                await DelayIfPositiveAsync(delay, time, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            if (attempt >= options.MaxRetries || !ShouldRetryResponse(response))
            {
                return response;
            }

            var retryAfter = TryGetRetryAfter(response.Headers, time.GetUtcNow());
            response.Dispose();
            var backoff = ComputeBackoffDelay(options, attempt, retryAfter);
            await DelayIfPositiveAsync(backoff, time, cancellationToken).ConfigureAwait(false);
            attempt++;
        }
    }

    /// <summary>Executes a raw <see cref="HttpResponseMessage"/> request using <see cref="ProviderRetryOptions.Default"/>.</summary>
    /// <param name="action">The asynchronous HTTP call.</param>
    /// <param name="time">The clock used for delays and <c>Retry-After</c> date calculations.</param>
    /// <param name="cancellationToken">Cancels the request or retry delay.</param>
    /// <returns>The final <see cref="HttpResponseMessage"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ValueTask<HttpResponseMessage> ExecuteHttpAsync(
        Func<CancellationToken, Task<HttpResponseMessage>> action,
        TimeProvider time,
        CancellationToken cancellationToken) =>
        ExecuteHttpAsync(action, ProviderRetryOptions.Default, time, cancellationToken);

    /// <summary>Executes a raw <see cref="HttpResponseMessage"/> request with exponential backoff and fuzzy jitter.</summary>
    /// <param name="action">The asynchronous HTTP call.</param>
    /// <param name="options">The retry and backoff options.</param>
    /// <param name="time">The clock used for delays and <c>Retry-After</c> date calculations.</param>
    /// <param name="cancellationToken">Cancels the request or retry delay.</param>
    /// <returns>The final <see cref="HttpResponseMessage"/>.</returns>
    public static async ValueTask<HttpResponseMessage> ExecuteHttpAsync(
        Func<CancellationToken, Task<HttpResponseMessage>> action,
        ProviderRetryOptions options,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);

        var attempt = 0;
        while (true)
        {
            HttpResponseMessage response;
            try
            {
                response = await action(cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException) when (attempt < options.MaxRetries && !cancellationToken.IsCancellationRequested)
            {
                var delay = ComputeBackoffDelay(options, attempt, null);
                await DelayIfPositiveAsync(delay, time, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            if (attempt >= options.MaxRetries || !IsTransientStatusCode(response.StatusCode))
            {
                return response;
            }

            var retryAfter = TryGetRetryAfter(response.Headers, time.GetUtcNow());
            response.Dispose();
            var backoff = ComputeBackoffDelay(options, attempt, retryAfter);
            await DelayIfPositiveAsync(backoff, time, cancellationToken).ConfigureAwait(false);
            attempt++;
        }
    }

    /// <summary>Determines whether an HTTP status code represents a transient failure eligible for retry.</summary>
    /// <param name="statusCode">The HTTP status code.</param>
    /// <returns>True for 408, 429, 500, 502, 503, or 504.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsTransientStatusCode(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.RequestTimeout
            or HttpStatusCode.TooManyRequests
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;

    /// <summary>
    /// Extracts a provider-supplied retry interval from HTTP response headers (<c>Retry-After</c> delta-seconds or
    /// HTTP-date, <c>x-ms-retry-after-ms</c>, or <c>retry-after-ms</c>).
    /// </summary>
    /// <param name="headers">The HTTP response headers, or <see langword="null"/>.</param>
    /// <param name="now">The current UTC timestamp used to convert HTTP-date headers to a relative delay.</param>
    /// <returns>The non-negative retry delay requested by the provider, or <see langword="null"/> when none was present.</returns>
    public static TimeSpan? TryGetRetryAfter(HttpResponseHeaders? headers, DateTimeOffset now)
    {
        if (headers is null)
        {
            return null;
        }

        if (TryGetStructuredRetryAfter(headers.RetryAfter, now) is { } structured)
        {
            return structured;
        }

        return TryGetMillisecondsHeader(headers, "x-ms-retry-after-ms", out var msDelay)
            || TryGetMillisecondsHeader(headers, "retry-after-ms", out msDelay)
            ? msDelay
            : TryGetRawRetryAfter(headers, now);
    }

    /// <summary>
    /// Computes the retry delay for a given zero-based <paramref name="attempt"/> using exponential backoff,
    /// fuzzy random jitter, and an optional provider-supplied <paramref name="providerRetryAfter"/> interval.
    /// </summary>
    /// <param name="options">The retry options.</param>
    /// <param name="attempt">The zero-based retry attempt index.</param>
    /// <param name="providerRetryAfter">The optional <c>Retry-After</c> interval returned by the provider.</param>
    /// <returns>The bounded backoff delay.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TimeSpan ComputeBackoffDelay(
        ProviderRetryOptions options,
        int attempt,
        TimeSpan? providerRetryAfter) =>
        ComputeBackoffDelay(options, attempt, providerRetryAfter, NextRandomSample());

    /// <summary>Computes the retry delay for a zero-based <paramref name="attempt"/> using a deterministic <paramref name="randomSample"/> in <c>[0.0, 1.0)</c>.</summary>
    /// <param name="options">The retry options.</param>
    /// <param name="attempt">The zero-based retry attempt index.</param>
    /// <param name="providerRetryAfter">The optional <c>Retry-After</c> interval returned by the provider.</param>
    /// <param name="randomSample">A uniform sample in <c>[0.0, 1.0)</c> used to compute fuzzy jitter.</param>
    /// <returns>The bounded backoff delay.</returns>
    public static TimeSpan ComputeBackoffDelay(
        ProviderRetryOptions options,
        int attempt,
        TimeSpan? providerRetryAfter,
        double randomSample)
    {
        ArgumentNullException.ThrowIfNull(options);
        var maxMs = Math.Max(0.0, options.MaxDelay.TotalMilliseconds);
        if (maxMs <= 0.0)
        {
            return TimeSpan.Zero;
        }

        var jitterRatio = Math.Clamp(options.JitterRatio, 0.0, 1.0);
        var sample = Math.Clamp(randomSample, 0.0, 1.0);

        if (providerRetryAfter is { TotalMilliseconds: > 0.0 } hinted)
        {
            var floorMs = Math.Min(hinted.TotalMilliseconds, maxMs);
            return TimeSpan.FromMilliseconds(Math.Min(floorMs + (floorMs * jitterRatio * sample), maxMs));
        }

        var initialMs = Math.Max(0.0, options.InitialDelay.TotalMilliseconds);
        if (initialMs <= 0.0)
        {
            return TimeSpan.Zero;
        }

        var multiplier = Math.Max(1.0, options.BackoffMultiplier);
        var exponentialMs = initialMs * Math.Pow(multiplier, Math.Max(0, attempt));
        var cappedMs = Math.Min(exponentialMs, maxMs);
        var symmetricFactor = 1.0 + (((sample * SymmetricRangeScale) - 1.0) * jitterRatio);
        var fuzzedMs = Math.Clamp(cappedMs * symmetricFactor, initialMs, maxMs);
        return TimeSpan.FromMilliseconds(fuzzedMs);
    }

    /// <summary>
    /// Computes a task-polling delay that respects a provider-supplied poll interval (such as Certum's
    /// <c>ping-after</c> milliseconds) with fuzzy jitter bounded by <paramref name="options"/>.
    /// </summary>
    /// <param name="options">The retry/poll bounds and jitter configuration.</param>
    /// <param name="providerPollInterval">The poll interval suggested by the provider, or <see langword="null"/>.</param>
    /// <returns>The bounded, fuzzed poll delay.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TimeSpan ComputePollDelay(ProviderRetryOptions options, TimeSpan? providerPollInterval) =>
        ComputePollDelay(options, providerPollInterval, NextRandomSample());

    /// <summary>Computes a task-polling delay using a deterministic <paramref name="randomSample"/> in <c>[0.0, 1.0)</c>.</summary>
    /// <param name="options">The retry/poll bounds and jitter configuration.</param>
    /// <param name="providerPollInterval">The poll interval suggested by the provider, or <see langword="null"/>.</param>
    /// <param name="randomSample">A uniform sample in <c>[0.0, 1.0)</c> used to compute fuzzy jitter.</param>
    /// <returns>The bounded, fuzzed poll delay.</returns>
    public static TimeSpan ComputePollDelay(
        ProviderRetryOptions options,
        TimeSpan? providerPollInterval,
        double randomSample)
    {
        ArgumentNullException.ThrowIfNull(options);
        var minMs = Math.Max(0.0, options.InitialDelay.TotalMilliseconds);
        var maxMs = Math.Max(minMs, options.MaxDelay.TotalMilliseconds);
        if (maxMs <= 0.0)
        {
            return TimeSpan.Zero;
        }

        var rawMs = providerPollInterval?.TotalMilliseconds ?? minMs;
        var baseMs = Math.Clamp(rawMs, minMs, maxMs);
        var jitterRatio = Math.Clamp(options.JitterRatio, 0.0, 1.0);
        var sample = Math.Clamp(randomSample, 0.0, 1.0);
        var symmetricFactor = 1.0 + (((sample * SymmetricRangeScale) - 1.0) * jitterRatio);
        var fuzzedMs = Math.Clamp(baseMs * symmetricFactor, minMs, maxMs);
        return TimeSpan.FromMilliseconds(fuzzedMs);
    }

    /// <summary>Draws a uniform random sample in <c>[0.0, 1.0)</c>.</summary>
    /// <returns>A random double in <c>[0.0, 1.0)</c>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double NextRandomSample() =>
        RandomNumberGenerator.GetInt32(SampleResolution) / (double)SampleResolution;

    /// <summary>Checks whether a Refit <see cref="IApiResponse"/> failed transiently and should be retried.</summary>
    /// <param name="response">The Refit response.</param>
    /// <returns>True when the response had a transient status code or network request error.</returns>
    private static bool ShouldRetryResponse(IApiResponse response) =>
        response.HasRequestError(out _)
        || (response.StatusCode is { } statusCode && IsTransientStatusCode(statusCode));

    /// <summary>Extracts a delay from a parsed <see cref="RetryConditionHeaderValue"/>.</summary>
    /// <param name="retryAfter">The parsed header value.</param>
    /// <param name="now">The current UTC time.</param>
    /// <returns>The non-negative delay, or <see langword="null"/>.</returns>
    private static TimeSpan? TryGetStructuredRetryAfter(RetryConditionHeaderValue? retryAfter, DateTimeOffset now)
    {
        if (retryAfter is null)
        {
            return null;
        }

        if (retryAfter.Delta is { } delta)
        {
            return delta > TimeSpan.Zero ? delta : TimeSpan.Zero;
        }

        if (retryAfter.Date is { } date)
        {
            var remaining = date - now;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        return null;
    }

    /// <summary>Parses a raw <c>Retry-After</c> header when it was not populated in <see cref="HttpResponseHeaders.RetryAfter"/>.</summary>
    /// <param name="headers">The HTTP response headers.</param>
    /// <param name="now">The current UTC time.</param>
    /// <returns>The non-negative delay, or <see langword="null"/>.</returns>
    private static TimeSpan? TryGetRawRetryAfter(HttpResponseHeaders headers, DateTimeOffset now)
    {
        if (!headers.TryGetValues("Retry-After", out var rawValues))
        {
            return null;
        }

        foreach (var raw in rawValues)
        {
            var trimmed = raw.AsSpan().Trim();
            if (int.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
            {
                return seconds > 0 ? TimeSpan.FromSeconds(seconds) : TimeSpan.Zero;
            }

            if (!DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedDate))
            {
                continue;
            }

            var remaining = parsedDate - now;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }

        return null;
    }

    /// <summary>Tries to read a positive millisecond delay header such as <c>x-ms-retry-after-ms</c>.</summary>
    /// <param name="headers">The HTTP response headers.</param>
    /// <param name="headerName">The header name.</param>
    /// <param name="delay">Receives the parsed delay.</param>
    /// <returns>True when the header was present and parsed as an integer millisecond value.</returns>
    private static bool TryGetMillisecondsHeader(HttpResponseHeaders headers, string headerName, out TimeSpan delay)
    {
        delay = TimeSpan.Zero;
        if (!headers.TryGetValues(headerName, out var values))
        {
            return false;
        }

        foreach (var raw in values)
        {
            if (!int.TryParse(raw.AsSpan().Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ms))
            {
                continue;
            }

            delay = ms > 0 ? TimeSpan.FromMilliseconds(ms) : TimeSpan.Zero;
            return true;
        }

        return false;
    }

    /// <summary>Awaits <see cref="Task.Delay(TimeSpan, TimeProvider, CancellationToken)"/> when <paramref name="delay"/> is positive.</summary>
    /// <param name="delay">The delay duration.</param>
    /// <param name="time">The clock.</param>
    /// <param name="cancellationToken">Cancels the delay.</param>
    /// <returns>A task that completes after <paramref name="delay"/>.</returns>
    private static async ValueTask DelayIfPositiveAsync(TimeSpan delay, TimeProvider time, CancellationToken cancellationToken)
    {
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, time, cancellationToken).ConfigureAwait(false);
        }
    }
}
