// Copyright (c) 2026 Glenn Watson and Contributors. All rights reserved.
// Glenn Watson and Contributors licenses this file to you under the MIT license.
// See the LICENSE file in the project root for full license information.

using System.Net;
using SafeSign.Providers.Shared;

namespace SafeSign.Providers.Tests;

/// <summary>Verifies exponential backoff, fuzzy jitter, and provider-supplied retry/poll intervals in <see cref="ProviderRetry"/>.</summary>
public sealed class ProviderRetryTests
{
    /// <summary>The retry limit used in exponential backoff tests.</summary>
    private const int TestMaxRetries = 4;

    /// <summary>The retry limit used in poll tests.</summary>
    private const int PollMaxRetries = 3;

    /// <summary>The attempt index that exceeds the maximum delay cap.</summary>
    private const int CappedAttemptIndex = 5;

    /// <summary>The second retry attempt index.</summary>
    private const int SecondAttemptIndex = 2;

    /// <summary>The third total attempt count expected after two retries.</summary>
    private const int ExpectedTotalAttempts = 3;

    /// <summary>The initial backoff delay in milliseconds for test policies.</summary>
    private const int InitialDelayMs = 100;

    /// <summary>The doubled backoff delay in milliseconds on attempt 1.</summary>
    private const int Attempt1DelayMs = 200;

    /// <summary>The lower jitter bound in milliseconds on attempt 2.</summary>
    private const int Attempt2LowDelayMs = 300;

    /// <summary>The midpoint backoff delay in milliseconds on attempt 2.</summary>
    private const int Attempt2MidDelayMs = 400;

    /// <summary>The upper jitter bound in milliseconds on attempt 2.</summary>
    private const int Attempt2HighDelayMs = 500;

    /// <summary>The upper jitter bound in milliseconds for the 500ms poll interval.</summary>
    private const int PollHighDelayMs = 600;

    /// <summary>The provider Retry-After floor in milliseconds.</summary>
    private const int ProviderFloorDelayMs = 800;

    /// <summary>The provider Retry-After upper bound in milliseconds with +25% fuzzy jitter.</summary>
    private const int ProviderHighDelayMs = 1000;

    /// <summary>The maximum backoff delay in milliseconds for test policies.</summary>
    private const int MaxDelayMs = 2000;

    /// <summary>The delta Retry-After header seconds.</summary>
    private const int DeltaRetrySeconds = 4;

    /// <summary>The HTTP-date Retry-After header seconds.</summary>
    private const int DateRetrySeconds = 7;

    /// <summary>The x-ms-retry-after-ms header value in milliseconds.</summary>
    private const int AzureRetryAfterMs = 350;

    /// <summary>The test timestamp year.</summary>
    private const int TestYear = 2026;

    /// <summary>The test timestamp month.</summary>
    private const int TestMonth = 10;

    /// <summary>The test timestamp day.</summary>
    private const int TestDay = 17;

    /// <summary>The test timestamp hour.</summary>
    private const int TestHour = 3;

    /// <summary>The exponential multiplier for test policies.</summary>
    private const double Multiplier = 2.0;

    /// <summary>The fuzzy jitter ratio for test policies.</summary>
    private const double JitterRatio = 0.25;

    /// <summary>The fuzzy jitter ratio for poll interval tests.</summary>
    private const double PollJitterRatio = 0.20;

    /// <summary>A midpoint random sample (0.5) that produces zero symmetric jitter offset.</summary>
    private const double MidpointSample = 0.5;

    /// <summary>A maximum random sample (1.0) that produces the upper jitter bound.</summary>
    private const double UpperSample = 1.0;

    /// <summary>A minimum random sample (0.0) that produces the lower jitter bound.</summary>
    private const double LowerSample = 0.0;

    /// <summary>Verifies exponential growth across attempts and clamping to <see cref="ProviderRetryOptions.MaxDelay"/>.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ComputeBackoffDelay_GrowsExponentiallyAndFuzzesWithinBounds()
    {
        var options = new ProviderRetryOptions(
            TestMaxRetries,
            TimeSpan.FromMilliseconds(InitialDelayMs),
            TimeSpan.FromMilliseconds(MaxDelayMs),
            Multiplier,
            JitterRatio);

        var attempt0Mid = ProviderRetry.ComputeBackoffDelay(options, 0, null, MidpointSample);
        var attempt1Mid = ProviderRetry.ComputeBackoffDelay(options, 1, null, MidpointSample);
        var attempt2Mid = ProviderRetry.ComputeBackoffDelay(options, SecondAttemptIndex, null, MidpointSample);
        var attempt5Mid = ProviderRetry.ComputeBackoffDelay(options, CappedAttemptIndex, null, MidpointSample);

        await Assert.That(attempt0Mid).IsEqualTo(TimeSpan.FromMilliseconds(InitialDelayMs));
        await Assert.That(attempt1Mid).IsEqualTo(TimeSpan.FromMilliseconds(Attempt1DelayMs));
        await Assert.That(attempt2Mid).IsEqualTo(TimeSpan.FromMilliseconds(Attempt2MidDelayMs));
        await Assert.That(attempt5Mid).IsEqualTo(TimeSpan.FromMilliseconds(MaxDelayMs));

        var attempt2Low = ProviderRetry.ComputeBackoffDelay(options, SecondAttemptIndex, null, LowerSample);
        var attempt2High = ProviderRetry.ComputeBackoffDelay(options, SecondAttemptIndex, null, UpperSample);
        await Assert.That(attempt2Low).IsEqualTo(TimeSpan.FromMilliseconds(Attempt2LowDelayMs));
        await Assert.That(attempt2High).IsEqualTo(TimeSpan.FromMilliseconds(Attempt2HighDelayMs));
    }

    /// <summary>Verifies that a provider-supplied <c>Retry-After</c> interval acts as a floor with positive fuzzy jitter.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ComputeBackoffDelay_HonorsProviderRetryAfterWithPositiveFuzzyJitter()
    {
        var options = new ProviderRetryOptions(
            PollMaxRetries,
            TimeSpan.FromMilliseconds(InitialDelayMs),
            TimeSpan.FromMilliseconds(MaxDelayMs),
            Multiplier,
            JitterRatio);
        var providerHint = TimeSpan.FromMilliseconds(ProviderFloorDelayMs);

        var low = ProviderRetry.ComputeBackoffDelay(options, 0, providerHint, LowerSample);
        var high = ProviderRetry.ComputeBackoffDelay(options, 0, providerHint, UpperSample);

        await Assert.That(low).IsEqualTo(TimeSpan.FromMilliseconds(ProviderFloorDelayMs));
        await Assert.That(high).IsEqualTo(TimeSpan.FromMilliseconds(ProviderHighDelayMs));
    }

    /// <summary>Verifies that <see cref="ProviderRetry.ComputePollDelay(ProviderRetryOptions, TimeSpan?, double)"/> respects provider <c>ping-after</c> hints and applies fuzzy jitter.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ComputePollDelay_FuzzesProviderPingAfterWithinBounds()
    {
        var options = new ProviderRetryOptions(
            PollMaxRetries,
            TimeSpan.FromMilliseconds(Attempt1DelayMs),
            TimeSpan.FromMilliseconds(MaxDelayMs),
            Multiplier,
            PollJitterRatio);
        var pingAfter = TimeSpan.FromMilliseconds(Attempt2HighDelayMs);

        var mid = ProviderRetry.ComputePollDelay(options, pingAfter, MidpointSample);
        var low = ProviderRetry.ComputePollDelay(options, pingAfter, LowerSample);
        var high = ProviderRetry.ComputePollDelay(options, pingAfter, UpperSample);

        await Assert.That(mid).IsEqualTo(TimeSpan.FromMilliseconds(Attempt2HighDelayMs));
        await Assert.That(low).IsEqualTo(TimeSpan.FromMilliseconds(Attempt2MidDelayMs));
        await Assert.That(high).IsEqualTo(TimeSpan.FromMilliseconds(PollHighDelayMs));
    }

    /// <summary>Verifies parsing of delta-seconds, HTTP-date, and <c>x-ms-retry-after-ms</c> response headers.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task TryGetRetryAfter_ParsesDeltaDateAndMillisecondHeaders()
    {
        var now = new DateTimeOffset(TestYear, TestMonth, TestDay, TestHour, 0, 0, TimeSpan.Zero);

        using var deltaResponse = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        deltaResponse.Headers.RetryAfter = new(TimeSpan.FromSeconds(DeltaRetrySeconds));
        await Assert.That(ProviderRetry.TryGetRetryAfter(deltaResponse.Headers, now)).IsEqualTo(TimeSpan.FromSeconds(DeltaRetrySeconds));

        using var dateResponse = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        dateResponse.Headers.RetryAfter = new(now.AddSeconds(DateRetrySeconds));
        await Assert.That(ProviderRetry.TryGetRetryAfter(dateResponse.Headers, now)).IsEqualTo(TimeSpan.FromSeconds(DateRetrySeconds));

        using var msResponse = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        msResponse.Headers.Add("x-ms-retry-after-ms", "350");
        await Assert.That(ProviderRetry.TryGetRetryAfter(msResponse.Headers, now)).IsEqualTo(TimeSpan.FromMilliseconds(AzureRetryAfterMs));
    }

    /// <summary>Verifies that <see cref="ProviderRetry"/> retries transient 429 and 503 HTTP responses before succeeding.</summary>
    /// <returns>A task representing the asynchronous test operation.</returns>
    [Test]
    public async Task ExecuteHttpAsync_RetriesTransientResponsesUntilSuccess()
    {
        var attempts = 0;
        using var response = await ProviderRetry.ExecuteHttpAsync(
            _ =>
            {
                attempts++;
                if (attempts == 1)
                {
                    var throttled = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                    throttled.Headers.Add("retry-after-ms", "1");
                    return Task.FromResult(throttled);
                }

                return Task.FromResult(new HttpResponseMessage(
                    attempts == SecondAttemptIndex ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
            },
            ProviderRetryOptions.FastTest,
            TimeProvider.System,
            CancellationToken.None);

        await Assert.That(attempts).IsEqualTo(ExpectedTotalAttempts);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }
}
