/**
 * @file SleepEvasion_Tests.cpp
 * @brief Behavioural contract for the observed-delay sleep analysis (T1497.003).
 *
 * WHY THIS SUITE EXISTS. Three sleep-evasion techniques were fully implemented in
 * TimeBasedEvasionDetector - SleepBombing, SleepAccelerationDetect and
 * SleepFragmentation - and none of them could ever fire, because every field their
 * predicates read came from a per-process monitoring context that nothing filled.
 * RecordTimingEvent had zero callers across src and tests. So HasSleepEvasion()
 * returned false for every process on every endpoint and false was being read as
 * "clean" rather than "never observed".
 *
 * AnalyzeObservedDelays is the producer that was missing. These tests drive it
 * directly with synthetic observations, so they assert BEHAVIOUR rather than source
 * text, and the fragmentation case is the first proof that T1497.003 is reachable.
 *
 * THE NEGATIVE CONTROL IS THE MOST IMPORTANT TEST HERE. A polling loop -
 * while (!done) { Sleep(100); DoWork(); } - produces hundreds of short sleeps
 * summing to a long total with no single long call, which matches the naive
 * fragmentation signature exactly and is entirely legitimate. If that case ever
 * starts detecting, this analysis has become a false-positive generator against
 * ordinary software.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "PhantomCore/AntiEvasion/TimeBasedEvasionDetector.hpp"

namespace {

using ShadowStrike::AntiEvasion::TimeBasedEvasionDetector;
using ObservedDelayCall = TimeBasedEvasionDetector::ObservedDelayCall;

/// @brief Build @p count identical delay calls of @p eachMs milliseconds.
[[nodiscard]] std::vector<ObservedDelayCall> MakeDelays(
    const char* functionName, std::size_t count, std::uint64_t eachMs) {
    std::vector<ObservedDelayCall> calls;
    calls.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        ObservedDelayCall call;
        call.functionName = functionName;
        call.requestedMs = eachMs;
        calls.push_back(call);
    }
    return calls;
}

// The module's own declared thresholds, restated here so a change to either is
// visible as a test failure rather than as a silent change of meaning:
//   MIN_SLEEP_FRAGMENTS_FOR_DETECTION = 10
//   SLEEP_EVASION_THRESHOLD_MS        = 60000
constexpr std::uint64_t kEvasionThresholdMs = 60000;

// ---------------------------------------------------------------------------

TEST(SleepEvasionObservationTest, AnEmptyObservationIsNotACleanResult) {
    // THE DISTINCTION THAT WAS MISSING ENTIRELY. Before this producer existed,
    // "nothing observed" and "no sleep evasion" were the same value.
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays({}, 0);

    EXPECT_FALSE(analysis.runtimeObservationAvailable)
        << "an empty observation must not claim that observation happened";
    EXPECT_FALSE(analysis.HasSleepEvasion());
    EXPECT_EQ(analysis.sleepCallCount, 0u);
}

TEST(SleepEvasionObservationTest, FragmentedSleepIsDetected) {
    // 600 x 100ms = 60,000ms total. No single call is independently evasive, the
    // aggregate is, and the sample does almost nothing but delay.
    const auto calls = MakeDelays("Sleep", 600, 100);
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 10);

    ASSERT_TRUE(analysis.runtimeObservationAvailable)
        << "a non-empty observation must record that it happened";
    EXPECT_EQ(analysis.sleepCallCount, 600u);
    EXPECT_EQ(analysis.totalRequestedDurationMs, 60000u);
    EXPECT_EQ(analysis.maxRequestedDurationMs, 100u);
    EXPECT_EQ(analysis.avgRequestedDurationMs, 100u);

    EXPECT_TRUE(analysis.fragmentationDetected)
        << "T1497.003: 600 short sleeps totalling 60s with no single long call is "
           "sleep fragmentation, and this is the first case in the product's "
           "history able to prove it";
    EXPECT_TRUE(analysis.HasSleepEvasion());

    // The reporting surface must be populated too, not just the flag.
    EXPECT_EQ(analysis.fragmentedSleepCount, 600u);
    EXPECT_EQ(analysis.avgFragmentDurationMs, 100u);
    EXPECT_GT(analysis.confidence, 0.0f);
}

TEST(SleepEvasionObservationTest, APollingLoopIsNotFragmentation) {
    // THE CRITICAL NEGATIVE CONTROL. Identical delay shape to the case above -
    // 600 x 100ms - but the sample does real work between sleeps, so the delays do
    // NOT outnumber other API activity. This is what ordinary software looks like
    // and it must never be reported.
    const auto calls = MakeDelays("Sleep", 600, 100);
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 600);

    EXPECT_TRUE(analysis.runtimeObservationAvailable);
    EXPECT_FALSE(analysis.fragmentationDetected)
        << "a polling loop that does work between its sleeps must not be reported "
           "as sleep fragmentation; the delay shape alone is not the technique";
}

TEST(SleepEvasionObservationTest, OneLongSleepIsNotFragmentation) {
    // A single long sleep is the emulator's own existing detection (ms > 60000).
    // It is NOT fragmentation, and reporting it here would double-report it under
    // the wrong technique.
    const auto calls = MakeDelays("Sleep", 1, kEvasionThresholdMs + 1);
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 0);

    EXPECT_TRUE(analysis.runtimeObservationAvailable);
    EXPECT_FALSE(analysis.fragmentationDetected)
        << "one long sleep is not a fragmented delay - too few fragments, and the "
           "single call is itself evasive";
}

TEST(SleepEvasionObservationTest, AShortTotalIsNotFragmentation) {
    // Below the declared aggregate threshold: many calls, but they do not add up
    // to an evasive delay.
    const auto calls = MakeDelays("Sleep", 50, 10);  // 500ms total
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 0);

    EXPECT_TRUE(analysis.runtimeObservationAvailable);
    EXPECT_EQ(analysis.totalRequestedDurationMs, 500u);
    EXPECT_FALSE(analysis.fragmentationDetected)
        << "500ms of accumulated delay is not evasive regardless of call count";
}

TEST(SleepEvasionObservationTest, TooFewFragmentsIsNotFragmentation) {
    // Above the aggregate threshold but below the declared fragment count, so the
    // pattern is not established. 9 x 7000ms = 63,000ms.
    const auto calls = MakeDelays("Sleep", 9, 7000);
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 0);

    EXPECT_TRUE(analysis.runtimeObservationAvailable);
    EXPECT_GE(analysis.totalRequestedDurationMs, kEvasionThresholdMs);
    EXPECT_FALSE(analysis.fragmentationDetected)
        << "nine calls is below the declared minimum fragment count, so this must "
           "not be reported even though the accumulated delay is evasive";
}

TEST(SleepEvasionObservationTest, DistinctDelayApisAreDeduplicated) {
    // sleepAPIsUsed feeds the sleep-bombing predicate, which counts DISTINCT APIs.
    // A duplicate would inflate it and could trip that detection on one API.
    std::vector<ObservedDelayCall> calls;
    for (int i = 0; i < 20; ++i) {
        ObservedDelayCall a;
        a.functionName = "Sleep";
        a.requestedMs = 10;
        calls.push_back(a);

        ObservedDelayCall b;
        b.functionName = "SleepEx";
        b.requestedMs = 10;
        calls.push_back(b);
    }
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 0);

    EXPECT_EQ(analysis.sleepCallCount, 40u);
    EXPECT_EQ(analysis.sleepAPIsUsed.size(), 2u)
        << "the distinct delay-API population must be deduplicated; sleep bombing "
           "counts distinct APIs and a duplicate would inflate it";
}

TEST(SleepEvasionObservationTest, PerCallDurationsArePreserved) {
    // sleepDurations is the distribution a future predicate would need. It was
    // documented as having no producer; it has one now.
    std::vector<ObservedDelayCall> calls;
    for (std::uint64_t ms : {5u, 50u, 500u}) {
        ObservedDelayCall call;
        call.functionName = "Sleep";
        call.requestedMs = ms;
        calls.push_back(call);
    }
    const auto analysis =
        TimeBasedEvasionDetector::Instance().AnalyzeObservedDelays(calls, 0);

    ASSERT_EQ(analysis.sleepDurations.size(), 3u);
    EXPECT_EQ(analysis.sleepDurations[0], 5u);
    EXPECT_EQ(analysis.sleepDurations[1], 50u);
    EXPECT_EQ(analysis.sleepDurations[2], 500u);
    EXPECT_EQ(analysis.maxRequestedDurationMs, 500u);
    EXPECT_EQ(analysis.totalRequestedDurationMs, 555u);
}

}  // namespace
