/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ServiceMonitor.cpp.
 *
 * Coverage focus:
 * - health-stat serialization
 * - default stats and diagnostics formatting
 * - configuration setter reflection in diagnostic output
 * - safe monitoring-thread lifecycle and heartbeat update surface
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <thread>

#include "../../../src/PhantomCore/Service/ServiceMonitor.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

bool WaitForHealthState(ServiceMonitor& monitor,
                        bool expectedState,
                        std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        if (monitor.IsHealthy() == expectedState) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    } while (std::chrono::steady_clock::now() < deadline);

    return monitor.IsHealthy() == expectedState;
}

// Health polling in ServiceMonitor::MonitorLoop is on a 5s cadence (raised from 1s
// because CollectMetrics takes a system-wide CreateToolhelp32Snapshot every tick and
// that cost was starving the single-threaded IPC accept loop on small VMs). Any test
// waiting for a state change that only a poll can produce must therefore allow more
// than one full poll interval; the fixed 250ms sleeps and the 1500ms deadline the two
// tests below used to have were written against the 1s cadence and are shorter than a
// single tick now.
constexpr auto kPollInterval = std::chrono::milliseconds(5000);
constexpr auto kPollWaitBudget = kPollInterval * 2;

// The ServiceMonitor singleton keeps its last published sample across tests:
// StopMonitoring() joins the monitor thread but does not clear m_currentStats, and
// there is no reset API. So neither "threadCount is non-zero" nor "health is already
// true" can distinguish a fresh sample from one an earlier test in this fixture left
// behind - reading stats straight after StartMonitoring() can return the previous
// test's measurement.
//
// Every wait in the two tests below is therefore a TRANSITION: health is first driven
// to the opposite of the value under test, then the test waits for it to flip. Only a
// new CollectMetrics publication can produce a flip, which makes each assertion
// independent of test order and of whatever ran before it. A 1-byte memory ceiling is
// the deterministic way to force the unhealthy side - it is below any real PrivateUsage
// - and 0 or a 10GB ceiling is the way back.
constexpr uint64_t kCertainlyExceededMemoryLimit = 1ULL;
constexpr uint64_t kUnreachableMemoryLimit = 10ULL * 1024ULL * 1024ULL * 1024ULL;

class ServiceMonitorTest : public ::testing::Test {
protected:
    ServiceMonitor& monitor = ServiceMonitor::Instance();

    void SetUp() override {
        monitor.StopMonitoring();
    }

    void TearDown() override {
        monitor.StopMonitoring();
        monitor.SetMaxMemoryLimit(500ULL * 1024ULL * 1024ULL);
        monitor.SetMaxCpuLimit(90.0);
        monitor.SetHeartbeatTimeout(std::chrono::seconds(30));
    }
};

TEST_F(ServiceMonitorTest, HealthStatsJsonSerializesAllPublishedFields) {
    const SSS::ServiceHealthStats stats{
        12.5,
        4096,
        55,
        6,
        77,
        false,
        "Need attention"
    };

    const std::string json = stats.ToJson();
    EXPECT_NE(json.find("\"cpuUsagePercent\":12.5"), std::string::npos);
    EXPECT_NE(json.find("\"memoryUsageBytes\":4096"), std::string::npos);
    EXPECT_NE(json.find("\"handleCount\":55"), std::string::npos);
    EXPECT_NE(json.find("\"threadCount\":6"), std::string::npos);
    EXPECT_NE(json.find("\"uptimeSeconds\":77"), std::string::npos);
    EXPECT_NE(json.find("\"isHealthy\":false"), std::string::npos);
    EXPECT_NE(json.find("\"statusMessage\":\"Need attention\""), std::string::npos);
}

TEST_F(ServiceMonitorTest, DiagnosticsSurfaceIsAvailableBeforeMonitoringStarts) {
    // Reads the constructor's placeholder stats, which is only true while no test in
    // this fixture has started the monitor yet - i.e. this case depends on running
    // before the Start/Stop cases below, per the singleton-state note above. The two
    // health tests at the bottom of the file no longer depend on order; this one still
    // does, and is left as-is because it is the only way to observe the pre-first-sample
    // state through the public API (there is no stats reset).
    const SSS::ServiceHealthStats stats = monitor.GetCurrentStats();
    EXPECT_EQ(stats.threadCount, 0ULL);
    EXPECT_FALSE(stats.statusMessage.empty());

    const std::string diagnostics = monitor.GetDiagnosticsJson();
    EXPECT_NE(diagnostics.find("\"stats\""), std::string::npos);
    EXPECT_NE(diagnostics.find("\"diagnostics\""), std::string::npos);
    EXPECT_NE(diagnostics.find("\"heartbeatAgeMs\""), std::string::npos);
    EXPECT_NE(diagnostics.find("\"uptimeTotalSeconds\""), std::string::npos);
    EXPECT_NE(diagnostics.find("\"statusMessage\":\""), std::string::npos);
}

TEST_F(ServiceMonitorTest, SettersAreReflectedInDiagnosticsOutput) {
    monitor.SetMaxMemoryLimit(123456789ULL);
    monitor.SetMaxCpuLimit(42.5);
    monitor.SetHeartbeatTimeout(std::chrono::milliseconds(1500));
    monitor.UpdateHeartbeat();

    const std::string diagnostics = monitor.GetDiagnosticsJson();
    EXPECT_NE(diagnostics.find("\"maxMemoryBytes\":123456789"), std::string::npos);
    EXPECT_NE(diagnostics.find("\"maxCpuPercent\":42.5"), std::string::npos);
    EXPECT_NE(diagnostics.find("\"heartbeatTimeoutMs\":1500"), std::string::npos);
}

TEST_F(ServiceMonitorTest, StartStopAndHeartbeatOperationsAreSafeAndIdempotent) {
    ASSERT_TRUE(monitor.StartMonitoring());
    EXPECT_TRUE(monitor.StartMonitoring());

    monitor.UpdateHeartbeat();
    EXPECT_TRUE(monitor.IsHealthy());

    monitor.StopMonitoring();
    monitor.StopMonitoring();
}

// WAS: TEST_F(ServiceMonitorTest, ZeroMemoryLimitTripsHealthWhileThreadCountRemainsUnset),
// which set the memory limit to 0 and expected isHealthy == false, a statusMessage
// containing "High Memory Usage", and threadCount == 0. Two deliberate product changes
// invalidated all three, and the old NAME asserted the opposite of current behaviour,
// so it is renamed rather than patched in place:
//
//   1. CollectMetrics now populates threadCount from a CreateToolhelp32Snapshot walk
//      filtered to the current PID, so it is a real measurement (~28 for this runner)
//      and never 0 once a sample has landed. It was previously left unset.
//   2. The memory check is now `memLimit != 0 && usage > memLimit`, i.e. 0 means "no
//      memory ceiling configured" instead of "a ceiling of zero bytes, which every
//      live process exceeds". A zero-byte limit is not a limit anyone can honour; the
//      old reading made a service configured with no limit permanently unhealthy and
//      would have masked a genuine memory problem behind a status that was already red.
//
// The test still proves the memory trip works - that is the behaviour worth keeping -
// but drives it with a finite limit, which is how the product now expresses one.
// If someone reverts to SetMaxMemoryLimit(0) expecting an unhealthy verdict: it fails,
// and satisfying it would mean removing the `memLimit != 0` guard and taking back the
// ability to run with no configured ceiling.
TEST_F(ServiceMonitorTest, ZeroMemoryLimitMeansUnlimitedWhileFiniteLimitStillTripsHealth) {
    // Long heartbeat timeout so the only thing that can move health here is memory.
    monitor.SetHeartbeatTimeout(std::chrono::hours(1));

    // Phase 1: a finite ceiling that is certainly exceeded still trips health. This is
    // the behaviour the original test was written to protect, driven the way the
    // product now expects a limit to be expressed.
    monitor.SetMaxMemoryLimit(kCertainlyExceededMemoryLimit);
    ASSERT_TRUE(monitor.StartMonitoring());
    ASSERT_TRUE(WaitForHealthState(monitor, false, kPollWaitBudget));

    const SSS::ServiceHealthStats limited = monitor.GetCurrentStats();
    EXPECT_FALSE(limited.isHealthy);
    EXPECT_NE(limited.statusMessage.find("High Memory Usage"), std::string::npos);
    EXPECT_GT(limited.threadCount, 0ULL);
    EXPECT_GT(limited.memoryUsageBytes, 0ULL);

    // Phase 2: 0 means "no ceiling configured", so health recovers. Reaching TRUE from
    // the FALSE established above can only happen through a fresh sample, so this also
    // proves the sample is current rather than inherited from an earlier test.
    monitor.SetMaxMemoryLimit(0);
    ASSERT_TRUE(WaitForHealthState(monitor, true, kPollWaitBudget));

    const SSS::ServiceHealthStats unlimited = monitor.GetCurrentStats();
    EXPECT_TRUE(unlimited.isHealthy);
    EXPECT_EQ(unlimited.statusMessage, "OK");
    EXPECT_GT(unlimited.threadCount, 0ULL);
}

TEST_F(ServiceMonitorTest, CpuLimitDoesNotByItselfFlipHealthStateAndStopDoesNotResetCollectedStats) {
    // A CPU ceiling of -1% is exceeded by every possible sample, and a 1-hour heartbeat
    // timeout cannot expire, so memory is the only other input that can move health.
    monitor.SetMaxCpuLimit(-1.0);
    monitor.SetHeartbeatTimeout(std::chrono::hours(1));

    // Start from a sample that is definitely unhealthy and definitely current.
    monitor.SetMaxMemoryLimit(kCertainlyExceededMemoryLimit);
    ASSERT_TRUE(monitor.StartMonitoring());
    ASSERT_TRUE(WaitForHealthState(monitor, false, kPollWaitBudget));

    // Remove the memory trip while leaving the CPU limit exceeded. If exceeding the CPU
    // limit demoted health, this transition could never happen - so the wait itself is
    // the assertion, and it cannot be satisfied by a stale sample because the state it
    // waits for is the opposite of the one just established.
    // WAS: sleep_for(250ms) then EXPECT_TRUE(IsHealthy()), which after the cadence
    // change could read a sample published before the configuration under test.
    monitor.SetMaxMemoryLimit(kUnreachableMemoryLimit);
    ASSERT_TRUE(WaitForHealthState(monitor, true, kPollWaitBudget));

    const SSS::ServiceHealthStats beforeStop = monitor.GetCurrentStats();
    EXPECT_TRUE(beforeStop.isHealthy);
    EXPECT_EQ(beforeStop.statusMessage, "OK");
    // Confirms the sample really did carry a CPU reading above the -1% ceiling, so the
    // healthy verdict above was reached in spite of the limit being exceeded and not
    // because the comparison never fired. Scan bursts routinely peg a core; a health
    // flag that flips on every burst is noise, not signal.
    EXPECT_GE(beforeStop.cpuUsagePercent, 0.0);
    // WAS: EXPECT_EQ(beforeStop.threadCount, 0ULL). threadCount is now measured via
    // CreateToolhelp32Snapshot rather than left unset - see the preceding test.
    EXPECT_GT(beforeStop.threadCount, 0ULL);

    // Second half: Stop() joins the monitor thread but does not wipe m_currentStats, so
    // the last collected sample stays readable for post-shutdown diagnostics.
    monitor.SetMaxMemoryLimit(kCertainlyExceededMemoryLimit);
    ASSERT_TRUE(WaitForHealthState(monitor, false, kPollWaitBudget));

    monitor.StopMonitoring();

    const SSS::ServiceHealthStats afterStop = monitor.GetCurrentStats();
    EXPECT_FALSE(afterStop.isHealthy);
    EXPECT_GT(afterStop.threadCount, 0ULL);
    EXPECT_NE(afterStop.statusMessage.find("High Memory Usage"), std::string::npos);
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
