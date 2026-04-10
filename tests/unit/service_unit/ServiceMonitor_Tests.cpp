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

#include "../../../src/Shared_modules/Service/ServiceMonitor.hpp"

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

TEST_F(ServiceMonitorTest, ZeroMemoryLimitTripsHealthWhileThreadCountRemainsUnset) {
    monitor.SetMaxMemoryLimit(0);
    monitor.SetHeartbeatTimeout(std::chrono::hours(1));

    ASSERT_TRUE(monitor.StartMonitoring());
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    const SSS::ServiceHealthStats stats = monitor.GetCurrentStats();
    EXPECT_FALSE(stats.isHealthy);
    EXPECT_EQ(stats.threadCount, 0ULL);
    EXPECT_NE(stats.statusMessage.find("High Memory Usage"), std::string::npos);
}

TEST_F(ServiceMonitorTest, CpuLimitDoesNotByItselfFlipHealthStateAndStopDoesNotResetCollectedStats) {
    monitor.SetMaxMemoryLimit(10ULL * 1024ULL * 1024ULL * 1024ULL);
    monitor.SetMaxCpuLimit(-1.0);
    monitor.SetHeartbeatTimeout(std::chrono::hours(1));

    ASSERT_TRUE(monitor.StartMonitoring());
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    EXPECT_TRUE(monitor.IsHealthy());
    const SSS::ServiceHealthStats beforeStop = monitor.GetCurrentStats();
    EXPECT_EQ(beforeStop.threadCount, 0ULL);

    monitor.SetMaxMemoryLimit(0);
    ASSERT_TRUE(WaitForHealthState(monitor, false, std::chrono::milliseconds(1500)));

    monitor.StopMonitoring();

    const SSS::ServiceHealthStats afterStop = monitor.GetCurrentStats();
    EXPECT_FALSE(afterStop.isHealthy);
    EXPECT_EQ(afterStop.threadCount, 0ULL);
    EXPECT_NE(afterStop.statusMessage.find("High Memory Usage"), std::string::npos);
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
