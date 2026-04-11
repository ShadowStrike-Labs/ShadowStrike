/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file PerformanceMonitor_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::PerformanceMonitor.
 *
 * Coverage focus:
 * - configuration presets and statistics reset behavior
 * - initialization, callback registration quirks, and safe fresh-state throttling logic
 * - kernel-metric ingestion, forced metadata updates, and persistence through shutdown
 */

#include "pch.h"

#include "../../../src/PhantomCore/Core/System/PerformanceMonitor.hpp"

#include <chrono>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::System;

class PerformanceMonitorTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& monitor = PerformanceMonitor::Instance();
        monitor.StopMonitoring();
        monitor.Shutdown();
    }

    void TearDown() override {
        auto& monitor = PerformanceMonitor::Instance();
        monitor.StopMonitoring();
        monitor.Shutdown();
    }
};

TEST(PerformanceMonitorValueTests, ConfigPresetsAndStatisticsResetReflectCollectionModes) {
    const auto defaults = PerformanceMonitorConfig::CreateDefault();
    const auto lowImpact = PerformanceMonitorConfig::CreateLowImpact();

    EXPECT_TRUE(defaults.monitorProcesses);
    EXPECT_TRUE(defaults.monitorSystem);
    EXPECT_TRUE(defaults.detectAnomalies);
    EXPECT_TRUE(defaults.autoThrottle);
    EXPECT_EQ(defaults.samplingIntervalMs, 1000u);
    EXPECT_EQ(defaults.historyDepthSeconds, 300u);
    EXPECT_DOUBLE_EQ(defaults.cpuThrottleThreshold, 70.0);
    EXPECT_DOUBLE_EQ(defaults.memoryThrottleThreshold, 85.0);

    EXPECT_EQ(lowImpact.samplingIntervalMs, 5000u);
    EXPECT_EQ(lowImpact.historyDepthSeconds, 180u);
    EXPECT_DOUBLE_EQ(lowImpact.thresholds.highCpuThreshold, 90.0);
    EXPECT_EQ(lowImpact.thresholds.highCpuDurationSec, 120u);
    EXPECT_DOUBLE_EQ(lowImpact.thresholds.memoryLeakGrowthMBPerMin, 20.0);
    EXPECT_DOUBLE_EQ(lowImpact.cpuThrottleThreshold, 80.0);
    EXPECT_DOUBLE_EQ(lowImpact.memoryThrottleThreshold, 90.0);

    PerformanceMonitorStatistics stats;
    stats.samplesTaken.store(2, std::memory_order_relaxed);
    stats.processesMonitored.store(5, std::memory_order_relaxed);
    stats.anomaliesDetected.store(1, std::memory_order_relaxed);
    stats.throttleEngagements.store(1, std::memory_order_relaxed);
    stats.highCpuDetections.store(1, std::memory_order_relaxed);
    stats.memoryLeakDetections.store(1, std::memory_order_relaxed);
    stats.miningDetections.store(1, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.samplesTaken.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesMonitored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.anomaliesDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.throttleEngagements.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.highCpuDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.memoryLeakDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.miningDetections.load(std::memory_order_relaxed), 0u);
}

TEST_F(PerformanceMonitorTest, InitializeSupportsCallbackRegistrationAndSafeFreshState) {
    auto& monitor = PerformanceMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(PerformanceMonitorConfig::CreateDefault()));

    const auto resourceId = monitor.RegisterResourceUsageCallback([](const SystemResourceUsage&) {});
    const auto anomalyId = monitor.RegisterAnomalyCallback([](const PerformanceAnomaly&) {});
    const auto throttleId = monitor.RegisterThrottleCallback([](bool, double) {});

    EXPECT_NE(resourceId, 0u);
    EXPECT_NE(anomalyId, 0u);
    EXPECT_NE(throttleId, 0u);
    EXPECT_NE(resourceId, anomalyId);
    EXPECT_NE(anomalyId, throttleId);

    monitor.UnregisterResourceUsageCallback(resourceId);
    monitor.UnregisterAnomalyCallback(anomalyId);
    monitor.UnregisterThrottleCallback(throttleId);

    EXPECT_FALSE(monitor.ShouldThrottle());
    EXPECT_DOUBLE_EQ(monitor.GetRecommendedThrottleLevel(), 0.0);
    EXPECT_FALSE(monitor.GetKernelMetrics().hasKernelData);
}

TEST_F(PerformanceMonitorTest, KernelMetricsRoundTripPreservesReportedValues) {
    auto& monitor = PerformanceMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(PerformanceMonitorConfig::CreateDefault()));

    KernelResourceMetrics metrics;
    metrics.nonPagedPoolUsageBytes = 4096;
    metrics.pagedPoolUsageBytes = 8192;
    metrics.systemPteUsage = 64;
    metrics.interruptRate = 123;
    metrics.contextSwitchRate = 456;
    metrics.dpcRate = 12;
    metrics.dpcQueueDepth = 3;
    metrics.kernelHandleCount = 9876;

    monitor.UpdateKernelMetrics(metrics);
    const auto observed = monitor.GetKernelMetrics();

    EXPECT_TRUE(observed.hasKernelData);
    EXPECT_EQ(observed.nonPagedPoolUsageBytes, 4096u);
    EXPECT_EQ(observed.pagedPoolUsageBytes, 8192u);
    EXPECT_EQ(observed.systemPteUsage, 64u);
    EXPECT_EQ(observed.interruptRate, 123u);
    EXPECT_EQ(observed.contextSwitchRate, 456u);
    EXPECT_EQ(observed.dpcRate, 12u);
    EXPECT_EQ(observed.dpcQueueDepth, 3u);
    EXPECT_EQ(observed.kernelHandleCount, 9876u);
    EXPECT_GT(observed.sampleTime.time_since_epoch().count(), 0);
}

TEST_F(PerformanceMonitorTest, EmptyCallbacksStillRegisterAndUnregisterCleanly) {
    auto& monitor = PerformanceMonitor::Instance();

    const auto resourceId = monitor.RegisterResourceUsageCallback(ResourceUsageCallback{});
    const auto anomalyId = monitor.RegisterAnomalyCallback(AnomalyCallback{});
    const auto throttleId = monitor.RegisterThrottleCallback(ThrottleCallback{});

    EXPECT_NE(resourceId, 0u);
    EXPECT_NE(anomalyId, 0u);
    EXPECT_NE(throttleId, 0u);
    EXPECT_NE(resourceId, anomalyId);
    EXPECT_NE(anomalyId, throttleId);

    monitor.UnregisterResourceUsageCallback(resourceId);
    monitor.UnregisterResourceUsageCallback(resourceId);
    monitor.UnregisterAnomalyCallback(anomalyId);
    monitor.UnregisterAnomalyCallback(anomalyId);
    monitor.UnregisterThrottleCallback(throttleId);
    monitor.UnregisterThrottleCallback(throttleId);
}

TEST_F(PerformanceMonitorTest, KernelMetricsAreForcedPresentAndPersistAcrossShutdown) {
    auto& monitor = PerformanceMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(PerformanceMonitorConfig::CreateDefault()));

    KernelResourceMetrics metrics;
    metrics.nonPagedPoolUsageBytes = 16384;
    metrics.interruptRate = 77;
    metrics.kernelHandleCount = 321;
    metrics.hasKernelData = false;
    metrics.sampleTime = std::chrono::steady_clock::time_point{};

    monitor.UpdateKernelMetrics(metrics);
    const auto observed = monitor.GetKernelMetrics();
    EXPECT_TRUE(observed.hasKernelData);
    EXPECT_EQ(observed.nonPagedPoolUsageBytes, 16384u);
    EXPECT_EQ(observed.interruptRate, 77u);
    EXPECT_EQ(observed.kernelHandleCount, 321u);
    EXPECT_NE(observed.sampleTime, metrics.sampleTime);

    monitor.Shutdown();
    const auto afterShutdown = monitor.GetKernelMetrics();
    EXPECT_TRUE(afterShutdown.hasKernelData);
    EXPECT_EQ(afterShutdown.nonPagedPoolUsageBytes, 16384u);
    EXPECT_EQ(afterShutdown.interruptRate, 77u);
    EXPECT_EQ(afterShutdown.kernelHandleCount, 321u);

    ASSERT_TRUE(monitor.Initialize(PerformanceMonitorConfig::CreateDefault()));
    const auto afterReinitialize = monitor.GetKernelMetrics();
    EXPECT_TRUE(afterReinitialize.hasKernelData);
    EXPECT_EQ(afterReinitialize.nonPagedPoolUsageBytes, 16384u);
    EXPECT_EQ(afterReinitialize.interruptRate, 77u);
    EXPECT_EQ(afterReinitialize.kernelHandleCount, 321u);
}

TEST_F(PerformanceMonitorTest, MonitoringBoundariesAndZeroCountQueriesRemainStable) {
    auto& monitor = PerformanceMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(PerformanceMonitorConfig::CreateDefault()));

    EXPECT_TRUE(monitor.GetTopCPUProcesses(0).empty());
    EXPECT_TRUE(monitor.GetTopMemoryProcesses(0).empty());
    EXPECT_TRUE(monitor.GetTopIOProcesses(0).empty());
    EXPECT_TRUE(monitor.GetUsageHistory(0s).empty());

    ASSERT_NO_THROW({
        (void)monitor.GetProcessUsage(0);
        monitor.StartMonitoring();
        monitor.StartMonitoring();
        monitor.StopMonitoring();
        monitor.StopMonitoring();
        monitor.UnregisterResourceUsageCallback(9999);
        monitor.UnregisterAnomalyCallback(9999);
        monitor.UnregisterThrottleCallback(9999);
    });
}

}  // namespace
