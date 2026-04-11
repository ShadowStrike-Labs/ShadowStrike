/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for MemoryProfiler.cpp.
 *
 * Coverage focus:
 * - configuration boundary validation
 * - JSON serialization of memory snapshots
 * - singleton lifecycle/configuration guard paths, including pre-init behavior
 * - refresh, capped process tracking, self-usage, and explicit self-test behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <Windows.h>

#include <string>

#include "../../../src/PhantomCore/Performance/dev/MemoryProfiler.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

class MemoryProfilerTest : public ::testing::Test {
protected:
    MemoryProfiler& profiler = MemoryProfiler::Instance();

    void SetUp() override {
        profiler.StopMonitoring();
        profiler.Shutdown();
    }

    void TearDown() override {
        profiler.StopMonitoring();
        profiler.Shutdown();
    }
};

TEST_F(MemoryProfilerTest, ConfigValidationRejectsOutOfRangeValues) {
    SSP::MemoryProfilerConfig config;
    EXPECT_TRUE(config.IsValid());

    config.samplingIntervalMs = 100;
    EXPECT_TRUE(config.IsValid());
    config.samplingIntervalMs = 3600000;
    EXPECT_TRUE(config.IsValid());
    config.samplingIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());
    config.samplingIntervalMs = 2000;

    config.historySize = 3;
    EXPECT_FALSE(config.IsValid());
    config.minSamplesForLeakDetection = 3;
    EXPECT_TRUE(config.IsValid());
    config.historySize = 10000;
    EXPECT_TRUE(config.IsValid());
    config.historySize = 2;
    EXPECT_FALSE(config.IsValid());
    config.historySize = 30;

    config.highLoadThreshold = 100;
    EXPECT_TRUE(config.IsValid());
    config.highLoadThreshold = 0;
    EXPECT_FALSE(config.IsValid());
    config.highLoadThreshold = 90;

    config.leakThresholdBytes = 0;
    EXPECT_FALSE(config.IsValid());
    config.leakThresholdBytes = 1024 * 1024;

    config.maxTrackedProcesses = 100000;
    EXPECT_TRUE(config.IsValid());
    config.maxTrackedProcesses = 0;
    EXPECT_FALSE(config.IsValid());
    config.maxTrackedProcesses = 2048;
    config.maxTrackedProcesses = 100001;
    EXPECT_FALSE(config.IsValid());
    config.maxTrackedProcesses = 2048;

    config.minSamplesForLeakDetection = config.historySize;
    EXPECT_TRUE(config.IsValid());
    config.minSamplesForLeakDetection = 31;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(MemoryProfilerTest, SerializationProducesExpectedJsonShapes) {
    const SSP::ProcessMemoryInfo processInfo{
        404,
        L"mem\"watch\nproc",
        4096,
        8192,
        16384,
        55,
        12.5,
        true
    };
    const std::string processJson = processInfo.ToJson();
    EXPECT_NE(processJson.find("\"pid\":404"), std::string::npos);
    EXPECT_NE(processJson.find("mem\\\"watch\\nproc"), std::string::npos);
    EXPECT_NE(processJson.find("\"privateBytes\":8192"), std::string::npos);
    EXPECT_NE(processJson.find("\"percentOfSystemMemory\":12.50"), std::string::npos);
    EXPECT_NE(processJson.find("\"isLeaking\":true"), std::string::npos);

    const SSP::SystemMemoryStats stats{
        10,
        9,
        8,
        7,
        6,
        5,
        4
    };
    const std::string statsJson = stats.ToJson();
    EXPECT_NE(statsJson.find("\"totalPhysicalBytes\":10"), std::string::npos);
    EXPECT_NE(statsJson.find("\"memoryLoadPercent\":4"), std::string::npos);
}

TEST_F(MemoryProfilerTest, LifecycleAndConfigurationUpdatesRespectValidation) {
    EXPECT_TRUE(SSP::MemoryProfiler::HasInstance());
    EXPECT_EQ(SSP::MemoryProfiler::GetVersionString(), "3.1.0");

    SSP::MemoryProfilerConfig invalidConfig;
    invalidConfig.maxTrackedProcesses = 0;
    EXPECT_FALSE(profiler.Initialize(invalidConfig));

    SSP::MemoryProfilerConfig validConfig;
    validConfig.enabled = false;
    validConfig.trackPerProcess = false;
    validConfig.samplingIntervalMs = 2500;
    validConfig.historySize = 40;
    ASSERT_TRUE(profiler.Initialize(validConfig));
    EXPECT_FALSE(profiler.IsMonitoring());

    const SSP::MemoryProfilerConfig initialized = profiler.GetConfiguration();
    EXPECT_EQ(initialized.samplingIntervalMs, 2500u);
    EXPECT_FALSE(initialized.trackPerProcess);

    SSP::MemoryProfilerConfig invalidUpdate = validConfig;
    invalidUpdate.minSamplesForLeakDetection = validConfig.historySize + 1;
    EXPECT_FALSE(profiler.UpdateConfiguration(invalidUpdate));
    const SSP::MemoryProfilerConfig afterInvalidUpdate = profiler.GetConfiguration();
    EXPECT_EQ(afterInvalidUpdate.samplingIntervalMs, 2500u);
    EXPECT_FALSE(afterInvalidUpdate.trackPerProcess);
    EXPECT_EQ(afterInvalidUpdate.maxTrackedProcesses, validConfig.maxTrackedProcesses);

    SSP::MemoryProfilerConfig validUpdate = validConfig;
    validUpdate.trackPerProcess = true;
    validUpdate.maxTrackedProcesses = 1024;
    EXPECT_TRUE(profiler.UpdateConfiguration(validUpdate));

    const SSP::MemoryProfilerConfig updated = profiler.GetConfiguration();
    EXPECT_TRUE(updated.trackPerProcess);
    EXPECT_EQ(updated.maxTrackedProcesses, 1024u);
}

TEST_F(MemoryProfilerTest, PreInitUpdatesAndMonitoringLifecycleFollowCurrentGuards) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = false;
    config.samplingIntervalMs = 100;
    config.historySize = 3;
    config.minSamplesForLeakDetection = 3;

    EXPECT_TRUE(profiler.UpdateConfiguration(config));
    const SSP::MemoryProfilerConfig updated = profiler.GetConfiguration();
    EXPECT_EQ(updated.samplingIntervalMs, 100u);
    EXPECT_EQ(updated.historySize, 3u);
    EXPECT_FALSE(updated.trackPerProcess);

    EXPECT_TRUE(profiler.RefreshNow());

    EXPECT_TRUE(profiler.StartMonitoring());
    EXPECT_TRUE(profiler.IsMonitoring());
    EXPECT_TRUE(profiler.StartMonitoring());
    EXPECT_TRUE(profiler.IsMonitoring());

    profiler.StopMonitoring();
    EXPECT_FALSE(profiler.IsMonitoring());
}

TEST_F(MemoryProfilerTest, ShutdownLeavesLastConfigAndSystemSnapshotAvailable) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = false;
    config.samplingIntervalMs = 500;
    config.historySize = 7;
    config.minSamplesForLeakDetection = 3;
    ASSERT_TRUE(profiler.Initialize(config));
    ASSERT_TRUE(profiler.RefreshNow());

    const SSP::SystemMemoryStats beforeShutdown = profiler.GetSystemStats();
    EXPECT_GT(beforeShutdown.totalPhysical, 0u);

    profiler.Shutdown();

    const SSP::MemoryProfilerConfig retainedConfig = profiler.GetConfiguration();
    EXPECT_FALSE(retainedConfig.enabled);
    EXPECT_FALSE(retainedConfig.trackPerProcess);
    EXPECT_EQ(retainedConfig.samplingIntervalMs, 500u);
    EXPECT_EQ(retainedConfig.historySize, 7u);

    const SSP::SystemMemoryStats afterShutdown = profiler.GetSystemStats();
    EXPECT_EQ(afterShutdown.totalPhysical, beforeShutdown.totalPhysical);
    EXPECT_EQ(afterShutdown.availablePhysical, beforeShutdown.availablePhysical);
}

TEST_F(MemoryProfilerTest, AccessorsAndRefreshReturnSafeAndPlausibleData) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = false;
    ASSERT_TRUE(profiler.Initialize(config));

    EXPECT_TRUE(profiler.RefreshNow());

    const SSP::SystemMemoryStats stats = profiler.GetSystemStats();
    EXPECT_GT(stats.totalPhysical, 0u);
    EXPECT_LE(stats.availablePhysical, stats.totalPhysical);

    EXPECT_FALSE(profiler.GetProcessInfo(0xFFFFFFFFu).has_value());
    EXPECT_TRUE(profiler.GetTopConsumers(0).empty());
    EXPECT_TRUE(profiler.GetTopConsumers(10).empty());

    const SSP::ProcessMemoryInfo self = profiler.GetSelfMemoryUsage();
    EXPECT_EQ(self.pid, ::GetCurrentProcessId());
    EXPECT_FALSE(self.name.empty());
    EXPECT_GT(self.workingSetSize, 0u);
    EXPECT_GE(self.percentOfSystemMemory, 0.0);
}

TEST_F(MemoryProfilerTest, ProcessTrackingRetainsSelfUnderTightCapsAndShutdownClearsCache) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = true;
    config.maxTrackedProcesses = 1;
    config.historySize = 3;
    config.minSamplesForLeakDetection = 3;
    ASSERT_TRUE(profiler.Initialize(config));

    ASSERT_TRUE(profiler.RefreshNow());

    const uint32_t selfPid = ::GetCurrentProcessId();
    const auto selfInfo = profiler.GetProcessInfo(selfPid);
    ASSERT_TRUE(selfInfo.has_value());
    EXPECT_EQ(selfInfo->pid, selfPid);
    EXPECT_FALSE(selfInfo->name.empty());

    const auto topPrivate = profiler.GetTopConsumers(10, true);
    ASSERT_EQ(topPrivate.size(), 1u);
    EXPECT_EQ(topPrivate.front().pid, selfPid);

    profiler.Shutdown();
    EXPECT_FALSE(profiler.GetProcessInfo(selfPid).has_value());
    EXPECT_TRUE(profiler.GetTopConsumers(10).empty());
}

TEST_F(MemoryProfilerTest, DisablingProcessTrackingPurgesCachedProcessSnapshotsOnRefresh) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = true;
    config.maxTrackedProcesses = 8;
    config.historySize = 5;
    config.minSamplesForLeakDetection = 3;
    ASSERT_TRUE(profiler.Initialize(config));
    ASSERT_TRUE(profiler.RefreshNow());

    const uint32_t selfPid = ::GetCurrentProcessId();
    ASSERT_TRUE(profiler.GetProcessInfo(selfPid).has_value());
    EXPECT_FALSE(profiler.GetTopConsumers(4).empty());

    config.trackPerProcess = false;
    ASSERT_TRUE(profiler.UpdateConfiguration(config));
    ASSERT_TRUE(profiler.RefreshNow());

    EXPECT_FALSE(profiler.GetProcessInfo(selfPid).has_value());
    EXPECT_TRUE(profiler.GetTopConsumers(4).empty());

    const SSP::ProcessMemoryInfo self = profiler.GetSelfMemoryUsage();
    EXPECT_EQ(self.pid, selfPid);
    EXPECT_FALSE(self.name.empty());
}

TEST_F(MemoryProfilerTest, SelfTestPassesWithProcessTrackingEnabled) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = true;
    ASSERT_TRUE(profiler.Initialize(config));
    EXPECT_TRUE(profiler.SelfTest());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
