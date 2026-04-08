/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for MemoryProfiler.cpp.
 *
 * Coverage focus:
 * - configuration boundary validation
 * - JSON serialization of memory snapshots
 * - singleton lifecycle/configuration guard paths
 * - refresh, self-usage, and explicit self-test behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <Windows.h>

#include <string>

#include "../../../src/Shared_modules/Performance/dev/MemoryProfiler.hpp"

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

    SSP::MemoryProfilerConfig validUpdate = validConfig;
    validUpdate.trackPerProcess = true;
    validUpdate.maxTrackedProcesses = 1024;
    EXPECT_TRUE(profiler.UpdateConfiguration(validUpdate));

    const SSP::MemoryProfilerConfig updated = profiler.GetConfiguration();
    EXPECT_TRUE(updated.trackPerProcess);
    EXPECT_EQ(updated.maxTrackedProcesses, 1024u);
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

TEST_F(MemoryProfilerTest, SelfTestPassesWithProcessTrackingEnabled) {
    SSP::MemoryProfilerConfig config;
    config.enabled = false;
    config.trackPerProcess = true;
    ASSERT_TRUE(profiler.Initialize(config));
    EXPECT_TRUE(profiler.SelfTest());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
