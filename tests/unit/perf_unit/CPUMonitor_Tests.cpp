/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for CPUMonitor.cpp.
 *
 * Coverage focus:
 * - configuration boundary validation
 * - JSON serialization of published snapshots
 * - singleton guard behavior and safe default accessors
 * - callback registration and explicit self-test surface
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "../../../src/PhantomCore/Performance/CPUMonitor.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

class CPUMonitorTest : public ::testing::Test {
protected:
    CPUMonitor& monitor = CPUMonitor::Instance();

    void SetUp() override {
        monitor.StopMonitoring();
        monitor.Shutdown();
    }

    void TearDown() override {
        monitor.StopMonitoring();
        monitor.Shutdown();
    }
};

TEST_F(CPUMonitorTest, ConfigValidationRejectsOutOfRangeValues) {
    SSP::CPUMonitorConfig config;
    EXPECT_TRUE(config.IsValid());

    config.samplingIntervalMs = 100;
    EXPECT_TRUE(config.IsValid());
    config.samplingIntervalMs = 60000;
    EXPECT_TRUE(config.IsValid());
    config.samplingIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());
    config.samplingIntervalMs = 1000;

    config.highUsageThreshold = 1.0;
    EXPECT_TRUE(config.IsValid());
    config.highUsageThreshold = 100.0;
    EXPECT_TRUE(config.IsValid());
    config.highUsageThreshold = 0.5;
    EXPECT_FALSE(config.IsValid());
    config.highUsageThreshold = 75.0;

    config.cryptoMinerThresholdPercent = 1.0;
    EXPECT_TRUE(config.IsValid());
    config.cryptoMinerThresholdPercent = 100.0;
    EXPECT_TRUE(config.IsValid());
    config.cryptoMinerThresholdPercent = 101.0;
    EXPECT_FALSE(config.IsValid());
    config.cryptoMinerThresholdPercent = 80.0;

    config.selfUsageAlertThreshold = 0.1;
    EXPECT_TRUE(config.IsValid());
    config.selfUsageAlertThreshold = 100.0;
    EXPECT_TRUE(config.IsValid());
    config.selfUsageAlertThreshold = 0.0;
    EXPECT_FALSE(config.IsValid());
    config.selfUsageAlertThreshold = 5.0;

    config.maxTrackedProcesses = 65536;
    EXPECT_TRUE(config.IsValid());
    config.maxTrackedProcesses = 0;
    EXPECT_FALSE(config.IsValid());
    config.maxTrackedProcesses = 512;
    config.maxTrackedProcesses = 65537;
    EXPECT_FALSE(config.IsValid());
    config.maxTrackedProcesses = 512;

    config.historySize = 1;
    EXPECT_TRUE(config.IsValid());
    config.historySize = 3600;
    EXPECT_TRUE(config.IsValid());
    config.historySize = 3601;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(CPUMonitorTest, SnapshotSerializationEscapesNamesAndEmitsExpectedFields) {
    const SSP::ProcessCpuInfo processInfo{
        42,
        L"cpu\"watch\nproc",
        12.5,
        7.25,
        5.25,
        99
    };
    const std::string processJson = processInfo.ToJson();
    EXPECT_NE(processJson.find("\"pid\":42"), std::string::npos);
    EXPECT_NE(processJson.find("cpu\\\"watch\\nproc"), std::string::npos);
    EXPECT_NE(processJson.find("\"usage\":12.50"), std::string::npos);
    EXPECT_NE(processJson.find("\"user\":7.25"), std::string::npos);
    EXPECT_NE(processJson.find("\"kernel\":5.25"), std::string::npos);
    EXPECT_NE(processJson.find("\"uptimeSeconds\":99"), std::string::npos);

    const SSP::SystemCpuStats systemStats{
        87.5,
        32.25,
        55.25,
        12.5,
        0,
        0,
        133,
        4096
    };
    const std::string systemJson = systemStats.ToJson();
    EXPECT_NE(systemJson.find("\"total\":87.50"), std::string::npos);
    EXPECT_NE(systemJson.find("\"user\":32.25"), std::string::npos);
    EXPECT_NE(systemJson.find("\"kernel\":55.25"), std::string::npos);
    EXPECT_NE(systemJson.find("\"idle\":12.50"), std::string::npos);
    EXPECT_NE(systemJson.find("\"processes\":133"), std::string::npos);
    EXPECT_NE(systemJson.find("\"threads\":4096"), std::string::npos);
}

TEST_F(CPUMonitorTest, LifecycleAndConfigurationUpdatesRespectValidation) {
    SSP::CPUMonitorConfig invalidConfig;
    invalidConfig.historySize = 0;
    EXPECT_FALSE(monitor.Initialize(invalidConfig));
    EXPECT_FALSE(monitor.IsMonitoring());

    SSP::CPUMonitorConfig validConfig;
    validConfig.enabled = false;
    validConfig.samplingIntervalMs = 1500;
    validConfig.highUsageThreshold = 77.5;
    validConfig.cryptoMinerThresholdPercent = 66.0;
    validConfig.selfUsageAlertThreshold = 4.0;
    validConfig.historySize = 120;
    validConfig.maxTrackedProcesses = 2048;
    validConfig.trackPerProcess = false;
    ASSERT_TRUE(monitor.Initialize(validConfig));
    EXPECT_FALSE(monitor.IsMonitoring());

    const SSP::CPUMonitorConfig initialized = monitor.GetConfiguration();
    EXPECT_EQ(initialized.samplingIntervalMs, validConfig.samplingIntervalMs);
    EXPECT_DOUBLE_EQ(initialized.highUsageThreshold, validConfig.highUsageThreshold);
    EXPECT_FALSE(initialized.trackPerProcess);

    SSP::CPUMonitorConfig update = validConfig;
    update.samplingIntervalMs = 2000;
    update.highUsageThreshold = 65.0;
    update.historySize = 300;
    ASSERT_TRUE(monitor.UpdateConfiguration(update));

    const SSP::CPUMonitorConfig updated = monitor.GetConfiguration();
    EXPECT_EQ(updated.samplingIntervalMs, 2000u);
    EXPECT_DOUBLE_EQ(updated.highUsageThreshold, 65.0);
    EXPECT_EQ(updated.historySize, 300u);

    SSP::CPUMonitorConfig invalidUpdate = update;
    invalidUpdate.maxTrackedProcesses = 0;
    EXPECT_FALSE(monitor.UpdateConfiguration(invalidUpdate));

    const SSP::CPUMonitorConfig unchanged = monitor.GetConfiguration();
    EXPECT_EQ(unchanged.maxTrackedProcesses, update.maxTrackedProcesses);
    EXPECT_EQ(unchanged.historySize, update.historySize);
}

TEST_F(CPUMonitorTest, StartMonitoringRequiresInitializationAndStopIsIdempotent) {
    EXPECT_FALSE(monitor.StartMonitoring());
    EXPECT_FALSE(monitor.IsMonitoring());

    SSP::CPUMonitorConfig config;
    config.enabled = false;
    config.samplingIntervalMs = 250;
    ASSERT_TRUE(monitor.Initialize(config));

    EXPECT_TRUE(monitor.StartMonitoring());
    EXPECT_TRUE(monitor.IsMonitoring());
    EXPECT_TRUE(monitor.StartMonitoring());
    EXPECT_TRUE(monitor.IsMonitoring());

    monitor.StopMonitoring();
    EXPECT_FALSE(monitor.IsMonitoring());
    monitor.StopMonitoring();
    EXPECT_FALSE(monitor.IsMonitoring());
}

TEST_F(CPUMonitorTest, AccessorsReturnSafeDefaultsWithoutPublishedSamples) {
    EXPECT_TRUE(SSP::CPUMonitor::HasInstance());
    EXPECT_GT(SSP::CPUMonitor::GetProcessorCount(), 0u);
    EXPECT_EQ(SSP::CPUMonitor::GetVersionString(), "3.1.0");

    EXPECT_FALSE(monitor.GetProcessUsage(0xFFFFFFFFu).has_value());
    EXPECT_FALSE(monitor.GetProcessInfo(0xFFFFFFFFu).has_value());
    EXPECT_TRUE(monitor.GetTopConsumers(0).empty());
    EXPECT_TRUE(monitor.GetTopConsumers(32).empty());
    EXPECT_GE(monitor.GetSelfUsage(), 0.0);
    EXPECT_FALSE(monitor.IsSelfUsageExcessive());
    EXPECT_TRUE(monitor.IsSystemUnderLoad(0.0));
    EXPECT_FALSE(monitor.IsSystemUnderLoad(101.0));
}

TEST_F(CPUMonitorTest, CallbackRegistrationUsesStableNonZeroIdsAndRejectsNullHandlers) {
    const uint32_t callbackId = monitor.RegisterHighCpuCallback(
        [](uint32_t, const std::wstring&, double) {});
    const uint32_t secondCallbackId = monitor.RegisterHighCpuCallback(
        [](uint32_t, const std::wstring&, double) {});
    EXPECT_NE(callbackId, 0u);
    EXPECT_NE(secondCallbackId, 0u);
    EXPECT_NE(secondCallbackId, callbackId);
    EXPECT_EQ(monitor.RegisterHighCpuCallback({}), 0u);

    monitor.UnregisterHighCpuCallback(callbackId);
    monitor.UnregisterHighCpuCallback(secondCallbackId);
    monitor.UnregisterHighCpuCallback(callbackId);
    monitor.UnregisterHighCpuCallback(0);
}

TEST_F(CPUMonitorTest, SelfTestPassesOnSupportedWindowsHost) {
    EXPECT_TRUE(monitor.SelfTest());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
