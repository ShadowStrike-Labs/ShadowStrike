/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for DiskMonitor.cpp.
 *
 * Coverage focus:
 * - configuration validation and update semantics
 * - JSON serialization for published disk telemetry and alerts
 * - singleton default-accessor behavior without live samples
 * - callback registration safety and explicit self-test surface
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "../../../src/Shared_modules/Performance/DiskMonitor.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

class DiskMonitorTest : public ::testing::Test {
protected:
    DiskMonitor& monitor = DiskMonitor::Instance();

    void SetUp() override {
        monitor.UnregisterCallbacks();
        monitor.Shutdown();
    }

    void TearDown() override {
        monitor.UnregisterCallbacks();
        monitor.Shutdown();
    }
};

TEST_F(DiskMonitorTest, ConfigValidationRejectsOutOfRangeValues) {
    SSP::DiskMonitorConfig config;
    EXPECT_TRUE(config.IsValid());

    config.pollingIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());
    config.pollingIntervalMs = SSP::DiskConstants::DEFAULT_POLLING_INTERVAL_MS;

    config.ransomwareSustainedWindowSec = 1;
    EXPECT_FALSE(config.IsValid());
    config.ransomwareSustainedWindowSec = SSP::DiskConstants::DEFAULT_SUSTAINED_WINDOW_SEC;

    config.ransomwareWriteThresholdBps = 0;
    EXPECT_FALSE(config.IsValid());
    config.ransomwareWriteThresholdBps = 32ULL * 1024ULL * 1024ULL;

    config.maxTrackedProcesses = 0;
    EXPECT_FALSE(config.IsValid());
    config.maxTrackedProcesses = 4096;

    config.lowSpaceThresholdPercent = 101.0;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(DiskMonitorTest, SerializationProducesExpectedJsonShapes) {
    const SSP::ProcessDiskUsage usage{
        77,
        L"disk\"writer\nproc",
        1024.5,
        2048.25,
        3.0,
        4.0,
        5.0,
        4096,
        8192,
        true,
        false
    };
    const std::string usageJson = usage.ToJson();
    EXPECT_NE(usageJson.find("\"processId\":77"), std::string::npos);
    EXPECT_NE(usageJson.find("disk\\\"writer\\nproc"), std::string::npos);
    EXPECT_NE(usageJson.find("\"highWriteRate\":true"), std::string::npos);
    EXPECT_NE(usageJson.find("\"highFileEnumeration\":false"), std::string::npos);

    SSP::RansomwareAlert ransomwareAlert;
    ransomwareAlert.processId = 91;
    ransomwareAlert.processName = L"locker";
    ransomwareAlert.sustainedWriteBytesPerSec = 9.5;
    ransomwareAlert.sustainedDurationSamples = 7;
    ransomwareAlert.totalBytesWrittenDuringWindow = 123456;
    const std::string ransomwareJson = ransomwareAlert.ToJson();
    EXPECT_NE(ransomwareJson.find("\"processId\":91"), std::string::npos);
    EXPECT_NE(ransomwareJson.find("\"sustainedDurationSamples\":7"), std::string::npos);

    SSP::FileEnumAlert fileEnumAlert;
    fileEnumAlert.processId = 13;
    fileEnumAlert.processName = L"crawler";
    fileEnumAlert.sustainedOtherOpsPerSec = 88.0;
    fileEnumAlert.sustainedDurationSamples = 4;
    const std::string fileEnumJson = fileEnumAlert.ToJson();
    EXPECT_NE(fileEnumJson.find("\"processId\":13"), std::string::npos);
    EXPECT_NE(fileEnumJson.find("\"sustainedDurationSamples\":4"), std::string::npos);

    const SSP::DriveInfo driveInfo{
        L"C:\\",
        L"System",
        L"NTFS",
        1000,
        250,
        200,
        75.0,
        -12.5,
        true
    };
    const std::string driveJson = driveInfo.ToJson();
    EXPECT_NE(driveJson.find("\"mountPoint\":\"C:\\\\\""), std::string::npos);
    EXPECT_NE(driveJson.find("\"isSystemDrive\":true"), std::string::npos);

    SSP::DiskGlobalStats globalStats;
    globalStats.totalReadBytesPerSec = 1.5;
    globalStats.totalWriteBytesPerSec = 2.5;
    globalStats.totalReadOpsPerSec = 3.5;
    globalStats.totalWriteOpsPerSec = 4.5;
    globalStats.activeProcesses = 11;
    const std::string globalJson = globalStats.ToJson();
    EXPECT_NE(globalJson.find("\"activeProcesses\":11"), std::string::npos);

    const SSP::DiskMonitorModuleStats moduleStats{1, 2, 3, 4, 5, 6, 7.5};
    const std::string moduleJson = moduleStats.ToJson();
    EXPECT_NE(moduleJson.find("\"cyclesCompleted\":1"), std::string::npos);
    EXPECT_NE(moduleJson.find("\"uptimeSeconds\":7.5"), std::string::npos);
}

TEST_F(DiskMonitorTest, LifecycleAndConfigurationUpdatesRespectValidation) {
    SSP::DiskMonitorConfig invalidConfig;
    invalidConfig.maxTrackedProcesses = 0;
    EXPECT_FALSE(monitor.Initialize(invalidConfig));
    EXPECT_FALSE(monitor.IsInitialized());

    SSP::DiskMonitorConfig validConfig;
    validConfig.enabled = false;
    validConfig.pollingIntervalMs = 750;
    validConfig.enableProcessMonitoring = false;
    validConfig.enableDriveSpaceMonitoring = false;
    validConfig.maxTrackedProcesses = 512;
    ASSERT_TRUE(monitor.Initialize(validConfig));
    EXPECT_TRUE(monitor.IsInitialized());

    const SSP::DiskMonitorConfig initialized = monitor.GetConfig();
    EXPECT_EQ(initialized.pollingIntervalMs, 750u);
    EXPECT_FALSE(initialized.enableProcessMonitoring);
    EXPECT_FALSE(initialized.enableDriveSpaceMonitoring);

    SSP::DiskMonitorConfig invalidUpdate = validConfig;
    invalidUpdate.lowSpaceThresholdPercent = -1.0;
    monitor.UpdateConfig(invalidUpdate);
    EXPECT_EQ(monitor.GetConfig().pollingIntervalMs, validConfig.pollingIntervalMs);

    SSP::DiskMonitorConfig validUpdate = validConfig;
    validUpdate.pollingIntervalMs = 1200;
    validUpdate.enableProcessMonitoring = true;
    monitor.UpdateConfig(validUpdate);

    const SSP::DiskMonitorConfig updated = monitor.GetConfig();
    EXPECT_EQ(updated.pollingIntervalMs, 1200u);
    EXPECT_TRUE(updated.enableProcessMonitoring);
}

TEST_F(DiskMonitorTest, AccessorsReturnSafeDefaultsWithoutPublishedSamples) {
    SSP::DiskMonitorConfig config;
    config.enabled = false;
    ASSERT_TRUE(monitor.Initialize(config));

    EXPECT_FALSE(monitor.GetProcessUsage(0xFFFFFFFFu).has_value());
    EXPECT_TRUE(monitor.GetTopConsumers(5).empty());
    EXPECT_TRUE(monitor.GetDriveInfo().empty());
    EXPECT_FALSE(monitor.GetSelfIoUsage().has_value());

    const SSP::DiskGlobalStats globalStats = monitor.GetGlobalStats();
    EXPECT_DOUBLE_EQ(globalStats.totalReadBytesPerSec, 0.0);
    EXPECT_DOUBLE_EQ(globalStats.totalWriteBytesPerSec, 0.0);
    EXPECT_EQ(globalStats.activeProcesses, 0u);

    const SSP::DiskMonitorModuleStats moduleStats = monitor.GetModuleStats();
    EXPECT_EQ(moduleStats.cyclesCompleted, 0u);
    EXPECT_EQ(moduleStats.alertsTriggered, 0u);
    EXPECT_GE(moduleStats.uptimeSeconds, 0.0);
    EXPECT_EQ(DiskMonitor::GetVersionString(), "4.0.0");
}

TEST_F(DiskMonitorTest, CallbackRegistrationAndResetAreSafeForNullAndLiveHandlers) {
    monitor.RegisterHighIoCallback({});
    monitor.RegisterLowSpaceCallback({});
    monitor.RegisterRansomwareCallback({});
    monitor.RegisterFileEnumCallback({});

    monitor.RegisterHighIoCallback([](const SSP::ProcessDiskUsage&) {});
    monitor.RegisterLowSpaceCallback([](const SSP::DriveInfo&) {});
    monitor.RegisterRansomwareCallback([](const SSP::RansomwareAlert&) {});
    monitor.RegisterFileEnumCallback([](const SSP::FileEnumAlert&) {});

    monitor.UnregisterCallbacks();
    monitor.UnregisterCallbacks();
}

TEST_F(DiskMonitorTest, SelfTestPassesOnSupportedWindowsHost) {
    EXPECT_TRUE(monitor.SelfTest());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
