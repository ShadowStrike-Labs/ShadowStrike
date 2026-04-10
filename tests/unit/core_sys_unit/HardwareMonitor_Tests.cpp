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
 * @file HardwareMonitor_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::HardwareMonitor.
 *
 * Coverage focus:
 * - configuration defaults, statistics reset, enum-name helpers, and versioning
 * - singleton lifecycle, configuration round-tripping, and permissive callback registration
 * - diagnostics and export surfaces that summarize current hardware state
 */

#include "pch.h"

#include "CoreSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/System/HardwareMonitor.hpp"

namespace {

using namespace ShadowStrike::Core::System;
using namespace ShadowStrike::Tests::CoreSystem;
using ::testing::HasSubstr;

class HardwareMonitorTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        auto& monitor = HardwareMonitor::Instance();
        monitor.Shutdown();
        monitor.ResetStatistics();
    }

    void TearDown() override {
        HardwareMonitor::Instance().Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(HardwareMonitorValueTests, ConfigStatisticsUtilitiesAndVersionRemainStable) {
    const auto defaults = HardwareMonitorConfig::CreateDefault();
    EXPECT_TRUE(defaults.monitorDisks);
    EXPECT_TRUE(defaults.monitorThermals);
    EXPECT_TRUE(defaults.monitorPower);
    EXPECT_TRUE(defaults.monitorDeviceChanges);
    EXPECT_EQ(defaults.pollingIntervalMs, 5000u);
    EXPECT_EQ(defaults.diskTempWarningCelsius, 50u);
    EXPECT_EQ(defaults.diskTempCriticalCelsius, 60u);
    EXPECT_EQ(defaults.cpuTempWarningCelsius, 80u);
    EXPECT_EQ(defaults.cpuTempCriticalCelsius, 95u);
    EXPECT_EQ(defaults.batteryLowPercent, 20u);
    EXPECT_EQ(defaults.batteryCriticalPercent, 10u);

    HardwareMonitorStatistics stats;
    stats.pollingCycles.store(2, std::memory_order_relaxed);
    stats.diskHealthChecks.store(3, std::memory_order_relaxed);
    stats.thermalWarnings.store(1, std::memory_order_relaxed);
    stats.powerStateChanges.store(1, std::memory_order_relaxed);
    stats.deviceChanges.store(4, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.pollingCycles.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.diskHealthChecks.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.thermalWarnings.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.powerStateChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.deviceChanges.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(GetDiskTypeName(DiskType::SSD_NVMe), "SSD (NVMe)");
    EXPECT_EQ(GetDiskHealthStatusName(DiskHealthStatus::Critical), "Critical");
    EXPECT_EQ(GetPowerSourceName(PowerSource::Battery), "Battery");
    EXPECT_EQ(GetBatteryStatusName(BatteryStatus::NotPresent), "Not Present");
    EXPECT_EQ(GetThermalStatusName(ThermalStatus::Warm), "Warm");
    EXPECT_EQ(GetDiskTypeName(static_cast<DiskType>(0xFF)), "Unknown");
    EXPECT_EQ(HardwareMonitor::GetVersionString(), "3.0.0");
}

TEST_F(HardwareMonitorTest, InitializeUpdateConfigDiagnosticsAndCallbackRegistrationStayConsistent) {
    auto& monitor = HardwareMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(HardwareMonitorConfig::CreateDefault()));

    EXPECT_TRUE(HardwareMonitor::HasInstance());
    EXPECT_TRUE(monitor.IsInitialized());

    auto updated = monitor.GetConfig();
    updated.monitorDeviceChanges = false;
    updated.cpuTempWarningCelsius = 77;
    updated.batteryCriticalPercent = 5;
    ASSERT_TRUE(monitor.UpdateConfig(updated));

    const auto reloaded = monitor.GetConfig();
    EXPECT_FALSE(reloaded.monitorDeviceChanges);
    EXPECT_EQ(reloaded.cpuTempWarningCelsius, 77u);
    EXPECT_EQ(reloaded.batteryCriticalPercent, 5u);

    const auto diskId = monitor.RegisterDiskHealthCallback([](const DiskHealthInfo&) {});
    const auto thermalId = monitor.RegisterThermalAlertCallback([](ThermalStatus, uint32_t) {});
    const auto powerId = monitor.RegisterPowerChangeCallback([](const PowerInfo&) {});
    const auto hardwareId = monitor.RegisterHardwareChangeCallback([](const HardwareChangeEvent&) {});

    EXPECT_NE(diskId, 0u);
    EXPECT_NE(thermalId, 0u);
    EXPECT_NE(powerId, 0u);
    EXPECT_NE(hardwareId, 0u);

    monitor.UnregisterDiskHealthCallback(diskId);
    monitor.UnregisterThermalAlertCallback(thermalId);
    monitor.UnregisterPowerChangeCallback(powerId);
    monitor.UnregisterHardwareChangeCallback(hardwareId);

    const auto diagnostics = monitor.RunDiagnostics();
    ASSERT_FALSE(diagnostics.empty());
    EXPECT_THAT(diagnostics.front(), HasSubstr(L"HardwareMonitor Diagnostics"));
}

TEST_F(HardwareMonitorTest, PreInitConfigRefreshAndNullCallbackRegistrationFollowImplementation) {
    auto& monitor = HardwareMonitor::Instance();

    auto updated = HardwareMonitorConfig::CreateDefault();
    updated.monitorDisks = false;
    updated.cpuTempCriticalCelsius = 99;
    ASSERT_TRUE(monitor.UpdateConfig(updated));

    const auto reloaded = monitor.GetConfig();
    EXPECT_FALSE(reloaded.monitorDisks);
    EXPECT_EQ(reloaded.cpuTempCriticalCelsius, 99u);

    monitor.Refresh();
    EXPECT_EQ(monitor.GetStatistics().pollingCycles.load(std::memory_order_relaxed), 0u);

    const auto diskId = monitor.RegisterDiskHealthCallback(DiskHealthCallback{});
    const auto thermalId = monitor.RegisterThermalAlertCallback(ThermalAlertCallback{});
    const auto powerId = monitor.RegisterPowerChangeCallback(PowerChangeCallback{});
    const auto hardwareId = monitor.RegisterHardwareChangeCallback(HardwareChangeCallback{});

    EXPECT_NE(diskId, 0u);
    EXPECT_NE(thermalId, 0u);
    EXPECT_NE(powerId, 0u);
    EXPECT_NE(hardwareId, 0u);
    EXPECT_NE(diskId, thermalId);
    EXPECT_NE(thermalId, powerId);
    EXPECT_NE(powerId, hardwareId);

    monitor.UnregisterDiskHealthCallback(diskId);
    monitor.UnregisterDiskHealthCallback(diskId);
    monitor.UnregisterThermalAlertCallback(thermalId);
    monitor.UnregisterThermalAlertCallback(thermalId);
    monitor.UnregisterPowerChangeCallback(powerId);
    monitor.UnregisterPowerChangeCallback(powerId);
    monitor.UnregisterHardwareChangeCallback(hardwareId);
    monitor.UnregisterHardwareChangeCallback(hardwareId);
}

TEST_F(HardwareMonitorTest, ExportReportWritesReadableSummary) {
    auto& monitor = HardwareMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(HardwareMonitorConfig::CreateDefault()));

    const auto reportPath = MakePath(L"hardware-report.txt");
    ASSERT_TRUE(monitor.ExportReport(reportPath.wstring()));
    EXPECT_THAT(ReadTextFile(reportPath), HasSubstr("HardwareMonitor Report"));
}

TEST_F(HardwareMonitorTest, ExportReportStillSucceedsWithoutInitialization) {
    auto& monitor = HardwareMonitor::Instance();

    const auto reportPath = MakePath(L"hardware-report-preinit.txt");
    ASSERT_TRUE(monitor.ExportReport(reportPath.wstring()));
    EXPECT_THAT(ReadTextFile(reportPath), HasSubstr("HardwareMonitor Report"));
}

TEST_F(HardwareMonitorTest, PreInitQueriesAndInvalidCallbackIdsRemainSafe) {
    auto& monitor = HardwareMonitor::Instance();

    EXPECT_FALSE(monitor.HasDiskHealthIssues());
    EXPECT_FALSE(monitor.IsThrottling());
    EXPECT_FALSE(monitor.GetDiskHealth(L"\\\\.\\PHYSICALDRIVE999").has_value());
    EXPECT_TRUE(monitor.GetRecentChanges(0).empty());

    const auto powerInfo = monitor.GetPowerInfo();
    EXPECT_EQ(powerInfo.activePowerPlan, L"");
    EXPECT_FALSE(powerInfo.battery.hasBattery);

    EXPECT_NO_THROW({
        monitor.ClearChangeHistory();
        monitor.UnregisterDiskHealthCallback(9999);
        monitor.UnregisterThermalAlertCallback(9999);
        monitor.UnregisterPowerChangeCallback(9999);
        monitor.UnregisterHardwareChangeCallback(9999);
    });
}

}  // namespace
