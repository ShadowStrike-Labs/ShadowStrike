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
 * @file SystemInfo_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::SystemInfo.
 *
 * Coverage focus:
 * - statistics reset, enum-name helpers, and versioning contracts
 * - singleton lifecycle, diagnostics, and built-in self-test behavior
 * - export path validation, statistics accounting, and readable snapshot generation
 */

#include "pch.h"

#include "CoreSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/System/SystemInfo.hpp"

namespace {

using namespace ShadowStrike::Core::System;
using namespace ShadowStrike::Tests::CoreSystem;
using ::testing::HasSubstr;

class SystemInfoTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        auto& info = SystemInfo::Instance();
        info.Shutdown();
        info.ResetStatistics();
    }

    void TearDown() override {
        SystemInfo::Instance().Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(SystemInfoValueTests, StatisticsUtilitiesAndVersionRemainStable) {
    SystemInfoStatistics stats;
    stats.queriesExecuted.store(4, std::memory_order_relaxed);
    stats.vmDetections.store(1, std::memory_order_relaxed);
    stats.sandboxDetections.store(1, std::memory_order_relaxed);
    stats.debuggerDetections.store(1, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.queriesExecuted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.vmDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.sandboxDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.debuggerDetections.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(GetVirtualizationTypeName(VirtualizationType::HyperV), "Hyper-V");
    EXPECT_EQ(GetSandboxTypeName(SandboxType::WindowsSandbox), "Windows Sandbox");
    EXPECT_EQ(GetBootModeName(BootMode::SafeModeWithNetworking), "Safe Mode with Networking");
    EXPECT_EQ(GetProcessorArchitectureName(ProcessorArchitecture::X64), "x64 (64-bit)");
    EXPECT_EQ(GetPowerStateName(PowerState::BatteryLow), "Battery Low");
    EXPECT_EQ(GetSandboxTypeName(static_cast<SandboxType>(0xFF)), "Unknown");
    EXPECT_EQ(SystemInfo::GetVersionString(), "3.1.0");
}

TEST_F(SystemInfoTest, InitializeDiagnosticsAndSelfTestExposeStableContracts) {
    auto& info = SystemInfo::Instance();
    ASSERT_TRUE(info.Initialize());
    EXPECT_TRUE(info.Initialize());

    EXPECT_TRUE(SystemInfo::HasInstance());
    EXPECT_TRUE(info.IsInitialized());

    const auto diagnostics = info.RunDiagnostics();
    ASSERT_FALSE(diagnostics.empty());
    EXPECT_THAT(diagnostics.front(), HasSubstr(L"SystemInfo Diagnostics"));

    EXPECT_TRUE(info.SelfTest());
}

TEST_F(SystemInfoTest, RefreshAndDiagnosticsOnlyAdvanceQueryCountersWhenInitialized) {
    auto& info = SystemInfo::Instance();

    info.Refresh();
    EXPECT_EQ(info.GetStatistics().queriesExecuted.load(std::memory_order_relaxed), 0u);

    ASSERT_TRUE(info.Initialize());
    info.Refresh();
    EXPECT_EQ(info.GetStatistics().queriesExecuted.load(std::memory_order_relaxed), 1u);

    const auto diagnostics = info.RunDiagnostics();
    ASSERT_FALSE(diagnostics.empty());
    EXPECT_THAT(diagnostics[2], HasSubstr(L"Initialized: Yes"));
    EXPECT_EQ(info.GetStatistics().queriesExecuted.load(std::memory_order_relaxed), 4u);
}

TEST_F(SystemInfoTest, ExportSnapshotRejectsTraversalAndWritesReadableReport) {
    auto& info = SystemInfo::Instance();
    ASSERT_TRUE(info.Initialize());

    EXPECT_FALSE(info.ExportSnapshot(L""));

    const auto blockedPath = MakePath(L"..\\blocked-snapshot.txt");
    EXPECT_FALSE(info.ExportSnapshot(blockedPath.wstring()));

    const auto dottedNamePath = MakePath(L"snapshot..txt");
    EXPECT_FALSE(info.ExportSnapshot(dottedNamePath.wstring()));

    EXPECT_FALSE(info.ExportSnapshot(std::wstring(MAX_PATH + 1, L'a')));

    const auto missingParentPath = testRoot_ / L"missing-parent" / L"snapshot.txt";
    EXPECT_FALSE(info.ExportSnapshot(missingParentPath.wstring()));

    const auto outputPath = MakePath(L"system-snapshot.txt");
    ASSERT_TRUE(info.ExportSnapshot(outputPath.wstring()));
    EXPECT_THAT(ReadTextFile(outputPath), HasSubstr("SystemInfo Snapshot"));
}

}  // namespace
