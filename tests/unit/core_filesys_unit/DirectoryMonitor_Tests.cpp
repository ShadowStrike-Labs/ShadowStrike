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
 * @file DirectoryMonitor_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::FileSystem::DirectoryMonitor.
 *
 * Coverage focus:
 * - monitor/config/statistics value semantics and JSON helpers
 * - utility name mapping functions
 * - initialization guards for invalid and disabled configurations
 * - monitor lifecycle on real temporary directories
 * - configuration round-tripping and built-in self-test behavior
 */

#include "pch.h"

#include "CoreFileSystem_TestUtils.hpp"
#include "../../../src/PhantomCore/Core/FileSystem/DirectoryMonitor.hpp"

namespace {

using namespace ShadowStrike::Core::FileSystem;
using namespace ShadowStrike::Tests::CoreFileSystem;
using ::testing::HasSubstr;

class DirectoryMonitorTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        auto& monitor = DirectoryMonitor::Instance();
        monitor.Shutdown();
        monitor.ResetStatistics();
    }

    void TearDown() override {
        auto& monitor = DirectoryMonitor::Instance();
        monitor.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(DirectoryMonitorValueTests, MonitoredPathCopyAndMovePreserveObservedState) {
    MonitoredPath original;
    original.monitorId = 42;
    original.path = L"C:\\Temp";
    original.category = PathCategory::Temporary;
    original.recursive = false;
    original.isActive = true;
    original.eventsReceived.store(7, std::memory_order_relaxed);

    MonitoredPath copy = original;
    MonitoredPath moved = std::move(copy);

    EXPECT_EQ(moved.monitorId, 42u);
    EXPECT_EQ(moved.path, L"C:\\Temp");
    EXPECT_EQ(moved.category, PathCategory::Temporary);
    EXPECT_FALSE(moved.recursive);
    EXPECT_TRUE(moved.isActive);
    EXPECT_EQ(moved.eventsReceived.load(std::memory_order_relaxed), 7u);
}

TEST(DirectoryMonitorValueTests, ConfigPresetsAndValidationReflectOperationalModes) {
    const auto defaults = DirectoryMonitorConfig::CreateDefault();
    const auto highSecurity = DirectoryMonitorConfig::CreateHighSecurity();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_FALSE(defaults.monitorNetworkShares);
    EXPECT_TRUE(highSecurity.monitorNetworkShares);
    EXPECT_FALSE(highSecurity.enableRateLimiting);
    EXPECT_EQ(highSecurity.maxEventsPerWindow, UINT32_MAX);
    EXPECT_TRUE(defaults.IsValid());

    DirectoryMonitorConfig invalid = defaults;
    invalid.maxConcurrentMonitors = 0;
    EXPECT_FALSE(invalid.IsValid());

    invalid = defaults;
    invalid.enableRateLimiting = false;
    invalid.rateLimitWindowSec = 0;
    EXPECT_TRUE(invalid.IsValid());

    invalid = defaults;
    invalid.enabled = false;
    invalid.maxConcurrentMonitors = 0;
    invalid.eventQueueCapacity = 0;
    EXPECT_TRUE(invalid.IsValid());

    EXPECT_THAT(defaults.ToJson(), HasSubstr("\"enabled\":true"));
}

TEST(DirectoryMonitorValueTests, StatisticsAndJsonHelpersExposeStableDiagnostics) {
    DirectoryMonitorStatistics stats;
    EXPECT_DOUBLE_EQ(stats.GetAverageProcessingTimeMs(), 0.0);
    stats.totalEvents.store(4, std::memory_order_relaxed);
    stats.totalProcessingTimeUs.store(8000, std::memory_order_relaxed);
    EXPECT_DOUBLE_EQ(stats.GetAverageProcessingTimeMs(), 2.0);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"totalEvents\":4"));

    stats.Reset();
    EXPECT_EQ(stats.totalEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalProcessingTimeUs.load(std::memory_order_relaxed), 0u);

    MonitoredPath path;
    path.monitorId = 7;
    path.path = L"C:\\Temp";
    path.category = PathCategory::Temporary;
    path.eventsReceived.store(5, std::memory_order_relaxed);
    EXPECT_THAT(path.ToJson(), HasSubstr("\"monitorId\":7"));

    DirectoryEvent event;
    event.eventId = 99;
    event.monitorId = 7;
    event.path = L"C:\\Temp";
    event.filename = L"sample.txt";
    event.action = FileSystemAction::FileModified;
    event.category = PathCategory::Temporary;
    EXPECT_THAT(event.ToJson(), HasSubstr("\"filename\":\"sample.txt\""));

    EXPECT_EQ(GetPathCategoryName(PathCategory::CloudSync), "CloudSync");
    EXPECT_EQ(GetFileSystemActionName(FileSystemAction::DirectoryRenamed), "DirectoryRenamed");
    EXPECT_EQ(GetMonitorStatusName(DirectoryMonitorStatus::Paused), "Paused");
}

TEST_F(DirectoryMonitorTest, InitializeRejectsInvalidAndDisabledConfigurations) {
    auto& monitor = DirectoryMonitor::Instance();

    DirectoryMonitorConfig invalid = DirectoryMonitorConfig::CreateDefault();
    invalid.maxConcurrentMonitors = 0;
    EXPECT_FALSE(monitor.Initialize(invalid));
    EXPECT_FALSE(monitor.IsInitialized());

    monitor.Shutdown();

    DirectoryMonitorConfig disabled = DirectoryMonitorConfig::CreateDefault();
    disabled.enabled = false;
    EXPECT_FALSE(monitor.Initialize(disabled));
    EXPECT_FALSE(monitor.IsInitialized());
}

TEST_F(DirectoryMonitorTest, InitializeAddMonitorDetectDuplicateAndRemoveMonitorWorks) {
    auto& monitor = DirectoryMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(DirectoryMonitorConfig::CreateDefault()));

    const auto firstId = monitor.AddMonitor(testRoot_.wstring(), PathCategory::Temporary, true);
    ASSERT_NE(firstId, 0u);

    const auto duplicateId = monitor.AddMonitor(testRoot_.wstring(), PathCategory::Temporary, true);
    EXPECT_EQ(duplicateId, firstId);
    EXPECT_TRUE(monitor.IsMonitored(testRoot_.wstring()));
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 1u);

    const auto monitorInfo = monitor.GetMonitorById(firstId);
    ASSERT_TRUE(monitorInfo.has_value());
    EXPECT_TRUE(monitorInfo->isActive);
    EXPECT_TRUE(monitorInfo->recursive);
    EXPECT_EQ(monitorInfo->category, PathCategory::Temporary);

    monitor.PauseMonitor(firstId);
    monitor.ResumeMonitor(firstId);
    monitor.RemoveMonitor(firstId);

    EXPECT_FALSE(monitor.IsMonitored(testRoot_.wstring()));
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 0u);
}

TEST_F(DirectoryMonitorTest, ConfigurationRoundTripAndRemoveAllMonitorsStayConsistent) {
    auto& monitor = DirectoryMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(DirectoryMonitorConfig::CreateDefault()));

    auto customConfig = monitor.GetConfiguration();
    customConfig.excludedPaths.push_back(testRoot_.wstring());
    customConfig.monitorNetworkShares = true;
    monitor.SetConfiguration(customConfig);

    const auto reloaded = monitor.GetConfiguration();
    EXPECT_TRUE(reloaded.monitorNetworkShares);
    EXPECT_EQ(reloaded.excludedPaths.size(), 1u);
    EXPECT_EQ(reloaded.excludedPaths.front(), testRoot_.wstring());

    const auto subdirOne = CreateDirectory(L"watched-one");
    const auto subdirTwo = CreateDirectory(L"watched-two");

    ASSERT_NE(monitor.AddMonitor(subdirOne.wstring(), PathCategory::Custom, false), 0u);
    ASSERT_NE(monitor.AddMonitor(subdirTwo.wstring(), PathCategory::Custom, false), 0u);
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 2u);

    monitor.RemoveAllMonitors();
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 0u);
}

TEST_F(DirectoryMonitorTest, AddMonitorRejectsEmptyMissingAndExcludedPaths) {
    auto& monitor = DirectoryMonitor::Instance();

    auto config = DirectoryMonitorConfig::CreateDefault();
    config.excludedPaths.push_back(testRoot_.wstring());
    ASSERT_TRUE(monitor.Initialize(config));

    EXPECT_EQ(monitor.AddMonitor(L"", PathCategory::Custom, false), 0u);
    EXPECT_EQ(monitor.AddMonitor(MakePath(L"missing").wstring(), PathCategory::Custom, false), 0u);
    EXPECT_EQ(monitor.AddMonitor(testRoot_.wstring(), PathCategory::Temporary, false), 0u);
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 0u);
}

TEST_F(DirectoryMonitorTest, AddMonitorCanonicalizesEquivalentPathsAndHonorsMaxMonitorLimit) {
    auto& monitor = DirectoryMonitor::Instance();

    auto config = DirectoryMonitorConfig::CreateDefault();
    config.maxConcurrentMonitors = 1;
    ASSERT_TRUE(monitor.Initialize(config));

    const auto firstPath = CreateDirectory(L"watched-one");
    const auto secondPath = CreateDirectory(L"watched-two");
    const auto canonicalVariant = (firstPath / L"." / L"..") / firstPath.filename();

    const auto firstId = monitor.AddMonitor(firstPath.wstring(), PathCategory::Custom, false);
    ASSERT_NE(firstId, 0u);

    const auto duplicateId = monitor.AddMonitor(canonicalVariant.wstring(), PathCategory::Custom, false);
    EXPECT_EQ(duplicateId, firstId);

    EXPECT_EQ(monitor.AddMonitor(secondPath.wstring(), PathCategory::Custom, false), 0u);
    EXPECT_EQ(monitor.GetActiveMonitorCount(), 1u);
}

TEST_F(DirectoryMonitorTest, PauseResumeAndStatusCallbacksTrackMonitorLifecycle) {
    auto& monitor = DirectoryMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(DirectoryMonitorConfig::CreateDefault()));

    std::vector<std::pair<uint32_t, bool>> statusTransitions;
    monitor.SetMonitorStatusCallback([&](uint32_t monitorId, bool active) {
        statusTransitions.emplace_back(monitorId, active);
    });

    const auto monitorId = monitor.AddMonitor(testRoot_.wstring(), PathCategory::Temporary, false);
    ASSERT_NE(monitorId, 0u);

    const auto monitoredPaths = monitor.GetMonitoredPaths();
    ASSERT_EQ(monitoredPaths.size(), 1u);
    EXPECT_EQ(monitoredPaths.front().monitorId, monitorId);

    monitor.PauseAll();
    EXPECT_EQ(monitor.GetStatus(), DirectoryMonitorStatus::Paused);

    monitor.ResumeAll();
    EXPECT_EQ(monitor.GetStatus(), DirectoryMonitorStatus::Running);

    monitor.RemoveMonitor(monitorId);
    monitor.UnregisterCallbacks();

    ASSERT_EQ(statusTransitions.size(), 2u);
    EXPECT_EQ(statusTransitions[0], std::make_pair(monitorId, true));
    EXPECT_EQ(statusTransitions[1], std::make_pair(monitorId, false));
}

TEST_F(DirectoryMonitorTest, SelfTestPassesAfterInitializationAndVersionStringIsStable) {
    auto& monitor = DirectoryMonitor::Instance();
    ASSERT_TRUE(monitor.Initialize(DirectoryMonitorConfig::CreateDefault()));

    EXPECT_TRUE(monitor.SelfTest());
    EXPECT_EQ(DirectoryMonitor::GetVersionString(), "3.0.0");
}

}  // namespace
