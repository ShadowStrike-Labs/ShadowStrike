/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\FileSystemFilter deterministic contracts.
 *
 * Focus:
 *   - string helpers and configuration preset factories
 *   - exclusion matching semantics and callback registration
 *   - safe default-state/statistics exposure without driver connectivity
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/FileSystemFilter.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class FileSystemFilterTest : public ::testing::Test {
protected:
    FileSystemFilter& filter = FileSystemFilter::Instance();

    void SetUp() override {
        filter.Shutdown();
        filter.ClearExclusions();
        filter.ResetStats();
    }

    void TearDown() override {
        filter.ClearExclusions();
        filter.Shutdown();
    }
};

TEST_F(FileSystemFilterTest, StringHelpersAndPresetFactoriesRemainStable) {
    EXPECT_STREQ("Running", FilterStatusToString(FilterStatus::Running));
    EXPECT_STREQ("BlockAndQuarantine", ScanVerdictToString(ScanVerdict::BlockAndQuarantine));
    EXPECT_STREQ("NotifyFileRename", FilterMessageTypeToString(FilterMessageType::NotifyFileRename));
    EXPECT_STREQ("Execute", FileAccessTypeToString(FileAccessType::Execute));
    EXPECT_EQ(std::wstring(L".txt"), GetFileExtension(L"C:\\Temp\\sample.txt"));
    EXPECT_TRUE(GetFileExtension(L"C:\\Temp\\sample").empty());

    const auto defaults = FileSystemFilterConfig::CreateDefault();
    const auto performance = FileSystemFilterConfig::CreateHighPerformance();
    const auto paranoid = FileSystemFilterConfig::CreateParanoid();

    EXPECT_TRUE(defaults.scanOnOpen);
    EXPECT_TRUE(defaults.scanOnExecute);
    EXPECT_FALSE(defaults.scanOnWrite);
    EXPECT_TRUE(defaults.enableNotifications);

    EXPECT_FALSE(performance.scanOnWrite);
    EXPECT_FALSE(performance.enableNotifications);
    EXPECT_EQ(128ULL * 1024ULL * 1024ULL, performance.maxScanFileSize);
    EXPECT_EQ(500000u, performance.cacheCapacity);

    EXPECT_TRUE(paranoid.scanOnWrite);
    EXPECT_TRUE(paranoid.blockOnTimeout);
    EXPECT_TRUE(paranoid.blockOnError);
    EXPECT_FALSE(paranoid.cacheNegativeResults);
}

TEST_F(FileSystemFilterTest, ExclusionMatchingAndCallbacksRemainDeterministic) {
    FilterExclusion processExclusion;
    processExclusion.type = FilterExclusion::Type::Process;
    processExclusion.pattern = L"POWERSHELL.EXE";
    processExclusion.comment = L"Trusted automation";

    FilterExclusion processPathExclusion;
    processPathExclusion.type = FilterExclusion::Type::ProcessPath;
    processPathExclusion.pattern = L"C:\\Windows\\System32\\";
    processPathExclusion.comment = L"Signed Windows binaries";

    EXPECT_TRUE(filter.AddExclusion(processExclusion));
    EXPECT_TRUE(filter.AddExclusion(processPathExclusion));
    EXPECT_EQ(2u, filter.GetExclusions().size());

    EXPECT_TRUE(filter.IsProcessExcluded(L"powershell.exe"));
    EXPECT_TRUE(filter.IsProcessExcluded(L"cmd.exe", L"c:\\windows\\system32\\cmd.exe"));
    EXPECT_FALSE(filter.IsProcessExcluded(L"notepad.exe", L"c:\\apps\\notepad.exe"));

    filter.RegisterScanCallback([](const FileAccessEvent&) { return ScanVerdict::Allow; });

    const uint64_t notificationId = filter.RegisterNotificationCallback(
        [](const FileAccessEvent&) {});
    const uint64_t statusId = filter.RegisterStatusCallback(
        [](FilterStatus, const std::wstring&) {});
    const uint64_t threatId = filter.RegisterThreatCallback(
        [](const FileAccessEvent&, const std::wstring&, double) {});

    EXPECT_NE(0u, notificationId);
    EXPECT_NE(0u, statusId);
    EXPECT_NE(0u, threatId);

    EXPECT_TRUE(filter.UnregisterNotificationCallback(notificationId));
    EXPECT_TRUE(filter.UnregisterStatusCallback(statusId));
    EXPECT_TRUE(filter.UnregisterThreatCallback(threatId));
    EXPECT_FALSE(filter.UnregisterThreatCallback(threatId));

    EXPECT_TRUE(filter.RemoveExclusion(processExclusion.pattern));
    EXPECT_TRUE(filter.RemoveExclusion(processPathExclusion.pattern));
    EXPECT_TRUE(filter.GetExclusions().empty());
}

TEST_F(FileSystemFilterTest, DefaultStateAndStatisticsRemainSafeWithoutDriverInitialization) {
    EXPECT_FALSE(filter.IsInitialized());
    EXPECT_FALSE(filter.IsRunning());
    EXPECT_EQ(FilterStatus::NotInitialized, filter.GetStatus());

    const auto stats = filter.GetStats();
    EXPECT_EQ(0u, stats.totalScanRequests);
    EXPECT_EQ(0u, stats.filesAllowed);
    EXPECT_EQ(0u, stats.filesBlocked);
    EXPECT_EQ(0u, stats.pendingRequests);
    EXPECT_EQ(0u, stats.avgScanTimeUs);
}

}  // namespace ShadowStrike::RealTime::Tests
