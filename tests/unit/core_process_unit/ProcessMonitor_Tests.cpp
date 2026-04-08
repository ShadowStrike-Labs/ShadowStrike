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
 * @file ProcessMonitor_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ProcessMonitor helper types.
 *
 * Coverage focus:
 * - unique-process identity and PID-reuse-safe hashing
 * - monitor configuration presets and statistics helpers
 * - ExtendedProcessInfo conversions used by higher-level consumers
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/ProcessMonitor.hpp"

#include <chrono>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::Process;

TEST(ProcessMonitorValueTests, ProcessUniqueIdSupportsEqualityOrderingAndStableHashing) {
    const ProcessUniqueId alpha{ 1234, 100 };
    const ProcessUniqueId alphaSame{ 1234, 100 };
    const ProcessUniqueId alphaNewer{ 1234, 101 };
    const ProcessUniqueId beta{ 5678, 50 };

    EXPECT_EQ(alpha, alphaSame);
    EXPECT_NE(alpha, alphaNewer);
    EXPECT_TRUE(alpha < alphaNewer);
    EXPECT_TRUE(alpha < beta);
    EXPECT_TRUE(alpha.MatchesPid(1234));
    EXPECT_FALSE(alpha.MatchesPid(4321));
    EXPECT_EQ(alpha.Hash(), alphaSame.Hash());
    EXPECT_NE(alpha.Hash(), alphaNewer.Hash());
}

TEST(ProcessMonitorValueTests, ConfigPresetsReflectMinimalAndForensicTradeoffs) {
    const auto defaults = MonitorConfig::CreateDefault();
    const auto minimal = MonitorConfig::CreateMinimal();
    const auto forensic = MonitorConfig::CreateForensic();

    EXPECT_TRUE(defaults.useKernelCallback);
    EXPECT_TRUE(defaults.useETWProvider);
    EXPECT_TRUE(defaults.trackAncestry);
    EXPECT_TRUE(defaults.enableHistoricalTracking);

    EXPECT_FALSE(minimal.useKernelCallback);
    EXPECT_FALSE(minimal.useETWProvider);
    EXPECT_FALSE(minimal.useFilterManager);
    EXPECT_FALSE(minimal.collectCommandLine);
    EXPECT_FALSE(minimal.collectWorkingDirectory);
    EXPECT_FALSE(minimal.trackAncestry);
    EXPECT_FALSE(minimal.detectPPIDSpoofing);
    EXPECT_FALSE(minimal.enableHistoricalTracking);
    EXPECT_GT(minimal.snapshotIntervalMs, defaults.snapshotIntervalMs);

    EXPECT_TRUE(forensic.useKernelCallback);
    EXPECT_TRUE(forensic.useETWProvider);
    EXPECT_TRUE(forensic.useFilterManager);
    EXPECT_TRUE(forensic.useWMI);
    EXPECT_TRUE(forensic.computeImageHash);
    EXPECT_FALSE(forensic.lazyMetadataFetch);
    EXPECT_TRUE(forensic.trackAncestry);
    EXPECT_TRUE(forensic.detectPPIDSpoofing);
    EXPECT_TRUE(forensic.enableHistoricalTracking);
    EXPECT_LT(forensic.snapshotIntervalMs, defaults.snapshotIntervalMs);
}

TEST(ProcessMonitorValueTests, StatisticsHelpersComputeRatiosRatesAndResetSentinels) {
    MonitorStatistics stats;
    stats.cacheLookups.store(4, std::memory_order_relaxed);
    stats.cacheHits.store(3, std::memory_order_relaxed);
    stats.totalLookupTimeUs.store(100, std::memory_order_relaxed);
    stats.eventsProcessed.store(10, std::memory_order_relaxed);
    stats.minLookupTimeUs.store(8, std::memory_order_relaxed);
    stats.maxLookupTimeUs.store(60, std::memory_order_relaxed);
    stats.startTime = std::chrono::system_clock::now() - 2s;

    EXPECT_DOUBLE_EQ(stats.GetCacheHitRatio(), 75.0);
    EXPECT_DOUBLE_EQ(stats.GetAverageLookupTimeUs(), 25.0);
    EXPECT_GE(stats.GetEventsPerSecond(), 4.0);
    EXPECT_LE(stats.GetEventsPerSecond(), 6.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetCacheHitRatio(), 0.0);
    EXPECT_DOUBLE_EQ(stats.GetAverageLookupTimeUs(), 0.0);
    EXPECT_EQ(stats.eventsProcessed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheLookups.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheHits.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalLookupTimeUs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.minLookupTimeUs.load(std::memory_order_relaxed), UINT64_MAX);
    EXPECT_EQ(stats.maxLookupTimeUs.load(std::memory_order_relaxed), 0u);
}

TEST(ProcessMonitorValueTests, ExtendedProcessInfoConversionsPreserveIdentityAndStalenessRules) {
    ExtendedProcessInfo info;
    info.uniqueId = { 4242, 0x12345678ULL };
    info.processName = L"shadowstrike-test.exe";
    info.processPath = L"C:\\ShadowStrike\\shadowstrike-test.exe";
    info.commandLine = L"shadowstrike-test.exe --scan";
    info.parentPid = 1337;
    info.sessionId = 3;
    info.isWow64 = true;
    info.isSystemProcess = false;
    info.isProtectedProcess = true;
    info.metadataComplete = true;
    info.lastUpdateTime = std::chrono::system_clock::now() - 1s;

    const auto processInfo = info.ToProcessInfo();
    EXPECT_EQ(processInfo.basic.pid, 4242u);
    EXPECT_EQ(processInfo.basic.name, info.processName);
    EXPECT_EQ(processInfo.basic.executablePath, info.processPath);
    EXPECT_EQ(processInfo.basic.commandLine, info.commandLine);
    EXPECT_EQ(processInfo.basic.parentPid, 1337u);
    EXPECT_EQ(processInfo.basic.sessionId, 3u);
    EXPECT_TRUE(processInfo.basic.isWow64);
    EXPECT_TRUE(processInfo.basic.isProtected);

    const auto basicInfo = info.ToBasicInfo();
    EXPECT_EQ(basicInfo.pid, 4242u);
    EXPECT_EQ(basicInfo.name, info.processName);
    EXPECT_EQ(basicInfo.executablePath, info.processPath);
    EXPECT_EQ(basicInfo.parentPid, 1337u);
    EXPECT_EQ(basicInfo.sessionId, 3u);
    EXPECT_TRUE(basicInfo.isWow64);
    EXPECT_FALSE(basicInfo.isSystemProcess);

    EXPECT_TRUE(info.IsValid());
    EXPECT_FALSE(info.IsStale(5s));

    info.lastUpdateTime = std::chrono::system_clock::now() - 10s;
    EXPECT_TRUE(info.IsStale(5s));

    info.metadataComplete = false;
    EXPECT_TRUE(info.IsStale(30s));
}

}  // namespace
