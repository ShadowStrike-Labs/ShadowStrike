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
 * @file ProcessKiller_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ProcessKiller value surfaces.
 *
 * Coverage focus:
 * - kill-option presets for standard, aggressive, malware, and forensic workflows
 * - success-rate math and reset semantics for runtime statistics
 */

#include "../../../src/pch.h"
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Core/Process/ProcessKiller.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(ProcessKillerValueTests, KillOptionPresetsReflectOperationalIntent) {
    const auto standard = KillOptions::CreateStandard();
    const auto aggressive = KillOptions::CreateAggressive();
    const auto malware = KillOptions::CreateMalwareKill();
    const auto forensic = KillOptions::CreateForensic();

    EXPECT_EQ(standard.preferredMethod, KillMethod::Auto);
    EXPECT_EQ(standard.timeoutMs, KillerConstants::DEFAULT_KILL_TIMEOUT_MS);
    EXPECT_EQ(standard.maxRetries, KillerConstants::MAX_RETRY_ATTEMPTS);
    EXPECT_FALSE(standard.killTree);
    EXPECT_FALSE(standard.defeatWatchdogs);
    EXPECT_FALSE(standard.cleanPersistence);
    EXPECT_FALSE(standard.preserveEvidence);
    EXPECT_FALSE(standard.allowCritical);

    EXPECT_EQ(aggressive.preferredMethod, KillMethod::Auto);
    EXPECT_EQ(aggressive.timeoutMs, 10000u);
    EXPECT_EQ(aggressive.maxRetries, 5u);
    EXPECT_TRUE(aggressive.killTree);
    EXPECT_EQ(aggressive.treeStrategy, TreeKillStrategy::BottomUp);
    EXPECT_TRUE(aggressive.defeatWatchdogs);
    EXPECT_TRUE(aggressive.verifyTermination);

    EXPECT_EQ(malware.timeoutMs, KillerConstants::TREE_KILL_TIMEOUT_MS);
    EXPECT_TRUE(malware.killTree);
    EXPECT_EQ(malware.treeStrategy, TreeKillStrategy::Simultaneous);
    EXPECT_TRUE(malware.defeatWatchdogs);
    EXPECT_TRUE(malware.cleanPersistence);
    EXPECT_TRUE(malware.preserveEvidence);
    EXPECT_EQ(malware.exitCode, KillerConstants::EXIT_CODE_SECURITY);

    EXPECT_EQ(forensic.preferredMethod, KillMethod::Freeze);
    EXPECT_EQ(forensic.maxRetries, 1u);
    EXPECT_FALSE(forensic.escalateOnFailure);
    EXPECT_FALSE(forensic.killTree);
    EXPECT_TRUE(forensic.verifyTermination);
    EXPECT_TRUE(forensic.preserveEvidence);
}

TEST(ProcessKillerValueTests, StatisticsSuccessRateAndResetRemainDeterministic) {
    KillerStatistics stats;
    stats.totalKillAttempts.store(8, std::memory_order_relaxed);
    stats.successfulKills.store(6, std::memory_order_relaxed);
    stats.failedKills.store(2, std::memory_order_relaxed);
    stats.treeKillAttempts.store(1, std::memory_order_relaxed);
    stats.watchdogsDetected.store(3, std::memory_order_relaxed);
    stats.timeoutErrors.store(1, std::memory_order_relaxed);

    EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 75.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetSuccessRate(), 0.0);
    EXPECT_EQ(stats.totalKillAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.successfulKills.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.failedKills.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.treeKillAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.watchdogsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.timeoutErrors.load(std::memory_order_relaxed), 0u);
}

}  // namespace
