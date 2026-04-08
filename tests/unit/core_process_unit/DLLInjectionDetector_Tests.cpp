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
 * @file DLLInjectionDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::DLLInjectionDetector value surfaces.
 *
 * Coverage focus:
 * - configuration presets for enforcement and performance tradeoffs
 * - atomic statistics snapshot, detection-rate math, and reset semantics
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/DLLInjectionDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(DLLInjectionValueTests, ConfigPresetsReflectEnforcementAndPerformanceTradeoffs) {
    const auto defaults = DLLInjectionConfig::CreateDefault();
    const auto strict = DLLInjectionConfig::CreateStrict();
    const auto performance = DLLInjectionConfig::CreatePerformance();

    EXPECT_EQ(defaults.mode, DLLMonitoringMode::PassiveOnly);
    EXPECT_TRUE(defaults.enableRealTimeMonitoring);
    EXPECT_TRUE(defaults.detectSideLoading);
    EXPECT_TRUE(defaults.detectCOMHijacking);
    EXPECT_TRUE(defaults.enableHashLookup);
    EXPECT_TRUE(defaults.computeHashesAsync);
    EXPECT_EQ(defaults.alertThreshold, InjectionConfidence::Medium);
    EXPECT_EQ(defaults.blockThreshold, InjectionConfidence::High);

    EXPECT_EQ(strict.mode, DLLMonitoringMode::ActiveBlock);
    EXPECT_EQ(strict.alertThreshold, InjectionConfidence::Low);
    EXPECT_EQ(strict.blockThreshold, InjectionConfidence::Medium);
    EXPECT_TRUE(strict.alertOnUnsignedLoads);
    EXPECT_FALSE(strict.blockUnsignedLoads);
    EXPECT_TRUE(strict.detectSearchOrderHijack);
    EXPECT_TRUE(strict.detectSideLoading);

    EXPECT_EQ(performance.mode, DLLMonitoringMode::PassiveOnly);
    EXPECT_FALSE(performance.detectSearchOrderHijack);
    EXPECT_FALSE(performance.detectSideLoading);
    EXPECT_FALSE(performance.detectCOMHijacking);
    EXPECT_FALSE(performance.detectShimInjection);
    EXPECT_EQ(performance.alertThreshold, InjectionConfidence::High);
    EXPECT_EQ(performance.blockThreshold, InjectionConfidence::Confirmed);
    EXPECT_FALSE(performance.enableHashLookup);
    EXPECT_FALSE(performance.computeHashesAsync);
}

TEST(DLLInjectionValueTests, StatisticsSnapshotDetectionRateAndResetRemainStable) {
    DLLInjectionStatistics stats;
    stats.totalModulesAnalyzed.store(8, std::memory_order_relaxed);
    stats.trustedModulesFound.store(4, std::memory_order_relaxed);
    stats.suspiciousModulesFound.store(3, std::memory_order_relaxed);
    stats.injectionsDetected.store(2, std::memory_order_relaxed);
    stats.hashCacheHits.store(5, std::memory_order_relaxed);
    stats.apcEventsProcessed.store(4, std::memory_order_relaxed);

    const DLLInjectionStatistics snapshot = stats;
    EXPECT_EQ(snapshot.totalModulesAnalyzed.load(std::memory_order_relaxed), 8u);
    EXPECT_EQ(snapshot.trustedModulesFound.load(std::memory_order_relaxed), 4u);
    EXPECT_EQ(snapshot.suspiciousModulesFound.load(std::memory_order_relaxed), 3u);
    EXPECT_EQ(snapshot.hashCacheHits.load(std::memory_order_relaxed), 5u);
    EXPECT_EQ(snapshot.apcEventsProcessed.load(std::memory_order_relaxed), 4u);
    EXPECT_DOUBLE_EQ(snapshot.GetDetectionRate(), 25.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 0.0);
    EXPECT_EQ(stats.totalModulesAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.injectionsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hashCacheHits.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.apcEventsProcessed.load(std::memory_order_relaxed), 0u);
}

}  // namespace
