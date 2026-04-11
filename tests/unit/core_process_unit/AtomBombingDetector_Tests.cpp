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
 * @file AtomBombingDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::AtomBombingDetector value surfaces.
 *
 * Coverage focus:
 * - configuration presets for sensitivity and performance tuning
 * - attack-rate math, copy semantics, and reset behavior for statistics
 */

#include "../../../src/pch.h"

#include "../../../src/PhantomCore/Core/Process/AtomBombingDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(AtomBombingValueTests, ConfigPresetsCaptureSensitivityAndPerformanceTradeoffs) {
    const auto defaults = AtomBombingConfig::CreateDefault();
    const auto sensitive = AtomBombingConfig::CreateHighSensitivity();
    const auto performance = AtomBombingConfig::CreatePerformance();

    EXPECT_EQ(defaults.mode, MonitoringMode::Active);
    EXPECT_TRUE(defaults.enableRealTimeMonitoring);
    EXPECT_TRUE(defaults.enableOnDemandScanning);
    EXPECT_TRUE(defaults.monitorAPCs);
    EXPECT_TRUE(defaults.correlateAtomAndAPC);
    EXPECT_TRUE(defaults.extractPayloads);
    EXPECT_EQ(defaults.alertThreshold, DetectionConfidence::Medium);

    EXPECT_EQ(sensitive.alertThreshold, DetectionConfidence::Low);
    EXPECT_DOUBLE_EQ(sensitive.entropyThreshold, 6.0);
    EXPECT_EQ(sensitive.suspiciousAtomSizeThreshold, 32u);
    EXPECT_TRUE(sensitive.enableAutoResponse);
    EXPECT_TRUE(sensitive.blockSuspiciousApcs);
    EXPECT_FALSE(sensitive.terminateAttacker);

    EXPECT_EQ(performance.mode, MonitoringMode::PassiveOnly);
    EXPECT_FALSE(performance.enableOnDemandScanning);
    EXPECT_FALSE(performance.monitorAPCs);
    EXPECT_FALSE(performance.correlateAtomAndAPC);
    EXPECT_FALSE(performance.analyzeEntropy);
    EXPECT_FALSE(performance.extractPayloads);
    EXPECT_EQ(performance.alertThreshold, DetectionConfidence::High);
    EXPECT_DOUBLE_EQ(performance.entropyThreshold, 7.5);
    EXPECT_EQ(performance.suspiciousAtomSizeThreshold, 128u);
    EXPECT_EQ(performance.maxAtomsToAnalyze, 4096u);
}

TEST(AtomBombingValueTests, StatisticsCopyDetectionRateAndResetRemainStable) {
    AtomBombingStatistics stats;
    stats.atomsMonitored.store(12, std::memory_order_relaxed);
    stats.atomCreations.store(10, std::memory_order_relaxed);
    stats.apcsMonitored.store(7, std::memory_order_relaxed);
    stats.attacksDetected.store(4, std::memory_order_relaxed);
    stats.payloadsExtracted.store(1, std::memory_order_relaxed);
    stats.scansPerformed.store(16, std::memory_order_relaxed);

    const AtomBombingStatistics snapshot = stats;
    EXPECT_EQ(snapshot.atomsMonitored.load(std::memory_order_relaxed), 12u);
    EXPECT_EQ(snapshot.atomCreations.load(std::memory_order_relaxed), 10u);
    EXPECT_EQ(snapshot.apcsMonitored.load(std::memory_order_relaxed), 7u);
    EXPECT_EQ(snapshot.payloadsExtracted.load(std::memory_order_relaxed), 1u);
    EXPECT_DOUBLE_EQ(snapshot.GetDetectionRate(), 25.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 0.0);
    EXPECT_EQ(stats.atomsMonitored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.attacksDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.payloadsExtracted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.scansPerformed.load(std::memory_order_relaxed), 0u);
}

}  // namespace
