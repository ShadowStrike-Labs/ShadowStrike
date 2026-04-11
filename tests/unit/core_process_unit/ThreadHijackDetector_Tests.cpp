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
 * @file ThreadHijackDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ThreadHijackDetector value surfaces.
 *
 * Coverage focus:
 * - configuration presets for active, high-sensitivity, and performance modes
 * - detection-rate math and reset semantics for runtime statistics
 */

#include "../../../src/pch.h"

#include "../../../src/PhantomCore/Core/Process/ThreadHijackDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(ThreadHijackValueTests, ConfigPresetsCaptureSensitivityAndPerformanceTradeoffs) {
    const auto defaults = ThreadHijackConfig::CreateDefault();
    const auto sensitive = ThreadHijackConfig::CreateHighSensitivity();
    const auto performance = ThreadHijackConfig::CreatePerformance();

    EXPECT_EQ(defaults.mode, MonitoringMode::Active);
    EXPECT_TRUE(defaults.enableRealTimeMonitoring);
    EXPECT_TRUE(defaults.validateInstructionPointer);
    EXPECT_TRUE(defaults.validateStackPointer);
    EXPECT_TRUE(defaults.analyzeCallStack);
    EXPECT_EQ(defaults.alertThreshold, DetectionConfidence::Medium);
    EXPECT_FALSE(defaults.enableAutoResponse);
    EXPECT_FALSE(defaults.blockSuspiciousChanges);

    EXPECT_EQ(sensitive.mode, MonitoringMode::Active);
    EXPECT_EQ(sensitive.alertThreshold, DetectionConfidence::Low);
    EXPECT_EQ(sensitive.maxUnbackedFrames, 0u);
    EXPECT_TRUE(sensitive.validateStackPointer);
    EXPECT_TRUE(sensitive.checkDebugRegisters);
    EXPECT_TRUE(sensitive.trackContextChanges);
    EXPECT_TRUE(sensitive.blockSuspiciousChanges);

    EXPECT_EQ(performance.mode, MonitoringMode::PassiveOnly);
    EXPECT_FALSE(performance.enableRealTimeMonitoring);
    EXPECT_FALSE(performance.validateStackPointer);
    EXPECT_FALSE(performance.validateSegmentRegisters);
    EXPECT_FALSE(performance.checkDebugRegisters);
    EXPECT_FALSE(performance.analyzeCallStack);
    EXPECT_FALSE(performance.trackContextChanges);
    EXPECT_EQ(performance.alertThreshold, DetectionConfidence::High);
    EXPECT_FALSE(performance.blockSuspiciousChanges);
}

TEST(ThreadHijackValueTests, StatisticsDetectionRateAndResetRemainDeterministic) {
    ThreadHijackStatistics stats;
    stats.threadsMonitored.store(10, std::memory_order_relaxed);
    stats.threadValidations.store(20, std::memory_order_relaxed);
    stats.hijacksDetected.store(5, std::memory_order_relaxed);
    stats.crossProcessChanges.store(3, std::memory_order_relaxed);
    stats.callStacksAnalyzed.store(9, std::memory_order_relaxed);
    stats.timeoutErrors.store(1, std::memory_order_relaxed);

    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 25.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 0.0);
    EXPECT_EQ(stats.threadsMonitored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threadValidations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hijacksDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.crossProcessChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.callStacksAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.timeoutErrors.load(std::memory_order_relaxed), 0u);
}

}  // namespace
