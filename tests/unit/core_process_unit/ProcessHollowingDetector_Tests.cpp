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
 * @file ProcessHollowingDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ProcessHollowingDetector helper logic.
 *
 * Coverage focus:
 * - hollowing confidence thresholds and capped risk scoring
 * - configuration preset tradeoffs for active, paranoid, and forensic modes
 * - statistics math used by monitoring and telemetry surfaces
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/ProcessHollowingDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(ProcessHollowingValueTests, ConfigPresetsReflectSensitivityAndPerformanceTradeoffs) {
    const auto defaults = HollowingDetectorConfig::CreateDefault();
    const auto paranoid = HollowingDetectorConfig::CreateParanoid();
    const auto performance = HollowingDetectorConfig::CreatePerformance();
    const auto forensic = HollowingDetectorConfig::CreateForensic();

    EXPECT_EQ(defaults.defaultScanMode, HollowingScanMode::Standard);
    EXPECT_EQ(defaults.monitorMode, MonitorMode::Active);
    EXPECT_TRUE(defaults.enableRealTimeMonitoring);
    EXPECT_TRUE(defaults.enableHeaderComparison);

    EXPECT_EQ(paranoid.defaultScanMode, HollowingScanMode::Paranoid);
    EXPECT_EQ(paranoid.monitorMode, MonitorMode::Aggressive);
    EXPECT_TRUE(paranoid.alertOnLowConfidence);
    EXPECT_TRUE(paranoid.enablePayloadExtraction);
    EXPECT_TRUE(paranoid.enableTransactionMonitoring);
    EXPECT_TRUE(paranoid.enableModuleStompingDetection);
    EXPECT_TRUE(paranoid.enableThreadContextValidation);
    EXPECT_LT(paranoid.sectionDifferenceThreshold, defaults.sectionDifferenceThreshold);

    EXPECT_EQ(performance.defaultScanMode, HollowingScanMode::Quick);
    EXPECT_EQ(performance.monitorMode, MonitorMode::PassiveOnly);
    EXPECT_FALSE(performance.enableSectionAnalysis);
    EXPECT_FALSE(performance.enablePayloadExtraction);
    EXPECT_TRUE(performance.enableCaching);
    EXPECT_GT(performance.maxConcurrentScans, defaults.maxConcurrentScans);

    EXPECT_EQ(forensic.defaultScanMode, HollowingScanMode::Comprehensive);
    EXPECT_TRUE(forensic.enablePayloadExtraction);
    EXPECT_TRUE(forensic.quarantinePayload);
    EXPECT_TRUE(forensic.reportToThreatIntel);
    EXPECT_GT(forensic.scanTimeoutMs, defaults.scanTimeoutMs);
}

TEST(ProcessHollowingValueTests, StatisticsComputeAverageAndDetectionRateAndResetSentinels) {
    HollowingStatistics stats;
    stats.totalScans.store(8, std::memory_order_relaxed);
    stats.hollowingDetected.store(2, std::memory_order_relaxed);
    stats.totalScanTimeMs.store(400, std::memory_order_relaxed);
    stats.minScanTimeMs.store(10, std::memory_order_relaxed);
    stats.maxScanTimeMs.store(90, std::memory_order_relaxed);

    EXPECT_DOUBLE_EQ(stats.GetAverageScanTimeMs(), 50.0);
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 25.0);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetAverageScanTimeMs(), 0.0);
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 0.0);
    EXPECT_EQ(stats.totalScans.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hollowingDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.minScanTimeMs.load(std::memory_order_relaxed), UINT64_MAX);
    EXPECT_EQ(stats.maxScanTimeMs.load(std::memory_order_relaxed), 0u);
}

TEST(ProcessHollowingValueTests, DetectionConfidenceEscalatesWithIndicatorStrength) {
    {
        HollowingDetectionResult result;
        result.detectionMethods = { DetectionMethod::MemoryProtection };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::Low);
    }

    {
        HollowingDetectionResult result;
        result.detectionMethods = { DetectionMethod::PEHeaderMismatch };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::Medium);
    }

    {
        HollowingDetectionResult result;
        result.detectionMethods = {
            DetectionMethod::PEHeaderMismatch,
            DetectionMethod::EntryPointAnomaly
        };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::High);
    }

    {
        HollowingDetectionResult result;
        result.detectionMethods = {
            DetectionMethod::PEHeaderMismatch,
            DetectionMethod::DeletePendingFile
        };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::Confirmed);
    }
}

TEST(ProcessHollowingValueTests, DetectionConfidenceUsesExactThresholdBoundariesAndBaselineRisk) {
    {
        HollowingDetectionResult result;
        result.detectionMethods = {
            DetectionMethod::EntryPointAnomaly,
            DetectionMethod::MemoryProtection,
            DetectionMethod::EntropyAnomaly
        };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::High);
    }

    {
        HollowingDetectionResult result;
        result.detectionMethods = {
            DetectionMethod::PEHeaderMismatch,
            DetectionMethod::SizeOfImageMismatch,
            DetectionMethod::ChecksumMismatch
        };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::Confirmed);
    }

    {
        HollowingDetectionResult result;
        result.confidence = HollowingConfidence::Low;
        result.CalculateRiskScore();
        EXPECT_EQ(result.riskScore, 30u);
    }
}

TEST(ProcessHollowingValueTests, RiskScoreIncludesContextualFlagsAndCapsAtMaximum) {
    HollowingDetectionResult result;
    result.confidence = HollowingConfidence::Confirmed;
    result.hasUnbackedExecutableMemory = true;
    result.hasRWXRegions = true;
    result.moduleStompingDetected = true;
    result.correlatedWithKnownThreat = true;
    result.entryPointAnalysis.hasShellcodePattern = true;

    result.CalculateRiskScore();

    EXPECT_EQ(result.riskScore, 100u);
}

TEST(ProcessHollowingValueTests, ConfidenceAndRiskScoreHandleEmptyAndIntermediateSignals) {
    {
        HollowingDetectionResult result;
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::None);
    }

    {
        HollowingDetectionResult result;
        result.detectionMethods = {
            DetectionMethod::MemoryProtection,
            DetectionMethod::EntropyAnomaly
        };
        result.CalculateConfidence();
        EXPECT_EQ(result.confidence, HollowingConfidence::Medium);
    }

    {
        HollowingDetectionResult result;
        result.confidence = HollowingConfidence::High;
        result.hasUnbackedExecutableMemory = true;
        result.entryPointAnalysis.hasShellcodePattern = true;
        result.CalculateRiskScore();
        EXPECT_EQ(result.riskScore, 85u);
    }
}

}  // namespace
