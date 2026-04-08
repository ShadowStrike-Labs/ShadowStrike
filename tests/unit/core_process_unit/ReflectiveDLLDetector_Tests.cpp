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
 * @file ReflectiveDLLDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ReflectiveDLLDetector helper logic.
 *
 * Coverage focus:
 * - reflective loader risk scoring and cap behavior
 * - preset configurations for standard, sensitive, performance, and forensic modes
 * - atomic statistics snapshot, rate calculation, and reset semantics
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/ReflectiveDLLDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

TEST(ReflectiveDLLValueTests, ConfigPresetsCaptureSensitivityAndForensicExtractionModes) {
    const auto defaults = ReflectiveConfig::CreateDefault();
    const auto sensitive = ReflectiveConfig::CreateHighSensitivity();
    const auto performance = ReflectiveConfig::CreatePerformance();
    const auto forensic = ReflectiveConfig::CreateForensic();

    EXPECT_EQ(defaults.defaultScanMode, ReflectiveScanMode::Standard);
    EXPECT_TRUE(defaults.scanRWXRegions);
    EXPECT_TRUE(defaults.scanAllExecutableRegions);
    EXPECT_FALSE(defaults.extractPayloads);

    EXPECT_EQ(sensitive.defaultScanMode, ReflectiveScanMode::Deep);
    EXPECT_TRUE(sensitive.extractPayloads);
    EXPECT_EQ(sensitive.alertThreshold, DetectionConfidence::Low);
    EXPECT_LT(sensitive.entropyThreshold, defaults.entropyThreshold);
    EXPECT_TRUE(sensitive.analyzeCallStacks);

    EXPECT_EQ(performance.defaultScanMode, ReflectiveScanMode::Quick);
    EXPECT_FALSE(performance.scanAllExecutableRegions);
    EXPECT_FALSE(performance.analyzeCallStacks);
    EXPECT_FALSE(performance.extractPayloads);
    EXPECT_EQ(performance.alertThreshold, DetectionConfidence::High);
    EXPECT_GT(performance.maxConcurrentScans, defaults.maxConcurrentScans);

    EXPECT_EQ(forensic.defaultScanMode, ReflectiveScanMode::Forensic);
    EXPECT_TRUE(forensic.extractPayloads);
    EXPECT_GT(forensic.scanTimeoutMs, sensitive.scanTimeoutMs);
    EXPECT_GT(forensic.maxRegionsToScan, sensitive.maxRegionsToScan);
    EXPECT_GT(forensic.maxPECandidates, sensitive.maxPECandidates);
}

TEST(ReflectiveDLLValueTests, StatisticsSnapshotDetectionRateAndResetRemainDeterministic) {
    ReflectiveStatistics stats;
    stats.totalScans.store(8, std::memory_order_relaxed);
    stats.reflectiveDLLsDetected.store(2, std::memory_order_relaxed);
    stats.regionsScanned.store(40, std::memory_order_relaxed);
    stats.payloadsExtracted.store(1, std::memory_order_relaxed);

    const ReflectiveStatistics snapshot = stats;
    EXPECT_DOUBLE_EQ(snapshot.GetDetectionRate(), 25.0);
    EXPECT_EQ(snapshot.regionsScanned.load(std::memory_order_relaxed), 40u);
    EXPECT_EQ(snapshot.payloadsExtracted.load(std::memory_order_relaxed), 1u);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetDetectionRate(), 0.0);
    EXPECT_EQ(stats.totalScans.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.reflectiveDLLsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.regionsScanned.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.payloadsExtracted.load(std::memory_order_relaxed), 0u);
}

TEST(ReflectiveDLLValueTests, RiskScoreWeightsConfidenceIndicatorsThreatIntelAndLoaderType) {
    {
        ReflectiveDetection lowSignal;
        lowSignal.confidence = DetectionConfidence::Low;
        lowSignal.loadType = ReflectiveLoadType::Unknown;
        lowSignal.CalculateRiskScore();
        EXPECT_EQ(lowSignal.riskScore, 15u);
    }

    {
        ReflectiveDetection highSignal;
        highSignal.confidence = DetectionConfidence::High;
        highSignal.isRWX = true;
        highSignal.isUnbacked = true;
        highSignal.isHiddenFromPEB = true;
        highSignal.correlatedWithKnownThreat = true;
        highSignal.loadType = ReflectiveLoadType::CobaltStrikeBeacon;
        highSignal.hasThreadStartingHere = true;
        highSignal.threadCount = 2;
        highSignal.foundInCallStack = true;
        highSignal.CalculateRiskScore();
        EXPECT_EQ(highSignal.riskScore, 100u);
    }
}

TEST(ReflectiveDLLValueTests, RiskScorePreservesIntermediateWeightedPathsWithoutClamping) {
    ReflectiveDetection mediumSignal;
    mediumSignal.confidence = DetectionConfidence::Medium;
    mediumSignal.isUnbacked = true;
    mediumSignal.loadType = ReflectiveLoadType::ManualMapping;
    mediumSignal.hasThreadStartingHere = true;

    mediumSignal.CalculateRiskScore();

    EXPECT_EQ(mediumSignal.riskScore, 65u);
}

}  // namespace
