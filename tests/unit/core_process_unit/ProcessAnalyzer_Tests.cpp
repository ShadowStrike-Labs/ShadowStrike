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
 * @file ProcessAnalyzer_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ProcessAnalyzer value surfaces.
 *
 * Coverage focus:
 * - analyzer configuration presets and statistics math
 * - deterministic overall risk scoring and risk-level mapping
 * - precedence rules for malicious indicators and trusted allowlists
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/ProcessAnalyzer.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

ProcessAnalysisResult MakeSignedBaselineResult() {
    ProcessAnalysisResult result;
    result.signatureInfo.status = SignatureStatus::Valid;
    result.signatureInfo.trustLevel = CertificateTrust::Microsoft;
    return result;
}

TEST(ProcessAnalyzerValueTests, ConfigPresetsReflectExpectedOperationalModes) {
    const auto defaults = AnalyzerConfig::CreateDefault();
    const auto quick = AnalyzerConfig::CreateQuick();
    const auto forensic = AnalyzerConfig::CreateForensic();
    const auto realtime = AnalyzerConfig::CreateRealTime();

    EXPECT_EQ(defaults.defaultDepth, AnalysisDepth::Standard);
    EXPECT_TRUE(defaults.enableHandleAnalysis);
    EXPECT_TRUE(defaults.enableMemoryAnalysis);

    EXPECT_EQ(quick.defaultDepth, AnalysisDepth::Quick);
    EXPECT_FALSE(quick.enableHandleAnalysis);
    EXPECT_FALSE(quick.enableMemoryAnalysis);
    EXPECT_FALSE(quick.enableThreadAnalysis);
    EXPECT_FALSE(quick.enableNetworkAnalysis);
    EXPECT_FALSE(quick.enableBehavioralAnalysis);
    EXPECT_TRUE(quick.enableSignatureVerification);

    EXPECT_EQ(forensic.defaultDepth, AnalysisDepth::Forensic);
    EXPECT_TRUE(forensic.enableHandleAnalysis);
    EXPECT_TRUE(forensic.enableMemoryAnalysis);
    EXPECT_TRUE(forensic.enableThreadAnalysis);
    EXPECT_GT(forensic.signatureCheckTimeoutMs, defaults.signatureCheckTimeoutMs);
    EXPECT_GT(forensic.handleEnumTimeoutMs, defaults.handleEnumTimeoutMs);
    EXPECT_GT(forensic.memoryScanTimeoutMs, defaults.memoryScanTimeoutMs);

    EXPECT_EQ(realtime.defaultDepth, AnalysisDepth::Standard);
    EXPECT_TRUE(realtime.enableAnalysisCache);
    EXPECT_TRUE(realtime.enableSignatureCache);
    EXPECT_GT(realtime.analysisCacheTTLSeconds, defaults.analysisCacheTTLSeconds);
    EXPECT_LT(realtime.signatureCheckTimeoutMs, defaults.signatureCheckTimeoutMs);
    EXPECT_LT(realtime.handleEnumTimeoutMs, defaults.handleEnumTimeoutMs);
    EXPECT_LT(realtime.memoryScanTimeoutMs, defaults.memoryScanTimeoutMs);
}

TEST(ProcessAnalyzerValueTests, StatisticsAverageAndCacheHitRatioUseStableSnapshots) {
    AnalyzerStatistics stats;
    stats.totalAnalyses.store(4, std::memory_order_relaxed);
    stats.totalAnalysisTimeMs.store(100, std::memory_order_relaxed);
    stats.analysisCacheHits.store(3, std::memory_order_relaxed);
    stats.analysisCacheMisses.store(1, std::memory_order_relaxed);
    stats.minAnalysisTimeMs.store(10, std::memory_order_relaxed);
    stats.maxAnalysisTimeMs.store(40, std::memory_order_relaxed);

    const AnalyzerStatistics snapshot = stats;
    EXPECT_DOUBLE_EQ(snapshot.GetAverageAnalysisTimeMs(), 25.0);
    EXPECT_DOUBLE_EQ(snapshot.GetAnalysisCacheHitRatio(), 75.0);
    EXPECT_EQ(snapshot.minAnalysisTimeMs.load(std::memory_order_relaxed), 10u);
    EXPECT_EQ(snapshot.maxAnalysisTimeMs.load(std::memory_order_relaxed), 40u);

    stats.Reset();
    EXPECT_DOUBLE_EQ(stats.GetAverageAnalysisTimeMs(), 0.0);
    EXPECT_DOUBLE_EQ(stats.GetAnalysisCacheHitRatio(), 0.0);
    EXPECT_EQ(stats.totalAnalyses.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalAnalysisTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.minAnalysisTimeMs.load(std::memory_order_relaxed), UINT64_MAX);
    EXPECT_EQ(stats.maxAnalysisTimeMs.load(std::memory_order_relaxed), 0u);
}

TEST(ProcessAnalyzerValueTests, RiskScoringHonorsMaliciousAndTrustPrecedence) {
    auto knownMalicious = MakeSignedBaselineResult();
    knownMalicious.isKnownMalicious = true;
    knownMalicious.isWhitelisted = true;
    knownMalicious.CalculateOverallRisk();
    EXPECT_EQ(knownMalicious.overallRiskScore, 100u);
    EXPECT_EQ(knownMalicious.riskLevel, ProcessRiskLevel::Malicious);

    auto maliciousHash = MakeSignedBaselineResult();
    maliciousHash.hashFoundMalicious = true;
    maliciousHash.isWhitelisted = true;
    maliciousHash.CalculateOverallRisk();
    EXPECT_EQ(maliciousHash.overallRiskScore, 95u);
    EXPECT_EQ(maliciousHash.riskLevel, ProcessRiskLevel::Malicious);

    auto trusted = MakeSignedBaselineResult();
    trusted.isWhitelisted = true;
    trusted.CalculateOverallRisk();
    EXPECT_EQ(trusted.overallRiskScore, 0u);
    EXPECT_EQ(trusted.riskLevel, ProcessRiskLevel::Trusted);
}

TEST(ProcessAnalyzerValueTests, RiskScoringMapsAccumulatedIndicatorsIntoPublishedBands) {
    {
        auto result = MakeSignedBaselineResult();
        result.signatureInfo.status = SignatureStatus::Unsigned;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 15u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::Unknown);
    }

    {
        auto result = MakeSignedBaselineResult();
        result.signatureInfo.status = SignatureStatus::Unsigned;
        result.suspiciousModuleCount = 3;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 30u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::LowRisk);
    }

    {
        auto result = MakeSignedBaselineResult();
        result.signatureInfo.status = SignatureStatus::Unsigned;
        result.suspiciousModuleCount = 6;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 45u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::MediumRisk);
    }

    {
        auto result = MakeSignedBaselineResult();
        result.memorySummary.rwxRegionCount = 3;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 60u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::HighRisk);
    }

    {
        auto result = MakeSignedBaselineResult();
        result.signatureInfo.status = SignatureStatus::Unsigned;
        result.suspiciousModuleCount = 12;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 75u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::Suspicious);
    }

    {
        auto result = MakeSignedBaselineResult();
        result.signatureInfo.status = SignatureStatus::Unsigned;
        result.memorySummary.rwxRegionCount = 2;
        result.memorySummary.unbackedExecRegionCount = 1;
        result.CalculateOverallRisk();
        EXPECT_EQ(result.overallRiskScore, 90u);
        EXPECT_EQ(result.riskLevel, ProcessRiskLevel::Critical);
    }
}

TEST(ProcessAnalyzerValueTests, RiskScoringCapsExploitHeavyProcessesAtMaximumRisk) {
    auto result = MakeSignedBaselineResult();
    result.signatureInfo.status = SignatureStatus::Revoked;
    result.suspiciousModuleCount = 10;
    result.unsignedModuleCount = 5;
    result.memorySummary.rwxRegionCount = 3;
    result.memorySummary.unbackedExecRegionCount = 2;
    result.threadSummary.unbackedStartCount = 2;
    result.parentChildAnalysis.anomaly = ParentChildAnomaly::UnexpectedParent;
    result.parentChildAnalysis.isPPIDSpoofed = true;
    result.behavioralIndicators.hasProcessHollowing = true;
    result.behavioralIndicators.hasDirectSyscalls = true;
    result.behavioralIndicators.hasRemoteThreads = true;

    result.CalculateOverallRisk();

    EXPECT_EQ(result.overallRiskScore, 100u);
    EXPECT_EQ(result.riskLevel, ProcessRiskLevel::Critical);
}

}  // namespace
