/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/TimeBasedEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(TimeBasedEvasionDetector_Helpers, EnumAndMitreMappingsRemainStable) {
    EXPECT_STREQ("RDTSC High Frequency", TimingEvasionTypeToString(TimingEvasionType::RDTSCHighFrequency));
    EXPECT_STREQ("Sleep Bombing", TimingEvasionTypeToString(TimingEvasionType::SleepBombing));
    EXPECT_STREQ("Unknown", TimingEvasionTypeToString(static_cast<TimingEvasionType>(0xFF)));

    EXPECT_STREQ("", TimingEvasionTypeToMitre(TimingEvasionType::None));
    EXPECT_STREQ("T1497.003", TimingEvasionTypeToMitre(TimingEvasionType::SleepBombing));
    EXPECT_STREQ("T1622", TimingEvasionTypeToMitre(TimingEvasionType::TimingAntiDebug));

    EXPECT_STREQ("Critical", TimingEvasionSeverityToString(TimingEvasionSeverity::Critical));
    EXPECT_STREQ("Unknown", TimingEvasionSeverityToString(static_cast<TimingEvasionSeverity>(0xFF)));
}

TEST(TimeBasedEvasionDetector_ResultHelpers, RiskDurationAndClearBehavePredictably) {
    TimingEvasionResult result;
    result.severity = TimingEvasionSeverity::High;
    result.threatScore = 75.0f;
    result.primaryEvasionType = TimingEvasionType::RDTSCHighFrequency;
    result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::RDTSCHighFrequency));
    result.detectedTypes.set(static_cast<size_t>(TimingEvasionType::SleepBombing));
    result.analysisStartTime = std::chrono::system_clock::time_point{};
    result.analysisEndTime = result.analysisStartTime + std::chrono::milliseconds(1500);
    result.processId = 1337;
    result.processName = L"sample.exe";
    result.processPath = L"C:\\Temp\\sample.exe";
    result.commandLine = L"sample.exe /quiet";
    result.parentProcessId = 4;
    result.mitreIds = { "T1497.003" };
    result.details = { L"High-frequency RDTSC pattern" };
    result.findings = { TimingEvasionFinding{ .type = TimingEvasionType::RDTSCHighFrequency } };
    result.qpcCallCount = 3;
    result.eventsAnalyzed = 8;
    result.errorMessage = L"stale";
    result.analysisComplete = true;

    EXPECT_TRUE(result.HasEvasionType(TimingEvasionType::RDTSCHighFrequency));
    EXPECT_TRUE(result.HasEvasionType(TimingEvasionType::SleepBombing));
    EXPECT_FALSE(result.HasEvasionType(TimingEvasionType::NTPQuery));
    EXPECT_EQ(2u, result.GetEvasionTypeCount());
    EXPECT_TRUE(result.IsHighRisk());
    EXPECT_EQ(std::chrono::milliseconds(1500), result.GetAnalysisDuration());

    result.Clear();

    EXPECT_FALSE(result.isEvasive);
    EXPECT_EQ(TimingEvasionSeverity::Info, result.severity);
    EXPECT_EQ(TimingEvasionType::None, result.primaryEvasionType);
    EXPECT_EQ(0u, result.GetEvasionTypeCount());
    EXPECT_TRUE(result.findings.empty());
    EXPECT_TRUE(result.details.empty());
    EXPECT_TRUE(result.mitreIds.empty());
    EXPECT_EQ("TA0005", result.mitreTactic);
    EXPECT_TRUE(result.processName.empty());
    EXPECT_TRUE(result.processPath.empty());
    EXPECT_TRUE(result.commandLine.empty());
    EXPECT_EQ(0u, result.parentProcessId);
    EXPECT_EQ(0u, result.qpcCallCount);
    EXPECT_EQ(0u, result.eventsAnalyzed);
    EXPECT_TRUE(result.errorMessage.empty());
    EXPECT_FALSE(result.analysisComplete);
}

TEST(TimeBasedEvasionDetector_ResultHelpers, HighThreatScoreTriggersHighRiskEvenAtInfoSeverity) {
    TimingEvasionResult result;
    result.severity = TimingEvasionSeverity::Info;
    result.threatScore = 70.0f;
    EXPECT_TRUE(result.IsHighRisk());

    result.threatScore = 69.9f;
    EXPECT_FALSE(result.IsHighRisk());
}

TEST(TimeBasedEvasionDetector_ConfigAndStats, FactoryMethodsAndStatisticsRemainStable) {
    const TimingDetectorConfig defaultConfig = TimingDetectorConfig::CreateDefault();
    EXPECT_TRUE(defaultConfig.enabled);
    EXPECT_TRUE(defaultConfig.includeEventDetails);
    EXPECT_FALSE(defaultConfig.detectSideChannels);

    const TimingDetectorConfig highSensitivity = TimingDetectorConfig::CreateHighSensitivity();
    EXPECT_EQ(1000u, highSensitivity.rdtscFrequencyThreshold);
    EXPECT_EQ(10000u, highSensitivity.sleepEvasionThresholdMs);
    EXPECT_DOUBLE_EQ(0.3, highSensitivity.sleepAccelerationThreshold);
    EXPECT_FLOAT_EQ(5.0f, highSensitivity.minReportableConfidence);
    EXPECT_TRUE(highSensitivity.detectSideChannels);
    EXPECT_TRUE(highSensitivity.includeEvidence);

    const TimingDetectorConfig performance = TimingDetectorConfig::CreatePerformanceOptimized();
    EXPECT_EQ(std::chrono::milliseconds(500), performance.sampleInterval);
    EXPECT_EQ(10000u, performance.maxEventsPerProcess);
    EXPECT_FALSE(performance.detectSideChannels);
    EXPECT_FALSE(performance.includeEventDetails);
    EXPECT_FALSE(performance.includeEvidence);

    TimingDetectorStats stats;
    stats.cacheHits = 3;
    stats.cacheMisses = 1;
    stats.totalProcessesAnalyzed = 5;
    stats.totalEventsProcessed = 12;
    stats.totalEvasionsDetected = 2;
    stats.detectionsByType[static_cast<size_t>(TimingEvasionType::SleepBombing)] = 1;

    EXPECT_DOUBLE_EQ(0.75, stats.GetCacheHitRatio());

    stats.Reset();

    EXPECT_EQ(0u, stats.totalProcessesAnalyzed.load());
    EXPECT_EQ(0u, stats.totalEventsProcessed.load());
    EXPECT_EQ(0u, stats.totalEvasionsDetected.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_DOUBLE_EQ(0.0, stats.GetCacheHitRatio());
    EXPECT_EQ(0u, stats.detectionsByType[static_cast<size_t>(TimingEvasionType::SleepBombing)].load());
}

} // namespace ShadowStrike::AntiEvasion::Tests
