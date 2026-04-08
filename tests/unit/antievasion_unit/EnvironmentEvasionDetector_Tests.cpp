/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/AntiEvasion/EnvironmentEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(EnvironmentEvasionDetector_Helpers, TechniqueMetadataMappingsRemainStable) {
    EXPECT_STREQ("T1082", EnvironmentTechniqueToMitreId(EnvironmentEvasionTechnique::NAME_BlacklistedUsername));
    EXPECT_STREQ("T1497.001", EnvironmentTechniqueToMitreId(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor));

    EXPECT_EQ(EnvironmentEvasionCategory::NameChecks,
        GetTechniqueCategory(EnvironmentEvasionTechnique::NAME_BlacklistedUsername));
    EXPECT_EQ(EnvironmentEvasionCategory::DisplayConfiguration,
        GetTechniqueCategory(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor));

    EXPECT_EQ(EnvironmentEvasionSeverity::Critical,
        GetDefaultTechniqueSeverity(EnvironmentEvasionTechnique::NAME_BlacklistedUsername));
    EXPECT_EQ(EnvironmentEvasionSeverity::Low,
        GetDefaultTechniqueSeverity(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor));
}

TEST(EnvironmentEvasionDetector_Helpers, TechniqueStringTranslationReturnsStableLabels) {
    EXPECT_STREQ(L"Blacklisted Username Detected",
        EnvironmentTechniqueToString(EnvironmentEvasionTechnique::NAME_BlacklistedUsername));
    EXPECT_STREQ(L"Single Monitor Only",
        EnvironmentTechniqueToString(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor));
    EXPECT_STREQ(L"Unknown Technique",
        EnvironmentTechniqueToString(static_cast<EnvironmentEvasionTechnique>(0xFFFF)));
}

TEST(EnvironmentEvasionDetector_Builder, DetectionBuilderPopulatesDerivedMetadata) {
    const auto detection = EnvironmentDetectionBuilder{}
        .Technique(EnvironmentEvasionTechnique::NAME_BlacklistedUsername)
        .Confidence(0.91)
        .DetectedValue(L"malware")
        .ExpectedValue(L"enterprise workstation username")
        .Description(L"Known sandbox username pattern observed")
        .Source(L"UnitTest")
        .Build();

    EXPECT_EQ(EnvironmentEvasionTechnique::NAME_BlacklistedUsername, detection.technique);
    EXPECT_EQ(GetTechniqueCategory(EnvironmentEvasionTechnique::NAME_BlacklistedUsername), detection.category);
    EXPECT_EQ(GetDefaultTechniqueSeverity(EnvironmentEvasionTechnique::NAME_BlacklistedUsername), detection.severity);
    EXPECT_STREQ(EnvironmentTechniqueToMitreId(EnvironmentEvasionTechnique::NAME_BlacklistedUsername),
        detection.mitreId.c_str());
    EXPECT_DOUBLE_EQ(0.91, detection.confidence);
    EXPECT_EQ(L"malware", detection.detectedValue);
    EXPECT_EQ(L"enterprise workstation username", detection.expectedValue);
    EXPECT_EQ(L"Known sandbox username pattern observed", detection.description);
    EXPECT_EQ(L"UnitTest", detection.source);
    EXPECT_GT(detection.detectionTime, std::chrono::system_clock::time_point{});
}

TEST(EnvironmentEvasionDetector_Statistics, ResetClearsCounters) {
    EnvironmentEvasionDetector::Statistics stats;
    stats.totalAnalyses = 11;
    stats.evasiveProcesses = 5;
    stats.totalDetections = 19;
    stats.cacheHits = 4;
    stats.cacheMisses = 7;
    stats.analysisErrors = 2;
    stats.totalAnalysisTimeUs = 8200;
    stats.categoryDetections[static_cast<size_t>(EnvironmentEvasionCategory::DisplayConfiguration)] = 3;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalAnalyses.load());
    EXPECT_EQ(0u, stats.evasiveProcesses.load());
    EXPECT_EQ(0u, stats.totalDetections.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_EQ(0u, stats.totalAnalysisTimeUs.load());

    for (const auto& categoryCounter : stats.categoryDetections) {
        EXPECT_EQ(0u, categoryCounter.load());
    }
}

} // namespace ShadowStrike::AntiEvasion::Tests
