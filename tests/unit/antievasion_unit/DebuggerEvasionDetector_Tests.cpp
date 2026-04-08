/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/AntiEvasion/DebuggerEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(DebuggerEvasionDetector_Helpers, TechniqueMetadataMappingsRemainStable) {
    EXPECT_STREQ("T1622", EvasionTechniqueToMitreId(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_STREQ("T1497.003", EvasionTechniqueToMitreId(EvasionTechnique::TIMING_RDTSC));
    EXPECT_STREQ("T1106", EvasionTechniqueToMitreId(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger));

    EXPECT_EQ(EvasionCategory::PEBBased, GetTechniqueCategory(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_EQ(EvasionCategory::TimingBased, GetTechniqueCategory(EvasionTechnique::TIMING_RDTSC));
    EXPECT_EQ(EvasionCategory::APIBased, GetTechniqueCategory(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger));

    EXPECT_EQ(EvasionSeverity::Medium, GetDefaultTechniqueSeverity(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_EQ(EvasionSeverity::High, GetDefaultTechniqueSeverity(EvasionTechnique::TIMING_RDTSC));
    EXPECT_EQ(EvasionSeverity::Critical, GetDefaultTechniqueSeverity(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger));
}

TEST(DebuggerEvasionDetector_Helpers, TechniqueStringTranslationReturnsStableLabels) {
    EXPECT_STREQ(L"PEB.BeingDebugged", EvasionTechniqueToString(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_STREQ(L"RDTSC Timing Check", EvasionTechniqueToString(EvasionTechnique::TIMING_RDTSC));
    EXPECT_STREQ(L"NtSetInformationThread(HideFromDebugger)",
        EvasionTechniqueToString(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger));
    EXPECT_STREQ(L"Unknown Technique", EvasionTechniqueToString(static_cast<EvasionTechnique>(0xFFFF)));
}

TEST(DebuggerEvasionDetector_Builder, DetectionPatternBuilderPopulatesDerivedFieldsAndPayload) {
    const std::array<uint8_t, 3> rawData{ 0x90, 0xCC, 0xC3 };

    DetectedTechnique detection = DetectionPatternBuilder{}
        .Technique(EvasionTechnique::THREAD_TLSCallback)
        .Confidence(0.94)
        .Address(0x1000)
        .ThreadId(1337)
        .Description(L"TLS callback anti-debug sequence")
        .TechnicalDetails(L"Callback executes before entry point.")
        .RawData(rawData.data(), rawData.size())
        .Build();

    EXPECT_EQ(EvasionTechnique::THREAD_TLSCallback, detection.technique);
    EXPECT_EQ(GetTechniqueCategory(EvasionTechnique::THREAD_TLSCallback), detection.category);
    EXPECT_EQ(GetDefaultTechniqueSeverity(EvasionTechnique::THREAD_TLSCallback), detection.severity);
    EXPECT_STREQ(EvasionTechniqueToMitreId(EvasionTechnique::THREAD_TLSCallback), detection.mitreId.c_str());
    EXPECT_DOUBLE_EQ(0.94, detection.confidence);
    EXPECT_EQ(0x1000u, detection.address);
    EXPECT_EQ(1337u, detection.threadId);
    EXPECT_EQ(L"TLS callback anti-debug sequence", detection.description);
    EXPECT_EQ(L"Callback executes before entry point.", detection.technicalDetails);
    EXPECT_EQ(std::vector<uint8_t>(rawData.begin(), rawData.end()), detection.rawData);
    EXPECT_GT(detection.detectionTime, std::chrono::system_clock::time_point{});
}

TEST(DebuggerEvasionDetector_Statistics, ResetClearsAllCounters) {
    DebuggerEvasionDetector::Statistics stats;
    stats.totalAnalyses = 9;
    stats.evasiveProcesses = 4;
    stats.totalDetections = 12;
    stats.cacheHits = 2;
    stats.cacheMisses = 3;
    stats.analysisErrors = 1;
    stats.totalAnalysisTimeUs = 5000;
    stats.categoryDetections[static_cast<size_t>(EvasionCategory::TimingBased)] = 7;

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
