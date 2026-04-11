/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/DebuggerEvasionDetector.hpp"

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

TEST(DebuggerEvasionDetector_ErrorHelpers, FactoryMethodsAndClearPreserveExplicitFailureState) {
    const Error win32Error = Error::FromWin32(ERROR_ACCESS_DENIED, L"OpenProcess");
    EXPECT_TRUE(win32Error.HasError());
    EXPECT_EQ(static_cast<DWORD>(ERROR_ACCESS_DENIED), win32Error.win32Code);
    EXPECT_EQ(0, win32Error.ntStatus);
    EXPECT_EQ(L"OpenProcess", win32Error.context);

    const LONG ntStatus = static_cast<LONG>(0xC0000022L);
    Error ntError = Error::FromNtStatus(ntStatus, L"NtQueryInformationProcess");
    EXPECT_TRUE(ntError.HasError());
    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), ntError.win32Code);
    EXPECT_EQ(ntStatus, ntError.ntStatus);
    EXPECT_EQ(L"NtQueryInformationProcess", ntError.context);

    ntError.message = L"Access denied";
    ntError.Clear();

    EXPECT_FALSE(ntError.HasError());
    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), ntError.win32Code);
    EXPECT_EQ(0, ntError.ntStatus);
    EXPECT_TRUE(ntError.message.empty());
    EXPECT_TRUE(ntError.context.empty());
}

TEST(DebuggerEvasionDetector_ResultHelpers, FilteringAndClearResetAllMutableState) {
    DebuggerEvasionResult result;
    result.targetPid = 4242;
    result.processName = L"sample.exe";
    result.processPath = L"C:\\Temp\\sample.exe";
    result.is64Bit = true;
    result.isEvasive = true;
    result.evasionScore = 88.5;
    result.maxSeverity = EvasionSeverity::Critical;
    result.totalDetections = 3;
    result.detectedCategories =
        (1u << static_cast<uint32_t>(EvasionCategory::TimingBased)) |
        (1u << static_cast<uint32_t>(EvasionCategory::PEBBased)) |
        (1u << static_cast<uint32_t>(EvasionCategory::APIBased));
    result.detectedTechniques = {
        DetectionPatternBuilder{}.Technique(EvasionTechnique::TIMING_RDTSC).Confidence(0.82).Build(),
        DetectionPatternBuilder{}.Technique(EvasionTechnique::PEB_BeingDebugged).Confidence(0.45).Build(),
        DetectionPatternBuilder{}.Technique(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger)
            .Confidence(0.97)
            .Build()
    };
    result.techniquesChecked = 11;
    result.threadsScanned = 4;
    result.memoryRegionsScanned = 8;
    result.handlesEnumerated = 2;
    result.bytesScanned = 4096;
    result.analysisComplete = true;
    result.fromCache = true;
    result.errors.push_back(Error::FromWin32(ERROR_ACCESS_DENIED, L"UnitTest"));

    EXPECT_TRUE(result.HasCategory(EvasionCategory::TimingBased));
    EXPECT_TRUE(result.HasTechnique(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger));
    EXPECT_FALSE(result.HasCategory(EvasionCategory::ThreadBased));
    EXPECT_FALSE(result.HasTechnique(EvasionTechnique::EXCEPTION_INT2D));
    EXPECT_EQ(1u, result.GetCategoryCount(EvasionCategory::TimingBased));
    EXPECT_EQ(0u, result.GetCategoryCount(EvasionCategory::ThreadBased));

    const auto highSeverity = result.GetBySeverity(EvasionSeverity::High);
    ASSERT_EQ(2u, highSeverity.size());
    EXPECT_EQ(EvasionTechnique::TIMING_RDTSC, highSeverity[0]->technique);
    EXPECT_EQ(EvasionTechnique::API_NtSetInformationThread_HideFromDebugger, highSeverity[1]->technique);

    result.Clear();

    EXPECT_EQ(0u, result.targetPid);
    EXPECT_TRUE(result.processName.empty());
    EXPECT_TRUE(result.processPath.empty());
    EXPECT_FALSE(result.is64Bit);
    EXPECT_FALSE(result.isEvasive);
    EXPECT_DOUBLE_EQ(0.0, result.evasionScore);
    EXPECT_EQ(EvasionSeverity::Low, result.maxSeverity);
    EXPECT_EQ(0u, result.totalDetections);
    EXPECT_EQ(0u, result.detectedCategories);
    EXPECT_TRUE(result.detectedTechniques.empty());
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(0u, result.techniquesChecked);
    EXPECT_EQ(0u, result.threadsScanned);
    EXPECT_EQ(0u, result.memoryRegionsScanned);
    EXPECT_EQ(0u, result.handlesEnumerated);
    EXPECT_EQ(0u, result.bytesScanned);
    EXPECT_FALSE(result.analysisComplete);
    EXPECT_FALSE(result.fromCache);
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
