/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/EnvironmentEvasionDetector.hpp"

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

TEST(EnvironmentEvasionDetector_ErrorHelpers, FactoryMethodsAndClearPreserveFailureState) {
    const EnvironmentError win32Error = EnvironmentError::FromWin32(ERROR_FILE_NOT_FOUND, L"CheckFileSystemArtifacts");
    EXPECT_TRUE(win32Error.HasError());
    EXPECT_EQ(static_cast<DWORD>(ERROR_FILE_NOT_FOUND), win32Error.win32Code);
    EXPECT_EQ(0, win32Error.ntStatus);
    EXPECT_EQ(L"CheckFileSystemArtifacts", win32Error.context);

    EnvironmentError error;
    error.win32Code = ERROR_ACCESS_DENIED;
    error.ntStatus = static_cast<LONG>(0xC0000022L);
    error.message = L"Access denied";
    error.context = L"AnalyzeProcess";
    EXPECT_TRUE(error.HasError());

    error.Clear();

    EXPECT_FALSE(error.HasError());
    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), error.win32Code);
    EXPECT_EQ(0, error.ntStatus);
    EXPECT_TRUE(error.message.empty());
    EXPECT_TRUE(error.context.empty());
}

TEST(EnvironmentEvasionDetector_ResultHelpers, FilteringAndClearResetAllMutableState) {
    EnvironmentEvasionResult result;
    result.targetPid = 31337;
    result.processName = L"sample.exe";
    result.processPath = L"C:\\Temp\\sample.exe";
    result.isEvasive = true;
    result.evasionScore = 91.0;
    result.maxSeverity = EnvironmentEvasionSeverity::Critical;
    result.totalDetections = 3;
    result.detectedCategories =
        (1u << static_cast<uint32_t>(EnvironmentEvasionCategory::NameChecks)) |
        (1u << static_cast<uint32_t>(EnvironmentEvasionCategory::DisplayConfiguration)) |
        (1u << static_cast<uint32_t>(EnvironmentEvasionCategory::TimingChecks));
    result.detectedTechniques = {
        EnvironmentDetectionBuilder{}
            .Technique(EnvironmentEvasionTechnique::NAME_BlacklistedUsername)
            .Confidence(0.95)
            .Build(),
        EnvironmentDetectionBuilder{}
            .Technique(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor)
            .Confidence(0.37)
            .Build(),
        EnvironmentDetectionBuilder{}
            .Technique(EnvironmentEvasionTechnique::TIMING_ShortUptime)
            .Confidence(0.81)
            .Severity(EnvironmentEvasionSeverity::High)
            .Build()
    };
    result.categoriesChecked = 6;
    result.techniquesChecked = 9;
    result.registryKeysChecked = 2;
    result.filesChecked = 4;
    result.processesChecked = 3;
    result.analysisComplete = true;
    result.fromCache = true;
    result.errors.push_back(EnvironmentError::FromWin32(ERROR_ACCESS_DENIED, L"UnitTest"));

    EXPECT_TRUE(result.HasCategory(EnvironmentEvasionCategory::NameChecks));
    EXPECT_TRUE(result.HasTechnique(EnvironmentEvasionTechnique::TIMING_ShortUptime));
    EXPECT_FALSE(result.HasCategory(EnvironmentEvasionCategory::BrowserArtifacts));
    EXPECT_FALSE(result.HasTechnique(EnvironmentEvasionTechnique::BROWSER_NoHistory));
    EXPECT_EQ(1u, result.GetCategoryCount(EnvironmentEvasionCategory::DisplayConfiguration));
    EXPECT_EQ(0u, result.GetCategoryCount(EnvironmentEvasionCategory::BrowserArtifacts));

    const auto highSeverity = result.GetBySeverity(EnvironmentEvasionSeverity::High);
    ASSERT_EQ(2u, highSeverity.size());
    EXPECT_EQ(EnvironmentEvasionTechnique::NAME_BlacklistedUsername, highSeverity[0]->technique);
    EXPECT_EQ(EnvironmentEvasionTechnique::TIMING_ShortUptime, highSeverity[1]->technique);

    result.Clear();

    EXPECT_EQ(0u, result.targetPid);
    EXPECT_TRUE(result.processName.empty());
    EXPECT_TRUE(result.processPath.empty());
    EXPECT_FALSE(result.isEvasive);
    EXPECT_DOUBLE_EQ(0.0, result.evasionScore);
    EXPECT_EQ(EnvironmentEvasionSeverity::Low, result.maxSeverity);
    EXPECT_EQ(0u, result.totalDetections);
    EXPECT_EQ(0u, result.detectedCategories);
    EXPECT_TRUE(result.detectedTechniques.empty());
    EXPECT_TRUE(result.vmIndicators.empty());
    EXPECT_TRUE(result.sandboxIndicators.empty());
    EXPECT_TRUE(result.analysisToolIndicators.empty());
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(0u, result.categoriesChecked);
    EXPECT_EQ(0u, result.techniquesChecked);
    EXPECT_EQ(0u, result.registryKeysChecked);
    EXPECT_EQ(0u, result.filesChecked);
    EXPECT_EQ(0u, result.processesChecked);
    EXPECT_FALSE(result.analysisComplete);
    EXPECT_FALSE(result.fromCache);
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

// ============================================================================
// Host context accessors
//
// Consumers for the host-subject routines in EnvironmentEvasionDetector_x64.asm,
// which had no caller before they existed. Same contract as
// TimeBasedEvasionDetector::GetHostTimingProfile: context only, never a verdict.
// The lifecycles differ because the subjects do - processor facts are invariant
// and cached, self debug state is volatile and sampled fresh.
// ============================================================================

TEST(EnvironmentEvasionDetector_HostFacts, ProcessorFactsAreMeasuredOnceAndStable) {
    const HostProcessorFacts& first  = EnvironmentEvasionDetector::GetHostProcessorFacts();
    const HostProcessorFacts& second = EnvironmentEvasionDetector::GetHostProcessorFacts();

    EXPECT_EQ(&first, &second)
        << "processor facts are invariant, so the accessor must cache them rather than "
           "re-issuing CPUID - which traps to the hypervisor - on every caller";
    EXPECT_EQ(first.extendedCpuidMaxLeaf, second.extendedCpuidMaxLeaf);
    EXPECT_EQ(first.cpuidFeaturesEdx, second.cpuidFeaturesEdx);
}

TEST(EnvironmentEvasionDetector_HostFacts, ProcessorFactsAgreeWithTheArchitecture) {
    const HostProcessorFacts& f = EnvironmentEvasionDetector::GetHostProcessorFacts();

    // SSE2 is architecturally guaranteed on x64. A false here means the probe did not run
    // rather than that the processor lacks it.
    EXPECT_TRUE(f.sse2Supported);

    // Leaf 0x80000000 reports the highest extended leaf; every x64 processor implements at
    // least 0x80000001, which is where the RDTSCP bit lives.
    EXPECT_GE(f.extendedCpuidMaxLeaf, 0x80000001u);

    // Two INDEPENDENT probes must agree: CheckSSE2Support answers the question directly,
    // while CPUID.01h:EDX bit 26 is the architectural SSE2 bit carried in the feature
    // flags. If these disagree, one of the two routines is reading the wrong register -
    // which no single-probe assertion above could reveal.
    const bool sse2FromFeatureBits = ((f.cpuidFeaturesEdx >> 26) & 1u) != 0u;
    EXPECT_EQ(f.sse2Supported, sse2FromFeatureBits);
}

TEST(EnvironmentEvasionDetector_HostFacts, SelfDebugStateIsInternallyConsistent) {
    const SelfDebugState s = EnvironmentEvasionDetector::SampleSelfDebugState();

    // Deliberately NOT asserting beingDebugged == false: running the suite under a debugger
    // is legitimate, and a test that failed in that case would be testing the environment
    // rather than the code.
    if (s.hardwareBreakpointSet) {
        const bool anyAddress = (s.dr0 | s.dr1 | s.dr2 | s.dr3) != 0ull;
        const bool anyEnable  = (s.dr7 & 0xFFull) != 0ull;
        EXPECT_TRUE(anyAddress || anyEnable)
            << "a hardware breakpoint was reported while every breakpoint address and the "
               "DR7 enable bits are clear, which cannot both be true";
    }
}

TEST(EnvironmentEvasionDetector_HostFacts, SelfDebugStateSamplesRatherThanCaches) {
    // Two immediate samples must agree in a stable environment. This does not by itself
    // prove the accessor re-reads rather than caches - that is a source property and is
    // pinned by the contract suite - but a disagreement here would mean the reads are not
    // reproducible, which would make the field useless either way.
    const SelfDebugState a = EnvironmentEvasionDetector::SampleSelfDebugState();
    const SelfDebugState b = EnvironmentEvasionDetector::SampleSelfDebugState();

    EXPECT_EQ(a.beingDebugged, b.beingDebugged);
    EXPECT_EQ(a.processHeapFlags, b.processHeapFlags);
    EXPECT_EQ(a.hardwareBreakpointSet, b.hardwareBreakpointSet);
}

} // namespace ShadowStrike::AntiEvasion::Tests
