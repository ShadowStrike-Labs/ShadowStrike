/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/AntiEvasion/ProcessEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion {
const wchar_t* ProcessEvasionTechniqueToString(ProcessEvasionTechnique technique) noexcept;
const wchar_t* InjectionMethodToString(InjectionMethod method) noexcept;
const char* ProcessEvasionTechniqueToMitreId(ProcessEvasionTechnique technique) noexcept;
}

namespace ShadowStrike::AntiEvasion::Tests {

TEST(ProcessEvasionDetector_Flags, OperatorsAndKernelContextBehaveAsDesigned) {
    constexpr ProcessAnalysisFlags customFlags =
        ProcessAnalysisFlags::CheckInjection |
        ProcessAnalysisFlags::CheckAntiDebug |
        ProcessAnalysisFlags::EnableCaching;

    EXPECT_TRUE(HasFlag(customFlags, ProcessAnalysisFlags::CheckInjection));
    EXPECT_TRUE(HasFlag(customFlags, ProcessAnalysisFlags::CheckAntiDebug));
    EXPECT_TRUE(HasFlag(customFlags, ProcessAnalysisFlags::EnableCaching));
    EXPECT_FALSE(HasFlag(customFlags, ProcessAnalysisFlags::CheckMasquerading));

    EXPECT_TRUE(HasFlag(ProcessAnalysisFlags::Default, ProcessAnalysisFlags::CheckInjection));
    EXPECT_TRUE(HasFlag(ProcessAnalysisFlags::Default, ProcessAnalysisFlags::CheckMasquerading));
    EXPECT_TRUE(HasFlag(ProcessAnalysisFlags::Default, ProcessAnalysisFlags::CheckAntiDebug));
    EXPECT_TRUE(HasFlag(ProcessAnalysisFlags::Default, ProcessAnalysisFlags::EnableCaching));

    ProcessKernelContext emptyContext;
    EXPECT_FALSE(emptyContext.hasKernelData());

    ProcessKernelContext parentOnlyContext;
    parentOnlyContext.parentProcessId = 4;
    EXPECT_TRUE(parentOnlyContext.hasKernelData());
}

TEST(ProcessEvasionDetector_Helpers, StringAndMitreMappingsRemainStable) {
    EXPECT_STREQ(L"Classic DLL Injection",
        ProcessEvasionTechniqueToString(ProcessEvasionTechnique::INJ_ClassicDLLInjection));
    EXPECT_STREQ(L"Process Path Anomaly",
        ProcessEvasionTechniqueToString(ProcessEvasionTechnique::MASK_PathAnomaly));
    EXPECT_STREQ(L"IsDebuggerPresent Check",
        ProcessEvasionTechniqueToString(ProcessEvasionTechnique::ANTI_IsDebuggerPresent));
    EXPECT_STREQ(L"Temporary Process Creation",
        ProcessEvasionTechniqueToString(ProcessEvasionTechnique::ENUM_TemporaryProcessCreation));
    EXPECT_STREQ(L"Unknown",
        ProcessEvasionTechniqueToString(static_cast<ProcessEvasionTechnique>(0xFFFF)));

    EXPECT_STREQ(L"Classic DLL Injection", InjectionMethodToString(InjectionMethod::ClassicDLL));
    EXPECT_STREQ(L"Process Herpaderping", InjectionMethodToString(InjectionMethod::Herpaderping));
    EXPECT_STREQ(L"Unknown", InjectionMethodToString(static_cast<InjectionMethod>(0xFF)));

    EXPECT_STREQ("T1055", ProcessEvasionTechniqueToMitreId(ProcessEvasionTechnique::INJ_ClassicDLLInjection));
    EXPECT_STREQ("T1036.005", ProcessEvasionTechniqueToMitreId(ProcessEvasionTechnique::MASK_PathAnomaly));
    EXPECT_STREQ("T1622", ProcessEvasionTechniqueToMitreId(ProcessEvasionTechnique::ANTI_IsDebuggerPresent));
    EXPECT_STREQ("T1055", ProcessEvasionTechniqueToMitreId(static_cast<ProcessEvasionTechnique>(0xFFFF)));
}

TEST(ProcessEvasionDetector_ResultHelpers, GetHighestConfidenceReturnsMostConfidentTechnique) {
    ProcessEvasionResult emptyResult;
    EXPECT_EQ(nullptr, emptyResult.GetHighestConfidence());

    ProcessEvasionResult result;
    result.detectedTechniques = {
        ProcessDetectedTechnique{ ProcessEvasionTechnique::ANTI_IsDebuggerPresent },
        ProcessDetectedTechnique{ ProcessEvasionTechnique::MASK_PathAnomaly },
        ProcessDetectedTechnique{ ProcessEvasionTechnique::INJ_ClassicDLLInjection }
    };

    result.detectedTechniques[0].confidence = 0.42;
    result.detectedTechniques[1].confidence = 0.91;
    result.detectedTechniques[2].confidence = 0.75;

    const ProcessDetectedTechnique* highest = result.GetHighestConfidence();
    ASSERT_NE(nullptr, highest);
    EXPECT_EQ(ProcessEvasionTechnique::MASK_PathAnomaly, highest->technique);
    EXPECT_DOUBLE_EQ(0.91, highest->confidence);
}

TEST(ProcessEvasionDetector_Statistics, ResetAndAverageAnalysisTimeBehaveCorrectly) {
    ProcessEvasionDetector::Statistics stats;
    stats.totalAnalyses = 4;
    stats.evasiveProcesses = 2;
    stats.injectionsDetected = 1;
    stats.masqueradingDetected = 1;
    stats.antiDebugDetected = 2;
    stats.totalDetections = 7;
    stats.cacheHits = 3;
    stats.cacheMisses = 1;
    stats.analysisErrors = 1;
    stats.totalAnalysisTimeUs = 5000;
    stats.categoryDetections[0] = 2;

    EXPECT_DOUBLE_EQ(1.25, stats.GetAverageAnalysisTimeMs());

    stats.Reset();

    EXPECT_EQ(0u, stats.totalAnalyses.load());
    EXPECT_EQ(0u, stats.evasiveProcesses.load());
    EXPECT_EQ(0u, stats.injectionsDetected.load());
    EXPECT_EQ(0u, stats.masqueradingDetected.load());
    EXPECT_EQ(0u, stats.antiDebugDetected.load());
    EXPECT_EQ(0u, stats.totalDetections.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_EQ(0u, stats.totalAnalysisTimeUs.load());
    EXPECT_DOUBLE_EQ(0.0, stats.GetAverageAnalysisTimeMs());

    for (const auto& categoryCounter : stats.categoryDetections) {
        EXPECT_EQ(0u, categoryCounter.load());
    }
}

} // namespace ShadowStrike::AntiEvasion::Tests
