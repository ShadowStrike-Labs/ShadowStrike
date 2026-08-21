/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/SandboxEvasionDetector.hpp"
#include "../../../src/PhantomCore/Utils/ThreadPool.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(SandboxEvasionDetector_Helpers, EnumAndMitreMappingsRemainStable) {
    EXPECT_STREQ("Cuckoo Sandbox", SandboxProductToString(SandboxProduct::Cuckoo));
    EXPECT_STREQ("Windows Sandbox", SandboxProductToString(SandboxProduct::WindowsSandbox));
    EXPECT_STREQ("Unknown", SandboxProductToString(static_cast<SandboxProduct>(0xFFFF)));

    EXPECT_STREQ("Network", SandboxIndicatorCategoryToString(SandboxIndicatorCategory::Network));
    EXPECT_STREQ("Registry", SandboxIndicatorCategoryToString(SandboxIndicatorCategory::Registry));
    EXPECT_STREQ("Unknown", SandboxIndicatorCategoryToString(static_cast<SandboxIndicatorCategory>(0xFF)));

    EXPECT_STREQ("T1497.001", SandboxCheckToMitre(SandboxCheckType::MouseMovement));
    EXPECT_STREQ("T1497.003", SandboxCheckToMitre(SandboxCheckType::SystemUptime));
    EXPECT_STREQ("T1497.001", SandboxCheckToMitre(SandboxCheckType::SandboxDLLs));
}

TEST(SandboxEvasionDetector_ResultHelpers, SummaryFilteringAndClearBehavePredictably) {
    SandboxEvasionResult result;
    result.isSandboxLikely = true;
    result.identifiedSandbox = SandboxProduct::Cuckoo;
    result.sandboxName = L"Cuckoo Sandbox";
    result.probability = 87.0f;
    result.confidence = 93.0f;
    result.failedChecks = 2;
    result.passedChecks = 3;
    result.totalChecks = 5;

    result.indicators.push_back(SandboxIndicator{
        .checkType = SandboxCheckType::SandboxDLLs,
        .category = SandboxIndicatorCategory::Artifact,
        .severity = SandboxIndicatorSeverity::High,
        .description = L"Known sandbox DLL loaded"
    });
    result.indicators.push_back(SandboxIndicator{
        .checkType = SandboxCheckType::MouseMovement,
        .category = SandboxIndicatorCategory::HumanInteraction,
        .severity = SandboxIndicatorSeverity::Low,
        .description = L"Limited user interaction"
    });
    result.indicators.push_back(SandboxIndicator{
        .checkType = SandboxCheckType::HookDetection,
        .category = SandboxIndicatorCategory::Environment,
        .severity = SandboxIndicatorSeverity::Critical,
        .description = L"User-mode hooks detected"
    });

    const std::wstring summary = result.GetSummary();
    EXPECT_NE(std::wstring::npos, summary.find(L"SANDBOX DETECTED"));
    EXPECT_NE(std::wstring::npos, summary.find(L"Cuckoo Sandbox"));
    EXPECT_NE(std::wstring::npos, summary.find(L"87%"));

    EXPECT_TRUE(result.HasCategoryIssues(SandboxIndicatorCategory::Artifact));
    EXPECT_TRUE(result.HasCategoryIssues(SandboxIndicatorCategory::Environment));
    EXPECT_FALSE(result.HasCategoryIssues(SandboxIndicatorCategory::HumanInteraction));

    EXPECT_EQ(1u, result.GetIndicatorCount(SandboxIndicatorCategory::Artifact));
    EXPECT_EQ(1u, result.GetIndicatorCount(SandboxIndicatorCategory::HumanInteraction));
    EXPECT_EQ(0u, result.GetIndicatorCount(SandboxIndicatorCategory::Kernel));

    const auto highest = result.GetHighestSeverityIndicator();
    ASSERT_TRUE(highest.has_value());
    EXPECT_EQ(SandboxIndicatorSeverity::Critical, highest->severity);
    EXPECT_EQ(SandboxCheckType::HookDetection, highest->checkType);

    result.Clear();

    EXPECT_FALSE(result.isSandboxLikely);
    EXPECT_EQ(0.0f, result.probability);
    EXPECT_EQ(0.0f, result.confidence);
    EXPECT_EQ(SandboxProduct::Unknown, result.identifiedSandbox);
    EXPECT_TRUE(result.indicators.empty());
    EXPECT_TRUE(result.sandboxName.empty());
    EXPECT_EQ(0u, result.totalChecks);
    EXPECT_FALSE(result.GetHighestSeverityIndicator().has_value());
}

TEST(SandboxEvasionDetector_Config, FactoryMethodsEncodeExpectedTradeoffs) {
    const SandboxDetectorConfig defaultConfig = SandboxDetectorConfig::CreateDefault();
    EXPECT_TRUE(defaultConfig.enabled);
    EXPECT_TRUE(defaultConfig.checkHumanInteraction);
    EXPECT_TRUE(defaultConfig.checkNetwork);
    EXPECT_TRUE(defaultConfig.checkFileSystem);

    const SandboxDetectorConfig highSensitivity = SandboxDetectorConfig::CreateHighSensitivity();
    EXPECT_FLOAT_EQ(40.0f, highSensitivity.probabilityThreshold);
    EXPECT_EQ(8ULL * 1024 * 1024 * 1024, highSensitivity.minRAM);
    EXPECT_EQ(4u, highSensitivity.minCPUCores);
    EXPECT_EQ(120ULL * 1024 * 1024 * 1024, highSensitivity.minDiskSize);
    EXPECT_EQ(20u, highSensitivity.minRecentDocuments);
    EXPECT_EQ(50u, highSensitivity.minInstalledPrograms);

    const SandboxDetectorConfig fastConfig = SandboxDetectorConfig::CreateFast();
    EXPECT_FALSE(fastConfig.checkHumanInteraction);
    EXPECT_FALSE(fastConfig.checkNetwork);
    EXPECT_FALSE(fastConfig.checkFileSystem);
    EXPECT_FALSE(fastConfig.checkWearAndTear);
    EXPECT_TRUE(fastConfig.checkHardware);
    EXPECT_TRUE(fastConfig.checkArtifacts);
}

TEST(SandboxEvasionDetector_Statistics, ResetClearsCountersAndProductDistribution) {
    SandboxDetectorStats stats;
    stats.totalScans = 12;
    stats.sandboxesDetected = 5;
    stats.definitiveDetections = 2;
    stats.humanInteractionChecks = 7;
    stats.cacheHits = 3;
    stats.cacheMisses = 4;
    stats.avgAnalysisDurationUs = 2500;
    stats.detectionsByProduct[static_cast<size_t>(SandboxProduct::Cuckoo)] = 2;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalScans.load());
    EXPECT_EQ(0u, stats.sandboxesDetected.load());
    EXPECT_EQ(0u, stats.definitiveDetections.load());
    EXPECT_EQ(0u, stats.humanInteractionChecks.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.avgAnalysisDurationUs.load());
    EXPECT_EQ(0u, stats.detectionsByProduct[static_cast<size_t>(SandboxProduct::Cuckoo)].load());
}

// ---------------------------------------------------------------------------
// Target (TYPE B) analysis: the half of this module that examines a supplied
// process rather than the machine we run on. It is the product's only producer
// of T1012 and T1057, and until it was wired into the deferred deep-scan thread
// it had no caller at all.
// ---------------------------------------------------------------------------

TEST(SandboxEvasionDetector_ProcessConfig, DefaultsAreTheOnesTheDeferredPathRelisOn) {
    // The deferred deep-scan thread deliberately runs this analysis at SHIPPED
    // DEFAULTS, because nothing waits on that thread and narrowing the scan is
    // what would give up the unpacked-content coverage that makes deferring it
    // worthwhile. Lowering either bound would silently narrow that coverage, so
    // the values are pinned here rather than left to be noticed in the field.
    const SandboxEvasionDetector::ProcessSandboxConfig defaults{};

    EXPECT_TRUE(defaults.checkImports);
    EXPECT_TRUE(defaults.checkMemoryStrings);
    EXPECT_TRUE(defaults.checkCodePatterns);
    EXPECT_EQ(64ULL * 1024 * 1024, defaults.maxMemoryScanBytes);
    EXPECT_EQ(4ULL * 1024 * 1024, defaults.maxCodeScanBytes);
}

TEST(SandboxEvasionDetector_TargetAnalysis, IsReachableAndReportsItsOwnCost) {
    // REACHABILITY IS THE POINT OF THIS TEST. The analysis had zero production
    // callers, and a detector nothing calls is indistinguishable from one that
    // finds nothing. Asserting it runs against a real process and reports a
    // duration is what makes the restored path observable from the suite.
    //
    // Imports only, deliberately: the full default configuration measured about
    // 367 ms per call against a live process, and this suite must not pay that.
    // The pool is CONSTRUCTED BUT NOT STARTED, and that is deliberate rather than
    // sloppy. Initialize only requires a non-null pool, and the target analysis
    // never submits to it - it opens the process and reads it on the calling
    // thread. Starting one costs several seconds in worker creation and join for a
    // dependency this code path does not use, and this suite already has runtime
    // problems worth not adding to. If the analysis ever does submit work, the
    // pool will refuse it loudly rather than silently dropping it, which is the
    // behaviour a started-but-unused pool would hide.
    auto pool = std::make_shared<::ShadowStrike::Utils::ThreadPool>();

    auto& detector = SandboxEvasionDetector::Instance();
    ASSERT_TRUE(detector.Initialize(pool));

    SandboxEvasionDetector::ProcessSandboxConfig config{};
    config.checkMemoryStrings = false;
    config.checkCodePatterns = false;

    SandboxEvasionDetector::ProcessSandboxResult result{};
    const bool analysed =
        detector.AnalyzeProcess(::GetCurrentProcessId(), result, config);

    EXPECT_TRUE(analysed) << "the target analysis must be able to examine a live "
                             "process we own; if this fails the restored feed "
                             "cannot produce anything";
    if (analysed) {
        EXPECT_EQ(::GetCurrentProcessId(), result.processId);
        EXPECT_GT(result.analysisDurationUs, 0ULL)
            << "the analysis must record its own cost - that field is how the "
               "deferred path's expense stays visible";
        // NOT an assertion about this binary's contents: a clean result and a
        // detection are both legitimate outcomes here. What must hold is that the
        // score and the capability flag agree with each other.
        EXPECT_EQ(result.hasEvasionCapability, result.evasionScore >= 25.0f);
    }

    detector.Shutdown();
}
} // namespace ShadowStrike::AntiEvasion::Tests
