/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/TimeBasedEvasionDetector.hpp"
#include "../../../src/PhantomCore/Utils/CpuFeatures.hpp"

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

// ============================================================================
// Host timing profile
//
// This is the consumer for the host-probing routines in
// TimeBasedEvasionDetector_x64.asm. Before it existed all eight had no caller, so
// neither the assembly nor its /ALTERNATENAME fallback ever executed.
//
// The assertions below hold for either implementation, which is deliberate: the
// contract belongs to the profile, not to whichever body the linker selected.
// ============================================================================

TEST(TimeBasedEvasionDetector_HostProfile, IsMeasuredOnceAndIsStable) {
    const HostTimingProfile& first  = TimeBasedEvasionDetector::GetHostTimingProfile();
    const HostTimingProfile& second = TimeBasedEvasionDetector::GetHostTimingProfile();

    // The SAME object must come back. Re-measuring per call would put CPUID - which traps
    // to the hypervisor on a virtualised host - on every caller's path, for values that
    // cannot change during the process lifetime.
    EXPECT_EQ(&first, &second);

    EXPECT_EQ(first.rawRdtscOverheadCycles,        second.rawRdtscOverheadCycles);
    EXPECT_EQ(first.serializedRdtscOverheadCycles, second.serializedRdtscOverheadCycles);
    EXPECT_EQ(first.cpuidLatencyCycles,            second.cpuidLatencyCycles);
    EXPECT_EQ(first.hypervisorPresent,             second.hypervisorPresent);
    EXPECT_EQ(first.hypervisorVendor,              second.hypervisorVendor);
}

TEST(TimeBasedEvasionDetector_HostProfile, ProbesReturnRealMeasurements) {
    const HostTimingProfile& p = TimeBasedEvasionDetector::GetHostTimingProfile();

    // A probe returning zero did not run. RDTSC and CPUID both cost cycles on every x64
    // processor, so zero here means the routine was never reached rather than that the
    // machine is infinitely fast.
    EXPECT_GT(p.rawRdtscOverheadCycles, 0u);
    EXPECT_GT(p.cpuidLatencyCycles, 0u);
    EXPECT_GT(p.instructionSequenceCycles, 0u);

    // CPUID serializes and traps under a hypervisor; RDTSC does neither. CPUID therefore
    // costs strictly more, on bare metal and in a VM alike. This is the assertion that
    // distinguishes the two probes from one another - without it, both returning the same
    // wrong value would still pass the non-zero checks above.
    EXPECT_GT(p.cpuidLatencyCycles, p.rawRdtscOverheadCycles);

    // Sanity ceiling. These are cycle counts for short sequences, not wall-clock figures;
    // a value this large would mean the routine returned something other than cycles.
    EXPECT_LT(p.rawRdtscOverheadCycles, 10ull * 1000ull * 1000ull);
    EXPECT_LT(p.cpuidLatencyCycles,     10ull * 1000ull * 1000ull);
}

TEST(TimeBasedEvasionDetector_HostProfile, RdtscpFieldsAreGatedOnAvailability) {
    const HostTimingProfile& p = TimeBasedEvasionDetector::GetHostTimingProfile();

    EXPECT_EQ(p.rdtscpAvailable, Utils::CpuFeatures::HasRDTSCP())
        << "the profile must agree with the feature probe, otherwise a consumer cannot "
           "tell whether rdtscpMinusRdtscCycles was measured or merely left at zero";

    if (!p.rdtscpAvailable) {
        EXPECT_EQ(0, p.rdtscpMinusRdtscCycles)
            << "RDTSCP raises #UD where the processor does not implement it, so the "
               "comparison must not have been attempted";
    }
}

TEST(TimeBasedEvasionDetector_HostProfile, HypervisorVendorIsConsistentWithPresence) {
    const HostTimingProfile& p = TimeBasedEvasionDetector::GetHostTimingProfile();

    if (!p.hypervisorPresent) {
        EXPECT_TRUE(p.hypervisorVendor.empty())
            << "a vendor string with no hypervisor reported would be a fabricated value";
    } else {
        // CPUID leaf 0x40000000 yields at most 12 vendor bytes across EBX/ECX/EDX.
        EXPECT_LE(p.hypervisorVendor.size(), 12u);
        EXPECT_FALSE(p.hypervisorVendor.empty())
            << "a reported hypervisor should carry its vendor string";
    }
}

} // namespace ShadowStrike::AntiEvasion::Tests
