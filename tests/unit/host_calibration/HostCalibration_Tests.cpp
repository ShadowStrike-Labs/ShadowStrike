/**
 * @file HostCalibration_Tests.cpp
 * @brief Behavioural contract for EnvironmentEvasionDetector's host-context calibration.
 *
 * WHY THIS SUITE EXISTS. The product carries a deliberate policy: on a host that IS
 * virtualized, a process probing for VM artefacts is materially more likely to be
 * legitimate - VM-aware software, VDI tooling and hypervisor guest agents all do it -
 * so its confidence is reduced. That policy was implemented, correct, and had NEVER
 * ONCE RUN, because it lived only inside AnalyzeSystemInternal and the sole entry
 * that reaches it, AnalyzeSystemEnvironment, has zero callers anywhere in src or
 * tests. Meanwhile the live per-creation path reported those probes at full
 * confidence on VM hosts - the opposite of the policy's purpose.
 *
 * The calibration is a pure public static specifically so it can be tested with BOTH
 * host states on any build machine, regardless of whether that machine is itself a
 * VM. A policy nobody can test is a policy nobody can verify.
 *
 * THE INVARIANT THAT MATTERS MOST is that calibration never removes a finding. It
 * adjusts a confidence number and nothing else. If a confidence gate is ever
 * introduced upstream, these tests are where that interaction must be reconsidered.
 */

#include <gtest/gtest.h>

#include "PhantomCore/AntiEvasion/EnvironmentEvasionDetector.hpp"

namespace {

using ShadowStrike::AntiEvasion::EnvironmentEvasionCategory;
using ShadowStrike::AntiEvasion::EnvironmentDetectedTechnique;
using ShadowStrike::AntiEvasion::EnvironmentEvasionDetector;

[[nodiscard]] EnvironmentDetectedTechnique MakeDetection(
    EnvironmentEvasionCategory category, double confidence) {
    EnvironmentDetectedTechnique detection;
    detection.category = category;
    detection.confidence = confidence;
    detection.description = L"synthetic detection for calibration contract";
    return detection;
}

constexpr double kVmReductionFactor = 0.6;

// ---------------------------------------------------------------------------
// The three VM-artefact categories ARE calibrated on a virtualized host.
// ---------------------------------------------------------------------------

TEST(HostContextCalibrationTest, HardwareProbeIsReducedOnAVirtualizedHost) {
    auto detection = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 0.9);
    EnvironmentEvasionDetector::CalibrateForHostContext(detection, /*hostIsVirtualized=*/true);

    EXPECT_DOUBLE_EQ(detection.confidence, 0.9 * kVmReductionFactor)
        << "on a VM host, hardware fingerprinting is what VM-aware software does, so "
           "its confidence must be reduced rather than reported at full weight";
}

TEST(HostContextCalibrationTest, RegistryAndFileSystemProbesAreAlsoReduced) {
    auto reg = MakeDetection(EnvironmentEvasionCategory::RegistryArtifacts, 0.8);
    auto fs = MakeDetection(EnvironmentEvasionCategory::FileSystemArtifacts, 0.8);

    EnvironmentEvasionDetector::CalibrateForHostContext(reg, true);
    EnvironmentEvasionDetector::CalibrateForHostContext(fs, true);

    EXPECT_DOUBLE_EQ(reg.confidence, 0.8 * kVmReductionFactor);
    EXPECT_DOUBLE_EQ(fs.confidence, 0.8 * kVmReductionFactor);
}

// ---------------------------------------------------------------------------
// Everything else is left alone. These are the discriminators.
// ---------------------------------------------------------------------------

TEST(HostContextCalibrationTest, BareMetalHostChangesNothing) {
    // THE PRIMARY DISCRIMINATOR. If the host fact is ignored, this fails.
    auto detection = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 0.9);
    EnvironmentEvasionDetector::CalibrateForHostContext(detection, /*hostIsVirtualized=*/false);

    EXPECT_DOUBLE_EQ(detection.confidence, 0.9)
        << "on bare metal a VM-artefact probe has no innocent explanation from host "
           "context, so it must keep its full confidence";
}

TEST(HostContextCalibrationTest, BehaviouralCategoriesAreNotCalibrated) {
    // Being on a VM says nothing about whether probing for user activity or timing is
    // legitimate, so those categories must be untouched. If the category test is ever
    // widened, this fails.
    for (const auto category : {EnvironmentEvasionCategory::UserActivityIndicators,
                                EnvironmentEvasionCategory::TimingChecks,
                                EnvironmentEvasionCategory::ProcessEnumeration,
                                EnvironmentEvasionCategory::NetworkConfiguration,
                                EnvironmentEvasionCategory::NameChecks}) {
        auto detection = MakeDetection(category, 0.9);
        EnvironmentEvasionDetector::CalibrateForHostContext(detection, true);
        EXPECT_DOUBLE_EQ(detection.confidence, 0.9)
            << "category " << static_cast<int>(category)
            << " is not a VM-artefact probe and must not be calibrated by host "
               "virtualization";
    }
}

TEST(HostContextCalibrationTest, AlreadyLowConfidenceIsNotReducedFurther) {
    // The policy carries a floor so a weak finding is not pushed toward zero.
    auto atFloor = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 0.3);
    auto belowFloor = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 0.1);

    EnvironmentEvasionDetector::CalibrateForHostContext(atFloor, true);
    EnvironmentEvasionDetector::CalibrateForHostContext(belowFloor, true);

    EXPECT_DOUBLE_EQ(atFloor.confidence, 0.3);
    EXPECT_DOUBLE_EQ(belowFloor.confidence, 0.1);
}

// ---------------------------------------------------------------------------
// The safety invariant.
// ---------------------------------------------------------------------------

TEST(HostContextCalibrationTest, CalibrationNeverRemovesADetection) {
    // Calibration adjusts a number. It must never zero a finding, never clear its
    // category, and never erase its description - a reduced-confidence detection is
    // still a detection and is still reported.
    auto detection = MakeDetection(EnvironmentEvasionCategory::RegistryArtifacts, 1.0);
    const auto originalCategory = detection.category;

    EnvironmentEvasionDetector::CalibrateForHostContext(detection, true);

    EXPECT_GT(detection.confidence, 0.0)
        << "a calibrated detection must remain a detection; confidence may fall but "
           "must not be zeroed";
    EXPECT_EQ(detection.category, originalCategory)
        << "calibration must not reclassify a finding";
    EXPECT_FALSE(detection.description.empty())
        << "calibration must not discard the finding's description";
}

TEST(HostContextCalibrationTest, CalibrationIsIdempotentPerInvocationNotCumulative) {
    // Documents a real hazard: the calibration is applied once per detection at the
    // merge point. If a future edit applied it on BOTH the per-process and the
    // system-aggregate path to the same object, the reduction would compound. This
    // test states the expected single-application factor so that compounding is
    // visible as a failure rather than as a quietly halved score.
    auto once = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 1.0);
    EnvironmentEvasionDetector::CalibrateForHostContext(once, true);
    EXPECT_DOUBLE_EQ(once.confidence, kVmReductionFactor);

    auto twice = MakeDetection(EnvironmentEvasionCategory::HardwareFingerprinting, 1.0);
    EnvironmentEvasionDetector::CalibrateForHostContext(twice, true);
    EnvironmentEvasionDetector::CalibrateForHostContext(twice, true);
    EXPECT_DOUBLE_EQ(twice.confidence, kVmReductionFactor * kVmReductionFactor)
        << "applying the calibration twice compounds it - that is the behaviour, and "
           "it is why the call must sit at exactly one merge point per detection";
}

}  // namespace
