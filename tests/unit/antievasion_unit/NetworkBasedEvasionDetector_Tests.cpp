/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "AntiEvasion_TestUtils.hpp"
#include "../../../src/Shared_modules/AntiEvasion/NetworkBasedEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion {
const wchar_t* NetworkEvasionTechniqueToString(NetworkEvasionTechnique technique) noexcept;
}

namespace ShadowStrike::AntiEvasion::Tests {

TEST(NetworkBasedEvasionDetector_Helpers, TechniqueMappingsAndConstructorPopulateDerivedMetadata) {
    NetworkDetectedTechnique detection(NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm);

    EXPECT_EQ(NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm, detection.technique);
    EXPECT_EQ(NetworkEvasionCategory::DNSEvasion, detection.category);
    EXPECT_EQ(NetworkEvasionSeverity::Critical, detection.severity);
    EXPECT_STREQ("T1568.002", detection.mitreId.c_str());
    EXPECT_GT(detection.detectionTime, std::chrono::system_clock::time_point{});

    EXPECT_STREQ(L"Ping to Known Domain",
        NetworkEvasionTechniqueToString(NetworkEvasionTechnique::CONN_PingKnownDomain));
    EXPECT_STREQ(L"DNS Tunneling",
        NetworkEvasionTechniqueToString(NetworkEvasionTechnique::DNS_Tunneling));
    EXPECT_STREQ(L"Unknown Technique",
        NetworkEvasionTechniqueToString(static_cast<NetworkEvasionTechnique>(0xFFFF)));
}

TEST(NetworkBasedEvasionDetector_Helpers, KernelContextUsesTamperProofFieldsForPresenceCheck) {
    NetworkKernelContext emptyContext;
    EXPECT_FALSE(emptyContext.hasKernelData());

    NetworkKernelContext parentOnlyContext;
    parentOnlyContext.parentProcessId = 4;
    EXPECT_TRUE(parentOnlyContext.hasKernelData());

    NetworkKernelContext pathContext;
    pathContext.imagePath = L"C:\\Program Files\\Sample\\sample.exe";
    EXPECT_TRUE(pathContext.hasKernelData());
}

TEST(NetworkBasedEvasionDetector_DGA, DomainEntropyAndWrapperRemainDeterministic) {
    NetworkBasedEvasionDetector detector;

    const std::wstring benignDomain = L"microsoft.com";
    const std::wstring suspiciousDomain = L"xj93kq2p9zv8q1w.biz";

    double benignScoreWrapped = 0.0;
    EXPECT_FALSE(detector.IsDGADomain(benignDomain, benignScoreWrapped));
    EXPECT_LT(benignScoreWrapped, NetworkEvasionConstants::MIN_DGA_SCORE);

    double suspiciousScoreWrapped = 0.0;
    const bool suspiciousFlagged = detector.IsDGADomain(suspiciousDomain, suspiciousScoreWrapped);
    EXPECT_LT(benignScoreWrapped, suspiciousScoreWrapped);
    EXPECT_EQ(suspiciousScoreWrapped >= NetworkEvasionConstants::MIN_DGA_SCORE, suspiciousFlagged);
}

TEST(NetworkBasedEvasionDetector_Beaconing, DetectBeaconingDistinguishesRegularAndIrregularIntervals) {
    NetworkBasedEvasionDetector detector;

    BeaconingInfo regularInfo;
    const auto regularTimestamps = BuildSystemClockSeries({ 0, 10, 20, 30 });
    EXPECT_TRUE(detector.DetectBeaconing(regularTimestamps, regularInfo));
    EXPECT_TRUE(regularInfo.isBeaconing);
    EXPECT_EQ(4u, regularInfo.beaconCount);
    EXPECT_NEAR(10.0, regularInfo.averageIntervalSec, 1e-6);
    EXPECT_NEAR(0.0, regularInfo.intervalVariance, 1e-6);
    EXPECT_GE(regularInfo.regularityScore, NetworkEvasionConstants::MIN_BEACONING_REGULARITY);

    BeaconingInfo irregularInfo;
    const auto irregularTimestamps = BuildSystemClockSeries({ 0, 2, 20, 47 });
    EXPECT_FALSE(detector.DetectBeaconing(irregularTimestamps, irregularInfo));
    EXPECT_FALSE(irregularInfo.isBeaconing);
    EXPECT_EQ(4u, irregularInfo.beaconCount);
}

} // namespace ShadowStrike::AntiEvasion::Tests
