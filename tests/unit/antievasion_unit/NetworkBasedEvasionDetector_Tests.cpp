/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "AntiEvasion_TestUtils.hpp"
#include "../../../src/PhantomCore/AntiEvasion/NetworkBasedEvasionDetector.hpp"
#include "../../../src/PhantomCore/Utils/DomainUtils.hpp"

#include <filesystem>

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

TEST(NetworkBasedEvasionDetector_ResultHelpers, FilteringAndClearResetAllMutableState) {
    NetworkEvasionResult result;
    result.processId = 5150;
    result.processName = L"sample.exe";
    result.isEvasive = true;
    result.evasionScore = 77.5;
    result.maxSeverity = NetworkEvasionSeverity::Critical;
    result.totalDetections = 2;
    result.detectedCategories =
        (1u << static_cast<uint32_t>(NetworkEvasionCategory::DNSEvasion)) |
        (1u << static_cast<uint32_t>(NetworkEvasionCategory::TrafficPattern));
    result.detectedTechniques = {
        NetworkDetectedTechnique(NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm),
        NetworkDetectedTechnique(NetworkEvasionTechnique::CONN_PingKnownDomain)
    };
    result.suspiciousDomains = { L"xj93kq2p9zv8q1w.biz" };
    result.suspiciousIPs = { L"203.0.113.10" };
    result.knownC2 = { L"c2.shadow.invalid" };
    result.totalDNSQueries = 5;
    result.totalHTTPRequests = 2;
    result.totalConnections = 7;
    result.networkConfig.hasProxy = true;
    result.networkConfig.proxyAddress = L"http://127.0.0.1:8080";
    result.analysisComplete = true;
    result.fromCache = true;

    EXPECT_TRUE(result.HasCategory(NetworkEvasionCategory::DNSEvasion));
    EXPECT_TRUE(result.HasTechnique(NetworkEvasionTechnique::DNS_DomainGenerationAlgorithm));
    EXPECT_FALSE(result.HasCategory(NetworkEvasionCategory::ProxyDetection));
    EXPECT_FALSE(result.HasTechnique(NetworkEvasionTechnique::DNS_Tunneling));

    result.Clear();

    EXPECT_EQ(0u, result.processId);
    EXPECT_TRUE(result.processName.empty());
    EXPECT_FALSE(result.isEvasive);
    EXPECT_DOUBLE_EQ(0.0, result.evasionScore);
    EXPECT_EQ(NetworkEvasionSeverity::Low, result.maxSeverity);
    EXPECT_EQ(0u, result.totalDetections);
    EXPECT_EQ(0u, result.detectedCategories);
    EXPECT_TRUE(result.detectedTechniques.empty());
    EXPECT_TRUE(result.suspiciousDomains.empty());
    EXPECT_TRUE(result.suspiciousIPs.empty());
    EXPECT_TRUE(result.knownC2.empty());
    EXPECT_FALSE(result.networkConfig.hasProxy);
    EXPECT_TRUE(result.networkConfig.proxyAddress.empty());
    EXPECT_EQ(0u, result.totalDNSQueries);
    EXPECT_EQ(0u, result.totalHTTPRequests);
    EXPECT_EQ(0u, result.totalConnections);
    EXPECT_FALSE(result.analysisComplete);
    EXPECT_FALSE(result.fromCache);
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

TEST(NetworkBasedEvasionDetector_Beaconing, RejectsInsufficientAndNonIncreasingSeriesWithoutLeakingState) {
    NetworkBasedEvasionDetector detector;

    BeaconingInfo shortSeriesInfo;
    shortSeriesInfo.target = L"stale.example";
    shortSeriesInfo.beaconCount = 99;

    EXPECT_FALSE(detector.DetectBeaconing(BuildSystemClockSeries({ 0, 10 }), shortSeriesInfo));
    EXPECT_FALSE(shortSeriesInfo.isBeaconing);
    EXPECT_EQ(0u, shortSeriesInfo.beaconCount);
    EXPECT_TRUE(shortSeriesInfo.timestamps.empty());
    EXPECT_TRUE(shortSeriesInfo.target.empty());

    BeaconingInfo duplicateSeriesInfo;
    duplicateSeriesInfo.isBeaconing = true;
    duplicateSeriesInfo.beaconCount = 42;

    EXPECT_FALSE(detector.DetectBeaconing(BuildSystemClockSeries({ 0, 0, 0, 0 }), duplicateSeriesInfo));
    EXPECT_FALSE(duplicateSeriesInfo.isBeaconing);
    EXPECT_EQ(4u, duplicateSeriesInfo.beaconCount);
    EXPECT_DOUBLE_EQ(0.0, duplicateSeriesInfo.averageIntervalSec);
    EXPECT_DOUBLE_EQ(0.0, duplicateSeriesInfo.intervalVariance);
}


// ===========================================================================================
// DNS tunnelling: the checks must measure the SUBDOMAIN, not the whole hostname.
//
// Three of the five checks were fed the entire host while being named for the subdomain, so
// each was charged for labels the registrant owns - a long company name read as a long
// subdomain label, and its characters as subdomain entropy.
// ===========================================================================================

namespace {

/// Loads the vendored public suffix list. EnsureLoaded() resolves beside the executable,
/// which the test binary is not, so the path is found by walking up from the working
/// directory. Without this the detector exercises its fallback approximation instead of the
/// list, and these tests would be measuring the wrong code path.
void EnsurePublicSuffixListLoaded() {
    using ShadowStrike::Utils::Domain::PublicSuffixList;
    auto& psl = PublicSuffixList::Instance();
    if (psl.IsLoaded()) {
        return;
    }
    std::error_code ec;
    std::filesystem::path here = std::filesystem::current_path(ec);
    for (int depth = 0; depth < 8 && !here.empty(); ++depth) {
        const std::filesystem::path candidate =
            here / L"content" / L"psl" / L"public_suffix_list.dat";
        if (std::filesystem::exists(candidate, ec)) {
            (void)psl.LoadFromFile(candidate.wstring());
            return;
        }
        if (!here.has_parent_path() || here.parent_path() == here) {
            break;
        }
        here = here.parent_path();
    }
}

[[nodiscard]] bool HasTunnelDetection(
    const std::vector<NetworkDetectedTechnique>& detections) noexcept {
    for (const auto& detection : detections) {
        if (detection.technique == NetworkEvasionTechnique::DNS_Tunneling) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(NetworkBasedEvasionDetector_DNSTunnel, ABareRegistrableDomainIsNeverATunnel) {
    EnsurePublicSuffixListLoaded();
    ASSERT_TRUE(ShadowStrike::Utils::Domain::PublicSuffixList::Instance().IsLoaded())
        << "the vendored public suffix list did not load, so this test would exercise the "
           "fallback approximation rather than the path under test";

    NetworkBasedEvasionDetector detector;
    // AnalyzeDomain returns early with ERROR_NOT_READY unless the detector is initialised,
    // leaving outDetections empty - which reads as "no tunnel" and would make every
    // negative assertion below pass without running a single check.
    ASSERT_TRUE(detector.Initialize());

    std::vector<NetworkDetectedTechnique> detections;

    // A 34-character alphanumeric registrable label and NO SUBDOMAIN AT ALL. Measuring the
    // whole host scored this +30 for a long subdomain label and +30 for an encoded
    // subdomain, reaching the 50-point verdict - a DNS tunnel with nothing to tunnel
    // through. Other checks such as DGA or high entropy may legitimately fire on a name
    // like this, so only the tunnelling verdict is asserted.
    (void)detector.AnalyzeDomain(L"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7.com", detections);

    EXPECT_FALSE(HasTunnelDetection(detections))
        << "a host with no subdomain was reported as a DNS tunnel, which means the tunnel"
           " checks are measuring the registrable domain again";
}

TEST(NetworkBasedEvasionDetector_DNSTunnel, ALegitimateMultiLabelCcTldHostIsNotATunnel) {
    EnsurePublicSuffixListLoaded();
    ASSERT_TRUE(ShadowStrike::Utils::Domain::PublicSuffixList::Instance().IsLoaded())
        << "the vendored public suffix list did not load, so this test would exercise the "
           "fallback approximation rather than the path under test";

    NetworkBasedEvasionDetector detector;
    // AnalyzeDomain returns early with ERROR_NOT_READY unless the detector is initialised,
    // leaving outDetections empty - which reads as "no tunnel" and would make every
    // negative assertion below pass without running a single check.
    ASSERT_TRUE(detector.Initialize());

    std::vector<NetworkDetectedTechnique> detections;

    // Six total labels but only three below the registrable domain. Counting total labels
    // put this over the old limit of 5; counting the subdomain puts it at the limit of 3.
    (void)detector.AnalyzeDomain(L"eu-west-1.api.prod.company.co.uk", detections);

    EXPECT_FALSE(HasTunnelDetection(detections))
        << "a routine multi-label ccTLD host was reported as a DNS tunnel";
}

TEST(NetworkBasedEvasionDetector_DNSTunnel, ALongEncodedLabelBeneathARegisteredDomainIsDetected) {
    EnsurePublicSuffixListLoaded();
    ASSERT_TRUE(ShadowStrike::Utils::Domain::PublicSuffixList::Instance().IsLoaded())
        << "the vendored public suffix list did not load, so this test would exercise the "
           "fallback approximation rather than the path under test";

    NetworkBasedEvasionDetector detector;
    // AnalyzeDomain returns early with ERROR_NOT_READY unless the detector is initialised,
    // leaving outDetections empty - which reads as "no tunnel" and would make every
    // negative assertion below pass without running a single check.
    ASSERT_TRUE(detector.Initialize());

    std::vector<NetworkDetectedTechnique> detections;

    // One 40-character base64-shaped label - the classic exfiltration payload. Sensitivity
    // for this shape must survive the change, because it is what the checks exist to catch.
    (void)detector.AnalyzeDomain(
        L"aGVsbG93b3JsZHRoaXNpc2FiYXNlNjRwYXlsb2Fk.evil.com", detections);

    EXPECT_TRUE(HasTunnelDetection(detections))
        << "a long encoded label beneath a registered domain was not detected as a tunnel";
}

TEST(NetworkBasedEvasionDetector_DNSTunnel, ADeepEncodedTunnelUnderACcTldIsDetected) {
    EnsurePublicSuffixListLoaded();
    ASSERT_TRUE(ShadowStrike::Utils::Domain::PublicSuffixList::Instance().IsLoaded())
        << "the vendored public suffix list did not load, so this test would exercise the "
           "fallback approximation rather than the path under test";

    NetworkBasedEvasionDetector detector;
    // AnalyzeDomain returns early with ERROR_NOT_READY unless the detector is initialised,
    // leaving outDetections empty - which reads as "no tunnel" and would make every
    // negative assertion below pass without running a single check.
    ASSERT_TRUE(detector.Initialize());

    std::vector<NetworkDetectedTechnique> detections;

    // Four encoded labels beneath a multi-label ccTLD. This is the case the change must not
    // lose: the registrable domain contributes three labels of its own, so the threshold has
    // to be reached on the subdomain alone.
    (void)detector.AnalyzeDomain(
        L"aGVsbG93b3JsZHRoaXNpc2E.YmFzZTY0cGF5bG9hZHR3bw.dGhpcmRjaHVuaw."
        L"Zm91cnRoY2h1bms.example.co.uk", detections);

    EXPECT_TRUE(HasTunnelDetection(detections))
        << "a deep encoded tunnel under a ccTLD was not detected";
}
} // namespace ShadowStrike::AntiEvasion::Tests
