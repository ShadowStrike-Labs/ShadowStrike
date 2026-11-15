/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PhishingVerdict_Tests.cpp
 * @brief Whether a phishing verdict blocks, and that it blocks against the threshold it was decided by.
 *
 * PhishingAnalysisResult::ShouldBlock is the enforcement half of the phishing decision. The analyser
 * sets isPhishing against m_config.phishingThreshold, a configurable value validated to the range 0-100.
 * ShouldBlock used to compare against a second, hardcoded constant of 80, so an administrator who lowered
 * the threshold to 60 got an email scoring 70 classified, counted and reported as phishing - and
 * delivered (task 273). The setting moved detection without moving enforcement.
 *
 * The result now carries appliedPhishingThreshold, the threshold its verdict was decided against, and
 * ShouldBlock compares against that. The default of 80 is unchanged for every installation that never
 * touched the setting, and a raised threshold still governs blocking.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Email/PhishingEmailDetector.hpp"

#include <string>

namespace ShadowStrike::Email::Test {
namespace {

[[nodiscard]] PhishingAnalysisResult ResultWith(bool isPhishing, int confidence) {
    PhishingAnalysisResult r{};
    r.isPhishing = isPhishing;
    r.confidenceScore = confidence;
    return r;
}

[[nodiscard]] PhishingAnalysisResult ResultWith(bool isPhishing, int confidence, int appliedThreshold) {
    PhishingAnalysisResult r = ResultWith(isPhishing, confidence);
    r.appliedPhishingThreshold = appliedThreshold;
    return r;
}

TEST(PhishingVerdictTest, ACleanEmailIsNotBlocked) {
    EXPECT_FALSE(ResultWith(false, 0).ShouldBlock());
}

TEST(PhishingVerdictTest, AHighConfidencePhishIsBlocked) {
    EXPECT_TRUE(ResultWith(true, 95).ShouldBlock());
}

TEST(PhishingVerdictTest, TheDefaultBlockingBoundaryHoldsFromBothSides) {
    // A result that never passed through the analyser keeps the documented constant of 80, which is
    // also the configuration default. Asserted either side so a one-point move fails here rather than
    // silently changing which mail is delivered.
    EXPECT_EQ(PhishingConstants::HIGH_CONFIDENCE_THRESHOLD, PhishingAnalysisResult{}.appliedPhishingThreshold);
    EXPECT_FALSE(ResultWith(true, 79).ShouldBlock())
        << "a phishing verdict at 79 confidence was blocked";
    EXPECT_TRUE(ResultWith(true, 80).ShouldBlock())
        << "a phishing verdict at exactly 80 confidence was delivered";
}

TEST(PhishingVerdictTest, ConfidenceAloneDoesNotBlock) {
    // The verdict flag is required as well as the score, so a high-scoring email that the analyser
    // did NOT classify as phishing must not be blocked by score alone.
    EXPECT_FALSE(ResultWith(false, 100).ShouldBlock())
        << "a non-phishing verdict was blocked purely on its confidence score";
    EXPECT_FALSE(ResultWith(false, 70, 60).ShouldBlock());
}

TEST(PhishingVerdictTest, ALoweredThresholdBlocksWhatItDetects) {
    // Task 273: with the threshold lowered to 60, an email scoring 70 is phishing AND blocked. Before
    // the fix this case was classified as phishing and delivered.
    EXPECT_TRUE(ResultWith(true, 70, 60).ShouldBlock())
        << "a verdict the lowered threshold classifies as phishing was delivered";
    EXPECT_TRUE(ResultWith(true, 60, 60).ShouldBlock()) << "the lowered boundary is inclusive";
    EXPECT_FALSE(ResultWith(true, 59, 60).ShouldBlock()) << "a score below the applied threshold blocked";
}

TEST(PhishingVerdictTest, ARaisedThresholdStillGovernsBlocking) {
    EXPECT_FALSE(ResultWith(true, 85, 90).ShouldBlock())
        << "a score below a raised threshold was blocked";
    EXPECT_TRUE(ResultWith(true, 90, 90).ShouldBlock());
}

TEST(PhishingVerdictTest, TheAppliedThresholdIsSerialised) {
    // A stored verdict says which threshold produced it.
    EXPECT_NE(std::string::npos,
              ResultWith(true, 70, 60).ToJson().find("\"appliedPhishingThreshold\":60"));
}

// End to end through the analyser: the configured threshold reaches the result, and a verdict decided
// against a lowered threshold is enforced. The fixture's score is measured first and the threshold is
// lowered exactly onto it, so the case discriminates whatever the scoring weights are - provided the
// score sits below the old constant of 80, which is asserted.
TEST(PhishingVerdictTest, TheAnalyserEnforcesTheConfiguredThreshold) {
    auto& detector = PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) {
        ASSERT_TRUE(detector.Initialize());
    }
    const PhishingDetectorConfiguration saved = detector.GetConfiguration();
    struct RestoreConfig {
        PhishingEmailDetector& d;
        const PhishingDetectorConfiguration& c;
        ~RestoreConfig() { (void)d.UpdateConfiguration(c); }
    } restore{detector, saved};

    const std::string subject = "Urgent: your account has been suspended";
    const std::string body =
        "Dear customer, we detected unusual activity. Verify your password immediately at "
        "http://paypa1-account-verify.example/login or your account will be closed today.";
    const std::string sender = "security-alert@paypa1-account-verify.example";

    const int score = detector.AnalyzeContent(subject, body, sender).confidenceScore;
    ASSERT_GE(score, 2) << "the fixture must score high enough to place a threshold on it";
    ASSERT_LT(score, PhishingConstants::HIGH_CONFIDENCE_THRESHOLD)
        << "the fixture must score below the old hardcoded 80, or this case cannot discriminate";

    PhishingDetectorConfiguration lowered = saved;
    lowered.phishingThreshold = score;
    lowered.suspiciousThreshold = score - 1;
    ASSERT_TRUE(detector.UpdateConfiguration(lowered));

    const PhishingAnalysisResult r = detector.AnalyzeContent(subject, body, sender);
    EXPECT_EQ(score, r.appliedPhishingThreshold) << "the configured threshold did not reach the result";
    EXPECT_TRUE(r.isPhishing);
    EXPECT_TRUE(r.ShouldBlock())
        << "a verdict the configured threshold classifies as phishing was delivered (score " << score
        << ")";
}

}  // namespace
}  // namespace ShadowStrike::Email::Test
