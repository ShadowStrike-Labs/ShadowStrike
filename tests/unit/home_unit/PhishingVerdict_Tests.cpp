/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PhishingVerdict_Tests.cpp
 * @brief Whether a phishing verdict blocks, and the configured threshold it does not consult.
 *
 * PhishingAnalysisResult::ShouldBlock is the enforcement half of the phishing decision. It reads
 *
 *     isPhishing && confidenceScore >= PhishingConstants::HIGH_CONFIDENCE_THRESHOLD
 *
 * where the constant is 80. But isPhishing is set by the analyser against m_config.phishingThreshold,
 * a configurable value validated to the range 0-100 with only the constraint that it exceed the
 * suspicious threshold. The two do not agree.
 *
 * So an administrator who lowers the phishing threshold to 60 in order to catch more phishing gets an
 * email scoring 70 marked as phishing, counted in phishingDetected, reported in diagnostics - and NOT
 * blocked. The setting moves detection without moving enforcement, in one direction only: raising the
 * threshold above 80 works, because isPhishing then never becomes true below it.
 *
 * The cases below pin the predicate's own behaviour, including the boundary from both sides. The
 * mismatch with the configured threshold is filed rather than fixed here, because closing it changes
 * what gets blocked for every installation that already lowered the setting, and that is an
 * enforcement change rather than a repair.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Email/PhishingEmailDetector.hpp"

namespace ShadowStrike::Email::Test {
namespace {

[[nodiscard]] PhishingAnalysisResult ResultWith(bool isPhishing, int confidence) {
    PhishingAnalysisResult r{};
    r.isPhishing = isPhishing;
    r.confidenceScore = confidence;
    return r;
}

TEST(PhishingVerdictTest, ACleanEmailIsNotBlocked) {
    EXPECT_FALSE(ResultWith(false, 0).ShouldBlock());
}

TEST(PhishingVerdictTest, AHighConfidencePhishIsBlocked) {
    EXPECT_TRUE(ResultWith(true, 95).ShouldBlock());
}

TEST(PhishingVerdictTest, TheBlockingBoundaryHoldsFromBothSides) {
    // 80 is the documented constant. Asserted either side so a one-point move fails here rather than
    // silently changing which mail is delivered.
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
}

TEST(PhishingVerdictTest, ADetectedPhishBelowTheConstantIsNotBlocked) {
    // THE MISMATCH THIS FILE RECORDS. isPhishing is set against the CONFIGURED threshold, which an
    // administrator may lower to 60. ShouldBlock compares against the hardcoded 80. This case is the
    // state an installation with a lowered threshold is in: the email is classified as phishing and
    // counted as detected, and it is still delivered.
    const auto detectedButDelivered = ResultWith(true, 70);
    EXPECT_TRUE(detectedButDelivered.isPhishing);
    EXPECT_FALSE(detectedButDelivered.ShouldBlock())
        << "if this now fails, ShouldBlock was made to honour the configured threshold - which is "
           "the filed fix. Update the filing and this comment rather than reverting.";
}

}  // namespace
}  // namespace ShadowStrike::Email::Test
