/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file SafeBrowsingVerdict_Tests.cpp
 * @brief The two verdict predicates that decide whether a URL is blocked or merely warned about.
 *
 * SafeBrowsingResult::ShouldBlock and ShouldWarn are the whole interface between a lookup result and
 * what the user experiences. They are three-line predicates, which is exactly why they go unchecked
 * and why a change to one of them is easy to make without noticing the consequence.
 *
 * The relationship between them is the part worth pinning. ShouldBlock fires on malicious, on
 * phishing, and on suspicious ONLY above a confidence of 80, while ShouldWarn fires on suspicious at
 * any confidence and on potentially-unwanted. So a low-confidence suspicious result warns without
 * blocking, and that boundary at 80 is the difference between interrupting a user and informing one.
 * It is asserted from both sides.
 *
 * A malicious result blocks WITHOUT setting the warn flag, which means a caller that checks ShouldWarn
 * first and returns early would show a warning page for a suspicious site and nothing for a malicious
 * one. That ordering dependency is asserted so it is visible to whoever writes the next caller.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/SafeBrowsingAPI.hpp"

namespace ShadowStrike::WebBrowser::Test {
namespace {

[[nodiscard]] SafeBrowsingResult Clean() {
    SafeBrowsingResult r{};
    r.isMalicious = false;
    r.isPhishing = false;
    r.isSuspicious = false;
    r.isPUA = false;
    r.confidence = 0;
    return r;
}

TEST(SafeBrowsingVerdictTest, ACleanResultNeitherBlocksNorWarns) {
    const auto r = Clean();
    EXPECT_FALSE(r.ShouldBlock());
    EXPECT_FALSE(r.ShouldWarn());
}

TEST(SafeBrowsingVerdictTest, MaliciousAndPhishingBlockRegardlessOfConfidence) {
    auto malicious = Clean();
    malicious.isMalicious = true;
    malicious.confidence = 0;
    EXPECT_TRUE(malicious.ShouldBlock())
        << "a malicious verdict did not block at zero confidence, so the confidence field gates a "
           "decision it is not supposed to gate";

    auto phishing = Clean();
    phishing.isPhishing = true;
    phishing.confidence = 0;
    EXPECT_TRUE(phishing.ShouldBlock());
}

TEST(SafeBrowsingVerdictTest, SuspiciousBlocksOnlyAboveTheConfidenceBoundary) {
    // The boundary is 80 and it is asserted from both sides, because a fix that moved it by one
    // would change which users are interrupted without changing any verdict name.
    auto below = Clean();
    below.isSuspicious = true;
    below.confidence = 79;
    EXPECT_FALSE(below.ShouldBlock()) << "suspicious at 79 confidence blocked";

    auto at = Clean();
    at.isSuspicious = true;
    at.confidence = 80;
    EXPECT_TRUE(at.ShouldBlock()) << "suspicious at exactly 80 confidence did not block";
}

TEST(SafeBrowsingVerdictTest, SuspiciousWarnsAtAnyConfidence) {
    auto r = Clean();
    r.isSuspicious = true;
    r.confidence = 1;
    EXPECT_TRUE(r.ShouldWarn())
        << "a low-confidence suspicious result neither blocks nor warns, so it is silently ignored";
    EXPECT_FALSE(r.ShouldBlock());
}

TEST(SafeBrowsingVerdictTest, PotentiallyUnwantedWarnsWithoutBlocking) {
    auto r = Clean();
    r.isPUA = true;
    EXPECT_TRUE(r.ShouldWarn());
    EXPECT_FALSE(r.ShouldBlock())
        << "a potentially-unwanted application was blocked outright rather than warned about";
}

TEST(SafeBrowsingVerdictTest, BlockingDoesNotImplyWarning) {
    // Pinned because it constrains callers: a malicious result blocks but does NOT warn, so any
    // caller that tests ShouldWarn first and returns early would warn about a suspicious site and
    // say nothing about a malicious one. ShouldBlock must be tested first.
    auto malicious = Clean();
    malicious.isMalicious = true;
    EXPECT_TRUE(malicious.ShouldBlock());
    EXPECT_FALSE(malicious.ShouldWarn())
        << "if this ever becomes true the ordering constraint on callers has changed and the "
           "comment above it is stale";
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
