/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ScheduleAndSenderScope_Tests.cpp
 * @brief An hour window that crosses midnight, and how far a sender-list entry reaches.
 *
 * Two independent modules, one shared theme: a rule the user writes has to mean what they meant.
 *
 * QUIET HOURS. BackupScheduler::IsInQuietHours is CORRECT and these cases exist to keep it that way and to
 * serve as the reference for a sibling that is not. Quiet hours are normally an overnight window - 22:00 to
 * 07:00 - so the wrap is the common case rather than the edge case, and the implementation branches on
 * startHour <= endHour explicitly to handle it. GameModeSchedule does not, and its overnight window is filed
 * as a defect; when that is fixed it should look like this. So the cases below are written to be portable to
 * it: they name the property rather than the module.
 *
 * SENDER LISTS. SpamDetector's whitelist and blacklist accept either an address or a domain, and the check
 * tries the full sender and then its domain. That is deliberate and useful - whitelisting a domain should
 * cover its senders - but it means the reach of one entry depends on which form was written, and the two
 * directions are not symmetric in consequence: a wrong whitelist entry lets spam through, a wrong blacklist
 * entry loses a legitimate message. The cases separate the two forms and assert both directions.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Backup/BackupScheduler.hpp"
#include "Products/Community/PhantomHome/Email/SpamDetector.hpp"

#include <string>

namespace ShadowStrike::ScheduleSenderTest {
namespace {

using ShadowStrike::Backup::IsInQuietHours;
using ShadowStrike::Email::SpamDetector;

}  // namespace

// ============================================================================================
// An hour window, including the one that wraps
// ============================================================================================

TEST(QuietHoursTest, ADaytimeWindowContainsItsOwnHours) {
    // start <= end, the simple case: 09:00 to 17:00.
    EXPECT_TRUE(IsInQuietHours(9, 9, 17)) << "the start hour must be inside the window";
    EXPECT_TRUE(IsInQuietHours(12, 9, 17));
    EXPECT_TRUE(IsInQuietHours(16, 9, 17));
}

TEST(QuietHoursTest, ADaytimeWindowExcludesTheEndHourAndEverythingOutside) {
    // The end hour is exclusive, which is what makes two adjacent windows tile without overlapping.
    EXPECT_FALSE(IsInQuietHours(17, 9, 17)) << "the end hour must be outside, or adjacent windows overlap";
    EXPECT_FALSE(IsInQuietHours(8, 9, 17));
    EXPECT_FALSE(IsInQuietHours(18, 9, 17));
    EXPECT_FALSE(IsInQuietHours(0, 9, 17));
    EXPECT_FALSE(IsInQuietHours(23, 9, 17));
}

TEST(QuietHoursTest, AnOvernightWindowCrossesMidnight) {
    // The case that matters, and the one a naive start <= hour <= end gets wrong. Quiet hours are normally
    // overnight, so this is the common configuration rather than an edge case.
    EXPECT_TRUE(IsInQuietHours(22, 22, 7)) << "the start hour of an overnight window";
    EXPECT_TRUE(IsInQuietHours(23, 22, 7));
    EXPECT_TRUE(IsInQuietHours(0, 22, 7)) << "midnight itself falls inside an overnight window";
    EXPECT_TRUE(IsInQuietHours(3, 22, 7));
    EXPECT_TRUE(IsInQuietHours(6, 22, 7));
}

TEST(QuietHoursTest, AnOvernightWindowExcludesTheDaytime) {
    // Anti-vacuity for the case above: a wrapping window must still exclude something, or it would be
    // permanently active and quiet hours would never end.
    EXPECT_FALSE(IsInQuietHours(7, 22, 7)) << "the end hour must be outside";
    EXPECT_FALSE(IsInQuietHours(8, 22, 7));
    EXPECT_FALSE(IsInQuietHours(12, 22, 7));
    EXPECT_FALSE(IsInQuietHours(21, 22, 7));
}

TEST(QuietHoursTest, AWindowThatStartsAndEndsAtTheSameHourIsEmpty) {
    // start == end takes the non-wrapping branch, where the end is exclusive, so the window is empty rather
    // than covering the whole day. Pinned because the opposite reading - a full day - is equally plausible
    // and would silently suspend backups forever.
    for (int hour = 0; hour < 24; ++hour) {
        EXPECT_FALSE(IsInQuietHours(hour, 3, 3))
            << "hour " << hour << " fell inside an empty window, so start == end means all day";
    }
}

TEST(QuietHoursTest, AWindowCoveringAlmostTheWholeDayStillExcludesOneHour) {
    // 1 to 0 wraps and should cover 01:00 through 23:00 plus midnight - every hour except... none.
    // Expressed the other way: 0 to 23 covers everything but 23:00.
    EXPECT_FALSE(IsInQuietHours(23, 0, 23));
    EXPECT_TRUE(IsInQuietHours(22, 0, 23));
    EXPECT_TRUE(IsInQuietHours(0, 0, 23));
}

// ============================================================================================
// Sender lists - an entry may be an address or a domain
// ============================================================================================

class SpamSenderListTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto& sd = SpamDetector::Instance();
        if (!sd.IsInitialized()) {
            (void)sd.Initialize();
        }
        ASSERT_TRUE(sd.IsInitialized()) << "the spam detector could not be initialised";
    }
    static SpamDetector& Detector() { return SpamDetector::Instance(); }
};

TEST_F(SpamSenderListTest, AWhitelistedAddressCoversOnlyThatAddress) {
    // A user naming one address must not exempt the whole provider. Whitelisting a free-mail address that
    // exempted every sender at that provider would be a very large hole.
    ASSERT_TRUE(Detector().AddToWhitelist("alice@probe-example.test"));
    EXPECT_TRUE(Detector().IsWhitelisted("alice@probe-example.test"));
    EXPECT_FALSE(Detector().IsWhitelisted("bob@probe-example.test"))
        << "whitelisting one address exempted a different sender at the same domain";
}

TEST_F(SpamSenderListTest, AWhitelistedDomainCoversItsSenders) {
    // The deliberate counterpart: naming a domain is how a user exempts an organisation.
    ASSERT_TRUE(Detector().AddToWhitelist("probe-domain.test"));
    EXPECT_TRUE(Detector().IsWhitelisted("anyone@probe-domain.test"));
    EXPECT_TRUE(Detector().IsWhitelisted("someone.else@probe-domain.test"));
}

TEST_F(SpamSenderListTest, TheSenderMatchIsCaseInsensitive) {
    // Addresses and domains are compared case-insensitively, so a user typing either form gets the same
    // result. If only one side normalised, an entry written naturally would never apply.
    ASSERT_TRUE(Detector().AddToWhitelist("Case@Probe-Case.Test"));
    EXPECT_TRUE(Detector().IsWhitelisted("case@probe-case.test"));
    EXPECT_TRUE(Detector().IsWhitelisted("CASE@PROBE-CASE.TEST"));
}

TEST_F(SpamSenderListTest, AnUnlistedSenderIsNeitherWhitelistedNorBlacklisted) {
    // Anti-vacuity for both lists: a detector answering true for everything would exempt all mail, and one
    // answering true on the blacklist would reject all mail.
    EXPECT_FALSE(Detector().IsWhitelisted("stranger@never-listed.test"));
    EXPECT_FALSE(Detector().IsBlacklisted("stranger@never-listed.test"));
    EXPECT_FALSE(Detector().IsWhitelisted(""));
    EXPECT_FALSE(Detector().IsBlacklisted(""));
}

TEST_F(SpamSenderListTest, ABlacklistedDomainCoversItsSenders) {
    ASSERT_TRUE(Detector().AddToBlacklist("probe-bad.test"));
    EXPECT_TRUE(Detector().IsBlacklisted("spammer@probe-bad.test"));
    EXPECT_FALSE(Detector().IsBlacklisted("spammer@probe-good.test"));
}

TEST_F(SpamSenderListTest, ADomainEntryDoesNotMatchALookalikeDomain) {
    // The reach of an entry must stop at the domain boundary. A list matched by substring would let
    // probe-reach.test.evil.example inherit the verdict.
    ASSERT_TRUE(Detector().AddToBlacklist("probe-reach.test"));
    EXPECT_TRUE(Detector().IsBlacklisted("x@probe-reach.test"));
    EXPECT_FALSE(Detector().IsBlacklisted("x@probe-reach.test.evil.example"))
        << "a subdomain of a listed domain inherited its blacklist verdict";
    EXPECT_FALSE(Detector().IsBlacklisted("x@notprobe-reach.test"))
        << "a host merely ending in the listed domain inherited its verdict";
}

}  // namespace ShadowStrike::ScheduleSenderTest
