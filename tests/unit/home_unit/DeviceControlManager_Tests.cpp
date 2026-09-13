/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DeviceControlManager_Tests.cpp
 * @brief The wildcard matcher that decides whether a device-control rule applies.
 *
 * DeviceCriteria::MatchWildcard is the pattern engine behind RuleMatchType::Wildcard, so it decides
 * whether an allow or a block rule applies to a device that was just plugged in. It is a hand-written
 * greedy matcher with backtracking, which is a shape that is easy to get subtly wrong: the classic
 * errors are failing to backtrack after a star, mishandling a trailing star, and accepting a pattern
 * that is longer than the string.
 *
 * Because the same engine serves both allow and block rules, an error is dangerous in both
 * directions - a block rule that fails to match lets a device through, and an allow rule that matches
 * too much admits one it should not - so the cases below assert both.
 *
 * ONE PROPERTY IS DELIBERATELY ASSERTED AS CURRENT BEHAVIOUR RATHER THAN AS DESIRABLE: matching is
 * case-sensitive. Whether it should be is a policy question, because making it insensitive would
 * widen allow rules as well as block rules, and that needs an owner ruling rather than a quiet
 * change. It is filed. Pinning the present behaviour means the decision is made deliberately when it
 * is made.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/USB_Protection/DeviceControlManager.hpp"

#include <string>

namespace ShadowStrike::USB::Test {
namespace {

[[nodiscard]] bool Match(const std::string& text, const std::string& pattern) {
    return DeviceCriteria::MatchWildcard(text, pattern);
}

TEST(DeviceWildcardTest, AnExactPatternMatchesOnlyItself) {
    EXPECT_TRUE(Match("VID_046D", "VID_046D"));
    EXPECT_FALSE(Match("VID_046D", "VID_046E"));
    EXPECT_FALSE(Match("VID_046D", "VID_046"))
        << "a pattern shorter than the string matched, so a rule would apply to more devices than "
           "it names";
    EXPECT_FALSE(Match("VID_046", "VID_046D"))
        << "a pattern longer than the string matched";
}

TEST(DeviceWildcardTest, ATrailingStarMatchesAnyRemainder) {
    EXPECT_TRUE(Match("VID_046D&PID_C52B", "VID_046D*"));
    EXPECT_TRUE(Match("VID_046D", "VID_046D*"))
        << "a trailing star must also match the empty remainder";
    EXPECT_FALSE(Match("VID_046E&PID_C52B", "VID_046D*"));
}

TEST(DeviceWildcardTest, ALeadingStarMatchesAnyPrefix) {
    EXPECT_TRUE(Match("USB\\VID_046D&PID_C52B", "*PID_C52B"));
    EXPECT_TRUE(Match("PID_C52B", "*PID_C52B"))
        << "a leading star must also match the empty prefix";
    EXPECT_FALSE(Match("USB\\VID_046D&PID_C52C", "*PID_C52B"));
}

TEST(DeviceWildcardTest, AnInteriorStarRequiresBacktracking) {
    // The case a naive matcher fails: after consuming greedily, the engine must retry from the star
    // when the tail stops matching.
    EXPECT_TRUE(Match("USB\\VID_046D&PID_C52B\\5&1F2E", "USB\\*C52B*"));
    EXPECT_TRUE(Match("aaaab", "a*b"));
    EXPECT_TRUE(Match("abcbcbcd", "a*d"))
        << "the matcher did not backtrack past a false tail match";
    EXPECT_FALSE(Match("abcbcbce", "a*d"));
}

TEST(DeviceWildcardTest, MultipleStarsCollapse) {
    EXPECT_TRUE(Match("VID_046D&PID_C52B", "*046D*C52B*"));
    EXPECT_TRUE(Match("abc", "***"));
    EXPECT_FALSE(Match("VID_046D&PID_C52B", "*046D*C52C*"));
}

TEST(DeviceWildcardTest, TheEmptyCasesBehaveConsistently) {
    EXPECT_TRUE(Match("", "")) << "an empty pattern must match an empty string";
    EXPECT_TRUE(Match("", "*")) << "a star must match an empty string";
    EXPECT_FALSE(Match("anything", ""))
        << "an empty pattern matched a non-empty string, so a rule with no pattern would apply to "
           "every device";
    EXPECT_FALSE(Match("", "a"));
}

TEST(DeviceWildcardTest, MatchingIsCaseSensitiveToday) {
    // CURRENT BEHAVIOUR, pinned rather than endorsed. Device strings come from the vendor's
    // descriptor, so a rule written as *kingston* does not match a device reporting Kingston. Making
    // this insensitive would widen ALLOW rules as well as block rules, so it is an owner decision and
    // is filed. This case exists so that decision is taken deliberately rather than by accident.
    EXPECT_FALSE(Match("Kingston DataTraveler", "*kingston*"));
    EXPECT_TRUE(Match("Kingston DataTraveler", "*Kingston*"));
}

TEST(DeviceWildcardTest, AStarDoesNotMatchAcrossAMissingLiteral) {
    // Anti-vacuity for every positive case above: if the matcher returned true whenever a star was
    // present, all of them would pass while the engine decided nothing.
    EXPECT_FALSE(Match("VID_046D", "*PID*"));
    EXPECT_FALSE(Match("short", "*averylongliteral*"));
}

}  // namespace
}  // namespace ShadowStrike::USB::Test
