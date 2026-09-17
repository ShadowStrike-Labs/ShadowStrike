/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file TrackerWhitelistScope_Tests.cpp
 * @brief How far a tracker whitelist entry reaches.
 *
 * The whitelist is the FIRST check in the request decision path and a match returns Allow immediately, so an
 * entry that reaches too far does not lower a score - it skips tracker blocking entirely.
 *
 * Two kinds of entry share one container, and only one of them may be matched as a substring:
 *
 *     WhitelistDomain("example.com")     the caller named a HOST     -> exact match only
 *     WhitelistUrl("/analytics/pixel")   the caller named a PATTERN  -> substring is what that means
 *
 * A domain was being registered as both, so any URL that merely MENTIONED a whitelisted domain was exempt -
 * a tracker appending ?referrer=example.com to its own URL was allowed through. The cases below separate the
 * two meanings and pin each.
 *
 * These run against a default-configured blocker with a whitelist the cases populate themselves, so nothing
 * depends on shipped blocklist content.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/TrackerBlocker.hpp"

#include <string>

namespace ShadowStrike::WebBrowser::WhitelistScopeTest {
namespace {

class TrackerWhitelistTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto& tb = TrackerBlocker::Instance();
        if (!tb.IsInitialized()) {
            (void)tb.Initialize();
        }
        ASSERT_TRUE(tb.IsInitialized()) << "the tracker blocker could not be initialised";
    }

    void SetUp() override {
        // Each case starts from an empty whitelist, so one case cannot widen another.
        TrackerBlocker::Instance().ClearWhitelist();
    }

    void TearDown() override { TrackerBlocker::Instance().ClearWhitelist(); }

    static TrackerBlocker& Blocker() { return TrackerBlocker::Instance(); }
};

}  // namespace

// ============================================================================================
// A whitelisted domain means that host, not that string
// ============================================================================================

TEST_F(TrackerWhitelistTest, AWhitelistedDomainExemptsItsOwnUrls) {
    // Anti-vacuity for every rejection below: the whitelist must actually work.
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));
    EXPECT_TRUE(Blocker().IsWhitelisted("https://example.com/"));
    EXPECT_TRUE(Blocker().IsWhitelisted("https://example.com/some/path?q=1"));
    EXPECT_TRUE(Blocker().IsWhitelisted("http://example.com"));
}

TEST_F(TrackerWhitelistTest, AWhitelistedDomainDoesNotExemptAUrlThatMerelyMentionsIt) {
    // The defect. The whitelist is the first check in the request path, so a match here skips tracker
    // blocking altogether - and a tracker only had to append the string to its own URL.
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));

    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.doubleclick.net/pixel?referrer=example.com"))
        << "a tracker was exempted because its QUERY STRING mentioned a whitelisted domain";
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.net/example.com/beacon"))
        << "a tracker was exempted because its PATH mentioned a whitelisted domain";
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.net/p#example.com"))
        << "a tracker was exempted because its FRAGMENT mentioned a whitelisted domain";
}

TEST_F(TrackerWhitelistTest, AWhitelistedDomainDoesNotExemptALookalikeHost) {
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://notexample.com/"))
        << "a host merely ending in the whitelisted domain was exempted";
    EXPECT_FALSE(Blocker().IsWhitelisted("https://example.com.evil.net/"))
        << "a host with the whitelisted domain as a PREFIX label was exempted";
}

TEST_F(TrackerWhitelistTest, AShortWhitelistedDomainIsNotACatchAll) {
    // The worst case of substring matching: a short entry matches almost anything.
    ASSERT_TRUE(Blocker().WhitelistDomain("t.co"));
    EXPECT_TRUE(Blocker().IsWhitelisted("https://t.co/abc"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.example.net/t.co/pixel"))
        << "a two-letter-plus-suffix entry exempted an unrelated tracker";
}

// ============================================================================================
// A whitelisted URL pattern means a substring, because that is what was asked for
// ============================================================================================

TEST_F(TrackerWhitelistTest, AWhitelistedUrlPatternStillMatchesAsASubstring) {
    // This must NOT be narrowed by the fix. A caller of WhitelistUrl named a pattern deliberately, and
    // matching it anywhere in the URL is the documented meaning.
    ASSERT_TRUE(Blocker().WhitelistUrl("/analytics/allowed-pixel"));
    EXPECT_TRUE(Blocker().IsWhitelisted("https://anyhost.example/analytics/allowed-pixel?id=7"))
        << "a URL pattern stopped matching as a substring, so pattern whitelisting is broken";
    EXPECT_FALSE(Blocker().IsWhitelisted("https://anyhost.example/analytics/other-pixel"));
}

TEST_F(TrackerWhitelistTest, TheTwoEntryKindsDoNotInterfere) {
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));
    ASSERT_TRUE(Blocker().WhitelistUrl("/allowed/beacon"));

    EXPECT_TRUE(Blocker().IsWhitelisted("https://example.com/anything"));
    EXPECT_TRUE(Blocker().IsWhitelisted("https://other.test/allowed/beacon"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.test/?ref=example.com"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.test/denied/beacon"));
}

// ============================================================================================
// Bookkeeping the UI depends on
// ============================================================================================

TEST_F(TrackerWhitelistTest, BothEntryKindsAppearInTheWhitelistListing) {
    // GetWhitelist is what the settings screen shows. A domain must remain visible there even though it is
    // no longer matched as a pattern - that is why the fix skips domains during matching rather than
    // omitting them from the container.
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));
    ASSERT_TRUE(Blocker().WhitelistUrl("/allowed/beacon"));

    const auto listing = Blocker().GetWhitelist();
    EXPECT_NE(listing.end(), std::find(listing.begin(), listing.end(), std::string("example.com")))
        << "a whitelisted domain vanished from the user's own whitelist listing";
    EXPECT_NE(listing.end(), std::find(listing.begin(), listing.end(), std::string("/allowed/beacon")));
}

TEST_F(TrackerWhitelistTest, RemovingADomainRevokesItsExemption) {
    ASSERT_TRUE(Blocker().WhitelistDomain("example.com"));
    ASSERT_TRUE(Blocker().IsWhitelisted("https://example.com/"));
    EXPECT_TRUE(Blocker().RemoveFromWhitelist("example.com"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://example.com/"))
        << "the exemption survived removal, so a whitelist cannot be narrowed once widened";
}

TEST_F(TrackerWhitelistTest, AnEmptyWhitelistExemptsNothing) {
    EXPECT_FALSE(Blocker().IsWhitelisted("https://example.com/"));
    EXPECT_FALSE(Blocker().IsWhitelisted("https://tracker.doubleclick.net/pixel"));
    EXPECT_FALSE(Blocker().IsWhitelisted(""));
}

}  // namespace ShadowStrike::WebBrowser::WhitelistScopeTest
