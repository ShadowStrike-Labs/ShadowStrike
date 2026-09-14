/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file TrackerParamStrip_Tests.cpp
 * @brief Removing tracking parameters from a URL the user is navigating to.
 *
 * StripTrackingParams rewrites a URL before the browser follows it - it is reached both through the
 * public entry point and inside the request decision path, where its output is carried as modifiedUrl.
 * So every difference between input and output is something the user did not ask for and cannot see.
 *
 * THE INVARIANT IS EXACTLY THAT: remove the named tracking parameters and change nothing else. The
 * cases below are grouped by what must be preserved rather than by what is removed, because the
 * removal was never the part that was broken. Two things were:
 *
 *   - the fragment was destroyed, because the rebuild took everything before the '?' and never
 *     re-appended anything after the query. A single-page application routes on the fragment, so
 *     https://app.example.com/?utm_source=x#/dashboard/settings collapsed to the application root.
 *   - a parameter with an explicitly empty value lost its separator, so ?a=&b=1 became ?a&b=1, and
 *     "?a=" is an empty string where "?a" is an absent value to many server frameworks.
 *
 * The suite runs against a default-configured blocker, so DEFAULT_STRIP_PARAMS is what is in force.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/TrackerBlocker.hpp"

#include <string>

namespace ShadowStrike::WebBrowser::Test {
namespace {

class TrackerParamStripTest : public ::testing::Test {
protected:
    /// The strip set is populated by Initialize() from DEFAULT_STRIP_PARAMS, so without this every
    /// case would run against an EMPTY set and nothing would ever be stripped - the tests would
    /// then describe an uninitialised object rather than the feature.
    static void SetUpTestSuite() {
        ASSERT_TRUE(TrackerBlocker::Instance().Initialize())
            << "the tracker blocker could not be initialised, so the strip set is empty and no case "
               "below would mean anything";
    }

    [[nodiscard]] std::string Strip(const std::string& url) const {
        return TrackerBlocker::Instance().StripTrackingParams(url);
    }
};

// ============================================================================================
// Removal - the part that already worked, asserted so the rest is not vacuous
// ============================================================================================

TEST_F(TrackerParamStripTest, AKnownTrackingParameterIsRemoved) {
    EXPECT_EQ("https://example.com/page", Strip("https://example.com/page?utm_source=newsletter"));
    EXPECT_EQ("https://example.com/page", Strip("https://example.com/page?fbclid=abc123"));
    EXPECT_EQ("https://example.com/page", Strip("https://example.com/page?gclid=xyz"));
}

TEST_F(TrackerParamStripTest, OnlyTheTrackingParametersAreRemoved) {
    EXPECT_EQ("https://example.com/search?q=widgets",
              Strip("https://example.com/search?q=widgets&utm_source=news"));
    EXPECT_EQ("https://example.com/search?q=widgets&page=2",
              Strip("https://example.com/search?utm_medium=email&q=widgets&page=2"));
}

TEST_F(TrackerParamStripTest, AUrlWithNothingToStripIsUnchanged) {
    // Anti-vacuity for every preservation case: the function must be capable of returning its input
    // untouched, or the assertions below would pass for the wrong reason.
    const std::string url = "https://example.com/search?q=widgets&page=2";
    EXPECT_EQ(url, Strip(url));
}

// ============================================================================================
// Preservation - what the rewrite must not touch
// ============================================================================================

TEST_F(TrackerParamStripTest, TheFragmentSurvivesStripping) {
    // The defect this file exists for. A single-page application routes on the fragment.
    EXPECT_EQ("https://app.example.com/#/dashboard/settings",
              Strip("https://app.example.com/?utm_source=x#/dashboard/settings"))
        << "the fragment was discarded, so a deep link collapses to the application root";
    EXPECT_EQ("https://example.com/doc#section-3",
              Strip("https://example.com/doc?fbclid=abc#section-3"));
}

TEST_F(TrackerParamStripTest, TheFragmentSurvivesAlongsideRemainingParameters) {
    EXPECT_EQ("https://example.com/doc?q=widgets#section-3",
              Strip("https://example.com/doc?q=widgets&utm_id=7#section-3"));
}

TEST_F(TrackerParamStripTest, AFragmentOnAUrlWithNoQueryIsUntouched) {
    const std::string url = "https://app.example.com/#/dashboard/settings";
    EXPECT_EQ(url, Strip(url));
}

TEST_F(TrackerParamStripTest, AnExplicitlyEmptyValueKeepsItsSeparator) {
    // "?a=" is an empty string; "?a" is an absent value. Rewriting one into the other changes a
    // parameter the product was not asked to touch.
    EXPECT_EQ("https://example.com/p?a=&b=1", Strip("https://example.com/p?a=&b=1&utm_source=x"))
        << "an empty-valued parameter lost its '=', changing its meaning to the server";
    EXPECT_EQ("https://example.com/p?flag", Strip("https://example.com/p?flag&utm_term=y"))
        << "a valueless parameter gained an '=' it did not have";
}

TEST_F(TrackerParamStripTest, TheSchemeHostAndPathAreUntouched) {
    EXPECT_EQ("https://sub.example.co.uk:8443/deep/path/file.html",
              Strip("https://sub.example.co.uk:8443/deep/path/file.html?utm_campaign=spring"));
}

// ============================================================================================
// Inputs that must not be mangled
// ============================================================================================

TEST_F(TrackerParamStripTest, AUrlWithNoQueryIsReturnedUnchanged) {
    EXPECT_EQ("https://example.com/page", Strip("https://example.com/page"));
    EXPECT_EQ("https://example.com/", Strip("https://example.com/"));
}

TEST_F(TrackerParamStripTest, AnEmptyOrMalformedUrlIsReturnedUnchanged) {
    // The parse failure path must return the input rather than an empty string, or a request would
    // be rewritten to nothing.
    EXPECT_EQ("", Strip(""));
    EXPECT_EQ("not a url at all", Strip("not a url at all"));
}

TEST_F(TrackerParamStripTest, StrippingIsIdempotent) {
    // Applying the rewrite twice must equal applying it once. If it were not, a URL passing through
    // the request path more than once would keep changing.
    const std::string once = Strip("https://example.com/p?q=1&utm_source=a&b=&utm_id=2#frag");
    EXPECT_EQ(once, Strip(once)) << "the rewrite is not idempotent, so repeated passes keep altering "
                                    "the URL";
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
