/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file BrowserSafeSearchHonesty_Tests.cpp
 * @brief BrowserProtection reports safe search as it is in effect, not as it was requested (task 247).
 *
 * This build has no safe-search enforcement mechanism: it writes no browser policy and rewrites no
 * search URL. EnforceSafeSearch used to store the request, log "enabled" and return true, and
 * IsSafeSearchEnforced then echoed the request; navigation counted every search-engine visit as an
 * enforcement. A caller was told the protection was on at every point while nothing enforced it.
 *
 * The cases pin the honest contract: an enable request is refused, the query never reports the
 * request as state, and the request itself is still recorded for GetConfiguration.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/BrowserProtection.hpp"

#include <string>

namespace ShadowStrike::WebBrowser::Test {
namespace {

// BrowserProtection is a process-wide singleton shared with other test files, so each case
// restores the original configuration on exit.
class BrowserSafeSearchHonestyTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& bp = BrowserProtection::Instance();
        if (!bp.IsInitialized()) {
            (void)bp.Initialize();
        }
        ASSERT_TRUE(bp.IsInitialized());
        m_saved = bp.GetConfiguration();
    }

    void TearDown() override {
        (void)BrowserProtection::Instance().UpdateConfiguration(m_saved);
    }

    BrowserProtectionConfiguration m_saved;
};

TEST_F(BrowserSafeSearchHonestyTest, AnEnableRequestIsRefusedBecauseNothingEnforcesIt) {
    auto& bp = BrowserProtection::Instance();
    EXPECT_FALSE(bp.EnforceSafeSearch(true))
        << "EnforceSafeSearch(true) reported success, but this build writes no browser policy and "
           "rewrites no search URL";
}

TEST_F(BrowserSafeSearchHonestyTest, TheQueryNeverReportsTheRequestAsState) {
    auto& bp = BrowserProtection::Instance();
    (void)bp.EnforceSafeSearch(true);
    EXPECT_FALSE(bp.IsSafeSearchEnforced())
        << "IsSafeSearchEnforced echoed the request; nothing enforces safe search";

    SafeSearchSettings settings;
    settings.enabled = true;
    EXPECT_FALSE(bp.UpdateSafeSearchSettings(settings))
        << "enabling safe search through its settings reported success with nothing enforced";
    EXPECT_FALSE(bp.IsSafeSearchEnforced());

    BrowserProtectionConfiguration cfg = bp.GetConfiguration();
    cfg.enableSafeSearch = true;
    ASSERT_TRUE(bp.UpdateConfiguration(cfg));
    EXPECT_FALSE(bp.IsSafeSearchEnforced())
        << "a configuration that requests safe search made the module report it as enforced";
}

TEST_F(BrowserSafeSearchHonestyTest, TheRequestIsStillRecordedInTheConfiguration) {
    auto& bp = BrowserProtection::Instance();
    (void)bp.EnforceSafeSearch(true);
    EXPECT_TRUE(bp.GetConfiguration().enableSafeSearch)
        << "the request was dropped; GetConfiguration should report what was asked";

    SafeSearchSettings settings;
    settings.enabled = true;
    settings.youtubeRestricted = false;
    (void)bp.UpdateSafeSearchSettings(settings);
    EXPECT_FALSE(bp.GetConfiguration().safeSearch.youtubeRestricted)
        << "UpdateSafeSearchSettings did not store the settings it was given";

    EXPECT_TRUE(bp.EnforceSafeSearch(false))
        << "clearing the request reports the true state, so it succeeds";
    EXPECT_FALSE(bp.GetConfiguration().enableSafeSearch);
    EXPECT_FALSE(bp.IsSafeSearchEnforced());
}

TEST_F(BrowserSafeSearchHonestyTest, TheStatisticsCarryNoEnforcementCount) {
    // Navigation used to count every search-engine visit as a safe-search enforcement while
    // nothing was enforced, and the count travelled in the statistics JSON. The statistic is
    // removed rather than left at zero: a field that can never move is not a measurement.
    const std::string json = BrowserProtection::Instance().GetStatistics().ToJson();
    EXPECT_EQ(std::string::npos, json.find("safeSearch"))
        << "the statistics report a safe-search figure again: " << json;
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
