/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PgtiFeedManager_Tests.cpp
 * @brief The threat-intel feed roster the UI reports from, and its per-feed enable switch.
 *
 * PgtiFeedManager owns the watchdog that marks a feed Degraded when a pull is overdue, and its
 * Snapshot is what the PGTI page and IPC verb 270 render. The roster is static, so the invariants
 * are structural: a feed must have an id, ids must be unique, and the enable switch must be
 * per-feed rather than global.
 *
 * The health value is deliberately NOT asserted to be any particular state. In a test process no
 * feed has ever been pulled, so Disabled is the correct and expected value, and asserting Healthy
 * would be asserting something false. What is asserted is that a feed reports zero work when it has
 * done none - a feed claiming loaded entries without a successful pull would be reporting
 * intelligence the product does not have.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/ThreatIntel/PgtiFeedManager.hpp"

#include <set>
#include <string>

namespace ShadowStrike::Products::Home::ThreatIntel::Test {
namespace {

class PgtiFeedManagerTest : public ::testing::Test {
protected:
    PgtiFeedManager& feeds = PgtiFeedManager::Instance();
};

TEST_F(PgtiFeedManagerTest, TheRosterIsPopulated) {
    // A lower bound rather than an exact count, so adding a feed does not fail the suite. An empty
    // roster would mean the PGTI page renders nothing while the feature is advertised.
    EXPECT_GE(feeds.Snapshot().size(), 5u)
        << "the PGTI feed roster is empty or nearly so, yet the UI advertises the feature";
}

TEST_F(PgtiFeedManagerTest, EveryFeedHasAUniqueIdentity) {
    // SetFeedEnabled and IPC verb 271 both address a feed by id, so a duplicate or empty id makes
    // one feed unaddressable.
    std::set<std::string> ids;
    for (const auto& feed : feeds.Snapshot()) {
        EXPECT_FALSE(feed.id.empty()) << "a feed has no id and cannot be addressed";
        EXPECT_TRUE(ids.insert(feed.id).second) << "duplicate feed id: " << feed.id;
    }
}

TEST_F(PgtiFeedManagerTest, AFeedThatHasNeverPulledReportsNoWork) {
    // Honesty of the reported state: a feed with no successful pull must not claim loaded entries
    // or transferred bytes, because the UI presents those as intelligence in hand.
    for (const auto& feed : feeds.Snapshot()) {
        if (feed.lastSuccess.time_since_epoch().count() != 0) {
            continue;   // a real pull happened; nothing to assert here
        }
        EXPECT_EQ(0u, feed.entriesLoaded)
            << feed.id << " reports loaded entries without a successful pull";
        EXPECT_EQ(0u, feed.bytesPulled)
            << feed.id << " reports transferred bytes without a successful pull";
    }
}

TEST_F(PgtiFeedManagerTest, EnablingOneFeedDoesNotEnableTheOthers) {
    // The switch must be per-feed. A global flag would mean disabling one credentialed feed
    // silently disabled the key-free public ones too.
    const auto roster = feeds.Snapshot();
    ASSERT_GE(roster.size(), 2u) << "at least two feeds are needed to prove independence";

    const std::string first = roster.front().id;
    const std::string second = roster.back().id;
    ASSERT_NE(first, second);

    feeds.SetFeedEnabled(first, false);
    feeds.SetFeedEnabled(second, true);

    bool sawFirst = false;
    bool sawSecond = false;
    for (const auto& feed : feeds.Snapshot()) {
        if (feed.id == first) {
            sawFirst = true;
            EXPECT_EQ(PgtiFeedStatus::Health::Disabled, feed.health)
                << first << " was disabled but does not report Disabled";
        }
        if (feed.id == second) {
            sawSecond = true;
            EXPECT_NE(PgtiFeedStatus::Health::Disabled, feed.health)
                << second << " was enabled but still reports Disabled, so the switch is global "
                << "or inverted";
        }
    }
    EXPECT_TRUE(sawFirst && sawSecond) << "a feed disappeared from the roster after being toggled";

    feeds.SetFeedEnabled(first, false);
    feeds.SetFeedEnabled(second, false);
}

TEST_F(PgtiFeedManagerTest, AnUnknownFeedIdIsIgnoredRatherThanCreatingAFeed) {
    const auto before = feeds.Snapshot().size();
    feeds.SetFeedEnabled("this-feed-does-not-exist", true);
    EXPECT_EQ(before, feeds.Snapshot().size())
        << "addressing an unknown feed id changed the roster";
}

}  // namespace
}  // namespace ShadowStrike::Products::Home::ThreatIntel::Test
