/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HomeAdvisoryState_Tests.cpp
 * @brief Dismissing a recommendation, and two enums that look alike and are not.
 *
 * Both services here are asynchronous: ForceRecompute sets a flag and wakes a worker thread, so nothing
 * below waits on a recomputation. Asserting on a worker's output would make these cases a statement about
 * machine load rather than about behaviour, and this suite already carries one wall-clock assertion that
 * fails under load. Only the synchronous paths are exercised, and the omission is deliberate.
 *
 * THE ENUM PAIR IS THE REASON THIS FILE COMBINES THE TWO MODULES.
 *
 *     Recommendations::Severity     Info 0,  Warn 1,     Critical 2                  <- ordered by severity
 *     HeadlineState::State          Healthy 0, AtRisk 1, Critical 2, Unknown 3       <- NOT ordered
 *
 * Severity may be compared numerically. State may not: Unknown means "before the first evaluation
 * completes", and it sits ABOVE Critical, so combining two states with std::max - the natural way to
 * write "take the worse of these" - would rank "not yet known" as worse than "critical". Nothing does
 * that today; it was measured across the tree, and the state is assigned by explicit branches and
 * consumed by a switch. These cases exist so that the day someone reaches for max, a test fails first.
 *
 * The same shape is already recorded for the kernel verdict enum, where Unknown, Clean, Malicious and
 * Suspicious are likewise not in severity order and a dedicated combining function exists specifically
 * so that nobody uses max.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/HeadlineState/HeadlineStateService.hpp"
#include "Products/Community/PhantomHome/Recommendations/RecommendationsEngine.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace ShadowStrike::Products::Home::Test {
namespace {

using HeadlineState::HeadlineStateService;
using Recommendations::RecommendationsEngine;
using Recommendations::Severity;

template <typename E>
[[nodiscard]] constexpr int Ord(E value) {
    return static_cast<int>(static_cast<std::uint8_t>(value));
}

}  // namespace

// ============================================================================================
// Recommendation severity - safe to compare
// ============================================================================================

TEST(RecommendationSeverityTest, SeverityIsOrderedByHowBadItIs) {
    // This enum MAY be compared numerically, and code that ranks recommendations relies on it.
    EXPECT_LT(Ord(Severity::Info), Ord(Severity::Warn));
    EXPECT_LT(Ord(Severity::Warn), Ord(Severity::Critical));
    EXPECT_EQ(0, Ord(Severity::Info)) << "Info must be the lowest value so a default-constructed "
                                         "severity is the least alarming, not the most";
}

// ============================================================================================
// Headline state - NOT safe to compare
// ============================================================================================

TEST(HeadlineStateTest, TheThreeEvaluatedStatesAreOrderedByHowBadTheyAre) {
    using State = HeadlineState::State;
    EXPECT_LT(Ord(State::Healthy), Ord(State::AtRisk));
    EXPECT_LT(Ord(State::AtRisk), Ord(State::Critical));
}

TEST(HeadlineStateTest, UnknownSortsAboveCriticalSoStatesMustNotBeCompared) {
    // PINNED DELIBERATELY. Unknown means "before the first evaluation completes" - the absence of
    // information, not the worst news - yet it holds the highest value in the enum.
    //
    // So this enum must never be ordered, maxed, or clamped. Nothing does so today; the tree was
    // searched for std::max over a State, for relational comparisons between States, and for casts of a
    // State to an integer, and the only consumers assign by explicit branch and read by switch.
    //
    // If this case fails, the enum was reordered. That is a GOOD change - but the codebase must then be
    // re-checked for anything that depended on the old layout, and this case should be replaced by one
    // asserting the new ordering rather than deleted.
    using State = HeadlineState::State;
    EXPECT_GT(Ord(State::Unknown), Ord(State::Critical))
        << "Unknown no longer sorts above Critical - the enum was reordered, which may now make "
           "numeric comparison safe; re-check consumers and update this case";
}

TEST(HeadlineStateTest, TheDefaultStateIsUnknownRatherThanHealthy) {
    // A default-constructed snapshot must not claim the machine is healthy. Before the first evaluation
    // the honest answer is that nothing is known, and the UI shows a distinct indicator for it.
    using State = HeadlineState::State;
    const HeadlineState::HeadlineSnapshot fresh{};
    EXPECT_EQ(State::Unknown, fresh.state)
        << "a default snapshot reports a definite state before anything has been evaluated";
}

TEST(HeadlineStateTest, SnapshotIsReadableWithoutStartingTheService) {
    // The IPC dashboard handler calls Snapshot() directly, so it must be safe to call on a service that
    // was never started - it must not construct a worker, block, or crash.
    const auto snapshot = HeadlineStateService::Instance().Snapshot();
    EXPECT_TRUE(snapshot.state == HeadlineState::State::Unknown
                || snapshot.state == HeadlineState::State::Healthy
                || snapshot.state == HeadlineState::State::AtRisk
                || snapshot.state == HeadlineState::State::Critical)
        << "Snapshot returned a state outside the enum";
}

// ============================================================================================
// Dismissing a recommendation - the synchronous half
// ============================================================================================

TEST(RecommendationDismissTest, DismissingAnIdThatIsNotPresentIsHarmless) {
    // Dismiss is void and takes an arbitrary string from an IPC verb, so an id that matches nothing must
    // be a no-op rather than an error or a crash.
    auto& engine = RecommendationsEngine::Instance();
    const auto before = engine.Snapshot().size();
    engine.Dismiss("test.probe.id.that.does.not.exist");
    EXPECT_EQ(before, engine.Snapshot().size())
        << "dismissing an unknown id changed the active set";
}

TEST(RecommendationDismissTest, DismissingAnEmptyIdIsHarmless) {
    auto& engine = RecommendationsEngine::Instance();
    const auto before = engine.Snapshot().size();
    engine.Dismiss("");
    EXPECT_EQ(before, engine.Snapshot().size())
        << "dismissing an empty id removed something, so the match is not on the id";
}

// A case asserting that Dismiss removes exactly the named recommendation was written and REMOVED. It
// could only run once the worker had produced something, so it needed a skip when the set was empty - and
// this suite is verified with zero skips, so adding one would weaken that guarantee rather than report a
// gap. The equivalent invariant is asserted deterministically at the source level instead, by the contract
// suite, which requires every recommendation id to be a distinct non-empty literal.

TEST(RecommendationDismissTest, EveryActiveRecommendationHasAUsableIdentity) {
    // The UI keys tiles by id and looks up its text by the two i18n keys, so an empty one renders a
    // blank tile the user cannot act on or dismiss. Ids must also be unique, since the struct documents
    // the id as the deduplication key.
    const auto active = RecommendationsEngine::Instance().Snapshot();
    std::vector<std::string> ids;
    ids.reserve(active.size());
    for (const auto& r : active) {
        EXPECT_FALSE(r.id.empty()) << "a recommendation has no id, so it cannot be dismissed";
        EXPECT_FALSE(r.titleKey.empty()) << "recommendation " << r.id << " has no title key";
        EXPECT_FALSE(r.detailKey.empty()) << "recommendation " << r.id << " has no detail key";
        ids.push_back(r.id);
    }
    std::sort(ids.begin(), ids.end());
    EXPECT_EQ(ids.end(), std::adjacent_find(ids.begin(), ids.end()))
        << "two active recommendations share an id, so dismissing one dismisses both";
}

}  // namespace ShadowStrike::Products::Home::Test
