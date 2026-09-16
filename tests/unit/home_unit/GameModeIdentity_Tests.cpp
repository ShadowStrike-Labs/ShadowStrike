/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file GameModeIdentity_Tests.cpp
 * @brief Recognising a game, whitelisting an overlay, and what a performance profile costs.
 *
 * Game mode trades protection for frame rate, so these three modules decide how much is given up and
 * when. The cases below concentrate on name matching and on the ordering of the profiles, because those
 * are the parts that decide rather than merely report.
 *
 * NAME MATCHING IS THE DEFECT CLASS HERE. Windows process and module names are case-insensitive, so any
 * container keyed on one must normalise. GameProcessDetector kept user-defined games in two containers
 * that disagreed - m_gameDatabase lowercased at all eight of its sites, m_userDefinedGames raw at all
 * four - so a removal could clear one and leave the other. That is now consistent, and these cases hold
 * it there.
 *
 * The profile settings are asserted RELATIONALLY rather than by value: a retuning of the numbers must not
 * fail the suite, but an inversion must - a profile advertised as lighter on the machine has to actually
 * permit less than one advertised as heavier, or the setting misleads.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/GameMode/GameProcessDetector.hpp"
#include "Products/Community/PhantomHome/GameMode/OverlayProtection.hpp"
#include "Products/Community/PhantomHome/GameMode/PerformanceOptimizer.hpp"

#include <string>

namespace ShadowStrike::GameMode::Test {

namespace {

/// Initialize() returns FALSE when the singleton is already initialised, which is indistinguishable
/// from a genuine failure. Since every suite in this binary shares one instance, each fixture below
/// initialises ONCE and accepts either outcome, then requires IsInitialized() to be true - which is the
/// question actually being asked.
template <typename T>
void InitialiseOnce(T& instance, const char* what) {
    if (!instance.IsInitialized()) {
        (void)instance.Initialize();
    }
    ASSERT_TRUE(instance.IsInitialized())
        << what << " could not be initialised, so no case below would mean anything";
}

}  // namespace

namespace {

class GameProcessIdentityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // IsKnownGame returns false outright when uninitialised, so without this every case below
        // would pass for the wrong reason.
        InitialiseOnce(GameProcessDetector::Instance(), "the game process detector");
    }

    static GameProcessDetector& Detector() { return GameProcessDetector::Instance(); }
};

}  // namespace

// ============================================================================================
// Recognising a game by name
// ============================================================================================

TEST_F(GameProcessIdentityTest, ABuiltInGameIsRecognisedWhateverTheCase) {
    // The built-in database is keyed lowercase and the lookup lowercases its argument, so all three
    // spellings must agree. A process name's case depends on how it was launched and enumerated.
    EXPECT_TRUE(Detector().IsKnownGame(L"Cyberpunk2077.exe"));
    EXPECT_TRUE(Detector().IsKnownGame(L"cyberpunk2077.exe"));
    EXPECT_TRUE(Detector().IsKnownGame(L"CYBERPUNK2077.EXE"));
}

TEST_F(GameProcessIdentityTest, AnOrdinaryProcessIsNotAGame) {
    // Anti-vacuity, and the direction that matters: game mode suppresses protection, so a false
    // positive here reduces protection for something that is not a game.
    EXPECT_FALSE(Detector().IsKnownGame(L"notepad.exe"));
    EXPECT_FALSE(Detector().IsKnownGame(L"svchost.exe"));
    EXPECT_FALSE(Detector().IsKnownGame(L"explorer.exe"));
    EXPECT_FALSE(Detector().IsKnownGame(L""));
}

TEST_F(GameProcessIdentityTest, AUserAddedGameIsFoundWhateverCaseTheQueryUses) {
    // The fix this file was written against. Both containers holding the name are now keyed the same
    // way, so a game added in one case is found in any other.
    ASSERT_TRUE(Detector().AddUserGame(L"MyCustomGame.exe", "My Custom Game"));
    EXPECT_TRUE(Detector().IsKnownGame(L"MyCustomGame.exe"));
    EXPECT_TRUE(Detector().IsKnownGame(L"mycustomgame.exe"));
    EXPECT_TRUE(Detector().IsKnownGame(L"MYCUSTOMGAME.EXE"));
    EXPECT_TRUE(Detector().RemoveUserGame(L"MyCustomGame.exe"));
}

TEST_F(GameProcessIdentityTest, AUserAddedGameIsRemovableUsingADifferentCase) {
    // The concrete consequence of the two containers disagreeing: the database entry was erased by a
    // lowercased key while the bookkeeping entry was erased by the raw one, so removing with a different
    // case cleared one and left the other. Both must now go.
    ASSERT_TRUE(Detector().AddUserGame(L"CaseTestGame.exe", "Case Test"));
    ASSERT_TRUE(Detector().IsKnownGame(L"casetestgame.exe"));

    EXPECT_TRUE(Detector().RemoveUserGame(L"casetestgame.exe"))
        << "removal with a different case reported failure";
    EXPECT_FALSE(Detector().IsKnownGame(L"CaseTestGame.exe"))
        << "the game is still recognised after removal, so one container kept its entry";
    EXPECT_FALSE(Detector().IsKnownGame(L"casetestgame.exe"));
}

TEST_F(GameProcessIdentityTest, RemovingSomethingNeverAddedReportsFailure) {
    // A removal that always reports success would hide the case above.
    EXPECT_FALSE(Detector().RemoveUserGame(L"NeverAddedGame.exe"));
}

TEST_F(GameProcessIdentityTest, AddingAGameTwiceInDifferentCasesLeavesOneEntry) {
    // Two containers keyed differently would hold two entries for one game, so a single removal would
    // leave the game half-registered.
    ASSERT_TRUE(Detector().AddUserGame(L"DoubleAdd.exe", "First"));
    ASSERT_TRUE(Detector().AddUserGame(L"doubleadd.exe", "Second"));
    EXPECT_TRUE(Detector().RemoveUserGame(L"DOUBLEADD.EXE"));
    EXPECT_FALSE(Detector().IsKnownGame(L"doubleadd.exe"))
        << "one removal did not clear the game, so it was registered twice under different keys";
}

// ============================================================================================
// Overlay whitelisting
// ============================================================================================

class OverlayWhitelistTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        InitialiseOnce(OverlayProtection::Instance(), "the overlay protection module");
    }
};

TEST_F(OverlayWhitelistTest, TheWhitelistIsCaseInsensitive) {
    // A module whitelist decides what is allowed to inject into a protected game process. It lowercases
    // both the stored value and the query, so an entry configured in any case must be found in any
    // other - otherwise a user's exemption silently does not apply.
    auto& overlay = OverlayProtection::Instance();
    ASSERT_TRUE(overlay.AddToWhitelist(L"MyOverlay.dll"));
    EXPECT_TRUE(overlay.IsWhitelisted(L"MyOverlay.dll"));
    EXPECT_TRUE(overlay.IsWhitelisted(L"myoverlay.dll"));
    EXPECT_TRUE(overlay.IsWhitelisted(L"MYOVERLAY.DLL"));
}

TEST_F(OverlayWhitelistTest, AnUnlistedModuleIsNotWhitelisted) {
    // The load-bearing negative: a whitelist that answers true for anything would exempt every injected
    // module from inspection.
    auto& overlay = OverlayProtection::Instance();
    EXPECT_FALSE(overlay.IsWhitelisted(L"never_whitelisted_module.dll"));
    EXPECT_FALSE(overlay.IsWhitelisted(L""));
}

// ============================================================================================
// What a performance profile permits
// ============================================================================================

class PerformanceProfileTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        InitialiseOnce(PerformanceOptimizer::Instance(), "the performance optimizer");
    }
};

TEST_F(PerformanceProfileTest, TheProfilesAreOrderedByHowMuchTheyPermit) {
    // Relational, so a retuning does not fail this but an inversion does. A profile advertised as
    // lighter on the machine must actually permit less.
    auto& opt = PerformanceOptimizer::Instance();

    const auto normal = opt.GetProfileSettings(OptimizationProfile::Normal);
    const auto balanced = opt.GetProfileSettings(OptimizationProfile::Balanced);
    const auto performance = opt.GetProfileSettings(OptimizationProfile::Performance);
    const auto powerSaver = opt.GetProfileSettings(OptimizationProfile::PowerSaver);
    const auto silent = opt.GetProfileSettings(OptimizationProfile::Silent);

    EXPECT_GT(normal.throttle.cpuUsageLimit, balanced.throttle.cpuUsageLimit);
    EXPECT_GT(balanced.throttle.cpuUsageLimit, performance.throttle.cpuUsageLimit);
    EXPECT_GT(performance.throttle.cpuUsageLimit, powerSaver.throttle.cpuUsageLimit);
    EXPECT_GT(powerSaver.throttle.cpuUsageLimit, silent.throttle.cpuUsageLimit);
}

TEST_F(PerformanceProfileTest, NormalImposesNoCpuCeiling) {
    // Anti-vacuity for the ordering above: the scale must reach an unthrottled end, or every profile
    // would restrict the product and Normal would not mean normal.
    auto& opt = PerformanceOptimizer::Instance();
    const auto normal = opt.GetProfileSettings(OptimizationProfile::Normal);
    EXPECT_EQ(100, static_cast<int>(normal.throttle.cpuUsageLimit));
    EXPECT_FALSE(normal.deferBackgroundWork)
        << "the Normal profile defers background work, so protection is reduced by default";
}

TEST_F(PerformanceProfileTest, EveryProfileAllowsAtLeastOneScanPerSecond) {
    // ShouldThrottleScan throttles when the count REACHES the limit, so a limit of zero would defer
    // every scan for as long as throttling is active. No profile may configure that.
    //
    // Nothing calls ShouldThrottleScan today, so this cannot bite yet; the filing records that. The
    // assertion is here so the value is safe if and when the throttle is wired up.
    auto& opt = PerformanceOptimizer::Instance();
    for (const auto profile : {OptimizationProfile::Normal, OptimizationProfile::Balanced,
                               OptimizationProfile::Performance, OptimizationProfile::PowerSaver,
                               OptimizationProfile::Silent}) {
        const auto settings = opt.GetProfileSettings(profile);
        EXPECT_GT(settings.throttle.scanRateLimit, 0u)
            << "profile " << settings.name
            << " permits zero scans per second, which stops scanning entirely while throttling is on";
    }
}

TEST_F(PerformanceProfileTest, AnUnknownProfileFallsBackToSomethingUsable) {
    // A profile value outside the enum must not yield a zeroed settings block, which would read as the
    // most restrictive possible configuration.
    auto& opt = PerformanceOptimizer::Instance();
    const auto bogus = opt.GetProfileSettings(static_cast<OptimizationProfile>(240));
    EXPECT_FALSE(bogus.name.empty()) << "an unknown profile produced a nameless settings block";
    EXPECT_GT(bogus.throttle.cpuUsageLimit, 0)
        << "an unknown profile produced a zero CPU ceiling, which would halt the product";
    EXPECT_GT(bogus.throttle.scanRateLimit, 0u);
}

}  // namespace ShadowStrike::GameMode::Test
