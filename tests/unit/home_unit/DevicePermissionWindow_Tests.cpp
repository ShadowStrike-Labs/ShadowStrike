/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DevicePermissionWindow_Tests.cpp
 * @brief The time-and-day window that permits microphone or camera access, and that both agree.
 *
 * AudioWhitelistEntry::IsCurrentlyAllowed and CameraWhitelistEntry::IsCurrentlyAllowed gate access to
 * a microphone and a camera respectively. Both are whitelist checks, so the dangerous direction is
 * answering ALLOWED when it should not: that grants a recording device to an application outside the
 * window the user configured.
 *
 * THE TWO IMPLEMENTATIONS ARE DUPLICATES. Their bodies are structurally identical and both delegate to
 * private IsWithinAllowedHours and IsCurrentDayAllowed helpers whose bodies are byte-identical after
 * whitespace normalisation - 72 characters each for the hours check and 56 each for the day check. They
 * are separate copies in separate files with no shared authority, so either can be changed alone.
 *
 * That is why this file tests them TOGETHER and asserts the same input yields the same answer from
 * both, rather than duplicating a test per module. The equivalence is the invariant worth holding: if
 * one copy is fixed or broken without the other, these cases fail rather than the divergence shipping.
 * The duplication itself is filed.
 *
 * Both helpers read the wall clock with no injection point, so the in-window and out-of-window
 * branches cannot be tested deterministically. What is tested exactly is everything reachable before
 * the clock, plus the day mask, which is invariant in COUNT even though which day matches is not.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Privacy/MicrophoneGuard.hpp"
#include "Products/Community/PhantomHome/Privacy/WebCamProtector.hpp"

#include <optional>

namespace ShadowStrike {
namespace {

/// An audio entry with no time or day restriction at all, so only the gate under test can deny it.
[[nodiscard]] Privacy::AudioWhitelistEntry UnrestrictedAudio() {
    Privacy::AudioWhitelistEntry e{};
    e.enabled = true;
    e.allowFromHour = std::nullopt;
    e.allowToHour = std::nullopt;
    e.allowedDays = 0x7F;
    return e;
}

/// The camera equivalent, configured identically.
[[nodiscard]] Privacy::CameraWhitelistEntry UnrestrictedCamera() {
    Privacy::CameraWhitelistEntry e{};
    e.enabled = true;
    e.allowFromHour = std::nullopt;
    e.allowToHour = std::nullopt;
    e.allowedDays = 0x7F;
    return e;
}

// ============================================================================================
// The gates that run before the clock
// ============================================================================================

TEST(DevicePermissionWindowTest, ADisabledEntryNeverAllows) {
    // The first gate. A user who disables a whitelist entry must not keep the permission it granted.
    auto audio = UnrestrictedAudio();
    audio.enabled = false;
    EXPECT_FALSE(audio.IsCurrentlyAllowed())
        << "a disabled microphone whitelist entry still permits access";

    auto camera = UnrestrictedCamera();
    camera.enabled = false;
    EXPECT_FALSE(camera.IsCurrentlyAllowed())
        << "a disabled camera whitelist entry still permits access";
}

TEST(DevicePermissionWindowTest, AnUnrestrictedEnabledEntryAllows) {
    // Anti-vacuity for every negative case here. If IsCurrentlyAllowed always returned false, the
    // whitelist would deny everything and each denial case below would pass while proving nothing.
    EXPECT_TRUE(UnrestrictedAudio().IsCurrentlyAllowed())
        << "an enabled, unrestricted microphone entry denies access, so the whitelist never works";
    EXPECT_TRUE(UnrestrictedCamera().IsCurrentlyAllowed())
        << "an enabled, unrestricted camera entry denies access, so the whitelist never works";
}

TEST(DevicePermissionWindowTest, AnEmptyDayMaskNeverAllows) {
    // A permission granted on no day must not fall through to allowing every day.
    auto audio = UnrestrictedAudio();
    audio.allowedDays = 0x00;
    EXPECT_FALSE(audio.IsCurrentlyAllowed())
        << "a microphone entry permitted on no day of the week still allows access";

    auto camera = UnrestrictedCamera();
    camera.allowedDays = 0x00;
    EXPECT_FALSE(camera.IsCurrentlyAllowed())
        << "a camera entry permitted on no day of the week still allows access";
}

TEST(DevicePermissionWindowTest, ExactlyOneSingleDayMaskMatchesToday) {
    // Clock-independent by construction: which day matches varies, the count does not. This catches a
    // wrong bit order without freezing time. The helper documents bit 0 as Sunday.
    int audioMatches = 0;
    int cameraMatches = 0;
    for (int day = 0; day < 7; ++day) {
        auto audio = UnrestrictedAudio();
        audio.allowedDays = static_cast<uint8_t>(1u << day);
        if (audio.IsCurrentlyAllowed()) {
            ++audioMatches;
        }
        auto camera = UnrestrictedCamera();
        camera.allowedDays = static_cast<uint8_t>(1u << day);
        if (camera.IsCurrentlyAllowed()) {
            ++cameraMatches;
        }
    }
    EXPECT_EQ(1, audioMatches)
        << "exactly one single-day mask should match the current day; " << audioMatches << " did";
    EXPECT_EQ(1, cameraMatches)
        << "exactly one single-day mask should match the current day; " << cameraMatches << " did";
}

// ============================================================================================
// The equivalence - the property that makes the duplication survivable
// ============================================================================================

TEST(DevicePermissionWindowTest, TheTwoImplementationsAgreeOnEveryReachableInput) {
    // The microphone and camera gates are separate copies of the same logic in separate files. If one
    // is changed without the other, a user's expectations hold for one recording device and not the
    // other. This case fails the moment they diverge on any input reachable without a clock.
    struct Case {
        bool enabled;
        uint8_t days;
        std::optional<int> from;
        std::optional<int> to;
        const char* name;
    };
    const Case cases[] = {
        {false, 0x7F, std::nullopt, std::nullopt, "disabled, otherwise unrestricted"},
        {true,  0x7F, std::nullopt, std::nullopt, "enabled and unrestricted"},
        {true,  0x00, std::nullopt, std::nullopt, "no days permitted"},
        {true,  0x7F, 9,            std::nullopt, "start hour set, end hour unset"},
        {true,  0x7F, std::nullopt, 17,           "end hour set, start hour unset"},
        {true,  0x7F, 0,            0,            "start equals end"},
        {true,  0x7F, 22,           2,            "window wrapping midnight"},
        {false, 0x00, 9,            17,           "disabled with every restriction set"},
    };
    for (const auto& c : cases) {
        auto audio = UnrestrictedAudio();
        audio.enabled = c.enabled;
        audio.allowedDays = c.days;
        audio.allowFromHour = c.from;
        audio.allowToHour = c.to;

        auto camera = UnrestrictedCamera();
        camera.enabled = c.enabled;
        camera.allowedDays = c.days;
        camera.allowFromHour = c.from;
        camera.allowToHour = c.to;

        EXPECT_EQ(audio.IsCurrentlyAllowed(), camera.IsCurrentlyAllowed())
            << "the microphone and camera permission gates disagree for: " << c.name
            << " - one copy of this duplicated logic has been changed without the other";
    }
}

TEST(DevicePermissionWindowTest, AHalfConfiguredWindowCurrentlyImposesNoRestriction) {
    // CURRENT BEHAVIOUR, pinned rather than endorsed. IsWithinAllowedHours returns true when EITHER
    // bound is absent, so an entry with a start hour and no end hour permits access around the clock
    // rather than being treated conservatively. For a microphone or camera permission that is a
    // fail-open, and it is filed. Both devices are asserted so a fix cannot land on one only.
    auto audio = UnrestrictedAudio();
    audio.allowFromHour = 9;
    audio.allowToHour = std::nullopt;
    auto camera = UnrestrictedCamera();
    camera.allowFromHour = 9;
    camera.allowToHour = std::nullopt;

    EXPECT_TRUE(audio.IsCurrentlyAllowed())
        << "if this now fails, the half-configured window was made restrictive - update the filing "
           "and this comment rather than restoring the permissive behaviour";
    EXPECT_TRUE(camera.IsCurrentlyAllowed())
        << "if this now fails, the half-configured window was made restrictive - update the filing "
           "and this comment rather than restoring the permissive behaviour";
}

}  // namespace
}  // namespace ShadowStrike
