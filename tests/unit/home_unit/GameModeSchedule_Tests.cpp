/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file GameModeSchedule_Tests.cpp
 * @brief When a game-mode schedule considers itself active, and what it cannot express.
 *
 * GameModeSchedule::IsActiveNow gates whether game mode engages, which in turn suppresses scans and
 * notifications - so a schedule that is active when it should not be is a window of reduced
 * protection. It reads the wall clock through GetCurrentDayOfWeek and GetCurrentMinutesFromMidnight,
 * neither of which is injectable, so the time-dependent branches cannot be tested deterministically.
 *
 * What CAN be tested exactly are the gates that precede the clock: the enabled flag and the
 * day-of-week mask. Those are asserted here, along with the property that matters most for a
 * protection-suppressing feature - that a schedule which is off, or whose mask excludes every day, is
 * never active regardless of the time.
 *
 * OVERNIGHT WINDOWS (task 275) are asserted through IsActiveAt, which takes the moment explicitly: a
 * selected day owns the window that starts on it, so Monday 22:00-02:00 runs into Tuesday morning.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/GameMode/GameModeManager.hpp"

namespace ShadowStrike::GameMode::Test {
namespace {

/// A schedule covering every day and the full 24 hours, so only the gates under test can disable it.
[[nodiscard]] GameModeSchedule AlwaysOn() {
    GameModeSchedule s{};
    s.enabled = true;
    s.daysOfWeek = 0x7F;      // all seven days; the header documents bit 0 as Sunday
    s.startMinutes = 0;
    s.endMinutes = 0;         // start == end is the documented 24-hour form
    return s;
}

TEST(GameModeScheduleTest, ADisabledScheduleIsNeverActive) {
    // The first gate, and the most important one: a user who switches a schedule off must not have
    // protection suppressed on its old timetable.
    auto s = AlwaysOn();
    s.enabled = false;
    EXPECT_FALSE(s.IsActiveNow())
        << "a disabled schedule reported itself active, so switching it off does not stop game mode";
}

TEST(GameModeScheduleTest, AnAllDayAllWeekScheduleIsActive) {
    // Anti-vacuity for the case above. If IsActiveNow always returned false, every negative case here
    // would pass while the feature never engaged at all.
    EXPECT_TRUE(AlwaysOn().IsActiveNow())
        << "a schedule covering all seven days and the full 24 hours is not active, so game mode "
           "can never engage on a schedule";
}

TEST(GameModeScheduleTest, AnEmptyDayMaskIsNeverActive) {
    // A schedule enabled but applying to no day must not fall through to the time comparison.
    auto s = AlwaysOn();
    s.daysOfWeek = 0x00;
    EXPECT_FALSE(s.IsActiveNow())
        << "a schedule with no days selected was active, so an unconfigured mask suppresses "
           "protection every day";
}

TEST(GameModeScheduleTest, TheDayMaskSelectsASingleDay) {
    // Exactly one of the seven single-day masks must match today, whichever day the suite runs on.
    // This is deterministic without freezing the clock: the COUNT is invariant even though which day
    // matches is not.
    int activeDays = 0;
    for (int day = 0; day < 7; ++day) {
        auto s = AlwaysOn();
        s.daysOfWeek = static_cast<uint8_t>(1u << day);
        if (s.IsActiveNow()) {
            ++activeDays;
        }
    }
    EXPECT_EQ(1, activeDays)
        << "exactly one single-day mask should match the current day; " << activeDays
        << " did, so the mask is not a day-of-week bitmap or the bit order is wrong";
}

TEST(GameModeScheduleTest, TheFullMaskIsTheUnionOfTheSingleDayMasks) {
    // Relational and clock-independent: whatever day it is, the all-days mask must agree with the
    // single-day mask for that same day.
    bool anySingleDayMatched = false;
    for (int day = 0; day < 7; ++day) {
        auto s = AlwaysOn();
        s.daysOfWeek = static_cast<uint8_t>(1u << day);
        anySingleDayMatched = anySingleDayMatched || s.IsActiveNow();
    }
    EXPECT_EQ(AlwaysOn().IsActiveNow(), anySingleDayMatched)
        << "the all-days mask disagrees with every single-day mask, so days are being tested against "
           "the wrong bit";
}

TEST(GameModeScheduleTest, AnIdenticalStartAndEndMeansTwentyFourHours) {
    // Documented in the implementation as the 24-hour form. Pinned because the obvious alternative
    // reading - a zero-length window - would make such a schedule never active, and the two are
    // indistinguishable from the field names alone.
    auto s = AlwaysOn();
    s.startMinutes = 13 * 60;
    s.endMinutes = 13 * 60;
    EXPECT_TRUE(s.IsActiveNow())
        << "a schedule whose start equals its end was treated as a zero-length window rather than as "
           "the documented 24-hour form";
}

}  // namespace
// Days: 0 Sunday, 1 Monday, 2 Tuesday. Monday-only, 22:00 to 02:00.
[[nodiscard]] GameModeSchedule MondayNight() {
    GameModeSchedule s{};
    s.enabled = true;
    s.daysOfWeek = static_cast<uint8_t>(1u << 1);
    s.startMinutes = 22 * 60;
    s.endMinutes = 2 * 60;
    return s;
}

TEST(GameModeScheduleTest, AnOvernightWindowContinuesIntoTheNextMorning) {
    const auto s = MondayNight();
    EXPECT_TRUE(s.IsActiveAt(1, 22 * 60)) << "Monday 22:00, the start";
    EXPECT_TRUE(s.IsActiveAt(1, 23 * 60 + 59));
    EXPECT_TRUE(s.IsActiveAt(2, 0)) << "Tuesday 00:00: the window crossed midnight";
    EXPECT_TRUE(s.IsActiveAt(2, 1 * 60 + 59)) << "Tuesday 01:59";
    EXPECT_FALSE(s.IsActiveAt(2, 2 * 60)) << "Tuesday 02:00, the end is exclusive";
}

TEST(GameModeScheduleTest, AnOvernightWindowDoesNotStartOnTheSelectedDaysOwnMorning) {
    // The old gate checked TODAY's bit for both halves, so Monday 00:00-02:00 was active and
    // Tuesday morning was not - the window sat at the wrong end of the day.
    const auto s = MondayNight();
    EXPECT_FALSE(s.IsActiveAt(1, 1 * 60)) << "Monday 01:00 belongs to a Sunday-night window";
    EXPECT_FALSE(s.IsActiveAt(2, 22 * 60)) << "Tuesday evening is not selected";
    EXPECT_FALSE(s.IsActiveAt(1, 12 * 60)) << "between end and start";
}

TEST(GameModeScheduleTest, SaturdayNightWrapsToSunday) {
    auto s = MondayNight();
    s.daysOfWeek = static_cast<uint8_t>(1u << 6);
    EXPECT_TRUE(s.IsActiveAt(0, 60)) << "Sunday 01:00 belongs to Saturday night";
    EXPECT_FALSE(s.IsActiveAt(6, 60)) << "Saturday 01:00 belongs to Friday night";
}

TEST(GameModeScheduleTest, ASameDayWindowIsUnchanged) {
    auto s = MondayNight();
    s.startMinutes = 9 * 60;
    s.endMinutes = 17 * 60;
    EXPECT_TRUE(s.IsActiveAt(1, 9 * 60));
    EXPECT_FALSE(s.IsActiveAt(1, 17 * 60));
    EXPECT_FALSE(s.IsActiveAt(2, 10 * 60));
    EXPECT_FALSE(s.IsActiveAt(9, 10 * 60)) << "an invalid day is never active";
}

}  // namespace ShadowStrike::GameMode::Test
