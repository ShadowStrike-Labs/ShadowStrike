// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Backup cron expression tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file BackupCronExpression_Tests.cpp
 * @brief Pins the cron parser, and the union rule for the two day fields.
 *
 * ParseCronExpression computes the next run for a schedule whose frequency is Cron, and AddSchedule requires
 * a non-empty expression for that frequency, so a user-configured schedule goes through it.
 *
 * The defect it had: day-of-month and day-of-week were combined as an intersection. crontab(5) and POSIX
 * specify a UNION when both are restricted - "0 2 15 * 5" means the 15th OR any Friday. Requiring both made
 * it fire only when the 15th fell on a Friday, roughly once every seven months instead of five times a month,
 * with no error reported because the expression still parsed and a next-run time still came back.
 *
 * The next-run time depends on the current clock, so these cases assert what can be asserted without one:
 * whether an expression is ACCEPTED, and where a returned time falls relative to now. The union rule is
 * tested through acceptance plus the bound on how far ahead the answer can be - under the old intersection
 * rule a both-restricted expression could return a date months away, and under the union rule it cannot be
 * more than about five weeks out.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "Products/Community/PhantomHome/Backup/BackupScheduler.hpp"

namespace {

using ShadowStrike::Backup::IsInQuietHours;
using ShadowStrike::Backup::ParseCronExpression;
using ShadowStrike::Backup::SystemTimePoint;

// Days between now and a parsed next-run time, or -1 if the expression was rejected.
double DaysAhead(const std::string& expression) {
    SystemTimePoint next{};
    if (!ParseCronExpression(expression, next)) {
        return -1.0;
    }
    const auto delta = next - std::chrono::system_clock::now();
    return std::chrono::duration<double, std::ratio<86400>>(delta).count();
}

// ============================================================================
// Accepted syntax
// ============================================================================

TEST(BackupCron, TheDocumentedFormsAreAccepted) {
    // The comment on the function states the supported forms: *, a specific number, and */step.
    for (const char* expression : {"* * * * *", "0 2 * * *", "30 3 1 * *", "0 0 * * 0",
                                   "*/15 * * * *", "0 */6 * * *", "0 2 */2 * *", "59 23 31 12 6"}) {
        SystemTimePoint next{};
        EXPECT_TRUE(ParseCronExpression(expression, next)) << expression;
    }
}

TEST(BackupCron, MalformedExpressionsAreRejected) {
    // Rejection matters more than acceptance here: a misread expression schedules a backup at the wrong time,
    // while a rejected one is reported by the caller.
    for (const char* expression : {"", "0", "0 2", "0 2 *", "0 2 * *",
                                   "0 2 * * * *",          // six fields
                                   "60 2 * * *",           // minute out of range
                                   "0 24 * * *",           // hour out of range
                                   "0 2 0 * *",            // day-of-month is 1-based
                                   "0 2 32 * *", "0 2 * 13 *", "0 2 * * 7",
                                   "x 2 * * *", "0 2 * * abc",
                                   "*/ * * * *", "*/0 * * * *", "*/-1 * * * *",
                                   "0x2 2 * * *", "2.5 2 * * *", " 0 2 * * * junk"}) {
        SystemTimePoint next{};
        EXPECT_FALSE(ParseCronExpression(expression, next)) << "'" << expression << "' was accepted";
    }
}

TEST(BackupCron, DayOfWeekSevenIsRejectedRatherThanAliasedToSunday) {
    // PINNED AS IT BEHAVES. Many cron implementations accept 7 as a second spelling of Sunday. This one takes
    // 0-6 and rejects 7, which is a missing feature rather than a wrong answer - a rejected expression is
    // reported, not silently mis-scheduled. Filed. If this starts passing, that was added: widen the case.
    SystemTimePoint next{};
    EXPECT_FALSE(ParseCronExpression("0 2 * * 7", next));
    EXPECT_TRUE(ParseCronExpression("0 2 * * 0", next)) << "Sunday as 0 is accepted";
}

TEST(BackupCron, RangesAndListsAreRejectedRatherThanMisread) {
    // Also pinned as it behaves, and also a missing feature. The important part is that these are REJECTED:
    // reading "1-5" as "1" would schedule a backup on one day where five were asked for, silently.
    SystemTimePoint next{};
    EXPECT_FALSE(ParseCronExpression("0 2 * * 1-5", next)) << "a range";
    EXPECT_FALSE(ParseCronExpression("0 2 * * 1,3,5", next)) << "a list";
    EXPECT_FALSE(ParseCronExpression("0 2 1-15 * *", next)) << "a day-of-month range";
}

// ============================================================================
// The two day fields
// ============================================================================

TEST(BackupCron, ARestrictedDayOfMonthAloneRunsWithinAMonth) {
    // dow is "*", so only the day-of-month restricts. The next 1st of a month is at most 31 days away.
    const double days = DaysAhead("0 2 1 * *");
    ASSERT_GE(days, 0.0) << "expression was rejected";
    EXPECT_LE(days, 32.0) << "the next first-of-month should be within a month";
}

TEST(BackupCron, ARestrictedDayOfWeekAloneRunsWithinAWeek) {
    // dom is "*", so only the day-of-week restricts. Every weekday recurs within seven days.
    for (const char* expression : {"0 2 * * 0", "0 2 * * 3", "0 2 * * 6"}) {
        const double days = DaysAhead(expression);
        ASSERT_GE(days, 0.0) << expression << " was rejected";
        EXPECT_LE(days, 8.0) << expression << " should recur within a week";
    }
}

TEST(BackupCron, BothDayFieldsRestrictedTakesTheUnionNotTheIntersection) {
    // THE DEFECT. Under the intersection rule this had to wait for a specific day-of-month to fall on a
    // specific weekday - for "0 2 15 * 5", about once every seven months. Under the union rule required by
    // crontab(5) the answer is the sooner of "the 15th" and "the next Friday", so it is always within about
    // five weeks whatever today is.
    for (const char* expression : {"0 2 15 * 5", "0 2 1 * 1", "0 2 28 * 3", "0 2 10 * 0"}) {
        const double days = DaysAhead(expression);
        ASSERT_GE(days, 0.0) << expression << " was rejected";
        EXPECT_LE(days, 35.0)
            << expression << " resolved " << days
            << " days out. Both day fields are restricted, so cron takes the UNION - the sooner of the "
               "day-of-month and the day-of-week - which cannot exceed about five weeks. An answer further "
               "out means the intersection rule is back.";
    }
}

TEST(BackupCron, AnUnsatisfiableDateIsRejectedRatherThanLooping) {
    // 30 February never occurs. The search is bounded to about two years and must give up rather than hang,
    // and must not return a shifted date - mktime would happily normalise 30 February into March.
    SystemTimePoint next{};
    EXPECT_FALSE(ParseCronExpression("0 2 30 2 *", next))
        << "the thirtieth of February must be refused, not normalised into March";
}

TEST(BackupCron, TheNextRunIsAlwaysInTheFuture) {
    // Non-vacuity for the bounds above: they would all hold for a function that returned a time in the past.
    for (const char* expression : {"* * * * *", "0 2 * * *", "0 2 1 * *", "0 2 15 * 5"}) {
        const double days = DaysAhead(expression);
        ASSERT_GE(days, 0.0) << expression << " was rejected";
        EXPECT_GT(days, 0.0) << expression << " resolved to a time that is not in the future";
    }
}

// ============================================================================
// Quiet hours - the reference implementation for the wrapping-window class
// ============================================================================

TEST(BackupQuietHours, AWindowThatWrapsMidnightIsHandled) {
    // This function is the reference for the wrapping-range defect filed against GameModeSchedule. Pinned
    // here alongside the cron work because both are scheduling decisions in the same module.
    EXPECT_TRUE(IsInQuietHours(23, 22, 7)) << "inside, before midnight";
    EXPECT_TRUE(IsInQuietHours(2, 22, 7)) << "inside, after midnight";
    EXPECT_TRUE(IsInQuietHours(22, 22, 7)) << "the start hour is inside";
    EXPECT_FALSE(IsInQuietHours(7, 22, 7)) << "the end hour is outside";
    EXPECT_FALSE(IsInQuietHours(12, 22, 7)) << "the middle of the day is outside";
}

TEST(BackupQuietHours, AnEqualStartAndEndIsAnEmptyWindow) {
    // Deliberately pinned: start == end takes the non-wrapping branch, where hour >= start && hour < end is
    // false for every hour. GameModeSchedule treats the same condition as twenty-four hours, so the two
    // modules hold OPPOSITE conventions - recorded on that filing, and this is the half that is pinned.
    for (int hour = 0; hour < 24; ++hour) {
        EXPECT_FALSE(IsInQuietHours(hour, 9, 9)) << "hour " << hour;
    }
}

}  // namespace
