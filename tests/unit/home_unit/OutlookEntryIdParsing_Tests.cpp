// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Outlook scanner utility tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file OutlookEntryIdParsing_Tests.cpp
 * @brief Pins the EntryID list parser, and that the two process lookups cannot disagree.
 *
 * Nothing here needed fixing. The parser trims correctly in every case tried, including the one that looks
 * like it should break - an all-whitespace element, where find_first_not_of returns npos, erase(0, npos)
 * clears the string, and the following erase(npos + 1) becomes erase(0) on an empty string, which is a
 * no-op rather than an out_of_range. That is correct by construction rather than by accident, but it is not
 * obvious, so it is pinned.
 *
 * IsOutlookRunning and GetOutlookProcessId are the SAME process-enumeration loop written twice, differing
 * only in what they return. Whether Outlook is running depends on the machine, so the answer cannot be
 * asserted - but the two must always agree, and that is checkable anywhere. If one is later taught about a
 * second process name or a different match rule and the other is not, the consistency case fails.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Email/OutlookScanner.hpp"

namespace {

using ShadowStrike::Email::GetOutlookProcessId;
using ShadowStrike::Email::IsOutlookRunning;
using ShadowStrike::Email::ParseEntryIdCollection;

// ============================================================================
// The EntryID list parser
// ============================================================================

TEST(OutlookEntryIdParsing, ASingleIdIsReturnedAsOneElement) {
    const auto ids = ParseEntryIdCollection("0000FE00A1B2C3");
    ASSERT_EQ(1u, ids.size());
    EXPECT_EQ("0000FE00A1B2C3", ids[0]);
}

TEST(OutlookEntryIdParsing, CommaSeparatedIdsAreSplitInOrder) {
    const auto ids = ParseEntryIdCollection("AAAA,BBBB,CCCC");
    ASSERT_EQ(3u, ids.size());
    EXPECT_EQ("AAAA", ids[0]);
    EXPECT_EQ("BBBB", ids[1]);
    EXPECT_EQ("CCCC", ids[2]) << "order matters - a caller indexes these against its own list";
}

TEST(OutlookEntryIdParsing, SurroundingWhitespaceIsTrimmedFromEveryElement) {
    const auto ids = ParseEntryIdCollection("  AAAA , \tBBBB\t , CCCC  ");
    ASSERT_EQ(3u, ids.size());
    EXPECT_EQ("AAAA", ids[0]);
    EXPECT_EQ("BBBB", ids[1]);
    EXPECT_EQ("CCCC", ids[2]);
}

TEST(OutlookEntryIdParsing, CarriageReturnsAndNewlinesAreTrimmedToo) {
    // A collection arriving from a text field or a pipe carries line endings.
    const auto ids = ParseEntryIdCollection("AAAA\r\n,\r\nBBBB\n");
    ASSERT_EQ(2u, ids.size());
    EXPECT_EQ("AAAA", ids[0]);
    EXPECT_EQ("BBBB", ids[1]);
}

TEST(OutlookEntryIdParsing, AnEmptyOrWhitespaceOnlyElementIsDropped) {
    // The case that looks like it should break. An element of only spaces sends find_first_not_of to npos;
    // erase(0, npos) clears the string, and erase(npos + 1) is erase(0) on an empty string - a no-op, not an
    // out_of_range. The element is then dropped as empty.
    const auto ids = ParseEntryIdCollection("AAAA,   ,BBBB");
    ASSERT_EQ(2u, ids.size()) << "a whitespace-only element must be dropped, not returned as empty";
    EXPECT_EQ("AAAA", ids[0]);
    EXPECT_EQ("BBBB", ids[1]);

    EXPECT_TRUE(ParseEntryIdCollection("   ").empty());
    EXPECT_TRUE(ParseEntryIdCollection("\t\r\n").empty());
}

TEST(OutlookEntryIdParsing, ConsecutiveAndTrailingSeparatorsProduceNoEmptyElements) {
    // An empty element must never reach a caller, which would then act on an EntryID of "".
    for (const char* input : {"AAAA,,BBBB", "AAAA,BBBB,", ",AAAA,BBBB", ",,AAAA,,BBBB,,"}) {
        const auto ids = ParseEntryIdCollection(input);
        EXPECT_EQ(2u, ids.size()) << "input '" << input << "'";
        for (const auto& id : ids) {
            EXPECT_FALSE(id.empty()) << "input '" << input << "' produced an empty EntryID";
        }
    }
}

TEST(OutlookEntryIdParsing, AnEmptyCollectionYieldsNothing) {
    // Non-vacuity in the other direction: the parser must not invent an element.
    EXPECT_TRUE(ParseEntryIdCollection("").empty());
    EXPECT_TRUE(ParseEntryIdCollection(",").empty());
    EXPECT_TRUE(ParseEntryIdCollection(",,,").empty());
}

TEST(OutlookEntryIdParsing, InteriorWhitespaceIsPreserved) {
    // Only the ENDS are trimmed. An EntryID is not expected to contain a space, but silently rewriting the
    // middle of one would corrupt an identifier rather than reject it.
    const auto ids = ParseEntryIdCollection("  AA BB  ");
    ASSERT_EQ(1u, ids.size());
    EXPECT_EQ("AA BB", ids[0]);
}

TEST(OutlookEntryIdParsing, ALargeCollectionIsParsedWithoutABound) {
    // PINNED AS IT BEHAVES. There is no cap on the number of elements, so the output size is whatever the
    // input dictates. That is fine for an internally generated collection and is worth knowing if one ever
    // arrives from outside the process. Filed.
    std::string input;
    for (int i = 0; i < 5000; ++i) {
        if (i != 0) {
            input += ',';
        }
        input += "ID" + std::to_string(i);
    }
    const auto ids = ParseEntryIdCollection(input);
    EXPECT_EQ(5000u, ids.size());
    EXPECT_EQ("ID0", ids.front());
    EXPECT_EQ("ID4999", ids.back());
}

// ============================================================================
// The two process lookups, which are the same loop twice
// ============================================================================

TEST(OutlookProcessLookup, TheTwoLookupsAlwaysAgree) {
    // Whether Outlook is running depends on the machine, so the answer is not asserted - only that the two
    // functions cannot disagree. They are separate copies of one enumeration loop, so if either is later
    // taught a second process name or a different match rule, this fails.
    const bool running = IsOutlookRunning();
    const auto pid = GetOutlookProcessId();

    EXPECT_EQ(running, pid.has_value())
        << "IsOutlookRunning said " << running << " while GetOutlookProcessId "
        << (pid.has_value() ? "returned a pid" : "returned nothing")
        << " - these are duplicate copies of one loop and have diverged";

    if (pid.has_value()) {
        EXPECT_GT(*pid, 4u) << "a returned pid must be a real process, not System or Idle";
    }
}

TEST(OutlookProcessLookup, RepeatedCallsAreStable) {
    // Non-vacuity for the agreement case: it would hold trivially if both always answered the same constant,
    // so this at least establishes that asking twice in a row is consistent and does not throw.
    EXPECT_NO_THROW({
        const bool first = IsOutlookRunning();
        const bool second = IsOutlookRunning();
        EXPECT_EQ(first, second);
    });
}

}  // namespace
