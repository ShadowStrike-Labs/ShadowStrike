/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AttachmentVerdict_Tests.cpp
 * @brief Which attachment verdicts block, and the rule that anything blocking must be reportable.
 *
 * AttachmentScanResult::ShouldBlock decides whether an email attachment reaches the user. The
 * defect these cases accompany was not in the predicate itself but in the gap between it and the
 * notification path: a verdict of HighRisk blocks, yet the threat callback fired only for Malicious
 * and Suspicious, so an attachment scoring 50-79 on heuristics was blocked while nothing told the
 * user or any subscriber why, and no detection counter recorded it.
 *
 * THE INVARIANT WORTH HOLDING IS THE RELATIONSHIP, NOT THE LIST. Every verdict that causes a block
 * must be a verdict the product can report, because a silent block is indistinguishable from a lost
 * email. The set of blocking verdicts is asserted explicitly so that adding a fourth one forces a
 * decision about notifying on it, rather than repeating the same omission.
 *
 * The 70 boundary inside ShouldBlock is asserted from both sides. Note it is currently unreachable
 * from the risk-band path, because that path only assigns Suspicious at 80 or above - the clause may
 * still be live via the macro and obfuscation checks earlier in the scan. That is filed rather than
 * assumed dead, and the case below pins the predicate's own behaviour regardless of which callers
 * reach it.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Email/AttachmentScanner.hpp"

#include <vector>

namespace ShadowStrike::Email::Test {
namespace {

[[nodiscard]] AttachmentScanResult ResultWith(AttachmentVerdict verdict, uint32_t riskScore) {
    AttachmentScanResult r{};
    r.verdict = verdict;
    r.riskScore = riskScore;
    return r;
}

TEST(AttachmentVerdictTest, ACleanAttachmentIsNotBlocked) {
    const auto r = ResultWith(AttachmentVerdict::Clean, 0);
    EXPECT_FALSE(r.ShouldBlock());
    EXPECT_FALSE(r.IsMalicious());
}

TEST(AttachmentVerdictTest, MaliciousBlocksAndReportsAsMalicious) {
    const auto r = ResultWith(AttachmentVerdict::Malicious, 100);
    EXPECT_TRUE(r.ShouldBlock());
    EXPECT_TRUE(r.IsMalicious());
}

TEST(AttachmentVerdictTest, HighRiskBlocksWithoutBeingMalicious) {
    // The verdict at the centre of the defect. It blocks, so it must be reportable, but it is not
    // malware and must not be reported as such.
    const auto r = ResultWith(AttachmentVerdict::HighRisk, 60);
    EXPECT_TRUE(r.ShouldBlock())
        << "HighRisk stopped blocking, which would let a disguised executable through";
    EXPECT_FALSE(r.IsMalicious())
        << "HighRisk is reported as confirmed malware, which overstates what was detected";
}

TEST(AttachmentVerdictTest, SuspiciousBlocksOnlyAboveTheRiskBoundary) {
    // Asserted from both sides so a one-point move in the boundary fails here rather than silently
    // changing which attachments are delivered.
    EXPECT_FALSE(ResultWith(AttachmentVerdict::Suspicious, 69).ShouldBlock())
        << "a suspicious attachment at risk 69 was blocked";
    EXPECT_TRUE(ResultWith(AttachmentVerdict::Suspicious, 70).ShouldBlock())
        << "a suspicious attachment at exactly risk 70 was delivered";
}

TEST(AttachmentVerdictTest, TheBlockingVerdictsAreExactlyThoseExpected) {
    // The relationship this file exists for. Every blocking verdict must be one the notification
    // path covers; if a fourth appears here, the threat callback in ScanAttachmentImpl has to be
    // revisited in the same change, which is precisely what did not happen for HighRisk.
    struct Case { AttachmentVerdict verdict; bool blocksAtHighRisk; const char* name; };
    const Case cases[] = {
        {AttachmentVerdict::Clean,               false, "Clean"},
        {AttachmentVerdict::Malicious,           true,  "Malicious"},
        {AttachmentVerdict::Suspicious,          true,  "Suspicious at risk 90"},
        {AttachmentVerdict::PotentiallyUnwanted, false, "PotentiallyUnwanted"},
        {AttachmentVerdict::HighRisk,            true,  "HighRisk"},
        {AttachmentVerdict::EncryptedArchive,    false, "EncryptedArchive"},
        {AttachmentVerdict::CorruptedFile,       false, "CorruptedFile"},
        {AttachmentVerdict::UnsupportedType,     false, "UnsupportedType"},
        {AttachmentVerdict::SizeLimitExceeded,   false, "SizeLimitExceeded"},
        {AttachmentVerdict::ScanError,           false, "ScanError"},
    };
    for (const auto& c : cases) {
        const auto r = ResultWith(c.verdict, 90);
        EXPECT_EQ(c.blocksAtHighRisk, r.ShouldBlock())
            << c.name << " changed whether it blocks; if that is intended, the threat-callback "
            << "condition in ScanAttachmentImpl must change with it or the block becomes silent";
    }
}

TEST(AttachmentVerdictTest, AnUnscannableAttachmentIsNotSilentlyBlockedByTheseVerdicts) {
    // EncryptedArchive and ScanError mean "could not examine", not "found something". They are
    // handled by their own explicit branches earlier in the scan, which increment their own
    // counters and notify directly, so ShouldBlock must not double as that decision.
    EXPECT_FALSE(ResultWith(AttachmentVerdict::EncryptedArchive, 70).ShouldBlock());
    EXPECT_FALSE(ResultWith(AttachmentVerdict::ScanError, 100).ShouldBlock())
        << "a scan error blocks by score, so an engine failure would silently quarantine mail";
}

}  // namespace
}  // namespace ShadowStrike::Email::Test
