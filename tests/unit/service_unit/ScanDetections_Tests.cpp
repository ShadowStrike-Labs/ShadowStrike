/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*
 * ============================================================================
 * What a scan found, and what the user may act on
 * ============================================================================
 *
 * The quarantine verb acts only on a file the cited scan reported. These cases
 * pin the pieces that decision rests on: which results become detections, how a
 * request is matched to one, and how the scan registry stays bounded without
 * ever discarding a scan that is still running.
 * ============================================================================
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "src/PhantomCore/Service/ScanDetections.hpp"

#include <string>
#include <vector>

namespace {

namespace SD = ShadowStrike::Service::ScanDetections;
using ShadowStrike::Core::Engine::EngineResult;
using ShadowStrike::Core::Engine::QuarantineStatus;
using ShadowStrike::Core::Engine::ScanVerdict;

EngineResult Result(ScanVerdict v, std::wstring path, std::string sha = "ab12") {
    EngineResult r{};
    r.verdict = v;
    r.filePath = std::move(path);
    r.sha256 = std::move(sha);
    r.threatName = "Test.Threat";
    r.detectionSource = "YARA";
    return r;
}

// ============================================================================
// Collect
// ============================================================================

TEST(ScanDetections, OnlyConfirmedInfectionsBecomeDetections) {
    // A heuristic hit shown beside a Quarantine button is shown as malware. The
    // list must match threatsFound, which counts confirmed detections only.
    const std::vector<EngineResult> results = {
        Result(ScanVerdict::Infected,    L"C:\\a\\infected.exe"),
        Result(ScanVerdict::Suspicious,  L"C:\\a\\suspicious.exe"),
        Result(ScanVerdict::PUA,         L"C:\\a\\pua.exe"),
        Result(ScanVerdict::Adware,      L"C:\\a\\adware.exe"),
        Result(ScanVerdict::Riskware,    L"C:\\a\\riskware.exe"),
        Result(ScanVerdict::Clean,       L"C:\\a\\clean.exe"),
        Result(ScanVerdict::Error,       L"C:\\a\\error.exe"),
        Result(ScanVerdict::Whitelisted, L"C:\\a\\allowed.exe"),
    };
    const auto c = SD::Collect(results);
    ASSERT_EQ(1u, c.items.size());
    EXPECT_EQ(L"C:\\a\\infected.exe", c.items[0].path);
    EXPECT_EQ(0u, c.omitted);
}

TEST(ScanDetections, AResultWithNoFileIsNotADetection) {
    // Memory, process, boot and UEFI scans have no file to act on.
    const auto c = SD::Collect({Result(ScanVerdict::Infected, L"")});
    EXPECT_TRUE(c.items.empty());
}

TEST(ScanDetections, AConvictionWithoutAFingerprintIsShownButNotActionable) {
    // Hiding a conviction is worse than showing one that cannot be acted on.
    const auto c = SD::Collect({Result(ScanVerdict::Infected, L"C:\\a\\x.exe", "")});
    ASSERT_EQ(1u, c.items.size());
    EXPECT_FALSE(c.items[0].Actionable())
        << "a detection with no recorded hash cannot be re-verified, so it must not be actionable";
}

TEST(ScanDetections, AnArchiveMemberIsNotActionable) {
    // "archive|entry" names nothing that can be opened or moved.
    const auto c = SD::Collect({Result(ScanVerdict::Infected, L"C:\\a\\x.zip|evil.exe")});
    ASSERT_EQ(1u, c.items.size());
    EXPECT_FALSE(c.items[0].Actionable());
}

TEST(ScanDetections, AnOrdinaryDetectionIsActionable) {
    const auto c = SD::Collect({Result(ScanVerdict::Infected, L"C:\\a\\x.exe")});
    ASSERT_EQ(1u, c.items.size());
    EXPECT_TRUE(c.items[0].Actionable());
    EXPECT_FALSE(c.items[0].quarantined);
    EXPECT_FALSE(c.items[0].inProgress);
}

TEST(ScanDetections, TheListIsCappedAndTheOverflowIsCountedNotLost) {
    std::vector<EngineResult> results;
    for (int i = 0; i < 7; ++i) {
        results.push_back(Result(ScanVerdict::Infected, L"C:\\a\\f" + std::to_wstring(i) + L".exe"));
    }
    const auto c = SD::Collect(results, /*cap=*/5);
    EXPECT_EQ(5u, c.items.size());
    EXPECT_EQ(2u, c.omitted)
        << "convictions beyond the cap must be reported as omitted, never silently dropped";
}

// ============================================================================
// Find - what keeps the verb from being "quarantine any path"
// ============================================================================

TEST(ScanDetections, APathTheScanDidNotReportIsNotFound) {
    auto c = SD::Collect({Result(ScanVerdict::Infected, L"C:\\a\\x.exe")});
    EXPECT_EQ(nullptr, SD::Find(c.items, L"C:\\Windows\\System32\\kernel32.dll"));
    EXPECT_EQ(nullptr, SD::Find(c.items, L"C:\\a\\x.exe.bak"));
    EXPECT_EQ(nullptr, SD::Find(c.items, L"C:\\a\\x.ex"));
    EXPECT_EQ(nullptr, SD::Find(c.items, L""));
}

TEST(ScanDetections, AReportedPathIsFoundRegardlessOfCase) {
    auto c = SD::Collect({Result(ScanVerdict::Infected, L"C:\\Users\\Ali\\Downloads\\Invoice.EXE")});
    ASSERT_NE(nullptr, SD::Find(c.items, L"c:\\users\\ali\\downloads\\invoice.exe"));
    ASSERT_NE(nullptr, SD::Find(c.items, L"C:\\USERS\\ALI\\DOWNLOADS\\INVOICE.EXE"));
}

TEST(ScanDetections, PathEqualityIsOrdinalNotLocaleDependent) {
    // Under a Turkish locale "I" and "i" are not a case pair. Ordinal comparison
    // is what NTFS uses, so a dotless or dotted variant must not be confused
    // with the plain one, and the plain pair must still match.
    EXPECT_TRUE(SD::SamePath(L"C:\\INVOICE.EXE", L"c:\\invoice.exe"));
    EXPECT_FALSE(SD::SamePath(L"C:\\\x0130NVOICE.EXE", L"c:\\invoice.exe"))
        << "U+0130 is not the same file-system character as 'i'";
    EXPECT_FALSE(SD::SamePath(L"C:\\a.exe", L"C:\\a.exe "));
}

// ============================================================================
// Retention
// ============================================================================

TEST(ScanDetections, NothingIsEvictedWithinTheBound) {
    std::vector<SD::RetentionEntry> e;
    for (std::uint64_t i = 1; i <= 4; ++i) e.push_back({i, true});
    EXPECT_TRUE(SD::SelectEvictions(e, 4).empty());
}

TEST(ScanDetections, TheOldestFinishedRecordsGoFirst) {
    std::vector<SD::RetentionEntry> e = {{5, true}, {1, true}, {3, true}, {2, true}, {4, true}};
    const auto evict = SD::SelectEvictions(e, 3);
    ASSERT_EQ(2u, evict.size());
    EXPECT_EQ(1u, evict[0]);
    EXPECT_EQ(2u, evict[1]);
}

TEST(ScanDetections, ARunningScanIsNeverEvicted) {
    // Evicting a running scan would make its own progress poll answer
    // "not found" mid-scan. The bound is allowed to be exceeded instead.
    std::vector<SD::RetentionEntry> e = {{1, false}, {2, false}, {3, true}, {4, false}};
    const auto evict = SD::SelectEvictions(e, 2);
    ASSERT_EQ(1u, evict.size());
    EXPECT_EQ(3u, evict[0]) << "only the finished record may go";
}

TEST(ScanDetections, StartOrderIsNumericNotLexical) {
    // Ids are "scan-N", and "scan-10" sorts before "scan-2" as text.
    std::vector<SD::RetentionEntry> e = {{10, true}, {2, true}, {11, true}};
    const auto evict = SD::SelectEvictions(e, 2);
    ASSERT_EQ(1u, evict.size());
    EXPECT_EQ(2u, evict[0]);
}

// ============================================================================
// Outcome codes
// ============================================================================

TEST(ScanDetections, QuarantineOutcomesHaveStableDistinctCodes) {
    EXPECT_STREQ("ok", SD::QuarantineOutcomeCode(QuarantineStatus::Success));
    EXPECT_STREQ("system_file_protected",
                 SD::QuarantineOutcomeCode(QuarantineStatus::SystemFileProtected));
    EXPECT_STREQ("file_in_use", SD::QuarantineOutcomeCode(QuarantineStatus::FileInUse));
    EXPECT_STREQ("already_quarantined",
                 SD::QuarantineOutcomeCode(QuarantineStatus::AlreadyQuarantined));
    EXPECT_STREQ("quarantine_unavailable",
                 SD::QuarantineOutcomeCode(QuarantineStatus::DatabaseError));
    EXPECT_STREQ("quarantine_failed",
                 SD::QuarantineOutcomeCode(QuarantineStatus::UnknownError));
}

}  // namespace
