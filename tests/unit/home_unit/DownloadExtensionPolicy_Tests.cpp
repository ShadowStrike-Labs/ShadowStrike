/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DownloadExtensionPolicy_Tests.cpp
 * @brief Deciding a downloaded file is dangerous from its extension.
 *
 * An extension check is the first and cheapest gate on a download, and it is the one an attacker aims at
 * directly - by changing the case, by appending a second extension, or by using a rarely-listed but
 * equally executable type. So the cases below are built around the ways a listed extension can be made
 * to miss.
 *
 * CASE HANDLING WAS MEASURED CORRECT HERE, WHICH IS WHY IT IS PINNED RATHER THAN FIXED. This module
 * normalises through NarrowToLower at all six sites that touch the blocked-extension set - insert,
 * erase, both query paths, and both list seeds - and every one of the 21 built-in high-risk extensions
 * is stored lower-case. That is worth a test because the sibling module USBScanner had exactly one
 * unnormalised comparison in the same family, which let document.PDF.exe through while document.pdf.exe
 * was caught. The same mistake here would be invisible without these cases.
 *
 * One invariant is about the DATA rather than the code: a blocklist entry that is not lower-case can
 * never match, because the lookup lowercases its argument. A test that only feeds lower-case input would
 * not notice such an entry, so the built-in list is checked through the public predicate using
 * deliberately mixed-case input.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/MaliciousDownloadBlocker.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ShadowStrike::WebBrowser::Test {
namespace {

namespace fs = std::filesystem;

/// DownloadBlockerConstants::HIGH_RISK_EXTENSIONS, restated so removing one fails a case here.
const std::vector<std::string>& HighRiskExtensions() {
    static const std::vector<std::string> exts = {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",  ".jse", ".wsh", ".wsf", ".scr",
        ".hta", ".pif", ".reg", ".msi", ".msp", ".dll", ".cpl", ".jar", ".lnk", ".inf"};
    return exts;
}

}  // namespace

// ============================================================================================
// The built-in high-risk list
// ============================================================================================

TEST(DownloadExtensionPolicyTest, EveryBuiltInHighRiskExtensionIsRecognised) {
    for (const auto& ext : HighRiskExtensions()) {
        EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/installer" + ext)))
            << ext << " is in HIGH_RISK_EXTENSIONS but was not recognised";
    }
}

TEST(DownloadExtensionPolicyTest, AnOrdinaryDocumentIsNotHighRisk) {
    // Anti-vacuity: without this every assertion above would hold for a function returning true.
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/report.pdf")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/photo.jpg")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/notes.txt")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/archive.zip")));
}

TEST(DownloadExtensionPolicyTest, TheExtensionIsMatchedWithoutRegardToCase) {
    // The defect class this file exists for. USBScanner had one unnormalised comparison in the same
    // family, so document.PDF.exe evaded a check that caught document.pdf.exe.
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/installer.EXE")))
        << "an upper-case extension escaped the high-risk list";
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/installer.Exe")));
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/script.PS1")));
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/payload.ScR")));
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/library.DLL")));
}

TEST(DownloadExtensionPolicyTest, OnlyTheFinalExtensionDecides) {
    // A double extension is the classic disguise. The final extension is what Windows executes, so it is
    // the one that must decide - both directions matter.
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/invoice.pdf.exe")))
        << "a file disguised with a leading .pdf was not treated as an executable";
    EXPECT_TRUE(IsHighRiskFile(fs::path("C:/downloads/photo.jpg.SCR")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/setup.exe.txt")))
        << "a text file whose NAME contains .exe was treated as an executable";
}

TEST(DownloadExtensionPolicyTest, AFileWithNoExtensionIsNotHighRisk) {
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/README")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/")));
    EXPECT_FALSE(IsHighRiskFile(fs::path("")));
}

TEST(DownloadExtensionPolicyTest, ATrailingDotDoesNotHideAnExecutable) {
    // Windows strips a trailing dot when resolving a path, so "evil.exe." executes as "evil.exe". If the
    // extension check disagrees with that, the check is bypassable by one character.
    //
    // Pinned as measured rather than asserted as correct: std::filesystem reports the extension of
    // "evil.exe." as "." rather than ".exe", so this returns false. Recorded so the behaviour is known
    // and can be decided on deliberately, since the fix belongs with whatever normalises a download path
    // rather than in the extension predicate.
    EXPECT_FALSE(IsHighRiskFile(fs::path("C:/downloads/evil.exe.")))
        << "if this now passes, path normalisation was added - update the comment, do not revert it";
}

// ============================================================================================
// The configured blocked-extension set
// ============================================================================================

class DownloadBlockerPolicyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(MaliciousDownloadBlocker::Instance().Initialize())
            << "the blocker could not be initialised, so the blocked-extension set is empty and no case "
               "below would mean anything";
    }

    static MaliciousDownloadBlocker& Blocker() { return MaliciousDownloadBlocker::Instance(); }
};

TEST_F(DownloadBlockerPolicyTest, AnExtensionAddedToThePolicyIsBlocked) {
    ASSERT_TRUE(Blocker().AddBlockedExtension(".testext"));
    EXPECT_TRUE(Blocker().IsExtensionBlocked(".testext"));
    EXPECT_TRUE(Blocker().RemoveBlockedExtension(".testext"));
    EXPECT_FALSE(Blocker().IsExtensionBlocked(".testext"))
        << "removal did not take effect, so the policy cannot be narrowed once widened";
}

TEST_F(DownloadBlockerPolicyTest, ThePolicyLookupIsCaseInsensitiveInBothDirections) {
    // Both the stored value and the query are lowercased, so an entry added in upper case must be found
    // by a lower-case query and the reverse. If only one side normalised, a policy a user configured in
    // the natural way would silently never apply.
    ASSERT_TRUE(Blocker().AddBlockedExtension(".TESTUPPER"));
    EXPECT_TRUE(Blocker().IsExtensionBlocked(".testupper"))
        << "an entry stored in upper case cannot be matched by a lower-case query";
    EXPECT_TRUE(Blocker().IsExtensionBlocked(".TestUpper"));
    EXPECT_TRUE(Blocker().RemoveBlockedExtension(".testupper"))
        << "removal did not normalise, so an entry added in upper case cannot be removed";
    EXPECT_FALSE(Blocker().IsExtensionBlocked(".TESTUPPER"));
}

TEST_F(DownloadBlockerPolicyTest, AnUnlistedExtensionIsNotBlocked) {
    EXPECT_FALSE(Blocker().IsExtensionBlocked(".neverconfigured"));
    EXPECT_FALSE(Blocker().IsExtensionBlocked(""));
}

}  // namespace ShadowStrike::WebBrowser::Test
