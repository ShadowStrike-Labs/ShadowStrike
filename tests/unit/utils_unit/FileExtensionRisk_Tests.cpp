/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Utils::FileExtensionRisk - the one executable-content extension list (task 309).
 *
 * Five copies used to decide this and none was a superset of another: the email
 * attachment scanner missed .cpl, EmailProtection and the download blocker missed
 * .vbe, the PhantomCore email scanner had 14 entries. These cases pin the shared
 * list's semantics and, through the three consumers this binary can reach, that
 * every check now gives the same answer for every entry.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>

#include "PhantomCore/Utils/FileExtensionRisk.hpp"
#include "Products/Community/PhantomHome/Email/AttachmentScanner.hpp"
#include "Products/Community/PhantomHome/Email/EmailProtection.hpp"
#include "Products/Community/PhantomHome/WebProtection/MaliciousDownloadBlocker.hpp"

namespace {

namespace Risk = ShadowStrike::Utils::FileExtensionRisk;

TEST(FileExtensionRisk, TheGapsBetweenTheOldListsAreClosed) {
    for (const char* ext : {".cpl", ".vbe", ".jar", ".inf", ".psm1", ".psd1", ".sys", ".lnk"}) {
        EXPECT_TRUE(Risk::IsExecutableContentExtension(std::string_view(ext))) << ext;
    }
}

TEST(FileExtensionRisk, MatchingIsCaseInsensitiveAndWholeString) {
    EXPECT_TRUE(Risk::IsExecutableContentExtension(std::string_view(".EXE")));
    EXPECT_TRUE(Risk::IsExecutableContentExtension(std::wstring_view(L".Vbe")));
    EXPECT_FALSE(Risk::IsExecutableContentExtension(std::string_view(".exe.txt")));
    EXPECT_FALSE(Risk::IsExecutableContentExtension(std::string_view("exe")));
    EXPECT_FALSE(Risk::IsExecutableContentExtension(std::string_view(".ex")));
    EXPECT_FALSE(Risk::IsExecutableContentExtension(std::string_view("")));
    EXPECT_FALSE(Risk::IsExecutableContentExtension(std::wstring_view(L".\u0130XE")))
        << "a non-ASCII code unit must not fold into an entry";
}

TEST(FileExtensionRisk, OrdinaryDocumentsAreNotExecutableContent) {
    // Non-vacuity for every positive case in this file.
    for (const char* ext : {".txt", ".pdf", ".jpg", ".png", ".docx", ".xlsx", ".zip", ".json"}) {
        EXPECT_FALSE(Risk::IsExecutableContentExtension(std::string_view(ext))) << ext;
    }
}

TEST(FileExtensionRisk, LastExtensionReadsOnlyTheFinalComponent) {
    using std::string_view;
    EXPECT_EQ(string_view(".exe"), Risk::LastExtension(string_view("invoice.pdf.exe")));
    EXPECT_EQ(string_view(".js"), Risk::LastExtension(string_view("dir/sub/payload.js")));
    EXPECT_EQ(string_view(""), Risk::LastExtension(string_view("README")));
    EXPECT_EQ(string_view(""), Risk::LastExtension(string_view("folder.v2\\README")))
        << "a dot in a directory name is not the file's extension";
    EXPECT_EQ(string_view(".json"), Risk::LastExtension(string_view("a.json")))
        << "and .js must not be found as a suffix of .json";
}

TEST(FileExtensionRisk, EveryReachableConsumerAgreesOnEveryEntry) {
    auto& attachments = ShadowStrike::Email::AttachmentScanner::Instance();
    for (const auto entry : Risk::kExecutableContentExtensions) {
        const std::string ext(entry);
        EXPECT_TRUE(ShadowStrike::Email::IsDangerousExtension(ext)) << "EmailProtection " << ext;
        EXPECT_TRUE(attachments.IsHighRiskExtension(ext)) << "AttachmentScanner " << ext;
        EXPECT_TRUE(ShadowStrike::WebBrowser::IsHighRiskFile(std::filesystem::path("C:/d/f" + ext)))
            << "MaliciousDownloadBlocker " << ext;
    }
}

} // namespace