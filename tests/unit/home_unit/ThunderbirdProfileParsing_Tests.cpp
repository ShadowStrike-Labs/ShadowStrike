// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Thunderbird profile and mailbox parsing tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ThunderbirdProfileParsing_Tests.cpp
 * @brief Pins profiles.ini parsing, including the directory-traversal refusal, and mailbox format detection.
 *
 * ParseProfilesIni reads a file Thunderbird owns and turns entries in it into PATHS THE SCANNER WILL READ, so
 * what it accepts decides what the product opens. It already does the right things - a size cap, the
 * IsRelative flag, canonicalisation and a traversal check - and none of that had a test.
 *
 * The traversal case is the one that matters. An entry of Path=../../../../Windows/System32 with IsRelative=1
 * resolves outside the profile root, and the parser must refuse it rather than hand the scanner a path into
 * the system directory.
 *
 * Every case builds a real profiles.ini in a temporary directory and removes it afterwards, because the
 * function takes a path and reads from disk. Nothing outside that directory is touched.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Email/ThunderbirdScanner.hpp"

namespace {

namespace fs = std::filesystem;

using ShadowStrike::Email::DetectMailboxFormat;
using ShadowStrike::Email::MailboxFormat;
using ShadowStrike::Email::ParseProfilesIni;

/// @brief A temporary directory that removes itself, so a failing case cannot leave files behind.
class ScopedTempDir {
public:
    ScopedTempDir() {
        std::error_code ec;
        m_path = fs::temp_directory_path(ec) /
                 ("ss_tb_test_" + std::to_string(::GetCurrentProcessId()) + "_" +
                  std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::create_directories(m_path, ec);
    }

    ~ScopedTempDir() {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    [[nodiscard]] const fs::path& path() const noexcept { return m_path; }

    [[nodiscard]] fs::path Write(const std::string& name, const std::string& content) const {
        const fs::path file = m_path / name;
        std::ofstream out(file, std::ios::binary);
        out << content;
        out.close();
        return file;
    }

private:
    fs::path m_path;
};

// ============================================================================
// profiles.ini
// ============================================================================

TEST(ThunderbirdProfiles, ARelativeProfileResolvesUnderTheIniDirectory) {
    ScopedTempDir temp;
    fs::create_directories(temp.path() / "Profiles" / "abcd1234.default");
    const auto ini = temp.Write("profiles.ini",
        "[Profile0]\n"
        "Name=default\n"
        "IsRelative=1\n"
        "Path=Profiles/abcd1234.default\n");

    const auto profiles = ParseProfilesIni(ini);
    ASSERT_EQ(1u, profiles.size());
    EXPECT_EQ("default", profiles[0].name);
    EXPECT_TRUE(profiles[0].path.is_absolute()) << "a relative entry must be resolved, not passed through";
    EXPECT_NE(std::string::npos, profiles[0].path.string().find("abcd1234.default"));
}

TEST(ThunderbirdProfiles, SeveralProfilesAreAllReturned) {
    ScopedTempDir temp;
    fs::create_directories(temp.path() / "Profiles" / "one");
    fs::create_directories(temp.path() / "Profiles" / "two");
    const auto ini = temp.Write("profiles.ini",
        "[General]\n"
        "StartWithLastProfile=1\n"
        "\n"
        "[Profile0]\n"
        "Name=default\n"
        "IsRelative=1\n"
        "Path=Profiles/one\n"
        "\n"
        "[Profile1]\n"
        "Name=work\n"
        "IsRelative=1\n"
        "Path=Profiles/two\n");

    const auto profiles = ParseProfilesIni(ini);
    ASSERT_EQ(2u, profiles.size()) << "the General section must not be counted as a profile";
    EXPECT_EQ("default", profiles[0].name);
    EXPECT_EQ("work", profiles[1].name);
}

TEST(ThunderbirdProfiles, ATraversingRelativePathIsRefused) {
    // THE CASE THAT MATTERS. These resolve outside the directory holding profiles.ini, and the resulting path
    // would be handed to the scanner to read. A parser that accepted them would point the product at the
    // system directory.
    ScopedTempDir temp;
    const auto ini = temp.Write("profiles.ini",
        "[Profile0]\n"
        "Name=evil\n"
        "IsRelative=1\n"
        "Path=../../../../Windows/System32\n"
        "\n"
        "[Profile1]\n"
        "Name=alsoevil\n"
        "IsRelative=1\n"
        "Path=..\\..\\..\\..\\Windows\n");

    for (const auto& profile : ParseProfilesIni(ini)) {
        const auto resolved = profile.path.lexically_normal().string();
        EXPECT_NE(std::string::npos, resolved.find(temp.path().filename().string()))
            << "profile '" << profile.name << "' escaped the profile root: " << resolved;
    }
}

TEST(ThunderbirdProfiles, AnEntryWithoutANameIsNotAProfile) {
    ScopedTempDir temp;
    const auto ini = temp.Write("profiles.ini",
        "[Profile0]\n"
        "IsRelative=1\n"
        "Path=Profiles/nameless\n");
    EXPECT_TRUE(ParseProfilesIni(ini).empty()) << "a profile with no Name must not be returned";
}

TEST(ThunderbirdProfiles, AMissingOrEmptyFileYieldsNothing) {
    // Non-vacuity: the cases above would pass against a parser that invented entries.
    ScopedTempDir temp;
    EXPECT_TRUE(ParseProfilesIni(temp.path() / "does-not-exist.ini").empty());
    EXPECT_TRUE(ParseProfilesIni(temp.Write("empty.ini", "")).empty());
    EXPECT_TRUE(ParseProfilesIni(temp.Write("junk.ini", "not an ini file at all\n")).empty());
    EXPECT_TRUE(ParseProfilesIni(temp.path()).empty()) << "a directory is not a profiles.ini";
}

TEST(ThunderbirdProfiles, AnOversizedFileIsRefusedRatherThanRead) {
    // The parser caps profiles.ini at one megabyte. A real one is a few hundred bytes, so anything larger is
    // either corrupt or hostile, and reading it would be the wrong response either way.
    ScopedTempDir temp;
    std::string huge = "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/one\n";
    huge.reserve(2u * 1024u * 1024u);
    while (huge.size() < 2u * 1024u * 1024u) {
        huge += "; padding padding padding padding padding padding padding padding\n";
    }
    EXPECT_TRUE(ParseProfilesIni(temp.Write("big.ini", huge)).empty())
        << "a file over the one-megabyte cap must be refused";
}

// ============================================================================
// Mailbox format detection
// ============================================================================

TEST(ThunderbirdMailbox, AnMboxIsRecognisedByItsFirstLine) {
    ScopedTempDir temp;
    const auto file = temp.Write("Inbox",
        "From sender@example.com Mon Jan  1 00:00:00 2026\n"
        "Subject: hello\n"
        "\n"
        "body\n");
    EXPECT_EQ(MailboxFormat::Mbox, DetectMailboxFormat(file));
}

TEST(ThunderbirdMailbox, AMaildirMessageIsRecognisedByItsParentDirectory) {
    // A Maildir message begins with ordinary headers, so the directory name is what identifies it.
    ScopedTempDir temp;
    for (const char* dir : {"cur", "new", "tmp"}) {
        const fs::path sub = temp.path() / dir;
        std::error_code ec;
        fs::create_directories(sub, ec);
        const fs::path file = sub / "1700000000.M1P2.host";
        std::ofstream out(file, std::ios::binary);
        out << "Return-Path: <sender@example.com>\nSubject: hello\n\nbody\n";
        out.close();
        EXPECT_EQ(MailboxFormat::Maildir, DetectMailboxFormat(file)) << dir;
    }
}

TEST(ThunderbirdMailbox, AnIndexFileIsNotAMailbox) {
    // .msf is Thunderbird's summary index, not mail. Treating it as a mailbox would have the scanner parse a
    // binary index as messages.
    ScopedTempDir temp;
    EXPECT_EQ(MailboxFormat::Unknown,
              DetectMailboxFormat(temp.Write("Inbox.msf", "From not-really-mail\n")))
        << "the extension must be checked before the first line";
}

TEST(ThunderbirdMailbox, AnUnrecognisedFileIsUnknownRatherThanGuessed) {
    // Non-vacuity, and the safe direction: Unknown means the caller does not parse it as mail.
    ScopedTempDir temp;
    EXPECT_EQ(MailboxFormat::Unknown, DetectMailboxFormat(temp.Write("notes.txt", "hello\n")));
    EXPECT_EQ(MailboxFormat::Unknown, DetectMailboxFormat(temp.Write("empty", "")));
    EXPECT_EQ(MailboxFormat::Unknown, DetectMailboxFormat(temp.path() / "missing"))
        << "a path that does not exist";
    EXPECT_EQ(MailboxFormat::Unknown, DetectMailboxFormat(temp.path()))
        << "a directory is not a mailbox";
}

TEST(ThunderbirdMailbox, TheFromPrefixMustBeTheWholeToken) {
    // "From " with the trailing space, not "From" - otherwise a message whose first header is From: would be
    // read as an mbox separator.
    ScopedTempDir temp;
    EXPECT_EQ(MailboxFormat::Unknown,
              DetectMailboxFormat(temp.Write("headers", "From: sender@example.com\nSubject: hi\n")))
        << "a From: header is not an mbox separator line";
}

}  // namespace
