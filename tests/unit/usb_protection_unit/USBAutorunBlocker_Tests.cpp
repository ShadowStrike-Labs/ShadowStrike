/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file USBAutorunBlocker_Tests.cpp
 * @brief The autorun.inf parser and its dangerous-key classification.
 *
 * autorun.inf is attacker-controlled content on removable media - the vector Conficker and Stuxnet
 * used - and the parser that reads it is pure, so it can be tested exactly. No defect was found in
 * this module while surveying it; these cases exist because the behaviour is currently unpinned,
 * and two specific hypotheses were checked and refuted rather than assumed:
 *
 *   - that IsDangerousAutorunKey compares case-sensitively. It lowercases internally, so
 *     ParseAutorunContent passing an already-lowered key and the public IsAutorunKey passing a raw
 *     one both work. The case-varied cases below hold that, because it is the kind of property
 *     that breaks silently when someone "simplifies" the comparison.
 *   - that a shell verb variant could evade classification. The starts_with/ends_with pair covers
 *     shell\<verb>\command for any verb, and that is asserted for verbs the constant list does not
 *     name.
 *
 * The threat-type mapping is asserted too, because a key can be correctly flagged as dangerous and
 * still be reported as the wrong kind of threat, which is what an operator acts on.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/USB_Protection/USBAutorunBlocker.hpp"

#include <string>
#include <string_view>

namespace ShadowStrike::USB::Test {
namespace {

[[nodiscard]] const AutorunEntry* FindEntry(const std::vector<AutorunEntry>& entries,
                                           std::string_view key) {
    for (const auto& e : entries) {
        std::string lower;
        lower.reserve(e.key.size());
        for (unsigned char c : e.key) {
            lower.push_back(static_cast<char>(std::tolower(c)));
        }
        if (lower == key) {
            return &e;
        }
    }
    return nullptr;
}

// ============================================================================================
// Dangerous key classification
// ============================================================================================

TEST(AutorunKeyClassificationTest, TheExecutionKeysAreDangerous) {
    EXPECT_TRUE(IsDangerousAutorunKey("open"));
    EXPECT_TRUE(IsDangerousAutorunKey("shellexecute"));
}

TEST(AutorunKeyClassificationTest, ThePresentationKeysAreNotDangerous) {
    // If these were flagged, every legitimate labelled volume would look like an attack.
    EXPECT_FALSE(IsDangerousAutorunKey("label"));
    EXPECT_FALSE(IsDangerousAutorunKey("icon"));
}

TEST(AutorunKeyClassificationTest, ClassificationIgnoresCase) {
    // An ini key is case-insensitive on Windows, so a mixed-case key must classify identically.
    // A case-sensitive comparison here would be a one-character bypass.
    EXPECT_TRUE(IsDangerousAutorunKey("OPEN"));
    EXPECT_TRUE(IsDangerousAutorunKey("Open"));
    EXPECT_TRUE(IsDangerousAutorunKey("ShellExecute"));
    EXPECT_TRUE(IsDangerousAutorunKey("SHELLEXECUTE"));
}

TEST(AutorunKeyClassificationTest, AnyShellVerbCommandIsDangerous) {
    // The pattern must cover verbs the constant list does not name, because the verb is chosen by
    // whoever writes the file.
    EXPECT_TRUE(IsDangerousAutorunKey("shell\\open\\command"));
    EXPECT_TRUE(IsDangerousAutorunKey("shell\\explore\\command"));
    EXPECT_TRUE(IsDangerousAutorunKey("shell\\anyverbatall\\command"));
    EXPECT_TRUE(IsDangerousAutorunKey("SHELL\\Open\\COMMAND"));
}

TEST(AutorunKeyClassificationTest, AKeyThatMerelyMentionsShellIsNotDangerous) {
    // Anti-vacuity for the case above: the pattern must not match on the word alone, or every
    // key containing "shell" would be flagged.
    EXPECT_FALSE(IsDangerousAutorunKey("shellicon"));
    EXPECT_FALSE(IsDangerousAutorunKey("myshellsetting"));
}

TEST(AutorunKeyClassificationTest, RecognisedKeysIncludeBothSafeAndDangerous) {
    // IsAutorunKey answers "is this a key autorun.inf defines", not "is this safe".
    EXPECT_TRUE(IsAutorunKey("open"));
    EXPECT_TRUE(IsAutorunKey("label"));
    EXPECT_TRUE(IsAutorunKey("useautoplay"));
    EXPECT_FALSE(IsAutorunKey("not-an-autorun-key-at-all"));
}

// ============================================================================================
// Parsing
// ============================================================================================

class AutorunParserTest : public ::testing::Test {
protected:
    static std::vector<AutorunEntry> Parse(std::string_view content) {
        return USBAutorunBlocker::Instance().ParseAutorunContent(content);
    }
};

TEST_F(AutorunParserTest, AMaliciousAutorunIsParsedAndFlagged) {
    const auto entries = Parse(
        "[autorun]\r\n"
        "open=evil.exe\r\n"
        "shellexecute=payload.vbs\r\n"
        "label=My USB Drive\r\n");

    ASSERT_EQ(3u, entries.size());

    const auto* open = FindEntry(entries, "open");
    ASSERT_NE(nullptr, open);
    EXPECT_EQ("evil.exe", open->value);
    EXPECT_TRUE(open->isDangerous);
    EXPECT_EQ(AutorunThreatType::OpenCommand, open->threatType)
        << "an open= key must be reported as an open command, not merely as dangerous";

    const auto* shell = FindEntry(entries, "shellexecute");
    ASSERT_NE(nullptr, shell);
    EXPECT_TRUE(shell->isDangerous);
    EXPECT_EQ(AutorunThreatType::ShellExecute, shell->threatType);

    const auto* label = FindEntry(entries, "label");
    ASSERT_NE(nullptr, label);
    EXPECT_FALSE(label->isDangerous);
    EXPECT_EQ("My USB Drive", label->value);
}

TEST_F(AutorunParserTest, TheSectionIsRecordedInLowerCase) {
    const auto entries = Parse("[AutoRun]\nopen=x.exe\n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("autorun", entries[0].section)
        << "an ini section is case-insensitive, so it must be normalised at parse time";
}

TEST_F(AutorunParserTest, CommentsAndBlankLinesAreIgnored) {
    const auto entries = Parse(
        "; this is a comment\n"
        "\n"
        "[autorun]\n"
        "; open=decoy.exe\n"
        "open=real.exe\n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("real.exe", entries[0].value)
        << "a commented-out key was parsed as live, so a decoy line would be reported";
}

TEST_F(AutorunParserTest, ABomAndBothLineEndingsAreHandled) {
    // Removable media is written by arbitrary tools; a UTF-8 BOM and bare LF are both common.
    const auto withBom = Parse("\xEF\xBB\xBF[autorun]\r\nopen=a.exe\r\n");
    ASSERT_EQ(1u, withBom.size());
    EXPECT_EQ("autorun", withBom[0].section)
        << "a leading BOM was left on the section name, so the section did not match";
    EXPECT_EQ("a.exe", withBom[0].value);

    const auto bareLf = Parse("[autorun]\nopen=b.exe\n");
    ASSERT_EQ(1u, bareLf.size());
    EXPECT_EQ("b.exe", bareLf[0].value);
}

TEST_F(AutorunParserTest, SurroundingWhitespaceIsNotPartOfTheKeyOrValue) {
    const auto entries = Parse("[autorun]\n   open   =   spaced.exe   \n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_TRUE(entries[0].isDangerous)
        << "a padded key was not recognised as dangerous, which is a whitespace bypass";
    EXPECT_EQ("spaced.exe", entries[0].value);
}

TEST_F(AutorunParserTest, ALineWithNoAssignmentIsNotAnEntry) {
    const auto entries = Parse("[autorun]\nthis line has no equals sign\nopen=x.exe\n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("x.exe", entries[0].value);
}

TEST_F(AutorunParserTest, AnEmptyKeyIsRejected) {
    const auto entries = Parse("[autorun]\n=orphanvalue\nopen=x.exe\n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("x.exe", entries[0].value);
}

TEST_F(AutorunParserTest, AValueMayContainAnEqualsSign) {
    // Only the FIRST separator divides key from value, or a command line with arguments is
    // truncated and the recorded value no longer matches what would run.
    const auto entries = Parse("[autorun]\nopen=cmd.exe /c set X=1\n");
    ASSERT_EQ(1u, entries.size());
    EXPECT_EQ("cmd.exe /c set X=1", entries[0].value);
}

TEST_F(AutorunParserTest, EmptyContentYieldsNoEntries) {
    EXPECT_TRUE(Parse("").empty());
    EXPECT_TRUE(Parse("\r\n\r\n").empty());
}

// ============================================================================================
// Path safety
// ============================================================================================

TEST(AutorunPathSafetyTest, ATraversalPathIsDangerous) {
    auto& blocker = USBAutorunBlocker::Instance();
    EXPECT_TRUE(blocker.IsDangerousPath("..\\..\\Windows\\System32\\cmd.exe"));
    EXPECT_TRUE(blocker.IsDangerousPath("payload/../../../windows/system32/calc.exe"));
}

TEST(AutorunPathSafetyTest, APlainRelativeNameIsNotDangerous) {
    // Anti-vacuity: if everything were dangerous the assertions above would prove nothing.
    auto& blocker = USBAutorunBlocker::Instance();
    EXPECT_FALSE(blocker.IsDangerousPath("setup.exe"));
    EXPECT_FALSE(blocker.IsDangerousPath("tools\\installer.exe"));
}

}  // namespace
}  // namespace ShadowStrike::USB::Test
