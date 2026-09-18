// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Email homograph and extension policy tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file EmailHomographAndExtensions_Tests.cpp
 * @brief Pins what counts as a homograph domain, and which attachment extensions are dangerous.
 *
 * A homograph attack substitutes a lookalike character into an otherwise Latin label, so the label mixes
 * scripts. The detector used to return true for any byte above 127, which made every internationalised
 * domain an attack and left the module's own 23-entry lookalike map unused. These cases pin both directions:
 * a mixed label is detected, and a domain that is merely not English is not.
 *
 * The extension policy is pinned per list rather than across them, because the three lists in this product
 * disagree and the disagreement is filed rather than fixed. What is asserted here is what each list actually
 * contains, so that consolidating them later is a visible change rather than a silent one.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/Email/EmailProtection.hpp"
#include "Products/Community/PhantomHome/Email/PhishingEmailDetector.hpp"

namespace {

using ShadowStrike::Email::ContainsHomographCharacters;
using ShadowStrike::Email::IsBlockedMimeType;
using ShadowStrike::Email::IsDangerousExtension;

// UTF-8 for the Cyrillic characters that exist to be confused with Latin ones. Written as explicit bytes so
// this file stays ASCII - the source encoding is not what is under test.
constexpr const char* kCyrillicA = "\xD0\xB0";  // U+0430, looks like 'a'
constexpr const char* kCyrillicO = "\xD0\xBE";  // U+043E, looks like 'o'
constexpr const char* kCyrillicE = "\xD0\xB5";  // U+0435, looks like 'e'
constexpr const char* kCyrillicP = "\xD1\x80";  // U+0440, looks like 'p'
constexpr const char* kCyrillicCh = "\xD1\x87";  // U+0447, looks like nothing Latin
constexpr const char* kCyrillicT = "\xD1\x82";  // U+0442, looks like nothing Latin
constexpr const char* kGreekOmicron = "\xCF\x8C";  // U+03CC, not in the map
constexpr const char* kUmlautU = "\xC3\xBC";  // U+00FC, an ordinary accented Latin letter
constexpr const char* kHanNi = "\xE6\x97\xA5";  // U+65E5, Han

// ============================================================================
// Homograph detection
// ============================================================================

TEST(EmailHomograph, ALatinLabelWithASubstitutedLookalikeIsDetected) {
    // The attack. Each of these is Latin except for one lookalike, which is exactly the mixing that matters.
    EXPECT_TRUE(ContainsHomographCharacters(std::string("p") + kCyrillicA + "ypal.com"))
        << "the case the module's own SelfTest asserts";
    EXPECT_TRUE(ContainsHomographCharacters(std::string("g") + kCyrillicO + "ogle.com"));
    EXPECT_TRUE(ContainsHomographCharacters(std::string("micr") + kCyrillicO + "soft.com"));
    EXPECT_TRUE(ContainsHomographCharacters(std::string("appl") + kCyrillicE + ".com"));
    EXPECT_TRUE(ContainsHomographCharacters(std::string("amazon-su") + kCyrillicP + "port.net"));
}

TEST(EmailHomograph, MixingIsDetectedWhereverItSitsInTheLabel) {
    EXPECT_TRUE(ContainsHomographCharacters(std::string(kCyrillicA) + "pple.com")) << "first character";
    EXPECT_TRUE(ContainsHomographCharacters(std::string("appl") + kCyrillicE)) << "last character";
    EXPECT_TRUE(ContainsHomographCharacters(std::string("b") + kCyrillicA + "nk" + kCyrillicO + "f.com"))
        << "more than one substitution";
}

TEST(EmailHomograph, AnInternationalisedDomainIsNotAnAttack) {
    // The false positives. Every one of these was reported as a homograph attack because it contains a byte
    // above 127, which says only that the text is not English.
    EXPECT_FALSE(ContainsHomographCharacters(std::string("m") + kUmlautU + "nchen.de"))
        << "an accented Latin letter is not a lookalike for a different letter";
    EXPECT_FALSE(ContainsHomographCharacters(std::string(kHanNi) + kHanNi + ".jp"))
        << "Han characters resemble no Latin letter";
    EXPECT_FALSE(ContainsHomographCharacters(std::string("caf") + "\xC3\xA9" + ".fr"));
    EXPECT_FALSE(ContainsHomographCharacters(std::string("stra") + "\xC3\x9F" + "e.de"));
}

TEST(EmailHomograph, ASingleScriptCyrillicDomainIsNotAnAttack) {
    // An ordinary Russian domain. Cyrillic o and a ARE in the lookalike map because they resemble Latin
    // letters, so testing for those characters alone would flag every Russian domain - which is why the test
    // is for MIXING within a label rather than for the characters.
    const std::string pochta = std::string(kCyrillicP) + kCyrillicO + kCyrillicCh + kCyrillicT + kCyrillicA;
    EXPECT_FALSE(ContainsHomographCharacters(pochta))
        << "wholly Cyrillic, so nothing is being disguised as Latin";

    // And the label boundary must hold when a Latin TLD or scheme sits beside it: those are separate runs.
    EXPECT_FALSE(ContainsHomographCharacters("http://" + pochta + ".com"))
        << "the scheme and the TLD are their own runs; mixing is judged within a run";
}

TEST(EmailHomograph, PureAsciiIsNeverAHomograph) {
    // Non-vacuity in the other direction: a typosquat is a different attack and this predicate must not
    // claim it.
    EXPECT_FALSE(ContainsHomographCharacters("paypal.com"));
    EXPECT_FALSE(ContainsHomographCharacters("paypa1.com")) << "digit one for letter l is a typosquat";
    EXPECT_FALSE(ContainsHomographCharacters("rnicrosoft.com")) << "rn for m is a typosquat";
    EXPECT_FALSE(ContainsHomographCharacters(""));
    EXPECT_FALSE(ContainsHomographCharacters("..."));
}

TEST(EmailHomograph, ALookalikeNotInTheMapIsNotClaimed) {
    // The map holds 23 characters. A Greek codepoint outside it is not reported, which is honest about the
    // coverage rather than guessing from a range - and is why the map, not a range, is the authority.
    EXPECT_FALSE(ContainsHomographCharacters(std::string("g") + kGreekOmicron + "ogle.com"))
        << "U+03CC is absent from the map; if this now passes the map was extended, which is an "
           "improvement - widen this case rather than reverting it";
}

TEST(EmailHomograph, MalformedUtf8IsReported) {
    // A lone continuation byte is not valid UTF-8. ToWide rejects it, and text that cannot be decoded
    // cannot be compared with anything, so it is reported rather than silently passed.
    EXPECT_TRUE(ContainsHomographCharacters(std::string("paypal") + "\x80" + ".com"));
    EXPECT_TRUE(ContainsHomographCharacters(std::string("\xC3") + "truncated.com"))
        << "a lead byte with no continuation";
}

// ============================================================================
// Attachment extension policy
// ============================================================================

TEST(EmailExtensionPolicy, TheExecutableFormatsAreDangerous) {
    for (const char* extension : {".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
                                  ".wsh", ".wsf", ".scr", ".hta", ".pif", ".reg", ".msi", ".msp",
                                  ".dll", ".cpl", ".jar", ".lnk"}) {
        EXPECT_TRUE(IsDangerousExtension(extension)) << extension;
    }
}

TEST(EmailExtensionPolicy, TheComparisonIsCaseInsensitiveAndWholeString) {
    EXPECT_TRUE(IsDangerousExtension(".EXE"));
    EXPECT_TRUE(IsDangerousExtension(".Exe"));
    EXPECT_TRUE(IsDangerousExtension(".PS1"));

    // Whole-string, not a prefix or a substring: the length is compared before the characters.
    EXPECT_FALSE(IsDangerousExtension(".exe.txt")) << "a longer string that begins with a dangerous one";
    EXPECT_FALSE(IsDangerousExtension("exe")) << "the leading dot is part of the entry";
    EXPECT_FALSE(IsDangerousExtension(".ex")) << "a prefix of a dangerous extension";
    EXPECT_FALSE(IsDangerousExtension("")) << "and empty is not dangerous";
}

TEST(EmailExtensionPolicy, TheOrdinaryDocumentFormatsAreNotDangerous) {
    // Non-vacuity: without this the cases above would pass against a predicate that always answers true.
    for (const char* extension : {".txt", ".pdf", ".jpg", ".png", ".docx", ".xlsx", ".zip"}) {
        EXPECT_FALSE(IsDangerousExtension(extension)) << extension;
    }
}

TEST(EmailExtensionPolicy, ThreeExtensionsAreAbsentFromThisListAndPresentInASibling) {
    // PINNED AS IT BEHAVES, NOT AS IT SHOULD. This product has THREE dangerous-extension lists and no one of
    // them is a superset: EmailProtection has 20 entries, AttachmentScanner 22, MaliciousDownloadBlocker 21,
    // and the union is 25. Filed rather than synchronised, because copying entries between duplicated lists
    // fixes today and guarantees the next divergence.
    //
    // If any of these starts passing, the lists were consolidated - which is the fix the filing asks for.
    // Update the filing and this case rather than reverting.
    EXPECT_FALSE(IsDangerousExtension(".inf"))
        << "a setup information file, which both sibling lists treat as high risk";
    EXPECT_FALSE(IsDangerousExtension(".vbe"))
        << "encoded VBScript - the standard way to obscure a .vbs, which this list does treat as dangerous";
    EXPECT_FALSE(IsDangerousExtension(".psm1")) << "a PowerShell module, where .ps1 is covered";
    EXPECT_FALSE(IsDangerousExtension(".psd1")) << "a PowerShell manifest";
}

TEST(EmailMimePolicy, TheExecutableMimeTypesAreBlockedCaseInsensitively) {
    for (const char* type : {"application/x-msdownload", "application/x-executable",
                             "application/x-msdos-program", "application/x-sh",
                             "application/x-shellscript"}) {
        EXPECT_TRUE(IsBlockedMimeType(type)) << type;
    }
    EXPECT_TRUE(IsBlockedMimeType("APPLICATION/X-MSDOWNLOAD")) << "lowered before the lookup";

    EXPECT_FALSE(IsBlockedMimeType("text/plain"));
    EXPECT_FALSE(IsBlockedMimeType("application/pdf"));
    EXPECT_FALSE(IsBlockedMimeType(""));
    EXPECT_FALSE(IsBlockedMimeType("application/x-msdownload; charset=utf-8"))
        << "the lookup is exact, so a parameter is not stripped first - worth knowing, since a real "
           "Content-Type header often carries one";
}

}  // namespace
