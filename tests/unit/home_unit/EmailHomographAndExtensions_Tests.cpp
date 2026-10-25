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

#include <optional>
#include <string>
#include <utility>

#include "Products/Community/PhantomHome/Email/EmailProtection.hpp"
#include "Products/Community/PhantomHome/Email/PhishingEmailDetector.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

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

TEST(EmailExtensionPolicy, TheFormatsThisListUsedToMissAreDangerous) {
    // This list had 20 entries and lacked these four, each present in a sibling list. All checks now share
    // Utils::FileExtensionRisk (task 309), so the gap cannot reopen in one place only.
    EXPECT_TRUE(IsDangerousExtension(".inf")) << "a setup information file";
    EXPECT_TRUE(IsDangerousExtension(".vbe"))
        << "encoded VBScript - the standard way to obscure a .vbs, which this list always treated as dangerous";
    EXPECT_TRUE(IsDangerousExtension(".psm1")) << "a PowerShell module, where .ps1 is covered";
    EXPECT_TRUE(IsDangerousExtension(".psd1")) << "a PowerShell manifest";
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
    // A real Content-Type header carries parameters; only the type/subtype is compared.
    EXPECT_TRUE(IsBlockedMimeType("application/x-msdownload; charset=utf-8"));
    EXPECT_TRUE(IsBlockedMimeType("  Application/X-MSDownload ;name=\"a.exe\""));
    EXPECT_FALSE(IsBlockedMimeType("text/plain; charset=application/x-msdownload"))
        << "a parameter value is not the type";
    EXPECT_FALSE(IsBlockedMimeType("application/x-msdownloadx"));
    EXPECT_FALSE(IsBlockedMimeType(";"));
}

// Task 292: a shortened link is one whose HOST is the shortener, not one that contains its name.
TEST(EmailShortenedLinks, TheHostMustBeTheShortener) {
    auto& detector = ShadowStrike::Email::PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) (void)detector.Initialize();
    for (const char* url : {"https://bit.ly/abc", "https://t.co/xyz", "http://BIT.LY./q", "https://www.tinyurl.com/z"}) {
        EXPECT_TRUE(detector.AnalyzeURL(url).isShortened) << url;
    }
    for (const char* url : {"https://www.microsoft.com/download", "https://shirt.co/sale",
                            "https://example.com/?next=bit.ly", "https://notbit.ly.example/x"}) {
        EXPECT_FALSE(detector.AnalyzeURL(url).isShortened) << url;
    }
}

// Task 310: a domain whose confusable skeleton spells a brand imitates it, whether its label is
// mixed-script or written entirely in lookalikes - which mixing alone cannot see.
constexpr const char* kCyrillicY = "\xD1\x83";        // U+0443, looks like 'y'
constexpr const char* kCyrillicPalochka = "\xD3\x8F"; // U+04CF, looks like 'l'
constexpr const char* kCyrillicEs = "\xD1\x81";       // U+0441, looks like 'c'

std::string AllLookalikePaypal() {
    return std::string(kCyrillicP) + kCyrillicA + kCyrillicY + kCyrillicP + kCyrillicA + kCyrillicPalochka;
}

TEST(EmailConfusableSkeleton, ASkeletonIsTheAsciiAReaderSees) {
    using ShadowStrike::Email::ConfusableSkeleton;
    EXPECT_EQ(std::optional<std::string>("paypal.com"), ConfusableSkeleton(AllLookalikePaypal() + ".com"));
    EXPECT_EQ(std::optional<std::string>("paypal.com"), ConfusableSkeleton(std::string("p") + kCyrillicA + "ypal.com"));
    EXPECT_FALSE(ConfusableSkeleton("paypal.com").has_value()) << "nothing was substituted";
    EXPECT_FALSE(ConfusableSkeleton(std::string(kCyrillicCh) + kCyrillicA + kCyrillicT + ".com").has_value())
        << "a letter with no Latin lookalike is ordinary Cyrillic text";
}

TEST(EmailConfusableSkeleton, APunycodeLinkIsDecodedFirst) {
    const std::wstring unicode = ShadowStrike::Utils::StringUtils::ToWide(AllLookalikePaypal() + ".com");
    wchar_t ascii[256]{};
    const int n = ::IdnToAscii(0, unicode.c_str(), static_cast<int>(unicode.size()), ascii, 256);
    ASSERT_GT(n, 0);
    const std::string puny = ShadowStrike::Utils::StringUtils::ToNarrow(std::wstring(ascii, static_cast<size_t>(n)));
    ASSERT_EQ(0u, puny.rfind("xn--", 0)) << puny;
    EXPECT_EQ(std::optional<std::string>("paypal.com"), ShadowStrike::Email::ConfusableSkeleton(puny));
}

TEST(EmailConfusableSkeleton, ALookalikeOfABrandIsImpersonationAndAnOrdinaryWordIsNot) {
    auto& detector = ShadowStrike::Email::PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) (void)detector.Initialize();
    EXPECT_EQ(std::optional<std::string>("paypal"), detector.DetectBrandImpersonation(AllLookalikePaypal() + ".com"))
        << "an all-Cyrillic paypal is single-script, so mixing never saw it";
    EXPECT_EQ(std::optional<std::string>("paypal"),
              detector.DetectBrandImpersonation(AllLookalikePaypal() + "-secure.example"));
    // Spelled entirely in lookalikes, but the skeleton (coco) names no brand.
    const std::string coco = std::string(kCyrillicEs) + kCyrillicO + kCyrillicEs + kCyrillicO + ".com";
    EXPECT_FALSE(detector.DetectBrandImpersonation(coco).has_value());
    EXPECT_FALSE(ContainsHomographCharacters(coco)) << "single-script Cyrillic stays clean";
    // The skeleton (paws) CONTAINS a brand (aws) without being it; a whole token must match.
    const std::string paws = std::string(kCyrillicP) + kCyrillicA + "\xD4\x9D" /* U+051D w */ +
                             "\xD1\x95" /* U+0455 s */ + ".com";
    EXPECT_EQ(std::optional<std::string>("paws.com"), ShadowStrike::Email::ConfusableSkeleton(paws));
    EXPECT_FALSE(detector.DetectBrandImpersonation(paws).has_value());
}

// Task 344: a brand's own domains are the brand, and ordinary words that contain a short brand
// name are not; every phishing shape the old substring match caught is still caught.
TEST(EmailBrandImpersonation, TheBrandsOwnDomainsAreNotImpersonation) {
    auto& detector = ShadowStrike::Email::PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) (void)detector.Initialize();
    for (const char* host : {"login.microsoftonline.com", "accounts.google.com", "outlook.office.com",
                             "outlook.office365.com", "www.amazon.co.uk", "aws.amazon.com", "drive.google.com",
                             "appleid.apple.com", "www.paypal.com", "paypal.com", "secure.chase.com",
                             "onedrive.live.com", "www.netflix.com.", "Login.Live.com",
                             // userinfo: the host contacted is PayPal's own apex, so the text
                             // before it must not be read as part of the domain
                             "someone@paypal.com"}) {
        EXPECT_FALSE(detector.DetectBrandImpersonation(host).has_value())
            << host << " was reported as impersonating " << detector.DetectBrandImpersonation(host).value_or("");
    }
}

TEST(EmailBrandImpersonation, AWordThatContainsAShortBrandIsNotTheBrand) {
    auto& detector = ShadowStrike::Email::PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) (void)detector.Initialize();
    for (const char* host : {"purchase-orders.example", "groups.example.org", "laws.example", "drivers.example",
                             "pineapple.example", "primeval.example", "stripes.example", "adobes.example",
                             "upsidedown.example", "applemyth.example"}) {
        EXPECT_FALSE(detector.DetectBrandImpersonation(host).has_value())
            << host << " matched " << detector.DetectBrandImpersonation(host).value_or("");
    }
}

TEST(EmailBrandImpersonation, EveryPhishingShapeIsStillDetected) {
    auto& detector = ShadowStrike::Email::PhishingEmailDetector::Instance();
    if (!detector.IsInitialized()) (void)detector.Initialize();
    const std::pair<const char*, const char*> cases[] = {
        {"microsoft-login.xyz", "microsoft"},       {"paypal-secure.example", "paypal"},
        {"paypalsupport.example", "paypal"},        {"securepaypal.example", "paypal"},
        {"paypal.com.evil.example", "paypal"},      {"paypal.com@evil.example", "paypal"},
        {"chasebank-alert.example", "chase"},       {"appleid-verify.example", "apple"},
        {"chase.example", "chase"},                 {"ups-delivery.example", "ups"},
        {"microsoft.com.evil.example", "microsoft"}, {"notpaypal.com", "paypal"},
        {"dhl.example", "dhl"},                     {"amazon-support.example", "amazon"},
        {"applesupportcenter.example", "apple"},    {"chasebankalert.example", "chase"},
        {"myupsaccount.example", "ups"},            {"secure-dhlparcel.example", "dhl"},
    };
    for (const auto& [host, brand] : cases) {
        EXPECT_EQ(std::optional<std::string>(brand), detector.DetectBrandImpersonation(host)) << host;
    }
}

}  // namespace
