/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PhishingDetector_Tests.cpp
 * @brief Typosquatting: a brand's own subdomain is not a typo, and a national brand is reachable.
 *
 * Two defects are pinned here, and they pull in opposite directions, which is why they were fixed
 * together.
 *
 * The FALSE POSITIVE. CheckTyposquatting compares both the full domain and the registrable domain
 * against each protected brand domain, but the exact-match guard only skipped a full-domain match.
 * So www.paypal.com produced the registrable candidate paypal.com, matched the brand domain at
 * distance 0 and similarity 1.0, and was reported as typosquatting the brand it belongs to. Every
 * subdomain of every protected brand was affected.
 *
 * The MISS. ExtractRegistrableDomain returned the last two labels, which for a multi-label public
 * suffix is the suffix itself, so a brand at hsbc.co.uk had only co.uk to compare against and
 * every typosquat of it was invisible. That covers most national banking and media brands.
 *
 * Correcting the registrable domain WITHOUT the identity skip would have extended the false
 * positive to those same brands, so each case below states which of the two it holds.
 *
 * Thresholds are TYPOSQUAT_MAX_EDIT_DIST = 3 and TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75. The
 * distances quoted in the comments are against those, not invented.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/Utils/DomainUtils.hpp"
#include "Products/Community/PhantomHome/WebProtection/PhishingDetector.hpp"

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace ShadowStrike::WebBrowser::Test {
namespace {

[[nodiscard]] bool LoadPublicSuffixListForTests() {
    using ShadowStrike::Utils::Domain::PublicSuffixList;
    auto& psl = PublicSuffixList::Instance();
    if (psl.IsLoaded()) {
        return true;
    }
    std::error_code ec;
    std::filesystem::path here = std::filesystem::current_path(ec);
    for (int depth = 0; depth < 8 && !here.empty(); ++depth) {
        const std::filesystem::path candidate =
            here / L"content" / L"psl" / L"public_suffix_list.dat";
        if (std::filesystem::exists(candidate, ec)) {
            return psl.LoadFromFile(candidate.wstring());
        }
        if (!here.has_parent_path() || here.parent_path() == here) {
            break;
        }
        here = here.parent_path();
    }
    return false;
}

class TyposquattingTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(LoadPublicSuffixListForTests())
            << "the vendored public suffix list could not be located; the multi-label cases "
               "would exercise the fallback and prove nothing";
    }

    void SetUp() override {
        auto& detector = PhishingDetector::Instance();
        // A two-label brand and a multi-label one, because the two defects show up on different
        // suffix shapes.
        ASSERT_TRUE(detector.AddProtectedBrand("TestPayBrand",
                                               std::vector<std::string>{"testpaybrand.com"}));
        ASSERT_TRUE(detector.AddProtectedBrand("TestBankBrand",
                                               std::vector<std::string>{"testbankbrand.co.uk"}));
    }
};

// ============================================================================================
// The false positive: a brand's own subdomain is not typosquatting
// ============================================================================================

TEST_F(TyposquattingTest, ASubdomainOfAProtectedBrandIsNotTyposquatting) {
    // Previously: registrable candidate testpaybrand.com matched the brand domain at distance 0
    // and similarity 1.0, so the brand's own www host was reported as attacking itself.
    auto& detector = PhishingDetector::Instance();

    const auto www = detector.CheckTyposquatting("www.testpaybrand.com");
    EXPECT_FALSE(www.isTyposquatting)
        << "www.testpaybrand.com reported as typosquatting " << www.targetBrand
        << " at edit distance " << www.editDistance;

    const auto login = detector.CheckTyposquatting("login.eu.testpaybrand.com");
    EXPECT_FALSE(login.isTyposquatting)
        << "a deep subdomain of the brand reported as typosquatting " << login.targetBrand;
}

TEST_F(TyposquattingTest, ASubdomainOfAMultiLabelSuffixBrandIsNotTyposquatting) {
    // The case that a naive registrable-domain fix would have broken: correcting the boundary
    // makes www.testbankbrand.co.uk resolve to the brand domain exactly, so without the identity
    // skip it would newly be flagged at distance 0.
    const auto result = PhishingDetector::Instance().CheckTyposquatting("www.testbankbrand.co.uk");
    EXPECT_FALSE(result.isTyposquatting)
        << "www.testbankbrand.co.uk reported as typosquatting " << result.targetBrand
        << " at edit distance " << result.editDistance;
}

TEST_F(TyposquattingTest, TheBrandDomainItselfIsNotTyposquatting) {
    auto& detector = PhishingDetector::Instance();
    EXPECT_FALSE(detector.CheckTyposquatting("testpaybrand.com").isTyposquatting);
    EXPECT_FALSE(detector.CheckTyposquatting("testbankbrand.co.uk").isTyposquatting);
}

// ============================================================================================
// The miss: a brand under a multi-label suffix is now reachable
// ============================================================================================

TEST_F(TyposquattingTest, ATyposquatOfAMultiLabelSuffixBrandIsDetected) {
    // brand testbankbrand.co.uk, host login.testbankbrand1.co.uk
    //   full domain  login.testbankbrand1.co.uk  distance 7  above the limit of 3
    //   old base     co.uk                       distance 14 above the limit  -> UNDETECTED
    //   registrable  testbankbrand1.co.uk        distance 1  similarity 0.95  -> DETECTED
    const auto result =
        PhishingDetector::Instance().CheckTyposquatting("login.testbankbrand1.co.uk");
    EXPECT_TRUE(result.isTyposquatting)
        << "a typosquat of a .co.uk brand was not detected";
    EXPECT_EQ("testbankbrand", result.targetBrand);
    EXPECT_EQ("testbankbrand.co.uk", result.targetDomain);
    EXPECT_GT(result.editDistance, 0)
        << "a reported typosquat must differ from the brand domain; distance 0 is identity";
}

TEST_F(TyposquattingTest, ATyposquatOfATwoLabelBrandIsStillDetected) {
    // Behaviour that must NOT change: this worked before and must keep working.
    const auto result = PhishingDetector::Instance().CheckTyposquatting("testpaybrand1.com");
    EXPECT_TRUE(result.isTyposquatting);
    EXPECT_EQ("testpaybrand", result.targetBrand);
    EXPECT_GT(result.editDistance, 0);
}

// ============================================================================================
// Directions that must not change
// ============================================================================================

TEST_F(TyposquattingTest, AnUnrelatedDomainIsNotTyposquatting) {
    // Anti-vacuity for the negative cases above: they would all read as passing if
    // isTyposquatting were always false, so prove a genuine positive is still reachable while an
    // unrelated domain stays negative.
    auto& detector = PhishingDetector::Instance();
    EXPECT_FALSE(detector.CheckTyposquatting("entirely-unrelated-host.example").isTyposquatting);
    EXPECT_FALSE(detector.CheckTyposquatting("nothinglikethebrand.org").isTyposquatting);
}

TEST_F(TyposquattingTest, ASuffixLookalikeIsNotTheBrand) {
    // The brand name appearing as a LABEL of someone else's domain must not resolve to the brand.
    const auto result =
        PhishingDetector::Instance().CheckTyposquatting("testpaybrand.com.attacker-host.example");
    EXPECT_NE("testpaybrand.com", result.targetDomain)
        << "a host owned by attacker-host.example resolved to the brand's own domain";
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
