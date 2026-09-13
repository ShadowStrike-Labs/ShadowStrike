/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file CookieManager_Tests.cpp
 * @brief Cookie party identity: which party a cookie belongs to, at the public suffix boundary.
 *
 * THIS IS THE FIRST BEHAVIOURAL TEST OF A PHANTOMHOME FEATURE MODULE. Until this file, the Home
 * product's feature modules were reachable only from PhantomHomeModules, ShadowStrike and the
 * service - none of which is the test binary - so Privacy, WebProtection, Email, Banking, IoT,
 * GameMode, USB and Backup had no unit coverage at all. The consequence was concrete: the
 * base-domain defect these cases pin shipped past a self-test asserting ".example.com" yields
 * "example.com", which holds under both the wrong rule and the right one.
 *
 * The rule being replaced returned the last two labels, which for a multi-label public suffix IS
 * the suffix. Every assertion below distinguishes that behaviour from the correct one, and the
 * expected values are written as the wrong answer would differ, so a regression fails here rather
 * than merely changing a score.
 *
 * Scope is IncludePrivate throughout, because these callers ask which party owns a cookie rather
 * than measuring a string an attacker chose.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/Utils/DomainUtils.hpp"
#include "Products/Community/PhantomHome/Privacy/CookieManager.hpp"

#include <filesystem>
#include <string>
#include <system_error>

namespace ShadowStrike::Privacy::Test {
namespace {

/**
 * @brief Load the vendored Public Suffix List for the test process.
 *
 * EnsureLoaded() resolves beside the executable, and the test binary lives in bin\Release, which
 * has no psl directory. Without this the cases below would silently exercise the FALLBACK rather
 * than the path under test - and the fallback is the very behaviour they exist to reject.
 */
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

class CookieIdentityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(LoadPublicSuffixListForTests())
            << "the vendored public suffix list could not be located; these cases would "
               "otherwise exercise the fallback and pass without testing anything";
    }
};

// ============================================================================================
// GetBaseDomain
// ============================================================================================

TEST_F(CookieIdentityTest, AMultiLabelSuffixIsNotABaseDomain) {
    // The defect: the last two labels of evil.co.uk are co.uk, which is the public suffix.
    EXPECT_EQ("evil.co.uk", GetBaseDomain("evil.co.uk"));
    EXPECT_EQ("evil.co.uk", GetBaseDomain("a.b.evil.co.uk"));
    EXPECT_EQ("bbc.co.uk", GetBaseDomain("www.bbc.co.uk"));
    EXPECT_EQ("example.com.au", GetBaseDomain("shop.example.com.au"));
}

TEST_F(CookieIdentityTest, TwoSitesUnderOneSuffixAreDifferentParties) {
    // Under the previous rule both of these were "co.uk", which is what made every UK domain
    // one party for tracker matching and one row for the domain summary.
    EXPECT_NE(GetBaseDomain("evil.co.uk"), GetBaseDomain("good.co.uk"));
}

TEST_F(CookieIdentityTest, TheCommonTwoLabelCaseIsUnchanged) {
    // These held under the previous rule too. They are asserted so the fix cannot be mistaken
    // for a behaviour change on ordinary hosts.
    EXPECT_EQ("example.com", GetBaseDomain("example.com"));
    EXPECT_EQ("example.com", GetBaseDomain("www.example.com"));
    EXPECT_EQ("example.com", GetBaseDomain("a.b.c.example.com"));
}

TEST_F(CookieIdentityTest, ALeadingDotIsNotALabel) {
    // A cookie domain commonly arrives as ".example.com". The dot must be stripped BEFORE
    // decomposition, or the first label is empty and the host is rejected as malformed.
    EXPECT_EQ("example.com", GetBaseDomain(".example.com"));
    EXPECT_EQ("evil.co.uk", GetBaseDomain(".evil.co.uk"));
    EXPECT_EQ("example.com", GetBaseDomain(".www.example.com"));
}

TEST_F(CookieIdentityTest, TenantsOfASharedHostAreDifferentParties) {
    // The IncludePrivate scope choice, stated as behaviour: github.io is a private-section
    // suffix, so two tenants must not resolve to the same party or one could be treated as
    // the owner of the other's cookies.
    EXPECT_EQ("a.github.io", GetBaseDomain("a.github.io"));
    EXPECT_NE(GetBaseDomain("a.github.io"), GetBaseDomain("b.github.io"));
}

TEST_F(CookieIdentityTest, AHostWithNoRegistrableDomainIsReturnedUnchanged) {
    // A bare public suffix, a single label and a host that is only a TLD have no registrable
    // domain. Returning the input is the existing contract and the in-module self-test relies
    // on it; returning empty would make every such cookie group together.
    EXPECT_EQ("co.uk", GetBaseDomain("co.uk"));
    EXPECT_EQ("localhost", GetBaseDomain("localhost"));
    EXPECT_FALSE(GetBaseDomain("com").empty());
}

// ============================================================================================
// IsThirdPartyCookie
// ============================================================================================

TEST_F(CookieIdentityTest, ACookieFromAnotherSiteUnderTheSameSuffixIsThirdParty) {
    // THE DEFECT THIS FIX EXISTS FOR. Both sides previously reduced to co.uk, compared equal,
    // and the function returned false - a third-party cookie reported as first-party.
    EXPECT_TRUE(IsThirdPartyCookie("evil.co.uk", "good.co.uk"));
    EXPECT_TRUE(IsThirdPartyCookie("tracker.evil.co.uk", "www.good.co.uk"));
    EXPECT_TRUE(IsThirdPartyCookie(".ads.evil.com.au", "shop.good.com.au"));
}

TEST_F(CookieIdentityTest, ASubdomainOfThePageIsNotThirdParty) {
    // The opposite direction: a first-party cookie must not become third-party, or a fix aimed
    // at under-blocking would turn into over-blocking.
    EXPECT_FALSE(IsThirdPartyCookie(".tracker.example.com", "www.example.com"));
    EXPECT_FALSE(IsThirdPartyCookie("example.com", "example.com"));
    EXPECT_FALSE(IsThirdPartyCookie(".evil.co.uk", "www.evil.co.uk"));
}

TEST_F(CookieIdentityTest, AnUnrelatedDomainIsThirdParty) {
    EXPECT_TRUE(IsThirdPartyCookie("doubleclick.net", "example.com"));
    EXPECT_TRUE(IsThirdPartyCookie(".google-analytics.com", "www.example.com"));
}

TEST_F(CookieIdentityTest, TenantsOfASharedHostAreThirdPartyToEachOther) {
    // Same scope argument as above, expressed as the decision it drives: one tenant reading
    // another's cookies is exactly what this must prevent.
    EXPECT_TRUE(IsThirdPartyCookie("a.github.io", "b.github.io"));
}

}  // namespace
}  // namespace ShadowStrike::Privacy::Test
