/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AdBlocker_Tests.cpp
 * @brief Whitelist party identity, reached through the only public door that exposes it.
 *
 * AdBlocker's GetBaseDomain lives in an anonymous namespace, so it cannot be called from a test.
 * IsWhitelisted is the public behaviour that depends on it: the whitelist is consulted for the
 * exact domain first and then for its base domain, so that whitelisting example.com also covers
 * its subdomains. Every case below is chosen so the previous implementation and the corrected one
 * disagree, or so a direction that must NOT change is pinned.
 *
 * The rule being replaced returned everything after the FIRST dot - the host minus one label -
 * so its answer depended on how deep the host was. Whitelisting example.com left
 * cdn.a.example.com unmatched, because the computed base was a.example.com.
 *
 * NOTE ON STATE. AdBlocker is a singleton and the whitelist is process-wide, so each case removes
 * what it adds. Initialize() is deliberately NOT called: the whitelist path has no initialization
 * gate, and initialising would load filter lists and start threads that these cases do not need.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/Utils/DomainUtils.hpp"
#include "Products/Community/PhantomHome/WebProtection/AdBlocker.hpp"

#include <filesystem>
#include <string>
#include <system_error>

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

/**
 * @brief Adds a whitelist entry and removes it again, whatever the case does.
 *
 * The whitelist outlives any single test, so leaving an entry behind would change the meaning of
 * every later case that queries a domain beneath it.
 */
class ScopedWhitelistEntry {
public:
    explicit ScopedWhitelistEntry(std::string domain) : m_domain(std::move(domain)) {
        m_added = AdBlocker::Instance().AddToWhitelist(m_domain);
    }
    ~ScopedWhitelistEntry() {
        if (m_added) {
            (void)AdBlocker::Instance().RemoveFromWhitelist(m_domain);
        }
    }
    ScopedWhitelistEntry(const ScopedWhitelistEntry&) = delete;
    ScopedWhitelistEntry& operator=(const ScopedWhitelistEntry&) = delete;
    [[nodiscard]] bool added() const noexcept { return m_added; }

private:
    std::string m_domain;
    bool m_added = false;
};

class AdBlockerWhitelistIdentityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(LoadPublicSuffixListForTests())
            << "the vendored public suffix list could not be located; these cases would "
               "otherwise exercise the fallback and prove nothing about the fix";
    }
};

// ============================================================================================
// Cases where the previous rule and the corrected one disagree
// ============================================================================================

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistedDomainCoversADeepSubdomain) {
    // The defect: the previous rule computed a.example.com for cdn.a.example.com, which is not
    // the entry the user created, so ads were blocked on a site the user chose to allow.
    const ScopedWhitelistEntry entry("example.com");
    ASSERT_TRUE(entry.added());

    auto& blocker = AdBlocker::Instance();
    EXPECT_TRUE(blocker.IsWhitelisted("example.com"));
    EXPECT_TRUE(blocker.IsWhitelisted("www.example.com"));
    EXPECT_TRUE(blocker.IsWhitelisted("cdn.a.example.com"));
    EXPECT_TRUE(blocker.IsWhitelisted("a.b.c.example.com"));
}

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistedDomainUnderAMultiLabelSuffixCoversItsSubdomains) {
    const ScopedWhitelistEntry entry("evil.co.uk");
    ASSERT_TRUE(entry.added());

    auto& blocker = AdBlocker::Instance();
    EXPECT_TRUE(blocker.IsWhitelisted("evil.co.uk"));
    EXPECT_TRUE(blocker.IsWhitelisted("www.evil.co.uk"));
    EXPECT_TRUE(blocker.IsWhitelisted("a.b.evil.co.uk"));
}

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistedTenantOfASharedHostCoversItsOwnSubdomains) {
    // The IncludePrivate scope choice as behaviour. github.io is a private-section suffix, so the
    // tenant a.github.io is a party in its own right.
    const ScopedWhitelistEntry entry("a.github.io");
    ASSERT_TRUE(entry.added());

    auto& blocker = AdBlocker::Instance();
    EXPECT_TRUE(blocker.IsWhitelisted("a.github.io"));
    EXPECT_TRUE(blocker.IsWhitelisted("sub.a.github.io"));
}

// ============================================================================================
// Directions that must NOT change - a fix for under-matching must not become over-matching
// ============================================================================================

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistEntryDoesNotCoverAnotherTenantOfTheSameHost) {
    // If this ever passed, one tenant of a shared host could disable ad blocking for another.
    const ScopedWhitelistEntry entry("a.github.io");
    ASSERT_TRUE(entry.added());

    EXPECT_FALSE(AdBlocker::Instance().IsWhitelisted("b.github.io"));
}

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistEntryDoesNotCoverASuffixLookalike) {
    // A domain that merely CONTAINS the whitelisted name must not match. attacker.net owns
    // example.com.attacker.net, and the whitelist entry belongs to someone else entirely.
    const ScopedWhitelistEntry entry("example.com");
    ASSERT_TRUE(entry.added());

    auto& blocker = AdBlocker::Instance();
    EXPECT_FALSE(blocker.IsWhitelisted("example.com.attacker.net"));
    EXPECT_FALSE(blocker.IsWhitelisted("notexample.com"));
    EXPECT_FALSE(blocker.IsWhitelisted("example.company"));
}

TEST_F(AdBlockerWhitelistIdentityTest, AWhitelistEntryDoesNotCoverAnUnrelatedSiteUnderTheSameSuffix) {
    // The public suffix must never become the matching key: if it did, whitelisting one UK site
    // would whitelist every UK site.
    const ScopedWhitelistEntry entry("evil.co.uk");
    ASSERT_TRUE(entry.added());

    auto& blocker = AdBlocker::Instance();
    EXPECT_FALSE(blocker.IsWhitelisted("good.co.uk"));
    EXPECT_FALSE(blocker.IsWhitelisted("www.good.co.uk"));
}

TEST_F(AdBlockerWhitelistIdentityTest, AnEmptyWhitelistMatchesNothing) {
    // Anti-vacuity for the cases above: they would all read as passing if IsWhitelisted returned
    // true unconditionally, so prove it returns false when nothing is whitelisted.
    auto& blocker = AdBlocker::Instance();
    EXPECT_FALSE(blocker.IsWhitelisted("never-whitelisted-by-any-test.example"));
    EXPECT_FALSE(blocker.IsWhitelisted("a.b.never-whitelisted-by-any-test.example"));
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
