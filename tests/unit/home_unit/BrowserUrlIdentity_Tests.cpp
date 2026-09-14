/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file BrowserUrlIdentity_Tests.cpp
 * @brief The host a blocklist decision is keyed on, and the normalisation that precedes it.
 *
 * ExtractDomain answers "which host is this", and blocklist and allowlist membership are decided on that
 * answer. The failure that matters is a host that resolves differently from how the browser resolves it,
 * because a blocked domain reached under a spelling the extractor does not recognise is a bypass.
 *
 * This module does NOT carry the last-dot defect corrected in six other sites: GetDomainFromUrl delegates
 * to NetworkUtils::ParseUrl and takes components.host, with an explicit branch preserving IPv6 literals
 * rather than splitting them on a colon. So the cases here pin correct behaviour rather than proving a
 * fix, and the equivalence classes are what make that worth doing - case, trailing dot, port, userinfo
 * and percent-encoding must all collapse to one key, or the allowlist is keyed on presentation.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/BrowserProtection.hpp"

#include <string>

namespace ShadowStrike::WebBrowser::Test {
namespace {

/// ExtractDomain and NormalizeURL are free functions in the utility block after the class, alongside
/// IsHTTPS, so no instance is needed and nothing has to be initialised - which also means these cases
/// cannot be affected by module state left behind by another suite.
class BrowserUrlIdentityTest : public ::testing::Test {
protected:
    static std::string Domain(const std::string& url) { return ExtractDomain(url); }
};

TEST_F(BrowserUrlIdentityTest, TheHostIsExtractedFromAnOrdinaryUrl) {
    EXPECT_EQ("example.com", Domain("https://example.com/path?q=1#frag"));
    EXPECT_EQ("example.com", Domain("http://example.com"));
    EXPECT_EQ("sub.example.co.uk", Domain("https://sub.example.co.uk/a/b"));
}

TEST_F(BrowserUrlIdentityTest, TheHostIsNotTruncatedToTwoLabels) {
    // The defect corrected in six other sites was reducing a host to its last two labels. A blocklist
    // keyed on a truncated host blocks every sibling subdomain, and an allowlist keyed on one exempts
    // them - so this asserts the FULL host survives.
    EXPECT_EQ("a.b.c.example.com", Domain("https://a.b.c.example.com/"))
        << "the host was shortened, so every sibling subdomain shares its blocklist decision";
    EXPECT_EQ("tracker.doubleclick.net", Domain("https://tracker.doubleclick.net/pixel"));
}

TEST_F(BrowserUrlIdentityTest, PresentationDifferencesCollapseToOneKey) {
    // Each of these is the same host to a browser. If any produced a different key, a blocklist entry
    // would apply to one spelling and not another, which is a bypass rather than an inconsistency.
    const std::string expected = "example.com";
    EXPECT_EQ(expected, Domain("https://EXAMPLE.COM/")) << "upper case";
    EXPECT_EQ(expected, Domain("https://Example.Com/")) << "mixed case";
    EXPECT_EQ(expected, Domain("https://example.com:8443/")) << "explicit port";
    EXPECT_EQ(expected, Domain("https://user:secret@example.com/")) << "userinfo";
    EXPECT_EQ(expected, Domain("https://example.com./")) << "fully qualified trailing dot";
}

TEST_F(BrowserUrlIdentityTest, ABareHostWithNoSchemeIsStillAHost) {
    // Blocklist entries are written as bare domains, so this path is how a user's own entry is keyed.
    EXPECT_EQ("example.com", Domain("example.com"));
    EXPECT_EQ("example.com", Domain("EXAMPLE.COM"));
}

TEST_F(BrowserUrlIdentityTest, AnIPv6LiteralIsNotSplitOnItsColons) {
    // A colon-splitting host parser destroys an IPv6 literal. The source has an explicit branch for this,
    // and this case is what keeps it.
    const std::string domain = Domain("https://[2001:db8::1]/path");
    EXPECT_NE("", domain) << "an IPv6 literal produced no host at all";
    EXPECT_NE("2001", domain) << "the literal was cut at its first colon";
}

TEST_F(BrowserUrlIdentityTest, AnIPv4LiteralIsReturnedIntact) {
    EXPECT_EQ("192.168.1.1", Domain("http://192.168.1.1/admin"));
    EXPECT_EQ("192.168.1.1", Domain("http://192.168.1.1:8080/admin"));
}

TEST_F(BrowserUrlIdentityTest, GarbageYieldsNoHostRatherThanAWrongOne) {
    // Returning a partial or invented host would be worse than returning nothing, because a wrong key
    // silently matches the wrong blocklist entry.
    EXPECT_EQ("", Domain(""));
    EXPECT_EQ("", Domain("https://"));
    EXPECT_EQ("", Domain("/just/a/path"));
    EXPECT_EQ("", Domain("?query=only"));
}

TEST_F(BrowserUrlIdentityTest, NormalisationLowercasesTheHostButNotThePath) {
    // A path is case-sensitive on most servers, so lowercasing it would change which resource is named.
    const std::string normalized =
        NormalizeURL("HTTPS://EXAMPLE.COM/CaseSensitive/Path");
    EXPECT_NE(std::string::npos, normalized.find("example.com"))
        << "the host was not lowercased";
    EXPECT_NE(std::string::npos, normalized.find("CaseSensitive"))
        << "the path was lowercased, which changes which resource the URL names";
}

TEST_F(BrowserUrlIdentityTest, NormalisationLeavesAnEmptyUrlEmpty) {
    EXPECT_EQ("", NormalizeURL(""));
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
