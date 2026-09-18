// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Browser miner domain matching tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file MinerDomainMatching_Tests.cpp
 * @brief Pins the domain matcher that this product gets RIGHT, so it stays right.
 *
 * BrowserMinerDetector's DomainMatches is the correct form of a check that is wrong elsewhere in this
 * codebase. It accepts an exact match, or a subdomain with a dot at the boundary, and nothing else:
 *
 *     if (candidate == rule) return true;
 *     return candidate.size() > rule.size() &&
 *            candidate.ends_with(rule) &&
 *            candidate[candidate.size() - rule.size() - 1] == '.';
 *
 * That boundary test is what SecureBrowser::IsBankingDomain lacks - it substring-matches a suffix list, so
 * it accepts secure.bank.phishing-site.com - and what TrackerBlocker's whitelist lacked before 27844634.
 * The same three rules were used to fix ScreenshotBlocker in c4abacf9 and OverlayProtection.
 *
 * So these cases exist to hold a reference implementation in place. The important ones are the NEGATIVE
 * ones: a rule must not match a domain that merely ends with its text.
 *
 * NormalizeDomainValue, reached through ExtractDomain, is pinned for the same reason. It strips a scheme,
 * a path, a query, a fragment and userinfo, and unwraps an IPv6 literal, in that order - and every entry
 * point in the module normalises through it before matching, which is what makes the matcher's guarantees
 * apply to real input rather than only to already-clean hostnames.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/CryptoMinersProtection/BrowserMinerDetector.hpp"

namespace {

using ShadowStrike::CryptoMiners::ExtractDomain;
using ShadowStrike::CryptoMiners::IsKnownMiningDomain;

// ============================================================================
// The matcher - exact, or a subdomain at a dot boundary
// ============================================================================

TEST(MinerDomainMatching, AKnownDomainMatchesExactly) {
    EXPECT_TRUE(IsKnownMiningDomain("coinhive.com"));
    EXPECT_TRUE(IsKnownMiningDomain("authedmine.com"));
    EXPECT_TRUE(IsKnownMiningDomain("cryptoloot.pro"));
    EXPECT_TRUE(IsKnownMiningDomain("webminepool.tk"));
}

TEST(MinerDomainMatching, ASubdomainOfAKnownDomainMatches) {
    // A miner moved to a subdomain is the same operator, so the rule must reach down.
    EXPECT_TRUE(IsKnownMiningDomain("ws.coinhive.com"));
    EXPECT_TRUE(IsKnownMiningDomain("cdn.authedmine.com"));
    EXPECT_TRUE(IsKnownMiningDomain("a.b.c.coinhive.com")) << "any depth";
}

TEST(MinerDomainMatching, ADomainThatMerelyEndsWithARuleDoesNotMatch) {
    // THE CASE THAT MATTERS. Each of these ends with the text of a rule and is a different registrable
    // domain, so each would be a false positive under a substring or bare suffix test. The dot boundary is
    // what refuses them.
    EXPECT_FALSE(IsKnownMiningDomain("notcoinhive.com"));
    EXPECT_FALSE(IsKnownMiningDomain("evil-coinhive.com"));
    EXPECT_FALSE(IsKnownMiningDomain("mycoinhive.com"));
    EXPECT_FALSE(IsKnownMiningDomain("xauthedmine.com"));
    EXPECT_FALSE(IsKnownMiningDomain("fakecryptoloot.pro"));
}

TEST(MinerDomainMatching, AKnownDomainUsedAsALabelElsewhereDoesNotMatch) {
    // The other direction: the rule's text appears, but not as the suffix.
    EXPECT_FALSE(IsKnownMiningDomain("coinhive.com.evil.net"))
        << "the registrable domain here is evil.net";
    EXPECT_FALSE(IsKnownMiningDomain("coinhive.com.co"));
    EXPECT_FALSE(IsKnownMiningDomain("mirror-of-coinhive.example.org"));
}

TEST(MinerDomainMatching, AnUnknownDomainDoesNotMatch) {
    // Non-vacuity: without this the positive cases would pass against a predicate that always answers true.
    EXPECT_FALSE(IsKnownMiningDomain("example.com"));
    EXPECT_FALSE(IsKnownMiningDomain("github.com"));
    EXPECT_FALSE(IsKnownMiningDomain(""));
    EXPECT_FALSE(IsKnownMiningDomain("."));
    EXPECT_FALSE(IsKnownMiningDomain("   "));
}

TEST(MinerDomainMatching, TheMatchIsMadeAgainstANormalisedHost) {
    // The matcher's guarantees only hold if the input has been reduced to a host first, which every entry
    // point in this module does. A full URL, a port, a trailing dot and mixed case all reach the same rule.
    EXPECT_TRUE(IsKnownMiningDomain("https://coinhive.com/lib/miner.js"));
    EXPECT_TRUE(IsKnownMiningDomain("http://ws.coinhive.com:8080/proxy"));
    EXPECT_TRUE(IsKnownMiningDomain("COINHIVE.COM")) << "case folded";
    EXPECT_TRUE(IsKnownMiningDomain("  coinhive.com  ")) << "surrounding whitespace trimmed";
}

// ============================================================================
// ExtractDomain - the normalisation the matcher depends on
// ============================================================================

TEST(MinerExtractDomain, AHostIsReturnedUnchanged) {
    EXPECT_EQ("example.com", ExtractDomain("example.com"));
    EXPECT_EQ("sub.example.com", ExtractDomain("sub.example.com"));
}

TEST(MinerExtractDomain, TheSchemePathQueryAndFragmentAreRemoved) {
    EXPECT_EQ("example.com", ExtractDomain("https://example.com"));
    EXPECT_EQ("example.com", ExtractDomain("http://example.com/deep/path"));
    EXPECT_EQ("example.com", ExtractDomain("https://example.com/?a=1&b=2"));
    EXPECT_EQ("example.com", ExtractDomain("https://example.com/page#section"));
    EXPECT_EQ("example.com", ExtractDomain("wss://example.com/socket"))
        << "a miner proxy commonly arrives over a websocket scheme";
}

TEST(MinerExtractDomain, UserInfoIsRemovedSoItCannotDisguiseTheHost) {
    // The classic disguise: everything before the last @ is userinfo, not the host. Reading it as the host
    // would let an attacker put a trusted name in front of their own.
    EXPECT_EQ("evil.com", ExtractDomain("http://coinhive.com@evil.com/"));
    EXPECT_EQ("evil.com", ExtractDomain("http://user:pass@evil.com/"));
}

TEST(MinerExtractDomain, AnIpv6LiteralIsUnwrappedFromItsBrackets) {
    EXPECT_EQ("::1", ExtractDomain("http://[::1]/path"));
    EXPECT_EQ("2001:db8::1", ExtractDomain("http://[2001:db8::1]:8080/"));
}

TEST(MinerExtractDomain, NonsenseYieldsNothingRatherThanSomethingWrong) {
    EXPECT_TRUE(ExtractDomain("").empty());
    EXPECT_TRUE(ExtractDomain("   ").empty());
    // Malformed UTF-8 is rejected by the wide conversion rather than passed through.
    EXPECT_TRUE(ExtractDomain(std::string("\x80\x80")).empty());
}

}  // namespace
