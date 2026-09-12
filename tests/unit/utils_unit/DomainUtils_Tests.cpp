/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DomainUtils_Tests.cpp
 * @brief Public Suffix List decomposition, against the list's canonical cases.
 *
 * The vectors below are the checks published with the Public Suffix List, plus the two this
 * codebase specifically needs: the ICANN-versus-PRIVATE scope distinction, and the subdomain
 * a DNS-tunnel or DGA heuristic must measure.
 *
 * The naive last-dot split these replace produced "co.uk" as the registrable domain of
 * "bbc.co.uk" and "a.b.good" as the subdomain of "a.b.good.co.uk". Both are asserted against
 * here so a regression to that behaviour fails rather than merely changing a score.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/Utils/DomainUtils.hpp"

#include <filesystem>
#include <string>

namespace {

using ShadowStrike::Utils::Domain::DomainParts;
using ShadowStrike::Utils::Domain::PublicSuffixList;
using ShadowStrike::Utils::Domain::SuffixScope;
using ShadowStrike::Utils::Domain::SuffixSection;

/// Locates the vendored list without assuming the working directory. Walks upward from the
/// current path looking for content/psl, which is where the file is vendored, and falls back
/// to the accessor the product uses.
std::wstring LocateList() {
    std::error_code ec;
    std::filesystem::path here = std::filesystem::current_path(ec);
    for (int depth = 0; depth < 8 && !here.empty(); ++depth) {
        const std::filesystem::path candidate =
            here / L"content" / L"psl" / L"public_suffix_list.dat";
        if (std::filesystem::exists(candidate, ec)) {
            return candidate.wstring();
        }
        if (!here.has_parent_path() || here.parent_path() == here) {
            break;
        }
        here = here.parent_path();
    }
    return {};
}

class DomainUtilsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto& psl = PublicSuffixList::Instance();
        if (!psl.IsLoaded()) {
            const std::wstring path = LocateList();
            if (!path.empty()) {
                (void)psl.LoadFromFile(path);
            } else {
                (void)psl.EnsureLoaded();
            }
        }
    }

    static PublicSuffixList& Psl() { return PublicSuffixList::Instance(); }

    static DomainParts Parse(const char* host,
                             SuffixScope scope = SuffixScope::IncludePrivate) {
        return Psl().Decompose(host, scope);
    }

    static std::string Registrable(const char* host,
                                   SuffixScope scope = SuffixScope::IncludePrivate) {
        return Parse(host, scope).registrableDomain;
    }
};

// ---------------------------------------------------------------------------------------
// The list itself
// ---------------------------------------------------------------------------------------

TEST_F(DomainUtilsTest, ListLoadsAndSeparatesItsSections) {
    ASSERT_TRUE(Psl().IsLoaded())
        << "the vendored Public Suffix List could not be loaded; without it no caller can "
           "determine a registrable domain";
    // Both sections must be present. A list parsed with only one of them cannot answer the
    // trust question that SuffixScope exists to ask.
    EXPECT_GT(Psl().RuleCount(), 5000u);
    EXPECT_GT(Psl().IcannRuleCount(), 1000u);
    EXPECT_LT(Psl().IcannRuleCount(), Psl().RuleCount())
        << "no PRIVATE-section rules were loaded, so IncludePrivate and IcannOnly would "
           "return identical answers and the distinction would be silently absent";
    EXPECT_FALSE(Psl().Version().empty())
        << "the list version is unknown, so a field log cannot state which revision "
           "produced a verdict";
}

// ---------------------------------------------------------------------------------------
// Malformed and non-domain input must not produce a fabricated answer
// ---------------------------------------------------------------------------------------

TEST_F(DomainUtilsTest, UnusableInputIsReportedRatherThanGuessed) {
    EXPECT_FALSE(Parse("").valid);
    EXPECT_FALSE(Parse(".").valid);
    EXPECT_FALSE(Parse(".com").valid)          << "a leading empty label is malformed";
    EXPECT_FALSE(Parse("a..b").valid)          << "an empty interior label is malformed";
    EXPECT_FALSE(Parse("example").valid)       << "a single label has no registrable domain";
    EXPECT_FALSE(Parse("192.168.1.1").valid)   << "an IPv4 literal has no public suffix";
    EXPECT_FALSE(Parse("::1").valid)           << "an IPv6 literal has no public suffix";
}

TEST_F(DomainUtilsTest, HostIsLoweredAndTheRootDotIsNotALabel) {
    EXPECT_EQ("bbc.co.uk", Registrable("BBC.CO.UK"));
    EXPECT_EQ("bbc.co.uk", Registrable("bbc.co.uk."));
    EXPECT_EQ("bbc.co.uk", Registrable("BbC.Co.Uk."));
}

// ---------------------------------------------------------------------------------------
// Canonical cases from the list's own checks
// ---------------------------------------------------------------------------------------

TEST_F(DomainUtilsTest, APublicSuffixHasNoRegistrableDomain) {
    // These are answers, not failures: "co.uk" is not a site, so nobody owns it.
    for (const char* suffix : {"com", "biz", "co.uk", "uk.com"}) {
        const DomainParts parts = Parse(suffix);
        EXPECT_TRUE(parts.registrableDomain.empty())
            << suffix << " was given a registrable domain of '"
            << parts.registrableDomain << "'";
    }
}

TEST_F(DomainUtilsTest, RegistrableDomainIsTheSuffixPlusExactlyOneLabel) {
    EXPECT_EQ("example.com",   Registrable("example.com"));
    EXPECT_EQ("example.com",   Registrable("b.example.com"));
    EXPECT_EQ("example.com",   Registrable("a.b.example.com"));
    EXPECT_EQ("domain.biz",    Registrable("domain.biz"));
    EXPECT_EQ("domain.biz",    Registrable("a.b.domain.biz"));
    EXPECT_EQ("bbc.co.uk",     Registrable("bbc.co.uk"));
    EXPECT_EQ("bbc.co.uk",     Registrable("a.bbc.co.uk"));
    EXPECT_EQ("test.ac",       Registrable("test.ac"));
}

TEST_F(DomainUtilsTest, AnUnlistedTldFallsBackToItsLastLabelAndSaysSo) {
    const DomainParts parts = Parse("example.example");
    EXPECT_TRUE(parts.valid);
    EXPECT_EQ("example.example", parts.registrableDomain);
    EXPECT_FALSE(parts.matchedExplicitRule)
        << "an unknown TLD must be distinguishable from a listed one, or a caller cannot "
           "tell a real answer from the implicit '*' fallback";
    // A listed one, for contrast.
    EXPECT_TRUE(Parse("example.com").matchedExplicitRule);
}

TEST_F(DomainUtilsTest, WildcardRulesMatchExactlyOneLabel) {
    // "*.ck" makes any single label under .ck a public suffix.
    EXPECT_TRUE(Parse("b.ck").registrableDomain.empty())
        << "b.ck is itself a public suffix under the *.ck rule";
    EXPECT_EQ("c.b.ck", Registrable("c.b.ck"));
    EXPECT_EQ("c.b.ck", Registrable("d.c.b.ck"));
}

TEST_F(DomainUtilsTest, ExceptionRulesOverrideTheWildcardTheySitUnder) {
    // "!www.ck" carves www.ck back out of "*.ck", so www.ck IS registrable.
    EXPECT_EQ("www.ck", Registrable("www.ck"));
    EXPECT_EQ("www.ck", Registrable("a.www.ck"));
}

// ---------------------------------------------------------------------------------------
// The distinction this codebase needs
// ---------------------------------------------------------------------------------------

TEST_F(DomainUtilsTest, ScopeDecidesWhetherASharedHostIsASuffix) {
    // blogspot.com is a PRIVATE-section rule. The two scopes answer different questions and
    // must not be interchangeable: for trust, one tenant must not speak for another; for
    // attribution, both belong to blogspot.com.
    EXPECT_EQ("evil.blogspot.com",
              Registrable("evil.blogspot.com", SuffixScope::IncludePrivate));
    EXPECT_EQ("blogspot.com",
              Registrable("evil.blogspot.com", SuffixScope::IcannOnly));

    EXPECT_NE(Registrable("a.github.io", SuffixScope::IncludePrivate),
              Registrable("b.github.io", SuffixScope::IncludePrivate))
        << "two tenants of a shared host resolved to the same registrable domain, so "
           "trusting one would trust the other";
    EXPECT_EQ(Registrable("a.github.io", SuffixScope::IcannOnly),
              Registrable("b.github.io", SuffixScope::IcannOnly));

    EXPECT_EQ(SuffixSection::Private,
              Parse("evil.blogspot.com", SuffixScope::IncludePrivate).section);
    EXPECT_EQ(SuffixSection::Icann,
              Parse("bbc.co.uk", SuffixScope::IncludePrivate).section);
}

TEST_F(DomainUtilsTest, SubdomainExcludesTheRegistrableDomain) {
    // This is the string a DNS-tunnel or DGA heuristic must measure. A last-dot split
    // yielded "a.b.good" here, inflating both the label count and the entropy for every
    // legitimate host under a multi-label suffix.
    const DomainParts parts = Parse("a.b.good.co.uk");
    ASSERT_TRUE(parts.valid);
    EXPECT_EQ("co.uk",      parts.publicSuffix);
    EXPECT_EQ("good.co.uk", parts.registrableDomain);
    EXPECT_EQ("a.b",        parts.subdomain);
    EXPECT_EQ(2u,           parts.subdomainLabelCount);

    const DomainParts flat = Parse("good.co.uk");
    EXPECT_TRUE(flat.subdomain.empty());
    EXPECT_EQ(0u, flat.subdomainLabelCount);

    const DomainParts deep = Parse("x.y.z.example.com");
    EXPECT_EQ("x.y.z", deep.subdomain);
    EXPECT_EQ(3u,      deep.subdomainLabelCount);
}

TEST_F(DomainUtilsTest, LongestMatchWinsSoAThreeLabelSuffixBeatsATwoLabelOne) {
    // pvt.k12.ma.us is a listed suffix; the longest matching rule must win, otherwise the
    // registrable domain would come out as a suffix fragment.
    const DomainParts parts = Parse("sub.pvt.k12.ma.us");
    ASSERT_TRUE(parts.valid);
    EXPECT_EQ("sub.pvt.k12.ma.us", parts.registrableDomain)
        << "the longest matching rule did not win; public suffix came out as '"
        << parts.publicSuffix << "'";
}

TEST_F(DomainUtilsTest, AnOverlongHostIsRejectedRatherThanTruncated) {
    std::string host(300, 'a');
    host += ".com";
    EXPECT_FALSE(Parse(host.c_str()).valid)
        << "a host beyond the DNS length limit was decomposed instead of rejected";
}

}  // namespace
