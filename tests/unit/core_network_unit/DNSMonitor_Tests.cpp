/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Network\DNSMonitor deterministic contracts.
 *
 * Focus:
 *   - config/statistics factory behavior and helper name functions
 *   - DGA, filtering, callback, cache, and diagnostics surfaces that stay in-process
 *   - validation helpers that do not require live DNS capture
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>
#include <limits>
#include <regex>
#include <string>

#include "../../../src/PhantomCore/Core/Network/DNSMonitor.hpp"
#include "../../../src/PhantomCore/Utils/DomainUtils.hpp"

#include <filesystem>
#include "CoreNetwork_TestUtils.hpp"

namespace ShadowStrike::Core::Network::Test {

class DNSMonitorTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_DNSMonitorTests_"};
    DNSMonitor& monitor = DNSMonitor::Instance();

    void SetUp() override {
        monitor.Shutdown();

        auto config = DNSMonitorConfig::CreatePerformance();
        config.useETW = false;
        config.useWFP = false;
        config.useHooks = false;
        ASSERT_TRUE(monitor.Initialize(config));
        monitor.ResetStatistics();
        monitor.FlushCache();
    }

    void TearDown() override {
        monitor.Shutdown();
    }
};

TEST_F(DNSMonitorTest, SingletonAndVersionContractsRemainStable) {
    EXPECT_EQ(&DNSMonitor::Instance(), &DNSMonitor::Instance());
    EXPECT_TRUE(DNSMonitor::HasInstance());
    EXPECT_TRUE(std::regex_match(DNSMonitor::GetVersionString(), std::regex(R"(\d+\.\d+\.\d+)")));
}

TEST_F(DNSMonitorTest, ConfigFactoriesStatisticsAndRuleHelpersPreserveExpectedDefaults) {
    const auto defaults = DNSMonitorConfig::CreateDefault();
    const auto highSecurity = DNSMonitorConfig::CreateHighSecurity();
    const auto performance = DNSMonitorConfig::CreatePerformance();
    const auto forensic = DNSMonitorConfig::CreateForensic();

    EXPECT_TRUE(defaults.captureQueries);
    EXPECT_FALSE(defaults.validateResponses);
    EXPECT_TRUE(defaults.enableCaching);
    EXPECT_FALSE(defaults.useWFP);
    ASSERT_GE(defaults.trustedResolvers.size(), 2u);

    EXPECT_TRUE(highSecurity.validateResponses);
    EXPECT_TRUE(highSecurity.validateAllResponses);
    EXPECT_TRUE(highSecurity.useWFP);
    EXPECT_FALSE(highSecurity.logBlockedOnly);

    EXPECT_FALSE(performance.detectTunneling);
    EXPECT_FALSE(performance.checkReputation);
    EXPECT_TRUE(performance.enableSampling);
    EXPECT_EQ(performance.sampleRate, 10u);

    EXPECT_TRUE(forensic.logAllQueries);
    EXPECT_TRUE(forensic.logResponses);
    EXPECT_EQ(forensic.maxQueriesPerSecond, std::numeric_limits<uint32_t>::max());

    DNSStatistics stats;
    stats.totalQueries.store(11, std::memory_order_relaxed);
    stats.domainsBlocked.store(2, std::memory_order_relaxed);
    stats.cacheHits.store(3, std::memory_order_relaxed);
    stats.errorCount.store(4, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.totalQueries.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.domainsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheHits.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.errorCount.load(std::memory_order_relaxed), 0u);

    DNSFilterRule exactRule;
    exactRule.domainPattern = "Example.COM";
    EXPECT_TRUE(exactRule.Matches("example.com"));

    DNSFilterRule wildcardRule;
    wildcardRule.domainPattern = "*.shadowstrike.dev";
    EXPECT_TRUE(wildcardRule.Matches("api.shadowstrike.dev"));
    EXPECT_FALSE(wildcardRule.Matches("shadowstrike.dev"));

    DNSFilterRule regexRule;
    regexRule.isRegex = true;
    regexRule.domainPattern = R"(.*\.corp\.local)";
    EXPECT_TRUE(regexRule.Matches("dc01.corp.local"));
    EXPECT_FALSE(regexRule.Matches("corp.local"));

    DNSFilterRule invalidRegexRule;
    invalidRegexRule.isRegex = true;
    invalidRegexRule.domainPattern = "(";
    EXPECT_FALSE(invalidRegexRule.Matches("corp.local"));
}

TEST_F(DNSMonitorTest, UtilityHelpersAndEnumNamesStayStableForPolicyConsumers) {
    EXPECT_DOUBLE_EQ(DNSMonitor::CalculateEntropy(""), 0.0);
    EXPECT_LT(DNSMonitor::CalculateEntropy("aaaaaaaa"), DNSMonitor::CalculateEntropy("a9Z3xQ2p"));

    EXPECT_EQ(DNSMonitor::GetBaseDomain("a.b.example.com"), "example.com");
    EXPECT_EQ(DNSMonitor::GetBaseDomain("example.com"), "example.com");
    EXPECT_EQ(DNSMonitor::GetBaseDomain("localhost"), "localhost");

    EXPECT_TRUE(DNSMonitor::IsValidDomain("good-domain_01.example"));
    EXPECT_FALSE(DNSMonitor::IsValidDomain(".leading-dot.example"));
    EXPECT_FALSE(DNSMonitor::IsValidDomain("trailing-dot.example."));
    EXPECT_FALSE(DNSMonitor::IsValidDomain("bad domain.example"));
    EXPECT_FALSE(DNSMonitor::IsValidDomain(std::string(DNSConstants::MAX_DOMAIN_LENGTH + 1, 'a')));

    EXPECT_EQ(DNSMonitor::GetRecordTypeName(DNSRecordType::AAAA), "AAAA");
    EXPECT_EQ(GetResponseCodeName(DNSResponseCode::NXDOMAIN), "NXDOMAIN");
    EXPECT_EQ(GetProtocolName(DNSProtocol::DOH), "DOH");
    EXPECT_EQ(GetDomainCategoryName(DomainCategory::PHISHING), "Phishing");
    EXPECT_EQ(GetThreatTypeName(DNSThreatType::DGA_DOMAIN), "DGA");
    EXPECT_EQ(GetDGAFamilyName(DGAFamily::EMOTET), "Emotet");
    EXPECT_EQ(GetFilterActionName(DNSFilterAction::SINKHOLE), "Sinkhole");
    EXPECT_EQ(GetValidationResultName(ValidationResult::DNSSEC_FAIL), "DNSSECFail");
    EXPECT_EQ(GetProtocolName(static_cast<DNSProtocol>(255)), "UNKNOWN");
}

TEST_F(DNSMonitorTest, DgaFilteringCallbackAndCacheContractsRemainDeterministic) {
    const DGAAnalysis suspicious = monitor.AnalyzeDGA("qzxjv9kptd8r.com");
    EXPECT_TRUE(suspicious.isDGA);
    EXPECT_TRUE(monitor.IsDGA("qzxjv9kptd8r.com"));
    EXPECT_FALSE(monitor.IsDGA("microsoft.com"));

    const uint64_t queryCallbackId = monitor.RegisterQueryCallback([](const DNSQuery&) {});
    const uint64_t responseCallbackId = monitor.RegisterResponseCallback([](const DNSResponse&) {});
    const uint64_t eventCallbackId = monitor.RegisterEventCallback([](const DNSEvent&) {});
    const uint64_t dgaCallbackId = monitor.RegisterDGACallback([](const std::string&, const DGAAnalysis&) {});
    const uint64_t tunnelingCallbackId = monitor.RegisterTunnelingCallback(
        [](const std::string&, const TunnelingAnalysis&) {});
    const uint64_t poisoningCallbackId = monitor.RegisterPoisoningCallback(
        [](const std::string&, const std::string&, const std::string&) {});

    EXPECT_TRUE(queryCallbackId < responseCallbackId);
    EXPECT_TRUE(responseCallbackId < eventCallbackId);
    EXPECT_TRUE(eventCallbackId < dgaCallbackId);
    EXPECT_TRUE(dgaCallbackId < tunnelingCallbackId);
    EXPECT_TRUE(tunnelingCallbackId < poisoningCallbackId);
    EXPECT_TRUE(monitor.UnregisterCallback(dgaCallbackId));
    EXPECT_FALSE(monitor.UnregisterCallback(dgaCallbackId));

    EXPECT_TRUE(monitor.BlockDomain("evil.example", L"unit-test"));
    EXPECT_TRUE(monitor.IsBlocked("evil.example"));
    EXPECT_TRUE(monitor.UnblockDomain("evil.example"));
    EXPECT_FALSE(monitor.IsBlocked("evil.example"));

    EXPECT_TRUE(monitor.SinkholeDomain("sinkhole.example", "127.0.0.1"));
    EXPECT_TRUE(monitor.IsBlocked("sinkhole.example"));
    EXPECT_EQ(monitor.GetStatistics().domainsSinkholed.load(std::memory_order_relaxed), 1u);

    DNSCacheEntry entry;
    entry.domain = "cached.example";
    entry.recordType = DNSRecordType::A;
    entry.cachedAt = std::chrono::system_clock::now();
    entry.expiresAt = entry.cachedAt + std::chrono::minutes(5);
    entry.ttl = 300;
    monitor.AddCacheEntry(entry);

    ASSERT_TRUE(monitor.QueryCache("cached.example").has_value());
    EXPECT_EQ(monitor.GetCacheSize(), 1u);

    monitor.InvalidateCache("cached.example");
    EXPECT_FALSE(monitor.QueryCache("cached.example").has_value());

    monitor.AddCacheEntry(entry);
    monitor.FlushCache();
    EXPECT_EQ(monitor.GetCacheSize(), 0u);
    EXPECT_FALSE(monitor.QueryCache("cached.example").has_value());
    EXPECT_FALSE(monitor.CrossValidate("", {"1.1.1.1"}));
    EXPECT_FALSE(monitor.CrossValidate("example.com", {}));
}

TEST_F(DNSMonitorTest, ExpiredCacheAndDiagnosticsFailurePathsRemainSafe) {
    DNSCacheEntry expiredEntry;
    expiredEntry.domain = "expired.example";
    expiredEntry.recordType = DNSRecordType::A;
    expiredEntry.cachedAt = std::chrono::system_clock::now() - std::chrono::minutes(10);
    expiredEntry.expiresAt = std::chrono::system_clock::now() - std::chrono::minutes(5);
    expiredEntry.ttl = 60;
    monitor.AddCacheEntry(expiredEntry);

    EXPECT_FALSE(monitor.QueryCache("expired.example", DNSRecordType::A).has_value());
    EXPECT_EQ(monitor.GetStatistics().cacheMisses.load(std::memory_order_relaxed), 1u);

    // WAS: EXPECT_TRUE(monitor.UnblockDomain("missing.example")).
    // UnblockDomain() now reports whether it actually changed policy. DNSMonitor.cpp
    // erases every filter rule whose normalized pattern matches AND whose action is
    // BLOCK, then returns "did I erase at least one". A domain that was never blocked
    // erases nothing, so the answer is false - the same false the syntactic-reject
    // path returns, both meaning "no block rule was removed".
    // This matters to callers, not just to bookkeeping: an unblock that answers true
    // unconditionally cannot distinguish a real policy change from a no-op. An
    // operator (or the management API) who unblocks a mistyped domain gets "success"
    // back while the actual block stays in force, and the same acknowledgement is
    // returned whether or not the block is gone.
    // If someone reverts this to EXPECT_TRUE: it fails against the current product,
    // and honouring it would mean going back to a write API that reports success for
    // work it did not do.
    EXPECT_FALSE(monitor.UnblockDomain("missing.example"));

    // The positive counterpart is asserted in
    // DgaFilteringCallbackAndCacheContractsRemainDeterministic: block, then unblock
    // the same domain, which does remove a rule and does return true.

    monitor.Shutdown();
    EXPECT_FALSE(monitor.PerformDiagnostics());
    EXPECT_FALSE(monitor.ExportDiagnostics(L""));
}

TEST_F(DNSMonitorTest, DiagnosticsExportAndSelfTestSucceedWithoutLiveCapture) {
    EXPECT_TRUE(monitor.PerformDiagnostics());

    const auto diagnosticsPath = tempDir.File(L"dns-diagnostics.txt");
    ASSERT_TRUE(monitor.ExportDiagnostics(diagnosticsPath.wstring()));

    const std::string report = ReadTextFile(diagnosticsPath);
    EXPECT_NE(report.find("DNSMonitor"), std::string::npos);
    EXPECT_NE(report.find("Cache Size"), std::string::npos);

    EXPECT_TRUE(monitor.SelfTest());
}


// ===========================================================================================
// Multi-label public suffixes. The previous last-two-labels rule returned the SUFFIX as the
// base domain for these - co.uk for evil.co.uk - which made every UK domain the same party
// for any decision keyed on it. These cases need the public suffix list loaded, because
// EnsureLoaded() resolves beside the executable and the test binary is not there.
// ===========================================================================================

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

}  // namespace

TEST_F(DNSMonitorTest, GetBaseDomainHandlesMultiLabelSuffixes) {
    ASSERT_TRUE(LoadPublicSuffixListForTests())
        << "the vendored public suffix list did not load, so this test would exercise the "
           "fallback rule it exists to replace";

    // The defect: the suffix itself was returned as the base domain, so bbc.co.uk and
    // gov.co.uk resolved to the same string and any reputation or grouping decision keyed
    // on it treated them as one party.
    EXPECT_EQ("evil.co.uk", DNSMonitor::GetBaseDomain("evil.co.uk"));
    EXPECT_EQ("evil.co.uk", DNSMonitor::GetBaseDomain("a.b.evil.co.uk"));
    EXPECT_EQ("example.com.au", DNSMonitor::GetBaseDomain("www.example.com.au"));

    EXPECT_NE(DNSMonitor::GetBaseDomain("one.co.uk"),
              DNSMonitor::GetBaseDomain("two.co.uk"))
        << "two unrelated UK domains still resolve to the same base domain";

    // A tenant of a shared host is its own party under IncludePrivate, which is the scope
    // this helper uses because its purpose is reputation keying.
    EXPECT_NE(DNSMonitor::GetBaseDomain("a.github.io"),
              DNSMonitor::GetBaseDomain("b.github.io"));

    // The behaviour the existing expectations pin must be unchanged.
    EXPECT_EQ("example.com", DNSMonitor::GetBaseDomain("a.b.example.com"));
    EXPECT_EQ("example.com", DNSMonitor::GetBaseDomain("example.com"));
    EXPECT_EQ("localhost", DNSMonitor::GetBaseDomain("localhost"));
}

TEST_F(DNSMonitorTest, DgaAnalysisNoLongerSkipsMultiLabelSuffixDomains) {
    ASSERT_TRUE(LoadPublicSuffixListForTests());

    // Taking the label between the last two dots yielded "co" for a .co.uk host. At two
    // characters that is below DGA_MIN_LENGTH of 8, so analysis returned before computing a
    // single feature: every domain under a multi-label suffix was invisible to DGA scoring.
    // The generated label below is 15 characters and highly random, so a non-zero entropy
    // proves the features were actually computed.
    const auto ccTld = monitor.AnalyzeDGA("xj93kq2p9zv8q1w.co.uk");
    EXPECT_GT(ccTld.totalLength, 8u)
        << "the analysed string is still the suffix label rather than the registrant's";
    EXPECT_GT(ccTld.entropy, 0.0)
        << "DGA analysis returned before extracting features for a .co.uk host";

    // The same label under a single-label suffix was already analysed, and must still be.
    const auto com = monitor.AnalyzeDGA("xj93kq2p9zv8q1w.com");
    EXPECT_GT(com.entropy, 0.0);
    EXPECT_EQ(com.totalLength, ccTld.totalLength)
        << "the same registrable label measured different lengths under different suffixes";
}
}  // namespace ShadowStrike::Core::Network::Test
