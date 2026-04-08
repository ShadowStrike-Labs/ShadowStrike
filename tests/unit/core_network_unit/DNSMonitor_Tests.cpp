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

#include "../../../src/Shared_modules/Core/Network/DNSMonitor.hpp"
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
    const DGAAnalysis suspicious = monitor.AnalyzeDGA("xvkdf8s9df.com");
    EXPECT_TRUE(suspicious.isDGA);
    EXPECT_TRUE(monitor.IsDGA("xvkdf8s9df.com"));
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

    EXPECT_TRUE(monitor.UnblockDomain("missing.example"));

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

}  // namespace ShadowStrike::Core::Network::Test
