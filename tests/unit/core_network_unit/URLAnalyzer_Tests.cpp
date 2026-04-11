/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Network\URLAnalyzer deterministic contracts.
 *
 * Focus:
 *   - URL parsing, normalization, utility helpers, and stable name lookups
 *   - local whitelist/blacklist, cache, callback, and diagnostics behavior
 *   - configuration/statistics contracts without external reputation backends
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <regex>
#include <string>

#include "../../../src/PhantomCore/Core/Network/URLAnalyzer.hpp"
#include "CoreNetwork_TestUtils.hpp"

namespace ShadowStrike::Core::Network::Test {

class URLAnalyzerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_URLAnalyzerTests_"};
    URLAnalyzer& analyzer = URLAnalyzer::Instance();

    void SetUp() override {
        analyzer.Shutdown();

        auto config = URLAnalyzerConfig::CreateDefault();
        config.whitelistedDomains = {"bootstrap.safe"};
        config.blacklistedDomains = {"bootstrap.bad"};
        ASSERT_TRUE(analyzer.Initialize(config));
        analyzer.ClearCache();
        analyzer.ResetStatistics();
    }

    void TearDown() override {
        analyzer.Shutdown();
    }
};

TEST_F(URLAnalyzerTest, ParseUrlExtractsComponentsAndSecurityFlagsConsistently) {
    const ParsedURL parsed = URLAnalyzer::ParseURL(
        "https://User:Pass@Sub.Example.com:8443/path/index.html?x=1#frag");

    EXPECT_TRUE(parsed.isValid);
    EXPECT_EQ(parsed.scheme, URLScheme::HTTPS);
    EXPECT_EQ(parsed.schemeString, "https");
    EXPECT_TRUE(parsed.hasCredentials);
    EXPECT_EQ(parsed.username, "User");
    EXPECT_EQ(parsed.password, "Pass");
    EXPECT_EQ(parsed.host, "Sub.Example.com");
    EXPECT_EQ(parsed.hostNormalized, "sub.example.com");
    EXPECT_EQ(parsed.port, 8443);
    EXPECT_TRUE(parsed.hasPort);
    EXPECT_EQ(parsed.path, "/path/index.html");
    EXPECT_EQ(parsed.query, "x=1");
    EXPECT_EQ(parsed.fragment, "frag");
    EXPECT_EQ(parsed.tld, "com");
    EXPECT_EQ(parsed.registeredDomain, "example.com");
    EXPECT_EQ(parsed.subdomain, "sub");
    ASSERT_EQ(parsed.labels.size(), 3u);
    EXPECT_EQ(parsed.labels[0], "sub");
    EXPECT_EQ(parsed.normalizedUrl, "https://sub.example.com/path/index.html");
    EXPECT_FALSE(parsed.isLocalhost);
    EXPECT_FALSE(parsed.isPrivateIP);
}

TEST_F(URLAnalyzerTest, ParseUrlRejectsUnsafeInputAndHandlesSpecialSchemes) {
    const ParsedURL javaScriptUrl = URLAnalyzer::ParseURL("  javascript:alert(1)");
    EXPECT_TRUE(javaScriptUrl.isValid);
    EXPECT_EQ(javaScriptUrl.scheme, URLScheme::JAVASCRIPT);
    EXPECT_TRUE(javaScriptUrl.hasJavaScript);
    EXPECT_TRUE(javaScriptUrl.host.empty());

    const ParsedURL dataUrl = URLAnalyzer::ParseURL("data:text/plain;base64,QQ==");
    EXPECT_TRUE(dataUrl.isValid);
    EXPECT_EQ(dataUrl.scheme, URLScheme::DATA);
    EXPECT_TRUE(dataUrl.hasDataUri);

    const ParsedURL mailtoUrl = URLAnalyzer::ParseURL("mailto:alerts@shadowstrike.dev");
    EXPECT_TRUE(mailtoUrl.isValid);
    EXPECT_EQ(mailtoUrl.scheme, URLScheme::MAILTO);
    EXPECT_EQ(mailtoUrl.schemeString, "mailto");
    EXPECT_TRUE(mailtoUrl.host.empty());
    EXPECT_EQ(mailtoUrl.path, "alerts@shadowstrike.dev");

    std::string embeddedNull("https://exa");
    embeddedNull.push_back('\0');
    embeddedNull += "mple.com";
    const ParsedURL invalid = URLAnalyzer::ParseURL(embeddedNull);
    EXPECT_FALSE(invalid.isValid);
}

TEST_F(URLAnalyzerTest, ParseUrlHandlesBareHostsIpv6AndLengthBoundaries) {
    const ParsedURL bareHost = URLAnalyzer::ParseURL("Example.com");
    EXPECT_TRUE(bareHost.isValid);
    EXPECT_EQ(bareHost.scheme, URLScheme::HTTP);
    EXPECT_EQ(bareHost.hostNormalized, "example.com");
    EXPECT_EQ(bareHost.path, "/");
    EXPECT_EQ(bareHost.normalizedUrl, "http://example.com/");

    const ParsedURL ipv6 = URLAnalyzer::ParseURL("http://[2001:db8::1]:8443");
    EXPECT_TRUE(ipv6.isValid);
    EXPECT_TRUE(ipv6.isIPv6);
    EXPECT_TRUE(ipv6.isIP);
    EXPECT_EQ(ipv6.host, "2001:db8::1");
    EXPECT_EQ(ipv6.port, 8443);
    EXPECT_TRUE(ipv6.hasPort);

    const ParsedURL hostOnlyQuery = URLAnalyzer::ParseURL("https://example.com?x=1#frag");
    EXPECT_TRUE(hostOnlyQuery.isValid);
    EXPECT_EQ(hostOnlyQuery.hostNormalized, "example.com");
    EXPECT_EQ(hostOnlyQuery.path, "/");
    EXPECT_EQ(hostOnlyQuery.query, "x=1");
    EXPECT_EQ(hostOnlyQuery.fragment, "frag");
    EXPECT_EQ(URLAnalyzer::ExtractDomain("https://example.com?x=1#frag"), "example.com");
    EXPECT_EQ(URLAnalyzer::NormalizeURL("https://example.com?x=1#frag"), "https://example.com/");

    const ParsedURL doubleEncoded = URLAnalyzer::ParseURL("http://example.com/%252e%252e");
    EXPECT_TRUE(doubleEncoded.hasEncodedChars);
    EXPECT_TRUE(doubleEncoded.hasDoubleEncoding);

    const std::string overlongHost(254, 'a');
    const ParsedURL tooLong = URLAnalyzer::ParseURL("http://" + overlongHost + ".com");
    EXPECT_FALSE(tooLong.isValid);
}

TEST_F(URLAnalyzerTest, UtilityHelpersNameLookupsAndEntropyContractsStayStable) {
    EXPECT_EQ(URLAnalyzer::NormalizeURL("http://Example.com/Path"), "http://example.com/Path");
    EXPECT_EQ(URLAnalyzer::ExtractDomain("https://Sub.Example.com/login"), "sub.example.com");
    EXPECT_EQ(URLAnalyzer::DecodePunycode("xn--paypa1-l2c.com"), L"xn--paypa1-l2c.com");
    EXPECT_DOUBLE_EQ(URLAnalyzer::CalculateEntropy(""), 0.0);
    EXPECT_LT(URLAnalyzer::CalculateEntropy("aaaaaaaa"), URLAnalyzer::CalculateEntropy("a9Z3xQ2p"));

    EXPECT_EQ(URLAnalyzer::GetCategoryName(URLCategory::MALWARE_DIST), "Malware Distribution");
    EXPECT_EQ(URLAnalyzer::GetCategoryName(URLCategory::ADULT), "Adult Content");
    EXPECT_EQ(URLAnalyzer::GetThreatTypeName(ThreatType::C2_BEACON), "C2 Beacon");
    EXPECT_EQ(URLAnalyzer::GetThreatTypeName(static_cast<ThreatType>(255)), "Unknown Threat");
}

TEST_F(URLAnalyzerTest, ConfigFactoriesAndStatisticsResetReflectExpectedProfiles) {
    const auto defaults = URLAnalyzerConfig::CreateDefault();
    const auto highSecurity = URLAnalyzerConfig::CreateHighSecurity();
    const auto performance = URLAnalyzerConfig::CreatePerformance();
    const auto contentFiltering = URLAnalyzerConfig::CreateContentFiltering();

    EXPECT_TRUE(defaults.enableDGADetection);
    EXPECT_FALSE(defaults.enableContentFiltering);
    EXPECT_TRUE(defaults.enableCaching);
    EXPECT_FALSE(defaults.followRedirects);

    EXPECT_TRUE(highSecurity.enableContentFiltering);
    EXPECT_TRUE(highSecurity.followRedirects);
    EXPECT_LT(highSecurity.blockThreshold, defaults.blockThreshold);
    EXPECT_FALSE(highSecurity.logBlockedOnly);

    EXPECT_FALSE(performance.enableDGADetection);
    EXPECT_FALSE(performance.enablePhishingDetection);
    EXPECT_FALSE(performance.enableMLClassification);
    EXPECT_EQ(performance.maxRedirectDepth, 0u);

    ASSERT_GE(contentFiltering.blockedCategories.size(), 6u);
    EXPECT_TRUE(std::find(contentFiltering.blockedCategories.begin(),
                          contentFiltering.blockedCategories.end(),
                          URLCategory::GAMBLING) != contentFiltering.blockedCategories.end());

    URLAnalyzerStatistics stats;
    stats.totalURLsAnalyzed = 9;
    stats.urlsBlocked = 3;
    stats.categoryHits[static_cast<size_t>(URLCategory::ADULT)] = 4;
    stats.cacheSize = 2;
    stats.analysisErrors = 1;
    stats.Reset();

    EXPECT_EQ(stats.totalURLsAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.urlsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.categoryHits[static_cast<size_t>(URLCategory::ADULT)].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheSize.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.analysisErrors.load(std::memory_order_relaxed), 0u);
}

TEST_F(URLAnalyzerTest, LocalListsCacheCallbacksAndConfigUpdatesRemainConsistent) {
    EXPECT_TRUE(analyzer.IsInitialized());
    EXPECT_TRUE(analyzer.IsWhitelisted("bootstrap.safe"));
    EXPECT_TRUE(analyzer.IsBlacklisted("BOOTSTRAP.BAD"));

    EXPECT_TRUE(analyzer.AddToWhitelist("Trusted.Example"));
    EXPECT_TRUE(analyzer.IsWhitelisted("trusted.example"));
    EXPECT_TRUE(analyzer.RemoveFromWhitelist("TRUSTED.EXAMPLE"));
    EXPECT_FALSE(analyzer.IsWhitelisted("trusted.example"));

    EXPECT_TRUE(analyzer.AddToBlacklist("Blocked.Example", "UnitThreat"));
    EXPECT_TRUE(analyzer.IsBlacklisted("blocked.example"));
    EXPECT_TRUE(analyzer.RemoveFromBlacklist("BLOCKED.EXAMPLE"));
    EXPECT_FALSE(analyzer.IsBlacklisted("blocked.example"));

    const uint64_t analysisCallbackId = analyzer.RegisterAnalysisCallback(
        [](const std::string&, const URLVerdict&) {});
    const uint64_t threatCallbackId = analyzer.RegisterThreatCallback(
        [](const std::string&, ThreatType, const URLVerdict&) {});
    const uint64_t phishingCallbackId = analyzer.RegisterPhishingCallback(
        [](const std::string&, const BrandMatch&, const URLVerdict&) {});
    const uint64_t dgaCallbackId = analyzer.RegisterDGACallback(
        [](const std::string&, double, const std::string&) {});

    EXPECT_TRUE(analysisCallbackId < threatCallbackId);
    EXPECT_TRUE(threatCallbackId < phishingCallbackId);
    EXPECT_TRUE(phishingCallbackId < dgaCallbackId);
    EXPECT_TRUE(analyzer.UnregisterCallback(phishingCallbackId));
    EXPECT_FALSE(analyzer.UnregisterCallback(phishingCallbackId));

    EXPECT_FALSE(analyzer.QueryCache("https://cache.example").has_value());
    analyzer.InvalidateCache("https://cache.example");
    analyzer.ClearCache();
    EXPECT_EQ(analyzer.GetCacheSize(), 0u);

    auto updated = URLAnalyzerConfig::CreatePerformance();
    updated.whitelistedDomains = {"performance.safe"};
    ASSERT_TRUE(analyzer.UpdateConfig(updated));
    const auto current = analyzer.GetConfig();
    EXPECT_FALSE(current.enableDGADetection);
    EXPECT_EQ(current.whitelistedDomains.size(), 1u);
    EXPECT_EQ(current.whitelistedDomains.front(), "performance.safe");
}

TEST_F(URLAnalyzerTest, AnalysisGuardsCacheAndDomainVerdictsRemainConsistent) {
    const URLVerdict empty = analyzer.ScanURL("");
    EXPECT_EQ(empty.category, URLCategory::UNKNOWN);
    EXPECT_EQ(empty.recommendedAction, URLFilterAction::BLOCK);
    EXPECT_FALSE(empty.isBlocked);
    EXPECT_EQ(analyzer.GetStatistics().parseErrors.load(std::memory_order_relaxed), 1u);

    const DomainVerdict whitelisted = analyzer.AnalyzeDomain("bootstrap.safe");
    EXPECT_FALSE(whitelisted.isBlocked);
    EXPECT_EQ(whitelisted.category, URLCategory::SAFE);
    EXPECT_EQ(whitelisted.confidenceScore, 100);
    EXPECT_EQ(whitelisted.reputationScore, 100);

    analyzer.AddToBlacklist("dangerous.example", "UnitThreat");
    const URLVerdict first = analyzer.ScanURL("http://dangerous.example/login");
    EXPECT_TRUE(first.isBlocked);
    EXPECT_FALSE(first.fromCache);
    EXPECT_EQ(first.threatName, "UnitThreat");

    const URLVerdict second = analyzer.ScanURL("http://dangerous.example/login");
    EXPECT_TRUE(second.isBlocked);
    EXPECT_TRUE(second.fromCache);
    EXPECT_EQ(second.threatName, "UnitThreat");

    EXPECT_FALSE(analyzer.RemoveFromWhitelist("missing.example"));
    EXPECT_FALSE(analyzer.RemoveFromBlacklist("missing.example"));
}

TEST_F(URLAnalyzerTest, ScanAndDiagnosticsContractsStayHealthyWithoutExternalFeeds) {
    analyzer.AddToBlacklist("dangerous.example", "UnitThreat");

    const DomainVerdict domainVerdict = analyzer.AnalyzeDomain("dangerous.example");
    EXPECT_TRUE(domainVerdict.isBlocked);
    EXPECT_EQ(domainVerdict.threatName, "UnitThreat");

    const URLVerdict urlVerdict = analyzer.ScanURL("http://dangerous.example/login", false, true);
    EXPECT_TRUE(urlVerdict.isBlocked);
    ASSERT_TRUE(urlVerdict.features.has_value());
    EXPECT_GT(urlVerdict.features->urlLength, 0u);

    EXPECT_TRUE(analyzer.PerformDiagnostics());
    EXPECT_FALSE(analyzer.ExportDiagnostics(L""));

    const auto diagnosticsPath = tempDir.File(L"url-diagnostics.json");
    ASSERT_TRUE(analyzer.ExportDiagnostics(diagnosticsPath.wstring()));
    const std::string report = ReadTextFile(diagnosticsPath);
    EXPECT_NE(report.find("\"module\": \"URLAnalyzer\""), std::string::npos);
    EXPECT_NE(report.find("\"initialized\": true"), std::string::npos);
}

}  // namespace ShadowStrike::Core::Network::Test
