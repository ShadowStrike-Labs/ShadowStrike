/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Network\FirewallManager deterministic rule contracts.
 *
 * Focus:
 *   - low-level match structures used to enforce policy decisions
 *   - firewall rule validation/factory helpers and legacy conversion behavior
 *   - configuration/statistics helpers and diagnostics export without WFP startup
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

#include "../../../src/PhantomCore/Core/Network/FirewallManager.hpp"
#include "CoreNetwork_TestUtils.hpp"

namespace ShadowStrike::Core::Network::Test {

namespace {

std::array<uint8_t, 16> IPv4Bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    std::array<uint8_t, 16> ip{};
    ip[0] = a;
    ip[1] = b;
    ip[2] = c;
    ip[3] = d;
    return ip;
}

}  // namespace

class FirewallManagerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_FirewallManagerTests_"};
    FirewallManager& manager = FirewallManager::Instance();

    void SetUp() override {
        manager.Shutdown();
    }

    void TearDown() override {
        manager.Shutdown();
    }
};

TEST_F(FirewallManagerTest, PortRangeAndIpAddressMatchersHonorCoreMatchingSemantics) {
    PortRange singlePort(443);
    PortRange invalidPortRange(9000, 1000);

    EXPECT_TRUE(singlePort.Contains(443));
    EXPECT_TRUE(singlePort.IsSinglePort());
    EXPECT_TRUE(singlePort.IsValid());
    EXPECT_FALSE(invalidPortRange.IsValid());

    IPAddressMatch anyMatch;
    EXPECT_TRUE(anyMatch.Matches(IPv4Bytes(1, 2, 3, 4)));
    EXPECT_EQ(anyMatch.ToString(), L"Any");

    IPAddressMatch singleMatch;
    singleMatch.type = IPAddressMatch::Type::SINGLE;
    singleMatch.address = IPv4Bytes(192, 168, 1, 10);
    EXPECT_TRUE(singleMatch.Matches(IPv4Bytes(192, 168, 1, 10)));
    EXPECT_FALSE(singleMatch.Matches(IPv4Bytes(192, 168, 1, 11)));
    EXPECT_EQ(singleMatch.ToString(), L"192.168.1.10");

    IPAddressMatch rangeMatch;
    rangeMatch.type = IPAddressMatch::Type::RANGE;
    rangeMatch.address = IPv4Bytes(192, 168, 1, 1);
    rangeMatch.rangeEnd = IPv4Bytes(192, 168, 1, 10);
    EXPECT_TRUE(rangeMatch.Matches(IPv4Bytes(192, 168, 1, 5)));
    EXPECT_FALSE(rangeMatch.Matches(IPv4Bytes(192, 168, 1, 42)));

    IPAddressMatch cidrMatch;
    cidrMatch.type = IPAddressMatch::Type::CIDR;
    cidrMatch.address = IPv4Bytes(10, 0, 0, 0);
    cidrMatch.prefixLength = 8;
    EXPECT_TRUE(cidrMatch.Matches(IPv4Bytes(10, 10, 10, 10)));
    EXPECT_FALSE(cidrMatch.Matches(IPv4Bytes(11, 0, 0, 1)));
    EXPECT_EQ(cidrMatch.ToString(), L"10.0.0.0/8");

    IPAddressMatch listMatch;
    listMatch.type = IPAddressMatch::Type::LIST;
    listMatch.addressList = {IPv4Bytes(1, 1, 1, 1), IPv4Bytes(8, 8, 8, 8)};
    EXPECT_TRUE(listMatch.Matches(IPv4Bytes(8, 8, 8, 8)));
    EXPECT_FALSE(listMatch.Matches(IPv4Bytes(9, 9, 9, 9)));
    EXPECT_EQ(listMatch.ToString(), L"2 addresses");
}

TEST_F(FirewallManagerTest, ApplicationAndGeoMatchersRespectExplicitCriteria) {
    ApplicationMatch anyApp;
    EXPECT_TRUE(anyApp.Matches(L"C:\\Apps\\good.exe", L"good.exe", L"ShadowStrike", {}));

    ApplicationMatch pathApp;
    pathApp.type = ApplicationMatch::Type::PATH;
    pathApp.path = L"C:\\Apps\\good.exe";
    EXPECT_TRUE(pathApp.Matches(L"C:\\Apps\\GOOD.exe", L"good.exe", L"", {}));

    ApplicationMatch wildcardPathApp;
    wildcardPathApp.type = ApplicationMatch::Type::PATH_WILDCARD;
    wildcardPathApp.path = L"C:\\Program Files\\ShadowStrike\\*.exe";
    EXPECT_TRUE(wildcardPathApp.Matches(
        L"C:\\Program Files\\ShadowStrike\\agent.exe", L"agent.exe", L"", {}));
    EXPECT_FALSE(wildcardPathApp.Matches(
        L"C:\\Program Files\\ShadowStrike\\agent.dll", L"agent.dll", L"", {}));

    ApplicationMatch singleCharWildcardApp;
    singleCharWildcardApp.type = ApplicationMatch::Type::PATH_WILDCARD;
    singleCharWildcardApp.path = L"C:\\Apps\\scanner?.exe";
    EXPECT_TRUE(singleCharWildcardApp.Matches(
        L"C:\\Apps\\scanner1.exe", L"scanner1.exe", L"", {}));
    EXPECT_FALSE(singleCharWildcardApp.Matches(
        L"C:\\Apps\\scanner12.exe", L"scanner12.exe", L"", {}));

    ApplicationMatch nameApp;
    nameApp.type = ApplicationMatch::Type::NAME;
    nameApp.processName = L"scanner.exe";
    EXPECT_TRUE(nameApp.Matches(L"C:\\Apps\\scanner.exe", L"SCANNER.EXE", L"", {}));

    ApplicationMatch publisherApp;
    publisherApp.type = ApplicationMatch::Type::PUBLISHER;
    publisherApp.publisher = L"ShadowStrike Labs";
    EXPECT_TRUE(publisherApp.Matches(L"", L"", L"CN=ShadowStrike Labs, O=ShadowStrike", {}));

    std::array<uint8_t, 32> hash{};
    hash[0] = 0xAA;
    ApplicationMatch hashApp;
    hashApp.type = ApplicationMatch::Type::HASH;
    hashApp.sha256 = hash;
    EXPECT_TRUE(hashApp.Matches(L"", L"", L"", hash));

    ApplicationMatch serviceApp;
    serviceApp.type = ApplicationMatch::Type::SERVICE;
    EXPECT_FALSE(serviceApp.Matches(L"", L"", L"", {}));

    GeoMatch geoMatch;
    geoMatch.countryCodes = {"US", "DE"};
    geoMatch.continentCodes = {"NA"};
    geoMatch.asnNumbers = {15169};
    EXPECT_TRUE(geoMatch.Matches("US", "NA", 15169));
    EXPECT_FALSE(geoMatch.Matches("FR", "EU", 3215));

    GeoMatch allowList;
    allowList.countryCodes = {"US"};
    allowList.isAllowList = true;
    EXPECT_FALSE(allowList.Matches("US", "NA", 15169));
    EXPECT_TRUE(allowList.Matches("FR", "EU", 3215));
}

TEST_F(FirewallManagerTest, FirewallRuleFactoriesAndValidationRemainConsistent) {
    const FirewallRule blockIp = FirewallRule::CreateBlockIP(L"192.168.10.25", RuleDirection::OUTBOUND);
    EXPECT_EQ(blockIp.type, RuleType::IP);
    EXPECT_EQ(blockIp.action, RuleAction::BLOCK);
    EXPECT_EQ(blockIp.direction, RuleDirection::OUTBOUND);
    EXPECT_EQ(blockIp.remoteAddress.type, IPAddressMatch::Type::SINGLE);
    EXPECT_TRUE(blockIp.isEnabled);
    EXPECT_TRUE(blockIp.IsValid());

    const FirewallRule blockPort = FirewallRule::CreateBlockPort(3389, RuleProtocol::TCP, RuleDirection::INBOUND);
    EXPECT_EQ(blockPort.type, RuleType::PORT);
    ASSERT_EQ(blockPort.remotePorts.size(), 1u);
    EXPECT_TRUE(blockPort.remotePorts.front().Contains(3389));
    EXPECT_EQ(blockPort.protocol, RuleProtocol::TCP);

    const FirewallRule blockApp = FirewallRule::CreateBlockApp(L"C:\\Malware\\bad.exe");
    EXPECT_EQ(blockApp.type, RuleType::APPLICATION);
    EXPECT_EQ(blockApp.application.type, ApplicationMatch::Type::PATH);
    EXPECT_EQ(blockApp.application.path, L"C:\\Malware\\bad.exe");

    const FirewallRule allowApp = FirewallRule::CreateAllowApp(L"C:\\Program Files\\ShadowStrike\\agent.exe");
    EXPECT_EQ(allowApp.action, RuleAction::ALLOW);
    EXPECT_EQ(allowApp.direction, RuleDirection::BOTH);

    const FirewallRule geoBlock = FirewallRule::CreateGeoBlock({"RU", "CN"});
    EXPECT_EQ(geoBlock.type, RuleType::GEO);
    EXPECT_EQ(geoBlock.geoMatch.countryCodes.size(), 2u);
    EXPECT_FALSE(geoBlock.geoMatch.isAllowList);

    FirewallRule invalidRule;
    invalidRule.name.clear();
    EXPECT_FALSE(invalidRule.IsValid());
    invalidRule.name = L"Invalid Port Rule";
    invalidRule.priority = 0;
    EXPECT_FALSE(invalidRule.IsValid());
    invalidRule.priority = 10;
    invalidRule.remotePorts.push_back(PortRange(100, 50));
    EXPECT_FALSE(invalidRule.IsValid());
}

TEST_F(FirewallManagerTest, LegacyConversionAndApplicationStatisticsResetPreserveBehavior) {
    FirewallRuleLegacy legacy;
    legacy.id = "legacy-allow-rule";
    legacy.appPath = L"C:\\Apps\\legacy.exe";
    legacy.port = 8443;
    legacy.isAllow = true;

    const FirewallRule converted = static_cast<FirewallRule>(legacy);
    EXPECT_EQ(converted.name, L"legacy-allow-rule");
    EXPECT_EQ(converted.action, RuleAction::ALLOW);
    EXPECT_EQ(converted.type, RuleType::APPLICATION);
    EXPECT_EQ(converted.application.path, legacy.appPath);
    ASSERT_EQ(converted.remotePorts.size(), 1u);
    EXPECT_TRUE(converted.remotePorts.front().Contains(8443));

    ApplicationNetworkStats stats;
    stats.connectionsAllowed.store(10, std::memory_order_relaxed);
    stats.connectionsBlocked.store(4, std::memory_order_relaxed);
    stats.bytesIn.store(1024, std::memory_order_relaxed);
    stats.bytesOut.store(2048, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.connectionsAllowed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.connectionsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesIn.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesOut.load(std::memory_order_relaxed), 0u);
}

TEST_F(FirewallManagerTest, ConfigFactoriesStatisticsAndDiagnosticsExportStayStable) {
    const auto defaults = FirewallManagerConfig::CreateDefault();
    const auto highSecurity = FirewallManagerConfig::CreateHighSecurity();
    const auto permissive = FirewallManagerConfig::CreatePermissive();
    const auto serverOptimized = FirewallManagerConfig::CreateServerOptimized();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_EQ(defaults.defaultInboundAction, RuleAction::BLOCK);
    EXPECT_EQ(defaults.defaultOutboundAction, RuleAction::ALLOW);

    EXPECT_TRUE(highSecurity.enableGeoBlocking);
    EXPECT_EQ(highSecurity.stealthMode, StealthMode::ENHANCED);
    EXPECT_TRUE(highSecurity.blockUnknownApplications);

    EXPECT_EQ(permissive.defaultInboundAction, RuleAction::ALLOW);
    EXPECT_EQ(permissive.defaultOutboundAction, RuleAction::ALLOW);
    EXPECT_EQ(permissive.stealthMode, StealthMode::OFF);

    EXPECT_FALSE(serverOptimized.enableApplicationControl);
    EXPECT_TRUE(serverOptimized.enableRuleCache);
    EXPECT_EQ(serverOptimized.maxRules, 50000u);

    FirewallStatistics stats;
    stats.totalConnections.store(7, std::memory_order_relaxed);
    stats.blockedConnections.store(3, std::memory_order_relaxed);
    stats.ruleMatches.store(2, std::memory_order_relaxed);
    stats.bytesBlocked.store(4096, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.totalConnections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.blockedConnections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.ruleMatches.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesBlocked.load(std::memory_order_relaxed), 0u);

    EXPECT_FALSE(manager.PerformDiagnostics());
    EXPECT_FALSE(manager.ExportDiagnostics(L""));

    const auto diagnosticsPath = tempDir.File(L"firewall-diagnostics.txt");
    ASSERT_TRUE(manager.ExportDiagnostics(diagnosticsPath.wstring()));
    const std::string report = ReadTextFile(diagnosticsPath);
    EXPECT_NE(report.find("ShadowStrike Firewall Manager Diagnostics"), std::string::npos);
    EXPECT_NE(report.find("CONFIGURATION"), std::string::npos);
}

}  // namespace ShadowStrike::Core::Network::Test
