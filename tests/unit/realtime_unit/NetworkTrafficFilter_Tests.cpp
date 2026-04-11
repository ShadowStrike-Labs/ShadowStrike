/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\NetworkTrafficFilter deterministic contracts.
 *
 * Focus:
 *   - IP/endpoint/tuple helper semantics and config presets
 *   - blocklist normalization behavior and callback registration
 *   - safe statistics exposure without requiring live traffic capture
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/NetworkTrafficFilter.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class NetworkTrafficFilterTest : public ::testing::Test {
protected:
    NetworkTrafficFilter& filter = NetworkTrafficFilter::Instance();

    void SetUp() override {
        filter.Shutdown();
        filter.ResetStats();
    }

    void TearDown() override {
        filter.Shutdown();
    }
};

TEST_F(NetworkTrafficFilterTest, HelperTypesAndConfigFactoriesRemainStable) {
    const IPAddress invalidIp = IPAddress::FromString("");
    const IPAddress privateV4 = IPAddress::FromString("192.168.1.10");
    const IPAddress boundaryPrivate = IPAddress::FromString("172.16.0.1");
    const IPAddress boundaryPublic = IPAddress::FromString("172.32.0.1");
    const IPAddress loopbackV4 = IPAddress::FromString("127.0.0.1");
    const IPAddress loopbackV6 = IPAddress::FromString("::1");

    EXPECT_EQ(IPVersion::Unknown, invalidIp.version);
    EXPECT_TRUE(invalidIp.ToString().empty());
    EXPECT_FALSE(invalidIp.IsPrivate());
    EXPECT_FALSE(invalidIp.IsLoopback());

    EXPECT_EQ(IPVersion::IPv4, privateV4.version);
    EXPECT_EQ(std::string("192.168.1.10"), privateV4.ToString());
    EXPECT_TRUE(privateV4.IsPrivate());
    EXPECT_FALSE(privateV4.IsLoopback());

    EXPECT_TRUE(boundaryPrivate.IsPrivate());
    EXPECT_FALSE(boundaryPublic.IsPrivate());
    EXPECT_TRUE(loopbackV4.IsPrivate());
    EXPECT_TRUE(loopbackV4.IsLoopback());

    EXPECT_EQ(IPVersion::IPv6, loopbackV6.version);
    EXPECT_EQ(std::string("::1"), loopbackV6.ToString());
    EXPECT_TRUE(loopbackV6.IsPrivate());
    EXPECT_TRUE(loopbackV6.IsLoopback());

    NetworkEndpoint endpoint{ privateV4, 443 };
    EXPECT_EQ(std::string("192.168.1.10:443"), endpoint.ToString());
    const NetworkEndpoint sameEndpoint{ privateV4, 443 };
    EXPECT_TRUE(endpoint == sameEndpoint);

    ConnectionTuple tuple;
    tuple.protocol = NetworkProtocol::TCP;
    tuple.local = { IPAddress::FromString("10.0.0.5"), 51515 };
    tuple.remote = { IPAddress::FromString("8.8.8.8"), 53 };

    ConnectionTuple copy = tuple;
    EXPECT_EQ(tuple.Hash(), copy.Hash());
    EXPECT_TRUE(tuple == copy);

    EXPECT_STREQ("Terminate", FilterActionToString(FilterAction::Terminate));
    EXPECT_STREQ("T1568", NetworkDetectionToMitre(NetworkDetectionType::DGADomain));

    const auto defaults = NetworkFilterConfig::CreateDefault();
    const auto strict = NetworkFilterConfig::CreateStrict();
    const auto monitorOnly = NetworkFilterConfig::CreateMonitorOnly();

    EXPECT_TRUE(defaults.deepInspection);
    EXPECT_EQ(FilterAction::Allow, defaults.defaultAction);

    EXPECT_EQ(FilterAction::Block, strict.defaultAction);
    EXPECT_TRUE(strict.blockTOR);
    EXPECT_TRUE(strict.blockVPN);
    EXPECT_TRUE(strict.blockProxy);

    EXPECT_EQ(FilterAction::LogOnly, monitorOnly.defaultAction);
    EXPECT_EQ(FilterAction::LogOnly, monitorOnly.maliciousIPAction);
    EXPECT_EQ(FilterAction::LogOnly, monitorOnly.c2Action);
}

TEST_F(NetworkTrafficFilterTest, BlocklistsNormalizeInputsAndCallbacksRemainSafe) {
    const IPAddress blockedIp = IPAddress::FromString("203.0.113.25");
    filter.BlockIP(blockedIp);
    EXPECT_TRUE(filter.IsIPBlocked(blockedIp));
    const auto blockedIps = filter.GetBlockedIPs();
    EXPECT_TRUE(ContainsValue(std::span<const IPAddress>(blockedIps), blockedIp));

    filter.UnblockIP(blockedIp);
    EXPECT_FALSE(filter.IsIPBlocked(blockedIp));

    filter.BlockIP("198.51.100.42");
    EXPECT_TRUE(filter.IsIPBlocked(IPAddress::FromString("198.51.100.42")));
    filter.UnblockIP(IPAddress::FromString("198.51.100.42"));
    EXPECT_FALSE(filter.IsIPBlocked(IPAddress::FromString("198.51.100.42")));

    filter.BlockDomain("MiXeD.Example.COM");
    EXPECT_TRUE(filter.IsDomainBlocked("mixed.example.com"));
    EXPECT_TRUE(ContainsString(filter.GetBlockedDomains(), "mixed.example.com"));

    filter.UnblockDomain("MIXED.EXAMPLE.COM");
    EXPECT_FALSE(filter.IsDomainBlocked("mixed.example.com"));
    filter.BlockDomain("");
    EXPECT_FALSE(filter.IsDomainBlocked(""));
    EXPECT_TRUE(filter.GetBlockedDomains().empty());
    filter.UnblockDomain("");
    EXPECT_FALSE(filter.IsDomainBlocked(""));

    const uint64_t nullConnectionId = filter.RegisterConnectionCallback({});
    const uint64_t nullEventId = filter.RegisterEventCallback({});
    const uint64_t nullDnsId = filter.RegisterDNSCallback({});
    const uint64_t nullC2Id = filter.RegisterC2Callback({});
    const uint64_t nullExfilId = filter.RegisterExfiltrationCallback({});
    const uint64_t connectionId = filter.RegisterConnectionCallback(
        [](const NetworkConnection&) { return FilterAction::Allow; });
    const uint64_t eventId = filter.RegisterEventCallback([](const NetworkEvent&) {});
    const uint64_t dnsId = filter.RegisterDNSCallback(
        [](const DNSQueryEvent&) { return FilterAction::LogOnly; });
    const uint64_t c2Id = filter.RegisterC2Callback([](const BeaconAnalysis&) {});
    const uint64_t exfilId = filter.RegisterExfiltrationCallback(
        [](uint32_t, const NetworkEndpoint&, size_t) { return FilterAction::Block; });

    EXPECT_NE(0u, nullConnectionId);
    EXPECT_NE(0u, nullEventId);
    EXPECT_NE(0u, nullDnsId);
    EXPECT_NE(0u, nullC2Id);
    EXPECT_NE(0u, nullExfilId);
    EXPECT_NE(0u, connectionId);
    EXPECT_NE(0u, eventId);
    EXPECT_NE(0u, dnsId);
    EXPECT_NE(0u, c2Id);
    EXPECT_NE(0u, exfilId);

    EXPECT_TRUE(filter.UnregisterConnectionCallback(nullConnectionId));
    EXPECT_TRUE(filter.UnregisterEventCallback(nullEventId));
    EXPECT_TRUE(filter.UnregisterDNSCallback(nullDnsId));
    EXPECT_TRUE(filter.UnregisterC2Callback(nullC2Id));
    EXPECT_TRUE(filter.UnregisterExfiltrationCallback(nullExfilId));
    EXPECT_TRUE(filter.UnregisterConnectionCallback(connectionId));
    EXPECT_TRUE(filter.UnregisterEventCallback(eventId));
    EXPECT_TRUE(filter.UnregisterDNSCallback(dnsId));
    EXPECT_TRUE(filter.UnregisterC2Callback(c2Id));
    EXPECT_TRUE(filter.UnregisterExfiltrationCallback(exfilId));
    EXPECT_FALSE(filter.UnregisterExfiltrationCallback(exfilId));
}

TEST_F(NetworkTrafficFilterTest, StatisticsExposureRemainsDeterministicAfterReset) {
    filter.ResetStats();

    const auto stats = filter.GetStats();
    EXPECT_EQ(0u, stats.totalConnections);
    EXPECT_EQ(0u, stats.connectionsBlocked);
    EXPECT_EQ(0u, stats.connectionsAllowed);
    EXPECT_EQ(0u, stats.rulesEvaluated);
    EXPECT_EQ(0u, stats.activeConnections);
}

}  // namespace ShadowStrike::RealTime::Tests
