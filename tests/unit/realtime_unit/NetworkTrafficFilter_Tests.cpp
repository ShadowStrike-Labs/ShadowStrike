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

#include "../../../src/PhantomCore/RealTime/NetworkTrafficFilter.hpp"
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

    // WAS: EXPECT_TRUE(loopbackV4.IsPrivate()) and EXPECT_TRUE(loopbackV6.IsPrivate()).
    // THE PRODUCT IS CORRECT AND THE TEST WAS WRONG. IsPrivate() and IsLoopback() are
    // deliberately DISJOINT predicates: IsPrivate() answers RFC 1918 (10/8,
    // 172.16/12, 192.168/16) and RFC 4193 (fc00::/7); loopback is RFC 1122 127/8 and
    // RFC 4291 ::1, a different address scope with its own predicate. 127.0.0.1 is
    // therefore not private, and ::1 is not private.
    //
    // This is a detection question, not a naming one. IsPrivate() is the "is the peer
    // on my LAN" predicate, and callers use it to decide how much scrutiny a flow
    // gets - a private<->private flow is internal traffic, a private->public flow is
    // egress that has to be examined for C2 and exfiltration. Loopback is neither: it
    // never reaches a wire. Folding it into "private" hands every localhost flow the
    // trusted-LAN treatment, and localhost is precisely where implants put their
    // local hop - a SOCKS/HTTP proxy bound to 127.0.0.1 that a tunnel client chains
    // through, or C2 relayed between two processes on the host. Any caller written as
    // `if (remote.IsPrivate()) { /* internal, skip deep inspection */ }` would then
    // skip exactly that traffic, and no caller could ask for localhost specifically
    // any more, because the two scopes would be indistinguishable through this API.
    //
    // Keeping them disjoint forces each caller to make loopback an explicit decision,
    // which is what the rest of the codebase already does:
    // NetworkMonitor::DetermineDirection tests IsLoopback() first and returns
    // ConnectionDirection::LOCAL before it ever considers INTERNAL or OUTBOUND.
    //
    // If someone reverts this to EXPECT_TRUE, the honest fix would have to be
    // widening IPAddress::IsPrivate() in NetworkTrafficFilter.cpp to swallow 127/8
    // and ::1 - which silently reclassifies all local-proxy traffic as trusted LAN
    // traffic for every present and future caller of the predicate. That is a
    // detection loss with no compensating gain.
    EXPECT_FALSE(loopbackV4.IsPrivate());
    EXPECT_TRUE(loopbackV4.IsLoopback());

    EXPECT_EQ(IPVersion::IPv6, loopbackV6.version);
    EXPECT_EQ(std::string("::1"), loopbackV6.ToString());
    EXPECT_FALSE(loopbackV6.IsPrivate());
    EXPECT_TRUE(loopbackV6.IsLoopback());

    // The disjointness itself, stated once so a future edit that merges the two
    // scopes fails here rather than in whichever caller happens to notice first.
    EXPECT_FALSE(privateV4.IsLoopback());
    EXPECT_FALSE(IPAddress::FromString("fd00::1").IsLoopback());
    EXPECT_TRUE(IPAddress::FromString("fd00::1").IsPrivate());

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
