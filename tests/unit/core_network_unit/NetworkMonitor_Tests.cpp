/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Network\NetworkMonitor foundational contracts.
 *
 * Focus:
 *   - IP and socket helper semantics used across network telemetry paths
 *   - configuration/statistics reset behavior and enum-name stability
 *   - self-test and version contracts that must remain deterministic
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <regex>
#include <string>

#include "../../../src/Shared_modules/Core/Network/NetworkMonitor.hpp"

namespace ShadowStrike::Core::Network::Test {

class NetworkMonitorTest : public ::testing::Test {
protected:
    NetworkMonitor& monitor = NetworkMonitor::Instance();

    void SetUp() override {
        monitor.Shutdown();
        monitor.ResetStatistics();
    }

    void TearDown() override {
        monitor.Shutdown();
    }
};

TEST_F(NetworkMonitorTest, InstanceReturnsStableSingletonReference) {
    EXPECT_EQ(&NetworkMonitor::Instance(), &NetworkMonitor::Instance());
}

TEST_F(NetworkMonitorTest, IPv4AddressContractsClassifyFormatAndCompareCorrectly) {
    const IPAddress loopback(0x7F000001);
    const IPAddress privateIp(0xC0A8012A);
    const IPAddress publicIp(0x08080808);

    EXPECT_EQ(loopback.type, IPAddressType::IPV4);
    EXPECT_EQ(loopback.classification, IPClassification::LOOPBACK);
    EXPECT_TRUE(loopback.IsValid());
    EXPECT_TRUE(loopback.IsLoopback());
    EXPECT_FALSE(loopback.IsPrivate());
    EXPECT_EQ(loopback.ToString(), "127.0.0.1");

    EXPECT_EQ(privateIp.classification, IPClassification::PRIVATE);
    EXPECT_TRUE(privateIp.IsPrivate());
    EXPECT_EQ(privateIp.ToString(), "192.168.1.42");

    EXPECT_EQ(publicIp.classification, IPClassification::PUBLIC);
    EXPECT_FALSE(publicIp.IsPrivate());
    EXPECT_FALSE(publicIp.IsLoopback());
    EXPECT_EQ(publicIp.ToString(), "8.8.8.8");

    EXPECT_TRUE(loopback < privateIp);
    EXPECT_NE(IPAddress::Hash{}(privateIp), 0u);
}

TEST_F(NetworkMonitorTest, IPv6AndRangeContractsPreserveClassificationContainmentAndCounts) {
    std::array<uint8_t, 16> linkLocalBytes{};
    linkLocalBytes[0] = 0xFE;
    linkLocalBytes[1] = 0x80;
    linkLocalBytes[15] = 0x01;

    std::array<uint8_t, 16> multicastBytes{};
    multicastBytes[0] = 0xFF;
    multicastBytes[1] = 0x02;
    multicastBytes[15] = 0x01;

    const IPAddress linkLocal(linkLocalBytes);
    const IPAddress multicast(multicastBytes);

    EXPECT_EQ(linkLocal.type, IPAddressType::IPV6);
    EXPECT_EQ(linkLocal.classification, IPClassification::LINK_LOCAL);
    EXPECT_TRUE(linkLocal.IsValid());

    EXPECT_EQ(multicast.classification, IPClassification::MULTICAST);
    EXPECT_TRUE(multicast.ToString().find(':') != std::string::npos);

    IPRange ipv4Range;
    ipv4Range.baseAddress = IPAddress(0xC0A80100);
    ipv4Range.prefixLength = 24;

    EXPECT_TRUE(ipv4Range.Contains(IPAddress(0xC0A801FE)));
    EXPECT_FALSE(ipv4Range.Contains(IPAddress(0xC0A80201)));
    EXPECT_EQ(ipv4Range.ToString(), "192.168.1.0/24");
    EXPECT_EQ(ipv4Range.GetAddressCount(), 256u);

    IPRange anyIpv4Range;
    anyIpv4Range.baseAddress = IPAddress(0x00000000);
    anyIpv4Range.prefixLength = 0;
    EXPECT_TRUE(anyIpv4Range.Contains(IPAddress(0x08080808)));
    EXPECT_EQ(anyIpv4Range.GetAddressCount(), 0x100000000ULL);

    IPRange ipv6Range;
    ipv6Range.baseAddress = linkLocal;
    ipv6Range.prefixLength = 64;
    EXPECT_EQ(ipv6Range.GetAddressCount(), std::numeric_limits<uint64_t>::max());

    IPRange singleIpv6Range;
    singleIpv6Range.baseAddress = linkLocal;
    singleIpv6Range.prefixLength = 128;
    EXPECT_EQ(singleIpv6Range.GetAddressCount(), 1u);
}

TEST_F(NetworkMonitorTest, SocketTupleAndBandwidthHelpersRemainStable) {
    SocketAddress local{IPAddress(0xC0A8010A), 443};
    SocketAddress remote{IPAddress(0x08080808), 53123};
    ConnectionTuple tuple{local, remote, ProtocolType::TCP};

    EXPECT_EQ(local.ToString(), "192.168.1.10:443");
    EXPECT_EQ(local.ToWString(), L"192.168.1.10:443");
    EXPECT_FALSE(local == remote);
    EXPECT_NE(SocketAddress::Hash{}(local), 0u);

    const std::string tupleText = tuple.ToString();
    EXPECT_NE(tupleText.find("192.168.1.10:443"), std::string::npos);
    EXPECT_NE(tupleText.find("8.8.8.8:53123"), std::string::npos);
    EXPECT_NE(tupleText.find("[TCP]"), std::string::npos);
    const ConnectionTuple expectedTuple{local, remote, ProtocolType::TCP};
    EXPECT_TRUE(tuple == expectedTuple);
    EXPECT_NE(ConnectionTuple::Hash{}(tuple), 0u);

    BandwidthStats bandwidth;
    bandwidth.bytesReceived.store(1024, std::memory_order_relaxed);
    bandwidth.bytesSent.store(2048, std::memory_order_relaxed);
    bandwidth.peakReceiveRate.store(99, std::memory_order_relaxed);
    bandwidth.peakSendRate.store(100, std::memory_order_relaxed);
    bandwidth.Reset();

    EXPECT_EQ(bandwidth.bytesReceived.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(bandwidth.bytesSent.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(bandwidth.peakReceiveRate.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(bandwidth.peakSendRate.load(std::memory_order_relaxed), 0u);
}

TEST_F(NetworkMonitorTest, ConfigurationFactoriesAndStatisticsResetReflectExpectedProfiles) {
    const auto defaults = NetworkMonitorConfig::CreateDefault();
    const auto highSecurity = NetworkMonitorConfig::CreateHighSecurity();
    const auto performance = NetworkMonitorConfig::CreatePerformance();
    const auto forensic = NetworkMonitorConfig::CreateForensic();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_EQ(defaults.level, MonitoringLevel::STANDARD);
    EXPECT_FALSE(defaults.extractTLSInfo);
    EXPECT_FALSE(defaults.useKernelFiltering);

    EXPECT_EQ(highSecurity.level, MonitoringLevel::DETAILED);
    EXPECT_TRUE(highSecurity.extractTLSInfo);
    EXPECT_TRUE(highSecurity.lookupGeoIP);
    EXPECT_TRUE(highSecurity.useKernelFiltering);

    EXPECT_EQ(performance.level, MonitoringLevel::MINIMAL);
    EXPECT_TRUE(performance.enableEventSampling);
    EXPECT_EQ(performance.eventSampleRate, 10u);
    EXPECT_FALSE(performance.detectBeaconing);

    EXPECT_EQ(forensic.level, MonitoringLevel::FORENSIC);
    EXPECT_TRUE(forensic.logAllConnections);
    EXPECT_TRUE(forensic.logBandwidth);
    EXPECT_EQ(forensic.connectionTimeoutMs, 3600000u);

    NetworkMonitorStatistics stats;
    stats.totalConnections.store(5, std::memory_order_relaxed);
    stats.blockedConnections.store(3, std::memory_order_relaxed);
    stats.totalBytesSent.store(1234, std::memory_order_relaxed);
    stats.threatsDetected.store(2, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.totalConnections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.blockedConnections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalBytesSent.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threatsDetected.load(std::memory_order_relaxed), 0u);
}

TEST_F(NetworkMonitorTest, EnumNameHelpersAndDiagnosticsContractsStayStable) {
    EXPECT_EQ(GetConnectionStateName(ConnectionState::ESTABLISHED), "ESTABLISHED");
    EXPECT_EQ(GetProtocolTypeName(ProtocolType::UDP), "UDP");
    EXPECT_EQ(GetAppProtocolName(ApplicationProtocol::DNS_OVER_HTTPS), "DoH");
    EXPECT_EQ(GetConnectionDirectionName(ConnectionDirection::OUTBOUND), "OUTBOUND");
    EXPECT_EQ(GetFilterActionName(FilterAction::RATE_LIMIT), "RATE_LIMIT");
    EXPECT_EQ(GetBlockReasonName(BlockReason::MANUAL_BLOCK), "MANUAL_BLOCK");
    EXPECT_EQ(GetThreatIndicatorName(ThreatIndicator::DNS_TUNNELING), "DNS_TUNNELING");
    EXPECT_EQ(GetIPAddressTypeName(IPAddressType::IPV6), "IPV6");
    EXPECT_EQ(GetIPClassificationName(IPClassification::LINK_LOCAL), "LINK_LOCAL");
    EXPECT_EQ(GetMonitoringLevelName(MonitoringLevel::FORENSIC), "FORENSIC");
    EXPECT_EQ(GetProtocolTypeName(static_cast<ProtocolType>(255)), "UNKNOWN");

    EXPECT_TRUE(monitor.SelfTest());
    EXPECT_TRUE(std::regex_match(NetworkMonitor::GetVersionString(), std::regex(R"(\d+\.\d+\.\d+)")));
}

TEST_F(NetworkMonitorTest, ConnectionFilterMatchesConfiguredCriteriaAndRejectsMismatches) {
    ConnectionInfo connection;
    connection.tuple.local = SocketAddress{IPAddress(0xC0A8010A), 443};
    connection.tuple.remote = SocketAddress{IPAddress(0x08080808), 53123};
    connection.tuple.protocol = ProtocolType::TCP;
    connection.appProtocol = ApplicationProtocol::HTTPS;
    connection.processContext.processPath = L"C:\\Program Files\\ShadowStrike\\agent.exe";
    connection.processContext.processName = L"agent.exe";
    connection.processContext.pid = 4242;
    connection.processContext.userSid = L"S-1-5-18";
    connection.remoteHostname = L"api.shadowstrike.dev";
    connection.remoteCountryCode = L"US";

    ConnectionFilter filter;
    filter.localIp = IPAddress(0xC0A8010A);
    filter.localPort = 443;
    filter.remoteIpRange = IPRange{IPAddress(0x08080800), 24};
    filter.remotePort = 53123;
    filter.protocol = ProtocolType::TCP;
    filter.appProtocol = ApplicationProtocol::HTTPS;
    filter.processPath = L"C:\\PROGRAM FILES\\SHADOWSTRIKE\\AGENT.EXE";
    filter.processName = L"AGENT.EXE";
    filter.pid = 4242;
    filter.userSid = L"S-1-5-18";
    filter.remoteHostname = L"api.shadowstrike.dev";
    filter.countryCode = L"US";

    EXPECT_TRUE(filter.Matches(connection));

    ConnectionFilter wrongHost = filter;
    wrongHost.remoteHostname = L"cdn.shadowstrike.dev";
    EXPECT_FALSE(wrongHost.Matches(connection));

    ConnectionFilter wrongRange = filter;
    wrongRange.remoteIpRange = IPRange{IPAddress(0x09000000), 8};
    EXPECT_FALSE(wrongRange.Matches(connection));

    ConnectionFilter wrongPid = filter;
    wrongPid.pid = 7;
    EXPECT_FALSE(wrongPid.Matches(connection));
}

}  // namespace ShadowStrike::Core::Network::Test
