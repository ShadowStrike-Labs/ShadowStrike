// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/*
 * ============================================================================
 * ShadowStrike NetworkUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for NetworkUtils module
 * Coverage: IP parsing, address validation, network adapter enumeration,
 *           DNS resolution (localhost), ping (localhost), URL parsing,
 *           port detection, MAC address parsing, protocol detection
 *
 * Test Standards: Sophos/CrowdStrike enterprise quality
 * Strategy: Use localhost (127.0.0.1, ::1) and system APIs for validation
 *
 * ============================================================================
 */
#include "pch.h"
#include <gtest/gtest.h>
#include "../../../src/Utils/NetworkUtils.hpp"
#include "../../../src/Utils/Logger.hpp"

#include <string>
#include <vector>
#include <thread>
#include <chrono>

using namespace ShadowStrike::Utils::NetworkUtils;

// ============================================================================
// TEST FIXTURE
// ============================================================================
class NetworkUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize Winsock for tests that need it
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    
    void TearDown() override {
        WSACleanup();
    }
};

// ============================================================================
// IPv4 ADDRESS TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, IPv4Address_Construction) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_Construction] Testing...");
    std::array<uint8_t, 4> bytes = {192, 168, 1, 1};
    IPv4Address ipv4(bytes);
    
    EXPECT_EQ(ipv4.octets[0], 192);
    EXPECT_EQ(ipv4.octets[1], 168);
    EXPECT_EQ(ipv4.octets[2], 1);
    EXPECT_EQ(ipv4.octets[3], 1);
}

TEST_F(NetworkUtilsTest, IPv4Address_ToString) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_ToString] Testing...");
    std::array<uint8_t, 4> bytes = {127, 0, 0, 1};
    IPv4Address ipv4(bytes);
    
    EXPECT_EQ(ipv4.ToString(), L"127.0.0.1");
}

TEST_F(NetworkUtilsTest, IPv4Address_Loopback) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_Loopback] Testing...");
    IPv4Address loopback({127, 0, 0, 1});
    IPv4Address normal({192, 168, 1, 1});
    
    EXPECT_TRUE(loopback.IsLoopback());
    EXPECT_FALSE(normal.IsLoopback());
}

TEST_F(NetworkUtilsTest, IPv4Address_Private) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_Private] Testing...");
    IPv4Address private10({10, 0, 0, 1});
    IPv4Address private172({172, 16, 0, 1});
    IPv4Address private192({192, 168, 0, 1});
    IPv4Address publicAddr({8, 8, 8, 8});
    
    EXPECT_TRUE(private10.IsPrivate());
    EXPECT_TRUE(private172.IsPrivate());
    EXPECT_TRUE(private192.IsPrivate());
    EXPECT_FALSE(publicAddr.IsPrivate());
}

TEST_F(NetworkUtilsTest, IPv4Address_Multicast) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_Multicast] Testing...");
    IPv4Address multicast({224, 0, 0, 1});
    IPv4Address normal({192, 168, 1, 1});
    
    EXPECT_TRUE(multicast.IsMulticast());
    EXPECT_FALSE(normal.IsMulticast());
}

TEST_F(NetworkUtilsTest, IPv4Address_Broadcast) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_Broadcast] Testing...");
    IPv4Address broadcast({255, 255, 255, 255});
    IPv4Address normal({192, 168, 1, 1});
    
    EXPECT_TRUE(broadcast.IsBroadcast());
    EXPECT_FALSE(normal.IsBroadcast());
}

TEST_F(NetworkUtilsTest, IPv4Address_LinkLocal) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv4Address_LinkLocal] Testing...");
    IPv4Address linkLocal({169, 254, 0, 1});
    IPv4Address normal({192, 168, 1, 1});
    
    EXPECT_TRUE(linkLocal.IsLinkLocal());
    EXPECT_FALSE(normal.IsLinkLocal());
}

// ============================================================================
// IPv6 ADDRESS TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, IPv6Address_Construction) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv6Address_Construction] Testing...");
    std::array<uint8_t, 16> bytes = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    IPv6Address ipv6(bytes);
    
    EXPECT_EQ(ipv6.bytes[0], 0x20);
    EXPECT_EQ(ipv6.bytes[1], 0x01);
}

TEST_F(NetworkUtilsTest, IPv6Address_Loopback) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv6Address_Loopback] Testing...");
    std::array<uint8_t, 16> loopbackBytes = {};
    loopbackBytes[15] = 1; // ::1
    
    IPv6Address loopback(loopbackBytes);
    EXPECT_TRUE(loopback.IsLoopback());
}

TEST_F(NetworkUtilsTest, IPv6Address_LinkLocal) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IPv6Address_LinkLocal] Testing...");
    std::array<uint8_t, 16> bytes = {};
    bytes[0] = 0xFE;
    bytes[1] = 0x80;
    
    IPv6Address ipv6(bytes);
    EXPECT_TRUE(ipv6.IsLinkLocal());
}

// ============================================================================
// IP ADDRESS PARSING TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, ParseIPv4_ValidAddress) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIPv4_ValidAddress] Testing...");
    IPv4Address ipv4;
    Error err;
    
    ASSERT_TRUE(ParseIPv4(L"127.0.0.1", ipv4, &err));
    EXPECT_EQ(ipv4.octets[0], 127);
    EXPECT_EQ(ipv4.octets[1], 0);
    EXPECT_EQ(ipv4.octets[2], 0);
    EXPECT_EQ(ipv4.octets[3], 1);
}

TEST_F(NetworkUtilsTest, ParseIPv4_InvalidAddress) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIPv4_InvalidAddress] Testing...");
    IPv4Address ipv4;
    Error err;
    
    EXPECT_FALSE(ParseIPv4(L"256.0.0.1", ipv4, &err));
    EXPECT_FALSE(ParseIPv4(L"192.168.1", ipv4, &err));
    EXPECT_FALSE(ParseIPv4(L"abc.def.ghi.jkl", ipv4, &err));
    EXPECT_FALSE(ParseIPv4(L"", ipv4, &err));
}

TEST_F(NetworkUtilsTest, ParseIPv6_ValidAddress) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIPv6_ValidAddress] Testing...");
    IPv6Address ipv6;
    Error err;
    
    ASSERT_TRUE(ParseIPv6(L"::1", ipv6, &err));
    EXPECT_TRUE(ipv6.IsLoopback());
}

TEST_F(NetworkUtilsTest, ParseIPv6_InvalidAddress) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIPv6_InvalidAddress] Testing...");
    IPv6Address ipv6;
    Error err;
    
    EXPECT_FALSE(ParseIPv6(L"gggg::1", ipv6, &err));
    EXPECT_FALSE(ParseIPv6(L"", ipv6, &err));
}

TEST_F(NetworkUtilsTest, ParseIpAddress_IPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIpAddress_IPv4] Testing...");
    IpAddress ip;
    Error err;
    
    ASSERT_TRUE(ParseIpAddress(L"192.168.1.1", ip, &err));
    EXPECT_TRUE(ip.IsIPv4());
    EXPECT_FALSE(ip.IsIPv6());
}

TEST_F(NetworkUtilsTest, ParseIpAddress_IPv6) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseIpAddress_IPv6] Testing...");
    IpAddress ip;
    Error err;
    
    ASSERT_TRUE(ParseIpAddress(L"::1", ip, &err));
    EXPECT_TRUE(ip.IsIPv6());
    EXPECT_FALSE(ip.IsIPv4());
}

TEST_F(NetworkUtilsTest, IsValidIPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsValidIPv4] Testing...");
    EXPECT_TRUE(IsValidIPv4(L"127.0.0.1"));
    EXPECT_TRUE(IsValidIPv4(L"192.168.1.1"));
    EXPECT_TRUE(IsValidIPv4(L"8.8.8.8"));
    
    EXPECT_FALSE(IsValidIPv4(L"256.0.0.1"));
    EXPECT_FALSE(IsValidIPv4(L"192.168.1"));
    EXPECT_FALSE(IsValidIPv4(L"not-an-ip"));
}

TEST_F(NetworkUtilsTest, IsValidIPv6) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsValidIPv6] Testing...");
    EXPECT_TRUE(IsValidIPv6(L"::1"));
    EXPECT_TRUE(IsValidIPv6(L"fe80::1"));
    EXPECT_TRUE(IsValidIPv6(L"2001:db8::1"));
    
    EXPECT_FALSE(IsValidIPv6(L"gggg::1"));
    EXPECT_FALSE(IsValidIPv6(L"192.168.1.1"));
}

// ============================================================================
// IP NETWORK CALCULATIONS
// ============================================================================
TEST_F(NetworkUtilsTest, IsInSubnet_IPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsInSubnet_IPv4] Testing...");
    IpAddress addr(IPv4Address({192, 168, 1, 100}));
    IpAddress subnet(IPv4Address({192, 168, 1, 0}));
    
    EXPECT_TRUE(IsInSubnet(addr, subnet, 24));
    EXPECT_FALSE(IsInSubnet(addr, subnet, 28));
}

TEST_F(NetworkUtilsTest, GetNetworkAddress_IPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetNetworkAddress_IPv4] Testing...");
    IpAddress addr(IPv4Address({192, 168, 1, 100}));
    
    auto network = GetNetworkAddress(addr, 24);
    ASSERT_TRUE(network.has_value());
    
    auto* ipv4 = network->AsIPv4();
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->octets[3], 0);
}

TEST_F(NetworkUtilsTest, GetBroadcastAddress_IPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetBroadcastAddress_IPv4] Testing...");
    IPv4Address network({192, 168, 1, 0});
    
    auto broadcast = GetBroadcastAddress(network, 24);
    ASSERT_TRUE(broadcast.has_value());
    
    auto* ipv4 = broadcast->AsIPv4();
    ASSERT_NE(ipv4, nullptr);
    EXPECT_EQ(ipv4->octets[3], 255);
}

TEST_F(NetworkUtilsTest, GetAddressCount) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetAddressCount] Testing...");
    EXPECT_EQ(GetAddressCount(24, IpVersion::IPv4), 256u);
    EXPECT_EQ(GetAddressCount(30, IpVersion::IPv4), 4u);
    EXPECT_EQ(GetAddressCount(32, IpVersion::IPv4), 1u);
}

// ============================================================================
// MAC ADDRESS TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, MacAddress_ToString) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[MacAddress_ToString] Testing...");
    std::array<uint8_t, 6> bytes = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E};
    MacAddress mac(bytes);
    
    std::wstring str = mac.ToString();
    EXPECT_EQ(str, L"00-1A-2B-3C-4D-5E");
}

TEST_F(NetworkUtilsTest, MacAddress_IsValid) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[MacAddress_IsValid] Testing...");
    MacAddress valid({0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E});
    MacAddress allZero({0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    MacAddress allFF({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    
    EXPECT_TRUE(valid.IsValid());
    EXPECT_FALSE(allZero.IsValid());
    EXPECT_FALSE(allFF.IsValid());
}

TEST_F(NetworkUtilsTest, MacAddress_IsBroadcast) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[MacAddress_IsBroadcast] Testing...");
    MacAddress broadcast({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    MacAddress normal({0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E});
    
    EXPECT_TRUE(broadcast.IsBroadcast());
    EXPECT_FALSE(normal.IsBroadcast());
}

TEST_F(NetworkUtilsTest, MacAddress_IsMulticast) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[MacAddress_IsMulticast] Testing...");
    MacAddress multicast({0x01, 0x00, 0x5E, 0x00, 0x00, 0x01});
    MacAddress unicast({0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E});
    
    EXPECT_TRUE(multicast.IsMulticast());
    EXPECT_FALSE(unicast.IsMulticast());
}

TEST_F(NetworkUtilsTest, ParseMacAddress_Valid) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseMacAddress_Valid] Testing...");
    MacAddress mac;
    Error err;
    
    ASSERT_TRUE(ParseMacAddress(L"00-1A-2B-3C-4D-5E", mac, &err));
    EXPECT_EQ(mac.bytes[0], 0x00);
    EXPECT_EQ(mac.bytes[1], 0x1A);
    EXPECT_EQ(mac.bytes[5], 0x5E);
}

TEST_F(NetworkUtilsTest, ParseMacAddress_ColonSeparator) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseMacAddress_ColonSeparator] Testing...");
    MacAddress mac;
    Error err;
    
    ASSERT_TRUE(ParseMacAddress(L"00:1A:2B:3C:4D:5E", mac, &err));
    EXPECT_EQ(mac.bytes[0], 0x00);
}

TEST_F(NetworkUtilsTest, ParseMacAddress_Invalid) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseMacAddress_Invalid] Testing...");
    MacAddress mac;
    Error err;
    
    EXPECT_FALSE(ParseMacAddress(L"00-1A-2B-3C-4D", mac, &err));
    EXPECT_FALSE(ParseMacAddress(L"GG-HH-II-JJ-KK-LL", mac, &err));
    EXPECT_FALSE(ParseMacAddress(L"", mac, &err));
}

// ============================================================================
// HOSTNAME RESOLUTION (Localhost only)
// ============================================================================
TEST_F(NetworkUtilsTest, ResolveHostname_Localhost) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ResolveHostname_Localhost] Testing...");
    std::vector<IpAddress> addresses;
    Error err;
    
    ASSERT_TRUE(ResolveHostname(L"localhost", addresses, AddressFamily::Unspecified, &err));
    EXPECT_FALSE(addresses.empty());
    
    bool hasLoopback = false;
    for (const auto& addr : addresses) {
        if (addr.IsLoopback()) {
            hasLoopback = true;
            break;
        }
    }
    EXPECT_TRUE(hasLoopback);
}

TEST_F(NetworkUtilsTest, ResolveHostnameIPv4_Localhost) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ResolveHostnameIPv4_Localhost] Testing...");
    std::vector<IPv4Address> addresses;
    Error err;
    
    ASSERT_TRUE(ResolveHostnameIPv4(L"localhost", addresses, &err));
    EXPECT_FALSE(addresses.empty());
    EXPECT_TRUE(addresses[0].IsLoopback());
}

// ============================================================================
// REVERSE DNS LOOKUP (Localhost)
// ============================================================================
TEST_F(NetworkUtilsTest, ReverseLookup_Loopback) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ReverseLookup_Loopback] Testing...");
    IpAddress loopback(IPv4Address({127, 0, 0, 1}));
    std::wstring hostname;
    Error err;
    
    bool result = ReverseLookup(loopback, hostname, &err);
    if (result) {
        EXPECT_FALSE(hostname.empty());
    }
}

// ============================================================================
// NETWORK ADAPTER ENUMERATION
// ============================================================================
TEST_F(NetworkUtilsTest, GetNetworkAdapters) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetNetworkAdapters] Testing...");
    std::vector<NetworkAdapterInfo> adapters;
    Error err;
    
    ASSERT_TRUE(GetNetworkAdapters(adapters, &err));
    EXPECT_FALSE(adapters.empty());
    
    bool hasLoopback = false;
    for (const auto& adapter : adapters) {
        EXPECT_FALSE(adapter.friendlyName.empty());
        
        if (adapter.type == AdapterType::Loopback) {
            hasLoopback = true;
        }
    }
    
    EXPECT_TRUE(hasLoopback);
}

TEST_F(NetworkUtilsTest, GetLocalIpAddresses) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetLocalIpAddresses] Testing...");
    std::vector<IpAddress> addresses;
    Error err;
    
    ASSERT_TRUE(GetLocalIpAddresses(addresses, true, &err));
    EXPECT_FALSE(addresses.empty());
    
    bool hasLoopback = false;
    for (const auto& addr : addresses) {
        if (addr.IsLoopback()) {
            hasLoopback = true;
            break;
        }
    }
    EXPECT_TRUE(hasLoopback);
}

TEST_F(NetworkUtilsTest, GetLocalIpAddresses_ExcludeLoopback) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetLocalIpAddresses_ExcludeLoopback] Testing...");
    std::vector<IpAddress> addresses;
    Error err;
    
    GetLocalIpAddresses(addresses, false, &err);
    
    for (const auto& addr : addresses) {
        EXPECT_FALSE(addr.IsLoopback());
    }
}

// ============================================================================
// PING TESTS (Localhost only)
// ============================================================================
TEST_F(NetworkUtilsTest, Ping_LoopbackIPv4) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[Ping_LoopbackIPv4] Testing...");
    IpAddress loopback(IPv4Address({127, 0, 0, 1}));
    PingResult result;
    PingOptions options;
    options.timeoutMs = 2000;
    Error err;
    
	ASSERT_TRUE(Ping(loopback, result, options, &err)) << "Error Code(win32): " << err.win32 << ", Message: " << err.message;
    EXPECT_TRUE(result.success);
    EXPECT_GE(result.roundTripTimeMs, 0u);
    EXPECT_LT(result.roundTripTimeMs, 100u);
}

TEST_F(NetworkUtilsTest, Ping_LocalhostHostname) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[Ping_LocalhostHostname] Testing...");
    PingResult result;
    PingOptions options;
    options.timeoutMs = 2000;
    Error err;
    
	ASSERT_TRUE(Ping(L"localhost", result, options, &err)) << "Error Code(win32): " << err.win32 << ", Message: " << err.message;
    EXPECT_TRUE(result.success);
}

// ============================================================================
// PORT SCANNING & CONNECTION INFO
// ============================================================================
TEST_F(NetworkUtilsTest, GetActiveConnections_TCP) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetActiveConnections_TCP] Testing...");
    std::vector<ConnectionInfo> connections;
    Error err;
    
    ASSERT_TRUE(GetActiveConnections(connections, ProtocolType::TCP, &err));
}

TEST_F(NetworkUtilsTest, GetActiveConnections_UDP) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetActiveConnections_UDP] Testing...");
    std::vector<ConnectionInfo> connections;
    Error err;
    
    ASSERT_TRUE(GetActiveConnections(connections, ProtocolType::UDP, &err));
}

TEST_F(NetworkUtilsTest, GetPortsInUse_TCP) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetPortsInUse_TCP] Testing...");
    std::vector<uint16_t> ports;
    Error err;
    
    ASSERT_TRUE(GetPortsInUse(ports, ProtocolType::TCP, &err));
    EXPECT_FALSE(ports.empty());
    
    for (size_t i = 1; i < ports.size(); ++i) {
        EXPECT_LE(ports[i-1], ports[i]);
    }
}

// ============================================================================
// URL PARSING TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, ParseUrl_HttpUrl) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseUrl_HttpUrl] Testing...");
    UrlComponents components;
    Error err;
    
    ASSERT_TRUE(ParseUrl(L"http://localhost:8080/path?query=1", components, &err));
    EXPECT_EQ(components.scheme, L"http");
    EXPECT_EQ(components.host, L"localhost");
    EXPECT_EQ(components.port, 8080);
    EXPECT_EQ(components.path, L"/path");
}

TEST_F(NetworkUtilsTest, ParseUrl_HttpsUrl) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ParseUrl_HttpsUrl] Testing...");
    UrlComponents components;
    Error err;
    
    ASSERT_TRUE(ParseUrl(L"https://example.com/page", components, &err));
    EXPECT_EQ(components.scheme, L"https");
    EXPECT_EQ(components.host, L"example.com");
    EXPECT_EQ(components.port, 443);
}

TEST_F(NetworkUtilsTest, UrlEncode_SpecialCharacters) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[UrlEncode_SpecialCharacters] Testing...");
    std::wstring encoded = UrlEncode(L"hello world");
    EXPECT_EQ(encoded, L"hello+world");
}

TEST_F(NetworkUtilsTest, UrlDecode_SpecialCharacters) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[UrlDecode_SpecialCharacters] Testing...");
    std::wstring decoded = UrlDecode(L"hello+world");
    EXPECT_EQ(decoded, L"hello world");
}

TEST_F(NetworkUtilsTest, ExtractDomain_ValidUrl) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[ExtractDomain_ValidUrl] Testing...");
    std::wstring domain = ExtractDomain(L"https://www.example.com:8080/path");
    EXPECT_EQ(domain, L"www.example.com");
}

TEST_F(NetworkUtilsTest, IsValidUrl) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsValidUrl] Testing...");
    EXPECT_TRUE(IsValidUrl(L"http://localhost"));
    EXPECT_TRUE(IsValidUrl(L"https://example.com/path"));
    
    EXPECT_FALSE(IsValidUrl(L"not a url"));
}

// ============================================================================
// DOMAIN VALIDATION TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, IsValidDomain) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsValidDomain] Testing...");
    EXPECT_TRUE(IsValidDomain(L"example.com"));
    EXPECT_TRUE(IsValidDomain(L"www.example.com"));
    
    EXPECT_FALSE(IsValidDomain(L""));
    EXPECT_FALSE(IsValidDomain(L"-invalid.com"));
}

TEST_F(NetworkUtilsTest, IsValidHostname) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[IsValidHostname] Testing...");
    EXPECT_TRUE(IsValidHostname(L"localhost"));
    EXPECT_TRUE(IsValidHostname(L"my-server"));
    
    EXPECT_FALSE(IsValidHostname(L""));
}

// ============================================================================
// PROTOCOL DETECTION TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, DetectProtocol_HTTP) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[DetectProtocol_HTTP] Testing...");
    std::vector<uint8_t> httpData = {'G', 'E', 'T', ' '};
    
    std::wstring protocol;
    ASSERT_TRUE(DetectProtocol(httpData, protocol));
    EXPECT_EQ(protocol, L"HTTP");
}

TEST_F(NetworkUtilsTest, DetectProtocol_HTTPS) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[DetectProtocol_HTTPS] Testing...");
    std::vector<uint8_t> tlsData = {0x16, 0x03, 0x03, 0x00, 0x00};
    
    std::wstring protocol;
    ASSERT_TRUE(DetectProtocol(tlsData, protocol));
    EXPECT_EQ(protocol, L"HTTPS/TLS");
}

TEST_F(NetworkUtilsTest, DetectProtocol_DNS) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[DetectProtocol_DNS] Testing...");
    std::vector<uint8_t> dnsData = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    std::wstring protocol;
    ASSERT_TRUE(DetectProtocol(dnsData, protocol));
    EXPECT_EQ(protocol, L"DNS");
}

// ============================================================================
// NETWORK STATISTICS TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, GetNetworkStatistics) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetNetworkStatistics] Testing...");
    NetworkStatistics stats;
    Error err;
    
    ASSERT_TRUE(GetNetworkStatistics(stats, &err));
    EXPECT_GE(stats.bytesReceived, 0ull);
}

TEST_F(NetworkUtilsTest, CalculateBandwidth) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[CalculateBandwidth] Testing...");
    NetworkStatistics prev, current;
    prev.timestamp = std::chrono::system_clock::now() - std::chrono::seconds(1);
    prev.bytesReceived = 1000;
    prev.bytesSent = 500;
    
    current.timestamp = std::chrono::system_clock::now();
    current.bytesReceived = 2000;
    current.bytesSent = 1000;
    
    BandwidthInfo bandwidth;
    ASSERT_TRUE(CalculateBandwidth(prev, current, bandwidth));
    
    EXPECT_GT(bandwidth.currentDownloadBps, 0ull);
    EXPECT_GT(bandwidth.currentUploadBps, 0ull);
}

// ============================================================================
// ROUTING TABLE TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, GetRoutingTable) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetRoutingTable] Testing...");
    std::vector<RouteEntry> routes;
    Error err;
    
    ASSERT_TRUE(GetRoutingTable(routes, &err));
    EXPECT_FALSE(routes.empty());
    
    for (const auto& route : routes) {
        EXPECT_TRUE(route.destination.IsValid());
    }
}

// ============================================================================
// PROXY TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, GetSystemProxySettings) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetSystemProxySettings] Testing...");
    ProxyInfo proxy;
    Error err;
    
    ASSERT_TRUE(GetSystemProxySettings(proxy, &err));
}

// ============================================================================
// UTILITY FUNCTIONS TESTS
// ============================================================================
TEST_F(NetworkUtilsTest, GetProtocolName) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[GetProtocolName] Testing...");
    EXPECT_EQ(GetProtocolName(ProtocolType::TCP), L"TCP");
    EXPECT_EQ(GetProtocolName(ProtocolType::UDP), L"UDP");
}

TEST_F(NetworkUtilsTest, FormatBytes) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[FormatBytes] Testing...");
    EXPECT_EQ(FormatBytes(1024), L"1.00 KB");
    EXPECT_EQ(FormatBytes(1024 * 1024), L"1.00 MB");
}

TEST_F(NetworkUtilsTest, FormatWsaError) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[FormatWsaError] Testing...");
    std::wstring err = FormatWsaError(WSAECONNREFUSED);
    EXPECT_FALSE(err.empty());
}

// ============================================================================
// EDGE CASES
// ============================================================================
TEST_F(NetworkUtilsTest, EdgeCase_EmptyInput) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[EdgeCase_EmptyInput] Testing...");
    IPv4Address ipv4;
    Error err;
    
    EXPECT_FALSE(ParseIPv4(L"", ipv4, &err));
    EXPECT_FALSE(err.message.empty());
}

TEST_F(NetworkUtilsTest, Stress_MultipleAdapterQueries) {
    SS_LOG_INFO(L"NetworkUtils_Tests", L"[Stress_MultipleAdapterQueries] Testing...");
    for (int i = 0; i < 5; ++i) {
        std::vector<NetworkAdapterInfo> adapters;
        ASSERT_TRUE(GetNetworkAdapters(adapters));
        EXPECT_FALSE(adapters.empty());
    }
}
