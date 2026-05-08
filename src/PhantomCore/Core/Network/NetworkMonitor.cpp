/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - NETWORK MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkMonitor.cpp
 * @brief Enterprise-grade network traffic monitoring and threat detection system
 *
 * Production-level implementation of comprehensive network monitoring with
 * connection tracking, traffic analysis, C2 beaconing detection, port scanning
 * detection, and real-time filtering. Competes with enterprise-grade enterprise-grade Network,
 * Palo Alto Networks Cortex XDR.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - WFP (Windows Filtering Platform) integration for packet filtering
 * - ETW (Event Tracing for Windows) integration for network events
 * - Connection tracking with 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Protocol)
 * - C2 beaconing detection with jitter analysis
 * - Port scanning detection (SYN scan, connect scan)
 * - Data exfiltration detection (upload volume analysis)
 * - Bandwidth monitoring per process/connection
 * - Protocol identification (HTTP, HTTPS, DNS, SMB, RDP, SSH, etc.)
 * - TLS fingerprinting (JA3/JA3S)
 * - IP reputation checking via ThreatIntel
 * - GeoIP lookup for country/ASN information
 * - Filter rule engine with priority-based matching
 * - Comprehensive statistics tracking
 * - Multiple callback support (Connection, StateChange, Event, Threat)
 * - Connection history with efficient lookups
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "NetworkMonitor.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cwctype>
#include <map>
#include <deque>
#include <fstream>
#include <numeric>
#include <limits>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <fwpmu.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "fwpuclnt.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

namespace {

// ---------------------------------------------------------------------------
// Internal helpers (anonymous namespace).
// SECURITY: These helpers normalize external input before it reaches caches,
// blocklists, or log records. Every public ingress point routes through them.
// ---------------------------------------------------------------------------

// Sanitize a wide string for log output: strip CR/LF and other control chars
// to defeat log-injection (CWE-117), and truncate to a fixed bound to avoid
// flooding the log channel with attacker-controlled payloads.
[[nodiscard]] std::wstring SanitizeForLogW(std::wstring_view in) noexcept {
    std::wstring out;
    const size_t cap = NetworkMonitorConstants::MAX_LOG_FIELD_LENGTH;
    out.reserve((in.size() < cap ? in.size() : cap) + 3);
    size_t copied = 0;
    for (wchar_t c : in) {
        if (copied >= cap) {
            out.append(L"...", 3);
            break;
        }
        // Drop CR/LF and C0/C1 control codes; allow tab as space.
        if (c == L'\r' || c == L'\n' || c == L'\v' || c == L'\f') {
            out.push_back(L' ');
        } else if (c == L'\t') {
            out.push_back(L' ');
        } else if (c < 0x20 || c == 0x7F) {
            out.push_back(L'?');
        } else {
            out.push_back(c);
        }
        ++copied;
    }
    return out;
}

[[nodiscard]] std::wstring SanitizeForLogA(std::string_view in) noexcept {
    return SanitizeForLogW(Utils::StringUtils::ToWide(in));
}

// Normalize a domain name for storage / equality:
//   * lowercase ASCII (DNS is case-insensitive per RFC 1035 §2.3.3)
//   * strip a single trailing '.'
//   * reject control characters and over-length input
// Returns empty string if the input is invalid.
[[nodiscard]] std::wstring NormalizeDomain(std::wstring_view in) noexcept {
    if (in.empty() || in.size() > NetworkMonitorConstants::MAX_DOMAIN_LENGTH) {
        return std::wstring{};
    }
    std::wstring out;
    out.reserve(in.size());
    for (wchar_t c : in) {
        if (c < 0x20 || c == 0x7F || c == L' ' || c == L'\t') {
            return std::wstring{};
        }
        // ASCII case fold; non-ASCII passed through (IDN already encoded upstream).
        if (c >= L'A' && c <= L'Z') {
            c = static_cast<wchar_t>(c - L'A' + L'a');
        }
        out.push_back(c);
    }
    if (!out.empty() && out.back() == L'.') {
        out.pop_back();
    }
    if (out.empty()) {
        return std::wstring{};
    }
    return out;
}

// SECURITY: cap callers cannot grow tracker maps unboundedly. Returns true if
// the map already holds the supplied key OR if a slot is available.  When the
// cap is reached, the call is silently dropped (and the caller may log).
template <typename Map, typename Key>
[[nodiscard]] bool HasCapacityOrContains(const Map& m, const Key& k, size_t cap) noexcept {
    if (m.size() < cap) {
        return true;
    }
    return m.find(k) != m.end();
}

// IPv4 prefix → host-order mask, with safe handling for prefix==0 and clamping.
[[nodiscard]] uint32_t PrefixToMaskV4(uint8_t prefix) noexcept {
    if (prefix == 0) return 0u;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return static_cast<uint32_t>(0xFFFFFFFFu << (32u - prefix));
}

}  // unnamed namespace


// ============================================================================
// IPAddress Helper Methods
// ============================================================================

IPAddress::IPAddress(uint32_t v4) noexcept
    : type(IPAddressType::IPV4)
    , ipv4(v4)
{
    // Classify IPv4 (host byte order).
    if (v4 == 0x7F000001u) {
        classification = IPClassification::LOOPBACK;
    } else if ((v4 & 0xFF000000u) == 0x0A000000u ||      // 10.0.0.0/8
               (v4 & 0xFFF00000u) == 0xAC100000u ||      // 172.16.0.0/12
               (v4 & 0xFFFF0000u) == 0xC0A80000u) {      // 192.168.0.0/16
        classification = IPClassification::PRIVATE;
    } else if ((v4 & 0xFFFF0000u) == 0xA9FE0000u) {      // 169.254.0.0/16
        classification = IPClassification::LINK_LOCAL;
    } else if ((v4 & 0xF0000000u) == 0xE0000000u) {      // 224.0.0.0/4
        classification = IPClassification::MULTICAST;
    } else if (v4 == 0xFFFFFFFFu) {
        classification = IPClassification::BROADCAST;
    } else {
        classification = IPClassification::PUBLIC;
    }
}

IPAddress::IPAddress(const std::array<uint8_t, 16>& v6) noexcept
    : type(IPAddressType::IPV6)
    , ipv6(v6)
{
    if (v6[0] == 0xFE && (v6[1] & 0xC0) == 0x80) {
        classification = IPClassification::LINK_LOCAL;
    } else if (v6[0] == 0xFF) {
        classification = IPClassification::MULTICAST;
    } else if (std::all_of(v6.begin(), v6.end() - 1, [](uint8_t b) { return b == 0; }) &&
               v6[15] == 0x01) {
        classification = IPClassification::LOOPBACK;
    } else {
        classification = IPClassification::PUBLIC;
    }
}

IPAddress::IPAddress(std::string_view str)
{
    type = IPAddressType::UNKNOWN;
    if (str.empty()) {
        return;
    }
    // SECURITY: cap the input length defensively before constructing a heap
    // string. INET6_ADDRSTRLEN (65) bounds any well-formed textual address.
    if (str.size() >= INET6_ADDRSTRLEN) {
        return;
    }

    // Use a stack buffer to avoid heap allocation on the parse hot path and to
    // guarantee NUL termination for inet_pton.
    char buf[INET6_ADDRSTRLEN] = {0};
    std::memcpy(buf, str.data(), str.size());
    buf[str.size()] = '\0';

    // Try IPv4 first
    {
        struct in_addr v4 {};
        if (inet_pton(AF_INET, buf, &v4) == 1) {
            type = IPAddressType::IPV4;
            ipv4 = ntohl(v4.S_un.S_addr);
            if (ipv4 == 0x7F000001u) {
                classification = IPClassification::LOOPBACK;
            } else if ((ipv4 & 0xFF000000u) == 0x0A000000u ||
                       (ipv4 & 0xFFF00000u) == 0xAC100000u ||
                       (ipv4 & 0xFFFF0000u) == 0xC0A80000u) {
                classification = IPClassification::PRIVATE;
            } else if ((ipv4 & 0xFFFF0000u) == 0xA9FE0000u) {
                classification = IPClassification::LINK_LOCAL;
            } else if ((ipv4 & 0xF0000000u) == 0xE0000000u) {
                classification = IPClassification::MULTICAST;
            } else if (ipv4 == 0xFFFFFFFFu) {
                classification = IPClassification::BROADCAST;
            } else {
                classification = IPClassification::PUBLIC;
            }
            return;
        }
    }

    // Try IPv6
    {
        struct in6_addr v6 {};
        if (inet_pton(AF_INET6, buf, &v6) == 1) {
            type = IPAddressType::IPV6;
            std::memcpy(ipv6.data(), &v6, 16);
            if (ipv6[0] == 0xFE && (ipv6[1] & 0xC0) == 0x80) {
                classification = IPClassification::LINK_LOCAL;
            } else if (ipv6[0] == 0xFF) {
                classification = IPClassification::MULTICAST;
            } else if (std::all_of(ipv6.begin(), ipv6.end() - 1,
                                   [](uint8_t b) { return b == 0; }) &&
                       ipv6[15] == 0x01) {
                classification = IPClassification::LOOPBACK;
            } else {
                classification = IPClassification::PUBLIC;
            }
            return;
        }
    }
    // Parse failed — leave type = UNKNOWN.
}

IPAddress::IPAddress(std::wstring_view wstr)
    : IPAddress(Utils::StringUtils::ToNarrow(wstr))
{
}

std::string IPAddress::ToString() const {
    if (type == IPAddressType::IPV4) {
        char buffer[INET_ADDRSTRLEN] = {0};
        struct in_addr addr{};
        addr.S_un.S_addr = htonl(ipv4);
        if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN) == nullptr) {
            return "INVALID";
        }
        return std::string(buffer);
    } else if (type == IPAddressType::IPV6) {
        char buffer[INET6_ADDRSTRLEN] = {0};
        struct in6_addr addr{};
        std::memcpy(&addr, ipv6.data(), 16);
        if (inet_ntop(AF_INET6, &addr, buffer, INET6_ADDRSTRLEN) == nullptr) {
            return "INVALID";
        }
        return std::string(buffer);
    }
    return "UNKNOWN";
}

std::wstring IPAddress::ToWString() const {
    return Utils::StringUtils::ToWide(ToString());
}

bool IPAddress::IsValid() const noexcept {
    return type != IPAddressType::UNKNOWN;
}

bool IPAddress::IsPrivate() const noexcept {
    return classification == IPClassification::PRIVATE;
}

bool IPAddress::IsLoopback() const noexcept {
    return classification == IPClassification::LOOPBACK;
}

bool IPAddress::operator==(const IPAddress& other) const noexcept {
    if (type != other.type) return false;
    if (type == IPAddressType::IPV4) {
        return ipv4 == other.ipv4;
    } else if (type == IPAddressType::IPV6) {
        return ipv6 == other.ipv6;
    }
    return false;
}

bool IPAddress::operator<(const IPAddress& other) const noexcept {
    if (type != other.type) return type < other.type;
    if (type == IPAddressType::IPV4) {
        return ipv4 < other.ipv4;
    } else if (type == IPAddressType::IPV6) {
        return ipv6 < other.ipv6;
    }
    return false;
}

size_t IPAddress::Hash::operator()(const IPAddress& ip) const noexcept {
    // Boost-style hash combine.
    auto mix = [](size_t seed, size_t v) noexcept {
        seed ^= v + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2);
        return seed;
    };
    if (ip.type == IPAddressType::IPV4) {
        return mix(0, std::hash<uint32_t>{}(ip.ipv4));
    } else if (ip.type == IPAddressType::IPV6) {
        size_t seed = 0;
        for (size_t i = 0; i < 16; i += 4) {
            uint32_t chunk =
                (static_cast<uint32_t>(ip.ipv6[i + 0]) << 24) |
                (static_cast<uint32_t>(ip.ipv6[i + 1]) << 16) |
                (static_cast<uint32_t>(ip.ipv6[i + 2]) << 8)  |
                 static_cast<uint32_t>(ip.ipv6[i + 3]);
            seed = mix(seed, std::hash<uint32_t>{}(chunk));
        }
        return seed;
    }
    return 0;
}

// ============================================================================
// SocketAddress Helper Methods
// ============================================================================

std::string SocketAddress::ToString() const {
    return ip.ToString() + ":" + std::to_string(port);
}

std::wstring SocketAddress::ToWString() const {
    return Utils::StringUtils::ToWide(ToString());
}

bool SocketAddress::operator==(const SocketAddress& other) const noexcept {
    return ip == other.ip && port == other.port;
}

bool SocketAddress::operator<(const SocketAddress& other) const noexcept {
    if (ip < other.ip) return true;
    if (other.ip < ip) return false;
    return port < other.port;
}

size_t SocketAddress::Hash::operator()(const SocketAddress& addr) const noexcept {
    return IPAddress::Hash()(addr.ip) ^ (std::hash<uint16_t>()(addr.port) << 1);
}

// ============================================================================
// ConnectionTuple Helper Methods
// ============================================================================

std::string ConnectionTuple::ToString() const {
    return local.ToString() + " <-> " + remote.ToString() +
           " [" + std::string(GetProtocolTypeName(protocol)) + "]";
}

bool ConnectionTuple::operator==(const ConnectionTuple& other) const noexcept {
    return local == other.local &&
           remote == other.remote &&
           protocol == other.protocol;
}

size_t ConnectionTuple::Hash::operator()(const ConnectionTuple& tuple) const noexcept {
    return SocketAddress::Hash()(tuple.local) ^
           (SocketAddress::Hash()(tuple.remote) << 1) ^
           (std::hash<uint8_t>()(static_cast<uint8_t>(tuple.protocol)) << 2);
}

// ============================================================================
// BandwidthStats Methods
// ============================================================================

void BandwidthStats::Reset() noexcept {
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    packetsReceived.store(0, std::memory_order_relaxed);
    packetsSent.store(0, std::memory_order_relaxed);
    receiveRate.store(0, std::memory_order_relaxed);
    sendRate.store(0, std::memory_order_relaxed);
    peakReceiveRate.store(0, std::memory_order_relaxed);
    peakSendRate.store(0, std::memory_order_relaxed);
}

// ============================================================================
// NetworkMonitorConfig Factory Methods
// ============================================================================

NetworkMonitorConfig NetworkMonitorConfig::CreateDefault() noexcept {
    NetworkMonitorConfig config;
    config.enabled = true;
    config.level = MonitoringLevel::STANDARD;
    config.trackConnections = true;
    config.trackBandwidth = true;
    config.identifyProtocols = true;
    config.extractTLSInfo = false;  // Performance impact
    config.resolveHostnames = false;
    config.lookupGeoIP = false;
    config.detectBeaconing = true;
    config.detectExfiltration = true;
    config.detectPortScanning = true;
    config.checkIPReputation = true;
    config.enableFiltering = true;
    config.useKernelFiltering = false;  // Requires driver
    config.useETWProvider = true;
    return config;
}

NetworkMonitorConfig NetworkMonitorConfig::CreateHighSecurity() noexcept {
    NetworkMonitorConfig config = CreateDefault();
    config.level = MonitoringLevel::DETAILED;
    config.extractTLSInfo = true;
    config.resolveHostnames = true;
    config.lookupGeoIP = true;
    config.blockMaliciousIPs = true;
    config.blockMaliciousDomains = true;
    config.logAllConnections = true;
    config.logBlockedOnly = false;
    config.useKernelFiltering = true;
    return config;
}

NetworkMonitorConfig NetworkMonitorConfig::CreatePerformance() noexcept {
    NetworkMonitorConfig config = CreateDefault();
    config.level = MonitoringLevel::MINIMAL;
    config.extractTLSInfo = false;
    config.resolveHostnames = false;
    config.lookupGeoIP = false;
    config.detectBeaconing = false;
    config.checkIPReputation = false;
    config.enableEventSampling = true;
    config.eventSampleRate = 10;  // 1 in 10
    config.maxTrackedConnections = 100000;
    return config;
}

NetworkMonitorConfig NetworkMonitorConfig::CreateForensic() noexcept {
    NetworkMonitorConfig config = CreateHighSecurity();
    config.level = MonitoringLevel::FORENSIC;
    config.logAllConnections = true;
    config.logBandwidth = true;
    config.maxTrackedConnections = NetworkMonitorConstants::MAX_TRACKED_CONNECTIONS;
    config.connectionTimeoutMs = 3600000;  // 1 hour
    return config;
}

// ============================================================================
// NetworkMonitorStatistics Methods
// ============================================================================

void NetworkMonitorStatistics::Reset() noexcept {
    totalConnections.store(0, std::memory_order_relaxed);
    activeConnections.store(0, std::memory_order_relaxed);
    inboundConnections.store(0, std::memory_order_relaxed);
    outboundConnections.store(0, std::memory_order_relaxed);
    closedConnections.store(0, std::memory_order_relaxed);
    blockedConnections.store(0, std::memory_order_relaxed);

    totalBytesReceived.store(0, std::memory_order_relaxed);
    totalBytesSent.store(0, std::memory_order_relaxed);
    totalPacketsReceived.store(0, std::memory_order_relaxed);
    totalPacketsSent.store(0, std::memory_order_relaxed);

    filtersMatched.store(0, std::memory_order_relaxed);
    ipsBlocked.store(0, std::memory_order_relaxed);
    domainsBlocked.store(0, std::memory_order_relaxed);
    portsBlocked.store(0, std::memory_order_relaxed);

    threatsDetected.store(0, std::memory_order_relaxed);
    beaconingDetected.store(0, std::memory_order_relaxed);
    exfiltrationDetected.store(0, std::memory_order_relaxed);
    portScansDetected.store(0, std::memory_order_relaxed);

    httpConnections.store(0, std::memory_order_relaxed);
    httpsConnections.store(0, std::memory_order_relaxed);
    dnsQueries.store(0, std::memory_order_relaxed);
    smbConnections.store(0, std::memory_order_relaxed);

    eventsProcessed.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    processingTimeUs.store(0, std::memory_order_relaxed);

    errorCount.store(0, std::memory_order_relaxed);
}

// ============================================================================
// ConnectionFilter Helper Methods
// ============================================================================

bool ConnectionFilter::Matches(const ConnectionInfo& conn) const {
    try {
        // Check local IP
        if (localIp.has_value() && !(conn.tuple.local.ip == *localIp)) {
            return false;
        }

        // Check local port
        if (localPort.has_value() && conn.tuple.local.port != *localPort) {
            return false;
        }

        // Check remote IP range
        if (remoteIpRange.has_value() && !remoteIpRange->Contains(conn.tuple.remote.ip)) {
            return false;
        }

        // Check remote port
        if (remotePort.has_value() && conn.tuple.remote.port != *remotePort) {
            return false;
        }

        // Check protocol
        if (protocol.has_value() && conn.tuple.protocol != *protocol) {
            return false;
        }

        // Check application protocol
        if (appProtocol.has_value() && conn.appProtocol != *appProtocol) {
            return false;
        }

        // Check process path (case-insensitive)
        if (processPath.has_value() &&
            _wcsicmp(conn.processContext.processPath.c_str(), processPath->c_str()) != 0) {
            return false;
        }

        // Check process name
        if (processName.has_value() &&
            _wcsicmp(conn.processContext.processName.c_str(), processName->c_str()) != 0) {
            return false;
        }

        // Check PID
        if (pid.has_value() && conn.processContext.pid != *pid) {
            return false;
        }

        // Check user SID
        if (userSid.has_value() && conn.processContext.userSid != *userSid) {
            return false;
        }

        // Check remote hostname
        if (remoteHostname.has_value() && conn.remoteHostname != *remoteHostname) {
            return false;
        }

        // Check country code
        if (countryCode.has_value() && conn.remoteCountryCode != *countryCode) {
            return false;
        }

        // All criteria matched
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Filter matching failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

// ============================================================================
// IPRange Helper Methods
// ============================================================================

bool IPRange::Contains(const IPAddress& ip) const noexcept {
    if (baseAddress.type != ip.type) return false;

    if (ip.type == IPAddressType::IPV4) {
        const uint8_t pfx = (prefixLength > 32) ? 32 : prefixLength;
        const uint32_t mask = PrefixToMaskV4(pfx);
        return (baseAddress.ipv4 & mask) == (ip.ipv4 & mask);
    } else if (ip.type == IPAddressType::IPV6) {
        // IPv6 prefix comparison: byte-wise then partial-byte mask. Clamp to
        // [0,128] to defend against malformed callers and avoid shift UB.
        const uint8_t pfx = (prefixLength > 128) ? 128 : prefixLength;
        const size_t fullBytes = static_cast<size_t>(pfx) / 8u;
        const size_t remainingBits = static_cast<size_t>(pfx) % 8u;

        for (size_t i = 0; i < fullBytes; i++) {
            if (baseAddress.ipv6[i] != ip.ipv6[i]) return false;
        }

        if (remainingBits > 0 && fullBytes < 16) {
            const uint8_t mask = static_cast<uint8_t>(
                0xFFu << (8u - remainingBits));
            if ((baseAddress.ipv6[fullBytes] & mask) !=
                (ip.ipv6[fullBytes] & mask)) {
                return false;
            }
        }

        return true;
    }

    return false;
}

std::string IPRange::ToString() const {
    return baseAddress.ToString() + "/" + std::to_string(prefixLength);
}

uint64_t IPRange::GetAddressCount() const noexcept {
    if (baseAddress.type == IPAddressType::IPV4) {
        if (prefixLength >= 32) return 1;
        if (prefixLength == 0) return 0x100000000ULL;
        return 1ULL << (32u - prefixLength);
    } else if (baseAddress.type == IPAddressType::IPV6) {
        // IPv6 address count is enormous; saturate at UINT64_MAX.
        if (prefixLength >= 128) return 1;
        if (prefixLength <= 64) return std::numeric_limits<uint64_t>::max();
        return 1ULL << (128u - prefixLength);
    }
    return 0;
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct NetworkMonitorImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    NetworkMonitorConfig m_config;

    // Infrastructure
    std::shared_ptr<ThreatIntel::ThreatIntelLookup> m_threatIntel;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // Connection tracking
    std::unordered_map<uint64_t, ConnectionInfo> m_connections;  // By connection ID
    std::unordered_map<ConnectionTuple, uint64_t, ConnectionTuple::Hash> m_tupleIndex;
    mutable std::shared_mutex m_connectionsMutex;
    std::atomic<uint64_t> m_nextConnectionId{1};

    // Connection history (ring buffer)
    std::deque<ConnectionInfo> m_connectionHistory;
    std::mutex m_historyMutex;

    // Blocked entities
    std::unordered_set<IPAddress, IPAddress::Hash> m_blockedIPs;
    // SECURITY: ports are protocol-scoped — TCP/80 and UDP/80 are distinct
    // policies, otherwise sequential calls overwrite one another.
    std::set<std::pair<uint16_t, ProtocolType>> m_blockedPorts;
    std::unordered_set<std::wstring> m_blockedDomains;
    std::unordered_set<uint32_t> m_blockedProcesses;
    mutable std::shared_mutex m_blocklistMutex;

    // Filter rules (priority-sorted)
    std::map<uint64_t, ConnectionFilter> m_filters;  // (priority * 1M + ID) -> Filter
    std::mutex m_filtersMutex;
    std::atomic<uint64_t> m_nextFilterId{1};

    // Beaconing detection (per remote address)
    struct BeaconingTracker {
        std::deque<std::chrono::system_clock::time_point> connectionTimes;
        std::deque<uint64_t> bytesTransferred;
        uint32_t connectionCount{0};
    };
    std::unordered_map<SocketAddress, BeaconingTracker, SocketAddress::Hash> m_beaconingTrackers;
    mutable std::mutex m_beaconingMutex;

    // Port scanning detection (per source IP)
    struct PortScanTracker {
        std::unordered_set<uint16_t> scannedPorts;
        std::chrono::system_clock::time_point firstScan;
        std::chrono::system_clock::time_point lastScan;
    };
    std::unordered_map<IPAddress, PortScanTracker, IPAddress::Hash> m_portScanTrackers;
    mutable std::mutex m_portScanMutex;

    // Data exfiltration tracking (per process)
    struct ExfiltrationTracker {
        uint64_t totalBytesSent{0};
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point lastActivity;
        uint32_t connectionCount{0};
    };
    std::unordered_map<uint32_t, ExfiltrationTracker> m_exfiltrationTrackers;
    mutable std::mutex m_exfiltrationMutex;

    // Callbacks
    std::vector<std::pair<uint64_t, ConnectionCallback>> m_connectionCallbacks;
    std::vector<std::pair<uint64_t, StateChangeCallback>> m_stateChangeCallbacks;
    std::vector<std::pair<uint64_t, NetworkEventCallback>> m_eventCallbacks;
    std::vector<std::pair<uint64_t, FilterMatchCallback>> m_filterMatchCallbacks;
    std::vector<std::pair<uint64_t, ThreatDetectionCallback>> m_threatCallbacks;
    std::vector<std::pair<uint64_t, BandwidthAlertCallback>> m_bandwidthCallbacks;
    std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Legacy single-slot connection callback (the SetConnectionCallback bridge
    // for older integrations that pre-date the multi-callback Register* API).
    ConnectionCallback m_legacyCallback;
    mutable std::shared_mutex m_legacyCallbackMutex;

    // Statistics
    NetworkMonitorStatistics m_statistics;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // Monitoring thread
    HANDLE m_hMonitorThread = nullptr;
    HANDLE m_hStopEvent = nullptr;

    // WFP engine session handle (opened via FwpmEngineOpen0)
    HANDLE m_hWfpEngine = nullptr;

    // WFP filter IDs for active block rules (for cleanup/removal)
    std::unordered_map<uint64_t, uint64_t> m_wfpFilterIds;  // internal ID → WFP filter ID
    std::atomic<uint64_t> m_nextWfpBlockId{1};
    mutable std::mutex m_wfpMutex;

    // Blocked IP ranges (local tracking + WFP enforcement)
    struct BlockedRange {
        IPRange range;
        BlockReason reason;
        uint64_t wfpFilterIdV4{0};
        uint64_t wfpFilterIdV6{0};
    };
    std::vector<BlockedRange> m_blockedRanges;
    mutable std::mutex m_blockedRangesMutex;

    // Constructor
    NetworkMonitorImpl() = default;

    // Destructor
    ~NetworkMonitorImpl() {
        StopMonitoring();
    }

    void StopMonitoring() {
        if (m_hStopEvent) {
            SetEvent(m_hStopEvent);
        }

        if (m_hMonitorThread) {
            WaitForSingleObject(m_hMonitorThread, 5000);
            CloseHandle(m_hMonitorThread);
            m_hMonitorThread = nullptr;
        }

        if (m_hStopEvent) {
            CloseHandle(m_hStopEvent);
            m_hStopEvent = nullptr;
        }

        if (m_hWfpEngine) {
            // Remove all active WFP block filters before closing
            {
                std::lock_guard<std::mutex> wfpLock(m_wfpMutex);
                for (auto& [internalId, filterId] : m_wfpFilterIds) {
                    FwpmFilterDeleteById0(m_hWfpEngine, filterId);
                }
                m_wfpFilterIds.clear();
            }
            {
                std::lock_guard<std::mutex> rangeLock(m_blockedRangesMutex);
                for (auto& br : m_blockedRanges) {
                    if (br.wfpFilterIdV4) FwpmFilterDeleteById0(m_hWfpEngine, br.wfpFilterIdV4);
                    if (br.wfpFilterIdV6) FwpmFilterDeleteById0(m_hWfpEngine, br.wfpFilterIdV6);
                }
                m_blockedRanges.clear();
            }
            FwpmEngineClose0(m_hWfpEngine);
            m_hWfpEngine = nullptr;
        }
    }

    // Identify application protocol from port
    ApplicationProtocol IdentifyProtocol(uint16_t port, ProtocolType protocol) const {
        if (protocol == ProtocolType::TCP) {
            switch (port) {
                case NetworkMonitorConstants::PORT_HTTP: return ApplicationProtocol::HTTP;
                case NetworkMonitorConstants::PORT_HTTPS: return ApplicationProtocol::HTTPS;
                case NetworkMonitorConstants::PORT_SMB: return ApplicationProtocol::SMB;
                case NetworkMonitorConstants::PORT_RDP: return ApplicationProtocol::RDP;
                case NetworkMonitorConstants::PORT_SSH: return ApplicationProtocol::SSH;
                case NetworkMonitorConstants::PORT_FTP: return ApplicationProtocol::FTP;
                case NetworkMonitorConstants::PORT_SMTP: return ApplicationProtocol::SMTP;
                case NetworkMonitorConstants::PORT_IMAP: return ApplicationProtocol::IMAP;
                case NetworkMonitorConstants::PORT_POP3: return ApplicationProtocol::POP3;
                default: return ApplicationProtocol::UNKNOWN;
            }
        } else if (protocol == ProtocolType::UDP) {
            if (port == NetworkMonitorConstants::PORT_DNS) {
                return ApplicationProtocol::DNS;
            }
        }
        return ApplicationProtocol::UNKNOWN;
    }

    // Determine connection direction
    ConnectionDirection DetermineDirection(const IPAddress& localIp, const IPAddress& remoteIp) const {
        if (localIp.IsLoopback() || remoteIp.IsLoopback()) {
            return ConnectionDirection::LOCAL;
        }

        if (localIp.IsPrivate() && remoteIp.IsPrivate()) {
            return ConnectionDirection::INTERNAL;
        }

        if (localIp.IsPrivate() && !remoteIp.IsPrivate()) {
            return ConnectionDirection::OUTBOUND;
        }

        if (!localIp.IsPrivate() && remoteIp.IsPrivate()) {
            return ConnectionDirection::INBOUND;
        }

        // Default to outbound for external-to-external
        return ConnectionDirection::OUTBOUND;
    }

    // Check filter rules
    std::optional<ConnectionFilter> CheckFilters(const ConnectionInfo& conn) {
        std::lock_guard<std::mutex> lock(m_filtersMutex);

        for (const auto& [key, filter] : m_filters) {
            if (!filter.isEnabled) continue;

            // Check expiration
            if (filter.isTemporary) {
                if (std::chrono::system_clock::now() > filter.expiresAt) {
                    continue;
                }
            }

            // Check match
            if (filter.Matches(conn)) {
                return filter;
            }
        }

        return std::nullopt;
    }

    // Analyze for C2 beaconing
    BeaconingAnalysis AnalyzeBeaconingInternal(const SocketAddress& remote) const {
        BeaconingAnalysis analysis;
        analysis.destination = remote;

        try {
            std::lock_guard<std::mutex> lock(m_beaconingMutex);

            auto it = m_beaconingTrackers.find(remote);
            if (it == m_beaconingTrackers.end() || it->second.connectionTimes.size() < NetworkMonitorConstants::BEACONING_MIN_CONNECTIONS) {
                return analysis;  // Not enough data
            }

            const auto& tracker = it->second;
            analysis.connectionCount = tracker.connectionCount;
            analysis.connectionTimes = std::vector<std::chrono::system_clock::time_point>(
                tracker.connectionTimes.begin(), tracker.connectionTimes.end()
            );

            if (tracker.connectionTimes.size() < 2) return analysis;

            analysis.firstSeen = tracker.connectionTimes.front();
            analysis.lastSeen = tracker.connectionTimes.back();

            // Calculate intervals (clamp negative deltas — wall-clock can move
            // backward, e.g. NTP step or DST adjustment, and a negative interval
            // would corrupt the average and stddev computation below).
            std::vector<std::chrono::milliseconds> intervals;
            intervals.reserve(tracker.connectionTimes.size());
            for (size_t i = 1; i < tracker.connectionTimes.size(); i++) {
                auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
                    tracker.connectionTimes[i] - tracker.connectionTimes[i-1]
                );
                if (interval.count() < 0) {
                    interval = std::chrono::milliseconds(0);
                }
                intervals.push_back(interval);
            }

            if (intervals.empty()) return analysis;

            // Calculate average interval
            auto totalMs = std::accumulate(intervals.begin(), intervals.end(),
                                          std::chrono::milliseconds(0));
            analysis.averageInterval = totalMs / static_cast<int64_t>(intervals.size());

            // Calculate standard deviation
            double avgMs = static_cast<double>(analysis.averageInterval.count());
            double variance = 0.0;
            for (const auto& interval : intervals) {
                double diff = static_cast<double>(interval.count()) - avgMs;
                variance += diff * diff;
            }
            variance /= intervals.size();
            analysis.intervalStdDev = std::chrono::milliseconds(
                static_cast<int64_t>(std::sqrt(variance))
            );

            // Calculate jitter percentage
            if (avgMs > 0) {
                analysis.jitterPercent = (static_cast<double>(analysis.intervalStdDev.count()) / avgMs) * 100.0;
            }

            // Calculate total bytes
            analysis.totalBytesSent = std::accumulate(
                tracker.bytesTransferred.begin(),
                tracker.bytesTransferred.end(),
                0ULL
            );

            // Beaconing heuristic:
            // - Regular intervals (low jitter < 20%)
            // - Minimum 10 connections
            // - Consistent timing
            bool regularIntervals = analysis.jitterPercent < 20.0;
            bool sufficientConnections = analysis.connectionCount >= NetworkMonitorConstants::BEACONING_MIN_CONNECTIONS;
            bool consistentTiming = analysis.averageInterval.count() > 1000 &&
                                   analysis.averageInterval.count() < 3600000;  // 1s to 1h

            int beaconScore = 0;
            if (regularIntervals) beaconScore++;
            if (sufficientConnections) beaconScore++;
            if (consistentTiming) beaconScore++;

            analysis.beaconingScore = static_cast<double>(beaconScore) / 3.0;
            analysis.isLikelyBeaconing = beaconScore >= 2;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Beaconing analysis failed - %ls",
                               Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return analysis;
    }

    // Analyze for data exfiltration
    DataExfiltrationAnalysis AnalyzeExfiltrationInternal(uint32_t pid) const {
        DataExfiltrationAnalysis analysis;
        analysis.pid = pid;

        try {
            std::lock_guard<std::mutex> lock(m_exfiltrationMutex);

            auto it = m_exfiltrationTrackers.find(pid);
            if (it == m_exfiltrationTrackers.end()) {
                return analysis;  // No data
            }

            const auto& tracker = it->second;
            analysis.totalBytesSent = tracker.totalBytesSent;
            analysis.connectionCount = tracker.connectionCount;

            auto timeSpan = std::chrono::duration_cast<std::chrono::milliseconds>(
                tracker.lastActivity - tracker.startTime
            );
            if (timeSpan.count() < 0) {
                timeSpan = std::chrono::milliseconds(0);
            }
            analysis.timeSpan = timeSpan;

            if (timeSpan.count() > 0) {
                analysis.bytesPerSecond = static_cast<double>(tracker.totalBytesSent) /
                                         (static_cast<double>(timeSpan.count()) / 1000.0);
            }

            // Exfiltration heuristic:
            // - Large volume (>100 MB)
            // - High rate
            bool largeVolume = analysis.totalBytesSent > NetworkMonitorConstants::SUSPICIOUS_UPLOAD_BYTES;
            bool highRate = analysis.bytesPerSecond > (10 * 1024 * 1024);  // >10 MB/s
            bool manyConnections = analysis.connectionCount > 50;

            int exfilScore = 0;
            if (largeVolume) exfilScore++;
            if (highRate) exfilScore++;
            if (manyConnections) exfilScore++;

            analysis.exfiltrationScore = static_cast<double>(exfilScore) / 3.0;
            analysis.isLikelyExfiltration = exfilScore >= 2;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Exfiltration analysis failed - %ls",
                               Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return analysis;
    }

    // Analyze for port scanning
    PortScanAnalysis AnalyzePortScanningInternal(const IPAddress& sourceIp) const {
        PortScanAnalysis analysis;
        analysis.sourceIp = sourceIp;

        try {
            std::lock_guard<std::mutex> lock(m_portScanMutex);

            auto it = m_portScanTrackers.find(sourceIp);
            if (it == m_portScanTrackers.end()) {
                return analysis;  // No data
            }

            const auto& tracker = it->second;
            analysis.scannedPorts = std::vector<uint16_t>(
                tracker.scannedPorts.begin(), tracker.scannedPorts.end()
            );
            analysis.totalPortsScanned = static_cast<uint32_t>(tracker.scannedPorts.size());
            analysis.startTime = tracker.firstScan;

            analysis.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                tracker.lastScan - tracker.firstScan
            );
            if (analysis.scanDuration.count() < 0) {
                analysis.scanDuration = std::chrono::milliseconds(0);
            }

            // Port scan heuristic:
            // - Many ports (>50)
            // - Short duration (<60 seconds)
            bool manyPorts = analysis.totalPortsScanned > NetworkMonitorConstants::PORT_SCAN_THRESHOLD;
            bool shortDuration = analysis.scanDuration.count() < 60000;
            bool rapidRate = manyPorts && shortDuration;

            int scanScore = 0;
            if (manyPorts) scanScore++;
            if (shortDuration) scanScore++;
            if (rapidRate) scanScore++;

            analysis.scanScore = static_cast<double>(scanScore) / 3.0;
            analysis.isLikelyScan = scanScore >= 2;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Port scan analysis failed - %ls",
                               Utils::StringUtils::ToWide(e.what()).c_str());
        }

        return analysis;
    }

    // Update beaconing tracker
    void UpdateBeaconingTracker(const SocketAddress& remote, uint64_t bytes) {
        std::lock_guard<std::mutex> lock(m_beaconingMutex);

        // SECURITY: cap distinct destinations to prevent state explosion under
        // hostile traffic that opens connections to many random remotes.
        if (!HasCapacityOrContains(m_beaconingTrackers, remote,
                                   NetworkMonitorConstants::MAX_BEACONING_TRACKERS)) {
            return;
        }

        auto& tracker = m_beaconingTrackers[remote];
        tracker.connectionTimes.push_back(std::chrono::system_clock::now());
        tracker.bytesTransferred.push_back(bytes);
        tracker.connectionCount++;

        // Keep only the most recent samples per tracker.
        while (tracker.connectionTimes.size() > NetworkMonitorConstants::MAX_TRACKER_HISTORY) {
            tracker.connectionTimes.pop_front();
        }
        while (tracker.bytesTransferred.size() > NetworkMonitorConstants::MAX_TRACKER_HISTORY) {
            tracker.bytesTransferred.pop_front();
        }
    }

    // Update port scan tracker. Snapshot any threat-detection result under the
    // lock, then release the lock before invoking callbacks/log to avoid the
    // self-deadlock that the previous AnalyzePortScanningInternal-while-locked
    // pattern guaranteed (CWE-833).
    void UpdatePortScanTracker(const IPAddress& sourceIp, uint16_t port) {
        bool detected = false;
        size_t portsObserved = 0;
        long long durationSec = 0;
        {
            std::lock_guard<std::mutex> lock(m_portScanMutex);

            if (!HasCapacityOrContains(m_portScanTrackers, sourceIp,
                                       NetworkMonitorConstants::MAX_PORTSCAN_TRACKERS)) {
                return;
            }

            auto& tracker = m_portScanTrackers[sourceIp];
            const auto now = std::chrono::system_clock::now();

            if (tracker.scannedPorts.empty()) {
                tracker.firstScan = now;
            }

            tracker.scannedPorts.insert(port);
            tracker.lastScan = now;

            if (tracker.scannedPorts.size() >= NetworkMonitorConstants::PORT_SCAN_THRESHOLD) {
                const auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                    tracker.lastScan - tracker.firstScan);
                if (duration.count() >= 0 && duration.count() < 60) {
                    detected = true;
                    portsObserved = tracker.scannedPorts.size();
                    durationSec = static_cast<long long>(duration.count());
                }
            }
        }

        if (detected) {
            // Re-acquire briefly via the analyzer (which takes its own lock).
            InvokeThreatCallbacks(0, ThreatIndicator::PORT_SCANNING,
                                  AnalyzePortScanningInternal(sourceIp));

            m_statistics.portScansDetected.fetch_add(1, std::memory_order_relaxed);
            m_statistics.threatsDetected.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_WARN(L"Network",
                        L"NetworkMonitor: Port scan detected from %ls - %zu ports in %lld seconds",
                        sourceIp.ToWString().c_str(), portsObserved, durationSec);
        }
    }

    // Update exfiltration tracker — same snapshot-then-release pattern.
    void UpdateExfiltrationTracker(uint32_t pid, uint64_t bytesSent) {
        bool overThreshold = false;
        uint64_t totalBytes = 0;
        {
            std::lock_guard<std::mutex> lock(m_exfiltrationMutex);

            if (!HasCapacityOrContains(m_exfiltrationTrackers, pid,
                                       NetworkMonitorConstants::MAX_EXFIL_TRACKERS)) {
                return;
            }

            auto& tracker = m_exfiltrationTrackers[pid];
            const auto now = std::chrono::system_clock::now();

            if (tracker.connectionCount == 0) {
                tracker.startTime = now;
            }

            tracker.totalBytesSent += bytesSent;
            tracker.lastActivity = now;
            tracker.connectionCount++;

            if (tracker.totalBytesSent > NetworkMonitorConstants::SUSPICIOUS_UPLOAD_BYTES) {
                overThreshold = true;
                totalBytes = tracker.totalBytesSent;
            }
        }

        if (overThreshold) {
            auto analysis = AnalyzeExfiltrationInternal(pid);
            if (analysis.isLikelyExfiltration) {
                InvokeThreatCallbacks(0, ThreatIndicator::DATA_EXFILTRATION, analysis);

                m_statistics.exfiltrationDetected.fetch_add(1, std::memory_order_relaxed);
                m_statistics.threatsDetected.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_WARN(L"Network",
                            L"NetworkMonitor: Data exfiltration detected - PID %u sent %llu bytes",
                            pid, static_cast<unsigned long long>(totalBytes));
            }
        }
    }

    // Process new connection
    void ProcessNewConnection(const ConnectionInfo& conn) {
        try {
            m_statistics.totalConnections.fetch_add(1, std::memory_order_relaxed);
            m_statistics.activeConnections.fetch_add(1, std::memory_order_relaxed);

            if (conn.direction == ConnectionDirection::INBOUND) {
                m_statistics.inboundConnections.fetch_add(1, std::memory_order_relaxed);
            } else if (conn.direction == ConnectionDirection::OUTBOUND) {
                m_statistics.outboundConnections.fetch_add(1, std::memory_order_relaxed);
            }

            // Update protocol statistics
            if (conn.appProtocol == ApplicationProtocol::HTTP) {
                m_statistics.httpConnections.fetch_add(1, std::memory_order_relaxed);
            } else if (conn.appProtocol == ApplicationProtocol::HTTPS) {
                m_statistics.httpsConnections.fetch_add(1, std::memory_order_relaxed);
            } else if (conn.appProtocol == ApplicationProtocol::DNS) {
                m_statistics.dnsQueries.fetch_add(1, std::memory_order_relaxed);
            } else if (conn.appProtocol == ApplicationProtocol::SMB ||
                      conn.appProtocol == ApplicationProtocol::SMB2) {
                m_statistics.smbConnections.fetch_add(1, std::memory_order_relaxed);
            }

            // Invoke connection callbacks (multi-slot)
            InvokeConnectionCallbacks(conn);

            // Legacy single-slot connection callback (copy-and-release pattern
            // so a re-entrant SetConnectionCallback does not self-deadlock).
            ConnectionCallback legacy;
            {
                std::shared_lock<std::shared_mutex> rl(m_legacyCallbackMutex);
                legacy = m_legacyCallback;
            }
            if (legacy) {
                try {
                    legacy(conn);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"Network", L"NetworkMonitor: Legacy callback failed - %ls",
                                 Utils::StringUtils::ToWide(e.what()).c_str());
                } catch (...) {
                    SS_LOG_ERROR(L"Network",
                                 L"NetworkMonitor: Legacy callback threw non-std exception");
                }
            }

            // Invoke event callbacks
            NetworkEvent event;
            // SECURITY/TELEMETRY: eventId is monotonic from a dedicated counter
            // so eventsProcessed remains a true count of dispatched events.
            event.eventId = m_statistics.eventsProcessed.fetch_add(1, std::memory_order_relaxed) + 1;
            event.timestamp = std::chrono::system_clock::now();
            event.type = NetworkEvent::Type::CONNECTION_OPENED;
            event.connectionId = conn.connectionId;
            event.tuple = conn.tuple;
            event.pid = conn.processContext.pid;
            event.processName = conn.processContext.processName;
            event.details = conn;

            InvokeEventCallbacks(event);

            const std::string appName(GetAppProtocolName(conn.appProtocol));
            SS_LOG_INFO(L"Network", L"NetworkMonitor: Connection opened - %ls [%hs] by %ls (PID %u)",
                              Utils::StringUtils::ToWide(conn.tuple.ToString()).c_str(),
                              appName.c_str(),
                              SanitizeForLogW(conn.processContext.processName).c_str(),
                              conn.processContext.pid);

        } catch (const std::exception& e) {
            m_statistics.errorCount.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Process new connection failed - %ls",
                               Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    // Callback invocation helpers.
    //
    // SECURITY/CORRECTNESS: each helper snapshots the callback list under the
    // lock, then releases the lock before invoking. This prevents (a) deadlocks
    // when a user callback re-enters Register*/Unregister* (which take the same
    // mutex) and (b) priority inversion where a slow consumer stalls every
    // producer thread that wants to dispatch.
    void InvokeConnectionCallbacks(const ConnectionInfo& conn) {
        decltype(m_connectionCallbacks) snapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            snapshot = m_connectionCallbacks;
        }
        for (const auto& [id, callback] : snapshot) {
            try {
                if (callback) callback(conn);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NetworkMonitor: Connection callback %llu failed - %ls",
                                   id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"Network",
                             L"NetworkMonitor: Connection callback %llu threw non-std exception", id);
            }
        }
    }

    void InvokeStateChangeCallbacks(uint64_t connId, ConnectionState oldState, ConnectionState newState) {
        decltype(m_stateChangeCallbacks) snapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            snapshot = m_stateChangeCallbacks;
        }
        for (const auto& [id, callback] : snapshot) {
            try {
                if (callback) callback(connId, oldState, newState);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NetworkMonitor: State change callback %llu failed - %ls",
                                   id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"Network",
                             L"NetworkMonitor: State callback %llu threw non-std exception", id);
            }
        }
    }

    void InvokeEventCallbacks(const NetworkEvent& event) {
        decltype(m_eventCallbacks) snapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            snapshot = m_eventCallbacks;
        }
        for (const auto& [id, callback] : snapshot) {
            try {
                if (callback) callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NetworkMonitor: Event callback %llu failed - %ls",
                                   id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"Network",
                             L"NetworkMonitor: Event callback %llu threw non-std exception", id);
            }
        }
    }

    void InvokeThreatCallbacks(uint64_t connId, ThreatIndicator indicator,
                              const std::variant<BeaconingAnalysis, DataExfiltrationAnalysis, PortScanAnalysis>& analysis) {
        decltype(m_threatCallbacks) snapshot;
        {
            std::lock_guard<std::mutex> lock(m_callbacksMutex);
            snapshot = m_threatCallbacks;
        }
        for (const auto& [id, callback] : snapshot) {
            try {
                if (callback) callback(connId, indicator, analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NetworkMonitor: Threat callback %llu failed - %ls",
                                   id, Utils::StringUtils::ToWide(e.what()).c_str());
            } catch (...) {
                SS_LOG_ERROR(L"Network",
                             L"NetworkMonitor: Threat callback %llu threw non-std exception", id);
            }
        }
    }

    // Monitor thread procedure.
    // SECURITY/RELIABILITY: any escape from the loop (exception or return)
    // must clear m_running so callers' Stop()/Shutdown() observe the
    // degraded state and do not hang waiting for an unresponsive worker.
    static DWORD WINAPI MonitorThreadProc(LPVOID lpParameter) {
        NetworkMonitorImpl* pThis = static_cast<NetworkMonitorImpl*>(lpParameter);
        if (!pThis) return 1;

        try {
            SS_LOG_INFO(L"Network", L"NetworkMonitor: Monitor thread started");

            // Main monitoring loop
            while (pThis->m_running.load(std::memory_order_acquire)) {
                if (WaitForSingleObject(pThis->m_hStopEvent, 1000) == WAIT_OBJECT_0) {
                    break;
                }
                pThis->PerformCleanup();
            }

            SS_LOG_INFO(L"Network", L"NetworkMonitor: Monitor thread stopped");
            return 0;

        } catch (const std::exception& e) {
            pThis->m_running.store(false, std::memory_order_release);
            SS_LOG_FATAL(L"Network", L"NetworkMonitor: Monitor thread aborted - %ls",
                                Utils::StringUtils::ToWide(e.what()).c_str());
            return 1;
        } catch (...) {
            pThis->m_running.store(false, std::memory_order_release);
            SS_LOG_FATAL(L"Network", L"NetworkMonitor: Monitor thread aborted - non-std exception");
            return 1;
        }
    }

    void PerformCleanup() {
        try {
            // Clean up closed connections
            {
                std::unique_lock<std::shared_mutex> lock(m_connectionsMutex);
                const auto now = std::chrono::system_clock::now();
                const auto timeout = std::chrono::milliseconds(m_config.connectionTimeoutMs);

                for (auto it = m_connections.begin(); it != m_connections.end();) {
                    const auto& conn = it->second;
                    auto idleTime = now - conn.lastActivityTime;

                    if (conn.state == ConnectionState::CLOSED ||
                        std::chrono::duration_cast<std::chrono::milliseconds>(idleTime) > timeout) {

                        // Remove from tuple index
                        m_tupleIndex.erase(conn.tuple);

                        // Move to history
                        {
                            std::lock_guard<std::mutex> histLock(m_historyMutex);
                            m_connectionHistory.push_back(conn);
                            if (m_connectionHistory.size() > NetworkMonitorConstants::MAX_CONNECTION_HISTORY) {
                                m_connectionHistory.pop_front();
                            }
                        }

                        it = m_connections.erase(it);
                        m_statistics.activeConnections.fetch_sub(1, std::memory_order_relaxed);
                    } else {
                        ++it;
                    }
                }
            }

            // Clean up old tracking data
            {
                std::lock_guard<std::mutex> lock(m_beaconingMutex);
                const auto cutoff = std::chrono::system_clock::now() -
                                   std::chrono::milliseconds(NetworkMonitorConstants::BEACONING_ANALYSIS_WINDOW_MS);

                for (auto it = m_beaconingTrackers.begin(); it != m_beaconingTrackers.end();) {
                    if (it->second.connectionTimes.empty() ||
                        it->second.connectionTimes.back() < cutoff) {
                        it = m_beaconingTrackers.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Reap stale port-scan trackers (no activity for > 10 minutes).
            {
                std::lock_guard<std::mutex> lock(m_portScanMutex);
                const auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(10);
                for (auto it = m_portScanTrackers.begin(); it != m_portScanTrackers.end();) {
                    if (it->second.lastScan < cutoff) {
                        it = m_portScanTrackers.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Reap stale exfiltration trackers (no activity for > 10 minutes).
            {
                std::lock_guard<std::mutex> lock(m_exfiltrationMutex);
                const auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(10);
                for (auto it = m_exfiltrationTrackers.begin(); it != m_exfiltrationTrackers.end();) {
                    if (it->second.lastActivity < cutoff) {
                        it = m_exfiltrationTrackers.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Cleanup failed - %ls",
                               Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }
};

// ============================================================================
// Singleton Implementation
// ============================================================================

std::atomic<bool> NetworkMonitor::s_instanceCreated{false};

NetworkMonitor& NetworkMonitor::Instance() noexcept {
    static NetworkMonitor instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool NetworkMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// Lifecycle
// ============================================================================

NetworkMonitor::NetworkMonitor()
    : m_impl(std::make_unique<NetworkMonitorImpl>())
{
    SS_LOG_INFO(L"Network", L"NetworkMonitor: Constructor called");
}

NetworkMonitor::~NetworkMonitor() {
    Shutdown();
    SS_LOG_INFO(L"Network", L"NetworkMonitor: Destructor called");
}

bool NetworkMonitor::Initialize(const NetworkMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"Network", L"NetworkMonitor: Already initialized");
        return true;
    }

    bool wsaStarted = false;
    try {
        m_impl->m_config = config;

        // Initialize infrastructure
        m_impl->m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelLookup>();
        m_impl->m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        // Initialize Winsock
        WSADATA wsaData{};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: WSAStartup failed (code %d)", WSAGetLastError());
            m_impl->m_threatIntel.reset();
            m_impl->m_whitelist.reset();
            return false;
        }
        wsaStarted = true;

        // Initialize WFP engine session for network filtering (best-effort).
        {
            FWPM_SESSION0 session = {};
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // Filters auto-removed on process exit
            session.displayData.name = const_cast<wchar_t*>(L"ShadowStrike NetworkMonitor");
            session.displayData.description = const_cast<wchar_t*>(L"ShadowStrike EDR network filtering session");
            session.txnWaitTimeoutInMSec = 10000;

            DWORD wfpResult = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                                              &m_impl->m_hWfpEngine);
            if (wfpResult != ERROR_SUCCESS) {
                SS_LOG_WARN(L"Network", L"NetworkMonitor: WFP engine open failed (0x%08X) - "
                            L"network filtering will use software-only blocklists", wfpResult);
                m_impl->m_hWfpEngine = nullptr;
                // Non-fatal: software blocklists still work via IsBlocked() checks
            } else {
                SS_LOG_INFO(L"Network", L"NetworkMonitor: WFP engine session established");
            }
        }

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Initialization failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        // Roll back partial init so a re-Initialize attempt finds clean state.
        if (m_impl->m_hWfpEngine) {
            FwpmEngineClose0(m_impl->m_hWfpEngine);
            m_impl->m_hWfpEngine = nullptr;
        }
        if (wsaStarted) {
            WSACleanup();
        }
        m_impl->m_threatIntel.reset();
        m_impl->m_whitelist.reset();
        return false;
    }
}

bool NetworkMonitor::Start() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Not initialized");
        return false;
    }

    if (m_impl->m_running.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"Network", L"NetworkMonitor: Already running");
        return true;
    }

    try {
        // Create stop event
        m_impl->m_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!m_impl->m_hStopEvent) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Failed to create stop event");
            return false;
        }

        m_impl->m_running.store(true, std::memory_order_release);

        // Create monitor thread
        m_impl->m_hMonitorThread = CreateThread(
            nullptr,
            0,
            NetworkMonitorImpl::MonitorThreadProc,
            m_impl.get(),
            0,
            nullptr
        );

        if (!m_impl->m_hMonitorThread) {
            m_impl->m_running.store(false, std::memory_order_release);
            CloseHandle(m_impl->m_hStopEvent);
            m_impl->m_hStopEvent = nullptr;
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Failed to create monitor thread");
            return false;
        }

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Started successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Start failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void NetworkMonitor::Stop() {
    if (!m_impl->m_running.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_impl->m_running.store(false, std::memory_order_release);
        m_impl->StopMonitoring();

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Stopped");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Stop failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void NetworkMonitor::Shutdown() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        Stop();

        // Clear all data
        {
            std::unique_lock<std::shared_mutex> connLock(m_impl->m_connectionsMutex);
            m_impl->m_connections.clear();
            m_impl->m_tupleIndex.clear();
        }

        {
            std::lock_guard<std::mutex> histLock(m_impl->m_historyMutex);
            m_impl->m_connectionHistory.clear();
        }

        {
            std::unique_lock<std::shared_mutex> blockLock(m_impl->m_blocklistMutex);
            m_impl->m_blockedIPs.clear();
            m_impl->m_blockedPorts.clear();
            m_impl->m_blockedDomains.clear();
            m_impl->m_blockedProcesses.clear();
        }

        {
            std::lock_guard<std::mutex> filterLock(m_impl->m_filtersMutex);
            m_impl->m_filters.clear();
        }

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_connectionCallbacks.clear();
            m_impl->m_stateChangeCallbacks.clear();
            m_impl->m_eventCallbacks.clear();
            m_impl->m_filterMatchCallbacks.clear();
            m_impl->m_threatCallbacks.clear();
            m_impl->m_bandwidthCallbacks.clear();
        }

        {
            std::unique_lock<std::shared_mutex> legacyLock(m_impl->m_legacyCallbackMutex);
            m_impl->m_legacyCallback = nullptr;
        }

        // Trackers — release attacker-influenced state.
        {
            std::lock_guard<std::mutex> lk(m_impl->m_beaconingMutex);
            m_impl->m_beaconingTrackers.clear();
        }
        {
            std::lock_guard<std::mutex> lk(m_impl->m_portScanMutex);
            m_impl->m_portScanTrackers.clear();
        }
        {
            std::lock_guard<std::mutex> lk(m_impl->m_exfiltrationMutex);
            m_impl->m_exfiltrationTrackers.clear();
        }

        // Release infrastructure
        m_impl->m_threatIntel.reset();
        m_impl->m_whitelist.reset();

        // Cleanup Winsock
        WSACleanup();

        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Shutdown error - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

bool NetworkMonitor::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool NetworkMonitor::IsRunning() const noexcept {
    return m_impl->m_running.load(std::memory_order_acquire);
}

NetworkMonitorConfig NetworkMonitor::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool NetworkMonitor::UpdateConfig(const NetworkMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"Network", L"NetworkMonitor: Configuration updated");
    return true;
}

// ============================================================================
// Connection Management
// ============================================================================

std::optional<ConnectionInfo> NetworkMonitor::GetConnection(uint64_t connectionId) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    auto it = m_impl->m_connections.find(connectionId);
    if (it != m_impl->m_connections.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::optional<ConnectionInfo> NetworkMonitor::GetConnectionByTuple(const ConnectionTuple& tuple) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    auto it = m_impl->m_tupleIndex.find(tuple);
    if (it != m_impl->m_tupleIndex.end()) {
        auto connIt = m_impl->m_connections.find(it->second);
        if (connIt != m_impl->m_connections.end()) {
            return connIt->second;
        }
    }

    return std::nullopt;
}

std::vector<ConnectionInfo> NetworkMonitor::GetActiveConnections() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    std::vector<ConnectionInfo> connections;
    connections.reserve(m_impl->m_connections.size());

    for (const auto& [id, conn] : m_impl->m_connections) {
        connections.push_back(conn);
    }

    return connections;
}

std::vector<EnhancedConnectionInfo> NetworkMonitor::GetActiveConnectionsSnapshot() {
    auto connections = GetActiveConnections();
    std::vector<EnhancedConnectionInfo> enhanced;
    enhanced.reserve(connections.size());

    for (const auto& conn : connections) {
        EnhancedConnectionInfo enh;
        enh.fullInfo = conn;
        enhanced.push_back(enh);
    }

    return enhanced;
}

std::vector<ConnectionInfo> NetworkMonitor::GetConnectionsByProcess(uint32_t pid) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    std::vector<ConnectionInfo> connections;

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.processContext.pid == pid) {
            connections.push_back(conn);
        }
    }

    return connections;
}

std::vector<ConnectionInfo> NetworkMonitor::GetConnectionsByRemoteIP(const IPAddress& ip) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    std::vector<ConnectionInfo> connections;

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.tuple.remote.ip == ip) {
            connections.push_back(conn);
        }
    }

    return connections;
}

bool NetworkMonitor::IsProcessListening(uint32_t pid, uint16_t port) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.processContext.pid == pid &&
            conn.state == ConnectionState::LISTENING &&
            conn.tuple.local.port == port) {
            return true;
        }
    }

    return false;
}

uint32_t NetworkMonitor::GetListeningProcess(uint16_t port, ProtocolType protocol) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.state == ConnectionState::LISTENING &&
            conn.tuple.local.port == port &&
            conn.tuple.protocol == protocol) {
            return conn.processContext.pid;
        }
    }

    return 0;
}

bool NetworkMonitor::TerminateConnection(uint64_t connectionId) {
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

        auto it = m_impl->m_connections.find(connectionId);
        if (it != m_impl->m_connections.end()) {
            // Mark as closed
            it->second.state = ConnectionState::CLOSED;
            it->second.closeTime = std::chrono::system_clock::now();

            SS_LOG_INFO(L"Network", L"NetworkMonitor: Connection %llu terminated", connectionId);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Terminate connection failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

// ============================================================================
// Filtering
// ============================================================================

bool NetworkMonitor::BlockIP(const IPAddress& ip, BlockReason reason, uint32_t durationMs) {
    (void)durationMs;
    try {
        if (ip.type == IPAddressType::UNKNOWN) {
            SS_LOG_WARN(L"Network", L"NetworkMonitor: BlockIP rejected unknown-type address");
            return false;
        }
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedIPs.size() >= NetworkMonitorConstants::MAX_BLOCKED_IPS &&
            m_impl->m_blockedIPs.find(ip) == m_impl->m_blockedIPs.end()) {
            SS_LOG_WARN(L"Network",
                        L"NetworkMonitor: IP blocklist at capacity (%zu) — refusing %ls",
                        m_impl->m_blockedIPs.size(), ip.ToWString().c_str());
            return false;
        }
        m_impl->m_blockedIPs.insert(ip);
        m_impl->m_statistics.ipsBlocked.fetch_add(1, std::memory_order_relaxed);

        const std::string reasonName(GetBlockReasonName(reason));
        SS_LOG_INFO(L"Network", L"NetworkMonitor: IP %ls blocked - Reason: %hs",
                          ip.ToWString().c_str(), reasonName.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Block IP failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::BlockIpAddress(const IPAddress& ip) {
    return BlockIP(ip, BlockReason::MANUAL_BLOCK, 0);
}

bool NetworkMonitor::UnblockIP(const IPAddress& ip) {
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        m_impl->m_blockedIPs.erase(ip);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: IP %ls unblocked", ip.ToWString().c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Unblock IP failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::BlockIPRange(const IPRange& range, BlockReason reason) {
    try {
        // Store in local blocklist (always — used by IsBlocked() software checks)
        NetworkMonitorImpl::BlockedRange entry{range, reason, 0, 0};

        // If WFP engine is available, install kernel-level block filters
        if (m_impl->m_hWfpEngine) {
            // Build WFP condition for the address range
            if (range.baseAddress.type == IPAddressType::IPV4) {
                FWP_RANGE0 addrRange = {};
                addrRange.valueLow.type = FWP_UINT32;
                addrRange.valueHigh.type = FWP_UINT32;

                const uint8_t pfx = (range.prefixLength > 32) ? 32u : range.prefixLength;
                const uint32_t mask = PrefixToMaskV4(pfx);
                const uint32_t networkAddr   = range.baseAddress.ipv4 & mask;
                const uint32_t broadcastAddr = networkAddr | ~mask;

                // SECURITY/CORRECTNESS: WFP IPv4 conditions take HOST byte order
                // for FWP_UINT32 (per WFP docs and the FirewallManager precedent
                // that ntohl()'s a network-order memcpy buffer back to host order).
                // Our IPAddress::ipv4 is already host order, so we pass it raw.
                addrRange.valueLow.uint32  = networkAddr;
                addrRange.valueHigh.uint32 = broadcastAddr;

                FWPM_FILTER_CONDITION0 condition = {};
                condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                condition.matchType = FWP_MATCH_RANGE;
                condition.conditionValue.type = FWP_RANGE_TYPE;
                condition.conditionValue.rangeValue = &addrRange;

                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"ShadowStrike IP Range Block");
                filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
                filter.action.type = FWP_ACTION_BLOCK;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 15;  // High priority
                filter.numFilterConditions = 1;
                filter.filterCondition = &condition;

                UINT64 filterId = 0;
                DWORD result = FwpmFilterAdd0(m_impl->m_hWfpEngine, &filter, nullptr, &filterId);
                if (result == ERROR_SUCCESS) {
                    entry.wfpFilterIdV4 = filterId;
                    SS_LOG_INFO(L"Network", L"NetworkMonitor: WFP outbound v4 block filter %llu "
                                L"installed for range %ls", filterId,
                                Utils::StringUtils::ToWide(range.ToString()).c_str());
                } else {
                    SS_LOG_WARN(L"Network", L"NetworkMonitor: WFP v4 filter add failed (0x%08X) "
                                L"for range %ls - software blocklist only", result,
                                Utils::StringUtils::ToWide(range.ToString()).c_str());
                }
            } else if (range.baseAddress.type == IPAddressType::IPV6) {
                // IPv6: use FWP_V6_ADDR_AND_MASK condition
                FWP_V6_ADDR_AND_MASK addrMask = {};
                memcpy(addrMask.addr, range.baseAddress.ipv6.data(), 16);
                addrMask.prefixLength = static_cast<UINT8>(
                    (range.prefixLength > 128) ? 128 : range.prefixLength);

                FWPM_FILTER_CONDITION0 condition = {};
                condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                condition.matchType = FWP_MATCH_EQUAL;
                condition.conditionValue.type = FWP_V6_ADDR_MASK;
                condition.conditionValue.v6AddrMask = &addrMask;

                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"ShadowStrike IPv6 Range Block");
                filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
                filter.action.type = FWP_ACTION_BLOCK;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 15;
                filter.numFilterConditions = 1;
                filter.filterCondition = &condition;

                UINT64 filterId = 0;
                DWORD result = FwpmFilterAdd0(m_impl->m_hWfpEngine, &filter, nullptr, &filterId);
                if (result == ERROR_SUCCESS) {
                    entry.wfpFilterIdV6 = filterId;
                    SS_LOG_INFO(L"Network", L"NetworkMonitor: WFP outbound v6 block filter %llu "
                                L"installed for range %ls", filterId,
                                Utils::StringUtils::ToWide(range.ToString()).c_str());
                } else {
                    SS_LOG_WARN(L"Network", L"NetworkMonitor: WFP v6 filter add failed (0x%08X) "
                                L"for range %ls - software blocklist only", result,
                                Utils::StringUtils::ToWide(range.ToString()).c_str());
                }
            }
        }

        // Always store in local tracking regardless of WFP success
        {
            std::lock_guard<std::mutex> lock(m_impl->m_blockedRangesMutex);
            if (m_impl->m_blockedRanges.size() >= NetworkMonitorConstants::MAX_BLOCKED_RANGES) {
                SS_LOG_WARN(L"Network",
                            L"NetworkMonitor: Range blocklist at capacity (%zu) — refusing %ls",
                            m_impl->m_blockedRanges.size(),
                            Utils::StringUtils::ToWide(range.ToString()).c_str());
                // Roll back any WFP filter we just installed.
                if (m_impl->m_hWfpEngine) {
                    if (entry.wfpFilterIdV4) {
                        FwpmFilterDeleteById0(m_impl->m_hWfpEngine, entry.wfpFilterIdV4);
                    }
                    if (entry.wfpFilterIdV6) {
                        FwpmFilterDeleteById0(m_impl->m_hWfpEngine, entry.wfpFilterIdV6);
                    }
                }
                return false;
            }
            m_impl->m_blockedRanges.push_back(std::move(entry));
        }

        m_impl->m_statistics.ipsBlocked.fetch_add(1, std::memory_order_relaxed);
        const std::string reasonName(GetBlockReasonName(reason));
        SS_LOG_INFO(L"Network", L"NetworkMonitor: IP range %ls blocked - Reason: %hs",
                          Utils::StringUtils::ToWide(range.ToString()).c_str(),
                          reasonName.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: BlockIPRange failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::BlockPort(uint16_t port, ProtocolType protocol, BlockReason reason) {
    (void)reason;
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedPorts.size() >= NetworkMonitorConstants::MAX_BLOCKED_PORTS) {
            SS_LOG_WARN(L"Network",
                        L"NetworkMonitor: Port blocklist at capacity (%zu) — refusing port %u",
                        m_impl->m_blockedPorts.size(), static_cast<unsigned>(port));
            return false;
        }
        m_impl->m_blockedPorts.insert({port, protocol});
        m_impl->m_statistics.portsBlocked.fetch_add(1, std::memory_order_relaxed);

        const std::string protoName(GetProtocolTypeName(protocol));
        SS_LOG_INFO(L"Network", L"NetworkMonitor: Port %u (%hs) blocked",
                          static_cast<unsigned>(port), protoName.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Block port failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::UnblockPort(uint16_t port, ProtocolType protocol) {
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        m_impl->m_blockedPorts.erase({port, protocol});

        const std::string protoName(GetProtocolTypeName(protocol));
        SS_LOG_INFO(L"Network", L"NetworkMonitor: Port %u (%hs) unblocked",
                          static_cast<unsigned>(port), protoName.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Unblock port failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::BlockDomain(const std::wstring& domain, BlockReason reason) {
    (void)reason;
    try {
        std::wstring normalized = NormalizeDomain(domain);
        if (normalized.empty()) {
            SS_LOG_WARN(L"Network", L"NetworkMonitor: BlockDomain rejected invalid input '%ls'",
                        SanitizeForLogW(domain).c_str());
            return false;
        }
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedDomains.size() >= NetworkMonitorConstants::MAX_BLOCKED_DOMAINS &&
            m_impl->m_blockedDomains.find(normalized) == m_impl->m_blockedDomains.end()) {
            SS_LOG_WARN(L"Network",
                        L"NetworkMonitor: Domain blocklist at capacity (%zu) — refusing '%ls'",
                        m_impl->m_blockedDomains.size(), SanitizeForLogW(normalized).c_str());
            return false;
        }
        m_impl->m_blockedDomains.insert(std::move(normalized));
        m_impl->m_statistics.domainsBlocked.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Domain '%ls' blocked",
                    SanitizeForLogW(domain).c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Block domain failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::UnblockDomain(const std::wstring& domain) {
    try {
        std::wstring normalized = NormalizeDomain(domain);
        if (normalized.empty()) {
            return false;
        }
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        m_impl->m_blockedDomains.erase(normalized);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Domain '%ls' unblocked",
                    SanitizeForLogW(domain).c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Unblock domain failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::BlockProcess(uint32_t pid, BlockReason reason) {
    (void)reason;
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        if (m_impl->m_blockedProcesses.size() >= NetworkMonitorConstants::MAX_BLOCKED_PROCESSES &&
            m_impl->m_blockedProcesses.find(pid) == m_impl->m_blockedProcesses.end()) {
            SS_LOG_WARN(L"Network",
                        L"NetworkMonitor: Process blocklist at capacity (%zu) — refusing PID %u",
                        m_impl->m_blockedProcesses.size(), pid);
            return false;
        }
        m_impl->m_blockedProcesses.insert(pid);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Process %u blocked", pid);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Block process failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::UnblockProcess(uint32_t pid) {
    try {
        std::unique_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
        m_impl->m_blockedProcesses.erase(pid);

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Process %u unblocked", pid);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Unblock process failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

uint64_t NetworkMonitor::AddFilter(const ConnectionFilter& filter) {
    std::lock_guard<std::mutex> lock(m_impl->m_filtersMutex);

    if (m_impl->m_filters.size() >= NetworkMonitorConstants::MAX_FILTERS) {
        SS_LOG_WARN(L"Network",
                    L"NetworkMonitor: Filter table at capacity (%zu) — refusing new filter '%ls'",
                    m_impl->m_filters.size(), SanitizeForLogW(filter.name).c_str());
        return 0;
    }

    uint64_t filterId = m_impl->m_nextFilterId.fetch_add(1, std::memory_order_relaxed);
    ConnectionFilter newFilter = filter;
    newFilter.filterId = filterId;
    newFilter.createdAt = std::chrono::system_clock::now();

    // SECURITY: priority key composition uses the high 32 bits for priority and
    // the low 32 bits for filter ID. The previous "priority * 1e6 + id" scheme
    // would collide once filterId >= 1e6 (one ID-allocation per outbound flow
    // exhausts that range in seconds on a busy host). std::map ordering lays
    // out lower-priority first; the dispatch path iterates as-is.
    const uint64_t key = (static_cast<uint64_t>(newFilter.priority) << 32) |
                         (filterId & 0xFFFFFFFFULL);
    m_impl->m_filters[key] = newFilter;

    SS_LOG_INFO(L"Network", L"NetworkMonitor: Filter added - ID: %llu, Name: '%ls'",
                      filterId, SanitizeForLogW(filter.name).c_str());

    return filterId;
}

bool NetworkMonitor::RemoveFilter(uint64_t filterId) {
    std::lock_guard<std::mutex> lock(m_impl->m_filtersMutex);

    for (auto it = m_impl->m_filters.begin(); it != m_impl->m_filters.end(); ++it) {
        if (it->second.filterId == filterId) {
            m_impl->m_filters.erase(it);
            SS_LOG_INFO(L"Network", L"NetworkMonitor: Filter removed - ID: %llu", filterId);
            return true;
        }
    }

    return false;
}

std::vector<ConnectionFilter> NetworkMonitor::GetFilters() const {
    std::lock_guard<std::mutex> lock(m_impl->m_filtersMutex);

    std::vector<ConnectionFilter> filters;
    filters.reserve(m_impl->m_filters.size());

    for (const auto& [key, filter] : m_impl->m_filters) {
        (void)key;
        filters.push_back(filter);
    }

    return filters;
}

bool NetworkMonitor::IsIPBlocked(const IPAddress& ip) const {
    if (ip.type == IPAddressType::UNKNOWN) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);
    if (m_impl->m_blockedIPs.find(ip) != m_impl->m_blockedIPs.end()) {
        return true;
    }
    // SECURITY: software check must also honor CIDR-range blocks; otherwise
    // BlockIPRange() is silently ineffective when WFP is unavailable.
    std::lock_guard<std::mutex> rangeLock(m_impl->m_blockedRangesMutex);
    for (const auto& br : m_impl->m_blockedRanges) {
        if (br.range.Contains(ip)) {
            return true;
        }
    }
    return false;
}

std::vector<IPAddress> NetworkMonitor::GetBlockedIPs() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_blocklistMutex);

    std::vector<IPAddress> blocked;
    blocked.reserve(m_impl->m_blockedIPs.size());

    for (const auto& ip : m_impl->m_blockedIPs) {
        blocked.push_back(ip);
    }

    return blocked;
}

void NetworkMonitor::ClearTemporaryBlocks() {
    // Would clear temporary blocks in real implementation
    SS_LOG_INFO(L"Network", L"NetworkMonitor: Temporary blocks cleared");
}

// ============================================================================
// Threat Analysis
// ============================================================================

BeaconingAnalysis NetworkMonitor::AnalyzeBeaconing(const SocketAddress& remoteAddress) const {
    return m_impl->AnalyzeBeaconingInternal(remoteAddress);
}

DataExfiltrationAnalysis NetworkMonitor::AnalyzeExfiltration(uint32_t pid) const {
    return m_impl->AnalyzeExfiltrationInternal(pid);
}

PortScanAnalysis NetworkMonitor::AnalyzePortScanning(const IPAddress& sourceIp) const {
    return m_impl->AnalyzePortScanningInternal(sourceIp);
}

std::vector<ThreatIndicator> NetworkMonitor::GetThreatIndicators(uint64_t connectionId) const {
    auto conn = GetConnection(connectionId);
    if (conn.has_value()) {
        return conn->indicators;
    }
    return {};
}

// ============================================================================
// Callback Registration
// ============================================================================

void NetworkMonitor::SetConnectionCallback(ConnectionCallback callback) {
    // Bridge into the impl-side single-slot callback so ProcessNewConnection
    // can fire it. Held under a writer-exclusive lock; readers in the
    // dispatch path acquire shared briefly to copy it out.
    std::unique_lock<std::shared_mutex> lock(m_impl->m_legacyCallbackMutex);
    m_impl->m_legacyCallback = std::move(callback);
}

uint64_t NetworkMonitor::RegisterConnectionCallback(ConnectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_connectionCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t NetworkMonitor::RegisterStateChangeCallback(StateChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_stateChangeCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t NetworkMonitor::RegisterNetworkEventCallback(NetworkEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_eventCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t NetworkMonitor::RegisterFilterMatchCallback(FilterMatchCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_filterMatchCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t NetworkMonitor::RegisterThreatDetectionCallback(ThreatDetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_threatCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t NetworkMonitor::RegisterBandwidthAlertCallback(BandwidthAlertCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_bandwidthCallbacks.emplace_back(id, std::move(callback));
    return id;
}

bool NetworkMonitor::UnregisterCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    auto removeById = [callbackId](auto& callbacks) {
        auto it = std::find_if(callbacks.begin(), callbacks.end(),
                              [callbackId](const auto& pair) { return pair.first == callbackId; });
        if (it != callbacks.end()) {
            callbacks.erase(it);
            return true;
        }
        return false;
    };

    return removeById(m_impl->m_connectionCallbacks) ||
           removeById(m_impl->m_stateChangeCallbacks) ||
           removeById(m_impl->m_eventCallbacks) ||
           removeById(m_impl->m_filterMatchCallbacks) ||
           removeById(m_impl->m_threatCallbacks) ||
           removeById(m_impl->m_bandwidthCallbacks);
}

// ============================================================================
// Statistics
// ============================================================================

const NetworkMonitorStatistics& NetworkMonitor::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void NetworkMonitor::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"Network", L"NetworkMonitor: Statistics reset");
}

BandwidthStats NetworkMonitor::GetProcessBandwidth(uint32_t pid) const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_connectionsMutex);

    BandwidthStats stats;

    for (const auto& [id, conn] : m_impl->m_connections) {
        if (conn.processContext.pid == pid) {
            stats.bytesReceived.fetch_add(conn.bandwidth.bytesReceived.load(), std::memory_order_relaxed);
            stats.bytesSent.fetch_add(conn.bandwidth.bytesSent.load(), std::memory_order_relaxed);
            stats.packetsReceived.fetch_add(conn.bandwidth.packetsReceived.load(), std::memory_order_relaxed);
            stats.packetsSent.fetch_add(conn.bandwidth.packetsSent.load(), std::memory_order_relaxed);
        }
    }

    return stats;
}

BandwidthStats NetworkMonitor::GetSystemBandwidth() const {
    BandwidthStats stats;
    stats.bytesReceived.store(m_impl->m_statistics.totalBytesReceived.load(), std::memory_order_relaxed);
    stats.bytesSent.store(m_impl->m_statistics.totalBytesSent.load(), std::memory_order_relaxed);
    stats.packetsReceived.store(m_impl->m_statistics.totalPacketsReceived.load(), std::memory_order_relaxed);
    stats.packetsSent.store(m_impl->m_statistics.totalPacketsSent.load(), std::memory_order_relaxed);
    return stats;
}

// ============================================================================
// Diagnostics
// ============================================================================

bool NetworkMonitor::PerformDiagnostics() const {
    try {
        SS_LOG_INFO(L"Network", L"NetworkMonitor: Running diagnostics");

        // Check initialization
        if (!IsInitialized()) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Not initialized");
            return false;
        }

        // Check infrastructure
        if (!m_impl->m_threatIntel) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: ThreatIntel not initialized");
            return false;
        }

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Diagnostics passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Diagnostics failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool NetworkMonitor::ExportDiagnostics(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        file << L"NetworkMonitor Diagnostics\n";
        file << L"==========================\n\n";
        file << L"Initialized: " << (IsInitialized() ? L"Yes" : L"No") << L"\n";
        file << L"Running: " << (IsRunning() ? L"Yes" : L"No") << L"\n";
        file << L"Total Connections: " << m_impl->m_statistics.totalConnections.load() << L"\n";
        file << L"Active Connections: " << m_impl->m_statistics.activeConnections.load() << L"\n";
        file << L"Blocked Connections: " << m_impl->m_statistics.blockedConnections.load() << L"\n";
        file << L"Threats Detected: " << m_impl->m_statistics.threatsDetected.load() << L"\n";
        file << L"Total Bytes Sent: " << m_impl->m_statistics.totalBytesSent.load() << L"\n";
        file << L"Total Bytes Received: " << m_impl->m_statistics.totalBytesReceived.load() << L"\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

bool NetworkMonitor::SelfTest() {
    try {
        SS_LOG_INFO(L"Network", L"NetworkMonitor: Starting self-test");

        // Test IP address operations (no global state mutated).
        IPAddress testIp(0x7F000001u);  // 127.0.0.1
        if (!testIp.IsLoopback()) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: IP classification test failed");
            return false;
        }

        // SECURITY: Self-test must not pollute the live blocklist. Use
        // documentation IPs (TEST-NET-1 / RFC 5737, TEST-NET-2, TEST-NET-3),
        // ports outside the well-known range, and a sentinel test domain.
        // Verify each insert/lookup/erase round-trips without leaking state.
        const IPAddress testV4(0xC0000201u);  // 192.0.2.1 (RFC 5737 TEST-NET-1)
        if (!BlockIP(testV4, BlockReason::MANUAL_BLOCK, 0) ||
            !IsIPBlocked(testV4) ||
            !UnblockIP(testV4) ||
            IsIPBlocked(testV4)) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: IP block round-trip test failed");
            return false;
        }

        constexpr uint16_t kSelfTestPort = 65000;
        if (!BlockPort(kSelfTestPort, ProtocolType::TCP, BlockReason::POLICY_VIOLATION) ||
            !UnblockPort(kSelfTestPort, ProtocolType::TCP)) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Port block round-trip test failed");
            return false;
        }

        const std::wstring kSelfTestDomain = L"selftest.invalid";  // RFC 6761 reserved TLD
        if (!BlockDomain(kSelfTestDomain, BlockReason::MALICIOUS_DOMAIN) ||
            !UnblockDomain(kSelfTestDomain)) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Domain block round-trip test failed");
            return false;
        }

        // Domain normalization rejects malformed inputs.
        if (!NormalizeDomain(L"  bad\n.example").empty() ||
            !NormalizeDomain(L"").empty()) {
            SS_LOG_ERROR(L"Network", L"NetworkMonitor: Domain normalization test failed");
            return false;
        }

        SS_LOG_INFO(L"Network", L"NetworkMonitor: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"NetworkMonitor: Self-test failed - %ls",
                            Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

std::string NetworkMonitor::GetVersionString() noexcept {
    return std::to_string(NetworkMonitorConstants::VERSION_MAJOR) + "." +
           std::to_string(NetworkMonitorConstants::VERSION_MINOR) + "." +
           std::to_string(NetworkMonitorConstants::VERSION_PATCH);
}

// ============================================================================
// Utility Methods
// ============================================================================

std::vector<IPAddress> NetworkMonitor::ResolveHostname(std::wstring_view hostname) {
    std::vector<IPAddress> addresses;

    // SECURITY: bound hostname length and reject embedded control characters
    // before pushing it through getaddrinfo. RFC 1035 caps a fully-qualified
    // domain at 253 octets; anything longer cannot be valid and likely is an
    // attempt to abuse the resolver / log channel.
    if (hostname.empty() || hostname.size() > NetworkMonitorConstants::MAX_DOMAIN_LENGTH) {
        return addresses;
    }
    for (wchar_t c : hostname) {
        if (c < 0x20 || c == 0x7F) return addresses;
    }

    try {
        const std::string hostA = Utils::StringUtils::ToNarrow(hostname);
        if (hostA.empty() || hostA.size() > NetworkMonitorConstants::MAX_DOMAIN_LENGTH) {
            return addresses;
        }

        struct addrinfo hints {};
        hints.ai_family = AF_UNSPEC;  // IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* result = nullptr;
        if (getaddrinfo(hostA.c_str(), nullptr, &hints, &result) == 0 && result) {
            for (struct addrinfo* ptr = result;
                 ptr != nullptr &&
                 addresses.size() < NetworkMonitorConstants::MAX_RESOLVED_ADDRESSES;
                 ptr = ptr->ai_next) {
                if (ptr->ai_family == AF_INET && ptr->ai_addrlen >= sizeof(sockaddr_in)) {
                    auto* addr = reinterpret_cast<struct sockaddr_in*>(ptr->ai_addr);
                    addresses.push_back(IPAddress(ntohl(addr->sin_addr.S_un.S_addr)));
                } else if (ptr->ai_family == AF_INET6 && ptr->ai_addrlen >= sizeof(sockaddr_in6)) {
                    auto* addr = reinterpret_cast<struct sockaddr_in6*>(ptr->ai_addr);
                    std::array<uint8_t, 16> ipv6{};
                    std::memcpy(ipv6.data(), &addr->sin6_addr, 16);
                    addresses.push_back(IPAddress(ipv6));
                }
            }
            freeaddrinfo(result);
        }
    } catch (...) {
        // Return empty vector on failure
    }

    return addresses;
}

std::wstring NetworkMonitor::ReverseLookup(const IPAddress& ip) {
    try {
        char hostname[NI_MAXHOST] = {0};
        if (ip.type == IPAddressType::IPV4) {
            struct sockaddr_in addr {};
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = htonl(ip.ipv4);
            if (getnameinfo(reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr),
                          hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) {
                return Utils::StringUtils::ToWide(std::string_view(hostname));
            }
        } else if (ip.type == IPAddressType::IPV6) {
            struct sockaddr_in6 addr {};
            addr.sin6_family = AF_INET6;
            std::memcpy(&addr.sin6_addr, ip.ipv6.data(), 16);
            if (getnameinfo(reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr),
                          hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) {
                return Utils::StringUtils::ToWide(std::string_view(hostname));
            }
        }
    } catch (...) {
        // Return empty on failure
    }

    return L"";
}

std::wstring NetworkMonitor::GetProtocolName(ProtocolType protocol) noexcept {
    return Utils::StringUtils::ToWide(GetProtocolTypeName(protocol));
}

std::wstring NetworkMonitor::GetAppProtocolName(ApplicationProtocol protocol) noexcept {
    return Utils::StringUtils::ToWide(::ShadowStrike::Core::Network::GetAppProtocolName(protocol));
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string_view GetConnectionStateName(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::UNKNOWN: return "UNKNOWN";
        case ConnectionState::LISTENING: return "LISTENING";
        case ConnectionState::SYN_SENT: return "SYN_SENT";
        case ConnectionState::SYN_RECEIVED: return "SYN_RECEIVED";
        case ConnectionState::ESTABLISHED: return "ESTABLISHED";
        case ConnectionState::FIN_WAIT_1: return "FIN_WAIT_1";
        case ConnectionState::FIN_WAIT_2: return "FIN_WAIT_2";
        case ConnectionState::CLOSE_WAIT: return "CLOSE_WAIT";
        case ConnectionState::CLOSING: return "CLOSING";
        case ConnectionState::LAST_ACK: return "LAST_ACK";
        case ConnectionState::TIME_WAIT: return "TIME_WAIT";
        case ConnectionState::CLOSED: return "CLOSED";
        case ConnectionState::DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

std::string_view GetProtocolTypeName(ProtocolType protocol) noexcept {
    switch (protocol) {
        case ProtocolType::UNKNOWN: return "UNKNOWN";
        case ProtocolType::TCP: return "TCP";
        case ProtocolType::UDP: return "UDP";
        case ProtocolType::ICMP: return "ICMP";
        case ProtocolType::ICMPv6: return "ICMPv6";
        case ProtocolType::SCTP: return "SCTP";
        case ProtocolType::GRE: return "GRE";
        default: return "UNKNOWN";
    }
}

std::string_view GetAppProtocolName(ApplicationProtocol protocol) noexcept {
    switch (protocol) {
        case ApplicationProtocol::UNKNOWN: return "UNKNOWN";
        case ApplicationProtocol::HTTP: return "HTTP";
        case ApplicationProtocol::HTTPS: return "HTTPS";
        case ApplicationProtocol::DNS: return "DNS";
        case ApplicationProtocol::DNS_OVER_HTTPS: return "DoH";
        case ApplicationProtocol::DNS_OVER_TLS: return "DoT";
        case ApplicationProtocol::SMB: return "SMB";
        case ApplicationProtocol::SMB2: return "SMB2";
        case ApplicationProtocol::RDP: return "RDP";
        case ApplicationProtocol::SSH: return "SSH";
        case ApplicationProtocol::FTP: return "FTP";
        case ApplicationProtocol::FTP_DATA: return "FTP-DATA";
        case ApplicationProtocol::SFTP: return "SFTP";
        case ApplicationProtocol::SMTP: return "SMTP";
        case ApplicationProtocol::SMTPS: return "SMTPS";
        case ApplicationProtocol::IMAP: return "IMAP";
        case ApplicationProtocol::IMAPS: return "IMAPS";
        case ApplicationProtocol::POP3: return "POP3";
        case ApplicationProtocol::POP3S: return "POP3S";
        case ApplicationProtocol::LDAP: return "LDAP";
        case ApplicationProtocol::LDAPS: return "LDAPS";
        case ApplicationProtocol::KERBEROS: return "KERBEROS";
        case ApplicationProtocol::NTP: return "NTP";
        case ApplicationProtocol::SNMP: return "SNMP";
        case ApplicationProtocol::SYSLOG: return "SYSLOG";
        case ApplicationProtocol::MYSQL: return "MYSQL";
        case ApplicationProtocol::POSTGRESQL: return "POSTGRESQL";
        case ApplicationProtocol::MSSQL: return "MSSQL";
        case ApplicationProtocol::MONGODB: return "MONGODB";
        case ApplicationProtocol::REDIS: return "REDIS";
        case ApplicationProtocol::MEMCACHED: return "MEMCACHED";
        case ApplicationProtocol::ELASTICSEARCH: return "ELASTICSEARCH";
        case ApplicationProtocol::KAFKA: return "KAFKA";
        case ApplicationProtocol::AMQP: return "AMQP";
        case ApplicationProtocol::MQTT: return "MQTT";
        case ApplicationProtocol::COAP: return "COAP";
        case ApplicationProtocol::WEBSOCKET: return "WEBSOCKET";
        case ApplicationProtocol::GRPC: return "GRPC";
        case ApplicationProtocol::QUIC: return "QUIC";
        case ApplicationProtocol::WIREGUARD: return "WIREGUARD";
        case ApplicationProtocol::OPENVPN: return "OPENVPN";
        case ApplicationProtocol::TOR: return "TOR";
        case ApplicationProtocol::BITTORRENT: return "BITTORRENT";
        case ApplicationProtocol::BITCOIN: return "BITCOIN";
        case ApplicationProtocol::CUSTOM_C2: return "CUSTOM_C2";
        default: return "UNKNOWN";
    }
}

std::string_view GetConnectionDirectionName(ConnectionDirection direction) noexcept {
    switch (direction) {
        case ConnectionDirection::UNKNOWN: return "UNKNOWN";
        case ConnectionDirection::INBOUND: return "INBOUND";
        case ConnectionDirection::OUTBOUND: return "OUTBOUND";
        case ConnectionDirection::LOCAL: return "LOCAL";
        case ConnectionDirection::INTERNAL: return "INTERNAL";
        default: return "UNKNOWN";
    }
}

std::string_view GetFilterActionName(FilterAction action) noexcept {
    switch (action) {
        case FilterAction::ALLOW: return "ALLOW";
        case FilterAction::BLOCK: return "BLOCK";
        case FilterAction::MONITOR: return "MONITOR";
        case FilterAction::QUARANTINE: return "QUARANTINE";
        case FilterAction::REDIRECT: return "REDIRECT";
        case FilterAction::RATE_LIMIT: return "RATE_LIMIT";
        default: return "UNKNOWN";
    }
}

std::string_view GetBlockReasonName(BlockReason reason) noexcept {
    switch (reason) {
        case BlockReason::NONE: return "NONE";
        case BlockReason::MALICIOUS_IP: return "MALICIOUS_IP";
        case BlockReason::MALICIOUS_DOMAIN: return "MALICIOUS_DOMAIN";
        case BlockReason::BLOCKED_PORT: return "BLOCKED_PORT";
        case BlockReason::BLOCKED_APPLICATION: return "BLOCKED_APPLICATION";
        case BlockReason::GEO_BLOCKED: return "GEO_BLOCKED";
        case BlockReason::REPUTATION_LOW: return "REPUTATION_LOW";
        case BlockReason::C2_DETECTED: return "C2_DETECTED";
        case BlockReason::POLICY_VIOLATION: return "POLICY_VIOLATION";
        case BlockReason::RATE_EXCEEDED: return "RATE_EXCEEDED";
        case BlockReason::MANUAL_BLOCK: return "MANUAL_BLOCK";
        case BlockReason::SUSPICIOUS_PATTERN: return "SUSPICIOUS_PATTERN";
        case BlockReason::KNOWN_MALWARE: return "KNOWN_MALWARE";
        default: return "UNKNOWN";
    }
}

std::string_view GetThreatIndicatorName(ThreatIndicator indicator) noexcept {
    switch (indicator) {
        case ThreatIndicator::NONE: return "NONE";
        case ThreatIndicator::BEACONING: return "BEACONING";
        case ThreatIndicator::DATA_EXFILTRATION: return "DATA_EXFILTRATION";
        case ThreatIndicator::PORT_SCANNING: return "PORT_SCANNING";
        case ThreatIndicator::LATERAL_MOVEMENT: return "LATERAL_MOVEMENT";
        case ThreatIndicator::DNS_TUNNELING: return "DNS_TUNNELING";
        case ThreatIndicator::ICMP_TUNNELING: return "ICMP_TUNNELING";
        case ThreatIndicator::DOMAIN_GENERATION: return "DOMAIN_GENERATION";
        case ThreatIndicator::TOR_USAGE: return "TOR_USAGE";
        case ThreatIndicator::CRYPTO_MINING: return "CRYPTO_MINING";
        case ThreatIndicator::BOTNET_ACTIVITY: return "BOTNET_ACTIVITY";
        case ThreatIndicator::EXPLOIT_TRAFFIC: return "EXPLOIT_TRAFFIC";
        default: return "UNKNOWN";
    }
}

std::string_view GetIPAddressTypeName(IPAddressType type) noexcept {
    switch (type) {
        case IPAddressType::UNKNOWN: return "UNKNOWN";
        case IPAddressType::IPV4: return "IPV4";
        case IPAddressType::IPV6: return "IPV6";
        default: return "UNKNOWN";
    }
}

std::string_view GetIPClassificationName(IPClassification classification) noexcept {
    switch (classification) {
        case IPClassification::UNKNOWN: return "UNKNOWN";
        case IPClassification::PRIVATE: return "PRIVATE";
        case IPClassification::PUBLIC: return "PUBLIC";
        case IPClassification::LOOPBACK: return "LOOPBACK";
        case IPClassification::LINK_LOCAL: return "LINK_LOCAL";
        case IPClassification::MULTICAST: return "MULTICAST";
        case IPClassification::BROADCAST: return "BROADCAST";
        case IPClassification::RESERVED: return "RESERVED";
        case IPClassification::DOCUMENTATION: return "DOCUMENTATION";
        default: return "UNKNOWN";
    }
}

std::string_view GetMonitoringLevelName(MonitoringLevel level) noexcept {
    switch (level) {
        case MonitoringLevel::MINIMAL: return "MINIMAL";
        case MonitoringLevel::STANDARD: return "STANDARD";
        case MonitoringLevel::DETAILED: return "DETAILED";
        case MonitoringLevel::FORENSIC: return "FORENSIC";
        default: return "UNKNOWN";
    }
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
