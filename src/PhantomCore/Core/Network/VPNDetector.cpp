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
 * ShadowStrike Core Network - VPN DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file VPNDetector.cpp
 * @brief Enterprise-grade VPN and proxy detection engine.
 *
 * This module implements comprehensive detection of Virtual Private Networks,
 * proxy servers, and anonymization services through multiple methods:
 * - Network adapter analysis (TAP/TUN/WireGuard detection)
 * - Routing table inspection (split tunneling, gateway analysis)
 * - Traffic fingerprinting (OpenVPN/WireGuard/IPSec protocol detection)
 * - IP range and ASN lookup (provider identification)
 * - Process detection (VPN client identification)
 * - DNS and IPv6 leak detection
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Background monitoring thread with adapter change detection
 * - Multi-layered detection (adapter → routing → traffic → IP)
 * - Policy enforcement engine (allow/monitor/block)
 * - Callback architecture for real-time notifications
 *
 * Detection Strategy:
 * 1. Enumerate network adapters (GetAdaptersAddresses)
 * 2. Identify virtual adapters (TAP/TUN/WireGuard)
 * 3. Analyze routing table for VPN gateways
 * 4. Fingerprint traffic patterns (OpenVPN handshake, WireGuard noise)
 * 5. Match IP ranges against known VPN providers
 * 6. Detect running VPN client processes
 * 7. Check for DNS/IPv6 leaks
 * 8. Invoke callbacks with detection results
 *
 * VPN Protocols Detected:
 * - OpenVPN (UDP/TCP)
 * - WireGuard
 * - IPSec/IKEv2
 * - L2TP/IPSec
 * - PPTP
 * - SSTP
 * - Corporate: Cisco AnyConnect, GlobalProtect, Pulse Secure
 *
 * Commercial Providers:
 * - NordVPN, ExpressVPN, Surfshark
 * - PIA, Mullvad, ProtonVPN
 * - CyberGhost, IPVanish, Windscribe
 *
 * MITRE ATT&CK Coverage:
 * - T1090.003: Proxy: Multi-hop Proxy
 * - T1573: Encrypted Channel
 * - T1572: Protocol Tunneling
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "VPNDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../HashStore/HashStore.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winhttp.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cwctype>
#include <fstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

namespace StringUtils = ShadowStrike::Utils::StringUtils;

using namespace Utils;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // TAP/TUN adapter keywords
    const std::vector<std::wstring> TAP_ADAPTER_KEYWORDS = {
        L"TAP-Windows",
        L"TAP Adapter",
        L"OpenVPN",
        L"tap0901",
        L"tapoas",
        L"wintun"
    };

    // WireGuard adapter keywords
    const std::vector<std::wstring> WIREGUARD_KEYWORDS = {
        L"WireGuard",
        L"wg0",
        L"utun"
    };

    // VPN process names
    const std::vector<std::wstring> VPN_PROCESS_NAMES = {
        L"openvpn.exe",
        L"wireguard.exe",
        L"vpnui.exe",
        L"expressvpn.exe",
        L"nordvpn.exe",
        L"surfshark.exe",
        L"windscribe.exe",
        L"mullvad.exe",
        L"protonvpn.exe",
        L"cyberghost.exe",
        L"ipvanish.exe",
        L"tunnelbear.exe",
        L"hidemyass.exe",
        L"cisco-vpn.exe",
        L"anyconnect.exe",
        L"globalprotect.exe",
        L"pulsesecure.exe"
    };

    // VPN registry key paths for installed VPN software
    const std::vector<std::wstring> VPN_REGISTRY_PATHS = {
        L"SOFTWARE\\OpenVPN",
        L"SOFTWARE\\WireGuard",
        L"SOFTWARE\\NordVPN",
        L"SOFTWARE\\ExpressVPN",
        L"SOFTWARE\\Surfshark",
        L"SOFTWARE\\Private Internet Access",
        L"SOFTWARE\\Mullvad VPN",
        L"SOFTWARE\\ProtonVPN",
        L"SOFTWARE\\CyberGhost",
        L"SOFTWARE\\IPVanish",
        L"SOFTWARE\\Windscribe",
        L"SOFTWARE\\TunnelBear",
        L"SOFTWARE\\AnchorFree\\Hotspot Shield",
        L"SOFTWARE\\Cisco\\Cisco AnyConnect Secure Mobility Client",
        L"SOFTWARE\\Palo Alto Networks\\GlobalProtect",
        L"SOFTWARE\\Pulse Secure\\Pulse",
        L"SOFTWARE\\Fortinet\\FortiClient",
    };

    // VPN service names to detect running VPN services
    const std::vector<std::wstring> VPN_SERVICE_NAMES = {
        L"OpenVPNService",
        L"WireGuardTunnel",
        L"NordVpnService",
        L"ExpressVpnService",
        L"SurfsharkService",
        L"PrivateInternetAccessService",
        L"MullvadVPN",
        L"ProtonVPN Service",
        L"CyberGhostService",
        L"vpnagent",            // Cisco AnyConnect
        L"PanGPS",              // GlobalProtect
        L"PulseSecureService",
        L"FortiClient",
    };

    // Update interval
    constexpr uint32_t ADAPTER_SCAN_INTERVAL_MS = 5000;
    constexpr uint32_t LEAK_CHECK_INTERVAL_MS = 10000;

    // Cap on tracked connections to prevent unbounded growth
    constexpr size_t MAX_ACTIVE_CONNECTIONS = 256;

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static bool IsVirtualAdapterName(const std::wstring& name) noexcept {
    std::wstring lowerName = StringUtils::ToLowerCopy(name);

    // Check for TAP/TUN
    for (const auto& keyword : TAP_ADAPTER_KEYWORDS) {
        if (lowerName.find(StringUtils::ToLowerCopy(keyword)) != std::wstring::npos) {
            return true;
        }
    }

    // Check for WireGuard
    for (const auto& keyword : WIREGUARD_KEYWORDS) {
        if (lowerName.find(StringUtils::ToLowerCopy(keyword)) != std::wstring::npos) {
            return true;
        }
    }

    // Check for common virtual adapter patterns
    if (lowerName.find(L"virtual") != std::wstring::npos) return true;
    if (lowerName.find(L"vpn") != std::wstring::npos) return true;
    if (lowerName.find(L"tunnel") != std::wstring::npos) return true;

    return false;
}

[[nodiscard]] static AdapterType DetermineAdapterType(const std::wstring& name, const std::wstring& description) noexcept {
    std::wstring lowerName = StringUtils::ToLowerCopy(name);
    std::wstring lowerDesc = StringUtils::ToLowerCopy(description);
    std::wstring combined = lowerName + L" " + lowerDesc;

    // WireGuard
    for (const auto& keyword : WIREGUARD_KEYWORDS) {
        if (combined.find(StringUtils::ToLowerCopy(keyword)) != std::wstring::npos) {
            return AdapterType::WIREGUARD;
        }
    }

    // TAP
    if (combined.find(L"tap") != std::wstring::npos) {
        return AdapterType::TAP;
    }

    // TUN - require word boundary to avoid false positives like "fortune", "stunt"
    for (size_t pos = combined.find(L"tun"); pos != std::wstring::npos;
         pos = combined.find(L"tun", pos + 3)) {
        // Check left boundary (start of string or non-alpha)
        bool leftOk = (pos == 0) || !std::iswalpha(combined[pos - 1]);
        // Check right boundary (end of string, digit, or non-alpha)
        size_t endPos = pos + 3;
        bool rightOk = (endPos >= combined.size()) || !std::iswalpha(combined[endPos]);
        if (leftOk && rightOk) {
            return AdapterType::TUN;
        }
    }

    // IPSec
    if (combined.find(L"ipsec") != std::wstring::npos) {
        return AdapterType::IPSEC;
    }

    // PPTP
    if (combined.find(L"pptp") != std::wstring::npos) {
        return AdapterType::PPTP;
    }

    // L2TP
    if (combined.find(L"l2tp") != std::wstring::npos) {
        return AdapterType::L2TP;
    }

    // SSTP
    if (combined.find(L"sstp") != std::wstring::npos) {
        return AdapterType::SSTP;
    }

    // Loopback
    if (combined.find(L"loopback") != std::wstring::npos) {
        return AdapterType::LOOPBACK;
    }

    // Physical vs Unknown
    if (IsVirtualAdapterName(name)) {
        return AdapterType::UNKNOWN;
    }

    return AdapterType::PHYSICAL;
}

[[nodiscard]] static VPNProtocol DetectProtocolFromAdapter(AdapterType type) noexcept {
    switch (type) {
        case AdapterType::WIREGUARD:
            return VPNProtocol::WIREGUARD;
        case AdapterType::IPSEC:
            return VPNProtocol::IPSEC_IKEV2;
        case AdapterType::PPTP:
            return VPNProtocol::PPTP;
        case AdapterType::L2TP:
            return VPNProtocol::L2TP_IPSEC;
        case AdapterType::SSTP:
            return VPNProtocol::SSTP;
        case AdapterType::TAP:
        case AdapterType::TUN:
            return VPNProtocol::OPENVPN_UDP;  // Most likely OpenVPN
        default:
            return VPNProtocol::UNKNOWN;
    }
}

[[nodiscard]] static std::string IPv6ToString(const IN6_ADDR& addr) noexcept {
    char buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&addr), buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "";
}

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

VPNDetectorConfig VPNDetectorConfig::CreateDefault() noexcept {
    VPNDetectorConfig config;
    config.enabled = true;
    config.policy = VPNPolicy::MONITOR;

    config.enableAdapterDetection = true;
    config.enableRoutingAnalysis = true;
    config.enableTrafficFingerprinting = false;  // Requires driver
    config.enableIPRangeLookup = true;
    config.enableASNLookup = true;
    config.enableProcessDetection = true;

    config.enableProxyDetection = true;
    config.detectSystemProxy = true;

    config.enableLeakDetection = true;
    config.checkDNSLeak = true;
    config.checkIPv6Leak = true;

    config.identifyProvider = true;

    config.blockConsumerVPNs = false;
    config.blockAllVPNs = false;
    config.allowCorporateVPNs = true;

    config.alertOnDetection = true;
    config.alertOnLeak = true;

    config.logAllConnections = false;
    config.logDetectionsOnly = true;

    return config;
}

VPNDetectorConfig VPNDetectorConfig::CreateHighSecurity() noexcept {
    VPNDetectorConfig config;
    config.enabled = true;
    config.policy = VPNPolicy::BLOCK_CONSUMER;

    config.enableAdapterDetection = true;
    config.enableRoutingAnalysis = true;
    config.enableTrafficFingerprinting = true;
    config.enableIPRangeLookup = true;
    config.enableASNLookup = true;
    config.enableProcessDetection = true;

    config.enableProxyDetection = true;
    config.detectSystemProxy = true;

    config.enableLeakDetection = true;
    config.checkDNSLeak = true;
    config.checkIPv6Leak = true;

    config.identifyProvider = true;

    config.blockConsumerVPNs = true;
    config.blockAllVPNs = false;
    config.allowCorporateVPNs = true;

    config.alertOnDetection = true;
    config.alertOnLeak = true;

    config.logAllConnections = true;
    config.logDetectionsOnly = false;

    return config;
}

VPNDetectorConfig VPNDetectorConfig::CreateCorporate() noexcept {
    VPNDetectorConfig config;
    config.enabled = true;
    config.policy = VPNPolicy::BLOCK_CONSUMER;

    config.enableAdapterDetection = true;
    config.enableRoutingAnalysis = true;
    config.enableTrafficFingerprinting = false;
    config.enableIPRangeLookup = true;
    config.enableASNLookup = true;
    config.enableProcessDetection = true;

    config.enableProxyDetection = true;
    config.detectSystemProxy = true;

    config.enableLeakDetection = false;
    config.checkDNSLeak = false;
    config.checkIPv6Leak = false;

    config.identifyProvider = true;

    config.blockConsumerVPNs = true;
    config.blockAllVPNs = false;
    config.allowCorporateVPNs = true;  // Allow corporate VPNs

    config.alertOnDetection = true;
    config.alertOnLeak = false;

    config.logAllConnections = false;
    config.logDetectionsOnly = true;

    return config;
}

VPNDetectorConfig VPNDetectorConfig::CreateMonitorOnly() noexcept {
    VPNDetectorConfig config;
    config.enabled = true;
    config.policy = VPNPolicy::MONITOR;

    config.enableAdapterDetection = true;
    config.enableRoutingAnalysis = true;
    config.enableTrafficFingerprinting = false;
    config.enableIPRangeLookup = false;
    config.enableASNLookup = false;
    config.enableProcessDetection = false;

    config.enableProxyDetection = false;
    config.detectSystemProxy = false;

    config.enableLeakDetection = false;
    config.checkDNSLeak = false;
    config.checkIPv6Leak = false;

    config.identifyProvider = false;

    config.blockConsumerVPNs = false;
    config.blockAllVPNs = false;
    config.allowCorporateVPNs = true;

    config.alertOnDetection = false;
    config.alertOnLeak = false;

    config.logAllConnections = true;
    config.logDetectionsOnly = false;

    return config;
}

void VPNDetectorStatistics::Reset() noexcept {
    totalScans = 0;
    vpnConnectionsDetected = 0;
    proxyConnectionsDetected = 0;

    openvpnDetected = 0;
    wireguardDetected = 0;
    ipsecDetected = 0;
    otherProtocolsDetected = 0;

    consumerVPNsDetected = 0;
    corporateVPNsDetected = 0;
    unknownProviders = 0;

    dnsLeaksDetected = 0;
    ipv6LeaksDetected = 0;
    webrtcLeaksDetected = 0;

    adapterDetections = 0;
    routingDetections = 0;
    trafficDetections = 0;
    ipRangeDetections = 0;

    connectionsBlocked = 0;
    blockRequestedNotPerformed = 0;
    alertsGenerated = 0;

    activeVPNConnections = 0;
    virtualAdapters = 0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class VPNDetectorImpl final {
public:
    VPNDetectorImpl() = default;
    ~VPNDetectorImpl() = default;

    // Delete copy/move
    VPNDetectorImpl(const VPNDetectorImpl&) = delete;
    VPNDetectorImpl& operator=(const VPNDetectorImpl&) = delete;
    VPNDetectorImpl(VPNDetectorImpl&&) = delete;
    VPNDetectorImpl& operator=(VPNDetectorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const VPNDetectorConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            m_initialized = true;

            // Initialize Winsock
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                SS_LOG_ERROR(L"Network", L"WSAStartup failed");
                return false;
            }
            m_wsaInitialized = true;

            SS_LOG_INFO(L"Network", L"VPNDetector initialized (policy=%d, adapters=%d, proxy=%d)",
                static_cast<int>(config.policy),
                config.enableAdapterDetection ? 1 : 0,
                config.enableProxyDetection ? 1 : 0);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"VPNDetector initialization failed: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        try {
            {
                std::unique_lock lock(m_mutex);

                if (!m_initialized) {
                    SS_LOG_ERROR(L"Network", L"Cannot start: not initialized");
                    return false;
                }

                if (m_running) {
                    SS_LOG_WARN(L"Network", L"Already running");
                    return true;
                }

                m_running = true;
                m_stopRequested = false;
            }

            // Perform initial scan outside the lock
            PerformAdapterScan();

            // Start monitoring thread
            m_monitorThread = std::thread([this]() {
                MonitorThreadProc();
            });

            SS_LOG_INFO(L"Network", L"VPNDetector started");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"Start failed: %hs", e.what());
            std::unique_lock lock(m_mutex);
            m_running = false;
            return false;
        }
    }

    void Stop() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_running) return;

            m_stopRequested = true;

            lock.unlock();

            if (m_monitorThread.joinable()) {
                m_monitorThread.join();
            }

            lock.lock();

            m_running = false;

            SS_LOG_INFO(L"Network", L"VPNDetector stopped");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"Stop failed: %hs", e.what());
        }
    }

    void Shutdown() noexcept {
        try {
            // Signal stop and join thread WITHOUT holding the mutex
            m_stopRequested = true;

            if (m_monitorThread.joinable()) {
                m_monitorThread.join();
            }

            std::unique_lock lock(m_mutex);

            if (m_wsaInitialized) {
                WSACleanup();
                m_wsaInitialized = false;
            }

            m_detectionCallbacks.clear();
            m_alertCallbacks.clear();
            m_leakCallbacks.clear();
            m_adapterCallbacks.clear();

            m_activeConnections.clear();
            m_adapters.clear();

            m_running = false;
            m_initialized = false;

            SS_LOG_INFO(L"Network", L"VPNDetector shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown path
        }
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_running;
    }

    // ========================================================================
    // ADAPTER ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<NetworkAdapter> EnumerateAdapters() const {
        std::vector<NetworkAdapter> adapters;
        m_lastEnumerationOk.store(false, std::memory_order_release);

        try {
            // Bounded retry loop for ERROR_BUFFER_OVERFLOW: at most 4 attempts
            // with the buffer size suggested by the kernel. Caps total
            // allocation to MAX_ENUMERATION_BUFFER_BYTES (16 MiB) to bound
            // memory pressure under a hostile or buggy network stack.
            constexpr ULONG MAX_ENUMERATION_BUFFER_BYTES = 16 * 1024 * 1024;
            constexpr int MAX_ENUMERATION_ATTEMPTS = 4;

            ULONG bufferSize = 15000;
            std::vector<uint8_t> buffer;
            ULONG result = ERROR_BUFFER_OVERFLOW;

            for (int attempt = 0;
                 attempt < MAX_ENUMERATION_ATTEMPTS && result == ERROR_BUFFER_OVERFLOW;
                 ++attempt) {
                if (bufferSize > MAX_ENUMERATION_BUFFER_BYTES) {
                    SS_LOG_ERROR(L"Network",
                        L"GetAdaptersAddresses requested buffer %lu exceeds cap %lu; aborting",
                        bufferSize, MAX_ENUMERATION_BUFFER_BYTES);
                    return adapters;
                }
                buffer.assign(bufferSize, 0);
                result = GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                    nullptr,
                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                    &bufferSize
                );
            }

            if (result != NO_ERROR) {
                SS_LOG_ERROR(L"Network", L"GetAdaptersAddresses failed: %lu", result);
                return adapters;
            }

            PIP_ADAPTER_ADDRESSES pAdapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

            while (pAdapter) {
                NetworkAdapter adapter;

                // Names
                adapter.name = pAdapter->AdapterName ? StringUtils::ToWide(pAdapter->AdapterName) : L"";
                adapter.description = pAdapter->Description ? pAdapter->Description : L"";
                adapter.friendlyName = pAdapter->FriendlyName ? pAdapter->FriendlyName : L"";
                adapter.index = pAdapter->IfIndex;

                // MAC address
                if (pAdapter->PhysicalAddressLength == 6) {
                    std::copy(pAdapter->PhysicalAddress,
                             pAdapter->PhysicalAddress + 6,
                             adapter.macAddress.begin());
                }

                // Determine type
                adapter.type = DetermineAdapterType(adapter.name, adapter.description);
                adapter.isVirtual = IsVirtualAdapterName(adapter.friendlyName);
                adapter.isVPN = (adapter.type != AdapterType::PHYSICAL &&
                                adapter.type != AdapterType::LOOPBACK &&
                                adapter.type != AdapterType::UNKNOWN);

                // IP addresses
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
                while (pUnicast) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                        auto* ipv4 = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                        char strBuffer[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &ipv4->sin_addr, strBuffer, sizeof(strBuffer))) {
                            adapter.ipv4Addresses.push_back(strBuffer);
                        }
                    } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                        adapter.ipv6Addresses.push_back(IPv6ToString(ipv6->sin6_addr));
                    }
                    pUnicast = pUnicast->Next;
                }

                // Gateway
                PIP_ADAPTER_GATEWAY_ADDRESS pGateway = pAdapter->FirstGatewayAddress;
                if (pGateway && pGateway->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* ipv4 = reinterpret_cast<sockaddr_in*>(pGateway->Address.lpSockaddr);
                    char strBuffer[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &ipv4->sin_addr, strBuffer, sizeof(strBuffer))) {
                        adapter.gateway = strBuffer;
                        adapter.isDefaultGateway = true;
                    }
                }

                // DNS servers
                PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pAdapter->FirstDnsServerAddress;
                while (pDns) {
                    if (pDns->Address.lpSockaddr->sa_family == AF_INET) {
                        auto* ipv4 = reinterpret_cast<sockaddr_in*>(pDns->Address.lpSockaddr);
                        char strBuffer[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &ipv4->sin_addr, strBuffer, sizeof(strBuffer))) {
                            adapter.dnsServers.push_back(strBuffer);
                        }
                    }
                    pDns = pDns->Next;
                }

                // Status
                adapter.isEnabled = (pAdapter->OperStatus == IfOperStatusUp);
                adapter.isConnected = (pAdapter->OperStatus == IfOperStatusUp);
                adapter.speed = pAdapter->TransmitLinkSpeed;
                adapter.metric = pAdapter->Ipv4Metric;

                // VPN protocol detection
                adapter.vpnProtocol = DetectProtocolFromAdapter(adapter.type);

                adapters.push_back(adapter);

                pAdapter = pAdapter->Next;
            }

            m_lastEnumerationOk.store(true, std::memory_order_release);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EnumerateAdapters - Exception: %hs", e.what());
        }

        return adapters;
    }

    // ========================================================================
    // VPN DETECTION
    // ========================================================================

    [[nodiscard]] std::optional<VPNConnection> DetectVPNInternal() {
        try {
            auto adapters = EnumerateAdapters();

            for (const auto& adapter : adapters) {
                if (adapter.isVPN && adapter.isConnected) {
                    // Found active VPN adapter
                    VPNConnection connection = CreateConnectionFromAdapter(adapter);

                    // Routing table analysis for split/full tunnel detection
                    if (m_config.enableRoutingAnalysis) {
                        AnalyzeRoutingTable(connection);
                    }

                    // Process-based VPN detection
                    if (m_config.enableProcessDetection) {
                        DetectVPNProcess(connection);
                    }

                    // Registry-based provider identification
                    if (connection.provider == VPNProvider::UNKNOWN) {
                        DetectVPNFromRegistry(connection);
                    }

                    // IP range lookup via ThreatIntel
                    if (m_config.enableIPRangeLookup) {
                        IdentifyProviderByIP(connection);
                    }

                    // Leak detection
                    if (m_config.enableLeakDetection) {
                        DetectLeaks(connection);
                    }

                    // Clamp confidence to [0, 1]
                    connection.confidence = std::clamp(connection.confidence, 0.0, 1.0);

                    return connection;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectVPNInternal - Exception: %hs", e.what());
        }

        return std::nullopt;
    }

    [[nodiscard]] VPNConnection CreateConnectionFromAdapter(const NetworkAdapter& adapter) const {
        VPNConnection connection;

        connection.connectionId = ++m_nextConnectionId;

        // Adapter info
        connection.adapterName = adapter.friendlyName;
        connection.adapterIndex = adapter.index;
        connection.adapterType = adapter.type;

        // Protocol
        connection.protocol = adapter.vpnProtocol;

        // Provider (will be refined by other detection methods)
        connection.provider = VPNProvider::UNKNOWN;
        connection.providerName = L"Unknown";

        // Network
        if (!adapter.ipv4Addresses.empty()) {
            connection.virtualIP = adapter.ipv4Addresses[0];
        }
        connection.vpnGateway = adapter.gateway;

        // Detection
        connection.detectionMethod = VPNDetectionMethod::ADAPTER_TYPE;
        connection.confidence = 0.85;
        connection.allMethods.push_back(VPNDetectionMethod::ADAPTER_TYPE);

        // Timing
        connection.detectedAt = std::chrono::system_clock::now();

        return connection;
    }

    void DetectVPNProcess(VPNConnection& connection) const {
        try {
            std::vector<ProcessUtils::ProcessId> pids;
            if (!ProcessUtils::EnumerateProcesses(pids)) {
                return;
            }

            for (auto pid : pids) {
                auto nameOpt = ProcessUtils::GetProcessName(pid);
                if (!nameOpt.has_value()) continue;

                std::wstring lowerName = StringUtils::ToLowerCopy(nameOpt.value());

                for (const auto& vpnProc : VPN_PROCESS_NAMES) {
                    if (lowerName == StringUtils::ToLowerCopy(vpnProc)) {
                        connection.processId = pid;
                        connection.processName = StringUtils::ToNarrow(nameOpt.value());

                        auto pathOpt = ProcessUtils::GetProcessPath(pid);
                        if (pathOpt.has_value()) {
                            connection.processPath = pathOpt.value();
                        }

                        connection.allMethods.push_back(VPNDetectionMethod::PROCESS_DETECTION);
                        connection.confidence += 0.1;

                        // Identify provider from process name
                        IdentifyProviderFromProcess(connection, lowerName);

                        return;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectVPNProcess - Exception: %hs", e.what());
        }
    }

    void IdentifyProviderFromProcess(VPNConnection& connection, const std::wstring& processName) const {
        if (processName.find(L"nordvpn") != std::wstring::npos) {
            connection.provider = VPNProvider::NORDVPN;
            connection.providerName = L"NordVPN";
        } else if (processName.find(L"expressvpn") != std::wstring::npos) {
            connection.provider = VPNProvider::EXPRESSVPN;
            connection.providerName = L"ExpressVPN";
        } else if (processName.find(L"surfshark") != std::wstring::npos) {
            connection.provider = VPNProvider::SURFSHARK;
            connection.providerName = L"Surfshark";
        } else if (processName.find(L"mullvad") != std::wstring::npos) {
            connection.provider = VPNProvider::MULLVAD;
            connection.providerName = L"Mullvad";
        } else if (processName.find(L"protonvpn") != std::wstring::npos) {
            connection.provider = VPNProvider::PROTONVPN;
            connection.providerName = L"ProtonVPN";
        } else if (processName.find(L"cyberghost") != std::wstring::npos) {
            connection.provider = VPNProvider::CYBERGHOST;
            connection.providerName = L"CyberGhost";
        } else if (processName.find(L"ipvanish") != std::wstring::npos) {
            connection.provider = VPNProvider::IPVANISH;
            connection.providerName = L"IPVanish";
        } else if (processName.find(L"windscribe") != std::wstring::npos) {
            connection.provider = VPNProvider::WINDSCRIBE;
            connection.providerName = L"Windscribe";
        } else if (processName.find(L"tunnelbear") != std::wstring::npos) {
            connection.provider = VPNProvider::TUNNELBEAR;
            connection.providerName = L"TunnelBear";
        } else if (processName.find(L"anyconnect") != std::wstring::npos) {
            connection.provider = VPNProvider::CISCO_ANYCONNECT_PROVIDER;
            connection.providerName = L"Cisco AnyConnect";
        } else if (processName.find(L"globalprotect") != std::wstring::npos) {
            connection.provider = VPNProvider::PALO_ALTO;
            connection.providerName = L"GlobalProtect";
        } else if (processName.find(L"pulsesecure") != std::wstring::npos) {
            connection.provider = VPNProvider::PULSE_SECURE_PROVIDER;
            connection.providerName = L"Pulse Secure";
        }
    }

    void IdentifyProviderByIP(VPNConnection& connection) const {
        try {
            if (connection.remoteServerIP.empty() && connection.virtualIP.empty()) return;

            const std::string& queryIP = connection.remoteServerIP.empty()
                ? connection.virtualIP : connection.remoteServerIP;

            // Query the orchestrator-injected ThreatIntelLookup for known
            // VPN/proxy/anonymizer IP ranges. The pointer is owned by the
            // orchestrator; we hold only a non-owning atomic reference.
            ThreatIntel::ThreatIntelLookup* threatIntel =
                m_threatIntelLookup.load(std::memory_order_acquire);

            if (threatIntel != nullptr && threatIntel->IsInitialized()) {
                auto result = threatIntel->LookupIPv4(queryIP);
                if (result.found) {
                    if (result.IsSuspicious() || result.IsMalicious()) {
                        connection.confidence += 0.15;
                        SS_LOG_WARN(L"Network",
                            L"VPN endpoint IP %hs flagged by ThreatIntel (score=%u)",
                            queryIP.c_str(),
                            static_cast<unsigned>(result.threatScore));
                    }
                    connection.allMethods.push_back(VPNDetectionMethod::IP_RANGE);
                } else {
                    SS_LOG_DEBUG(L"Network",
                        L"VPN endpoint IP %hs not found in ThreatIntel database",
                        queryIP.c_str());
                }
            } else {
                // Log once per orchestrator-wiring state transition rather
                // than on every scan to avoid log flooding when ThreatIntel
                // is intentionally not wired (e.g. lightweight deployments).
                if (!m_threatIntelMissingLogged.exchange(true, std::memory_order_acq_rel)) {
                    SS_LOG_DEBUG(L"Network",
                        L"ThreatIntelLookup not wired; skipping IP reputation check for %hs",
                        queryIP.c_str());
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"IdentifyProviderByIP - Exception: %hs", e.what());
        }
    }

    void DetectLeaks(VPNConnection& connection) const {
        try {
            // DNS leak detection
            if (m_config.checkDNSLeak) {
                if (CheckDNSLeakInternal()) {
                    connection.hasDNSLeak = true;
                    connection.detectedLeaks.push_back(LeakType::DNS_LEAK);
                }
            }

            // IPv6 leak detection
            if (m_config.checkIPv6Leak) {
                if (CheckIPv6LeakInternal()) {
                    connection.hasIPv6Leak = true;
                    connection.detectedLeaks.push_back(LeakType::IPV6_LEAK);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectLeaks - Exception: %hs", e.what());
        }
    }

    [[nodiscard]] bool CheckDNSLeakInternal() const {
        try {
            // Get all adapters
            auto adapters = EnumerateAdapters();

            // Find VPN adapter index
            uint32_t vpnAdapterIndex = 0;
            bool foundVPN = false;
            for (const auto& adapter : adapters) {
                if (adapter.isVPN && adapter.isConnected) {
                    vpnAdapterIndex = adapter.index;
                    foundVPN = true;
                    break;
                }
            }

            if (!foundVPN) return false;

            // Check if DNS servers are different from VPN's DNS
            for (const auto& adapter : adapters) {
                if (adapter.index == vpnAdapterIndex) continue;
                if (!adapter.isConnected) continue;

                // If another adapter has DNS servers configured, it's a leak
                if (!adapter.dnsServers.empty()) {
                    SS_LOG_WARN(L"Network", L"DNS leak detected: Adapter '%ls' has DNS servers while VPN active",
                        adapter.friendlyName.c_str());
                    return true;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CheckDNSLeakInternal - Exception: %hs", e.what());
        }

        return false;
    }

    [[nodiscard]] bool CheckIPv6LeakInternal() const {
        try {
            auto adapters = EnumerateAdapters();

            // Find VPN adapter
            bool hasVPN = false;
            for (const auto& adapter : adapters) {
                if (adapter.isVPN && adapter.isConnected) {
                    hasVPN = true;
                    break;
                }
            }

            if (!hasVPN) return false;

            // Check if any non-VPN adapter has IPv6
            for (const auto& adapter : adapters) {
                if (adapter.isVPN) continue;
                if (!adapter.isConnected) continue;

                if (!adapter.ipv6Addresses.empty()) {
                    SS_LOG_WARN(L"Network", L"IPv6 leak detected: Adapter '%ls' has IPv6 while VPN active",
                        adapter.friendlyName.c_str());
                    return true;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CheckIPv6LeakInternal - Exception: %hs", e.what());
        }

        return false;
    }

    // ========================================================================
    // PROXY DETECTION
    // ========================================================================

    [[nodiscard]] ProxyInfo DetectProxyInternal() const {
        ProxyInfo proxy;

        try {
            if (!m_config.enableProxyDetection) {
                return proxy;
            }

            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = {};

            // RAII wrapper for WinHTTP module handle
            struct HModuleDeleter { void operator()(HMODULE h) const noexcept { if (h) FreeLibrary(h); } };
            std::unique_ptr<std::remove_pointer_t<HMODULE>, HModuleDeleter> hWinHttp(
                LoadLibraryW(L"winhttp.dll"));
            if (!hWinHttp) return proxy;

            typedef BOOL (WINAPI *WinHttpGetIEProxyConfigForCurrentUser_t)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG*);
            auto pWinHttpGetIEProxyConfigForCurrentUser =
                reinterpret_cast<WinHttpGetIEProxyConfigForCurrentUser_t>(
                    GetProcAddress(hWinHttp.get(), "WinHttpGetIEProxyConfigForCurrentUser"));

            if (pWinHttpGetIEProxyConfigForCurrentUser) {
                if (pWinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
                    // RAII guard for GlobalFree of proxy config strings
                    // These MUST be freed even if parsing throws
                    struct ProxyConfigGuard {
                        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& cfg;
                        ~ProxyConfigGuard() {
                            if (cfg.lpszProxy) GlobalFree(cfg.lpszProxy);
                            if (cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
                            if (cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
                        }
                    } guard{proxyConfig};

                    if (proxyConfig.lpszProxy) {
                        std::wstring proxyStr(proxyConfig.lpszProxy);

                        // Parse proxy string (format: "http://host:port" or "host:port")
                        // Strip scheme prefix first
                        std::wstring normalized = proxyStr;
                        if (normalized.starts_with(L"http://")) {
                            normalized = normalized.substr(7);
                        } else if (normalized.starts_with(L"https://")) {
                            normalized = normalized.substr(8);
                        }

                        size_t colonPos = normalized.rfind(L':');
                        if (colonPos != std::wstring::npos && colonPos > 0) {
                            std::wstring hostPart = normalized.substr(0, colonPos);
                            std::wstring portPart = normalized.substr(colonPos + 1);

                            proxy.isActive = true;
                            proxy.proxyHost = StringUtils::ToNarrow(hostPart);
                            try {
                                unsigned long portVal = std::stoul(portPart);
                                if (portVal > 65535) portVal = 0;
                                proxy.proxyPort = static_cast<uint16_t>(portVal);
                            } catch (...) {
                                proxy.proxyPort = 0;
                            }
                            proxy.type = ProxyType::HTTP;
                            proxy.isSystemProxy = true;
                            proxy.confidence = 0.95;
                        }
                    }

                    if (proxyConfig.lpszAutoConfigUrl) {
                        proxy.isPACConfigured = true;
                        proxy.pacUrl = StringUtils::ToNarrow(proxyConfig.lpszAutoConfigUrl);
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectProxyInternal - Exception: %hs", e.what());
        }

        return proxy;
    }

    // ========================================================================
    // MONITORING
    // ========================================================================

    void MonitorThreadProc() {
        SS_LOG_DEBUG(L"Network", L"VPN monitor thread started");

        while (!m_stopRequested) {
            try {
                PerformAdapterScan();

                if (m_config.enableLeakDetection) {
                    PerformLeakCheck();
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"MonitorThreadProc - Exception: %hs", e.what());
            }

            // Sleep with stop check
            for (uint32_t i = 0; i < ADAPTER_SCAN_INTERVAL_MS / 100 && !m_stopRequested; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        SS_LOG_DEBUG(L"Network", L"VPN monitor thread stopped");
    }

    void PerformAdapterScan() {
        try {
            m_stats.totalScans++;

            auto adapters = EnumerateAdapters();

            // If enumeration failed (returned empty due to an OS error rather
            // than a genuine "no adapters" state), skip change detection and
            // do not poison the cached adapter list. Otherwise a transient
            // GetAdaptersAddresses failure would make every adapter look
            // "removed" and then "added" on the next successful scan,
            // generating spurious change-callback storms.
            if (!m_lastEnumerationOk.load(std::memory_order_acquire)) {
                SS_LOG_DEBUG(L"Network",
                    L"VPN adapter scan skipped: enumeration failed transiently");
                return;
            }

            // Detect adapter changes before overwriting the cached list
            DetectAdapterChanges(adapters);

            {
                std::unique_lock lock(m_mutex);
                m_adapters = adapters;
            }

            // Count virtual adapters (stats are atomic, no lock needed)
            uint32_t virtualCount = 0;
            for (const auto& adapter : adapters) {
                if (adapter.isVirtual) virtualCount++;
            }
            m_stats.virtualAdapters = virtualCount;

            // Detect VPN connections WITHOUT holding the mutex
            DetectAndNotifyVPNConnections();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"PerformAdapterScan - Exception: %hs", e.what());
        }
    }

    void DetectAndNotifyVPNConnections() {
        try {
            auto vpnOpt = DetectVPNInternal();

            if (vpnOpt.has_value()) {
                auto& connection = vpnOpt.value();

                // Update atomic statistics (no lock needed)
                m_stats.vpnConnectionsDetected++;

                // Protocol statistics
                if (connection.protocol == VPNProtocol::OPENVPN_UDP ||
                    connection.protocol == VPNProtocol::OPENVPN_TCP) {
                    m_stats.openvpnDetected++;
                } else if (connection.protocol == VPNProtocol::WIREGUARD) {
                    m_stats.wireguardDetected++;
                } else if (connection.protocol == VPNProtocol::IPSEC_IKEV1 ||
                          connection.protocol == VPNProtocol::IPSEC_IKEV2) {
                    m_stats.ipsecDetected++;
                } else {
                    m_stats.otherProtocolsDetected++;
                }

                // Provider statistics using helper to avoid reliance on enum contiguity
                if (IsConsumerVPN(connection.provider)) {
                    m_stats.consumerVPNsDetected++;
                } else if (IsCorporateVPN(connection.provider)) {
                    m_stats.corporateVPNsDetected++;
                } else {
                    m_stats.unknownProviders++;
                }

                // Store connection under lock; reuse existing entry keyed by
                // adapter index to prevent connectionId churn (the same
                // adapter scanned across N intervals must keep the same
                // connectionId, otherwise external callers cannot correlate
                // FeedPacket() / AnalyzeTraffic() / IdentifyProvider() calls
                // and the map grows by one entry per scan until eviction).
                {
                    std::unique_lock lock(m_mutex);

                    bool reused = false;
                    for (auto& [existingId, existingConn] : m_activeConnections) {
                        if (existingConn.adapterIndex == connection.adapterIndex) {
                            // Preserve the existing connection ID and
                            // detectedAt timestamp so callers and eviction
                            // logic see a stable lifetime for this VPN.
                            connection.connectionId = existingId;
                            connection.detectedAt = existingConn.detectedAt;
                            existingConn = connection;
                            reused = true;
                            break;
                        }
                    }

                    if (!reused) {
                        // Evict oldest connections if at capacity. Hard cap
                        // bounds memory under abnormal adapter-index churn.
                        while (m_activeConnections.size() >= MAX_ACTIVE_CONNECTIONS) {
                            auto oldest = m_activeConnections.begin();
                            for (auto it = m_activeConnections.begin();
                                 it != m_activeConnections.end(); ++it) {
                                if (it->second.detectedAt < oldest->second.detectedAt) {
                                    oldest = it;
                                }
                            }
                            m_activeConnections.erase(oldest);
                        }

                        m_activeConnections[connection.connectionId] = connection;
                    }

                    m_stats.activeVPNConnections =
                        static_cast<uint32_t>(m_activeConnections.size());
                }

                // Apply policy and invoke callbacks WITHOUT holding the mutex
                ApplyPolicy(connection);
                InvokeDetectionCallbacks(connection);

            } else {
                // No active VPN found; clear stale connections
                {
                    std::unique_lock lock(m_mutex);
                    m_activeConnections.clear();
                    m_stats.activeVPNConnections = 0;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectAndNotifyVPNConnections - Exception: %hs", e.what());
        }
    }

    void PerformLeakCheck() {
        try {
            if (CheckDNSLeakInternal()) {
                m_stats.dnsLeaksDetected++;
                InvokeLeakCallbacks(LeakType::DNS_LEAK, "DNS leak detected");
            }

            if (CheckIPv6LeakInternal()) {
                m_stats.ipv6LeaksDetected++;
                InvokeLeakCallbacks(LeakType::IPV6_LEAK, "IPv6 leak detected");
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"PerformLeakCheck - Exception: %hs", e.what());
        }
    }

    // ========================================================================
    // VPN PROVIDER CLASSIFICATION (avoids relying on enum contiguity)
    // ========================================================================

    [[nodiscard]] static bool IsConsumerVPN(VPNProvider provider) noexcept {
        switch (provider) {
            case VPNProvider::NORDVPN:
            case VPNProvider::EXPRESSVPN:
            case VPNProvider::SURFSHARK:
            case VPNProvider::PRIVATE_INTERNET_ACCESS:
            case VPNProvider::MULLVAD:
            case VPNProvider::PROTONVPN:
            case VPNProvider::CYBERGHOST:
            case VPNProvider::IPVANISH:
            case VPNProvider::WINDSCRIBE:
            case VPNProvider::HIDE_MY_ASS:
            case VPNProvider::TUNNELBEAR:
            case VPNProvider::HOTSPOT_SHIELD:
                return true;
            default:
                return false;
        }
    }

    [[nodiscard]] static bool IsCorporateVPN(VPNProvider provider) noexcept {
        switch (provider) {
            case VPNProvider::CISCO_ANYCONNECT_PROVIDER:
            case VPNProvider::PALO_ALTO:
            case VPNProvider::FORTINET_PROVIDER:
            case VPNProvider::PULSE_SECURE_PROVIDER:
            case VPNProvider::F5_BIG_IP:
            case VPNProvider::CHECK_POINT:
            case VPNProvider::CITRIX_NETSCALER:
            case VPNProvider::ZSCALER:
            case VPNProvider::MICROSOFT_ALWAYS_ON:
                return true;
            default:
                return false;
        }
    }

    // ========================================================================
    // ROUTING TABLE ANALYSIS
    // ========================================================================

    void AnalyzeRoutingTable(VPNConnection& connection) const {
        try {
            std::vector<NetworkUtils::RouteEntry> routes;
            NetworkUtils::Error err;
            if (!NetworkUtils::GetRoutingTable(routes, &err)) {
                SS_LOG_WARN(L"Network", L"AnalyzeRoutingTable - GetRoutingTable failed: %ls",
                    err.message.c_str());
                return;
            }

            if (routes.empty()) return;

            // Find default route(s) - routes to 0.0.0.0/0
            size_t defaultRouteCount = 0;
            bool foundVPNDefault = false;
            uint32_t lowestMetric = UINT32_MAX;
            std::string defaultGatewayIP;

            for (const auto& route : routes) {
                if (!route.destination.IsValid()) continue;
                if (!route.destination.IsIPv4()) continue;
                const auto* dst = route.destination.AsIPv4();
                if (!dst) continue;

                // Default route: destination 0.0.0.0
                if (dst->ToUInt32() == 0) {
                    defaultRouteCount++;

                    if (route.metric < lowestMetric) {
                        lowestMetric = route.metric;
                        if (route.gateway.IsIPv4() && route.gateway.AsIPv4()) {
                            defaultGatewayIP = StringUtils::ToNarrow(
                                route.gateway.AsIPv4()->ToString());
                        }
                    }

                    // Check if the default route goes through the VPN adapter
                    if (route.interfaceIndex == connection.adapterIndex) {
                        foundVPNDefault = true;
                    }
                }
            }

            if (foundVPNDefault) {
                // VPN owns the default route = full tunnel
                connection.isFullTunnel = true;
                connection.isSplitTunnel = false;
                connection.vpnGateway = defaultGatewayIP;
                connection.confidence += 0.10;
                connection.allMethods.push_back(VPNDetectionMethod::ROUTING_TABLE);

                SS_LOG_INFO(L"Network",
                    L"Full-tunnel VPN detected: default route via adapter %u (metric %u)",
                    connection.adapterIndex, lowestMetric);
            } else if (defaultRouteCount > 1) {
                // Multiple default routes may indicate split tunneling
                connection.isFullTunnel = false;
                connection.isSplitTunnel = true;
                connection.allMethods.push_back(VPNDetectionMethod::ROUTING_TABLE);

                SS_LOG_INFO(L"Network",
                    L"Split-tunnel VPN detected: %zu default routes present",
                    defaultRouteCount);
            }

            // Store original gateway for leak detection context
            if (!defaultGatewayIP.empty() && connection.originalGateway.empty()) {
                connection.originalGateway = defaultGatewayIP;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeRoutingTable - Exception: %hs", e.what());
        }
    }

    // ========================================================================
    // REGISTRY-BASED VPN DETECTION
    // ========================================================================

    void DetectVPNFromRegistry(VPNConnection& connection) const {
        try {
            for (const auto& regPath : VPN_REGISTRY_PATHS) {
                Utils::RegistryUtils::RegistryKey key;
                Utils::RegistryUtils::Error regErr;

                Utils::RegistryUtils::OpenOptions opts;
                opts.access = KEY_READ;

                if (key.Open(HKEY_LOCAL_MACHINE, regPath, opts, &regErr)) {
                    // Registry key exists = VPN software installed
                    // Try to identify which provider
                    std::wstring lowerPath = StringUtils::ToLowerCopy(regPath);

                    if (lowerPath.find(L"openvpn") != std::wstring::npos &&
                        connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::OPENVPN_SELF;
                        connection.providerName = L"OpenVPN";
                    } else if (lowerPath.find(L"wireguard") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::WIREGUARD_SELF;
                        connection.providerName = L"WireGuard";
                    } else if (lowerPath.find(L"nordvpn") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::NORDVPN;
                        connection.providerName = L"NordVPN";
                    } else if (lowerPath.find(L"expressvpn") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::EXPRESSVPN;
                        connection.providerName = L"ExpressVPN";
                    } else if (lowerPath.find(L"surfshark") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::SURFSHARK;
                        connection.providerName = L"Surfshark";
                    } else if (lowerPath.find(L"mullvad") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::MULLVAD;
                        connection.providerName = L"Mullvad";
                    } else if (lowerPath.find(L"protonvpn") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::PROTONVPN;
                        connection.providerName = L"ProtonVPN";
                    } else if (lowerPath.find(L"cisco") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::CISCO_ANYCONNECT_PROVIDER;
                        connection.providerName = L"Cisco AnyConnect";
                    } else if (lowerPath.find(L"globalprotect") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::PALO_ALTO;
                        connection.providerName = L"GlobalProtect";
                    } else if (lowerPath.find(L"pulse") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::PULSE_SECURE_PROVIDER;
                        connection.providerName = L"Pulse Secure";
                    } else if (lowerPath.find(L"fortinet") != std::wstring::npos &&
                               connection.provider == VPNProvider::UNKNOWN) {
                        connection.provider = VPNProvider::FORTINET_PROVIDER;
                        connection.providerName = L"Fortinet";
                    }

                    if (connection.provider != VPNProvider::UNKNOWN) {
                        // Only add confidence if we actually identified a provider
                        connection.confidence += 0.05;
                        SS_LOG_DEBUG(L"Network",
                            L"VPN software detected via registry: %ls",
                            connection.providerName.c_str());
                        return;  // Found a match, no need to continue
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectVPNFromRegistry - Exception: %hs", e.what());
        }
    }

    // ========================================================================
    // ADAPTER CHANGE DETECTION
    // ========================================================================

    void DetectAdapterChanges(const std::vector<NetworkAdapter>& newAdapters) {
        // Compare old vs new adapter list; invoke adapter callbacks for changes
        std::vector<NetworkAdapter> oldAdapters;
        {
            std::shared_lock lock(m_mutex);
            oldAdapters = m_adapters;
        }

        // Build sets of adapter indices
        std::unordered_set<uint32_t> oldIndices;
        for (const auto& a : oldAdapters) oldIndices.insert(a.index);
        std::unordered_set<uint32_t> newIndices;
        for (const auto& a : newAdapters) newIndices.insert(a.index);

        // Copy callbacks under lock
        std::vector<AdapterChangeCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_adapterCallbacks.size());
            for (const auto& [id, cb] : m_adapterCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        if (callbacks.empty()) return;

        // Detect added adapters
        for (const auto& adapter : newAdapters) {
            if (oldIndices.find(adapter.index) == oldIndices.end()) {
                for (const auto& cb : callbacks) {
                    try {
                        cb(adapter, true /* added */);
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(L"Network",
                            L"AdapterChangeCallback exception (added): %hs", e.what());
                    }
                }
            }
        }

        // Detect removed adapters
        for (const auto& adapter : oldAdapters) {
            if (newIndices.find(adapter.index) == newIndices.end()) {
                for (const auto& cb : callbacks) {
                    try {
                        cb(adapter, false /* removed */);
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(L"Network",
                            L"AdapterChangeCallback exception (removed): %hs", e.what());
                    }
                }
            }
        }
    }

    // ========================================================================
    // POLICY ENFORCEMENT
    // ========================================================================

    void ApplyPolicy(VPNConnection& connection) {
        try {
            bool shouldBlock = false;

            VPNPolicy currentPolicy;
            std::vector<std::wstring> allowedAdapters;
            {
                std::shared_lock lock(m_mutex);
                currentPolicy = m_config.policy;
                allowedAdapters = m_config.allowedAdapters;
            }

            // Check policy
            if (currentPolicy == VPNPolicy::BLOCK_ALL) {
                shouldBlock = true;
            } else if (currentPolicy == VPNPolicy::BLOCK_CONSUMER) {
                // Block consumer VPNs
                if (IsConsumerVPN(connection.provider)) {
                    shouldBlock = true;
                }
            }

            // Check exceptions
            if (shouldBlock) {
                std::wstring lowerAdapterName = StringUtils::ToLowerCopy(connection.adapterName);
                for (const auto& allowed : allowedAdapters) {
                    if (lowerAdapterName == StringUtils::ToLowerCopy(allowed)) {
                        shouldBlock = false;
                        break;
                    }
                }
            }

            if (shouldBlock) {
                // POLICY SELECTED THIS CONNECTION, AND THAT IS ALL THAT HAPPENS
                // HERE. Nothing below disables the adapter, installs a WFP
                // filter, adds a firewall rule or terminates the owning
                // process, so the connection continues. The previous version of
                // this branch logged "Blocking VPN connection", incremented a
                // counter named connectionsBlocked and raised an alert whose
                // description read "VPN connection blocked" - three statements
                // of an outcome that never occurred.
                SS_LOG_WARN(L"Network",
                    L"VPN connection DETECTED BUT NOT BLOCKED (policy asked for a block; "
                    L"nothing in this build stops a VPN connection): %ls (policy=%d)",
                    connection.providerName.c_str(),
                    static_cast<int>(currentPolicy));

                m_stats.blockRequestedNotPerformed++;

                // Generate alert, recording the request rather than an outcome
                GenerateAlert(connection, /*blockRequested=*/true);

            } else if (currentPolicy == VPNPolicy::MONITOR ||
                      currentPolicy == VPNPolicy::ALERT_ONLY) {
                bool alertOnDetection;
                {
                    std::shared_lock lock(m_mutex);
                    alertOnDetection = m_config.alertOnDetection;
                }
                if (alertOnDetection) {
                    GenerateAlert(connection, false);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ApplyPolicy - Exception: %hs", e.what());
        }
    }

    // The second parameter is the policy's REQUEST, not an outcome. It was
    // previously named wasBlocked and assigned straight to alert.wasBlocked,
    // which is how a configured policy came to be reported as a performed
    // block on a module that performs none.
    void GenerateAlert(const VPNConnection& connection, bool blockRequested) {
        VPNAlert alert;
        alert.alertId = ++m_nextAlertId;
        alert.timestamp = std::chrono::system_clock::now();

        alert.method = connection.detectionMethod;
        alert.confidence = connection.confidence;

        alert.protocol = connection.protocol;
        alert.provider = connection.provider;
        alert.providerName = connection.providerName;

        alert.virtualIP = connection.virtualIP;
        alert.remoteServer = connection.remoteServerIP;

        alert.processId = connection.processId;
        alert.processPath = connection.processPath;
        alert.processName = connection.processName;

        // Three states, not two: a plain detection, a detection whose requested
        // block was not carried out, and - once a real enforcement path exists -
        // an actual block. Collapsing the middle state into the last is exactly
        // the defect being removed, so it is spelled out here.
        if (blockRequested) {
            alert.description = "VPN connection DETECTED BUT NOT BLOCKED "
                                "(policy asked for a block; nothing in this build "
                                "stops a VPN connection)";
        } else {
            alert.description = "VPN connection detected";
        }

        {
            std::shared_lock lock(m_mutex);
            alert.appliedPolicy = m_config.policy;
        }
        alert.blockRequested = blockRequested;
        alert.wasBlocked = false;

        alert.leaks = connection.detectedLeaks;

        m_stats.alertsGenerated++;

        // Invoke alert callbacks
        InvokeAlertCallbacks(alert);

        SS_LOG_INFO(L"Network", L"VPN alert: %hs (provider=%ls, confidence=%.2f)",
            alert.description.c_str(),
            connection.providerName.c_str(),
            connection.confidence);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeDetectionCallbacks(const VPNConnection& connection) {
        // Copy callbacks under lock, invoke outside to prevent deadlock
        std::vector<VPNDetectionCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_detectionCallbacks.size());
            for (const auto& [id, cb] : m_detectionCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        for (const auto& cb : callbacks) {
            try {
                cb(connection);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"VPN detection callback threw: %hs", e.what());
            }
        }
    }

    void InvokeAlertCallbacks(const VPNAlert& alert) {
        std::vector<VPNAlertCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_alertCallbacks.size());
            for (const auto& [id, cb] : m_alertCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        for (const auto& cb : callbacks) {
            try {
                cb(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"VPN alert callback threw: %hs", e.what());
            }
        }
    }

    void InvokeLeakCallbacks(LeakType leak, const std::string& details) {
        std::vector<LeakCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks.reserve(m_leakCallbacks.size());
            for (const auto& [id, cb] : m_leakCallbacks) {
                if (cb) callbacks.push_back(cb);
            }
        }

        for (const auto& cb : callbacks) {
            try {
                cb(leak, details);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"VPN leak callback threw: %hs", e.what());
            }
        }
    }

    uint64_t RegisterDetectionCallback(VPNDetectionCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_detectionCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlertCallback(VPNAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterLeakCallback(LeakCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_leakCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAdapterCallback(AdapterChangeCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_adapterCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);

        bool removed = false;
        removed |= (m_detectionCallbacks.erase(callbackId) > 0);
        removed |= (m_alertCallbacks.erase(callbackId) > 0);
        removed |= (m_leakCallbacks.erase(callbackId) > 0);
        removed |= (m_adapterCallbacks.erase(callbackId) > 0);

        return removed;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const VPNDetectorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const {
        std::shared_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"Network", L"=== VPNDetector Diagnostics ===");
            SS_LOG_INFO(L"Network", L"Initialized: %d", m_initialized ? 1 : 0);
            SS_LOG_INFO(L"Network", L"Running: %d", m_running ? 1 : 0);
            SS_LOG_INFO(L"Network", L"Policy: %d", static_cast<int>(m_config.policy));
            SS_LOG_INFO(L"Network", L"Total scans: %llu", m_stats.totalScans.load());
            SS_LOG_INFO(L"Network", L"VPN connections detected: %llu", m_stats.vpnConnectionsDetected.load());
            SS_LOG_INFO(L"Network", L"Active VPN connections: %u", m_stats.activeVPNConnections.load());
            SS_LOG_INFO(L"Network", L"Virtual adapters: %u", m_stats.virtualAdapters.load());
            SS_LOG_INFO(L"Network", L"Connections blocked: %llu", m_stats.connectionsBlocked.load());
            SS_LOG_INFO(L"Network", L"Block requested but not performed: %llu",
                        m_stats.blockRequestedNotPerformed.load());
            SS_LOG_INFO(L"Network", L"DNS leaks: %llu", m_stats.dnsLeaksDetected.load());
            SS_LOG_INFO(L"Network", L"IPv6 leaks: %llu", m_stats.ipv6LeaksDetected.load());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"PerformDiagnostics - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_running{ false };
    bool m_wsaInitialized{ false };
    std::atomic<bool> m_stopRequested{ false };

    VPNDetectorConfig m_config;
    VPNDetectorStatistics m_stats;

    // Monitoring
    std::thread m_monitorThread;

    // State
    std::vector<NetworkAdapter> m_adapters;
    std::unordered_map<uint64_t, VPNConnection> m_activeConnections;

    // Callbacks
    std::unordered_map<uint64_t, VPNDetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, VPNAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, LeakCallback> m_leakCallbacks;
    std::unordered_map<uint64_t, AdapterChangeCallback> m_adapterCallbacks;
    uint64_t m_nextCallbackId{ 0 };

    // ID generation
    mutable std::atomic<uint64_t> m_nextConnectionId{ 1 };
    std::atomic<uint64_t> m_nextAlertId{ 1 };

    // Orchestrator-injected dependencies (non-owning).
    // Atomic for lock-free reads from hot detection paths and to allow the
    // orchestrator to update wiring without synchronizing with m_mutex.
    std::atomic<ThreatIntel::ThreatIntelLookup*> m_threatIntelLookup{ nullptr };

    // Tracks whether the most recent EnumerateAdapters() call observed a
    // successful GetAdaptersAddresses() return; used to suppress spurious
    // adapter add/remove storms on transient failures. Mutable because
    // EnumerateAdapters() is logically const.
    mutable std::atomic<bool> m_lastEnumerationOk{ false };

    // Throttle for "ThreatIntel not wired" debug logging — we log once per
    // wiring transition rather than once per scan.
    mutable std::atomic<bool> m_threatIntelMissingLogged{ false };
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

VPNDetector& VPNDetector::Instance() {
    static VPNDetector instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

VPNDetector::VPNDetector()
    : m_impl(std::make_unique<VPNDetectorImpl>()) {
    SS_LOG_INFO(L"Network", L"VPNDetector instance created");
}

VPNDetector::~VPNDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Network", L"VPNDetector instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool VPNDetector::Initialize(const VPNDetectorConfig& config) {
    return m_impl->Initialize(config);
}

bool VPNDetector::Start() {
    return m_impl->Start();
}

void VPNDetector::Stop() {
    m_impl->Stop();
}

void VPNDetector::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool VPNDetector::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

// ========================================================================
// VPN DETECTION
// ========================================================================

VPNInfo VPNDetector::GetCurrentVPN() {
    auto vpnOpt = m_impl->DetectVPNInternal();

    VPNInfo info;
    if (vpnOpt.has_value()) {
        info.isActive = true;
        info.providerName = vpnOpt->providerName;
        info.virtualIp = vpnOpt->virtualIP;
    }

    return info;
}

std::optional<VPNConnection> VPNDetector::GetActiveVPN() const {
    return m_impl->DetectVPNInternal();
}

std::vector<VPNConnection> VPNDetector::GetAllVPNConnections() const {
    std::vector<VPNConnection> connections;

    auto adapters = m_impl->EnumerateAdapters();
    for (const auto& adapter : adapters) {
        if (adapter.isVPN && adapter.isConnected) {
            auto connection = m_impl->CreateConnectionFromAdapter(adapter);

            // Enrich with process detection and provider identification
            // so callers get the same quality as the internal monitor
            if (m_impl->m_config.enableProcessDetection) {
                m_impl->DetectVPNProcess(connection);
            }
            if (connection.provider == VPNProvider::UNKNOWN) {
                m_impl->DetectVPNFromRegistry(connection);
            }
            if (m_impl->m_config.enableRoutingAnalysis) {
                m_impl->AnalyzeRoutingTable(connection);
            }

            connection.confidence = std::clamp(connection.confidence, 0.0, 1.0);
            connections.push_back(connection);
        }
    }

    return connections;
}

bool VPNDetector::IsVPNActive() const noexcept {
    try {
        auto vpnOpt = m_impl->DetectVPNInternal();
        return vpnOpt.has_value();
    } catch (...) {
        return false;
    }
}

std::optional<VPNConnection> VPNDetector::DetectVPNOnAdapter(uint32_t adapterIndex) {
    auto adapters = m_impl->EnumerateAdapters();

    for (const auto& adapter : adapters) {
        if (adapter.index == adapterIndex && adapter.isVPN && adapter.isConnected) {
            return m_impl->CreateConnectionFromAdapter(adapter);
        }
    }

    return std::nullopt;
}

// ========================================================================
// ADAPTER MANAGEMENT
// ========================================================================

std::vector<NetworkAdapter> VPNDetector::GetAllAdapters() const {
    return m_impl->EnumerateAdapters();
}

std::vector<NetworkAdapter> VPNDetector::GetVirtualAdapters() const {
    auto adapters = m_impl->EnumerateAdapters();
    std::vector<NetworkAdapter> virtual_adapters;

    for (const auto& adapter : adapters) {
        if (adapter.isVirtual) {
            virtual_adapters.push_back(adapter);
        }
    }

    return virtual_adapters;
}

bool VPNDetector::IsVPNAdapter(const std::wstring& adapterName) const {
    auto adapters = m_impl->EnumerateAdapters();

    std::wstring lowerTarget = StringUtils::ToLowerCopy(adapterName);
    for (const auto& adapter : adapters) {
        if (StringUtils::ToLowerCopy(adapter.friendlyName) == lowerTarget) {
            return adapter.isVPN;
        }
    }

    return false;
}

// ========================================================================
// PROXY DETECTION
// ========================================================================

ProxyInfo VPNDetector::GetProxyInfo() const {
    return m_impl->DetectProxyInternal();
}

bool VPNDetector::IsProxyActive() const {
    auto proxy = m_impl->DetectProxyInternal();
    return proxy.isActive;
}

// ========================================================================
// TRAFFIC ANALYSIS
// ========================================================================

TrafficFingerprint VPNDetector::AnalyzeTraffic(uint64_t connectionId) const {
    TrafficFingerprint fingerprint;
    fingerprint.protocol = VPNProtocol::UNKNOWN;
    fingerprint.confidence = 0.0;

    // Traffic fingerprinting requires kernel driver (PhantomSensor) packet feed
    // Return cached connection protocol if available
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeConnections.find(connectionId);
    if (it != m_impl->m_activeConnections.end()) {
        fingerprint.protocol = it->second.protocol;
        fingerprint.confidence = it->second.confidence;
    }

    return fingerprint;
}

void VPNDetector::FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet) {
    if (packet.empty() || packet.size() < 4) return;

    // Hard cap on inspected packet size. VPN protocol fingerprinting only
    // needs the first few dozen bytes (OpenVPN/WireGuard/IKE/SSTP/GRE
    // headers); refusing oversize input prevents an attacker (or a buggy
    // caller) from feeding multi-megabyte buffers in tight loops just to
    // burn CPU in this hot path.
    constexpr size_t kMaxInspectedPacketBytes = 64 * 1024;
    if (packet.size() > kMaxInspectedPacketBytes) {
        packet = packet.first(kMaxInspectedPacketBytes);
    }

    // Detect VPN protocol from packet header signatures
    VPNProtocol detected = VPNProtocol::UNKNOWN;
    double confidence = 0.0;

    // OpenVPN detection:
    // - P_CONTROL_HARD_RESET_CLIENT_V2 has opcode 7 (0x38 = 0b00111_000)
    // - P_CONTROL_HARD_RESET_SERVER_V2 has opcode 8 (0x40 = 0b01000_000)
    // - Data packets use opcode 6 (P_DATA_V1) or 9 (P_DATA_V2)
    // - The opcode is in the upper 5 bits of byte[0]
    // - Byte[1] has key_id in lower 3 bits
    // - For P_CONTROL packets, bytes [1..8] carry the session ID
    if (packet.size() >= 2) {
        uint8_t opcode = (packet[0] >> 3) & 0x1F;
        if (opcode >= 1 && opcode <= 10) {
            // OpenVPN opcodes 1-10 are valid; 7/8 are handshake, 6/9 are data
            if (opcode == 7 || opcode == 8) {
                detected = VPNProtocol::OPENVPN_UDP;
                confidence = 0.90;  // Handshake is high-confidence
            } else if (opcode == 6 || opcode == 9) {
                detected = VPNProtocol::OPENVPN_UDP;
                confidence = 0.75;
            }
        }
    }

    // WireGuard: First 4 bytes are message type in little-endian uint32
    // 1 = handshake initiation (148 bytes), 2 = handshake response (92 bytes)
    // 3 = cookie reply (64 bytes), 4 = transport data (variable)
    if (detected == VPNProtocol::UNKNOWN && packet.size() >= 4 &&
        packet[0] >= 1 && packet[0] <= 4 &&
        packet[1] == 0 && packet[2] == 0 && packet[3] == 0) {
        // Validate expected sizes for handshake messages
        bool sizeValid = true;
        if (packet[0] == 1 && packet.size() < 148) sizeValid = false;
        if (packet[0] == 2 && packet.size() < 92) sizeValid = false;
        if (packet[0] == 3 && packet.size() < 64) sizeValid = false;
        if (packet[0] == 4 && packet.size() < 32) sizeValid = false;  // min transport

        if (sizeValid) {
            detected = VPNProtocol::WIREGUARD;
            confidence = (packet[0] <= 3) ? 0.90 : 0.80;  // Handshakes are higher confidence
        }
    }

    // IPSec IKE (ISAKMP): Header structure:
    // [Initiator SPI (8)] [Responder SPI (8)] [Next Payload (1)] [Version (1)]
    // [Exchange Type (1)] [Flags (1)] [Message ID (4)] [Length (4)]
    // Total header = 28 bytes
    if (detected == VPNProtocol::UNKNOWN && packet.size() >= 28) {
        bool hasInitiatorSPI = false;
        for (size_t i = 0; i < 8; ++i) {
            if (packet[i] != 0) { hasInitiatorSPI = true; break; }
        }
        uint8_t version = packet[17];
        uint8_t exchangeType = packet[18];
        uint32_t msgLen = (static_cast<uint32_t>(packet[24]) << 24) |
                          (static_cast<uint32_t>(packet[25]) << 16) |
                          (static_cast<uint32_t>(packet[26]) << 8) |
                          static_cast<uint32_t>(packet[27]);

        if (hasInitiatorSPI && (version == 0x10 || version == 0x20) &&
            exchangeType <= 46 && msgLen >= 28 && msgLen <= 65535) {
            detected = (version == 0x20) ? VPNProtocol::IPSEC_IKEV2 : VPNProtocol::IPSEC_IKEV1;
            confidence = 0.80;
        }
    }

    // ESP (Encapsulating Security Payload) - IPSec data packets
    // ESP header: [SPI (4)] [Sequence (4)] then encrypted payload
    // ESP uses IP protocol 50 (but at this layer we see raw payload)
    // We can heuristically detect ESP by checking for non-zero SPI with
    // monotonically increasing sequence numbers (detected across packets)

    // SSTP (Secure Socket Tunneling Protocol) detection:
    // SSTP runs over HTTPS (port 443) but has distinctive framing:
    // Byte[0] = version (must be 0x10 for SSTP v1)
    // Byte[1] bit 0 = C bit (control), bit 1 = reserved
    // Bytes[2-3] = length (big endian)
    if (detected == VPNProtocol::UNKNOWN && packet.size() >= 4) {
        uint8_t sstpVersion = packet[0];
        uint16_t sstpLen = (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
        if (sstpVersion == 0x10 && (packet[1] & 0xFE) == 0 &&
            sstpLen >= 4 && sstpLen <= packet.size()) {
            detected = VPNProtocol::SSTP;
            confidence = 0.75;
        }
    }

    // GRE (Generic Routing Encapsulation) for PPTP:
    // GRE header: flags[2] protocol[2]
    // PPTP uses enhanced GRE with protocol = 0x880B (PPP)
    if (detected == VPNProtocol::UNKNOWN && packet.size() >= 8) {
        uint16_t greProto = (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
        if (greProto == 0x880B) {
            detected = VPNProtocol::PPTP;
            confidence = 0.85;
        }
    }

    if (detected == VPNProtocol::UNKNOWN) return;

    // Update the active connection with fingerprinted protocol
    std::unique_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeConnections.find(connectionId);
    if (it != m_impl->m_activeConnections.end()) {
        if (confidence > it->second.confidence) {
            it->second.protocol = detected;
            it->second.confidence = confidence;
            // Avoid duplicate method entries
            auto& methods = it->second.allMethods;
            if (std::find(methods.begin(), methods.end(),
                          VPNDetectionMethod::TRAFFIC_FINGERPRINT) == methods.end()) {
                methods.push_back(VPNDetectionMethod::TRAFFIC_FINGERPRINT);
            }
        }
    }
}

// ========================================================================
// PROVIDER IDENTIFICATION
// ========================================================================

std::optional<IPRangeInfo> VPNDetector::IdentifyProvider(const std::string& ip) const {
    if (ip.empty()) return std::nullopt;

    // Check active connections for matching VPN endpoint
    std::shared_lock lock(m_impl->m_mutex);
    for (const auto& [id, conn] : m_impl->m_activeConnections) {
        if (conn.remoteServerIP == ip || conn.virtualIP == ip) {
            IPRangeInfo info;
            info.provider = conn.provider;
            info.providerName = StringUtils::ToNarrow(conn.providerName);
            info.isKnownVPN = true;
            return info;
        }
    }

    return std::nullopt;
}

bool VPNDetector::IsKnownVPNIP(const std::string& ip) const {
    auto result = IdentifyProvider(ip);
    return result.has_value() && result->isKnownVPN;
}

std::string_view VPNDetector::GetProviderName(VPNProvider provider) noexcept {
    switch (provider) {
        case VPNProvider::NORDVPN: return "NordVPN";
        case VPNProvider::EXPRESSVPN: return "ExpressVPN";
        case VPNProvider::SURFSHARK: return "Surfshark";
        case VPNProvider::PRIVATE_INTERNET_ACCESS: return "Private Internet Access";
        case VPNProvider::MULLVAD: return "Mullvad";
        case VPNProvider::PROTONVPN: return "ProtonVPN";
        case VPNProvider::CYBERGHOST: return "CyberGhost";
        case VPNProvider::IPVANISH: return "IPVanish";
        case VPNProvider::WINDSCRIBE: return "Windscribe";
        case VPNProvider::HIDE_MY_ASS: return "HideMyAss";
        case VPNProvider::TUNNELBEAR: return "TunnelBear";
        case VPNProvider::HOTSPOT_SHIELD: return "Hotspot Shield";
        case VPNProvider::CISCO_ANYCONNECT_PROVIDER: return "Cisco AnyConnect";
        case VPNProvider::PALO_ALTO: return "Palo Alto GlobalProtect";
        case VPNProvider::FORTINET_PROVIDER: return "Fortinet";
        case VPNProvider::PULSE_SECURE_PROVIDER: return "Pulse Secure";
        case VPNProvider::F5_BIG_IP: return "F5 BIG-IP";
        case VPNProvider::CHECK_POINT: return "Check Point";
        case VPNProvider::CITRIX_NETSCALER: return "Citrix NetScaler";
        case VPNProvider::ZSCALER: return "Zscaler";
        case VPNProvider::MICROSOFT_ALWAYS_ON: return "Microsoft Always On VPN";
        case VPNProvider::OPENVPN_SELF: return "OpenVPN (Self-hosted)";
        case VPNProvider::WIREGUARD_SELF: return "WireGuard (Self-hosted)";
        case VPNProvider::SOFTETHER_SELF: return "SoftEther (Self-hosted)";
        default: return "Unknown";
    }
}

// ========================================================================
// LEAK DETECTION
// ========================================================================

bool VPNDetector::HasDNSLeak() const {
    return m_impl->CheckDNSLeakInternal();
}

bool VPNDetector::HasIPv6Leak() const {
    return m_impl->CheckIPv6LeakInternal();
}

std::vector<LeakType> VPNDetector::GetDetectedLeaks() const {
    std::vector<LeakType> leaks;

    if (HasDNSLeak()) {
        leaks.push_back(LeakType::DNS_LEAK);
    }

    if (HasIPv6Leak()) {
        leaks.push_back(LeakType::IPV6_LEAK);
    }

    return leaks;
}

// ========================================================================
// POLICY MANAGEMENT
// ========================================================================

void VPNDetector::SetPolicy(VPNPolicy policy) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.policy = policy;
}

VPNPolicy VPNDetector::GetPolicy() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.policy;
}

void VPNDetector::AddAdapterException(const std::wstring& adapterName) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.allowedAdapters.push_back(adapterName);
}

void VPNDetector::RemoveAdapterException(const std::wstring& adapterName) {
    std::unique_lock lock(m_impl->m_mutex);

    auto& allowed = m_impl->m_config.allowedAdapters;
    std::wstring lowerTarget = StringUtils::ToLowerCopy(adapterName);
    allowed.erase(
        std::remove_if(allowed.begin(), allowed.end(),
            [&](const std::wstring& name) {
                return StringUtils::ToLowerCopy(name) == lowerTarget;
            }),
        allowed.end()
    );
}

// ========================================================================
// CALLBACK REGISTRATION
// ========================================================================

uint64_t VPNDetector::RegisterDetectionCallback(VPNDetectionCallback callback) {
    return m_impl->RegisterDetectionCallback(std::move(callback));
}

uint64_t VPNDetector::RegisterAlertCallback(VPNAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t VPNDetector::RegisterLeakCallback(LeakCallback callback) {
    return m_impl->RegisterLeakCallback(std::move(callback));
}

uint64_t VPNDetector::RegisterAdapterCallback(AdapterChangeCallback callback) {
    return m_impl->RegisterAdapterCallback(std::move(callback));
}

bool VPNDetector::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

// ========================================================================
// STATISTICS
// ========================================================================

const VPNDetectorStatistics& VPNDetector::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void VPNDetector::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

// ========================================================================
// DIAGNOSTICS
// ========================================================================

bool VPNDetector::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool VPNDetector::ExportDiagnostics(const std::wstring& outputPath) const {
    try {
        // Snapshot all data under lock, then write to file WITHOUT holding the lock
        // to prevent blocking all other operations during potentially slow file I/O
        bool initialized;
        bool running;
        int policyVal;
        uint64_t totalScans;
        uint64_t vpnDetected;
        uint32_t activeVPN;
        uint32_t virtualAdapt;
        uint64_t blocked;
        uint64_t blockNotPerformed;
        uint64_t dnsLeaks;
        uint64_t ipv6Leaks;
        uint64_t alertsGen;
        std::vector<std::pair<uint64_t, VPNConnection>> connectionsCopy;

        {
            std::shared_lock lock(m_impl->m_mutex);
            initialized = m_impl->m_initialized;
            running = m_impl->m_running;
            policyVal = static_cast<int>(m_impl->m_config.policy);

            const auto& stats = m_impl->m_stats;
            totalScans = stats.totalScans.load();
            vpnDetected = stats.vpnConnectionsDetected.load();
            activeVPN = stats.activeVPNConnections.load();
            virtualAdapt = stats.virtualAdapters.load();
            blocked = stats.connectionsBlocked.load();
            blockNotPerformed = stats.blockRequestedNotPerformed.load();
            dnsLeaks = stats.dnsLeaksDetected.load();
            ipv6Leaks = stats.ipv6LeaksDetected.load();
            alertsGen = stats.alertsGenerated.load();

            for (const auto& [id, conn] : m_impl->m_activeConnections) {
                connectionsCopy.emplace_back(id, conn);
            }
        }

        // Now write to file without any lock held
        std::wofstream file(outputPath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Failed to open output file: %ls",
                outputPath.c_str());
            return false;
        }

        file << L"=== VPNDetector Diagnostics ===\n";
        file << L"Initialized: " << (initialized ? L"yes" : L"no") << L"\n";
        file << L"Running: " << (running ? L"yes" : L"no") << L"\n";
        file << L"Policy: " << policyVal << L"\n";
        file << L"Total scans: " << totalScans << L"\n";
        file << L"VPN connections detected: " << vpnDetected << L"\n";
        file << L"Active VPN connections: " << activeVPN << L"\n";
        file << L"Virtual adapters: " << virtualAdapt << L"\n";
        file << L"Connections blocked: " << blocked << L"\n";
        file << L"Block requested but not performed: " << blockNotPerformed << L"\n";
        file << L"DNS leaks: " << dnsLeaks << L"\n";
        file << L"IPv6 leaks: " << ipv6Leaks << L"\n";
        file << L"Alerts generated: " << alertsGen << L"\n";

        file << L"\n=== Active Connections ===\n";
        for (const auto& [id, conn] : connectionsCopy) {
            file << L"Connection " << id << L": " << conn.providerName
                 << L" (protocol=" << static_cast<int>(conn.protocol)
                 << L", confidence=" << conn.confidence << L")\n";
        }

        file.flush();
        SS_LOG_INFO(L"Network", L"Exported VPN detector diagnostics to: %ls",
            outputPath.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// STORE WIRING (ORCHESTRATOR-INJECTED DEPENDENCIES)
// ============================================================================

void VPNDetector::SetThreatIntelLookup(
    ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
    if (!m_impl) return;

    m_impl->m_threatIntelLookup.store(lookup, std::memory_order_release);
    // Reset the throttle so the "not wired" debug message can fire again
    // if the orchestrator later clears wiring.
    m_impl->m_threatIntelMissingLogged.store(false, std::memory_order_release);

    SS_LOG_INFO(L"Network", L"VPNDetector: ThreatIntelLookup %ls",
        lookup ? L"wired" : L"cleared");
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
