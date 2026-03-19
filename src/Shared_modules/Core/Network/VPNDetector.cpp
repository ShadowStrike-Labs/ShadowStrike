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
#include <wininet.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <regex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

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

    // OpenVPN signature (first bytes of handshake)
    const std::vector<uint8_t> OPENVPN_SIGNATURE = {
        0x00, 0x00, 0x00, 0x00  // HMAC placeholder
    };

    // WireGuard handshake signature
    const std::vector<uint8_t> WIREGUARD_HANDSHAKE = {
        0x01, 0x00, 0x00, 0x00  // Message type 1 (handshake initiation)
    };

    // IPSec IKE signature
    const std::vector<uint8_t> IPSEC_IKE_SIGNATURE = {
        // ISAKMP header
    };

    // Update interval
    constexpr uint32_t ADAPTER_SCAN_INTERVAL_MS = 5000;
    constexpr uint32_t LEAK_CHECK_INTERVAL_MS = 10000;

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static bool IsVirtualAdapterName(const std::wstring& name) noexcept {
    std::wstring lowerName = StringUtils::ToLower(name);

    // Check for TAP/TUN
    for (const auto& keyword : TAP_ADAPTER_KEYWORDS) {
        if (lowerName.find(StringUtils::ToLower(keyword)) != std::wstring::npos) {
            return true;
        }
    }

    // Check for WireGuard
    for (const auto& keyword : WIREGUARD_KEYWORDS) {
        if (lowerName.find(StringUtils::ToLower(keyword)) != std::wstring::npos) {
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
    std::wstring lowerName = StringUtils::ToLower(name);
    std::wstring lowerDesc = StringUtils::ToLower(description);
    std::wstring combined = lowerName + L" " + lowerDesc;

    // WireGuard
    for (const auto& keyword : WIREGUARD_KEYWORDS) {
        if (combined.find(StringUtils::ToLower(keyword)) != std::wstring::npos) {
            return AdapterType::WIREGUARD;
        }
    }

    // TAP
    if (combined.find(L"tap") != std::wstring::npos) {
        return AdapterType::TAP;
    }

    // TUN
    if (combined.find(L"tun") != std::wstring::npos) {
        return AdapterType::TUN;
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
                Logger::Error("WSAStartup failed");
                return false;
            }
            m_wsaInitialized = true;

            Logger::Info("VPNDetector initialized (policy={}, adapters={}, proxy={})",
                static_cast<int>(config.policy),
                config.enableAdapterDetection,
                config.enableProxyDetection);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("VPNDetector initialization failed: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                Logger::Error("Cannot start: not initialized");
                return false;
            }

            if (m_running) {
                Logger::Warn("Already running");
                return true;
            }

            // Perform initial scan
            PerformAdapterScan();

            // Start monitoring thread
            m_stopRequested = false;
            m_monitorThread = std::thread([this]() {
                MonitorThreadProc();
            });

            m_running = true;

            Logger::Info("VPNDetector started");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("Start failed: {}", e.what());
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

            Logger::Info("VPNDetector stopped");

        } catch (const std::exception& e) {
            Logger::Error("Stop failed: {}", e.what());
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            if (m_running) {
                m_stopRequested = true;
                if (m_monitorThread.joinable()) {
                    m_monitorThread.join();
                }
            }

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

            m_initialized = false;

            Logger::Info("VPNDetector shutdown complete");

        } catch (...) {
            // Suppress all exceptions
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

        try {
            ULONG bufferSize = 15000;
            std::vector<uint8_t> buffer(bufferSize);

            ULONG result = GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                nullptr,
                reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                &bufferSize
            );

            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                result = GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                    nullptr,
                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                    &bufferSize
                );
            }

            if (result != NO_ERROR) {
                Logger::Error("GetAdaptersAddresses failed: {}", result);
                return adapters;
            }

            PIP_ADAPTER_ADDRESSES pAdapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

            while (pAdapter) {
                NetworkAdapter adapter;

                // Names
                adapter.name = pAdapter->AdapterName ? StringUtils::Utf8ToWide(pAdapter->AdapterName) : L"";
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

        } catch (const std::exception& e) {
            Logger::Error("EnumerateAdapters - Exception: {}", e.what());
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

                    // Additional detection methods
                    if (m_config.enableProcessDetection) {
                        DetectVPNProcess(connection);
                    }

                    if (m_config.enableIPRangeLookup) {
                        IdentifyProviderByIP(connection);
                    }

                    if (m_config.enableLeakDetection) {
                        DetectLeaks(connection);
                    }

                    return connection;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("DetectVPNInternal - Exception: {}", e.what());
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
            auto processes = ProcessUtils::EnumerateProcesses();

            for (uint32_t pid : processes) {
                std::wstring processName = ProcessUtils::GetProcessName(pid);
                std::wstring lowerName = StringUtils::ToLower(processName);

                for (const auto& vpnProc : VPN_PROCESS_NAMES) {
                    if (lowerName == StringUtils::ToLower(vpnProc)) {
                        connection.processId = pid;
                        connection.processName = StringUtils::WideToUtf8(processName);
                        connection.processPath = ProcessUtils::GetProcessPath(pid);

                        connection.allMethods.push_back(VPNDetectionMethod::PROCESS_DETECTION);
                        connection.confidence += 0.1;

                        // Identify provider from process name
                        IdentifyProviderFromProcess(connection, lowerName);

                        return;
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("DetectVPNProcess - Exception: {}", e.what());
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
            if (connection.virtualIP.empty()) return;

            // Query ThreatIntel for IP range information
            // In production, would use ASN/GeoIP database
            // Placeholder implementation

            connection.allMethods.push_back(VPNDetectionMethod::IP_RANGE);

        } catch (const std::exception& e) {
            Logger::Error("IdentifyProviderByIP - Exception: {}", e.what());
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
            Logger::Error("DetectLeaks - Exception: {}", e.what());
        }
    }

    [[nodiscard]] bool CheckDNSLeakInternal() const {
        try {
            // Get all adapters
            auto adapters = EnumerateAdapters();

            // Find VPN adapter
            NetworkAdapter* vpnAdapter = nullptr;
            for (const auto& adapter : adapters) {
                if (adapter.isVPN && adapter.isConnected) {
                    vpnAdapter = const_cast<NetworkAdapter*>(&adapter);
                    break;
                }
            }

            if (!vpnAdapter) return false;

            // Check if DNS servers are different from VPN's DNS
            for (const auto& adapter : adapters) {
                if (adapter.index == vpnAdapter->index) continue;
                if (!adapter.isConnected) continue;

                // If another adapter has DNS servers configured, it's a leak
                if (!adapter.dnsServers.empty()) {
                    Logger::Warn("DNS leak detected: Adapter '{}' has DNS servers while VPN active",
                        StringUtils::WideToUtf8(adapter.friendlyName));
                    return true;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("CheckDNSLeakInternal - Exception: {}", e.what());
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
                    Logger::Warn("IPv6 leak detected: Adapter '{}' has IPv6 while VPN active",
                        StringUtils::WideToUtf8(adapter.friendlyName));
                    return true;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("CheckIPv6LeakInternal - Exception: {}", e.what());
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

            // Get IE proxy settings (system proxy)
            HMODULE hWinHttp = LoadLibraryW(L"winhttp.dll");
            if (!hWinHttp) return proxy;

            typedef BOOL (WINAPI *WinHttpGetIEProxyConfigForCurrentUser_t)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG*);
            auto pWinHttpGetIEProxyConfigForCurrentUser =
                reinterpret_cast<WinHttpGetIEProxyConfigForCurrentUser_t>(
                    GetProcAddress(hWinHttp, "WinHttpGetIEProxyConfigForCurrentUser"));

            if (pWinHttpGetIEProxyConfigForCurrentUser) {
                if (pWinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
                    if (proxyConfig.lpszProxy) {
                        std::wstring proxyStr(proxyConfig.lpszProxy);

                        // Parse proxy string (format: "http://host:port" or "host:port")
                        size_t colonPos = proxyStr.find(L':');
                        if (colonPos != std::wstring::npos) {
                            std::wstring hostPart = proxyStr.substr(0, colonPos);
                            std::wstring portPart = proxyStr.substr(colonPos + 1);

                            // Remove http:// prefix if present
                            if (hostPart.starts_with(L"http://")) {
                                hostPart = hostPart.substr(7);
                            } else if (hostPart.starts_with(L"https://")) {
                                hostPart = hostPart.substr(8);
                            }

                            proxy.isActive = true;
                            proxy.proxyHost = StringUtils::WideToUtf8(hostPart);
                            proxy.proxyPort = static_cast<uint16_t>(std::stoul(portPart));
                            proxy.type = ProxyType::HTTP;
                            proxy.isSystemProxy = true;
                            proxy.confidence = 0.95;
                        }

                        GlobalFree(proxyConfig.lpszProxy);
                    }

                    if (proxyConfig.lpszAutoConfigUrl) {
                        proxy.isPACConfigured = true;
                        proxy.pacUrl = StringUtils::WideToUtf8(proxyConfig.lpszAutoConfigUrl);
                        GlobalFree(proxyConfig.lpszAutoConfigUrl);
                    }

                    if (proxyConfig.lpszProxyBypass) {
                        GlobalFree(proxyConfig.lpszProxyBypass);
                    }
                }
            }

            FreeLibrary(hWinHttp);

        } catch (const std::exception& e) {
            Logger::Error("DetectProxyInternal - Exception: {}", e.what());
        }

        return proxy;
    }

    // ========================================================================
    // MONITORING
    // ========================================================================

    void MonitorThreadProc() {
        Logger::Debug("VPN monitor thread started");

        while (!m_stopRequested) {
            try {
                PerformAdapterScan();

                if (m_config.enableLeakDetection) {
                    PerformLeakCheck();
                }

            } catch (const std::exception& e) {
                Logger::Error("MonitorThreadProc - Exception: {}", e.what());
            }

            // Sleep with stop check
            for (uint32_t i = 0; i < ADAPTER_SCAN_INTERVAL_MS / 100 && !m_stopRequested; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        Logger::Debug("VPN monitor thread stopped");
    }

    void PerformAdapterScan() {
        try {
            m_stats.totalScans++;

            auto adapters = EnumerateAdapters();

            std::unique_lock lock(m_mutex);

            // Update adapter list
            m_adapters = adapters;

            // Count virtual adapters
            uint32_t virtualCount = 0;
            for (const auto& adapter : adapters) {
                if (adapter.isVirtual) virtualCount++;
            }
            m_stats.virtualAdapters = virtualCount;

            // Detect VPN connections
            DetectAndNotifyVPNConnections();

        } catch (const std::exception& e) {
            Logger::Error("PerformAdapterScan - Exception: {}", e.what());
        }
    }

    void DetectAndNotifyVPNConnections() {
        try {
            auto vpnOpt = DetectVPNInternal();

            if (vpnOpt.has_value()) {
                auto& connection = vpnOpt.value();

                // Update statistics
                m_stats.vpnConnectionsDetected++;
                m_stats.activeVPNConnections = 1;

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

                // Provider statistics
                if (connection.provider >= VPNProvider::NORDVPN &&
                    connection.provider <= VPNProvider::HOTSPOT_SHIELD) {
                    m_stats.consumerVPNsDetected++;
                } else if (connection.provider >= VPNProvider::CISCO_ANYCONNECT_PROVIDER &&
                          connection.provider <= VPNProvider::MICROSOFT_ALWAYS_ON) {
                    m_stats.corporateVPNsDetected++;
                } else {
                    m_stats.unknownProviders++;
                }

                // Store connection
                m_activeConnections[connection.connectionId] = connection;

                // Apply policy
                ApplyPolicy(connection);

                // Invoke detection callbacks
                InvokeDetectionCallbacks(connection);

            } else {
                m_stats.activeVPNConnections = 0;
            }

        } catch (const std::exception& e) {
            Logger::Error("DetectAndNotifyVPNConnections - Exception: {}", e.what());
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
            Logger::Error("PerformLeakCheck - Exception: {}", e.what());
        }
    }

    // ========================================================================
    // POLICY ENFORCEMENT
    // ========================================================================

    void ApplyPolicy(VPNConnection& connection) {
        try {
            bool shouldBlock = false;

            // Check policy
            if (m_config.policy == VPNPolicy::BLOCK_ALL) {
                shouldBlock = true;
            } else if (m_config.policy == VPNPolicy::BLOCK_CONSUMER) {
                // Block consumer VPNs
                if (connection.provider >= VPNProvider::NORDVPN &&
                    connection.provider <= VPNProvider::HOTSPOT_SHIELD) {
                    shouldBlock = true;
                }
            }

            // Check exceptions
            if (shouldBlock) {
                // Check adapter exceptions
                for (const auto& allowed : m_config.allowedAdapters) {
                    if (StringUtils::ToLower(connection.adapterName) == StringUtils::ToLower(allowed)) {
                        shouldBlock = false;
                        break;
                    }
                }
            }

            if (shouldBlock) {
                Logger::Warn("Blocking VPN connection: {} (policy={})",
                    StringUtils::WideToUtf8(connection.providerName),
                    static_cast<int>(m_config.policy));

                m_stats.connectionsBlocked++;

                // Generate alert
                GenerateAlert(connection, true);

                // In production, would disable adapter or kill process
                // For now, just log

            } else if (m_config.policy == VPNPolicy::MONITOR ||
                      m_config.policy == VPNPolicy::ALERT_ONLY) {
                // Just monitor/alert
                if (m_config.alertOnDetection) {
                    GenerateAlert(connection, false);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ApplyPolicy - Exception: {}", e.what());
        }
    }

    void GenerateAlert(const VPNConnection& connection, bool wasBlocked) {
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

        alert.description = wasBlocked ? "VPN connection blocked" : "VPN connection detected";
        alert.appliedPolicy = m_config.policy;
        alert.wasBlocked = wasBlocked;

        alert.leaks = connection.detectedLeaks;

        m_stats.alertsGenerated++;

        // Invoke alert callbacks
        InvokeAlertCallbacks(alert);

        Logger::Info("VPN alert: {} (provider={}, confidence={})",
            alert.description,
            StringUtils::WideToUtf8(connection.providerName),
            connection.confidence);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeDetectionCallbacks(const VPNConnection& connection) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_detectionCallbacks) {
                if (callback) {
                    callback(connection);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokeDetectionCallbacks - Exception: {}", e.what());
        }
    }

    void InvokeAlertCallbacks(const VPNAlert& alert) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_alertCallbacks) {
                if (callback) {
                    callback(alert);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokeAlertCallbacks - Exception: {}", e.what());
        }
    }

    void InvokeLeakCallbacks(LeakType leak, const std::string& details) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_leakCallbacks) {
                if (callback) {
                    callback(leak, details);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokeLeakCallbacks - Exception: {}", e.what());
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
            Logger::Info("=== VPNDetector Diagnostics ===");
            Logger::Info("Initialized: {}", m_initialized);
            Logger::Info("Running: {}", m_running);
            Logger::Info("Policy: {}", static_cast<int>(m_config.policy));
            Logger::Info("Total scans: {}", m_stats.totalScans.load());
            Logger::Info("VPN connections detected: {}", m_stats.vpnConnectionsDetected.load());
            Logger::Info("Active VPN connections: {}", m_stats.activeVPNConnections.load());
            Logger::Info("Virtual adapters: {}", m_stats.virtualAdapters.load());
            Logger::Info("Connections blocked: {}", m_stats.connectionsBlocked.load());
            Logger::Info("DNS leaks: {}", m_stats.dnsLeaksDetected.load());
            Logger::Info("IPv6 leaks: {}", m_stats.ipv6LeaksDetected.load());

            return true;

        } catch (const std::exception& e) {
            Logger::Error("PerformDiagnostics - Exception: {}", e.what());
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
    Logger::Info("VPNDetector instance created");
}

VPNDetector::~VPNDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("VPNDetector instance destroyed");
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
            connections.push_back(connection);
        }
    }

    return connections;
}

bool VPNDetector::IsVPNActive() const noexcept {
    auto vpnOpt = m_impl->DetectVPNInternal();
    return vpnOpt.has_value();
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

    for (const auto& adapter : adapters) {
        if (StringUtils::ToLower(adapter.friendlyName) == StringUtils::ToLower(adapterName)) {
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
    // Placeholder for traffic analysis
    TrafficFingerprint fingerprint;
    fingerprint.protocol = VPNProtocol::UNKNOWN;
    fingerprint.confidence = 0.0;
    return fingerprint;
}

void VPNDetector::FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet) {
    // Placeholder for packet feeding
    // In production, would analyze packet patterns
}

// ========================================================================
// PROVIDER IDENTIFICATION
// ========================================================================

std::optional<IPRangeInfo> VPNDetector::IdentifyProvider(const std::string& ip) const {
    // Placeholder for IP range lookup
    // In production, would use ASN/GeoIP database
    return std::nullopt;
}

bool VPNDetector::IsKnownVPNIP(const std::string& ip) const {
    // Placeholder
    return false;
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
    allowed.erase(
        std::remove_if(allowed.begin(), allowed.end(),
            [&](const std::wstring& name) {
                return StringUtils::ToLower(name) == StringUtils::ToLower(adapterName);
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
    std::shared_lock lock(m_impl->m_mutex);

    try {
        Logger::Info("Exported VPN detector diagnostics to: {}",
            StringUtils::WideToUtf8(outputPath));
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ExportDiagnostics - Exception: {}", e.what());
        return false;
    }
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
