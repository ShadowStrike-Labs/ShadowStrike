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
 * ShadowStrike NGAV - IOT DEVICE SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file IoTDeviceScanner.cpp
 * @brief Enterprise-grade IoT device discovery and vulnerability assessment
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - RAII socket wrapper for leak-free networking
 * - Integration with ThreatIntel, PatternStore, NetworkUtils
 *
 * DETECTION CAPABILITIES:
 * 1. Network discovery (ARP, mDNS, UPnP, DHCP)
 * 2. Device fingerprinting (MAC OUI, banners, services)
 * 3. Vulnerability assessment (CVE matching, default creds)
 * 4. Botnet detection (Mirai, C2 patterns)
 * 5. Risk scoring and categorization
 *
 * PERFORMANCE TARGETS:
 * - Device discovery: <100ms per device (ARP)
 * - Port scan: <5s per device (common ports)
 * - Deep scan: <30s per device (full assessment)
 * - Passive monitoring: <1ms per packet
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: AGPL-3.0-or-later
 * ============================================================================
 */

#include "pch.h"
#include "IoTDeviceScanner.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../../../../PhantomCore/Utils/StringUtils.hpp"
#include "../../../../PhantomCore/Utils/SystemUtils.hpp"
#include "../../../../PhantomCore/Utils/JSONUtils.hpp"
#include "../../../../PhantomCore/Utils/Timer.hpp"
#include "../../../../PhantomCore/Utils/HashUtils.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <future>
#include <bit>
#include <charconv>
#include <numeric>
#include <atomic>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    using namespace ShadowStrike::IoT;

    /// @brief ARP hardware type (Ethernet)
    constexpr uint16_t ARP_HW_TYPE_ETHERNET = 1;

    /// @brief ARP protocol type (IPv4)
    constexpr uint16_t ARP_PROTO_IPV4 = 0x0800;

    /// @brief ARP opcode: reply
    constexpr uint16_t ARP_OP_REPLY = 2;

    /// @brief ARP opcode: request
    constexpr uint16_t ARP_OP_REQUEST = 1;

    /// @brief Minimum ARP packet size (hdr + payload)
    constexpr size_t ARP_PACKET_MIN_SIZE = 28;

    /// @brief DNS minimum header size
    constexpr size_t DNS_HEADER_SIZE = 12;

    /// @brief DNS QR bit position
    constexpr uint16_t DNS_QR_RESPONSE = 0x8000;

    /// @brief Connection timeout (ms)
    constexpr uint32_t CONNECT_TIMEOUT_MS = 2000;

    /// @brief Banner read timeout (ms)
    constexpr uint32_t BANNER_TIMEOUT_MS = 3000;

    /// @brief Scan batch size
    constexpr size_t SCAN_BATCH_SIZE = 50;

    // ========================================================================
    // RAII SOCKET WRAPPER
    // ========================================================================

    /**
     * @brief RAII wrapper for Winsock SOCKET — prevents leaks on all exit paths
     */
    class SocketGuard final {
    public:
        explicit SocketGuard(SOCKET sock = INVALID_SOCKET) noexcept : m_socket(sock) {}

        ~SocketGuard() noexcept {
            Close();
        }

        SocketGuard(const SocketGuard&) = delete;
        SocketGuard& operator=(const SocketGuard&) = delete;

        SocketGuard(SocketGuard&& other) noexcept : m_socket(other.m_socket) {
            other.m_socket = INVALID_SOCKET;
        }

        SocketGuard& operator=(SocketGuard&& other) noexcept {
            if (this != &other) {
                Close();
                m_socket = other.m_socket;
                other.m_socket = INVALID_SOCKET;
            }
            return *this;
        }

        [[nodiscard]] SOCKET Get() const noexcept { return m_socket; }

        [[nodiscard]] bool IsValid() const noexcept { return m_socket != INVALID_SOCKET; }

        SOCKET Release() noexcept {
            SOCKET s = m_socket;
            m_socket = INVALID_SOCKET;
            return s;
        }

        void Close() noexcept {
            if (m_socket != INVALID_SOCKET) {
                ::closesocket(m_socket);
                m_socket = INVALID_SOCKET;
            }
        }

    private:
        SOCKET m_socket;
    };

    // ========================================================================
    // ARP PACKET STRUCTURES
    // ========================================================================

#pragma pack(push, 1)
    struct ARPHeader {
        uint16_t hardwareType;
        uint16_t protocolType;
        uint8_t  hardwareAddrLen;
        uint8_t  protocolAddrLen;
        uint16_t opcode;
        uint8_t  senderMAC[6];
        uint8_t  senderIP[4];
        uint8_t  targetMAC[6];
        uint8_t  targetIP[4];
    };

    struct DNSHeader {
        uint16_t id;
        uint16_t flags;
        uint16_t questions;
        uint16_t answers;
        uint16_t authority;
        uint16_t additional;
    };
#pragma pack(pop)

    // ========================================================================
    // MAC VENDOR DATABASE
    // ========================================================================

    struct MACVendorEntry {
        const char* prefix;
        const char* vendor;
        DeviceCategory suggestedCategory;
    };

    constexpr MACVendorEntry MAC_VENDORS[] = {
        {"00:11:32", "Synology", DeviceCategory::NAS},
        {"00:17:88", "Philips Hue", DeviceCategory::SmartLight},
        {"00:1D:C9", "Nest Labs", DeviceCategory::Thermostat},
        {"00:23:12", "Canon", DeviceCategory::Printer},
        {"00:24:E4", "Withings", DeviceCategory::SmartWatch},
        {"00:50:C2", "IEEE 1394", DeviceCategory::Computer},
        {"18:B4:30", "Nest Labs", DeviceCategory::Thermostat},
        {"24:A1:60", "TP-Link", DeviceCategory::Router},
        {"28:6A:B8", "Nest Labs", DeviceCategory::IPCamera},
        {"30:AE:A4", "Espressif", DeviceCategory::IoTHub},
        {"44:D9:E7", "Amazon Echo", DeviceCategory::VoiceAssistant},
        {"50:C7:BF", "TP-Link", DeviceCategory::SmartPlug},
        {"54:60:09", "Samsung SmartTV", DeviceCategory::SmartTV},
        {"58:CF:79", "HP", DeviceCategory::Printer},
        {"60:01:94", "Espressif", DeviceCategory::IoTHub},
        {"68:9E:19", "Espressif", DeviceCategory::IoTHub},
        {"6C:0B:84", "Universal Global Scientific", DeviceCategory::Router},
        {"74:C6:3B", "Amazon Echo", DeviceCategory::VoiceAssistant},
        {"78:8A:20", "Ubiquiti", DeviceCategory::AccessPoint},
        {"80:7D:3A", "Espressif", DeviceCategory::IoTHub},
        {"84:F3:EB", "Google Home", DeviceCategory::SmartSpeaker},
        {"A0:20:A6", "Espressif", DeviceCategory::IoTHub},
        {"A4:CF:12", "Espressif", DeviceCategory::IoTHub},
        {"AC:84:C6", "TP-Link", DeviceCategory::Router},
        {"B4:E6:2D", "TP-Link", DeviceCategory::SmartPlug},
        {"B8:27:EB", "Raspberry Pi", DeviceCategory::Computer},
        {"C4:4F:33", "Espressif", DeviceCategory::IoTHub},
        {"CC:50:E3", "Espressif", DeviceCategory::IoTHub},
        {"D8:F1:5B", "Espressif", DeviceCategory::IoTHub},
        {"DC:A6:32", "Raspberry Pi", DeviceCategory::Computer},
        {"E0:76:D0", "Xiaomi", DeviceCategory::IPCamera},
        {"E8:DB:84", "Espressif", DeviceCategory::IoTHub},
        {"F0:EF:86", "Google Home", DeviceCategory::SmartSpeaker},
        {"F4:CF:A2", "Espressif", DeviceCategory::IoTHub},
    };

    // ========================================================================
    // DEFAULT CREDENTIALS DATABASE
    // ========================================================================

    struct DefaultCredential {
        const char* username;
        const char* password;
        const char* devicePattern;
    };

    constexpr DefaultCredential DEFAULT_CREDS[] = {
        {"admin", "admin", ""},
        {"admin", "password", ""},
        {"admin", "12345", ""},
        {"admin", "1234", ""},
        {"admin", "", ""},
        {"root", "root", ""},
        {"root", "admin", ""},
        {"root", "12345", ""},
        {"root", "toor", ""},
        {"support", "support", ""},
        {"ubnt", "ubnt", "Ubiquiti"},
        {"pi", "raspberry", "Raspberry"},
        {"Administrator", "1234", ""},
        {"user", "user", ""},
        {"guest", "guest", ""},
        {"admin", "default", ""},
        {"admin", "pass", ""},
        {"root", "vizxv", ""},
        {"root", "xc3511", ""},
        {"root", "888888", ""},
        {"root", "xmhdipc", ""},
        {"admin", "7ujMko0admin", ""},
        {"admin", "system", ""},
        {"root", "Zte521", "ZTE"},
        {"admin", "smcadmin", "SMC"},
    };

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Generate deterministic device ID from MAC address
     */
    [[nodiscard]] std::string GenerateDeviceId(const std::string& mac) {
        std::string hex;
        if (!::ShadowStrike::Utils::HashUtils::ComputeHex(
                ::ShadowStrike::Utils::HashUtils::Algorithm::SHA256,
                mac.data(), mac.size(), hex)) {
            return {};
        }
        return hex.substr(0, 16);
    }

    /**
     * @brief Format MAC from 6 raw bytes to "XX:XX:XX:XX:XX:XX"
     */
    [[nodiscard]] std::string FormatMAC(const uint8_t mac[6]) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf, 17);
    }

    /**
     * @brief Format IPv4 from 4 raw bytes to "A.B.C.D"
     */
    [[nodiscard]] std::string FormatIPv4(const uint8_t ip[4]) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        return buf;
    }

    /**
     * @brief Base64 encode for HTTP Basic Auth
     */
    [[nodiscard]] std::string Base64Encode(const std::string& input) {
        static constexpr const char* TABLE =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string output;
        output.reserve(((input.size() + 2) / 3) * 4);

        for (size_t i = 0; i < input.size(); i += 3) {
            uint32_t n = (static_cast<uint8_t>(input[i]) << 16);
            if (i + 1 < input.size()) n |= (static_cast<uint8_t>(input[i + 1]) << 8);
            if (i + 2 < input.size()) n |= static_cast<uint8_t>(input[i + 2]);

            output.push_back(TABLE[(n >> 18) & 0x3F]);
            output.push_back(TABLE[(n >> 12) & 0x3F]);
            output.push_back((i + 1 < input.size()) ? TABLE[(n >> 6) & 0x3F] : '=');
            output.push_back((i + 2 < input.size()) ? TABLE[n & 0x3F] : '=');
        }

        return output;
    }

    /**
     * @brief Parse CIDR notation to generate list of host IPs
     *
     * Supports: "192.168.1.0/24", "10.0.0.0/16" (capped at MAX_SUBNET_HOSTS)
     */
    [[nodiscard]] std::vector<std::string> ParseCIDRToHosts(const std::string& cidr) {
        std::vector<std::string> hosts;

        auto slashPos = cidr.find('/');
        if (slashPos == std::string::npos) {
            hosts.push_back(cidr);
            return hosts;
        }

        std::string ipStr = cidr.substr(0, slashPos);
        std::string maskStr = cidr.substr(slashPos + 1);

        int prefixLen = 0;
        auto [ptr, ec] = std::from_chars(maskStr.data(), maskStr.data() + maskStr.size(), prefixLen);
        if (ec != std::errc{} || prefixLen < 0 || prefixLen > 32) {
            ::ShadowStrike::Utils::Logger::Error("Invalid CIDR prefix length: {}", cidr);
            return hosts;
        }

        in_addr addr{};
        if (::inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) {
            ::ShadowStrike::Utils::Logger::Error("Invalid CIDR IP address: {}", cidr);
            return hosts;
        }

        uint32_t ip = ntohl(addr.s_addr);
        uint32_t mask = (prefixLen == 0) ? 0 : ~((1u << (32 - prefixLen)) - 1);
        uint32_t network = ip & mask;
        uint32_t broadcast = network | ~mask;

        // Handle /32 (single host) and /31 (point-to-point) specially
        if (prefixLen == 32) {
            hosts.push_back(ipStr);
            return hosts;
        }

        if (broadcast <= network + 1) {
            // /31 point-to-point: no traditional host range
            return hosts;
        }

        uint32_t hostCount = broadcast - network - 1;
        if (hostCount > IoTConstants::MAX_SUBNET_HOSTS) {
            hostCount = IoTConstants::MAX_SUBNET_HOSTS;
            ::ShadowStrike::Utils::Logger::Warn("CIDR {} exceeds max host limit, capped at {}", cidr,
                                IoTConstants::MAX_SUBNET_HOSTS);
        }

        hosts.reserve(static_cast<size_t>(hostCount));
        for (uint32_t h = network + 1; h < broadcast && hosts.size() < hostCount; ++h) {
            in_addr hostAddr{};
            hostAddr.s_addr = htonl(h);
            char buf[INET_ADDRSTRLEN];
            if (::inet_ntop(AF_INET, &hostAddr, buf, sizeof(buf))) {
                hosts.emplace_back(buf);
            }
        }

        return hosts;
    }

    [[nodiscard]] std::optional<int> GetCIDRPrefixLength(const std::string& cidr) {
        const auto slashPos = cidr.find('/');
        if (slashPos == std::string::npos) {
            return std::nullopt;
        }

        int prefixLen = 0;
        const std::string maskStr = cidr.substr(slashPos + 1);
        const auto [ptr, ec] = std::from_chars(maskStr.data(), maskStr.data() + maskStr.size(), prefixLen);
        if (ec != std::errc{} || ptr != maskStr.data() + maskStr.size() || prefixLen < 0 || prefixLen > 32) {
            return std::nullopt;
        }

        return prefixLen;
    }

    [[nodiscard]] bool IsSubnetScopeAllowed(const std::string& cidr, bool allowLargeSubnets) {
        const auto prefixLen = GetCIDRPrefixLength(cidr);
        if (!prefixLen.has_value()) {
            return true;
        }

        if (*prefixLen <= 16 && !allowLargeSubnets) {
            ::ShadowStrike::Utils::Logger::Warn(
                "Rejecting broad subnet {} without explicit consent (minimum supported prefix is /17)",
                cidr);
            return false;
        }

        return true;
    }

    /**
     * @brief Auto-detect local subnet from interface info
     */
    [[nodiscard]] std::string DeriveCIDRFromInterface(const std::string& ip, const std::string& mask) {
        in_addr ipAddr{}, maskAddr{};
        if (::inet_pton(AF_INET, ip.c_str(), &ipAddr) != 1 ||
            ::inet_pton(AF_INET, mask.c_str(), &maskAddr) != 1) {
            return {};
        }

        uint32_t maskBits = ntohl(maskAddr.s_addr);
        int prefix = std::popcount(maskBits);

        uint32_t network = ntohl(ipAddr.s_addr) & maskBits;
        in_addr netAddr{};
        netAddr.s_addr = htonl(network);

        char buf[INET_ADDRSTRLEN];
        if (!::inet_ntop(AF_INET, &netAddr, buf, sizeof(buf))) {
            return {};
        }

        return std::string(buf) + "/" + std::to_string(prefix);
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::IoT {

class IoTDeviceScannerImpl final {
public:
    IoTDeviceScannerImpl() {
        WSADATA wsaData{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            ::ShadowStrike::Utils::Logger::Error("WSAStartup failed: {}", ::WSAGetLastError());
        }
    }

    ~IoTDeviceScannerImpl() {
        StopAllScans();
        ::WSACleanup();
    }

    IoTDeviceScannerImpl(const IoTDeviceScannerImpl&) = delete;
    IoTDeviceScannerImpl& operator=(const IoTDeviceScannerImpl&) = delete;
    IoTDeviceScannerImpl(IoTDeviceScannerImpl&&) = delete;
    IoTDeviceScannerImpl& operator=(IoTDeviceScannerImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    IoTScannerConfiguration m_config;
    IoTScanStatistics m_stats;

    // Device database
    std::unordered_map<std::string, IoTDeviceInfo> m_devices;   // IP -> Device
    std::unordered_map<std::string, std::string>   m_macToIP;   // MAC -> IP

    // Scan state
    std::atomic<bool> m_scanActive{false};
    std::atomic<bool> m_passiveMonitoring{false};
    std::thread m_scanThread;
    std::thread m_monitorThread;
    IoTScanProgress m_progress;
    IoTScanConfig m_activeScanConfig;

    // Callbacks (protected by m_callbackMutex to avoid holding m_mutex during invocation)
    std::mutex m_callbackMutex;
    std::vector<DeviceFoundCallback>    m_deviceFoundCallbacks;
    std::vector<VulnerabilityCallback>  m_vulnerabilityCallbacks;
    std::vector<ScanProgressCallback>   m_progressCallbacks;
    std::vector<ScanCompleteCallback>   m_completeCallbacks;
    std::vector<ErrorCallback>          m_errorCallbacks;

    // ========================================================================
    // ========================================================================
    // CALLBACK INVOCATION — copy-under-lock, invoke-outside-lock
    // ========================================================================

    void NotifyError(const std::string& message, int code = 0) {
        std::vector<ErrorCallback> cbs;
        {
            std::lock_guard lock(m_callbackMutex);
            cbs = m_errorCallbacks;
        }
        for (const auto& callback : cbs) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                ::ShadowStrike::Utils::Logger::Error("Error callback exception: {}", e.what());
            } catch (...) {
                ::ShadowStrike::Utils::Logger::Error("Unknown error callback exception");
            }
        }
    }

    void NotifyDeviceFound(const IoTDeviceInfo& device) {
        std::vector<DeviceFoundCallback> cbs;
        {
            std::lock_guard lock(m_callbackMutex);
            cbs = m_deviceFoundCallbacks;
        }
        for (const auto& callback : cbs) {
            try {
                callback(device);
            } catch (const std::exception& e) {
                ::ShadowStrike::Utils::Logger::Error("DeviceFound callback exception: {}", e.what());
            } catch (...) {
                ::ShadowStrike::Utils::Logger::Error("Unknown DeviceFound callback exception");
            }
        }
    }

    void NotifyVulnerability(const IoTDeviceInfo& device, RiskFactor risk) {
        std::vector<VulnerabilityCallback> cbs;
        {
            std::lock_guard lock(m_callbackMutex);
            cbs = m_vulnerabilityCallbacks;
        }
        for (const auto& callback : cbs) {
            try {
                callback(device, risk);
            } catch (const std::exception& e) {
                ::ShadowStrike::Utils::Logger::Error("Vulnerability callback exception: {}", e.what());
            } catch (...) {
                ::ShadowStrike::Utils::Logger::Error("Unknown Vulnerability callback exception");
            }
        }
    }

    void NotifyProgress(const IoTScanProgress& progress) {
        std::vector<ScanProgressCallback> cbs;
        {
            std::lock_guard lock(m_callbackMutex);
            cbs = m_progressCallbacks;
        }
        for (const auto& callback : cbs) {
            try {
                callback(progress);
            } catch (const std::exception& e) {
                ::ShadowStrike::Utils::Logger::Error("Progress callback exception: {}", e.what());
            } catch (...) {
                ::ShadowStrike::Utils::Logger::Error("Unknown Progress callback exception");
            }
        }
    }

    void NotifyComplete(const IoTScanResultSummary& summary) {
        std::vector<ScanCompleteCallback> cbs;
        {
            std::lock_guard lock(m_callbackMutex);
            cbs = m_completeCallbacks;
        }
        for (const auto& callback : cbs) {
            try {
                callback(summary);
            } catch (const std::exception& e) {
                ::ShadowStrike::Utils::Logger::Error("Complete callback exception: {}", e.what());
            } catch (...) {
                ::ShadowStrike::Utils::Logger::Error("Unknown Complete callback exception");
            }
        }
    }

    // ========================================================================
    // THREAD MANAGEMENT
    // ========================================================================

    void StopAllScans() {
        m_scanActive.store(false, std::memory_order_release);
        m_passiveMonitoring.store(false, std::memory_order_release);

        if (m_scanThread.joinable()) {
            m_scanThread.join();
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }
    }

    // ========================================================================
    // MAC VENDOR LOOKUP
    // ========================================================================

    [[nodiscard]] std::string LookupVendor(const std::string& mac) const {
        if (mac.length() < 8) {
            return "Unknown";
        }

        std::string prefix = mac.substr(0, 8);
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

        for (const auto& entry : MAC_VENDORS) {
            if (prefix == entry.prefix) {
                return entry.vendor;
            }
        }

        return "Unknown";
    }

    [[nodiscard]] DeviceCategory ClassifyByVendor(const std::string& vendor) const {
        for (const auto& entry : MAC_VENDORS) {
            if (vendor.find(entry.vendor) != std::string::npos) {
                return entry.suggestedCategory;
            }
        }
        return DeviceCategory::Unknown;
    }

    // ========================================================================
    // PORT SCANNING (RAII-safe)
    // ========================================================================

    /**
     * @brief Check if host is reachable using non-blocking TCP connect to port 80
     */
    [[nodiscard]] bool IsHostReachable(const std::string& ipAddress) const {
        SocketGuard sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!sock.IsValid()) {
            return false;
        }

        u_long mode = 1;
        ::ioctlsocket(sock.Get(), FIONBIO, &mode);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        if (::inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        ::connect(sock.Get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sock.Get(), &writeSet);

        fd_set errorSet;
        FD_ZERO(&errorSet);
        FD_SET(sock.Get(), &errorSet);

        timeval timeout{};
        timeout.tv_sec = static_cast<long>(CONNECT_TIMEOUT_MS / 1000);
        timeout.tv_usec = static_cast<long>((CONNECT_TIMEOUT_MS % 1000) * 1000);

        int result = ::select(0, nullptr, &writeSet, &errorSet, &timeout);
        if (result <= 0) {
            return false;
        }

        if (FD_ISSET(sock.Get(), &errorSet)) {
            return false;
        }

        return FD_ISSET(sock.Get(), &writeSet) != 0;
    }

    /**
     * @brief Scan a single port with RAII socket and banner grabbing
     */
    [[nodiscard]] bool ScanPort(const std::string& ipAddress, uint16_t port, ServiceInfo& service) {
        SocketGuard sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!sock.IsValid()) {
            return false;
        }

        DWORD timeout = CONNECT_TIMEOUT_MS;
        ::setsockopt(sock.Get(), SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<char*>(&timeout), sizeof(timeout));
        ::setsockopt(sock.Get(), SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<char*>(&timeout), sizeof(timeout));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, ipAddress.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        if (::connect(sock.Get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            return false;
        }

        service.port = port;
        service.protocol = ServiceProtocol::TCP;
        service.isOpen = true;

        char banner[IoTConstants::MAX_BANNER_SIZE] = {};
        int received = ::recv(sock.Get(), banner, sizeof(banner) - 1, 0);
        if (received > 0) {
            service.banner = std::string(banner, static_cast<size_t>(received));
            ParseServiceBanner(service);
        }

        AssignServiceByPort(service);

        return true;
    }

    /**
     * @brief Assign service name by well-known port when banner is absent
     */
    void AssignServiceByPort(ServiceInfo& service) {
        if (!service.serviceName.empty()) {
            return;
        }

        switch (service.port) {
            case 21:   service.serviceName = "FTP"; break;
            case 22:   service.serviceName = "SSH"; break;
            case 23:   service.serviceName = "Telnet";
                       service.risks |= RiskFactor::OpenTelnet;
                       break;
            case 25:   service.serviceName = "SMTP"; break;
            case 53:   service.serviceName = "DNS"; break;
            case 80:   service.serviceName = "HTTP"; break;
            case 443:  service.serviceName = "HTTPS"; service.isSecure = true; break;
            case 554:  service.serviceName = "RTSP"; break;
            case 1883: service.serviceName = "MQTT"; break;
            case 1900: service.serviceName = "UPnP/SSDP"; break;
            case 5353: service.serviceName = "mDNS"; break;
            case 5683: service.serviceName = "CoAP"; break;
            case 5684: service.serviceName = "CoAPs"; service.isSecure = true; break;
            case 7547: service.serviceName = "TR-069/CWMP"; break;
            case 8080: service.serviceName = "HTTP-Alt"; break;
            case 8443: service.serviceName = "HTTPS-Alt"; service.isSecure = true; break;
            case 8883: service.serviceName = "MQTTS"; service.isSecure = true; break;
            case 9100: service.serviceName = "Print"; break;
            default: break;
        }

        if (service.port == 443 || service.port == 8443 ||
            service.port == 8883 || service.port == 5684) {
            service.isSecure = true;
        }
    }

    /**
     * @brief Parse service banner to extract product, version, and risk indicators
     */
    void ParseServiceBanner(ServiceInfo& service) {
        if (service.banner.empty()) {
            return;
        }

        const std::string& banner = service.banner;

        // HTTP server detection
        if (banner.find("HTTP/") != std::string::npos) {
            service.serviceName = "HTTP";

            auto serverPos = banner.find("Server:");
            if (serverPos != std::string::npos) {
                auto start = serverPos + 7;
                while (start < banner.size() && banner[start] == ' ') ++start;
                auto end = banner.find_first_of("\r\n", start);
                if (end != std::string::npos) {
                    service.product = banner.substr(start, end - start);
                }
            }
        }
        // FTP
        else if (banner.find("220") != std::string::npos &&
                 banner.find("FTP") != std::string::npos) {
            service.serviceName = "FTP";
            auto end = banner.find('\r');
            service.product = banner.substr(0, end != std::string::npos ? end : 80);
        }
        // SSH
        else if (banner.find("SSH-") != std::string::npos) {
            service.serviceName = "SSH";
            auto end = banner.find_first_of("\r\n");
            service.version = banner.substr(0, end != std::string::npos ? end : 30);
        }
        // Telnet
        else if (service.port == 23) {
            service.serviceName = "Telnet";
            service.risks |= RiskFactor::OpenTelnet;
        }
        // RTSP
        else if (banner.find("RTSP/") != std::string::npos) {
            service.serviceName = "RTSP";
        }
        // MQTT
        else if (service.port == 1883 || service.port == 8883) {
            service.serviceName = (service.port == 8883) ? "MQTTS" : "MQTT";
        }

        // Check for authentication requirement
        if (banner.find("401") != std::string::npos ||
            banner.find("Unauthorized") != std::string::npos ||
            banner.find("WWW-Authenticate") != std::string::npos) {
            service.requiresAuth = true;
        }

        // Check for login prompt
        if (banner.find("login:") != std::string::npos ||
            banner.find("Login") != std::string::npos ||
            banner.find("Password") != std::string::npos) {
            service.requiresAuth = true;
        }
    }

    // ========================================================================
    // DEFAULT CREDENTIAL CHECKING (REAL IMPLEMENTATION)
    // ========================================================================

    /**
     * @brief Check HTTP Basic Auth with default credentials against a device.
     *
     * Sends an HTTP GET with Authorization header. If the response is NOT 401,
     * the credential pair succeeded.
     */
    [[nodiscard]] bool CheckDefaultCredentials(IoTDeviceInfo& device) {
        bool hasHTTP = false;
        uint16_t httpPort = 80;

        for (const auto& svc : device.services) {
            if (svc.isOpen && (svc.port == 80 || svc.port == 8080 || svc.port == 8888)) {
                hasHTTP = true;
                httpPort = svc.port;
                break;
            }
        }

        if (!hasHTTP) {
            return false;
        }

        for (const auto& cred : DEFAULT_CREDS) {
            if (cred.devicePattern[0] != '\0' &&
                device.vendor.find(cred.devicePattern) == std::string::npos) {
                continue;
            }

            if (!m_scanActive.load(std::memory_order_acquire)) {
                return false;
            }

            if (TryHTTPBasicAuth(device.ipAddress, httpPort, cred.username, cred.password)) {
                ::ShadowStrike::Utils::Logger::Warn("Default credentials found on {} ({}:****)",
                                    device.ipAddress, cred.username);
                m_stats.defaultCredentialsFound++;
                return true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        return false;
    }

    /**
     * @brief Attempt HTTP Basic Authentication against device
     *
     * Returns true if authentication succeeds (non-401 response).
     */
    [[nodiscard]] bool TryHTTPBasicAuth(const std::string& ip, uint16_t port,
                                         const char* username, const char* password) {
        SocketGuard sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!sock.IsValid()) {
            return false;
        }

        DWORD timeout = CONNECT_TIMEOUT_MS;
        ::setsockopt(sock.Get(), SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<char*>(&timeout), sizeof(timeout));
        ::setsockopt(sock.Get(), SOL_SOCKET, SO_SNDTIMEO,
                     reinterpret_cast<char*>(&timeout), sizeof(timeout));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            return false;
        }

        if (::connect(sock.Get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            return false;
        }

        std::string credentials = std::string(username) + ":" + std::string(password);
        std::string encoded = Base64Encode(credentials);

        std::string request =
            "GET / HTTP/1.1\r\n"
            "Host: " + ip + ":" + std::to_string(port) + "\r\n"
            "Authorization: Basic " + encoded + "\r\n"
            "Connection: close\r\n"
            "\r\n";

        int sent = ::send(sock.Get(), request.c_str(), static_cast<int>(request.size()), 0);
        if (sent <= 0) {
            return false;
        }

        char response[1024] = {};
        int received = ::recv(sock.Get(), response, sizeof(response) - 1, 0);
        if (received <= 0) {
            return false;
        }

        std::string_view resp(response, static_cast<size_t>(received));

        // Success: anything other than 401 Unauthorized
        if (resp.find("HTTP/") != std::string_view::npos) {
            bool is401 = resp.find("401") != std::string_view::npos;
            bool is403 = resp.find("403") != std::string_view::npos;
            return !is401 && !is403;
        }

        return false;
    }

    // ========================================================================
    // VULNERABILITY ASSESSMENT
    // ========================================================================

    void AssessVulnerabilities(IoTDeviceInfo& device) {
        device.risks = RiskFactor::None;
        device.riskFactors.clear();
        device.vulnerabilityLevel = VulnerabilityLevel::None;

        // Check for open Telnet
        for (const auto& svc : device.services) {
            if (svc.port == 23 && svc.isOpen) {
                device.risks |= RiskFactor::OpenTelnet;
                device.riskFactors.push_back(RiskFactor::OpenTelnet);
                if (device.vulnerabilityLevel < VulnerabilityLevel::High) {
                    device.vulnerabilityLevel = VulnerabilityLevel::High;
                }
            }

            // Unauthenticated open service
            if (!svc.requiresAuth && svc.isOpen &&
                svc.port != 80 && svc.port != 443) {
                device.risks |= RiskFactor::UnauthorizedService;
                if (device.vulnerabilityLevel < VulnerabilityLevel::Medium) {
                    device.vulnerabilityLevel = VulnerabilityLevel::Medium;
                }
            }

            // Unencrypted services carrying potentially sensitive data
            if (!svc.isSecure && svc.isOpen &&
                (svc.port == 554 || svc.port == 1883 || svc.port == 21)) {
                device.risks |= RiskFactor::NoEncryption;
                if (device.vulnerabilityLevel < VulnerabilityLevel::Medium) {
                    device.vulnerabilityLevel = VulnerabilityLevel::Medium;
                }
            }

            // UPnP enabled
            if (svc.port == 1900 && svc.isOpen) {
                device.risks |= RiskFactor::UPnPEnabled;
                device.riskFactors.push_back(RiskFactor::UPnPEnabled);
            }

            // TR-069 exposed
            if (svc.port == 7547 && svc.isOpen) {
                device.risks |= RiskFactor::DebugInterface;
                device.riskFactors.push_back(RiskFactor::DebugInterface);
                if (device.vulnerabilityLevel < VulnerabilityLevel::High) {
                    device.vulnerabilityLevel = VulnerabilityLevel::High;
                }
            }

            // RTSP streaming without auth
            if (svc.port == 554 && svc.isOpen && !svc.requiresAuth) {
                device.risks |= RiskFactor::UnencryptedStream;
                device.riskFactors.push_back(RiskFactor::UnencryptedStream);
                if (device.vulnerabilityLevel < VulnerabilityLevel::High) {
                    device.vulnerabilityLevel = VulnerabilityLevel::High;
                }
            }
        }

        // Check for default credentials (if enabled)
        if (m_config.defaultScanConfig.checkDefaultCredentials) {
            if (CheckDefaultCredentials(device)) {
                device.hasDefaultCredentials = true;
                device.risks |= RiskFactor::DefaultCredentials;
                device.riskFactors.push_back(RiskFactor::DefaultCredentials);
                device.vulnerabilityLevel = VulnerabilityLevel::Critical;
            }
        }

        // Update statistics
        if (device.vulnerabilityLevel != VulnerabilityLevel::None) {
            m_stats.totalVulnerabilitiesFound++;
            size_t level = static_cast<size_t>(device.vulnerabilityLevel);
            if (level < m_stats.byVulnerabilityLevel.size()) {
                m_stats.byVulnerabilityLevel[level]++;
            }
        }
    }

    // ========================================================================
    // ARP PACKET PARSING (REAL IMPLEMENTATION)
    // ========================================================================

    void ParseARPPacket(std::span<const uint8_t> packet) {
        if (packet.size() < ARP_PACKET_MIN_SIZE) {
            return;
        }

        const auto* arp = reinterpret_cast<const ARPHeader*>(packet.data());

        if (ntohs(arp->hardwareType) != ARP_HW_TYPE_ETHERNET ||
            ntohs(arp->protocolType) != ARP_PROTO_IPV4) {
            return;
        }

        uint16_t opcode = ntohs(arp->opcode);
        if (opcode != ARP_OP_REPLY && opcode != ARP_OP_REQUEST) {
            return;
        }

        std::string senderMAC = FormatMAC(arp->senderMAC);
        std::string senderIP = FormatIPv4(arp->senderIP);

        if (senderIP == "0.0.0.0" || senderMAC == "00:00:00:00:00:00") {
            return;
        }

        std::unique_lock lock(m_mutex);

        auto it = m_devices.find(senderIP);
        if (it != m_devices.end()) {
            it->second.lastSeen = std::chrono::system_clock::now();
            it->second.isOnline = true;
            if (it->second.macAddress.empty()) {
                it->second.macAddress = senderMAC;
                it->second.vendor = LookupVendor(senderMAC);
                it->second.category = ClassifyByVendor(it->second.vendor);
                m_macToIP[senderMAC] = senderIP;
            }
        } else {
            if (m_devices.size() >= IoTConstants::MAX_TRACKED_DEVICES) {
                return;
            }

            IoTDeviceInfo device;
            device.ipAddress = senderIP;
            device.macAddress = senderMAC;
            device.deviceId = GenerateDeviceId(senderMAC);
            device.vendor = LookupVendor(senderMAC);
            device.category = ClassifyByVendor(device.vendor);
            device.discoveryMethod = DiscoveryMethod::PassiveSniff;
            device.isOnline = true;
            device.firstSeen = std::chrono::system_clock::now();
            device.lastSeen = device.firstSeen;

            m_devices[senderIP] = device;
            m_macToIP[senderMAC] = senderIP;

            m_stats.totalDevicesDiscovered++;
            size_t catIdx = static_cast<size_t>(device.category);
            if (catIdx < m_stats.byCategory.size()) {
                m_stats.byCategory[catIdx]++;
            }

            lock.unlock();
            NotifyDeviceFound(device);

            ::ShadowStrike::Utils::Logger::Debug("ARP: Discovered {} ({}) at {}", senderMAC,
                                 device.vendor, senderIP);
        }
    }

    // ========================================================================
    // DNS PACKET PARSING (REAL IMPLEMENTATION)
    // ========================================================================

    void ParseDNSPacket(std::span<const uint8_t> packet) {
        if (packet.size() < DNS_HEADER_SIZE) {
            return;
        }

        const auto* dns = reinterpret_cast<const DNSHeader*>(packet.data());

        uint16_t flags = ntohs(dns->flags);
        bool isResponse = (flags & DNS_QR_RESPONSE) != 0;
        uint16_t questions = ntohs(dns->questions);
        uint16_t answers = ntohs(dns->answers);

        if (!isResponse || answers == 0) {
            return;
        }

        // Cap counts to prevent DoS from malformed packets
        if (questions > 256 || answers > 256) {
            return;
        }

        const size_t packetLen = packet.size();

        // Lambda: parse a DNS name, handling compression pointers (RFC 1035 §4.1.4)
        auto parseName = [&](size_t startOff, std::string& name, size_t& endOff) -> bool {
            name.clear();
            size_t pos = startOff;
            bool jumped = false;
            size_t jumpCount = 0;
            endOff = 0;

            while (pos < packetLen) {
                uint8_t labelLen = packet[pos];

                if (labelLen == 0) {
                    if (!jumped) endOff = pos + 1;
                    return true;
                }

                // Compression pointer: top 2 bits are 11
                if ((labelLen & 0xC0) == 0xC0) {
                    if (pos + 1 >= packetLen) return false;
                    uint16_t ptr = static_cast<uint16_t>(
                        ((labelLen & 0x3F) << 8) | packet[pos + 1]);
                    if (ptr >= packetLen) return false;
                    if (!jumped) endOff = pos + 2;
                    jumped = true;
                    pos = ptr;
                    // Guard against infinite loops in malformed packets
                    if (++jumpCount > packetLen) return false;
                    continue;
                }

                if (labelLen > 63) return false;
                pos++;

                if (pos + labelLen > packetLen) return false;
                if (name.size() + labelLen + 1 > 253) return false; // RFC max domain length

                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<const char*>(&packet[pos]), labelLen);
                pos += labelLen;
            }
            return false;
        };

        // Skip question section
        size_t offset = DNS_HEADER_SIZE;
        for (uint16_t q = 0; q < questions; ++q) {
            std::string qname;
            size_t nextOff = 0;
            if (!parseName(offset, qname, nextOff)) return;
            offset = nextOff;
            if (offset + 4 > packetLen) return;
            offset += 4; // QTYPE(2) + QCLASS(2)
        }

        // Parse answer section — extract A records to correlate hostnames with IPs
        for (uint16_t a = 0; a < answers; ++a) {
            std::string aname;
            size_t nextOff = 0;
            if (!parseName(offset, aname, nextOff)) return;
            offset = nextOff;

            if (offset + 10 > packetLen) return;

            uint16_t rtype = static_cast<uint16_t>(
                (packet[offset] << 8) | packet[offset + 1]);
            // Skip: CLASS(2) + TTL(4)
            uint16_t rdlength = static_cast<uint16_t>(
                (packet[offset + 8] << 8) | packet[offset + 9]);
            offset += 10;

            if (offset + rdlength > packetLen) return;

            // A record (type 1, 4-byte IPv4 address)
            if (rtype == 1 && rdlength == 4 && !aname.empty()) {
                std::string ip = FormatIPv4(&packet[offset]);

                std::string hostname = aname;
                std::transform(hostname.begin(), hostname.end(),
                               hostname.begin(), ::tolower);

                // Strip .local suffix for mDNS names
                if (auto dotLocal = hostname.rfind(".local");
                    dotLocal != std::string::npos && dotLocal + 6 == hostname.size()) {
                    hostname.erase(dotLocal);
                }

                std::unique_lock lock(m_mutex);
                auto it = m_devices.find(ip);
                if (it != m_devices.end() && it->second.hostName.empty()) {
                    it->second.hostName = hostname;
                    lock.unlock();
                    ::ShadowStrike::Utils::Logger::Debug("DNS: Resolved hostname '{}' for {}",
                                         hostname, ip);
                }
            }

            offset += rdlength;
        }
    }

    // ========================================================================
    // PASSIVE MONITORING THREAD
    // ========================================================================

    void PassiveMonitorThreadFunc() {
        ::ShadowStrike::Utils::Logger::Info("Passive monitoring thread started");

        while (m_passiveMonitoring.load(std::memory_order_acquire)) {
            // Monitor loop — in production this would read from a packet
            // capture source (ETW, WFP, or raw socket).
            // The callbacks ProcessARPPacket/ProcessDNSPacket are invoked
            // by the caller who has the actual packet capture driver.
            // This thread performs periodic maintenance:

            // 1) Age-out stale devices (not seen in >5 minutes)
            {
                auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(5);
                std::unique_lock lock(m_mutex);
                for (auto& [ip, device] : m_devices) {
                    if (device.isOnline && device.lastSeen < cutoff) {
                        device.isOnline = false;
                    }
                }

                // Update active device count
                uint32_t activeCount = 0;
                for (const auto& [ip, device] : m_devices) {
                    if (device.isOnline) {
                        activeCount++;
                    }
                }
                m_stats.activeDevices.store(activeCount, std::memory_order_relaxed);
            }

            // Sleep for 10 seconds between maintenance cycles
            for (int i = 0; i < 100 && m_passiveMonitoring.load(std::memory_order_acquire); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        ::ShadowStrike::Utils::Logger::Info("Passive monitoring thread stopped");
    }

    // ========================================================================
    // DEEP SCAN
    // ========================================================================

    [[nodiscard]] IoTDeviceInfo PerformDeepScan(const std::string& ipAddress) {
        IoTDeviceInfo device;
        device.ipAddress = ipAddress;
        device.deviceId = GenerateDeviceId(ipAddress);
        device.firstSeen = std::chrono::system_clock::now();
        device.lastSeen = device.firstSeen;
        device.isOnline = false;

        try {
            if (!IsHostReachable(ipAddress)) {
                return device;
            }

            device.isOnline = true;

            // Resolve MAC via ARP table
            ResolveMAC(device);

            // Select port list based on scan mode
            auto ports = m_activeScanConfig.scanCommonPortsOnly
                ? std::span<const uint16_t>(IoTConstants::COMMON_IOT_PORTS)
                : std::span<const uint16_t>(IoTConstants::EXTENDED_IOT_PORTS);

            for (uint16_t port : ports) {
                if (!m_scanActive.load(std::memory_order_acquire)) {
                    break;
                }

                ServiceInfo service;
                if (ScanPort(ipAddress, port, service)) {
                    device.services.push_back(service);
                }

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(IoTConstants::PORT_SCAN_THROTTLE_MS));
            }

            // Assess vulnerabilities
            AssessVulnerabilities(device);

            device.lastScanned = std::chrono::system_clock::now();
            m_stats.totalDevicesDiscovered++;

            size_t catIdx = static_cast<size_t>(device.category);
            if (catIdx < m_stats.byCategory.size()) {
                m_stats.byCategory[catIdx]++;
            }

        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("Deep scan failed for {}: {}", ipAddress, e.what());
        }

        return device;
    }

    /**
     * @brief Resolve MAC address for a device using the system ARP table
     */
    void ResolveMAC(IoTDeviceInfo& device) {
        in_addr destIP{};
        if (::inet_pton(AF_INET, device.ipAddress.c_str(), &destIP) != 1) {
            return;
        }

        ULONG macAddr[2]{};
        ULONG macAddrLen = 6;

        DWORD result = ::SendARP(destIP.s_addr, 0, macAddr, &macAddrLen);
        if (result == NO_ERROR && macAddrLen == 6) {
            auto* macBytes = reinterpret_cast<uint8_t*>(macAddr);
            device.macAddress = FormatMAC(macBytes);
            device.deviceId = GenerateDeviceId(device.macAddress);
            device.vendor = LookupVendor(device.macAddress);
            device.category = ClassifyByVendor(device.vendor);
        }
    }

    // ========================================================================
    // PROGRESS TRACKING
    // ========================================================================

    void UpdateProgress(ScanStatus status, float percent, const std::string& current) {
        IoTScanProgress snapshot;
        {
            std::unique_lock lock(m_mutex);
            m_progress.status = status;
            m_progress.progressPercent = percent;
            m_progress.currentDevice = current;
            snapshot = m_progress;
        }

        NotifyProgress(snapshot);
    }

    // ========================================================================
    // SCAN THREAD
    // ========================================================================

    void ScanThreadFunc(std::vector<std::string> targets) {
        ::ShadowStrike::Utils::Logger::Info("Scan thread started for {} targets", targets.size());

        const auto scanStartTime = std::chrono::system_clock::now();
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(m_activeScanConfig.scanTimeoutMs);
        UpdateProgress(ScanStatus::Discovering, 0.0f, "");

        size_t count = 0;
        bool cancelled = false;
        bool timedOut = false;
        for (const auto& ip : targets) {
            if (!m_scanActive.load(std::memory_order_acquire)) {
                cancelled = true;
                break;
            }

            if (std::chrono::steady_clock::now() >= deadline) {
                timedOut = true;
                break;
            }

            float progress = static_cast<float>(count) / static_cast<float>(targets.size()) * 100.0f;
            UpdateProgress(ScanStatus::Scanning, progress, ip);

            auto device = PerformDeepScan(ip);

            if (device.isOnline) {
                {
                    std::unique_lock lock(m_mutex);
                    m_devices[ip] = device;
                    if (!device.macAddress.empty()) {
                        m_macToIP[device.macAddress] = ip;
                    }
                    m_progress.devicesFound++;
                    m_progress.devicesScanned++;

                    if (device.vulnerabilityLevel >= VulnerabilityLevel::Medium) {
                        m_progress.vulnerabilitiesFound +=
                            static_cast<uint32_t>(device.riskFactors.size());
                    }
                }

                NotifyDeviceFound(device);

                if (device.vulnerabilityLevel >= VulnerabilityLevel::Medium) {
                    for (auto risk : device.riskFactors) {
                        NotifyVulnerability(device, risk);
                    }
                }
            } else {
                std::unique_lock lock(m_mutex);
                m_progress.devicesScanned++;
            }

            ++count;
        }

        if (timedOut) {
            UpdateProgress(ScanStatus::Error,
                static_cast<float>(count) / static_cast<float>(targets.size()) * 100.0f,
                "scan-timeout");
            NotifyError("IoT scan timed out before completing all targets", ERROR_TIMEOUT);
        } else if (cancelled) {
            UpdateProgress(ScanStatus::Cancelled,
                static_cast<float>(count) / static_cast<float>(targets.size()) * 100.0f, "");
        } else {
            UpdateProgress(ScanStatus::Completed, 100.0f, "");
        }

        m_scanActive.store(false, std::memory_order_release);
        GenerateScanSummary(scanStartTime);

        ::ShadowStrike::Utils::Logger::Info("Scan thread {} — {} devices found on {} targets",
                            timedOut ? "timed out" : (cancelled ? "cancelled" : "completed"),
                            m_progress.devicesFound,
                            targets.size());
    }

    // ========================================================================
    // SCAN SUMMARY
    // ========================================================================

    void GenerateScanSummary(std::chrono::system_clock::time_point startTime) {
        IoTScanResultSummary summary;
        summary.status = ScanStatus::Completed;
        summary.startTime = AtomicValueLoadRelaxed(startTime);
        summary.endTime = std::chrono::system_clock::now();
        summary.duration = std::chrono::duration_cast<std::chrono::seconds>(
            summary.endTime - summary.startTime);

        {
            std::shared_lock lock(m_mutex);
            summary.totalDevicesFound = static_cast<uint32_t>(m_devices.size());

            for (const auto& [ip, device] : m_devices) {
                summary.devicesByCategory[device.category]++;

                switch (device.vulnerabilityLevel) {
                    case VulnerabilityLevel::Critical:
                        summary.criticalVulnerabilities++;
                        break;
                    case VulnerabilityLevel::High:
                        summary.highVulnerabilities++;
                        break;
                    case VulnerabilityLevel::Medium:
                        summary.mediumVulnerabilities++;
                        break;
                    case VulnerabilityLevel::Low:
                        summary.lowVulnerabilities++;
                        break;
                    default:
                        break;
                }

                if (device.hasDefaultCredentials) {
                    summary.devicesWithDefaultCreds++;
                }

                if (device.isPotentiallyCompromised) {
                    summary.potentiallyCompromised++;
                }
            }
        }

        NotifyComplete(summary);
    }

    // ========================================================================
    // NETWORK INTERFACE ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<NetworkInterface> EnumerateInterfaces() const {
        std::vector<NetworkInterface> interfaces;

        ULONG bufferSize = 0;
        if (::GetAdaptersInfo(nullptr, &bufferSize) != ERROR_BUFFER_OVERFLOW) {
            return interfaces;
        }

        std::vector<uint8_t> buffer(bufferSize);
        auto* adapter = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());

        if (::GetAdaptersInfo(adapter, &bufferSize) != ERROR_SUCCESS) {
            ::ShadowStrike::Utils::Logger::Error("GetAdaptersInfo failed: {}", ::GetLastError());
            return interfaces;
        }

        while (adapter) {
            NetworkInterface iface;
            iface.name = adapter->AdapterName;
            iface.description = adapter->Description;
            iface.ipv4Address = adapter->IpAddressList.IpAddress.String;
            iface.subnetMask = adapter->IpAddressList.IpMask.String;
            iface.gatewayAddress = adapter->GatewayList.IpAddress.String;

            std::ostringstream macStream;
            for (UINT i = 0; i < adapter->AddressLength; ++i) {
                if (i > 0) macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(adapter->Address[i]);
            }
            iface.macAddress = macStream.str();
            std::transform(iface.macAddress.begin(), iface.macAddress.end(),
                           iface.macAddress.begin(), ::toupper);

            iface.interfaceIndex = adapter->Index;
            iface.isConnected = (iface.ipv4Address != "0.0.0.0" && !iface.ipv4Address.empty());
            iface.isWireless = (adapter->Type == IF_TYPE_IEEE80211);

            interfaces.push_back(iface);
            adapter = adapter->Next;
        }

        return interfaces;
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> IoTDeviceScanner::s_instanceCreated{false};

[[nodiscard]] IoTDeviceScanner& IoTDeviceScanner::Instance() noexcept {
    static IoTDeviceScanner instance;
    return instance;
}

[[nodiscard]] bool IoTDeviceScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

IoTDeviceScanner::IoTDeviceScanner()
    : m_impl(std::make_unique<IoTDeviceScannerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    ::ShadowStrike::Utils::Logger::Info("IoTDeviceScanner singleton created");
}

IoTDeviceScanner::~IoTDeviceScanner() {
    try {
        Shutdown();
        ::ShadowStrike::Utils::Logger::Info("IoTDeviceScanner singleton destroyed");
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool IoTDeviceScanner::Initialize(
    const IoTScannerConfiguration& config)
{
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            ::ShadowStrike::Utils::Logger::Warn("IoTDeviceScanner already initialized");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("Invalid IoTDeviceScanner configuration");
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }

        m_impl->m_config = config;
        m_impl->m_stats.Reset();
        AtomicValueStoreRelaxed(m_impl->m_stats.startTime, Clock::now());

        m_impl->m_status = ModuleStatus::Running;

        ::ShadowStrike::Utils::Logger::Info("IoTDeviceScanner initialized successfully (v{})", GetVersionString());

        if (config.autoDiscoveryOnStartup && config.enabled) {
            lock.unlock();
            StartDiscovery(config.defaultScanConfig);
        }

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("IoTDeviceScanner initialization failed: {}", e.what());
        m_impl->m_status = ModuleStatus::Error;
        m_impl->NotifyError("Initialization failed: " + std::string(e.what()), -1);
        return false;
    }
}

void IoTDeviceScanner::Shutdown() {
    try {
        auto status = m_impl->m_status.load(std::memory_order_acquire);
        if (status == ModuleStatus::Uninitialized || status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;

        m_impl->StopAllScans();

        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_devices.clear();
            m_impl->m_macToIP.clear();
        }

        {
            std::lock_guard lock(m_impl->m_callbackMutex);
            m_impl->m_deviceFoundCallbacks.clear();
            m_impl->m_vulnerabilityCallbacks.clear();
            m_impl->m_progressCallbacks.clear();
            m_impl->m_completeCallbacks.clear();
            m_impl->m_errorCallbacks.clear();
        }

        m_impl->m_status = ModuleStatus::Stopped;

        ::ShadowStrike::Utils::Logger::Info("IoTDeviceScanner shut down");

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool IoTDeviceScanner::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == ModuleStatus::Running ||
           status == ModuleStatus::Scanning ||
           status == ModuleStatus::Monitoring;
}

[[nodiscard]] ModuleStatus IoTDeviceScanner::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

[[nodiscard]] bool IoTDeviceScanner::UpdateConfiguration(
    const IoTScannerConfiguration& config)
{
    try {
        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = config;

        ::ShadowStrike::Utils::Logger::Info("IoTDeviceScanner configuration updated");
        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("Configuration update failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] IoTScannerConfiguration IoTDeviceScanner::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

[[nodiscard]] bool IoTDeviceScanner::StartDiscovery(const IoTScanConfig& config) {
    try {
        bool expected = false;
        if (!m_impl->m_scanActive.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            ::ShadowStrike::Utils::Logger::Warn("Scan already in progress");
            return false;
        }

        auto releaseOnFailure = [this]() noexcept {
            m_impl->m_scanActive.store(false, std::memory_order_release);
        };

        if (!IsInitialized()) {
            ::ShadowStrike::Utils::Logger::Error("Scanner not initialized");
            releaseOnFailure();
            return false;
        }

        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("StartDiscovery rejected invalid scan configuration");
            releaseOnFailure();
            return false;
        }

        m_impl->m_activeScanConfig = config;

        std::vector<std::string> targets;
        std::unordered_set<std::string> dedupedTargets;

        auto appendTargets = [&](const std::string& cidr) {
            if (!IsSubnetScopeAllowed(cidr, config.allowLargeSubnets)) {
                return;
            }

            auto hosts = ParseCIDRToHosts(cidr);
            for (auto& host : hosts) {
                if (dedupedTargets.insert(host).second) {
                    targets.push_back(std::move(host));
                }
            }
        };

        if (config.targetSubnets.empty()) {
            auto interfaces = m_impl->EnumerateInterfaces();
            for (const auto& iface : interfaces) {
                if (iface.isConnected && !iface.ipv4Address.empty() &&
                    iface.ipv4Address != "0.0.0.0") {

                    std::string cidr = DeriveCIDRFromInterface(iface.ipv4Address, iface.subnetMask);
                    if (!cidr.empty()) {
                        appendTargets(cidr);
                    }
                }
            }
        } else {
            for (const auto& subnet : config.targetSubnets) {
                appendTargets(subnet);
            }
        }

        if (!config.excludedIPs.empty()) {
            std::unordered_set<std::string> excluded(config.excludedIPs.begin(),
                                                     config.excludedIPs.end());
            targets.erase(
                std::remove_if(targets.begin(), targets.end(),
                    [&excluded](const std::string& ip) {
                        return excluded.count(ip) > 0;
                    }),
                targets.end());
        }

        if (targets.empty()) {
            ::ShadowStrike::Utils::Logger::Error("No scan targets remained after scope validation");
            releaseOnFailure();
            return false;
        }

        if (targets.size() > IoTConstants::MAX_TRACKED_DEVICES) {
            ::ShadowStrike::Utils::Logger::Warn(
                "Target set exceeded device cap ({}), truncating",
                IoTConstants::MAX_TRACKED_DEVICES);
            targets.resize(IoTConstants::MAX_TRACKED_DEVICES);
        }

        ::ShadowStrike::Utils::Logger::Info("Starting IoT scan of {} targets", targets.size());

        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_progress = IoTScanProgress{};
            m_impl->m_progress.status = ScanStatus::Initializing;
        }

        if (m_impl->m_scanThread.joinable()) {
            m_impl->m_scanThread.join();
        }

        m_impl->m_status = ModuleStatus::Scanning;
        m_impl->m_scanThread = std::thread(
            &IoTDeviceScannerImpl::ScanThreadFunc, m_impl.get(), std::move(targets));
        m_impl->m_stats.totalScans++;
        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("StartDiscovery failed: {}", e.what());
        m_impl->m_scanActive.store(false, std::memory_order_release);
        m_impl->NotifyError("Failed to start discovery: " + std::string(e.what()), -1);
        return false;
    }
}

void IoTDeviceScanner::StopScan() {
    m_impl->m_scanActive.store(false, std::memory_order_release);

    if (m_impl->m_scanThread.joinable()) {
        m_impl->m_scanThread.join();
    }

    m_impl->m_status = ModuleStatus::Running;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_progress.status = ScanStatus::Cancelled;

    ::ShadowStrike::Utils::Logger::Info("Scan stopped");
}

[[nodiscard]] IoTDeviceInfo IoTDeviceScanner::DeepScanDevice(
    const std::string& ipAddress)
{
    try {
        // Validate IP address before passing to network APIs
        if (ipAddress.empty() || ipAddress.size() > 45) {
            ::ShadowStrike::Utils::Logger::Error("DeepScanDevice: invalid IP address length");
            return IoTDeviceInfo{};
        }

        in_addr validateAddr{};
        if (::inet_pton(AF_INET, ipAddress.c_str(), &validateAddr) != 1) {
            ::ShadowStrike::Utils::Logger::Error("DeepScanDevice: invalid IPv4 address: {}",
                                 ipAddress);
            return IoTDeviceInfo{};
        }

        ::ShadowStrike::Utils::Logger::Debug("Deep scanning device: {}", ipAddress);

        auto device = m_impl->PerformDeepScan(ipAddress);

        if (device.isOnline) {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_devices[ipAddress] = device;
            if (!device.macAddress.empty()) {
                m_impl->m_macToIP[device.macAddress] = ipAddress;
            }
        }

        return device;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("DeepScanDevice failed: {}", e.what());
        return IoTDeviceInfo{};
    }
}

[[nodiscard]] bool IoTDeviceScanner::ScanSubnet(const std::string& cidrSubnet) {
    IoTScanConfig config;
    {
        std::shared_lock lock(m_impl->m_mutex);
        config = m_impl->m_config.defaultScanConfig;
    }
    config.targetSubnets.clear();
    config.targetSubnets.push_back(cidrSubnet);

    return StartDiscovery(config);
}

[[nodiscard]] IoTScanProgress IoTDeviceScanner::GetProgress() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_progress;
}

// ============================================================================
// NETWORK MAP
// ============================================================================

[[nodiscard]] std::vector<IoTDeviceInfo> IoTDeviceScanner::GetNetworkMap() const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<IoTDeviceInfo> devices;
    devices.reserve(m_impl->m_devices.size());

    for (const auto& [ip, device] : m_impl->m_devices) {
        devices.push_back(device);
    }

    return devices;
}

[[nodiscard]] std::optional<IoTDeviceInfo> IoTDeviceScanner::GetDevice(
    const std::string& ipAddress) const
{
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_devices.find(ipAddress);
    if (it != m_impl->m_devices.end()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<IoTDeviceInfo> IoTDeviceScanner::GetDeviceByMAC(
    const std::string& macAddress) const
{
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_macToIP.find(macAddress);
    if (it != m_impl->m_macToIP.end()) {
        auto devIt = m_impl->m_devices.find(it->second);
        if (devIt != m_impl->m_devices.end()) {
            return devIt->second;
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<IoTDeviceInfo> IoTDeviceScanner::GetDevicesByCategory(
    DeviceCategory category) const
{
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<IoTDeviceInfo> devices;

    for (const auto& [ip, device] : m_impl->m_devices) {
        if (device.category == category) {
            devices.push_back(device);
        }
    }

    return devices;
}

[[nodiscard]] std::vector<IoTDeviceInfo> IoTDeviceScanner::GetVulnerableDevices(
    VulnerabilityLevel minLevel) const
{
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<IoTDeviceInfo> devices;

    for (const auto& [ip, device] : m_impl->m_devices) {
        if (device.vulnerabilityLevel >= minLevel) {
            devices.push_back(device);
        }
    }

    return devices;
}

[[nodiscard]] std::vector<NetworkInterface> IoTDeviceScanner::GetNetworkInterfaces() const {
    return m_impl->EnumerateInterfaces();
}

// ============================================================================
// PASSIVE MONITORING
// ============================================================================

void IoTDeviceScanner::ProcessARPPacket(std::span<const uint8_t> packet) {
    try {
        if (packet.size() < ARP_PACKET_MIN_SIZE) {
            return;
        }

        m_impl->m_stats.packetsAnalyzed++;
        m_impl->ParseARPPacket(packet);

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("ProcessARPPacket failed: {}", e.what());
    }
}

void IoTDeviceScanner::ProcessDNSPacket(std::span<const uint8_t> packet) {
    try {
        if (packet.size() < DNS_HEADER_SIZE) {
            return;
        }

        m_impl->m_stats.packetsAnalyzed++;
        m_impl->ParseDNSPacket(packet);

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("ProcessDNSPacket failed: {}", e.what());
    }
}

[[nodiscard]] bool IoTDeviceScanner::StartPassiveMonitoring() {
    try {
        if (m_impl->m_passiveMonitoring.load(std::memory_order_acquire)) {
            return true;
        }

        if (!IsInitialized()) {
            ::ShadowStrike::Utils::Logger::Error("Cannot start passive monitoring: not initialized");
            return false;
        }

        // Join previous monitor thread if still joinable
        if (m_impl->m_monitorThread.joinable()) {
            m_impl->m_monitorThread.join();
        }

        m_impl->m_passiveMonitoring.store(true, std::memory_order_release);
        m_impl->m_monitorThread = std::thread(
            &IoTDeviceScannerImpl::PassiveMonitorThreadFunc, m_impl.get());

        m_impl->m_status = ModuleStatus::Monitoring;

        ::ShadowStrike::Utils::Logger::Info("Passive monitoring started");
        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("StartPassiveMonitoring failed: {}", e.what());
        return false;
    }
}

void IoTDeviceScanner::StopPassiveMonitoring() {
    m_impl->m_passiveMonitoring.store(false, std::memory_order_release);

    if (m_impl->m_monitorThread.joinable()) {
        m_impl->m_monitorThread.join();
    }

    if (m_impl->m_status == ModuleStatus::Monitoring) {
        m_impl->m_status = ModuleStatus::Running;
    }

    ::ShadowStrike::Utils::Logger::Info("Passive monitoring stopped");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void IoTDeviceScanner::RegisterDeviceFoundCallback(DeviceFoundCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_deviceFoundCallbacks.push_back(std::move(callback));
}

void IoTDeviceScanner::RegisterVulnerabilityCallback(VulnerabilityCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_vulnerabilityCallbacks.push_back(std::move(callback));
}

void IoTDeviceScanner::RegisterProgressCallback(ScanProgressCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallbacks.push_back(std::move(callback));
}

void IoTDeviceScanner::RegisterCompleteCallback(ScanCompleteCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completeCallbacks.push_back(std::move(callback));
}

void IoTDeviceScanner::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void IoTDeviceScanner::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->m_callbackMutex);

    m_impl->m_deviceFoundCallbacks.clear();
    m_impl->m_vulnerabilityCallbacks.clear();
    m_impl->m_progressCallbacks.clear();
    m_impl->m_completeCallbacks.clear();
    m_impl->m_errorCallbacks.clear();

    ::ShadowStrike::Utils::Logger::Info("All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] IoTScanStatistics::Snapshot IoTDeviceScanner::GetStatistics() const {
    return m_impl->m_stats.ToSnapshot();
}

void IoTDeviceScanner::ResetStatistics() {
    m_impl->m_stats.Reset();
    AtomicValueStoreRelaxed(m_impl->m_stats.startTime, Clock::now());

    ::ShadowStrike::Utils::Logger::Info("Statistics reset");
}

[[nodiscard]] bool IoTDeviceScanner::SelfTest() {
    try {
        ::ShadowStrike::Utils::Logger::Info("Running IoTDeviceScanner self-test...");

        bool allPassed = true;

        // Test 1: Configuration validation
        IoTScannerConfiguration config;
        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Invalid default configuration");
            allPassed = false;
        }

        // Test 2: Scan config validation
        IoTScanConfig scanConfig;
        if (!scanConfig.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Invalid default scan config");
            allPassed = false;
        }

        // Test 3: Invalid scan config should fail validation
        IoTScanConfig badConfig;
        badConfig.scanTimeoutMs = 0;
        if (badConfig.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Zero-timeout config should be invalid");
            allPassed = false;
        }

        // Test 4: Network interface enumeration
        try {
            auto interfaces = GetNetworkInterfaces();
            if (interfaces.empty()) {
                ::ShadowStrike::Utils::Logger::Warn("Self-test: No network interfaces found");
            } else {
                ::ShadowStrike::Utils::Logger::Debug("Self-test: Found {} network interfaces", interfaces.size());
            }
        } catch (...) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Interface enumeration");
            allPassed = false;
        }

        // Test 5: Device ID generation consistency
        auto id1 = GenerateDeviceId("00:11:22:33:44:55");
        auto id2 = GenerateDeviceId("00:11:22:33:44:55");
        auto id3 = GenerateDeviceId("AA:BB:CC:DD:EE:FF");

        if (id1 != id2) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Inconsistent device ID generation");
            allPassed = false;
        }

        if (id1 == id3) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Device ID collision");
            allPassed = false;
        }

        // Test 6: CIDR parser
        auto hosts = ParseCIDRToHosts("192.168.1.0/30");
        if (hosts.size() != 2) { // /30 = 4 IPs, 2 hosts (minus network and broadcast)
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: CIDR /30 should produce 2 hosts, got {}",
                                 hosts.size());
            allPassed = false;
        }

        // Test 7: MAC vendor lookup
        auto vendor = LookupMACVendor("B8:27:EB:00:00:00");
        if (vendor == "Unknown") {
            ::ShadowStrike::Utils::Logger::Warn("Self-test: MAC vendor lookup returned Unknown for Raspberry Pi OUI");
        }

        // Test 8: Base64 encoding
        auto encoded = Base64Encode("admin:admin");
        if (encoded != "YWRtaW46YWRtaW4=") {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: Base64 encoding mismatch");
            allPassed = false;
        }

        // Test 9: RiskFactor bitwise operators
        RiskFactor combined = RiskFactor::OpenTelnet | RiskFactor::DefaultCredentials;
        if (!HasFlag(combined, RiskFactor::OpenTelnet) ||
            !HasFlag(combined, RiskFactor::DefaultCredentials) ||
            HasFlag(combined, RiskFactor::KnownCVE)) {
            ::ShadowStrike::Utils::Logger::Error("Self-test failed: RiskFactor bitwise operators");
            allPassed = false;
        }

        if (allPassed) {
            ::ShadowStrike::Utils::Logger::Info("Self-test PASSED - All tests successful");
        } else {
            ::ShadowStrike::Utils::Logger::Error("Self-test FAILED - See errors above");
        }

        return allPassed;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string IoTDeviceScanner::GetVersionString() noexcept {
    return std::to_string(IoTConstants::VERSION_MAJOR) + "." +
           std::to_string(IoTConstants::VERSION_MINOR) + "." +
           std::to_string(IoTConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

void IoTScanStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    totalDevicesDiscovered.store(0, std::memory_order_relaxed);
    totalVulnerabilitiesFound.store(0, std::memory_order_relaxed);
    defaultCredentialsFound.store(0, std::memory_order_relaxed);
    botnetIndicatorsDetected.store(0, std::memory_order_relaxed);
    cvesMatched.store(0, std::memory_order_relaxed);
    packetsAnalyzed.store(0, std::memory_order_relaxed);
    activeDevices.store(0, std::memory_order_relaxed);

    for (auto& cat : byCategory) {
        cat.store(0, std::memory_order_relaxed);
    }

    for (auto& level : byVulnerabilityLevel) {
        level.store(0, std::memory_order_relaxed);
    }
}

[[nodiscard]] IoTScanStatistics::Snapshot IoTScanStatistics::ToSnapshot() const noexcept {
    Snapshot snap;
    snap.totalScans = totalScans.load(std::memory_order_relaxed);
    snap.totalDevicesDiscovered = totalDevicesDiscovered.load(std::memory_order_relaxed);
    snap.totalVulnerabilitiesFound = totalVulnerabilitiesFound.load(std::memory_order_relaxed);
    snap.defaultCredentialsFound = defaultCredentialsFound.load(std::memory_order_relaxed);
    snap.botnetIndicatorsDetected = botnetIndicatorsDetected.load(std::memory_order_relaxed);
    snap.cvesMatched = cvesMatched.load(std::memory_order_relaxed);
    snap.packetsAnalyzed = packetsAnalyzed.load(std::memory_order_relaxed);
    snap.activeDevices = activeDevices.load(std::memory_order_relaxed);
    snap.startTime = AtomicValueLoadRelaxed(startTime);

    for (size_t i = 0; i < byCategory.size(); ++i) {
        snap.byCategory[i] = byCategory[i].load(std::memory_order_relaxed);
    }
    for (size_t i = 0; i < byVulnerabilityLevel.size(); ++i) {
        snap.byVulnerabilityLevel[i] = byVulnerabilityLevel[i].load(std::memory_order_relaxed);
    }

    return snap;
}

[[nodiscard]] std::string IoTScanStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["totalScans"] = totalScans.load(std::memory_order_relaxed);
    j["totalDevicesDiscovered"] = totalDevicesDiscovered.load(std::memory_order_relaxed);
    j["totalVulnerabilitiesFound"] = totalVulnerabilitiesFound.load(std::memory_order_relaxed);
    j["defaultCredentialsFound"] = defaultCredentialsFound.load(std::memory_order_relaxed);
    j["botnetIndicatorsDetected"] = botnetIndicatorsDetected.load(std::memory_order_relaxed);
    j["cvesMatched"] = cvesMatched.load(std::memory_order_relaxed);
    j["packetsAnalyzed"] = packetsAnalyzed.load(std::memory_order_relaxed);
    j["activeDevices"] = activeDevices.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - AtomicValueLoadRelaxed(startTime)).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] std::string IoTScanStatistics::Snapshot::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["totalScans"] = totalScans;
    j["totalDevicesDiscovered"] = totalDevicesDiscovered;
    j["totalVulnerabilitiesFound"] = totalVulnerabilitiesFound;
    j["defaultCredentialsFound"] = defaultCredentialsFound;
    j["botnetIndicatorsDetected"] = botnetIndicatorsDetected;
    j["cvesMatched"] = cvesMatched;
    j["packetsAnalyzed"] = packetsAnalyzed;
    j["activeDevices"] = activeDevices;

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - AtomicValueLoadRelaxed(startTime)).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] bool IoTScannerConfiguration::IsValid() const noexcept {
    if (!defaultScanConfig.IsValid()) {
        return false;
    }
    return enabled || (!autoDiscoveryOnStartup && !continuousMonitoring);
}

[[nodiscard]] bool IoTScanConfig::IsValid() const noexcept {
    if (scanTimeoutMs == 0) return false;
    if (scanTimeoutMs > 300000) return false; // Max 5 minutes
    if (maxParallelScans == 0 || maxParallelScans > IoTConstants::MAX_CONCURRENT_PORT_SCANS) return false;
    if (scanIntervalSeconds > 0 && scanIntervalSeconds < 60) return false; // Min 60s between auto-scans
    return true;
}

[[nodiscard]] std::string IoTScanConfig::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["enableActiveScanning"] = enableActiveScanning;
    j["enablePassiveMonitoring"] = enablePassiveMonitoring;
    j["checkDefaultCredentials"] = checkDefaultCredentials;
    j["scanCommonPortsOnly"] = scanCommonPortsOnly;
    j["enableUPnPDiscovery"] = enableUPnPDiscovery;
    j["enableMDNSDiscovery"] = enableMDNSDiscovery;
    j["enableARPScanning"] = enableARPScanning;
    j["enableCVEChecking"] = enableCVEChecking;
    j["allowLargeSubnets"] = allowLargeSubnets;
    j["targetSubnets"] = targetSubnets;
    j["excludedIPs"] = excludedIPs;
    j["scanIntervalSeconds"] = scanIntervalSeconds;
    j["scanTimeoutMs"] = scanTimeoutMs;
    j["lowBandwidthMode"] = lowBandwidthMode;
    j["maxParallelScans"] = maxParallelScans;

    return j.dump(2);
}

[[nodiscard]] std::string NetworkInterface::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["name"] = name;
    j["description"] = description;
    j["ipv4Address"] = ipv4Address;
    j["ipv6Address"] = ipv6Address;
    j["subnetMask"] = subnetMask;
    j["macAddress"] = macAddress;
    j["gatewayAddress"] = gatewayAddress;
    j["isWireless"] = isWireless;
    j["isConnected"] = isConnected;
    j["interfaceIndex"] = interfaceIndex;

    return j.dump(2);
}

[[nodiscard]] std::string ServiceInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["port"] = port;
    j["protocol"] = static_cast<int>(protocol);
    j["serviceName"] = serviceName;
    j["product"] = product;
    j["version"] = version;
    j["banner"] = banner;
    j["isOpen"] = isOpen;
    j["isSecure"] = isSecure;
    j["requiresAuth"] = requiresAuth;
    j["risks"] = static_cast<uint32_t>(risks);

    return j.dump(2);
}

[[nodiscard]] std::string CVEInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["cveId"] = cveId;
    j["description"] = description;
    j["cvssScore"] = cvssScore;
    j["severity"] = static_cast<int>(severity);
    j["hasExploit"] = hasExploit;
    j["affectedProduct"] = affectedProduct;
    j["affectedVersions"] = affectedVersions;

    return j.dump(2);
}

[[nodiscard]] std::string IoTDeviceInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["deviceId"] = deviceId;
    j["ipAddress"] = ipAddress;
    j["ipv6Address"] = ipv6Address;
    j["macAddress"] = macAddress;
    j["hostName"] = hostName;
    j["deviceName"] = deviceName;
    j["vendor"] = vendor;
    j["model"] = model;
    j["firmwareVersion"] = firmwareVersion;
    j["category"] = static_cast<int>(category);
    j["vulnerabilityLevel"] = static_cast<int>(vulnerabilityLevel);
    j["risks"] = static_cast<uint32_t>(risks);
    j["discoveryMethod"] = static_cast<int>(discoveryMethod);
    j["isOnline"] = isOnline;
    j["isGateway"] = isGateway;
    j["hasDefaultCredentials"] = hasDefaultCredentials;
    j["isPotentiallyCompromised"] = isPotentiallyCompromised;

    Json servicesArray = Json::array();
    for (const auto& svc : services) {
        servicesArray.push_back(Json::parse(svc.ToJson()));
    }
    j["services"] = servicesArray;

    Json cvesArray = Json::array();
    for (const auto& cve : cves) {
        cvesArray.push_back(Json::parse(cve.ToJson()));
    }
    j["cves"] = cvesArray;

    return j.dump(2);
}

[[nodiscard]] int IoTDeviceInfo::GetOverallRiskScore() const {
    int score = 0;

    // Base score from vulnerability level
    score += static_cast<int>(vulnerabilityLevel) * 20;

    // Add points for each risk factor (portable popcount)
    uint32_t riskBits = static_cast<uint32_t>(risks);
    score += std::popcount(riskBits) * 5;

    // Critical flags
    if (hasDefaultCredentials) score += 30;
    if (isPotentiallyCompromised) score += 50;

    // Open services without auth
    for (const auto& svc : services) {
        if (svc.isOpen && !svc.requiresAuth) {
            score += 10;
        }
    }

    return std::min(score, 100);
}

[[nodiscard]] std::string IoTScanProgress::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["status"] = static_cast<int>(status);
    j["progressPercent"] = progressPercent;
    j["devicesFound"] = devicesFound;
    j["devicesScanned"] = devicesScanned;
    j["vulnerabilitiesFound"] = vulnerabilitiesFound;
    j["currentDevice"] = currentDevice;
    j["estimatedTimeRemaining"] = estimatedTimeRemaining.count();

    return j.dump(2);
}

[[nodiscard]] std::string IoTScanResultSummary::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["status"] = static_cast<int>(status);
    j["subnetScanned"] = subnetScanned;
    j["totalDevicesFound"] = totalDevicesFound;
    j["criticalVulnerabilities"] = criticalVulnerabilities;
    j["highVulnerabilities"] = highVulnerabilities;
    j["mediumVulnerabilities"] = mediumVulnerabilities;
    j["lowVulnerabilities"] = lowVulnerabilities;
    j["devicesWithDefaultCreds"] = devicesWithDefaultCreds;
    j["potentiallyCompromised"] = potentiallyCompromised;
    j["duration"] = duration.count();

    return j.dump(2);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDeviceCategoryName(DeviceCategory cat) noexcept {
    switch (cat) {
        case DeviceCategory::Router: return "Router";
        case DeviceCategory::Gateway: return "Gateway";
        case DeviceCategory::AccessPoint: return "AccessPoint";
        case DeviceCategory::IPCamera: return "IPCamera";
        case DeviceCategory::SmartTV: return "SmartTV";
        case DeviceCategory::SmartSpeaker: return "SmartSpeaker";
        case DeviceCategory::VoiceAssistant: return "VoiceAssistant";
        case DeviceCategory::Thermostat: return "Thermostat";
        case DeviceCategory::SmartLight: return "SmartLight";
        case DeviceCategory::SmartPlug: return "SmartPlug";
        case DeviceCategory::SmartLock: return "SmartLock";
        case DeviceCategory::DoorSensor: return "DoorSensor";
        case DeviceCategory::MotionSensor: return "MotionSensor";
        case DeviceCategory::Printer: return "Printer";
        case DeviceCategory::NAS: return "NAS";
        case DeviceCategory::MediaServer: return "MediaServer";
        case DeviceCategory::GamingConsole: return "GamingConsole";
        case DeviceCategory::SetTopBox: return "SetTopBox";
        case DeviceCategory::SmartWatch: return "SmartWatch";
        case DeviceCategory::SmartAppliance: return "SmartAppliance";
        case DeviceCategory::HVACController: return "HVACController";
        case DeviceCategory::SecuritySystem: return "SecuritySystem";
        case DeviceCategory::BabyMonitor: return "BabyMonitor";
        case DeviceCategory::MobileDevice: return "MobileDevice";
        case DeviceCategory::Computer: return "Computer";
        case DeviceCategory::NetworkSwitch: return "NetworkSwitch";
        case DeviceCategory::IoTHub: return "IoTHub";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetVulnerabilityLevelName(VulnerabilityLevel level) noexcept {
    switch (level) {
        case VulnerabilityLevel::Informational: return "Informational";
        case VulnerabilityLevel::Low: return "Low";
        case VulnerabilityLevel::Medium: return "Medium";
        case VulnerabilityLevel::High: return "High";
        case VulnerabilityLevel::Critical: return "Critical";
        default: return "None";
    }
}

[[nodiscard]] std::string_view GetRiskFactorName(RiskFactor risk) noexcept {
    switch (risk) {
        case RiskFactor::DefaultCredentials: return "DefaultCredentials";
        case RiskFactor::WeakCredentials: return "WeakCredentials";
        case RiskFactor::OpenTelnet: return "OpenTelnet";
        case RiskFactor::OpenSSHWeakCrypto: return "OpenSSHWeakCrypto";
        case RiskFactor::OutdatedFirmware: return "OutdatedFirmware";
        case RiskFactor::KnownCVE: return "KnownCVE";
        case RiskFactor::BotnetCommunication: return "BotnetCommunication";
        case RiskFactor::UnencryptedStream: return "UnencryptedStream";
        case RiskFactor::UPnPEnabled: return "UPnPEnabled";
        case RiskFactor::WPSEnabled: return "WPSEnabled";
        case RiskFactor::DNSHijacking: return "DNSHijacking";
        case RiskFactor::UnauthorizedService: return "UnauthorizedService";
        case RiskFactor::ScanningBehavior: return "ScanningBehavior";
        case RiskFactor::AnomalousTraffic: return "AnomalousTraffic";
        case RiskFactor::DebugInterface: return "DebugInterface";
        case RiskFactor::NoEncryption: return "NoEncryption";
        default: return "None";
    }
}

[[nodiscard]] std::string_view GetServiceProtocolName(ServiceProtocol proto) noexcept {
    switch (proto) {
        case ServiceProtocol::TCP: return "TCP";
        case ServiceProtocol::UDP: return "UDP";
        case ServiceProtocol::Both: return "Both";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetDiscoveryMethodName(DiscoveryMethod method) noexcept {
    switch (method) {
        case DiscoveryMethod::ARPScan: return "ARPScan";
        case DiscoveryMethod::PingSweep: return "PingSweep";
        case DiscoveryMethod::PortScan: return "PortScan";
        case DiscoveryMethod::MDNSDiscovery: return "MDNSDiscovery";
        case DiscoveryMethod::UPnPDiscovery: return "UPnPDiscovery";
        case DiscoveryMethod::DHCPLease: return "DHCPLease";
        case DiscoveryMethod::PassiveSniff: return "PassiveSniff";
        case DiscoveryMethod::ManualAdd: return "ManualAdd";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string LookupMACVendor(const std::string& mac) {
    if (mac.length() < 8) {
        return "Unknown";
    }

    std::string prefix = mac.substr(0, 8);
    std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);

    for (const auto& entry : MAC_VENDORS) {
        if (prefix == entry.prefix) {
            return entry.vendor;
        }
    }

    return "Unknown";
}

[[nodiscard]] DeviceCategory ClassifyDeviceByVendor(const std::string& vendor) {
    for (const auto& entry : MAC_VENDORS) {
        if (vendor.find(entry.vendor) != std::string::npos) {
            return entry.suggestedCategory;
        }
    }
    return DeviceCategory::Unknown;
}

}  // namespace ShadowStrike::IoT
