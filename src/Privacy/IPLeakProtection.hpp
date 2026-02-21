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
 * ShadowStrike NGAV - IP LEAK PROTECTION MODULE
 * ============================================================================
 *
 * @file IPLeakProtection.hpp
 * @brief Enterprise-grade IP leak protection with WebRTC blocking,
 *        kill switch, and multi-layer leak prevention.
 *
 * Provides comprehensive IP privacy protection including VPN/proxy leak
 * detection, WebRTC blocking, and network kill switch capabilities.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. WEBRTC LEAK PREVENTION
 *    - STUN/TURN server blocking
 *    - Browser WebRTC disable
 *    - mDNS ICE candidate prevention
 *    - Per-browser configuration
 *    - Extension-based blocking
 *
 * 2. VPN KILL SWITCH
 *    - Network traffic blocking
 *    - Adapter monitoring
 *    - Route table protection
 *    - Application-level block
 *    - Instant disconnect protection
 *
 * 3. IPv6 LEAK PROTECTION
 *    - IPv6 disable/enable
 *    - Teredo tunnel blocking
 *    - 6to4 tunnel blocking
 *    - ISATAP tunnel blocking
 *    - Dual-stack leak prevention
 *
 * 4. PROXY LEAK PROTECTION
 *    - HTTP proxy enforcement
 *    - SOCKS proxy enforcement
 *    - Transparent proxy detection
 *    - Proxy bypass prevention
 *    - Per-application proxy
 *
 * 5. LEAK DETECTION
 *    - Real IP exposure detection
 *    - VPN bypass detection
 *    - Split tunnel leaks
 *    - API-based checks
 *    - Packet capture analysis
 *
 * LEAK VECTORS PROTECTED:
 * =======================
 * - WebRTC ICE candidates
 * - HTTP headers (X-Forwarded-For)
 * - IPv6 leak (dual-stack)
 * - DNS leak (handled by DNSLeakProtection)
 * - Teredo/6to4/ISATAP tunnels
 * - VPN connection drops
 * - Browser fingerprinting
 *
 * @note Requires WFP (Windows Filtering Platform) for kill switch.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class IPLeakProtectionImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IPLeakConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief VPN status check interval (ms)
    inline constexpr uint32_t VPN_CHECK_INTERVAL_MS = 1000;
    
    /// @brief Kill switch activation delay (ms)
    inline constexpr uint32_t KILL_SWITCH_DELAY_MS = 100;
    
    /// @brief WebRTC STUN port
    inline constexpr uint16_t STUN_PORT = 3478;
    
    /// @brief WebRTC TURN port
    inline constexpr uint16_t TURN_PORT = 5349;

    /// @brief Known STUN servers to block
    inline constexpr const char* STUN_SERVERS[] = {
        "stun.l.google.com",
        "stun1.l.google.com",
        "stun2.l.google.com",
        "stun3.l.google.com",
        "stun4.l.google.com",
        "stun.services.mozilla.com",
        "stun.stunprotocol.org"
    };

}  // namespace IPLeakConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief IP leak type
 */
enum class IPLeakType : uint8_t {
    None            = 0,
    WebRTC          = 1,    ///< WebRTC STUN/TURN leak
    IPv6            = 2,    ///< IPv6 leak through VPN
    DNS             = 3,    ///< DNS leak (ref to DNS module)
    HTTPHeader      = 4,    ///< X-Forwarded-For header
    VPNDrop         = 5,    ///< VPN connection dropped
    SplitTunnel     = 6,    ///< Split tunnel leak
    Teredo          = 7,    ///< Teredo tunnel leak
    ISATAP          = 8,    ///< ISATAP tunnel leak
    ProxyBypass     = 9     ///< Proxy bypass leak
};

/**
 * @brief Kill switch mode
 */
enum class KillSwitchMode : uint8_t {
    Disabled        = 0,    ///< No kill switch
    Enabled         = 1,    ///< Block all non-VPN traffic
    AppLevel        = 2,    ///< Block only specific apps
    SystemLevel     = 3     ///< Block at system level (WFP)
};

/**
 * @brief VPN status
 */
enum class VPNStatus : uint8_t {
    Unknown         = 0,
    Connected       = 1,
    Connecting      = 2,
    Disconnected    = 3,
    Reconnecting    = 4,
    Error           = 5
};

/**
 * @brief Network adapter type
 */
enum class AdapterType : uint8_t {
    Unknown         = 0,
    Physical        = 1,    ///< Physical NIC
    Virtual         = 2,    ///< Virtual adapter (VPN)
    Loopback        = 3,    ///< Loopback
    WiFi            = 4,    ///< Wireless
    Ethernet        = 5,    ///< Wired Ethernet
    Cellular        = 6,    ///< Mobile data
    VPN             = 7     ///< VPN tunnel adapter
};

/**
 * @brief IPv6 protection mode
 */
enum class IPv6ProtectionMode : uint8_t {
    Disabled        = 0,    ///< IPv6 allowed
    DisableAll      = 1,    ///< Disable all IPv6
    TunnelsOnly     = 2,    ///< Block only tunnels
    VPNOnly         = 3     ///< Block when VPN active
};

/**
 * @brief WebRTC block method
 */
enum class WebRTCBlockMethod : uint8_t {
    Disabled        = 0,
    BrowserPolicy   = 1,    ///< Set browser policies
    NetworkBlock    = 2,    ///< Block STUN/TURN traffic
    ExtensionBased  = 3,    ///< Use browser extension
    Combined        = 4     ///< All methods
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    KillSwitchActive= 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief IP address info
 */
struct IPAddressInfo {
    /// @brief IP address
    std::string address;
    
    /// @brief Is IPv6
    bool isIPv6 = false;
    
    /// @brief Is private/local
    bool isPrivate = false;
    
    /// @brief Is VPN address
    bool isVPN = false;
    
    /// @brief Adapter name
    std::string adapterName;
    
    /// @brief Country (from GeoIP)
    std::string country;
    
    /// @brief ISP
    std::string isp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network adapter info
 */
struct NetworkAdapterInfo {
    /// @brief Adapter GUID
    std::string guid;
    
    /// @brief Adapter name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Type
    AdapterType type = AdapterType::Unknown;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief IPv4 addresses
    std::vector<std::string> ipv4Addresses;
    
    /// @brief IPv6 addresses
    std::vector<std::string> ipv6Addresses;
    
    /// @brief Gateway
    std::string gateway;
    
    /// @brief DNS servers
    std::vector<std::string> dnsServers;
    
    /// @brief Is connected
    bool isConnected = false;
    
    /// @brief Is VPN adapter
    bool isVPN = false;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief VPN connection info
 */
struct VPNConnectionInfo {
    /// @brief Connection name
    std::string connectionName;
    
    /// @brief VPN protocol
    std::string protocol;  // OpenVPN, WireGuard, IKEv2, etc.
    
    /// @brief Server address
    std::string serverAddress;
    
    /// @brief Server port
    uint16_t serverPort = 0;
    
    /// @brief Status
    VPNStatus status = VPNStatus::Unknown;
    
    /// @brief Assigned IP
    std::string assignedIP;
    
    /// @brief Connection start time
    SystemTimePoint connectedSince;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Adapter GUID
    std::string adapterGuid;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IP leak event
 */
struct IPLeakEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Leak type
    IPLeakType leakType = IPLeakType::None;
    
    /// @brief Leaked IP
    IPAddressInfo leakedIP;
    
    /// @brief Expected IP (VPN)
    std::string expectedIP;
    
    /// @brief Detection method
    std::string detectionMethod;
    
    /// @brief Process ID (if applicable)
    uint32_t processId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Destination
    std::string destination;
    
    /// @brief Severity (1-10)
    int severity = 5;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Kill switch event
 */
struct KillSwitchEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Trigger reason
    std::string reason;
    
    /// @brief VPN status before
    VPNStatus vpnStatusBefore = VPNStatus::Connected;
    
    /// @brief VPN status after
    VPNStatus vpnStatusAfter = VPNStatus::Disconnected;
    
    /// @brief Blocked connections count
    uint32_t blockedConnections = 0;
    
    /// @brief Activation time
    SystemTimePoint activationTime;
    
    /// @brief Deactivation time (if reactivated)
    std::optional<SystemTimePoint> deactivationTime;
    
    /// @brief Duration active
    std::chrono::seconds duration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct IPLeakStatistics {
    std::atomic<uint64_t> leaksDetected{0};
    std::atomic<uint64_t> leaksBlocked{0};
    std::atomic<uint64_t> webRTCBlocked{0};
    std::atomic<uint64_t> ipv6Blocked{0};
    std::atomic<uint64_t> killSwitchActivations{0};
    std::atomic<uint64_t> killSwitchDuration{0};  // seconds
    std::atomic<uint64_t> vpnDisconnections{0};
    std::atomic<uint64_t> proxyBypassBlocked{0};
    std::atomic<uint64_t> connectionsBlocked{0};
    std::array<std::atomic<uint64_t>, 16> byLeakType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct IPLeakConfiguration {
    /// @brief Enable IP leak protection
    bool enabled = true;
    
    /// @brief Kill switch mode
    KillSwitchMode killSwitchMode = KillSwitchMode::Enabled;
    
    /// @brief WebRTC block method
    WebRTCBlockMethod webRTCBlockMethod = WebRTCBlockMethod::Combined;
    
    /// @brief IPv6 protection mode
    IPv6ProtectionMode ipv6Protection = IPv6ProtectionMode::VPNOnly;
    
    /// @brief Block Teredo
    bool blockTeredo = true;
    
    /// @brief Block ISATAP
    bool blockISATAP = true;
    
    /// @brief Block 6to4
    bool block6to4 = true;
    
    /// @brief Require VPN for internet
    bool requireVPN = false;
    
    /// @brief Allowed adapters (when kill switch active)
    std::vector<std::string> allowedAdapters;
    
    /// @brief Allowed processes (when kill switch active)
    std::vector<std::string> allowedProcesses;
    
    /// @brief Allowed local networks
    std::vector<std::string> allowedLocalNetworks;
    
    /// @brief VPN adapter patterns
    std::vector<std::string> vpnAdapterPatterns;
    
    /// @brief Notification on leak
    bool notifyOnLeak = true;
    
    /// @brief Notification on kill switch
    bool notifyOnKillSwitch = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using LeakDetectedCallback = std::function<void(const IPLeakEvent&)>;
using KillSwitchCallback = std::function<void(const KillSwitchEvent&)>;
using VPNStatusCallback = std::function<void(VPNStatus newStatus)>;
using AdapterCallback = std::function<void(const NetworkAdapterInfo&, bool added)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// IP LEAK PROTECTION CLASS
// ============================================================================

/**
 * @class IPLeakProtection
 * @brief Enterprise IP leak protection
 */
class IPLeakProtection final {
public:
    [[nodiscard]] static IPLeakProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    IPLeakProtection(const IPLeakProtection&) = delete;
    IPLeakProtection& operator=(const IPLeakProtection&) = delete;
    IPLeakProtection(IPLeakProtection&&) = delete;
    IPLeakProtection& operator=(IPLeakProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const IPLeakConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const IPLeakConfiguration& config);
    [[nodiscard]] IPLeakConfiguration GetConfiguration() const;

    // ========================================================================
    // KILL SWITCH
    // ========================================================================
    
    /// @brief Activate kill switch
    [[nodiscard]] bool RunKillSwitch();
    
    /// @brief Deactivate kill switch
    [[nodiscard]] bool StopKillSwitch();
    
    /// @brief Is kill switch active
    [[nodiscard]] bool IsKillSwitchActive() const noexcept;
    
    /// @brief Set kill switch mode
    void SetKillSwitchMode(KillSwitchMode mode);
    
    /// @brief Get kill switch mode
    [[nodiscard]] KillSwitchMode GetKillSwitchMode() const noexcept;

    // ========================================================================
    // WEBRTC PROTECTION
    // ========================================================================
    
    /// @brief Block WebRTC leaks
    [[nodiscard]] bool BlockWebRtcLeaks();
    
    /// @brief Unblock WebRTC
    [[nodiscard]] bool UnblockWebRtc();
    
    /// @brief Is WebRTC blocked
    [[nodiscard]] bool IsWebRtcBlocked() const noexcept;
    
    /// @brief Set WebRTC block method
    void SetWebRTCBlockMethod(WebRTCBlockMethod method);

    // ========================================================================
    // IPv6 PROTECTION
    // ========================================================================
    
    /// @brief Set IPv6 protection mode
    void SetIPv6ProtectionMode(IPv6ProtectionMode mode);
    
    /// @brief Get IPv6 protection mode
    [[nodiscard]] IPv6ProtectionMode GetIPv6ProtectionMode() const noexcept;
    
    /// @brief Disable IPv6 globally
    [[nodiscard]] bool DisableIPv6();
    
    /// @brief Enable IPv6
    [[nodiscard]] bool EnableIPv6();
    
    /// @brief Is IPv6 disabled
    [[nodiscard]] bool IsIPv6Disabled() const noexcept;
    
    /// @brief Block IPv6 tunnels (Teredo, ISATAP, 6to4)
    [[nodiscard]] bool BlockIPv6Tunnels();

    // ========================================================================
    // VPN MONITORING
    // ========================================================================
    
    /// @brief Start VPN monitoring
    [[nodiscard]] bool StartVPNMonitoring();
    
    /// @brief Stop VPN monitoring
    void StopVPNMonitoring();
    
    /// @brief Get VPN status
    [[nodiscard]] VPNStatus GetVPNStatus() const noexcept;
    
    /// @brief Get VPN connection info
    [[nodiscard]] std::optional<VPNConnectionInfo> GetVPNConnection();
    
    /// @brief Detect VPN adapters
    [[nodiscard]] std::vector<NetworkAdapterInfo> DetectVPNAdapters();

    // ========================================================================
    // IP DETECTION
    // ========================================================================
    
    /// @brief Get current public IP
    [[nodiscard]] std::optional<IPAddressInfo> GetPublicIP();
    
    /// @brief Get all IP addresses
    [[nodiscard]] std::vector<IPAddressInfo> GetAllIPAddresses();
    
    /// @brief Check for IP leaks
    [[nodiscard]] std::vector<IPLeakEvent> CheckForLeaks();
    
    /// @brief Get network adapters
    [[nodiscard]] std::vector<NetworkAdapterInfo> GetNetworkAdapters();

    // ========================================================================
    // LEAK HISTORY
    // ========================================================================
    
    /// @brief Get recent leak events
    [[nodiscard]] std::vector<IPLeakEvent> GetRecentLeaks(size_t limit = 100);
    
    /// @brief Get kill switch events
    [[nodiscard]] std::vector<KillSwitchEvent> GetKillSwitchEvents(size_t limit = 100);
    
    /// @brief Clear history
    void ClearHistory();

    // ========================================================================
    // EXCEPTIONS
    // ========================================================================
    
    /// @brief Add allowed adapter (kill switch exception)
    [[nodiscard]] bool AddAllowedAdapter(const std::string& adapterGuid);
    
    /// @brief Remove allowed adapter
    [[nodiscard]] bool RemoveAllowedAdapter(const std::string& adapterGuid);
    
    /// @brief Add allowed process
    [[nodiscard]] bool AddAllowedProcess(const std::string& processName);
    
    /// @brief Remove allowed process
    [[nodiscard]] bool RemoveAllowedProcess(const std::string& processName);
    
    /// @brief Add allowed local network
    [[nodiscard]] bool AddAllowedLocalNetwork(const std::string& cidr);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterLeakCallback(LeakDetectedCallback callback);
    void RegisterKillSwitchCallback(KillSwitchCallback callback);
    void RegisterVPNStatusCallback(VPNStatusCallback callback);
    void RegisterAdapterCallback(AdapterCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] IPLeakStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    IPLeakProtection();
    ~IPLeakProtection();
    
    std::unique_ptr<IPLeakProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetIPLeakTypeName(IPLeakType type) noexcept;
[[nodiscard]] std::string_view GetKillSwitchModeName(KillSwitchMode mode) noexcept;
[[nodiscard]] std::string_view GetVPNStatusName(VPNStatus status) noexcept;
[[nodiscard]] std::string_view GetAdapterTypeName(AdapterType type) noexcept;
[[nodiscard]] std::string_view GetIPv6ProtectionModeName(IPv6ProtectionMode mode) noexcept;
[[nodiscard]] std::string_view GetWebRTCBlockMethodName(WebRTCBlockMethod method) noexcept;

/// @brief Check if IP is private
[[nodiscard]] bool IsPrivateIP(const std::string& ip);

/// @brief Check if IP is IPv6
[[nodiscard]] bool IsIPv6Address(const std::string& ip);

/// @brief Get adapter type from description
[[nodiscard]] AdapterType DetectAdapterType(const std::string& description);

/// @brief Is VPN adapter based on name/description
[[nodiscard]] bool IsVPNAdapter(const std::string& name, const std::string& description);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IP_KILLSWITCH_START() \
    ::ShadowStrike::Privacy::IPLeakProtection::Instance().RunKillSwitch()

#define SS_IP_KILLSWITCH_STOP() \
    ::ShadowStrike::Privacy::IPLeakProtection::Instance().StopKillSwitch()

#define SS_IP_BLOCK_WEBRTC() \
    ::ShadowStrike::Privacy::IPLeakProtection::Instance().BlockWebRtcLeaks()

#define SS_IP_CHECK_LEAKS() \
    ::ShadowStrike::Privacy::IPLeakProtection::Instance().CheckForLeaks()

#define SS_IP_GET_VPN_STATUS() \
    ::ShadowStrike::Privacy::IPLeakProtection::Instance().GetVPNStatus()
