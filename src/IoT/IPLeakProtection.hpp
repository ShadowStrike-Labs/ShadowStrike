/**
 * ============================================================================
 * ShadowStrike NGAV - IP LEAK PROTECTION MODULE
 * ============================================================================
 *
 * @file IPLeakProtection.hpp
 * @brief Enterprise-grade IP leak detection and prevention engine for
 *        identifying VPN leaks, DNS leaks, WebRTC leaks, and proxy bypasses.
 *
 * Provides comprehensive IP leak protection including VPN tunnel monitoring,
 * DNS leak detection, WebRTC leak prevention, and IPv6 leak mitigation.
 * Also serves as an integration point for IoT security subsystems.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. VPN LEAK DETECTION
 *    - VPN tunnel monitoring
 *    - Kill switch functionality
 *    - DNS leak detection
 *    - IPv6 leak detection
 *    - Split tunneling detection
 *
 * 2. DNS LEAK DETECTION
 *    - DNS query monitoring
 *    - DNS server validation
 *    - ISP DNS detection
 *    - Transparent proxy detection
 *    - DNSCrypt verification
 *
 * 3. WEBRTC LEAK PREVENTION
 *    - WebRTC IP exposure detection
 *    - STUN/TURN server monitoring
 *    - Browser extension integration
 *    - ICE candidate filtering
 *
 * 4. IPV6 LEAK DETECTION
 *    - IPv6 tunnel monitoring
 *    - 6to4/Teredo detection
 *    - Dual-stack leak detection
 *    - IPv6 firewall rules
 *
 * 5. PROXY BYPASS DETECTION
 *    - Proxy configuration monitoring
 *    - Direct connection detection
 *    - SOCKS proxy validation
 *    - HTTP(S) proxy verification
 *
 * 6. IOT SUBSYSTEM INTEGRATION
 *    - IoT device scanner coordination
 *    - WiFi security analyzer integration
 *    - Router security checker coordination
 *    - Smart home protection integration
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for known leak servers
 * - NetworkUtils for monitoring
 * - Whitelist for trusted servers
 * - IoT modules coordination
 *
 * @note Requires administrative privileges for some features.
 * @note VPN kill switch requires firewall access.
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
#include <span>

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
#  include <WinSock2.h>
#  include <WS2tcpip.h>
#  include <iphlpapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::IoT {
    class IPLeakProtectionImpl;
}

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IPLeakConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief DNS leak check timeout (ms)
    inline constexpr uint32_t DNS_LEAK_CHECK_TIMEOUT_MS = 5000;

    /// @brief VPN check interval (ms)
    inline constexpr uint32_t VPN_CHECK_INTERVAL_MS = 10000;

    /// @brief WebRTC check interval (ms)
    inline constexpr uint32_t WEBRTC_CHECK_INTERVAL_MS = 30000;

    /// @brief Maximum tracked leaks
    inline constexpr size_t MAX_TRACKED_LEAKS = 1000;

    /// @brief DNS query timeout (ms)
    inline constexpr uint32_t DNS_QUERY_TIMEOUT_MS = 3000;

    /// @brief Known DNS leak test servers
    inline constexpr const char* DNS_LEAK_TEST_SERVERS[] = {
        "whoami.akamai.net",
        "resolver.dnscrypt.info",
        "o-o.myaddr.l.google.com"
    };

    /// @brief Common STUN servers (WebRTC leak detection)
    inline constexpr const char* STUN_SERVERS[] = {
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302"
    };

}  // namespace IPLeakConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief IP leak type
 */
enum class LeakType : uint32_t {
    None                    = 0,
    VPNLeak                 = 1 << 0,
    DNSLeak                 = 1 << 1,
    WebRTCLeak              = 1 << 2,
    IPv6Leak                = 1 << 3,
    ProxyBypass             = 1 << 4,
    SplitTunnelLeak         = 1 << 5,
    TimezoneLeak            = 1 << 6,
    GeoLocationLeak         = 1 << 7,
    TransparentProxy        = 1 << 8,
    TeredoLeak              = 1 << 9,
    STUNLeak                = 1 << 10,
    TURNLeak                = 1 << 11,
    LocalNetworkLeak        = 1 << 12,
    HostnameLeak            = 1 << 13,
    PortForwardLeak         = 1 << 14,
    HTTPProxyLeak           = 1 << 15
};

/**
 * @brief Leak severity
 */
enum class LeakSeverity : uint8_t {
    None            = 0,
    Informational   = 1,
    Low             = 2,
    Medium          = 3,
    High            = 4,
    Critical        = 5
};

/**
 * @brief VPN connection state
 */
enum class VPNState : uint8_t {
    Unknown         = 0,
    Disconnected    = 1,
    Connecting      = 2,
    Connected       = 3,
    Reconnecting    = 4,
    Disconnecting   = 5,
    Failed          = 6
};

/**
 * @brief Protection action
 */
enum class ProtectionAction : uint8_t {
    None            = 0,
    Alert           = 1,
    Block           = 2,
    KillSwitch      = 3,
    Reconnect       = 4,
    Disable         = 5
};

/**
 * @brief DNS server type
 */
enum class DNSServerType : uint8_t {
    Unknown         = 0,
    ISP             = 1,
    Public          = 2,
    Private         = 3,
    VPN             = 4,
    DNSCrypt        = 5,
    DoH             = 6,    // DNS over HTTPS
    DoT             = 7     // DNS over TLS
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Protected       = 4,
    Vulnerable      = 5,
    Error           = 6,
    Stopped         = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief IP address info
 */
struct IPAddressInfo {
    /// @brief IP address
    std::string ipAddress;

    /// @brief Is IPv6
    bool isIPv6 = false;

    /// @brief Is private
    bool isPrivate = false;

    /// @brief Country code
    std::string countryCode;

    /// @brief City
    std::string city;

    /// @brief ISP name
    std::string ispName;

    /// @brief ASN (Autonomous System Number)
    uint32_t asn = 0;

    /// @brief Organization
    std::string organization;

    /// @brief Is VPN address
    bool isVPN = false;

    /// @brief Is proxy
    bool isProxy = false;

    /// @brief Hostname
    std::string hostname;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DNS server info
 */
struct DNSServerInfo {
    /// @brief DNS server IP
    std::string serverIP;

    /// @brief Server type
    DNSServerType serverType = DNSServerType::Unknown;

    /// @brief ISP name
    std::string ispName;

    /// @brief Is ISP DNS
    bool isISPDNS = false;

    /// @brief Is VPN DNS
    bool isVPNDNS = false;

    /// @brief Response time (ms)
    uint32_t responseTimeMs = 0;

    /// @brief Country code
    std::string countryCode;

    /// @brief Supports DNSSEC
    bool supportsDNSSEC = false;

    /// @brief Supports DoH
    bool supportsDoH = false;

    /// @brief Supports DoT
    bool supportsDoT = false;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief VPN connection info
 */
struct VPNConnectionInfo {
    /// @brief VPN state
    VPNState state = VPNState::Unknown;

    /// @brief VPN provider
    std::string providerName;

    /// @brief VPN server location
    std::string serverLocation;

    /// @brief VPN protocol
    std::string protocol;

    /// @brief Tunnel interface
    std::string tunnelInterface;

    /// @brief VPN gateway IP
    std::string gatewayIP;

    /// @brief Assigned IP
    std::string assignedIP;

    /// @brief DNS servers
    std::vector<std::string> dnsServers;

    /// @brief Is kill switch active
    bool killSwitchActive = false;

    /// @brief Is IPv6 blocked
    bool ipv6Blocked = false;

    /// @brief Connection duration
    std::chrono::seconds connectionDuration{0};

    /// @brief Bytes sent
    uint64_t bytesSent = 0;

    /// @brief Bytes received
    uint64_t bytesReceived = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IP leak detection result
 */
struct IPLeakDetectionResult {
    /// @brief Leak detected
    bool leakDetected = false;

    /// @brief Leak type
    LeakType leakType = LeakType::None;

    /// @brief Leak severity
    LeakSeverity severity = LeakSeverity::None;

    /// @brief Leaked IP addresses
    std::vector<std::string> leakedIPs;

    /// @brief Expected IP
    std::string expectedIP;

    /// @brief Actual IP
    std::string actualIP;

    /// @brief DNS servers detected
    std::vector<DNSServerInfo> dnsServers;

    /// @brief WebRTC IPs exposed
    std::vector<std::string> webrtcIPs;

    /// @brief Detection method
    std::string detectionMethod;

    /// @brief Detection details
    std::string details;

    /// @brief Recommended action
    std::string recommendation;

    /// @brief Detection time
    SystemTimePoint detectionTime;

    /// @brief Confidence (0-100)
    int confidence = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief WebRTC leak info
 */
struct WebRTCLeakInfo {
    /// @brief Leak detected
    bool detected = false;

    /// @brief Local IPs exposed
    std::vector<std::string> localIPs;

    /// @brief Public IPs exposed
    std::vector<std::string> publicIPs;

    /// @brief IPv6 IPs exposed
    std::vector<std::string> ipv6IPs;

    /// @brief STUN servers contacted
    std::vector<std::string> stunServers;

    /// @brief ICE candidates
    std::vector<std::string> iceCandidates;

    /// @brief Browser info
    std::string browserInfo;

    /// @brief Detection time
    SystemTimePoint detectionTime;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Kill switch event
 */
struct KillSwitchEvent {
    /// @brief Event ID
    std::string eventId;

    /// @brief Event type
    std::string eventType;

    /// @brief Triggered by
    LeakType triggeredBy = LeakType::None;

    /// @brief Action taken
    ProtectionAction action = ProtectionAction::None;

    /// @brief Affected connections
    uint32_t affectedConnections = 0;

    /// @brief Event time
    SystemTimePoint eventTime;

    /// @brief Event description
    std::string description;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct IPLeakProtectionConfiguration {
    /// @brief Enable protection
    bool enabled = true;

    /// @brief Enable VPN monitoring
    bool enableVPNMonitoring = true;

    /// @brief Enable DNS leak detection
    bool enableDNSLeakDetection = true;

    /// @brief Enable WebRTC leak detection
    bool enableWebRTCDetection = true;

    /// @brief Enable IPv6 leak detection
    bool enableIPv6Detection = true;

    /// @brief Enable kill switch
    bool enableKillSwitch = false;

    /// @brief Block IPv6 when VPN active
    bool blockIPv6OnVPN = true;

    /// @brief Auto-reconnect on leak
    bool autoReconnectOnLeak = false;

    /// @brief Alert on leak detection
    bool alertOnLeak = true;

    /// @brief Monitoring interval (seconds)
    uint32_t monitoringIntervalSeconds = 30;

    /// @brief DNS check interval (seconds)
    uint32_t dnsCheckIntervalSeconds = 60;

    /// @brief WebRTC check interval (seconds)
    uint32_t webrtcCheckIntervalSeconds = 120;

    /// @brief VPN required
    bool vpnRequired = false;

    /// @brief Allowed DNS servers
    std::vector<std::string> allowedDNSServers;

    /// @brief Whitelisted IPs
    std::vector<std::string> whitelistedIPs;

    /// @brief Verbose logging
    bool verboseLogging = false;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct IPLeakStatistics {
    std::atomic<uint64_t> totalChecks{0};
    std::atomic<uint64_t> leaksDetected{0};
    std::atomic<uint64_t> vpnLeaks{0};
    std::atomic<uint64_t> dnsLeaks{0};
    std::atomic<uint64_t> webrtcLeaks{0};
    std::atomic<uint64_t> ipv6Leaks{0};
    std::atomic<uint64_t> killSwitchActivations{0};
    std::atomic<uint64_t> autoReconnects{0};
    std::atomic<uint32_t> currentVPNConnections{0};
    std::array<std::atomic<uint64_t>, 16> byLeakType{};
    std::array<std::atomic<uint64_t>, 6> bySeverity{};
    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IoT subsystem status
 */
struct IoTSubsystemStatus {
    /// @brief IoT device scanner active
    bool deviceScannerActive = false;

    /// @brief WiFi analyzer active
    bool wifiAnalyzerActive = false;

    /// @brief Router checker active
    bool routerCheckerActive = false;

    /// @brief Smart home protection active
    bool smartHomeActive = false;

    /// @brief Total devices found
    uint32_t totalDevicesFound = 0;

    /// @brief WiFi threats detected
    uint32_t wifiThreatsDetected = 0;

    /// @brief Router vulnerabilities
    uint32_t routerVulnerabilities = 0;

    /// @brief Smart home issues
    uint32_t smartHomeIssues = 0;

    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using LeakDetectedCallback = std::function<void(const IPLeakDetectionResult&)>;
using KillSwitchCallback = std::function<void(const KillSwitchEvent&)>;
using VPNStateChangeCallback = std::function<void(VPNState oldState, VPNState newState)>;
using DNSLeakCallback = std::function<void(const std::vector<DNSServerInfo>&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// IP LEAK PROTECTION CLASS
// ============================================================================

/**
 * @class IPLeakProtection
 * @brief Enterprise IP leak detection and prevention engine
 *
 * Also serves as an integration point for IoT security subsystems.
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

    [[nodiscard]] bool Initialize(const IPLeakProtectionConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;

    [[nodiscard]] bool UpdateConfiguration(const IPLeakProtectionConfiguration& config);
    [[nodiscard]] IPLeakProtectionConfiguration GetConfiguration() const;

    // ========================================================================
    // LEAK DETECTION
    // ========================================================================

    /// @brief Comprehensive leak check
    [[nodiscard]] IPLeakDetectionResult CheckForLeaks();

    /// @brief Check VPN leak
    [[nodiscard]] IPLeakDetectionResult CheckVPNLeak();

    /// @brief Check DNS leak
    [[nodiscard]] IPLeakDetectionResult CheckDNSLeak();

    /// @brief Check WebRTC leak
    [[nodiscard]] WebRTCLeakInfo CheckWebRTCLeak();

    /// @brief Check IPv6 leak
    [[nodiscard]] IPLeakDetectionResult CheckIPv6Leak();

    /// @brief Get public IP
    [[nodiscard]] IPAddressInfo GetPublicIP();

    /// @brief Get DNS servers
    [[nodiscard]] std::vector<DNSServerInfo> GetDNSServers();

    // ========================================================================
    // VPN MANAGEMENT
    // ========================================================================

    /// @brief Get VPN connection info
    [[nodiscard]] std::optional<VPNConnectionInfo> GetVPNInfo() const;

    /// @brief Is VPN connected
    [[nodiscard]] bool IsVPNConnected() const noexcept;

    /// @brief Get VPN state
    [[nodiscard]] VPNState GetVPNState() const noexcept;

    /// @brief Start VPN monitoring
    [[nodiscard]] bool StartVPNMonitoring();

    /// @brief Stop VPN monitoring
    void StopVPNMonitoring();

    // ========================================================================
    // KILL SWITCH
    // ========================================================================

    /// @brief Activate kill switch
    [[nodiscard]] bool ActivateKillSwitch();

    /// @brief Deactivate kill switch
    [[nodiscard]] bool DeactivateKillSwitch();

    /// @brief Is kill switch active
    [[nodiscard]] bool IsKillSwitchActive() const noexcept;

    /// @brief Get kill switch events
    [[nodiscard]] std::vector<KillSwitchEvent> GetKillSwitchEvents() const;

    // ========================================================================
    // PROTECTION ACTIONS
    // ========================================================================

    /// @brief Block IPv6
    [[nodiscard]] bool BlockIPv6();

    /// @brief Unblock IPv6
    [[nodiscard]] bool UnblockIPv6();

    /// @brief Force VPN reconnect
    [[nodiscard]] bool ForceVPNReconnect();

    /// @brief Apply protection policy
    [[nodiscard]] bool ApplyProtectionPolicy(LeakType leakType, ProtectionAction action);

    // ========================================================================
    // MONITORING
    // ========================================================================

    /// @brief Start continuous monitoring
    [[nodiscard]] bool StartMonitoring();

    /// @brief Stop monitoring
    void StopMonitoring();

    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoring() const noexcept;

    /// @brief Get detected leaks
    [[nodiscard]] std::vector<IPLeakDetectionResult> GetDetectedLeaks() const;

    // ========================================================================
    // IOT SUBSYSTEM INTEGRATION
    // ========================================================================

    /// @brief Get IoT subsystem status
    [[nodiscard]] IoTSubsystemStatus GetIoTStatus() const;

    /// @brief Start all IoT modules
    [[nodiscard]] bool StartIoTModules();

    /// @brief Stop all IoT modules
    void StopIoTModules();

    /// @brief Run IoT security scan
    [[nodiscard]] bool RunIoTSecurityScan();

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterLeakCallback(LeakDetectedCallback callback);
    void RegisterKillSwitchCallback(KillSwitchCallback callback);
    void RegisterVPNStateCallback(VPNStateChangeCallback callback);
    void RegisterDNSLeakCallback(DNSLeakCallback callback);
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

[[nodiscard]] std::string_view GetLeakTypeName(LeakType type) noexcept;
[[nodiscard]] std::string_view GetLeakSeverityName(LeakSeverity severity) noexcept;
[[nodiscard]] std::string_view GetVPNStateName(VPNState state) noexcept;
[[nodiscard]] std::string_view GetProtectionActionName(ProtectionAction action) noexcept;
[[nodiscard]] std::string_view GetDNSServerTypeName(DNSServerType type) noexcept;
[[nodiscard]] bool IsPrivateIP(const std::string& ip) noexcept;
[[nodiscard]] bool IsIPv6Address(const std::string& ip) noexcept;
[[nodiscard]] LeakSeverity CalculateLeakSeverity(LeakType type, bool vpnRequired) noexcept;

}  // namespace IoT
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CHECK_IP_LEAK() \
    ::ShadowStrike::IoT::IPLeakProtection::Instance().CheckForLeaks()

#define SS_ACTIVATE_KILL_SWITCH() \
    ::ShadowStrike::IoT::IPLeakProtection::Instance().ActivateKillSwitch()
