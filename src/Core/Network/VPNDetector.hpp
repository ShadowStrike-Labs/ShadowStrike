/**
 * ============================================================================
 * ShadowStrike Core Network - VPN DETECTOR (The IP Mask)
 * ============================================================================
 *
 * @file VPNDetector.hpp
 * @brief Enterprise-grade VPN and proxy detection engine.
 *
 * This module provides comprehensive detection of Virtual Private Networks,
 * proxy servers, and anonymization services through multiple detection methods
 * including adapter analysis, traffic fingerprinting, and behavioral patterns.
 *
 * Key Capabilities:
 * =================
 * 1. ADAPTER DETECTION
 *    - TAP/TUN adapter identification
 *    - WireGuard interface detection
 *    - Virtual adapter enumeration
 *    - OpenVPN adapter detection
 *    - IPSec virtual adapters
 *
 * 2. ROUTING ANALYSIS
 *    - Default gateway inspection
 *    - Route table analysis
 *    - Split tunneling detection
 *    - Kill switch detection
 *
 * 3. TRAFFIC FINGERPRINTING
 *    - OpenVPN protocol detection
 *    - WireGuard protocol detection
 *    - IPSec/IKEv2 detection
 *    - L2TP/PPTP detection
 *    - SSTP detection
 *
 * 4. PROVIDER IDENTIFICATION
 *    - Commercial VPN detection (NordVPN, ExpressVPN, etc.)
 *    - Corporate VPN detection
 *    - IP range analysis
 *    - ASN-based detection
 *
 * 5. PROXY DETECTION
 *    - HTTP/HTTPS proxy
 *    - SOCKS4/SOCKS5 proxy
 *    - Transparent proxy
 *    - Web proxy (CGI proxy)
 *
 * Detection Architecture:
 * =======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         VPNDetector                                 │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │AdapterAnalyz │  │RoutingAnalyz │  │    TrafficFingerprint    │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - TAP/TUN    │  │ - Gateway    │  │ - OpenVPN FP             │  │
 *   │  │ - WireGuard  │  │ - Routes     │  │ - WireGuard FP           │  │
 *   │  │ - IPSec      │  │ - Split Tun  │  │ - IPSec FP               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ProviderIdent │  │ ProxyDetect  │  │    LeakChecker           │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Commercial │  │ - HTTP Proxy │  │ - DNS Leak               │  │
 *   │  │ - Corporate  │  │ - SOCKS      │  │ - IPv6 Leak              │  │
 *   │  │ - ASN Match  │  │ - Transparent│  │ - WebRTC Leak            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * VPN Protocols Detected:
 * =======================
 * - OpenVPN (UDP/TCP)
 * - WireGuard
 * - IPSec/IKEv2
 * - L2TP/IPSec
 * - PPTP
 * - SSTP
 * - SoftEther
 * - Cisco AnyConnect
 * - GlobalProtect
 * - Pulse Secure
 *
 * Commercial VPN Providers:
 * =========================
 * - NordVPN, ExpressVPN, Surfshark
 * - PIA, Mullvad, ProtonVPN
 * - CyberGhost, IPVanish
 * - Corporate: Cisco, Palo Alto, Fortinet
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1090.003: Proxy: Multi-hop Proxy
 * - T1573: Encrypted Channel
 * - T1572: Protocol Tunneling
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Adapter enumeration is serialized
 * - Concurrent traffic analysis supported
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see TorDetector.hpp for Tor detection
 * @see NetworkMonitor.hpp for traffic monitoring
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/SystemUtils.hpp"        // Adapter enumeration
#include "../../Utils/ProcessUtils.hpp"       // Process identification
#include "../../Utils/RegistryUtils.hpp"      // VPN registry entries
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // VPN IP ranges
#include "../../PatternStore/PatternStore.hpp" // Protocol fingerprints
#include "../../Whitelist/WhiteListStore.hpp" // Allowed VPN providers

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class VPNDetectorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace VPNDetectorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Protocol ports
    constexpr uint16_t OPENVPN_UDP_PORT = 1194;
    constexpr uint16_t OPENVPN_TCP_PORT = 443;
    constexpr uint16_t WIREGUARD_PORT = 51820;
    constexpr uint16_t IPSEC_IKE_PORT = 500;
    constexpr uint16_t IPSEC_NAT_PORT = 4500;
    constexpr uint16_t L2TP_PORT = 1701;
    constexpr uint16_t PPTP_PORT = 1723;
    constexpr uint16_t SSTP_PORT = 443;

    // Detection
    constexpr double CONFIDENCE_THRESHOLD = 0.70;
    constexpr uint32_t MIN_PACKETS_FOR_FINGERPRINT = 5;
    constexpr size_t MAX_TRACKED_CONNECTIONS = 10000;

    // Provider detection
    constexpr size_t MAX_PROVIDER_SIGNATURES = 500;
    constexpr size_t MAX_IP_RANGES = 10000;

    // Adapter names
    constexpr size_t MAX_ADAPTER_NAME_LENGTH = 256;

}  // namespace VPNDetectorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum VPNProtocol
 * @brief VPN protocol types.
 */
enum class VPNProtocol : uint8_t {
    UNKNOWN = 0,
    OPENVPN_UDP = 1,
    OPENVPN_TCP = 2,
    WIREGUARD = 3,
    IPSEC_IKEV1 = 4,
    IPSEC_IKEV2 = 5,
    L2TP_IPSEC = 6,
    PPTP = 7,
    SSTP = 8,
    SOFTETHER = 9,
    CISCO_ANYCONNECT = 10,
    GLOBALPROTECT = 11,
    PULSE_SECURE = 12,
    FORTINET = 13,
    CUSTOM = 255
};

/**
 * @enum VPNProvider
 * @brief Known VPN providers.
 */
enum class VPNProvider : uint16_t {
    UNKNOWN = 0,

    // Consumer VPNs
    NORDVPN = 100,
    EXPRESSVPN = 101,
    SURFSHARK = 102,
    PRIVATE_INTERNET_ACCESS = 103,
    MULLVAD = 104,
    PROTONVPN = 105,
    CYBERGHOST = 106,
    IPVANISH = 107,
    WINDSCRIBE = 108,
    HIDE_MY_ASS = 109,
    TUNNELBEAR = 110,
    HOTSPOT_SHIELD = 111,

    // Corporate VPNs
    CISCO_ANYCONNECT_PROVIDER = 200,
    PALO_ALTO = 201,
    FORTINET_PROVIDER = 202,
    PULSE_SECURE_PROVIDER = 203,
    F5_BIG_IP = 204,
    CHECK_POINT = 205,
    CITRIX_NETSCALER = 206,
    ZSCALER = 207,
    MICROSOFT_ALWAYS_ON = 208,

    // Self-hosted
    OPENVPN_SELF = 300,
    WIREGUARD_SELF = 301,
    SOFTETHER_SELF = 302,

    CUSTOM_PROVIDER = 999
};

/**
 * @enum AdapterType
 * @brief Virtual adapter types.
 */
enum class AdapterType : uint8_t {
    UNKNOWN = 0,
    TAP = 1,
    TUN = 2,
    WIREGUARD = 3,
    IPSEC = 4,
    PPTP = 5,
    L2TP = 6,
    SSTP = 7,
    LOOPBACK = 8,
    PHYSICAL = 9
};

/**
 * @enum ProxyType
 * @brief Proxy types.
 */
enum class ProxyType : uint8_t {
    NONE = 0,
    HTTP = 1,
    HTTPS = 2,
    SOCKS4 = 3,
    SOCKS5 = 4,
    TRANSPARENT = 5,
    CGI_WEB = 6,
    REVERSE = 7
};

/**
 * @enum DetectionMethod
 * @brief How VPN was detected.
 */
enum class VPNDetectionMethod : uint8_t {
    NONE = 0,
    ADAPTER_NAME = 1,
    ADAPTER_TYPE = 2,
    ROUTING_TABLE = 3,
    TRAFFIC_FINGERPRINT = 4,
    IP_RANGE = 5,
    ASN_LOOKUP = 6,
    PROCESS_DETECTION = 7,
    DNS_RESOLUTION = 8,
    COMBINED = 9
};

/**
 * @enum VPNPolicy
 * @brief Policy for VPN traffic.
 */
enum class VPNPolicy : uint8_t {
    ALLOW = 0,
    MONITOR = 1,
    BLOCK_CONSUMER = 2,         // Block consumer VPNs
    BLOCK_ALL = 3,
    ALERT_ONLY = 4
};

/**
 * @enum LeakType
 * @brief Type of VPN leak.
 */
enum class LeakType : uint8_t {
    NONE = 0,
    DNS_LEAK = 1,
    IPV6_LEAK = 2,
    WEBRTC_LEAK = 3,
    ROUTING_LEAK = 4,
    TORRENT_LEAK = 5
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct VPNInfo
 * @brief Basic VPN information (legacy compatible).
 */
struct VPNInfo {
    bool isActive{ false };
    std::wstring providerName;
    std::string virtualIp;
};

/**
 * @struct NetworkAdapter
 * @brief Network adapter information.
 */
struct alignas(128) NetworkAdapter {
    // Identity
    std::wstring name;
    std::wstring description;
    std::wstring friendlyName;
    std::array<uint8_t, 6> macAddress{ 0 };
    uint32_t index{ 0 };

    // Type
    AdapterType type{ AdapterType::UNKNOWN };
    bool isVirtual{ false };
    bool isVPN{ false };

    // Addresses
    std::vector<std::string> ipv4Addresses;
    std::vector<std::string> ipv6Addresses;
    std::string gateway;
    std::string subnetMask;

    // DNS
    std::vector<std::string> dnsServers;
    std::string dnsSuffix;

    // Status
    bool isEnabled{ false };
    bool isConnected{ false };
    uint64_t speed{ 0 };                   // bits/sec

    // Metrics
    uint32_t metric{ 0 };
    bool isDefaultGateway{ false };

    // VPN specifics
    VPNProtocol vpnProtocol{ VPNProtocol::UNKNOWN };
    VPNProvider vpnProvider{ VPNProvider::UNKNOWN };
    std::string remoteEndpoint;
};

/**
 * @struct VPNConnection
 * @brief Detected VPN connection details.
 */
struct alignas(256) VPNConnection {
    // Identity
    uint64_t connectionId{ 0 };

    // Adapter
    std::wstring adapterName;
    uint32_t adapterIndex{ 0 };
    AdapterType adapterType{ AdapterType::UNKNOWN };

    // Protocol
    VPNProtocol protocol{ VPNProtocol::UNKNOWN };
    std::string protocolVersion;

    // Provider
    VPNProvider provider{ VPNProvider::UNKNOWN };
    std::wstring providerName;
    std::string providerCountry;

    // Network
    std::string localIP;
    std::string virtualIP;
    std::string remoteServerIP;
    uint16_t remotePort{ 0 };

    // Gateway
    std::string originalGateway;
    std::string vpnGateway;
    bool isFullTunnel{ false };
    bool isSplitTunnel{ false };

    // Encryption
    std::string cipher;
    std::string authMethod;
    uint32_t keySize{ 0 };

    // Process
    uint32_t processId{ 0 };
    std::wstring processPath;
    std::string processName;

    // Detection
    VPNDetectionMethod detectionMethod{ VPNDetectionMethod::NONE };
    double confidence{ 0.0 };
    std::vector<VPNDetectionMethod> allMethods;

    // Traffic
    uint64_t bytesSent{ 0 };
    uint64_t bytesReceived{ 0 };

    // Timing
    std::chrono::system_clock::time_point connectedAt;
    std::chrono::system_clock::time_point detectedAt;
    std::chrono::milliseconds uptime{ 0 };

    // Leaks
    std::vector<LeakType> detectedLeaks;
    bool hasDNSLeak{ false };
    bool hasIPv6Leak{ false };
};

/**
 * @struct ProxyInfo
 * @brief Detected proxy information.
 */
struct alignas(64) ProxyInfo {
    bool isActive{ false };
    ProxyType type{ ProxyType::NONE };

    std::string proxyHost;
    uint16_t proxyPort{ 0 };
    std::string username;

    // System proxy
    bool isSystemProxy{ false };
    bool isPACConfigured{ false };
    std::string pacUrl;

    // Bypass
    std::vector<std::string> bypassList;

    // Detection
    double confidence{ 0.0 };
};

/**
 * @struct TrafficFingerprint
 * @brief VPN traffic fingerprint.
 */
struct alignas(64) TrafficFingerprint {
    VPNProtocol protocol{ VPNProtocol::UNKNOWN };
    double confidence{ 0.0 };

    // Packet analysis
    uint32_t packetsAnalyzed{ 0 };
    double avgPacketSize{ 0.0 };
    double packetSizeVariance{ 0.0 };

    // Timing
    double avgInterPacketMs{ 0.0 };

    // Protocol-specific
    bool hasHandshake{ false };
    std::string handshakeType;
    uint16_t detectedPort{ 0 };

    // Matches
    std::vector<std::string> matchedPatterns;
};

/**
 * @struct IPRangeInfo
 * @brief IP range information for VPN provider.
 */
struct alignas(64) IPRangeInfo {
    std::string cidr;
    std::string startIP;
    std::string endIP;

    VPNProvider provider{ VPNProvider::UNKNOWN };
    std::string providerName;

    std::string asn;
    std::string asName;
    std::string country;

    bool isKnownVPN{ false };
    bool isDatacenter{ false };
    bool isHostingProvider{ false };
};

/**
 * @struct VPNAlert
 * @brief Alert for VPN detection.
 */
struct alignas(256) VPNAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Detection
    VPNDetectionMethod method{ VPNDetectionMethod::NONE };
    double confidence{ 0.0 };

    // VPN info
    VPNProtocol protocol{ VPNProtocol::UNKNOWN };
    VPNProvider provider{ VPNProvider::UNKNOWN };
    std::wstring providerName;

    // Network
    std::string virtualIP;
    std::string remoteServer;

    // Process
    uint32_t processId{ 0 };
    std::wstring processPath;
    std::string processName;
    std::string username;

    // Description
    std::string description;
    std::vector<std::string> indicators;

    // Policy
    VPNPolicy appliedPolicy{ VPNPolicy::MONITOR };
    bool wasBlocked{ false };

    // Leaks detected
    std::vector<LeakType> leaks;

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct VPNDetectorConfig
 * @brief Configuration for VPN detector.
 */
struct alignas(64) VPNDetectorConfig {
    // Main settings
    bool enabled{ true };
    VPNPolicy policy{ VPNPolicy::MONITOR };

    // Detection methods
    bool enableAdapterDetection{ true };
    bool enableRoutingAnalysis{ true };
    bool enableTrafficFingerprinting{ true };
    bool enableIPRangeLookup{ true };
    bool enableASNLookup{ true };
    bool enableProcessDetection{ true };

    // Proxy detection
    bool enableProxyDetection{ true };
    bool detectSystemProxy{ true };

    // Leak detection
    bool enableLeakDetection{ true };
    bool checkDNSLeak{ true };
    bool checkIPv6Leak{ true };

    // Provider detection
    bool identifyProvider{ true };
    std::wstring providerDatabasePath;

    // Blocking
    bool blockConsumerVPNs{ false };
    bool blockAllVPNs{ false };
    bool allowCorporateVPNs{ true };

    // Exceptions
    std::vector<std::wstring> allowedAdapters;
    std::vector<std::string> allowedProviders;
    std::vector<uint32_t> allowedProcessIds;
    std::vector<std::string> allowedIPRanges;

    // Alerts
    bool alertOnDetection{ true };
    bool alertOnLeak{ true };

    // Logging
    bool logAllConnections{ false };
    bool logDetectionsOnly{ true };

    // Factory methods
    static VPNDetectorConfig CreateDefault() noexcept;
    static VPNDetectorConfig CreateHighSecurity() noexcept;
    static VPNDetectorConfig CreateCorporate() noexcept;
    static VPNDetectorConfig CreateMonitorOnly() noexcept;
};

/**
 * @struct VPNDetectorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) VPNDetectorStatistics {
    // Detection statistics
    std::atomic<uint64_t> totalScans{ 0 };
    std::atomic<uint64_t> vpnConnectionsDetected{ 0 };
    std::atomic<uint64_t> proxyConnectionsDetected{ 0 };

    // Protocol statistics
    std::atomic<uint64_t> openvpnDetected{ 0 };
    std::atomic<uint64_t> wireguardDetected{ 0 };
    std::atomic<uint64_t> ipsecDetected{ 0 };
    std::atomic<uint64_t> otherProtocolsDetected{ 0 };

    // Provider statistics
    std::atomic<uint64_t> consumerVPNsDetected{ 0 };
    std::atomic<uint64_t> corporateVPNsDetected{ 0 };
    std::atomic<uint64_t> unknownProviders{ 0 };

    // Leak statistics
    std::atomic<uint64_t> dnsLeaksDetected{ 0 };
    std::atomic<uint64_t> ipv6LeaksDetected{ 0 };
    std::atomic<uint64_t> webrtcLeaksDetected{ 0 };

    // Detection method statistics
    std::atomic<uint64_t> adapterDetections{ 0 };
    std::atomic<uint64_t> routingDetections{ 0 };
    std::atomic<uint64_t> trafficDetections{ 0 };
    std::atomic<uint64_t> ipRangeDetections{ 0 };

    // Policy statistics
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Current state
    std::atomic<uint32_t> activeVPNConnections{ 0 };
    std::atomic<uint32_t> virtualAdapters{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for VPN detection.
 */
using VPNDetectionCallback = std::function<void(const VPNConnection& connection)>;

/**
 * @brief Callback for VPN alerts.
 */
using VPNAlertCallback = std::function<void(const VPNAlert& alert)>;

/**
 * @brief Callback for leak detection.
 */
using LeakCallback = std::function<void(LeakType leak, const std::string& details)>;

/**
 * @brief Callback for adapter changes.
 */
using AdapterChangeCallback = std::function<void(
    const NetworkAdapter& adapter,
    bool added
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class VPNDetector
 * @brief Enterprise-grade VPN and proxy detection.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& detector = VPNDetector::Instance();
 * 
 * // Initialize
 * auto config = VPNDetectorConfig::CreateCorporate();
 * detector.Initialize(config);
 * 
 * // Register detection callback
 * detector.RegisterDetectionCallback([](const VPNConnection& conn) {
 *     HandleVPNDetection(conn);
 * });
 * 
 * // Get current VPN state
 * auto vpn = detector.GetCurrentVPN();
 * if (vpn.isActive) {
 *     LogVPNUsage(vpn);
 * }
 * @endcode
 */
class VPNDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static VPNDetector& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the VPN detector.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const VPNDetectorConfig& config);

    /**
     * @brief Starts detection threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops detection threads.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if running.
     * @return True if active.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // VPN DETECTION
    // ========================================================================

    /**
     * @brief Get current VPN state (legacy compatible).
     * @return VPN info.
     */
    [[nodiscard]] VPNInfo GetCurrentVPN();

    /**
     * @brief Get detailed VPN connection info.
     * @return VPN connection, or nullopt if not connected.
     */
    [[nodiscard]] std::optional<VPNConnection> GetActiveVPN() const;

    /**
     * @brief Get all active VPN connections.
     * @return Vector of VPN connections.
     */
    [[nodiscard]] std::vector<VPNConnection> GetAllVPNConnections() const;

    /**
     * @brief Check if any VPN is active.
     * @return True if VPN active.
     */
    [[nodiscard]] bool IsVPNActive() const noexcept;

    /**
     * @brief Detect VPN for specific adapter.
     * @param adapterIndex Adapter index.
     * @return VPN connection if detected.
     */
    [[nodiscard]] std::optional<VPNConnection> DetectVPNOnAdapter(uint32_t adapterIndex);

    // ========================================================================
    // ADAPTER MANAGEMENT
    // ========================================================================

    /**
     * @brief Get all network adapters.
     * @return Vector of adapters.
     */
    [[nodiscard]] std::vector<NetworkAdapter> GetAllAdapters() const;

    /**
     * @brief Get virtual adapters only.
     * @return Vector of virtual adapters.
     */
    [[nodiscard]] std::vector<NetworkAdapter> GetVirtualAdapters() const;

    /**
     * @brief Check if adapter is VPN.
     * @param adapterName Adapter name.
     * @return True if VPN adapter.
     */
    [[nodiscard]] bool IsVPNAdapter(const std::wstring& adapterName) const;

    // ========================================================================
    // PROXY DETECTION
    // ========================================================================

    /**
     * @brief Get proxy information.
     * @return Proxy info.
     */
    [[nodiscard]] ProxyInfo GetProxyInfo() const;

    /**
     * @brief Check if proxy is active.
     * @return True if proxy active.
     */
    [[nodiscard]] bool IsProxyActive() const;

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze traffic for VPN fingerprint.
     * @param connectionId Connection ID.
     * @return Traffic fingerprint.
     */
    [[nodiscard]] TrafficFingerprint AnalyzeTraffic(uint64_t connectionId) const;

    /**
     * @brief Feed packet for analysis.
     * @param connectionId Connection ID.
     * @param packet Packet data.
     */
    void FeedPacket(uint64_t connectionId, std::span<const uint8_t> packet);

    // ========================================================================
    // PROVIDER IDENTIFICATION
    // ========================================================================

    /**
     * @brief Identify VPN provider from IP.
     * @param ip IP address.
     * @return Provider info.
     */
    [[nodiscard]] std::optional<IPRangeInfo> IdentifyProvider(const std::string& ip) const;

    /**
     * @brief Check if IP is known VPN.
     * @param ip IP address.
     * @return True if known VPN IP.
     */
    [[nodiscard]] bool IsKnownVPNIP(const std::string& ip) const;

    /**
     * @brief Get provider name.
     * @param provider Provider enum.
     * @return Provider name.
     */
    [[nodiscard]] static std::string_view GetProviderName(VPNProvider provider) noexcept;

    // ========================================================================
    // LEAK DETECTION
    // ========================================================================

    /**
     * @brief Check for DNS leak.
     * @return True if DNS leak detected.
     */
    [[nodiscard]] bool HasDNSLeak() const;

    /**
     * @brief Check for IPv6 leak.
     * @return True if IPv6 leak detected.
     */
    [[nodiscard]] bool HasIPv6Leak() const;

    /**
     * @brief Get all detected leaks.
     * @return Vector of leak types.
     */
    [[nodiscard]] std::vector<LeakType> GetDetectedLeaks() const;

    // ========================================================================
    // POLICY MANAGEMENT
    // ========================================================================

    /**
     * @brief Sets VPN policy.
     * @param policy Policy to apply.
     */
    void SetPolicy(VPNPolicy policy);

    /**
     * @brief Gets current policy.
     * @return Current policy.
     */
    [[nodiscard]] VPNPolicy GetPolicy() const noexcept;

    /**
     * @brief Adds adapter exception.
     * @param adapterName Adapter name.
     */
    void AddAdapterException(const std::wstring& adapterName);

    /**
     * @brief Removes adapter exception.
     * @param adapterName Adapter name.
     */
    void RemoveAdapterException(const std::wstring& adapterName);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterDetectionCallback(VPNDetectionCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(VPNAlertCallback callback);
    [[nodiscard]] uint64_t RegisterLeakCallback(LeakCallback callback);
    [[nodiscard]] uint64_t RegisterAdapterCallback(AdapterChangeCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const VPNDetectorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    VPNDetector();
    ~VPNDetector();

    VPNDetector(const VPNDetector&) = delete;
    VPNDetector& operator=(const VPNDetector&) = delete;

    std::unique_ptr<VPNDetectorImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
