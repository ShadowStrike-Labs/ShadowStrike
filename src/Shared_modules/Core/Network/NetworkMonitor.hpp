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
 * ShadowStrike Core Network - NETWORK MONITOR (The Sentinel)
 * ============================================================================
 *
 * @file NetworkMonitor.hpp
 * @brief Enterprise-grade network traffic monitoring and connection tracking system.
 *
 * This module provides comprehensive network visibility and control by interfacing
 * with the Windows Filtering Platform (WFP) and ETW network providers. It serves
 * as the foundation for all network-based threat detection and response.
 *
 * Key Capabilities:
 * =================
 * 1. CONNECTION TRACKING
 *    - Real-time tracking of all TCP/UDP connections
 *    - 5-tuple mapping (SrcIP, SrcPort, DstIP, DstPort, Protocol)
 *    - Process-to-connection attribution via PID/TID
 *    - Connection state machine tracking (SYN, ESTABLISHED, FIN, etc.)
 *    - Historical connection logging with configurable retention
 *
 * 2. TRAFFIC ANALYSIS
 *    - Bandwidth monitoring per process/connection
 *    - Protocol identification (HTTP, HTTPS, DNS, SMB, RDP, SSH, etc.)
 *    - Deep packet inspection for unencrypted protocols
 *    - TLS/SSL fingerprinting (JA3/JA3S)
 *    - Traffic pattern analysis for anomaly detection
 *
 * 3. THREAT DETECTION INTEGRATION
 *    - IP/Domain reputation checking via ThreatIntel
 *    - C2 beaconing detection (periodic connections)
 *    - Data exfiltration detection (unusual upload patterns)
 *    - Lateral movement detection (internal scanning)
 *    - Port scanning detection (reconnaissance)
 *
 * 4. BLOCKING AND FILTERING
 *    - Real-time connection blocking via WFP
 *    - IP address blocking (IPv4/IPv6)
 *    - Port blocking (global or per-process)
 *    - Domain blocking (via DNS interception)
 *    - Geo-blocking (country-based filtering)
 *
 * 5. CONTEXT ENRICHMENT
 *    - Process name and path for each connection
 *    - User SID and username
 *    - Command line arguments
 *    - Parent process chain
 *    - Digital signature information
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                    Kernel WFP Callout Driver                        │
 *   │       (ShadowStrikeNet.sys - Packet Interception/Filtering)         │
 *   └────────────────────────────┬────────────────────────────────────────┘
 *                                │ Filter Communication Port
 *                                ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       NetworkMonitor                                │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ConnectionMgr │  │TrafficAnalyz │  │    ThreatIntegration     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Tracking   │  │ - Bandwidth  │  │ - IP Reputation          │  │
 *   │  │ - States     │  │ - Protocols  │  │ - Domain Reputation      │  │
 *   │  │ - History    │  │ - DPI        │  │ - Beaconing Detection    │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │FilterEngine  │  │ContextEnrich│  │     EventDispatcher      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - IP Block   │  │ - Process    │  │ - Callbacks              │  │
 *   │  │ - Port Block │  │ - User       │  │ - Logging                │  │
 *   │  │ - Geo Block  │  │ - Signature  │  │ - Alerts                 │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                    │                           │
 *          ┌─────────┴─────────┐       ┌────────┴────────┐
 *          ▼                   ▼       ▼                 ▼
 *   ┌──────────────┐   ┌──────────┐  ┌──────────┐ ┌──────────────┐
 *   │ProcessMonitor│   │ThreatIntel│ │ HashStore│ │ NetworkUtils │
 *   └──────────────┘   └──────────┘  └──────────┘ └──────────────┘
 *
 * WFP Integration:
 * ================
 * - Uses FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 for outbound connections
 * - Uses FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6 for inbound connections
 * - Uses FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT for port binding
 * - Uses FWPM_LAYER_STREAM for stream data inspection
 *
 * ETW Providers:
 * ==============
 * - Microsoft-Windows-Kernel-Network
 * - Microsoft-Windows-TCPIP
 * - Microsoft-Windows-DNS-Client
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1071: Application Layer Protocol (Detection)
 * - T1095: Non-Application Layer Protocol (Detection)
 * - T1571: Non-Standard Port (Detection)
 * - T1572: Protocol Tunneling (Detection)
 * - T1090: Proxy (Detection)
 * - T1573: Encrypted Channel (JA3 Fingerprinting)
 * - T1048: Exfiltration Over Alternative Protocol (Detection)
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Connection table uses concurrent data structures
 * - Callbacks may be invoked from multiple threads
 * - Statistics use atomic operations
 *
 * Performance Considerations:
 * ===========================
 * - Lock-free connection lookup for hot path
 * - Batched WFP filter updates
 * - Lazy DNS resolution
 * - Configurable event sampling for high-volume environments
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see Utils/NetworkUtils.hpp for low-level network utilities
 * @see ThreatIntel/ThreatIntelManager.hpp for reputation lookups
 * @see Core/Process/ProcessMonitor.hpp for process context
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Low-level network utilities
#include "../../Utils/ProcessUtils.hpp"       // Process context
#include "../../Utils/StringUtils.hpp"        // IP/DNS string handling
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // IP/Domain reputation
#include "../../Whitelist/WhiteListStore.hpp" // Trusted connections

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
#include <map>
#include <set>
#include <queue>
#include <optional>
#include <variant>
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
class NetworkMonitorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace NetworkMonitorConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Connection tracking limits
    constexpr size_t MAX_TRACKED_CONNECTIONS = 1000000;      // 1M connections
    constexpr size_t MAX_CONNECTION_HISTORY = 100000;        // Historical entries
    constexpr size_t MAX_BLOCKED_IPS = 100000;               // IP blocklist size
    constexpr size_t MAX_BLOCKED_DOMAINS = 50000;            // Domain blocklist
    constexpr size_t MAX_BLOCKED_PORTS = 1000;               // Port blocklist

    // Timing constants
    constexpr uint32_t CONNECTION_TIMEOUT_MS = 300000;       // 5 minutes idle timeout
    constexpr uint32_t CLEANUP_INTERVAL_MS = 60000;          // 1 minute cleanup
    constexpr uint32_t STATS_UPDATE_INTERVAL_MS = 5000;      // 5 seconds
    constexpr uint32_t BANDWIDTH_SAMPLE_INTERVAL_MS = 1000;  // 1 second
    constexpr uint32_t BEACONING_ANALYSIS_WINDOW_MS = 3600000; // 1 hour

    // Traffic thresholds
    constexpr uint64_t SUSPICIOUS_UPLOAD_BYTES = 100ULL * 1024 * 1024;  // 100 MB
    constexpr uint32_t SUSPICIOUS_CONNECTION_RATE = 100;     // Per minute
    constexpr uint32_t PORT_SCAN_THRESHOLD = 50;             // Ports per minute
    constexpr uint32_t BEACONING_MIN_CONNECTIONS = 10;       // Minimum for detection

    // Protocol identification
    constexpr uint16_t PORT_HTTP = 80;
    constexpr uint16_t PORT_HTTPS = 443;
    constexpr uint16_t PORT_DNS = 53;
    constexpr uint16_t PORT_SMB = 445;
    constexpr uint16_t PORT_RDP = 3389;
    constexpr uint16_t PORT_SSH = 22;
    constexpr uint16_t PORT_FTP = 21;
    constexpr uint16_t PORT_SMTP = 25;
    constexpr uint16_t PORT_IMAP = 143;
    constexpr uint16_t PORT_POP3 = 110;

    // WFP layer GUIDs (simplified identifiers)
    constexpr uint32_t WFP_LAYER_OUTBOUND_V4 = 0x01;
    constexpr uint32_t WFP_LAYER_OUTBOUND_V6 = 0x02;
    constexpr uint32_t WFP_LAYER_INBOUND_V4 = 0x03;
    constexpr uint32_t WFP_LAYER_INBOUND_V6 = 0x04;
    constexpr uint32_t WFP_LAYER_STREAM_V4 = 0x05;
    constexpr uint32_t WFP_LAYER_STREAM_V6 = 0x06;

}  // namespace NetworkMonitorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ConnectionState
 * @brief TCP connection state machine states.
 */
enum class ConnectionState : uint8_t {
    UNKNOWN = 0,
    LISTENING = 1,           ///< Server listening
    SYN_SENT = 2,            ///< Client sent SYN
    SYN_RECEIVED = 3,        ///< Server received SYN
    ESTABLISHED = 4,         ///< Connection established
    FIN_WAIT_1 = 5,          ///< First FIN sent
    FIN_WAIT_2 = 6,          ///< ACK received for FIN
    CLOSE_WAIT = 7,          ///< Received FIN, waiting to close
    CLOSING = 8,             ///< Both sides sent FIN
    LAST_ACK = 9,            ///< Waiting for final ACK
    TIME_WAIT = 10,          ///< Waiting for packets to expire
    CLOSED = 11,             ///< Connection closed
    DELETE_TCB = 12          ///< TCB being deleted
};

/**
 * @enum ProtocolType
 * @brief Network protocol types.
 */
enum class ProtocolType : uint8_t {
    UNKNOWN = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
    SCTP = 132,
    GRE = 47
};

/**
 * @enum ApplicationProtocol
 * @brief Application layer protocol identification.
 */
enum class ApplicationProtocol : uint16_t {
    UNKNOWN = 0,
    HTTP = 1,
    HTTPS = 2,
    DNS = 3,
    DNS_OVER_HTTPS = 4,
    DNS_OVER_TLS = 5,
    SMB = 6,
    SMB2 = 7,
    RDP = 8,
    SSH = 9,
    FTP = 10,
    FTP_DATA = 11,
    SFTP = 12,
    SMTP = 13,
    SMTPS = 14,
    IMAP = 15,
    IMAPS = 16,
    POP3 = 17,
    POP3S = 18,
    LDAP = 19,
    LDAPS = 20,
    KERBEROS = 21,
    NTP = 22,
    SNMP = 23,
    SYSLOG = 24,
    MYSQL = 25,
    POSTGRESQL = 26,
    MSSQL = 27,
    MONGODB = 28,
    REDIS = 29,
    MEMCACHED = 30,
    ELASTICSEARCH = 31,
    KAFKA = 32,
    AMQP = 33,
    MQTT = 34,
    COAP = 35,
    WEBSOCKET = 36,
    GRPC = 37,
    QUIC = 38,
    WIREGUARD = 39,
    OPENVPN = 40,
    TOR = 41,
    BITTORRENT = 42,
    BITCOIN = 43,
    CUSTOM_C2 = 100          ///< Detected C2 protocol
};

/**
 * @enum ConnectionDirection
 * @brief Direction of network connection.
 */
enum class ConnectionDirection : uint8_t {
    UNKNOWN = 0,
    INBOUND = 1,             ///< External → Local
    OUTBOUND = 2,            ///< Local → External
    LOCAL = 3,               ///< Loopback
    INTERNAL = 4             ///< LAN traffic
};

/**
 * @enum FilterAction
 * @brief Action to take on filtered traffic.
 */
enum class FilterAction : uint8_t {
    ALLOW = 0,
    BLOCK = 1,
    MONITOR = 2,             ///< Allow but log
    QUARANTINE = 3,          ///< Block and isolate
    REDIRECT = 4,            ///< Redirect to proxy
    RATE_LIMIT = 5           ///< Throttle connection
};

/**
 * @enum BlockReason
 * @brief Reason for blocking a connection.
 */
enum class BlockReason : uint8_t {
    NONE = 0,
    MALICIOUS_IP = 1,
    MALICIOUS_DOMAIN = 2,
    BLOCKED_PORT = 3,
    BLOCKED_APPLICATION = 4,
    GEO_BLOCKED = 5,
    REPUTATION_LOW = 6,
    C2_DETECTED = 7,
    POLICY_VIOLATION = 8,
    RATE_EXCEEDED = 9,
    MANUAL_BLOCK = 10,
    SUSPICIOUS_PATTERN = 11,
    KNOWN_MALWARE = 12
};

/**
 * @enum ThreatIndicator
 * @brief Network-based threat indicators.
 */
enum class ThreatIndicator : uint8_t {
    NONE = 0,
    BEACONING = 1,           ///< Periodic C2 communication
    DATA_EXFILTRATION = 2,   ///< Large outbound data transfer
    PORT_SCANNING = 3,       ///< Reconnaissance activity
    LATERAL_MOVEMENT = 4,    ///< Internal network spreading
    DNS_TUNNELING = 5,       ///< DNS as covert channel
    ICMP_TUNNELING = 6,      ///< ICMP as covert channel
    DOMAIN_GENERATION = 7,   ///< DGA detected
    TOR_USAGE = 8,           ///< Tor network connection
    CRYPTO_MINING = 9,       ///< Mining pool connection
    BOTNET_ACTIVITY = 10,    ///< Botnet C2 pattern
    EXPLOIT_TRAFFIC = 11     ///< Exploit kit traffic
};

/**
 * @enum IPAddressType
 * @brief Type of IP address.
 */
enum class IPAddressType : uint8_t {
    UNKNOWN = 0,
    IPV4 = 4,
    IPV6 = 6
};

/**
 * @enum IPClassification
 * @brief Classification of IP address.
 */
enum class IPClassification : uint8_t {
    UNKNOWN = 0,
    PRIVATE = 1,             ///< RFC 1918 private
    PUBLIC = 2,              ///< Routable public IP
    LOOPBACK = 3,            ///< 127.0.0.0/8 or ::1
    LINK_LOCAL = 4,          ///< 169.254.0.0/16 or fe80::/10
    MULTICAST = 5,           ///< 224.0.0.0/4 or ff00::/8
    BROADCAST = 6,           ///< 255.255.255.255
    RESERVED = 7,            ///< IANA reserved
    DOCUMENTATION = 8        ///< TEST-NET, etc.
};

/**
 * @enum MonitoringLevel
 * @brief Level of network monitoring detail.
 */
enum class MonitoringLevel : uint8_t {
    MINIMAL = 0,             ///< Connection events only
    STANDARD = 1,            ///< + Basic metadata
    DETAILED = 2,            ///< + Process context
    FORENSIC = 3             ///< + Packet capture
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct IPAddress
 * @brief Unified IPv4/IPv6 address structure.
 */
struct alignas(8) IPAddress {
    IPAddressType type{ IPAddressType::UNKNOWN };
    IPClassification classification{ IPClassification::UNKNOWN };
    
    union {
        uint32_t ipv4{ 0 };                      ///< IPv4 in host byte order
        std::array<uint8_t, 16> ipv6;            ///< IPv6 address bytes
    };

    // Constructors
    IPAddress() noexcept = default;
    explicit IPAddress(uint32_t v4) noexcept;
    explicit IPAddress(const std::array<uint8_t, 16>& v6) noexcept;
    explicit IPAddress(std::string_view str);
    explicit IPAddress(std::wstring_view str);

    // Conversion
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] std::wstring ToWString() const;
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] bool IsPrivate() const noexcept;
    [[nodiscard]] bool IsLoopback() const noexcept;

    // Comparison
    bool operator==(const IPAddress& other) const noexcept;
    bool operator<(const IPAddress& other) const noexcept;

    // Hash support
    struct Hash {
        size_t operator()(const IPAddress& ip) const noexcept;
    };
};

/**
 * @struct IPRange
 * @brief IP address range (CIDR notation support).
 */
struct alignas(8) IPRange {
    IPAddress baseAddress;
    uint8_t prefixLength{ 0 };                   ///< CIDR prefix (e.g., /24)

    [[nodiscard]] bool Contains(const IPAddress& ip) const noexcept;
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] uint64_t GetAddressCount() const noexcept;

    static std::optional<IPRange> Parse(std::string_view cidr);
};

/**
 * @struct SocketAddress
 * @brief Complete socket address (IP + port).
 */
struct alignas(8) SocketAddress {
    IPAddress ip;
    uint16_t port{ 0 };

    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] std::wstring ToWString() const;

    bool operator==(const SocketAddress& other) const noexcept;
    bool operator<(const SocketAddress& other) const noexcept;

    struct Hash {
        size_t operator()(const SocketAddress& addr) const noexcept;
    };
};

/**
 * @struct ConnectionTuple
 * @brief 5-tuple uniquely identifying a connection.
 */
struct alignas(8) ConnectionTuple {
    SocketAddress local;
    SocketAddress remote;
    ProtocolType protocol{ ProtocolType::UNKNOWN };

    [[nodiscard]] std::string ToString() const;
    bool operator==(const ConnectionTuple& other) const noexcept;

    struct Hash {
        size_t operator()(const ConnectionTuple& tuple) const noexcept;
    };
};

/**
 * @struct JA3Fingerprint
 * @brief TLS client fingerprint (JA3).
 */
struct alignas(8) JA3Fingerprint {
    std::array<uint8_t, 16> md5{ 0 };            ///< MD5 of fingerprint string
    std::string fingerprintString;               ///< Raw fingerprint
    std::wstring clientName;                     ///< Identified client (if known)
    bool isMalicious{ false };                   ///< Known malicious fingerprint

    [[nodiscard]] std::string GetMD5String() const;
};

/**
 * @struct JA3SFingerprint
 * @brief TLS server fingerprint (JA3S).
 */
struct alignas(8) JA3SFingerprint {
    std::array<uint8_t, 16> md5{ 0 };
    std::string fingerprintString;
    std::wstring serverName;
    bool isMalicious{ false };

    [[nodiscard]] std::string GetMD5String() const;
};

/**
 * @struct TLSInfo
 * @brief TLS connection information.
 */
struct alignas(64) TLSInfo {
    uint16_t version{ 0 };                       ///< TLS version (0x0303 = TLS 1.2)
    std::wstring cipherSuite;
    std::wstring serverName;                     ///< SNI hostname
    std::wstring certificateSubject;
    std::wstring certificateIssuer;
    std::chrono::system_clock::time_point certExpiry;
    bool isSelfSigned{ false };
    bool isExpired{ false };
    bool isRevoked{ false };

    JA3Fingerprint ja3;
    JA3SFingerprint ja3s;
};

/**
 * @struct ProcessNetworkContext
 * @brief Process context for a network connection.
 */
struct alignas(64) ProcessNetworkContext {
    uint32_t pid{ 0 };
    uint32_t parentPid{ 0 };
    uint64_t processUniqueId{ 0 };               ///< For PID reuse handling
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;
    std::wstring workingDirectory;

    // User context
    std::wstring userSid;
    std::wstring userName;
    std::wstring userDomain;
    bool isElevated{ false };
    bool isService{ false };

    // Signature info
    bool isSigned{ false };
    std::wstring publisher;
    bool isValidSignature{ false };
    bool isTrusted{ false };

    // Hash
    std::array<uint8_t, 32> imageSha256{ 0 };
    bool hashValid{ false };
};

/**
 * @struct BandwidthStats
 * @brief Bandwidth statistics for a connection.
 */
struct alignas(64) BandwidthStats {
    std::atomic<uint64_t> bytesReceived{ 0 };
    std::atomic<uint64_t> bytesSent{ 0 };
    std::atomic<uint64_t> packetsReceived{ 0 };
    std::atomic<uint64_t> packetsSent{ 0 };

    // Rate calculations (bytes per second)
    std::atomic<uint64_t> receiveRate{ 0 };
    std::atomic<uint64_t> sendRate{ 0 };

    // Peak rates
    std::atomic<uint64_t> peakReceiveRate{ 0 };
    std::atomic<uint64_t> peakSendRate{ 0 };

    // Timing
    std::chrono::steady_clock::time_point lastUpdate;
    std::chrono::steady_clock::time_point lastRateCalc;

    void Reset() noexcept;
};

/**
 * @struct ConnectionInfo
 * @brief Comprehensive information about a network connection.
 */
struct alignas(128) ConnectionInfo {
    // Connection identity
    uint64_t connectionId{ 0 };                  ///< Unique connection ID
    ConnectionTuple tuple;

    // State
    ConnectionState state{ ConnectionState::UNKNOWN };
    ConnectionDirection direction{ ConnectionDirection::UNKNOWN };
    FilterAction currentAction{ FilterAction::ALLOW };

    // Protocol identification
    ApplicationProtocol appProtocol{ ApplicationProtocol::UNKNOWN };
    std::wstring protocolDetails;                ///< Additional protocol info

    // TLS info (if encrypted)
    std::optional<TLSInfo> tlsInfo;

    // Process context
    ProcessNetworkContext processContext;

    // DNS info
    std::wstring remoteHostname;                 ///< Resolved hostname
    bool hostnameResolved{ false };

    // Timing
    std::chrono::system_clock::time_point createTime;
    std::chrono::system_clock::time_point lastActivityTime;
    std::chrono::system_clock::time_point closeTime;
    std::chrono::milliseconds duration{ 0 };

    // Bandwidth
    BandwidthStats bandwidth;

    // Threat indicators
    std::vector<ThreatIndicator> indicators;
    uint8_t riskScore{ 0 };                      ///< 0-100 risk score
    BlockReason blockReason{ BlockReason::NONE };

    // Geo info
    std::wstring remoteCountryCode;
    std::wstring remoteCountryName;
    std::wstring remoteASN;
    std::wstring remoteASName;

    // Flags
    bool isBlocked{ false };
    bool isMonitored{ false };
    bool isSuspicious{ false };
    bool isWhitelisted{ false };
};

/**
 * @struct EnhancedConnectionInfo
 * @brief Network connection details enriched with process metadata (legacy compat).
 */
struct alignas(64) EnhancedConnectionInfo {
    ConnectionInfo fullInfo;

    // Convenience accessors (backward compatibility)
    [[nodiscard]] const std::wstring& GetProcessPath() const noexcept {
        return fullInfo.processContext.processPath;
    }
    [[nodiscard]] const std::wstring& GetUserSid() const noexcept {
        return fullInfo.processContext.userSid;
    }
    [[nodiscard]] bool IsInbound() const noexcept {
        return fullInfo.direction == ConnectionDirection::INBOUND;
    }
    [[nodiscard]] uint64_t GetTimestamp() const noexcept;
};

/**
 * @struct ConnectionFilter
 * @brief Filter rule for network connections.
 */
struct alignas(64) ConnectionFilter {
    // Filter identity
    uint64_t filterId{ 0 };
    std::wstring name;
    std::wstring description;

    // Match criteria (all optional - empty means match all)
    std::optional<IPAddress> localIp;
    std::optional<uint16_t> localPort;
    std::optional<IPRange> remoteIpRange;
    std::optional<uint16_t> remotePort;
    std::optional<ProtocolType> protocol;
    std::optional<ApplicationProtocol> appProtocol;
    std::optional<std::wstring> processPath;
    std::optional<std::wstring> processName;
    std::optional<uint32_t> pid;
    std::optional<std::wstring> userSid;
    std::optional<std::wstring> remoteHostname;
    std::optional<std::wstring> countryCode;

    // Action
    FilterAction action{ FilterAction::BLOCK };
    BlockReason reason{ BlockReason::POLICY_VIOLATION };

    // Priority (higher = evaluated first)
    uint32_t priority{ 1000 };

    // Timing
    bool isTemporary{ false };
    std::chrono::system_clock::time_point expiresAt;

    // Metadata
    std::chrono::system_clock::time_point createdAt;
    std::wstring createdBy;
    bool isEnabled{ true };
    bool isBuiltIn{ false };

    // Statistics
    std::atomic<uint64_t> hitCount{ 0 };
    std::chrono::system_clock::time_point lastHitTime;

    [[nodiscard]] bool Matches(const ConnectionInfo& conn) const;
};

/**
 * @struct BeaconingAnalysis
 * @brief Analysis of potential C2 beaconing behavior.
 */
struct alignas(64) BeaconingAnalysis {
    SocketAddress destination;
    uint32_t connectionCount{ 0 };
    std::chrono::milliseconds averageInterval{ 0 };
    std::chrono::milliseconds intervalStdDev{ 0 };
    double jitterPercent{ 0.0 };                 ///< Interval variation
    uint64_t totalBytesSent{ 0 };
    uint64_t totalBytesReceived{ 0 };
    double beaconingScore{ 0.0 };                ///< 0-1 likelihood
    bool isLikelyBeaconing{ false };
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::vector<std::chrono::system_clock::time_point> connectionTimes;
};

/**
 * @struct DataExfiltrationAnalysis
 * @brief Analysis of potential data exfiltration.
 */
struct alignas(64) DataExfiltrationAnalysis {
    uint32_t pid{ 0 };
    std::wstring processPath;
    SocketAddress destination;
    uint64_t totalBytesSent{ 0 };
    std::chrono::milliseconds timeSpan{ 0 };
    double bytesPerSecond{ 0.0 };
    uint32_t connectionCount{ 0 };
    double exfiltrationScore{ 0.0 };             ///< 0-1 likelihood
    bool isLikelyExfiltration{ false };
    std::wstring destinationCountry;
};

/**
 * @struct PortScanAnalysis
 * @brief Analysis of potential port scanning.
 */
struct alignas(64) PortScanAnalysis {
    IPAddress sourceIp;
    uint32_t sourcePid{ 0 };
    IPAddress targetIp;
    std::vector<uint16_t> scannedPorts;
    uint32_t totalPortsScanned{ 0 };
    uint32_t openPortsFound{ 0 };
    std::chrono::milliseconds scanDuration{ 0 };
    double scanScore{ 0.0 };
    bool isLikelyScan{ false };
    std::chrono::system_clock::time_point startTime;
};

/**
 * @struct NetworkEvent
 * @brief Event from network monitoring.
 */
struct alignas(64) NetworkEvent {
    // Event identity
    uint64_t eventId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Event type
    enum class Type : uint8_t {
        CONNECTION_OPENED = 0,
        CONNECTION_CLOSED = 1,
        CONNECTION_BLOCKED = 2,
        DATA_RECEIVED = 3,
        DATA_SENT = 4,
        THREAT_DETECTED = 5,
        FILTER_MATCHED = 6,
        PROTOCOL_IDENTIFIED = 7,
        DNS_QUERY = 8,
        DNS_RESPONSE = 9
    } type{ Type::CONNECTION_OPENED };

    // Connection reference
    uint64_t connectionId{ 0 };
    ConnectionTuple tuple;

    // Process context
    uint32_t pid{ 0 };
    std::wstring processName;

    // Event details
    std::variant<
        ConnectionInfo,                          // CONNECTION_OPENED/CLOSED
        BlockReason,                             // CONNECTION_BLOCKED
        uint64_t,                                // DATA_RECEIVED/SENT (bytes)
        ThreatIndicator,                         // THREAT_DETECTED
        uint64_t,                                // FILTER_MATCHED (filter ID)
        ApplicationProtocol,                     // PROTOCOL_IDENTIFIED
        std::wstring                             // DNS_QUERY/RESPONSE
    > details;
};

/**
 * @struct NetworkMonitorConfig
 * @brief Configuration for the NetworkMonitor.
 */
struct alignas(64) NetworkMonitorConfig {
    // Feature toggles
    bool enabled{ true };
    MonitoringLevel level{ MonitoringLevel::STANDARD };

    // Connection tracking
    bool trackConnections{ true };
    bool trackBandwidth{ true };
    bool identifyProtocols{ true };
    bool extractTLSInfo{ true };
    bool resolveHostnames{ true };
    bool lookupGeoIP{ true };

    // Threat detection
    bool detectBeaconing{ true };
    bool detectExfiltration{ true };
    bool detectPortScanning{ true };
    bool detectDNSTunneling{ true };
    bool checkIPReputation{ true };
    bool checkDomainReputation{ true };

    // Filtering
    bool enableFiltering{ true };
    bool blockMaliciousIPs{ true };
    bool blockMaliciousDomains{ true };
    FilterAction defaultAction{ FilterAction::ALLOW };

    // Performance
    uint32_t maxTrackedConnections{ NetworkMonitorConstants::MAX_TRACKED_CONNECTIONS };
    uint32_t connectionTimeoutMs{ NetworkMonitorConstants::CONNECTION_TIMEOUT_MS };
    uint32_t cleanupIntervalMs{ NetworkMonitorConstants::CLEANUP_INTERVAL_MS };
    bool enableEventSampling{ false };
    uint32_t eventSampleRate{ 100 };             ///< 1 in N events

    // Logging
    bool logAllConnections{ false };
    bool logBlockedOnly{ true };
    bool logBandwidth{ false };

    // WFP settings
    bool useKernelFiltering{ true };
    bool useETWProvider{ true };

    // Factory methods
    static NetworkMonitorConfig CreateDefault() noexcept;
    static NetworkMonitorConfig CreateHighSecurity() noexcept;
    static NetworkMonitorConfig CreatePerformance() noexcept;
    static NetworkMonitorConfig CreateForensic() noexcept;
};

/**
 * @struct NetworkMonitorStatistics
 * @brief Runtime statistics for network monitoring.
 */
struct alignas(128) NetworkMonitorStatistics {
    // Connection statistics
    std::atomic<uint64_t> totalConnections{ 0 };
    std::atomic<uint64_t> activeConnections{ 0 };
    std::atomic<uint64_t> inboundConnections{ 0 };
    std::atomic<uint64_t> outboundConnections{ 0 };
    std::atomic<uint64_t> closedConnections{ 0 };
    std::atomic<uint64_t> blockedConnections{ 0 };

    // Traffic statistics
    std::atomic<uint64_t> totalBytesReceived{ 0 };
    std::atomic<uint64_t> totalBytesSent{ 0 };
    std::atomic<uint64_t> totalPacketsReceived{ 0 };
    std::atomic<uint64_t> totalPacketsSent{ 0 };

    // Filtering statistics
    std::atomic<uint64_t> filtersMatched{ 0 };
    std::atomic<uint64_t> ipsBlocked{ 0 };
    std::atomic<uint64_t> domainsBlocked{ 0 };
    std::atomic<uint64_t> portsBlocked{ 0 };

    // Threat statistics
    std::atomic<uint64_t> threatsDetected{ 0 };
    std::atomic<uint64_t> beaconingDetected{ 0 };
    std::atomic<uint64_t> exfiltrationDetected{ 0 };
    std::atomic<uint64_t> portScansDetected{ 0 };

    // Protocol statistics
    std::atomic<uint64_t> httpConnections{ 0 };
    std::atomic<uint64_t> httpsConnections{ 0 };
    std::atomic<uint64_t> dnsQueries{ 0 };
    std::atomic<uint64_t> smbConnections{ 0 };

    // Performance
    std::atomic<uint64_t> eventsProcessed{ 0 };
    std::atomic<uint64_t> eventsDropped{ 0 };
    std::atomic<uint64_t> processingTimeUs{ 0 };

    // Errors
    std::atomic<uint64_t> errorCount{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for new connection events.
 * @param info The connection information
 */
using ConnectionCallback = std::function<void(const ConnectionInfo& info)>;

/**
 * @brief Callback for connection state changes.
 * @param connectionId The connection ID
 * @param oldState Previous state
 * @param newState New state
 */
using StateChangeCallback = std::function<void(
    uint64_t connectionId,
    ConnectionState oldState,
    ConnectionState newState
)>;

/**
 * @brief Callback for network events.
 * @param event The network event
 */
using NetworkEventCallback = std::function<void(const NetworkEvent& event)>;

/**
 * @brief Callback for filter matches.
 * @param filter The matched filter
 * @param connection The connection that matched
 * @return True to apply filter action, false to skip
 */
using FilterMatchCallback = std::function<bool(
    const ConnectionFilter& filter,
    const ConnectionInfo& connection
)>;

/**
 * @brief Callback for threat detection.
 * @param connectionId The connection ID
 * @param indicator The threat indicator
 * @param analysis Additional analysis data
 */
using ThreatDetectionCallback = std::function<void(
    uint64_t connectionId,
    ThreatIndicator indicator,
    const std::variant<BeaconingAnalysis, DataExfiltrationAnalysis, PortScanAnalysis>& analysis
)>;

/**
 * @brief Callback for bandwidth alerts.
 * @param connectionId The connection ID
 * @param bytesTransferred Total bytes transferred
 * @param direction Transfer direction
 */
using BandwidthAlertCallback = std::function<void(
    uint64_t connectionId,
    uint64_t bytesTransferred,
    ConnectionDirection direction
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class NetworkMonitor
 * @brief Enterprise-grade network traffic monitoring and connection tracking system.
 *
 * This class provides comprehensive network visibility including connection
 * tracking, traffic analysis, threat detection, and filtering capabilities.
 *
 * Thread Safety:
 * All public methods are thread-safe. Callbacks may be invoked from multiple threads.
 *
 * Usage Example:
 * @code
 * auto& monitor = NetworkMonitor::Instance();
 * 
 * // Configure
 * auto config = NetworkMonitorConfig::CreateHighSecurity();
 * monitor.Initialize(config);
 * 
 * // Register threat callback
 * monitor.RegisterThreatDetectionCallback(
 *     [](uint64_t connId, ThreatIndicator ind, const auto& analysis) {
 *         HandleThreat(connId, ind);
 *     }
 * );
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // Block malicious IP
 * monitor.BlockIP(IPAddress("192.168.1.100"), BlockReason::MALICIOUS_IP);
 * 
 * // Get active connections
 * auto connections = monitor.GetActiveConnections();
 * @endcode
 */
class NetworkMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance of NetworkMonitor.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static NetworkMonitor& Instance() noexcept;

    /**
     * @brief Checks if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the network monitor with specified configuration.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    bool Initialize(const NetworkMonitorConfig& config);

    /**
     * @brief Starts the network monitoring subsystem.
     * @return True if started successfully.
     */
    bool Start();

    /**
     * @brief Stops the network monitoring subsystem.
     */
    void Stop();

    /**
     * @brief Shuts down and releases all resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if network monitor is initialized.
     * @return True if initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Checks if monitoring is active.
     * @return True if running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Gets the current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] NetworkMonitorConfig GetConfig() const;

    /**
     * @brief Updates configuration at runtime.
     * @param config New configuration.
     * @return True if update succeeded.
     */
    bool UpdateConfig(const NetworkMonitorConfig& config);

    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets information about a specific connection.
     * @param connectionId The connection ID.
     * @return Connection info, or nullopt if not found.
     */
    [[nodiscard]] std::optional<ConnectionInfo> GetConnection(uint64_t connectionId) const;

    /**
     * @brief Gets connection by tuple.
     * @param tuple The connection tuple.
     * @return Connection info, or nullopt if not found.
     */
    [[nodiscard]] std::optional<ConnectionInfo> GetConnectionByTuple(
        const ConnectionTuple& tuple
    ) const;

    /**
     * @brief Gets all active connections.
     * @return Vector of active connections.
     */
    [[nodiscard]] std::vector<ConnectionInfo> GetActiveConnections() const;

    /**
     * @brief Gets all active connections (legacy interface).
     * @return Vector of enhanced connection info.
     */
    [[nodiscard]] std::vector<EnhancedConnectionInfo> GetActiveConnectionsSnapshot();

    /**
     * @brief Gets connections for a specific process.
     * @param pid Process ID.
     * @return Vector of connections for the process.
     */
    [[nodiscard]] std::vector<ConnectionInfo> GetConnectionsByProcess(uint32_t pid) const;

    /**
     * @brief Gets connections to a specific remote IP.
     * @param ip Remote IP address.
     * @return Vector of matching connections.
     */
    [[nodiscard]] std::vector<ConnectionInfo> GetConnectionsByRemoteIP(const IPAddress& ip) const;

    /**
     * @brief Checks if a process is listening on a specific port.
     * @param pid Process ID.
     * @param port Port number.
     * @return True if listening.
     */
    [[nodiscard]] bool IsProcessListening(uint32_t pid, uint16_t port) const;

    /**
     * @brief Gets the process listening on a port.
     * @param port Port number.
     * @param protocol Protocol type.
     * @return Process ID, or 0 if no process is listening.
     */
    [[nodiscard]] uint32_t GetListeningProcess(uint16_t port, ProtocolType protocol) const;

    /**
     * @brief Terminates a specific connection.
     * @param connectionId The connection ID.
     * @return True if terminated.
     */
    bool TerminateConnection(uint64_t connectionId);

    // ========================================================================
    // FILTERING
    // ========================================================================

    /**
     * @brief Blocks an IP address.
     * @param ip IP address to block.
     * @param reason Reason for blocking.
     * @param durationMs Duration in milliseconds (0 = permanent).
     * @return True if blocked.
     */
    bool BlockIP(
        const IPAddress& ip,
        BlockReason reason = BlockReason::MANUAL_BLOCK,
        uint32_t durationMs = 0
    );

    /**
     * @brief Blocks an IP address (legacy interface).
     */
    bool BlockIpAddress(const IPAddress& ip);

    /**
     * @brief Unblocks an IP address.
     * @param ip IP address to unblock.
     * @return True if unblocked.
     */
    bool UnblockIP(const IPAddress& ip);

    /**
     * @brief Blocks an IP range.
     * @param range IP range to block.
     * @param reason Reason for blocking.
     * @return True if blocked.
     */
    bool BlockIPRange(const IPRange& range, BlockReason reason = BlockReason::MANUAL_BLOCK);

    /**
     * @brief Blocks a port.
     * @param port Port number.
     * @param protocol Protocol type.
     * @param reason Reason for blocking.
     * @return True if blocked.
     */
    bool BlockPort(
        uint16_t port,
        ProtocolType protocol = ProtocolType::TCP,
        BlockReason reason = BlockReason::POLICY_VIOLATION
    );

    /**
     * @brief Unblocks a port.
     * @param port Port number.
     * @param protocol Protocol type.
     * @return True if unblocked.
     */
    bool UnblockPort(uint16_t port, ProtocolType protocol = ProtocolType::TCP);

    /**
     * @brief Blocks a domain.
     * @param domain Domain name to block.
     * @param reason Reason for blocking.
     * @return True if blocked.
     */
    bool BlockDomain(const std::wstring& domain, BlockReason reason = BlockReason::MALICIOUS_DOMAIN);

    /**
     * @brief Unblocks a domain.
     * @param domain Domain name.
     * @return True if unblocked.
     */
    bool UnblockDomain(const std::wstring& domain);

    /**
     * @brief Blocks network access for a process.
     * @param pid Process ID.
     * @param reason Reason for blocking.
     * @return True if blocked.
     */
    bool BlockProcess(uint32_t pid, BlockReason reason = BlockReason::BLOCKED_APPLICATION);

    /**
     * @brief Unblocks network access for a process.
     * @param pid Process ID.
     * @return True if unblocked.
     */
    bool UnblockProcess(uint32_t pid);

    /**
     * @brief Adds a custom filter rule.
     * @param filter The filter rule.
     * @return Filter ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t AddFilter(const ConnectionFilter& filter);

    /**
     * @brief Removes a filter rule.
     * @param filterId The filter ID.
     * @return True if removed.
     */
    bool RemoveFilter(uint64_t filterId);

    /**
     * @brief Gets all active filters.
     * @return Vector of active filters.
     */
    [[nodiscard]] std::vector<ConnectionFilter> GetFilters() const;

    /**
     * @brief Checks if an IP is blocked.
     * @param ip IP address.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsIPBlocked(const IPAddress& ip) const;

    /**
     * @brief Gets the list of blocked IPs.
     * @return Vector of blocked IP addresses.
     */
    [[nodiscard]] std::vector<IPAddress> GetBlockedIPs() const;

    /**
     * @brief Clears all temporary blocks.
     */
    void ClearTemporaryBlocks();

    // ========================================================================
    // THREAT ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes a connection for beaconing behavior.
     * @param remoteAddress Remote address to analyze.
     * @return Beaconing analysis results.
     */
    [[nodiscard]] BeaconingAnalysis AnalyzeBeaconing(const SocketAddress& remoteAddress) const;

    /**
     * @brief Analyzes a process for data exfiltration.
     * @param pid Process ID.
     * @return Exfiltration analysis results.
     */
    [[nodiscard]] DataExfiltrationAnalysis AnalyzeExfiltration(uint32_t pid) const;

    /**
     * @brief Analyzes for port scanning activity.
     * @param sourceIp Source IP to analyze.
     * @return Port scan analysis results.
     */
    [[nodiscard]] PortScanAnalysis AnalyzePortScanning(const IPAddress& sourceIp) const;

    /**
     * @brief Gets detected threat indicators for a connection.
     * @param connectionId The connection ID.
     * @return Vector of threat indicators.
     */
    [[nodiscard]] std::vector<ThreatIndicator> GetThreatIndicators(uint64_t connectionId) const;

    // ========================================================================
    // CALLBACK REGISTRATION (Legacy)
    // ========================================================================

    /**
     * @brief Sets the connection callback (legacy interface).
     * @param callback The callback function.
     */
    void SetConnectionCallback(ConnectionCallback callback);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a callback for connection events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterConnectionCallback(ConnectionCallback callback);

    /**
     * @brief Registers a callback for state change events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterStateChangeCallback(StateChangeCallback callback);

    /**
     * @brief Registers a callback for network events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterNetworkEventCallback(NetworkEventCallback callback);

    /**
     * @brief Registers a callback for filter matches.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterFilterMatchCallback(FilterMatchCallback callback);

    /**
     * @brief Registers a callback for threat detection.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterThreatDetectionCallback(ThreatDetectionCallback callback);

    /**
     * @brief Registers a callback for bandwidth alerts.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterBandwidthAlertCallback(BandwidthAlertCallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId The callback ID.
     * @return True if unregistered.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Gets current statistics.
     * @return Reference to statistics.
     */
    [[nodiscard]] const NetworkMonitorStatistics& GetStatistics() const noexcept;

    /**
     * @brief Resets all statistics.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Gets bandwidth for a specific process.
     * @param pid Process ID.
     * @return Bandwidth stats for the process.
     */
    [[nodiscard]] BandwidthStats GetProcessBandwidth(uint32_t pid) const;

    /**
     * @brief Gets total system bandwidth.
     * @return System-wide bandwidth stats.
     */
    [[nodiscard]] BandwidthStats GetSystemBandwidth() const;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Performs diagnostic check.
     * @return True if healthy.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Exports diagnostic data.
     * @param outputPath Output file path.
     * @return True if exported.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

    /**
     * @brief Performs self-test of NetworkMonitor functionality.
     * @return True if all tests pass.
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Gets version string.
     * @return Version in format "MAJOR.MINOR.PATCH".
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * @brief Resolves hostname to IP addresses.
     * @param hostname The hostname.
     * @return Vector of resolved IP addresses.
     */
    [[nodiscard]] static std::vector<IPAddress> ResolveHostname(std::wstring_view hostname);

    /**
     * @brief Performs reverse DNS lookup.
     * @param ip IP address.
     * @return Hostname, or empty if not found.
     */
    [[nodiscard]] static std::wstring ReverseLookup(const IPAddress& ip);

    /**
     * @brief Gets the protocol name.
     * @param protocol Protocol type.
     * @return Protocol name string.
     */
    [[nodiscard]] static std::wstring_view GetProtocolName(ProtocolType protocol) noexcept;

    /**
     * @brief Gets the application protocol name.
     * @param protocol Application protocol.
     * @return Protocol name string.
     */
    [[nodiscard]] static std::wstring_view GetAppProtocolName(ApplicationProtocol protocol) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    NetworkMonitor();
    ~NetworkMonitor();

    // Non-copyable, non-movable
    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;
    NetworkMonitor(NetworkMonitor&&) = delete;
    NetworkMonitor& operator=(NetworkMonitor&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<NetworkMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;

    // ========================================================================
    // LEGACY MEMBERS
    // ========================================================================
    std::atomic<bool> m_running{ false };
    ConnectionCallback m_legacyCallback;
    mutable std::shared_mutex m_callbackMutex;
    std::vector<IPAddress> m_blockedIps;
    mutable std::shared_mutex m_filterMutex;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetConnectionStateName(ConnectionState state) noexcept;
[[nodiscard]] std::string_view GetProtocolTypeName(ProtocolType protocol) noexcept;
[[nodiscard]] std::string_view GetAppProtocolName(ApplicationProtocol protocol) noexcept;
[[nodiscard]] std::string_view GetConnectionDirectionName(ConnectionDirection direction) noexcept;
[[nodiscard]] std::string_view GetFilterActionName(FilterAction action) noexcept;
[[nodiscard]] std::string_view GetBlockReasonName(BlockReason reason) noexcept;
[[nodiscard]] std::string_view GetThreatIndicatorName(ThreatIndicator indicator) noexcept;
[[nodiscard]] std::string_view GetIPAddressTypeName(IPAddressType type) noexcept;
[[nodiscard]] std::string_view GetIPClassificationName(IPClassification classification) noexcept;
[[nodiscard]] std::string_view GetMonitoringLevelName(MonitoringLevel level) noexcept;

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike