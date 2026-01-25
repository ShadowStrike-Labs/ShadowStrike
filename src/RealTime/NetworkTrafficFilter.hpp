/**
 * ============================================================================
 * ShadowStrike Real-Time - NETWORK TRAFFIC FILTER (The Gate)
 * ============================================================================
 *
 * @file NetworkTrafficFilter.hpp
 * @brief Enterprise-grade network traffic filtering and inspection.
 *
 * This module provides comprehensive network security capabilities using
 * Windows Filtering Platform (WFP) for kernel-level packet filtering and
 * user-mode deep packet inspection.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **WFP Integration**
 *    - Kernel-level packet filtering via WFP callout driver
 *    - ALE (Application Layer Enforcement) layers
 *    - Stream inspection
 *    - Connection tracking
 *
 * 2. **Firewall Rules**
 *    - IP/port/protocol blocking
 *    - Application-aware rules (process-based)
 *    - Domain-based blocking
 *    - GeoIP filtering
 *    - Time-based rules
 *
 * 3. **Deep Packet Inspection**
 *    - Protocol identification
 *    - SSL/TLS inspection
 *    - HTTP/HTTPS analysis
 *    - DNS monitoring
 *    - Malware traffic detection
 *
 * 4. **C2 (Command & Control) Detection**
 *    - Beacon pattern detection
 *    - Domain generation algorithm (DGA) detection
 *    - DNS tunneling detection
 *    - HTTP tunneling detection
 *    - Encrypted channel analysis
 *
 * 5. **Data Loss Prevention**
 *    - Outbound content inspection
 *    - Sensitive data pattern matching
 *    - Large transfer detection
 *    - Exfiltration blocking
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          KERNEL MODE                                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    WFP Callout Driver                                │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
 * │  │  │ FWPM_LAYER_     │  │ FWPM_LAYER_     │  │ FWPM_LAYER_         │  │   │
 * │  │  │ ALE_AUTH_       │  │ ALE_FLOW_       │  │ STREAM              │  │   │
 * │  │  │ CONNECT_V4/V6   │  │ ESTABLISHED_V4  │  │ V4/V6               │  │   │
 * │  │  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘  │   │
 * │  │           │                    │                      │              │   │
 * │  │           └────────────────────┼──────────────────────┘              │   │
 * │  │                                │                                     │   │
 * │  │                                ▼                                     │   │
 * │  │  ┌─────────────────────────────────────────────────────────────┐   │   │
 * │  │  │              Filter Decision Engine (Kernel)                 │   │   │
 * │  │  │  - Fast path: Rule matching (block/allow)                    │   │   │
 * │  │  │  - Slow path: Forward to user-mode for inspection            │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * └───────────────────────────────────────────┬──────────────────────────────────┘
 *                                             │
 * ════════════════════════════════════════════╪══════════════════════════════════
 *                                             │ IOCTL / FilterSendMessage
 * ════════════════════════════════════════════╪══════════════════════════════════
 *                                             │
 * ┌───────────────────────────────────────────┼──────────────────────────────────┐
 * │                                           ▼                                  │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    NetworkTrafficFilter (User-mode)                  │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐   │   │
 * │  │  │    Rule     │  │   Deep      │  │    C2       │  │   DLP     │   │   │
 * │  │  │   Manager   │  │  Inspection │  │  Detection  │  │  Engine   │   │   │
 * │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘   │   │
 * │  │         │                │                │               │         │   │
 * │  │  ┌──────▼────────────────▼────────────────▼───────────────▼─────┐   │   │
 * │  │  │                   Connection Tracker                          │   │   │
 * │  │  │  - Per-connection state machine                               │   │   │
 * │  │  │  - Process → connection mapping                               │   │   │
 * │  │  │  - Traffic statistics                                         │   │   │
 * │  │  │  - Threat correlation                                         │   │   │
 * │  │  └──────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  │  ┌──────────────────────────────────────────────────────────────┐   │   │
 * │  │  │                   Integration Layer                           │   │   │
 * │  │  │  - ThreatIntel (IP/domain reputation)                         │   │   │
 * │  │  │  - PatternStore (traffic signatures)                          │   │   │
 * │  │  │  - BehaviorAnalyzer (network behavior)                        │   │   │
 * │  │  └──────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │                           USER MODE                                          │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * WFP LAYERS SUPPORTED
 * =============================================================================
 *
 * | Layer                          | Purpose                                  |
 * |--------------------------------|-----------------------------------------|
 * | ALE_AUTH_CONNECT_V4/V6         | Outbound connection authorization       |
 * | ALE_AUTH_RECV_ACCEPT_V4/V6     | Inbound connection authorization        |
 * | ALE_FLOW_ESTABLISHED_V4/V6     | Flow establishment notification         |
 * | INBOUND_TRANSPORT_V4/V6        | Inbound packet inspection               |
 * | OUTBOUND_TRANSPORT_V4/V6       | Outbound packet inspection              |
 * | STREAM_V4/V6                   | Stream data inspection                  |
 * | ALE_RESOURCE_ASSIGNMENT        | Port binding authorization              |
 *
 * =============================================================================
 * C2 DETECTION TECHNIQUES
 * =============================================================================
 *
 * | Technique          | Detection Method                                   |
 * |--------------------|----------------------------------------------------|
 * | Periodic Beaconing | Time-series analysis of connection intervals       |
 * | DGA Domains        | ML-based domain name analysis                      |
 * | DNS Tunneling      | Large DNS TXT records, encoded queries             |
 * | HTTP Tunneling     | Unusual request patterns, response sizes           |
 * | Fast Flux          | Rapid IP rotation for domain                       |
 * | Dead Drop          | Pastebin/GitHub/etc. communication                 |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Description                          | Detection Method         |
 * |-----------|--------------------------------------|--------------------------|
 * | T1071     | Application Layer Protocol           | Protocol analysis        |
 * | T1573     | Encrypted Channel                    | Traffic analysis         |
 * | T1568     | Dynamic Resolution                   | DGA/Fast-flux detection  |
 * | T1572     | Protocol Tunneling                   | DNS/HTTP tunnel detect   |
 * | T1095     | Non-Application Layer Protocol       | Raw socket monitoring    |
 * | T1090     | Proxy                                | Proxy chain detection    |
 * | T1048     | Exfiltration Over Alternative Proto  | Data volume analysis     |
 *
 * @note Thread-safe for all public methods
 * @note Requires WFP callout driver for kernel-level filtering
 *
 * @see ThreatIntelIndex for IP/domain reputation
 * @see BehaviorAnalyzer for network behavior correlation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <guiddef.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace Core {
        namespace Engine {
            class BehaviorAnalyzer;
            class ThreatDetector;
        }
    }
    namespace ThreatIntel {
        class ThreatIntelIndex;
    }
    namespace PatternStore {
        class PatternIndex;
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class NetworkTrafficFilter;
struct NetworkConnection;
struct NetworkEvent;
struct FilterRule;
struct ConnectionStats;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace NetworkFilterConstants {
    // -------------------------------------------------------------------------
    // Connection Tracking
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked connections
    constexpr size_t MAX_TRACKED_CONNECTIONS = 100000;
    
    /// @brief Maximum connections per process
    constexpr size_t MAX_CONNECTIONS_PER_PROCESS = 1000;
    
    /// @brief Connection timeout (idle)
    constexpr std::chrono::minutes CONNECTION_TIMEOUT{ 30 };
    
    /// @brief Maximum connection history
    constexpr size_t MAX_CONNECTION_HISTORY = 50000;
    
    // -------------------------------------------------------------------------
    // Rules
    // -------------------------------------------------------------------------
    
    /// @brief Maximum filter rules
    constexpr size_t MAX_FILTER_RULES = 10000;
    
    /// @brief Maximum blocked IPs
    constexpr size_t MAX_BLOCKED_IPS = 100000;
    
    /// @brief Maximum blocked domains
    constexpr size_t MAX_BLOCKED_DOMAINS = 50000;
    
    // -------------------------------------------------------------------------
    // Inspection
    // -------------------------------------------------------------------------
    
    /// @brief Maximum packet size for inspection
    constexpr size_t MAX_INSPECTION_SIZE = 64 * 1024;  // 64 KB
    
    /// @brief Deep inspection sample size
    constexpr size_t DPI_SAMPLE_SIZE = 4096;
    
    /// @brief DNS query max size
    constexpr size_t MAX_DNS_QUERY_SIZE = 512;
    
    // -------------------------------------------------------------------------
    // Detection Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Beacon interval variance threshold (for regular beaconing)
    constexpr double BEACON_VARIANCE_THRESHOLD = 0.1;
    
    /// @brief Minimum beacon samples for detection
    constexpr size_t MIN_BEACON_SAMPLES = 10;
    
    /// @brief DGA entropy threshold
    constexpr double DGA_ENTROPY_THRESHOLD = 3.5;
    
    /// @brief Large transfer threshold (bytes)
    constexpr size_t LARGE_TRANSFER_THRESHOLD = 100 * 1024 * 1024;  // 100 MB
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief Malicious IP connection score
    constexpr double MALICIOUS_IP_SCORE = 70.0;
    
    /// @brief Malicious domain score
    constexpr double MALICIOUS_DOMAIN_SCORE = 75.0;
    
    /// @brief Beacon detection score
    constexpr double BEACON_DETECTION_SCORE = 60.0;
    
    /// @brief DGA detection score
    constexpr double DGA_DETECTION_SCORE = 65.0;
    
    /// @brief Data exfiltration score
    constexpr double EXFILTRATION_SCORE = 80.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Network protocol type.
 */
enum class NetworkProtocol : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief TCP
    TCP = 6,
    
    /// @brief UDP
    UDP = 17,
    
    /// @brief ICMP
    ICMP = 1,
    
    /// @brief ICMPv6
    ICMPv6 = 58,
    
    /// @brief Raw IP
    RawIP = 255
};

/**
 * @brief Application protocol type.
 */
enum class AppProtocol : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief HTTP
    HTTP = 1,
    
    /// @brief HTTPS
    HTTPS = 2,
    
    /// @brief DNS
    DNS = 3,
    
    /// @brief SMTP
    SMTP = 4,
    
    /// @brief FTP
    FTP = 5,
    
    /// @brief SSH
    SSH = 6,
    
    /// @brief RDP
    RDP = 7,
    
    /// @brief SMB
    SMB = 8,
    
    /// @brief TLS
    TLS = 9,
    
    /// @brief WebSocket
    WebSocket = 10,
    
    /// @brief QUIC
    QUIC = 11
};

/**
 * @brief Connection state.
 */
enum class ConnectionState : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Connecting
    Connecting = 1,
    
    /// @brief Connected (established)
    Established = 2,
    
    /// @brief Closing
    Closing = 3,
    
    /// @brief Closed
    Closed = 4,
    
    /// @brief Blocked
    Blocked = 5,
    
    /// @brief Listen (server socket)
    Listen = 6
};

/**
 * @brief Connection direction.
 */
enum class ConnectionDirection : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Outbound
    Outbound = 1,
    
    /// @brief Inbound
    Inbound = 2,
    
    /// @brief Both (bidirectional)
    Bidirectional = 3
};

/**
 * @brief Filter action.
 */
enum class FilterAction : uint8_t {
    /// @brief Allow traffic
    Allow = 0,
    
    /// @brief Block traffic
    Block = 1,
    
    /// @brief Log and allow
    LogOnly = 2,
    
    /// @brief Inspect (deep packet inspection)
    Inspect = 3,
    
    /// @brief Rate limit
    RateLimit = 4,
    
    /// @brief Redirect
    Redirect = 5,
    
    /// @brief Terminate connection
    Terminate = 6
};

/**
 * @brief Network event type.
 */
enum class NetworkEventType : uint16_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Connection attempt
    ConnectionAttempt = 1,
    
    /// @brief Connection established
    ConnectionEstablished = 2,
    
    /// @brief Connection blocked
    ConnectionBlocked = 3,
    
    /// @brief Connection closed
    ConnectionClosed = 4,
    
    /// @brief Data sent
    DataSent = 5,
    
    /// @brief Data received
    DataReceived = 6,
    
    /// @brief DNS query
    DNSQuery = 7,
    
    /// @brief DNS response
    DNSResponse = 8,
    
    /// @brief Beacon detected
    BeaconDetected = 10,
    
    /// @brief DGA detected
    DGADetected = 11,
    
    /// @brief Tunneling detected
    TunnelingDetected = 12,
    
    /// @brief Exfiltration detected
    ExfiltrationDetected = 13,
    
    /// @brief Malicious destination
    MaliciousDestination = 14
};

/**
 * @brief Detection type.
 */
enum class NetworkDetectionType : uint16_t {
    /// @brief None
    None = 0,
    
    /// @brief C2 beacon
    C2Beacon = 1,
    
    /// @brief DGA domain
    DGADomain = 2,
    
    /// @brief DNS tunneling
    DNSTunneling = 3,
    
    /// @brief HTTP tunneling
    HTTPTunneling = 4,
    
    /// @brief Data exfiltration
    Exfiltration = 5,
    
    /// @brief Fast flux
    FastFlux = 6,
    
    /// @brief Port scan
    PortScan = 7,
    
    /// @brief Lateral movement
    LateralMovement = 8,
    
    /// @brief Cryptomining
    Cryptomining = 9,
    
    /// @brief Known malware traffic
    MalwareTraffic = 10
};

/**
 * @brief IP version.
 */
enum class IPVersion : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief IPv4
    IPv4 = 4,
    
    /// @brief IPv6
    IPv6 = 6
};

/**
 * @brief Get string for FilterAction.
 */
[[nodiscard]] constexpr const char* FilterActionToString(FilterAction action) noexcept;

/**
 * @brief Get MITRE technique for detection type.
 */
[[nodiscard]] constexpr const char* NetworkDetectionToMitre(NetworkDetectionType type) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief IP address (v4 or v6).
 */
struct IPAddress {
    /// @brief IP version
    IPVersion version = IPVersion::Unknown;
    
    /// @brief IPv4 address (network byte order)
    uint32_t ipv4 = 0;
    
    /// @brief IPv6 address (network byte order)
    std::array<uint8_t, 16> ipv6{};
    
    /**
     * @brief Create from string.
     */
    [[nodiscard]] static IPAddress FromString(const std::string& str);
    
    /**
     * @brief Convert to string.
     */
    [[nodiscard]] std::string ToString() const;
    
    /**
     * @brief Check if private/local address.
     */
    [[nodiscard]] bool IsPrivate() const noexcept;
    
    /**
     * @brief Check if loopback.
     */
    [[nodiscard]] bool IsLoopback() const noexcept;
    
    /**
     * @brief Compare.
     */
    bool operator==(const IPAddress& other) const noexcept;
    bool operator!=(const IPAddress& other) const noexcept;
};

/**
 * @brief Hash function for IPAddress.
 */
struct IPAddressHash {
    size_t operator()(const IPAddress& addr) const noexcept;
};

/**
 * @brief Network endpoint (IP + port).
 */
struct NetworkEndpoint {
    /// @brief IP address
    IPAddress address;
    
    /// @brief Port number
    uint16_t port = 0;
    
    /**
     * @brief Convert to string.
     */
    [[nodiscard]] std::string ToString() const;
    
    bool operator==(const NetworkEndpoint& other) const noexcept;
};

/**
 * @brief 5-tuple connection identifier.
 */
struct ConnectionTuple {
    /// @brief Protocol
    NetworkProtocol protocol = NetworkProtocol::Unknown;
    
    /// @brief Local endpoint
    NetworkEndpoint local;
    
    /// @brief Remote endpoint
    NetworkEndpoint remote;
    
    /**
     * @brief Generate hash for lookup.
     */
    [[nodiscard]] uint64_t Hash() const noexcept;
    
    bool operator==(const ConnectionTuple& other) const noexcept;
};

/**
 * @brief Network connection.
 */
struct NetworkConnection {
    /// @brief Connection ID
    uint64_t connectionId = 0;
    
    /// @brief Connection tuple
    ConnectionTuple tuple;
    
    /// @brief Direction
    ConnectionDirection direction = ConnectionDirection::Unknown;
    
    /// @brief State
    ConnectionState state = ConnectionState::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Application protocol
    AppProtocol appProtocol = AppProtocol::Unknown;
    
    /// @brief SNI (Server Name Indication) for TLS
    std::string sni;
    
    /// @brief Resolved domain name
    std::string domainName;
    
    /// @brief Creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Last activity time
    std::chrono::system_clock::time_point lastActivity{};
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Packets sent
    uint64_t packetsSent = 0;
    
    /// @brief Packets received
    uint64_t packetsReceived = 0;
    
    /// @brief Is TLS encrypted
    bool isTLS = false;
    
    /// @brief TLS version
    uint16_t tlsVersion = 0;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Detected threats
    std::vector<NetworkDetectionType> detections;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief Block reason
    std::wstring blockReason;
};

/**
 * @brief Network event.
 */
struct NetworkEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Event type
    NetworkEventType eventType = NetworkEventType::Unknown;
    
    /// @brief Connection ID
    uint64_t connectionId = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Local endpoint
    NetworkEndpoint local;
    
    /// @brief Remote endpoint
    NetworkEndpoint remote;
    
    /// @brief Protocol
    NetworkProtocol protocol = NetworkProtocol::Unknown;
    
    /// @brief Application protocol
    AppProtocol appProtocol = AppProtocol::Unknown;
    
    /// @brief Domain name
    std::string domainName;
    
    /// @brief Data size
    size_t dataSize = 0;
    
    /// @brief Data preview (first N bytes)
    std::vector<uint8_t> dataPreview;
    
    /// @brief Detection type (if detection event)
    NetworkDetectionType detectionType = NetworkDetectionType::None;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Action taken
    FilterAction actionTaken = FilterAction::Allow;
    
    /// @brief MITRE technique
    std::string mitreTechnique;
    
    /// @brief Additional context
    std::map<std::string, std::string> context;
};

/**
 * @brief DNS query event.
 */
struct DNSQueryEvent {
    /// @brief Query ID
    uint16_t queryId = 0;
    
    /// @brief Timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Query domain
    std::string domain;
    
    /// @brief Query type (A, AAAA, TXT, etc.)
    uint16_t queryType = 0;
    
    /// @brief Resolved IPs
    std::vector<IPAddress> resolvedIPs;
    
    /// @brief Response time (ms)
    uint32_t responseTimeMs = 0;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief Is DGA domain
    bool isDGA = false;
    
    /// @brief DGA confidence
    double dgaConfidence = 0.0;
    
    /// @brief Is tunneling
    bool isTunneling = false;
};

/**
 * @brief C2 beacon analysis result.
 */
struct BeaconAnalysis {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Remote endpoint
    NetworkEndpoint remote;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Detected as beacon
    bool isBeacon = false;
    
    /// @brief Confidence (0-100)
    double confidence = 0.0;
    
    /// @brief Average interval (seconds)
    double avgInterval = 0.0;
    
    /// @brief Interval jitter
    double jitter = 0.0;
    
    /// @brief Sample count
    size_t sampleCount = 0;
    
    /// @brief First seen
    std::chrono::system_clock::time_point firstSeen{};
    
    /// @brief Last seen
    std::chrono::system_clock::time_point lastSeen{};
};

/**
 * @brief Filter rule.
 */
struct FilterRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::wstring name;
    
    /// @brief Rule description
    std::wstring description;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Priority (higher = checked first)
    uint32_t priority = 0;
    
    /// @brief Action
    FilterAction action = FilterAction::Block;
    
    /// @brief Direction
    ConnectionDirection direction = ConnectionDirection::Outbound;
    
    /// @brief Protocol (0 = any)
    NetworkProtocol protocol = NetworkProtocol::Unknown;
    
    /// @brief Remote IP (empty = any)
    std::optional<IPAddress> remoteIP;
    
    /// @brief Remote IP subnet mask
    uint8_t remoteSubnetBits = 0;
    
    /// @brief Remote port (0 = any)
    uint16_t remotePort = 0;
    
    /// @brief Remote port range end
    uint16_t remotePortEnd = 0;
    
    /// @brief Domain pattern
    std::optional<std::string> domainPattern;
    
    /// @brief Process name pattern
    std::optional<std::wstring> processPattern;
    
    /// @brief Process path pattern
    std::optional<std::wstring> processPathPattern;
    
    /// @brief Time restriction (start hour, 0-23)
    std::optional<uint8_t> timeStart;
    
    /// @brief Time restriction (end hour, 0-23)
    std::optional<uint8_t> timeEnd;
    
    /// @brief GeoIP country codes to block
    std::vector<std::string> blockedCountries;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief Hit count
    std::atomic<uint64_t> hitCount{ 0 };
    
    /// @brief Last hit time
    std::chrono::system_clock::time_point lastHit{};
    
    /// @brief Created time
    std::chrono::system_clock::time_point created{};
};

/**
 * @brief Configuration for network traffic filter.
 */
struct NetworkFilterConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable filtering
    bool enabled = true;
    
    /// @brief Enable deep packet inspection
    bool deepInspection = true;
    
    /// @brief Enable C2 detection
    bool detectC2 = true;
    
    /// @brief Enable DGA detection
    bool detectDGA = true;
    
    /// @brief Enable data exfiltration detection
    bool detectExfiltration = true;
    
    /// @brief Enable DNS monitoring
    bool monitorDNS = true;
    
    // -------------------------------------------------------------------------
    // Default Actions
    // -------------------------------------------------------------------------
    
    /// @brief Default action for unknown traffic
    FilterAction defaultAction = FilterAction::Allow;
    
    /// @brief Action for malicious IPs
    FilterAction maliciousIPAction = FilterAction::Block;
    
    /// @brief Action for malicious domains
    FilterAction maliciousDomainAction = FilterAction::Block;
    
    /// @brief Action for detected C2
    FilterAction c2Action = FilterAction::Terminate;
    
    /// @brief Action for exfiltration
    FilterAction exfiltrationAction = FilterAction::Block;
    
    // -------------------------------------------------------------------------
    // Detection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Beacon variance threshold
    double beaconVarianceThreshold = NetworkFilterConstants::BEACON_VARIANCE_THRESHOLD;
    
    /// @brief DGA entropy threshold
    double dgaEntropyThreshold = NetworkFilterConstants::DGA_ENTROPY_THRESHOLD;
    
    /// @brief Large transfer threshold (bytes)
    size_t largeTransferThreshold = NetworkFilterConstants::LARGE_TRANSFER_THRESHOLD;
    
    // -------------------------------------------------------------------------
    // Privacy Settings
    // -------------------------------------------------------------------------
    
    /// @brief Block TOR connections
    bool blockTOR = false;
    
    /// @brief Block VPN connections
    bool blockVPN = false;
    
    /// @brief Block proxy connections
    bool blockProxy = false;
    
    // -------------------------------------------------------------------------
    // Performance Settings
    // -------------------------------------------------------------------------
    
    /// @brief Maximum tracked connections
    size_t maxConnections = NetworkFilterConstants::MAX_TRACKED_CONNECTIONS;
    
    /// @brief Connection timeout
    std::chrono::minutes connectionTimeout = NetworkFilterConstants::CONNECTION_TIMEOUT;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static NetworkFilterConfig CreateDefault() noexcept {
        return NetworkFilterConfig{};
    }
    
    /**
     * @brief Create strict configuration.
     */
    [[nodiscard]] static NetworkFilterConfig CreateStrict() noexcept {
        NetworkFilterConfig config;
        config.defaultAction = FilterAction::Block;
        config.blockTOR = true;
        config.blockVPN = true;
        config.blockProxy = true;
        return config;
    }
    
    /**
     * @brief Create monitor-only configuration.
     */
    [[nodiscard]] static NetworkFilterConfig CreateMonitorOnly() noexcept {
        NetworkFilterConfig config;
        config.defaultAction = FilterAction::LogOnly;
        config.maliciousIPAction = FilterAction::LogOnly;
        config.maliciousDomainAction = FilterAction::LogOnly;
        config.c2Action = FilterAction::LogOnly;
        config.exfiltrationAction = FilterAction::LogOnly;
        return config;
    }
};

/**
 * @brief Network filter statistics.
 */
struct NetworkFilterStats {
    /// @brief Total connections tracked
    std::atomic<uint64_t> totalConnections{ 0 };
    
    /// @brief Connections blocked
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    
    /// @brief Connections allowed
    std::atomic<uint64_t> connectionsAllowed{ 0 };
    
    /// @brief Connections terminated
    std::atomic<uint64_t> connectionsTerminated{ 0 };
    
    /// @brief Bytes transferred (outbound)
    std::atomic<uint64_t> bytesOutbound{ 0 };
    
    /// @brief Bytes transferred (inbound)
    std::atomic<uint64_t> bytesInbound{ 0 };
    
    /// @brief DNS queries
    std::atomic<uint64_t> dnsQueries{ 0 };
    
    /// @brief DNS queries blocked
    std::atomic<uint64_t> dnsBlocked{ 0 };
    
    /// @brief C2 beacons detected
    std::atomic<uint64_t> c2Detected{ 0 };
    
    /// @brief DGA domains detected
    std::atomic<uint64_t> dgaDetected{ 0 };
    
    /// @brief Exfiltration attempts detected
    std::atomic<uint64_t> exfiltrationDetected{ 0 };
    
    /// @brief Deep inspections performed
    std::atomic<uint64_t> deepInspections{ 0 };
    
    /// @brief Rules evaluated
    std::atomic<uint64_t> rulesEvaluated{ 0 };
    
    /// @brief Current active connections
    std::atomic<size_t> activeConnections{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalConnections.store(0, std::memory_order_relaxed);
        connectionsBlocked.store(0, std::memory_order_relaxed);
        connectionsAllowed.store(0, std::memory_order_relaxed);
        connectionsTerminated.store(0, std::memory_order_relaxed);
        bytesOutbound.store(0, std::memory_order_relaxed);
        bytesInbound.store(0, std::memory_order_relaxed);
        dnsQueries.store(0, std::memory_order_relaxed);
        dnsBlocked.store(0, std::memory_order_relaxed);
        c2Detected.store(0, std::memory_order_relaxed);
        dgaDetected.store(0, std::memory_order_relaxed);
        exfiltrationDetected.store(0, std::memory_order_relaxed);
        deepInspections.store(0, std::memory_order_relaxed);
        rulesEvaluated.store(0, std::memory_order_relaxed);
        activeConnections.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using ConnectionCallback = std::function<FilterAction(const NetworkConnection&)>;
using NetworkEventCallback = std::function<void(const NetworkEvent&)>;
using DNSCallback = std::function<FilterAction(const DNSQueryEvent&)>;
using C2DetectionCallback = std::function<void(const BeaconAnalysis&)>;
using ExfiltrationCallback = std::function<FilterAction(uint32_t pid, const NetworkEndpoint& remote, size_t dataSize)>;

// ============================================================================
// MAIN NETWORK TRAFFIC FILTER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade network traffic filtering and inspection.
 *
 * Provides comprehensive network security using WFP for kernel-level filtering
 * and user-mode deep packet inspection.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& filter = NetworkTrafficFilter::Instance();
 * 
 * // Initialize
 * NetworkFilterConfig config = NetworkFilterConfig::CreateDefault();
 * filter.Initialize(threadPool, config);
 * 
 * // Set integrations
 * filter.SetThreatIntelIndex(&ThreatIntelIndex::Instance());
 * filter.SetPatternIndex(&PatternIndex::Instance());
 * 
 * // Add blocking rules
 * FilterRule rule;
 * rule.ruleId = "block-tor";
 * rule.name = L"Block TOR Exit Nodes";
 * rule.action = FilterAction::Block;
 * rule.domainPattern = "*.onion";
 * filter.AddRule(rule);
 * 
 * // Block specific IP
 * filter.BlockIP(IPAddress::FromString("192.168.1.100"));
 * 
 * // Register callbacks
 * filter.RegisterC2Callback([](const BeaconAnalysis& beacon) {
 *     LOG_WARN("C2 beacon detected: {} -> {}:{}", 
 *              beacon.processId, beacon.remote.address.ToString(), beacon.remote.port);
 * });
 * 
 * // Start filtering
 * filter.Start();
 * 
 * // Kill active connection
 * filter.KillConnection(pid, remoteIP, remotePort);
 * 
 * // Get connection info
 * auto connections = filter.GetProcessConnections(pid);
 * 
 * filter.Stop();
 * filter.Shutdown();
 * @endcode
 */
class NetworkTrafficFilter {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static NetworkTrafficFilter& Instance();

    // Non-copyable, non-movable
    NetworkTrafficFilter(const NetworkTrafficFilter&) = delete;
    NetworkTrafficFilter& operator=(const NetworkTrafficFilter&) = delete;
    NetworkTrafficFilter(NetworkTrafficFilter&&) = delete;
    NetworkTrafficFilter& operator=(NetworkTrafficFilter&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the filter.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const NetworkFilterConfig& config
    );

    /**
     * @brief Shutdown the filter.
     */
    void Shutdown();

    /**
     * @brief Start filtering.
     */
    void Start();

    /**
     * @brief Stop filtering.
     */
    void Stop();

    /**
     * @brief Check if filter is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const NetworkFilterConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] NetworkFilterConfig GetConfig() const;

    // =========================================================================
    // Connection Management
    // =========================================================================

    /**
     * @brief Handle new connection attempt.
     * @return Action to take.
     */
    [[nodiscard]] FilterAction OnConnectionAttempt(const NetworkConnection& connection);

    /**
     * @brief Handle connection established.
     */
    void OnConnectionEstablished(const NetworkConnection& connection);

    /**
     * @brief Handle connection closed.
     */
    void OnConnectionClosed(uint64_t connectionId);

    /**
     * @brief Handle data transfer.
     */
    void OnDataTransfer(
        uint64_t connectionId,
        bool outbound,
        size_t dataSize,
        std::span<const uint8_t> data
    );

    /**
     * @brief Kill an active connection.
     */
    bool KillConnection(uint32_t pid, const std::string& remoteIP, uint16_t remotePort);

    /**
     * @brief Kill connection by ID.
     */
    bool KillConnection(uint64_t connectionId);

    /**
     * @brief Kill all connections for process.
     */
    size_t KillProcessConnections(uint32_t pid);

    // =========================================================================
    // IP/Domain Blocking
    // =========================================================================

    /**
     * @brief Block an IP address.
     */
    void BlockIP(const IPAddress& ip);

    /**
     * @brief Block an IP address (string).
     */
    void BlockIP(const std::string& ip);

    /**
     * @brief Unblock an IP address.
     */
    void UnblockIP(const IPAddress& ip);

    /**
     * @brief Check if IP is blocked.
     */
    [[nodiscard]] bool IsIPBlocked(const IPAddress& ip) const;

    /**
     * @brief Block a domain.
     */
    void BlockDomain(const std::string& domain);

    /**
     * @brief Unblock a domain.
     */
    void UnblockDomain(const std::string& domain);

    /**
     * @brief Check if domain is blocked.
     */
    [[nodiscard]] bool IsDomainBlocked(const std::string& domain) const;

    /**
     * @brief Get all blocked IPs.
     */
    [[nodiscard]] std::vector<IPAddress> GetBlockedIPs() const;

    /**
     * @brief Get all blocked domains.
     */
    [[nodiscard]] std::vector<std::string> GetBlockedDomains() const;

    /**
     * @brief Load block lists from file.
     */
    bool LoadBlockListFromFile(const std::wstring& filePath);

    // =========================================================================
    // Rule Management
    // =========================================================================

    /**
     * @brief Add filter rule.
     */
    bool AddRule(const FilterRule& rule);

    /**
     * @brief Remove filter rule.
     */
    bool RemoveRule(const std::string& ruleId);

    /**
     * @brief Enable/disable rule.
     */
    void SetRuleEnabled(const std::string& ruleId, bool enabled);

    /**
     * @brief Get rule by ID.
     */
    [[nodiscard]] std::optional<FilterRule> GetRule(const std::string& ruleId) const;

    /**
     * @brief Get all rules.
     */
    [[nodiscard]] std::vector<FilterRule> GetRules() const;

    /**
     * @brief Load rules from file.
     */
    bool LoadRulesFromFile(const std::wstring& filePath);

    /**
     * @brief Save rules to file.
     */
    bool SaveRulesToFile(const std::wstring& filePath) const;

    // =========================================================================
    // DNS Monitoring
    // =========================================================================

    /**
     * @brief Handle DNS query.
     */
    [[nodiscard]] FilterAction OnDNSQuery(const DNSQueryEvent& query);

    /**
     * @brief Get DNS queries for process.
     */
    [[nodiscard]] std::vector<DNSQueryEvent> GetProcessDNSQueries(uint32_t pid) const;

    /**
     * @brief Get recent DNS queries.
     */
    [[nodiscard]] std::vector<DNSQueryEvent> GetRecentDNSQueries(size_t count = 100) const;

    // =========================================================================
    // Detection
    // =========================================================================

    /**
     * @brief Check for C2 beacon pattern.
     */
    [[nodiscard]] BeaconAnalysis AnalyzeBeaconPattern(uint32_t pid, const NetworkEndpoint& remote);

    /**
     * @brief Check if domain is DGA.
     */
    [[nodiscard]] bool IsDGADomain(const std::string& domain) const;

    /**
     * @brief Calculate domain entropy (for DGA detection).
     */
    [[nodiscard]] double CalculateDomainEntropy(const std::string& domain) const;

    /**
     * @brief Check for data exfiltration.
     */
    [[nodiscard]] bool CheckExfiltration(uint32_t pid);

    // =========================================================================
    // Query
    // =========================================================================

    /**
     * @brief Get connection by ID.
     */
    [[nodiscard]] std::optional<NetworkConnection> GetConnection(uint64_t connectionId) const;

    /**
     * @brief Get connections for process.
     */
    [[nodiscard]] std::vector<NetworkConnection> GetProcessConnections(uint32_t pid) const;

    /**
     * @brief Get all active connections.
     */
    [[nodiscard]] std::vector<NetworkConnection> GetActiveConnections() const;

    /**
     * @brief Get connection history.
     */
    [[nodiscard]] std::vector<NetworkConnection> GetConnectionHistory(size_t count = 100) const;

    /**
     * @brief Get connections to IP.
     */
    [[nodiscard]] std::vector<NetworkConnection> GetConnectionsToIP(const IPAddress& ip) const;

    /**
     * @brief Get recent network events.
     */
    [[nodiscard]] std::vector<NetworkEvent> GetRecentEvents(size_t count = 100) const;

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] NetworkFilterStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    /**
     * @brief Get bandwidth usage for process.
     */
    [[nodiscard]] std::pair<uint64_t, uint64_t> GetProcessBandwidth(uint32_t pid) const;

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register connection callback.
     */
    [[nodiscard]] uint64_t RegisterConnectionCallback(ConnectionCallback callback);

    /**
     * @brief Unregister connection callback.
     */
    bool UnregisterConnectionCallback(uint64_t callbackId);

    /**
     * @brief Register network event callback.
     */
    [[nodiscard]] uint64_t RegisterEventCallback(NetworkEventCallback callback);

    /**
     * @brief Unregister event callback.
     */
    bool UnregisterEventCallback(uint64_t callbackId);

    /**
     * @brief Register DNS callback.
     */
    [[nodiscard]] uint64_t RegisterDNSCallback(DNSCallback callback);

    /**
     * @brief Unregister DNS callback.
     */
    bool UnregisterDNSCallback(uint64_t callbackId);

    /**
     * @brief Register C2 detection callback.
     */
    [[nodiscard]] uint64_t RegisterC2Callback(C2DetectionCallback callback);

    /**
     * @brief Unregister C2 callback.
     */
    bool UnregisterC2Callback(uint64_t callbackId);

    /**
     * @brief Register exfiltration callback.
     */
    [[nodiscard]] uint64_t RegisterExfiltrationCallback(ExfiltrationCallback callback);

    /**
     * @brief Unregister exfiltration callback.
     */
    bool UnregisterExfiltrationCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set threat intel index.
     */
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

    /**
     * @brief Set pattern index.
     */
    void SetPatternIndex(PatternStore::PatternIndex* index);

    /**
     * @brief Set behavior analyzer.
     */
    void SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    NetworkTrafficFilter();
    ~NetworkTrafficFilter();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Evaluate rules for connection.
     */
    FilterAction EvaluateRules(const NetworkConnection& connection);

    /**
     * @brief Check IP reputation.
     */
    double GetIPReputation(const IPAddress& ip);

    /**
     * @brief Check domain reputation.
     */
    double GetDomainReputation(const std::string& domain);

    /**
     * @brief Perform deep packet inspection.
     */
    void PerformDPI(uint64_t connectionId, std::span<const uint8_t> data);

    /**
     * @brief Detect application protocol.
     */
    AppProtocol DetectAppProtocol(std::span<const uint8_t> data);

    /**
     * @brief Update beacon analysis.
     */
    void UpdateBeaconAnalysis(uint32_t pid, const NetworkEndpoint& remote);

    /**
     * @brief Connection cleanup thread.
     */
    void ConnectionCleanupThread();

    /**
     * @brief WFP message handler thread.
     */
    void WFPMessageThread();

    /**
     * @brief Invoke connection callbacks.
     */
    FilterAction InvokeConnectionCallbacks(const NetworkConnection& connection);

    /**
     * @brief Invoke event callbacks.
     */
    void InvokeEventCallbacks(const NetworkEvent& event);

    /**
     * @brief Invoke DNS callbacks.
     */
    FilterAction InvokeDNSCallbacks(const DNSQueryEvent& query);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Parse IP address from string.
 */
[[nodiscard]] std::optional<IPAddress> ParseIPAddress(const std::string& str) noexcept;

/**
 * @brief Check if IP is in CIDR range.
 */
[[nodiscard]] bool IsIPInRange(const IPAddress& ip, const IPAddress& network, uint8_t subnetBits) noexcept;

/**
 * @brief Get GeoIP country code for IP.
 */
[[nodiscard]] std::string GetGeoIPCountry(const IPAddress& ip) noexcept;

/**
 * @brief Check if IP is TOR exit node.
 */
[[nodiscard]] bool IsTORExitNode(const IPAddress& ip) noexcept;

/**
 * @brief Extract domain from URL.
 */
[[nodiscard]] std::string ExtractDomainFromURL(const std::string& url) noexcept;

/**
 * @brief Check if domain matches pattern (supports wildcards).
 */
[[nodiscard]] bool DomainMatchesPattern(const std::string& domain, const std::string& pattern) noexcept;

} // namespace RealTime
} // namespace ShadowStrike
