/**
 * ============================================================================
 * ShadowStrike Core Network - FIREWALL MANAGER (The Gatekeeper)
 * ============================================================================
 *
 * @file FirewallManager.hpp
 * @brief Enterprise-grade firewall policy management and enforcement system.
 *
 * This module provides comprehensive firewall functionality through direct
 * integration with Windows Filtering Platform (WFP), offering application
 * control, geo-blocking, port management, and advanced network policies.
 *
 * Key Capabilities:
 * =================
 * 1. WINDOWS FILTERING PLATFORM (WFP) INTEGRATION
 *    - Direct kernel-level rule enforcement
 *    - Provider, sublayer, and filter management
 *    - Callout driver coordination
 *    - Transaction-based rule updates
 *    - Persistent and boot-time filters
 *
 * 2. APPLICATION CONTROL
 *    - Per-application network access rules
 *    - Process path-based filtering
 *    - Publisher/certificate-based rules
 *    - Child process inheritance policies
 *    - Application group management
 *
 * 3. GEO-BLOCKING
 *    - Country-based IP blocking
 *    - MaxMind GeoIP database integration
 *    - ASN-based filtering
 *    - Regional policy enforcement
 *    - Geo-fence alerting
 *
 * 4. PORT AND PROTOCOL MANAGEMENT
 *    - Inbound/outbound port rules
 *    - Protocol-specific filtering (TCP/UDP/ICMP)
 *    - Port range support
 *    - Service-based port management
 *    - Dynamic port reservation
 *
 * 5. STEALTH MODE
 *    - ICMP ping blocking
 *    - Port scan prevention
 *    - TCP/UDP stealth responses
 *    - Network discovery hiding
 *    - ARP protection
 *
 * 6. POLICY MANAGEMENT
 *    - Rule prioritization and ordering
 *    - Policy profiles (Home/Work/Public)
 *    - Scheduled rule activation
 *    - Emergency lockdown mode
 *    - Policy import/export
 *
 * WFP Architecture:
 * =================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       Windows Filtering Platform                    │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │                                                                     │
 *   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
 *   │  │  Provider   │  │  Sublayer   │  │   Filter    │                │
 *   │  │ (ShadowFW)  │──│ (Default)   │──│  Objects    │                │
 *   │  └─────────────┘  └─────────────┘  └─────────────┘                │
 *   │         │                                  │                        │
 *   │         │         ┌─────────────┐         │                        │
 *   │         └────────►│   Callout   │◄────────┘                        │
 *   │                   │   Driver    │                                   │
 *   │                   └─────────────┘                                   │
 *   │                          │                                          │
 *   └──────────────────────────┼──────────────────────────────────────────┘
 *                              │
 *                              ▼
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                     FirewallManager                                 │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │WFPEngine     │  │RuleManager   │  │    GeoIPManager          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Sessions   │  │ - CRUD       │  │ - Country Lookup         │  │
 *   │  │ - Providers  │  │ - Ordering   │  │ - ASN Lookup             │  │
 *   │  │ - Filters    │  │ - Profiles   │  │ - Range Blocking         │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │AppControl    │  │PortManager   │  │    StealthMode           │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Per-App    │  │ - Inbound    │  │ - ICMP Block             │  │
 *   │  │ - Publisher  │  │ - Outbound   │  │ - Scan Prevent           │  │
 *   │  │ - Groups     │  │ - Ranges     │  │ - Discovery Hide         │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * WFP Layers Used:
 * ================
 * - FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 (Outbound connections)
 * - FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6 (Inbound connections)
 * - FWPM_LAYER_ALE_AUTH_LISTEN_V4/V6 (Listen operations)
 * - FWPM_LAYER_INBOUND_TRANSPORT_V4/V6 (Transport layer inbound)
 * - FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6 (Transport layer outbound)
 * - FWPM_LAYER_INBOUND_ICMP_ERROR_V4/V6 (ICMP filtering)
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1090: Proxy (Block unauthorized proxies)
 * - T1095: Non-Application Layer Protocol (Protocol filtering)
 * - T1571: Non-Standard Port (Port policy enforcement)
 * - T1048: Exfiltration (Outbound filtering)
 * - T1219: Remote Access Software (Application control)
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - WFP transactions ensure atomicity
 * - Rule updates are transactional
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see NetworkMonitor.hpp for traffic monitoring
 * @see ThreatIntel/ThreatIntelManager.hpp for IP reputation
 */

#pragma once

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
class FirewallManagerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FirewallConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // WFP provider/sublayer GUIDs (defined in implementation)
    // These are placeholder identifiers
    constexpr uint32_t PROVIDER_KEY = 0x5348414457;          // "SHADW"
    constexpr uint32_t SUBLAYER_KEY = 0x53545249;            // "STRI"

    // Limits
    constexpr size_t MAX_RULES = 100000;
    constexpr size_t MAX_APP_RULES = 10000;
    constexpr size_t MAX_PORT_RULES = 5000;
    constexpr size_t MAX_GEO_RULES = 500;
    constexpr size_t MAX_IP_RULES = 100000;
    constexpr size_t MAX_RULE_NAME_LENGTH = 256;
    constexpr size_t MAX_RULE_DESCRIPTION_LENGTH = 1024;

    // Priority ranges (higher = evaluated first)
    constexpr uint32_t PRIORITY_EMERGENCY = 0xFFFF0000;
    constexpr uint32_t PRIORITY_SYSTEM = 0xFFF00000;
    constexpr uint32_t PRIORITY_SHADOWSTRIKE = 0xFF000000;
    constexpr uint32_t PRIORITY_ADMIN = 0xF0000000;
    constexpr uint32_t PRIORITY_HIGH = 0x80000000;
    constexpr uint32_t PRIORITY_NORMAL = 0x40000000;
    constexpr uint32_t PRIORITY_LOW = 0x20000000;
    constexpr uint32_t PRIORITY_DEFAULT = 0x10000000;

    // Timing
    constexpr uint32_t RULE_SYNC_INTERVAL_MS = 30000;
    constexpr uint32_t STATS_UPDATE_INTERVAL_MS = 5000;
    constexpr uint32_t TRANSACTION_TIMEOUT_MS = 10000;

    // Well-known ports
    constexpr uint16_t PORT_ANY = 0;
    constexpr uint16_t PORT_RANGE_START = 1;
    constexpr uint16_t PORT_RANGE_END = 65535;
    constexpr uint16_t EPHEMERAL_PORT_START = 49152;
    constexpr uint16_t EPHEMERAL_PORT_END = 65535;

}  // namespace FirewallConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum RuleAction
 * @brief Action to take when a rule matches.
 */
enum class RuleAction : uint8_t {
    ALLOW = 0,               ///< Permit the connection
    BLOCK = 1,               ///< Block the connection
    ALLOW_BYPASS = 2,        ///< Allow, bypassing other filters
    BLOCK_RESET = 3,         ///< Block with TCP RST
    BLOCK_SILENT = 4,        ///< Block without response
    LOG_ONLY = 5,            ///< Allow but log
    CALLOUT = 6              ///< Defer to callout driver
};

/**
 * @enum RuleDirection
 * @brief Direction of traffic for rule matching.
 */
enum class RuleDirection : uint8_t {
    INBOUND = 0,             ///< Incoming connections
    OUTBOUND = 1,            ///< Outgoing connections
    BOTH = 2                 ///< Bidirectional
};

/**
 * @enum RuleProtocol
 * @brief Protocol types for rule matching.
 */
enum class RuleProtocol : uint8_t {
    ANY = 0,                 ///< Any protocol
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
    GRE = 47,
    ESP = 50,
    AH = 51
};

/**
 * @enum RuleType
 * @brief Type of firewall rule.
 */
enum class RuleType : uint8_t {
    IP = 0,                  ///< IP address-based
    PORT = 1,                ///< Port-based
    APPLICATION = 2,         ///< Application-based
    GEO = 3,                 ///< Geographic
    COMBINED = 4,            ///< Multiple criteria
    CUSTOM = 5               ///< Custom WFP conditions
};

/**
 * @enum NetworkProfile
 * @brief Network profile for context-aware rules.
 */
enum class NetworkProfile : uint8_t {
    ANY = 0,                 ///< All profiles
    DOMAIN = 1,              ///< Domain-joined network
    PRIVATE = 2,             ///< Private/home network
    PUBLIC = 3               ///< Public network
};

/**
 * @enum RulePersistence
 * @brief Rule persistence type.
 */
enum class RulePersistence : uint8_t {
    TEMPORARY = 0,           ///< Cleared on restart
    PERSISTENT = 1,          ///< Survives restart
    BOOT_TIME = 2            ///< Active at boot (before services)
};

/**
 * @enum GeoBlockAction
 * @brief Action for geo-blocking.
 */
enum class GeoBlockAction : uint8_t {
    BLOCK = 0,               ///< Block all traffic
    ALLOW_ONLY = 1,          ///< Allow only listed countries
    LOG_ONLY = 2,            ///< Log but allow
    ALERT = 3                ///< Allow with alert
};

/**
 * @enum StealthMode
 * @brief Stealth mode options.
 */
enum class StealthMode : uint8_t {
    OFF = 0,                 ///< Normal operation
    BASIC = 1,               ///< Block ICMP echo only
    ENHANCED = 2,            ///< + Drop unsolicited inbound
    MAXIMUM = 3              ///< Full stealth (no responses)
};

/**
 * @enum ServiceType
 * @brief Predefined service types.
 */
enum class ServiceType : uint16_t {
    CUSTOM = 0,
    HTTP = 1,
    HTTPS = 2,
    FTP = 3,
    SSH = 4,
    TELNET = 5,
    SMTP = 6,
    DNS = 7,
    DHCP = 8,
    POP3 = 9,
    IMAP = 10,
    SNMP = 11,
    RDP = 12,
    SMB = 13,
    LDAP = 14,
    MYSQL = 15,
    MSSQL = 16,
    POSTGRESQL = 17,
    NTP = 18,
    SYSLOG = 19,
    VNC = 20,
    KERBEROS = 21
};

/**
 * @enum RuleMatchResult
 * @brief Result of rule evaluation.
 */
enum class RuleMatchResult : uint8_t {
    NO_MATCH = 0,
    MATCH_ALLOW = 1,
    MATCH_BLOCK = 2,
    MATCH_LOG = 3,
    MATCH_CALLOUT = 4,
    ERROR = 5
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PortRange
 * @brief Range of ports.
 */
struct alignas(4) PortRange {
    uint16_t start{ 0 };
    uint16_t end{ 0 };

    PortRange() = default;
    PortRange(uint16_t single) : start(single), end(single) {}
    PortRange(uint16_t s, uint16_t e) : start(s), end(e) {}

    [[nodiscard]] bool Contains(uint16_t port) const noexcept {
        return port >= start && port <= end;
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return start <= end && end <= 65535;
    }

    [[nodiscard]] bool IsSinglePort() const noexcept {
        return start == end;
    }
};

/**
 * @struct IPAddressMatch
 * @brief IP address match criteria.
 */
struct alignas(32) IPAddressMatch {
    enum class Type : uint8_t {
        ANY = 0,
        SINGLE = 1,
        RANGE = 2,
        CIDR = 3,
        LIST = 4
    } type{ Type::ANY };

    // For SINGLE
    std::array<uint8_t, 16> address{ 0 };        ///< IPv4 or IPv6
    bool isIPv6{ false };

    // For RANGE
    std::array<uint8_t, 16> rangeEnd{ 0 };

    // For CIDR
    uint8_t prefixLength{ 0 };

    // For LIST
    std::vector<std::array<uint8_t, 16>> addressList;

    [[nodiscard]] bool Matches(const std::array<uint8_t, 16>& ip) const;
    [[nodiscard]] std::wstring ToString() const;
};

/**
 * @struct ApplicationMatch
 * @brief Application match criteria.
 */
struct alignas(64) ApplicationMatch {
    enum class Type : uint8_t {
        ANY = 0,
        PATH = 1,              ///< Exact path match
        PATH_WILDCARD = 2,     ///< Wildcard path
        NAME = 3,              ///< Process name only
        PUBLISHER = 4,         ///< Certificate publisher
        HASH = 5,              ///< File hash
        SERVICE = 6            ///< Windows service name
    } type{ Type::ANY };

    std::wstring path;
    std::wstring processName;
    std::wstring publisher;
    std::array<uint8_t, 32> sha256{ 0 };
    std::wstring serviceName;

    [[nodiscard]] bool Matches(
        const std::wstring& processPath,
        const std::wstring& procName,
        const std::wstring& pub,
        const std::array<uint8_t, 32>& hash
    ) const;
};

/**
 * @struct GeoMatch
 * @brief Geographic match criteria.
 */
struct alignas(32) GeoMatch {
    std::vector<std::string> countryCodes;       ///< ISO 3166-1 alpha-2
    std::vector<std::string> continentCodes;     ///< AF, AN, AS, EU, NA, OC, SA
    std::vector<uint32_t> asnNumbers;            ///< Autonomous System Numbers
    bool isAllowList{ false };                   ///< True = allow only these

    [[nodiscard]] bool Matches(
        const std::string& country,
        const std::string& continent,
        uint32_t asn
    ) const;
};

/**
 * @struct FirewallRule
 * @brief Complete firewall rule definition.
 */
struct alignas(128) FirewallRule {
    // Rule identity
    uint64_t ruleId{ 0 };
    std::wstring name;
    std::wstring description;
    RuleType type{ RuleType::COMBINED };

    // Core action
    RuleAction action{ RuleAction::BLOCK };
    RuleDirection direction{ RuleDirection::BOTH };
    RuleProtocol protocol{ RuleProtocol::ANY };

    // Priority and ordering
    uint32_t priority{ FirewallConstants::PRIORITY_NORMAL };
    uint32_t weight{ 1000 };

    // Match criteria
    IPAddressMatch localAddress;
    IPAddressMatch remoteAddress;
    std::vector<PortRange> localPorts;
    std::vector<PortRange> remotePorts;
    ApplicationMatch application;
    GeoMatch geoMatch;

    // Context
    NetworkProfile profile{ NetworkProfile::ANY };
    bool applyToIPv4{ true };
    bool applyToIPv6{ true };

    // User context
    std::optional<std::wstring> userSid;
    std::optional<std::wstring> userGroup;

    // Schedule
    bool hasSchedule{ false };
    std::chrono::system_clock::time_point scheduleStart;
    std::chrono::system_clock::time_point scheduleEnd;
    std::vector<uint8_t> activeDays;             ///< 0=Sun, 6=Sat
    std::optional<std::pair<uint8_t, uint8_t>> activeHours; ///< Start, end hour

    // Persistence
    RulePersistence persistence{ RulePersistence::PERSISTENT };
    bool isTemporary{ false };
    std::chrono::system_clock::time_point expiresAt;

    // Metadata
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point modifiedAt;
    std::wstring createdBy;
    std::wstring groupName;                      ///< Rule group
    bool isEnabled{ true };
    bool isBuiltIn{ false };                     ///< System rule
    bool isLocked{ false };                      ///< Cannot be modified

    // WFP internal
    uint64_t wfpFilterId{ 0 };                   ///< WFP filter ID when added
    uint64_t wfpFilterId6{ 0 };                  ///< IPv6 filter ID

    // Statistics
    std::atomic<uint64_t> hitCount{ 0 };
    std::atomic<uint64_t> bytesMatched{ 0 };
    std::chrono::system_clock::time_point lastHitTime;

    // Validation
    [[nodiscard]] bool IsValid() const;

    // Factory methods
    static FirewallRule CreateBlockIP(const std::wstring& ip, RuleDirection dir);
    static FirewallRule CreateBlockPort(uint16_t port, RuleProtocol proto, RuleDirection dir);
    static FirewallRule CreateBlockApp(const std::wstring& appPath);
    static FirewallRule CreateAllowApp(const std::wstring& appPath);
    static FirewallRule CreateGeoBlock(const std::vector<std::string>& countries);
};

/**
 * @struct FirewallRuleLegacy
 * @brief Legacy rule structure (backward compatibility).
 */
struct FirewallRuleLegacy {
    std::string id;
    std::wstring appPath;
    uint16_t port{ 0 };
    bool isAllow{ true };

    operator FirewallRule() const;               ///< Conversion to new format
};

using FirewallRuleOld = FirewallRuleLegacy;      ///< Alias for compatibility

/**
 * @struct GeoIPEntry
 * @brief Geographic IP information.
 */
struct alignas(32) GeoIPEntry {
    std::string countryCode;                     ///< ISO 3166-1 alpha-2
    std::string countryName;
    std::string continentCode;
    std::string continentName;
    std::string city;
    std::string region;
    uint32_t asn{ 0 };
    std::string asnOrg;
    double latitude{ 0.0 };
    double longitude{ 0.0 };
    bool isAnonymousProxy{ false };
    bool isSatelliteProvider{ false };
};

/**
 * @struct ConnectionAttempt
 * @brief Record of a connection attempt (for logging/callbacks).
 */
struct alignas(128) ConnectionAttempt {
    // Connection details
    std::array<uint8_t, 16> localIp{ 0 };
    uint16_t localPort{ 0 };
    std::array<uint8_t, 16> remoteIp{ 0 };
    uint16_t remotePort{ 0 };
    RuleProtocol protocol{ RuleProtocol::TCP };
    RuleDirection direction{ RuleDirection::OUTBOUND };
    bool isIPv6{ false };

    // Process context
    uint32_t pid{ 0 };
    std::wstring processPath;
    std::wstring processName;

    // User context
    std::wstring userSid;
    std::wstring userName;

    // Match result
    RuleMatchResult result{ RuleMatchResult::NO_MATCH };
    uint64_t matchedRuleId{ 0 };
    std::wstring matchedRuleName;

    // Geo info
    GeoIPEntry remoteGeo;

    // Timing
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @struct ApplicationNetworkStats
 * @brief Network statistics for an application.
 */
struct alignas(64) ApplicationNetworkStats {
    std::wstring applicationPath;
    uint32_t pid{ 0 };

    std::atomic<uint64_t> connectionsAllowed{ 0 };
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> bytesIn{ 0 };
    std::atomic<uint64_t> bytesOut{ 0 };

    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastActivity;

    void Reset() noexcept;
};

/**
 * @struct FirewallManagerConfig
 * @brief Configuration for the FirewallManager.
 */
struct alignas(64) FirewallManagerConfig {
    // Feature toggles
    bool enabled{ true };
    bool enableIPFiltering{ true };
    bool enablePortFiltering{ true };
    bool enableApplicationControl{ true };
    bool enableGeoBlocking{ false };
    StealthMode stealthMode{ StealthMode::OFF };

    // Default policies
    RuleAction defaultInboundAction{ RuleAction::BLOCK };
    RuleAction defaultOutboundAction{ RuleAction::ALLOW };

    // Network profiles
    bool useNetworkProfiles{ true };
    NetworkProfile defaultProfile{ NetworkProfile::PUBLIC };

    // Geo-blocking
    std::vector<std::string> blockedCountries;
    std::vector<std::string> allowedCountries;   ///< If set, block all others
    std::wstring geoIPDatabasePath;

    // Application control
    bool blockUnknownApplications{ false };
    bool allowSignedApplications{ true };
    std::vector<std::wstring> trustedPublishers;

    // WFP settings
    bool useBootTimeFilters{ false };
    bool useTransactions{ true };
    std::wstring providerName{ L"ShadowStrike Firewall" };
    std::wstring sublayerName{ L"ShadowStrike Filter Layer" };

    // Logging
    bool logAllConnections{ false };
    bool logBlockedOnly{ true };
    bool logApplicationStats{ true };

    // Performance
    uint32_t maxRules{ FirewallConstants::MAX_RULES };
    uint32_t ruleSyncIntervalMs{ FirewallConstants::RULE_SYNC_INTERVAL_MS };
    bool enableRuleCache{ true };

    // Self-protection
    bool protectShadowStrikeRules{ true };
    bool preventRuleBypass{ true };

    // Factory methods
    static FirewallManagerConfig CreateDefault() noexcept;
    static FirewallManagerConfig CreateHighSecurity() noexcept;
    static FirewallManagerConfig CreatePermissive() noexcept;
    static FirewallManagerConfig CreateServerOptimized() noexcept;
};

/**
 * @struct FirewallStatistics
 * @brief Firewall runtime statistics.
 */
struct alignas(128) FirewallStatistics {
    // Connection statistics
    std::atomic<uint64_t> totalConnections{ 0 };
    std::atomic<uint64_t> allowedConnections{ 0 };
    std::atomic<uint64_t> blockedConnections{ 0 };
    std::atomic<uint64_t> loggedConnections{ 0 };

    // Direction breakdown
    std::atomic<uint64_t> inboundAllowed{ 0 };
    std::atomic<uint64_t> inboundBlocked{ 0 };
    std::atomic<uint64_t> outboundAllowed{ 0 };
    std::atomic<uint64_t> outboundBlocked{ 0 };

    // Rule statistics
    std::atomic<uint64_t> ruleEvaluations{ 0 };
    std::atomic<uint64_t> ruleMatches{ 0 };
    std::atomic<uint32_t> activeRuleCount{ 0 };
    std::atomic<uint32_t> wfpFilterCount{ 0 };

    // Feature statistics
    std::atomic<uint64_t> geoBlockedConnections{ 0 };
    std::atomic<uint64_t> appBlockedConnections{ 0 };
    std::atomic<uint64_t> portBlockedConnections{ 0 };

    // Traffic statistics
    std::atomic<uint64_t> bytesAllowed{ 0 };
    std::atomic<uint64_t> bytesBlocked{ 0 };

    // Performance
    std::atomic<uint64_t> avgEvaluationTimeNs{ 0 };
    std::atomic<uint64_t> maxEvaluationTimeNs{ 0 };

    // Errors
    std::atomic<uint64_t> wfpErrors{ 0 };
    std::atomic<uint64_t> ruleErrors{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for connection attempts.
 * @param attempt The connection attempt details
 */
using ConnectionAttemptCallback = std::function<void(const ConnectionAttempt& attempt)>;

/**
 * @brief Callback for rule matches.
 * @param rule The matched rule
 * @param attempt The connection that triggered the match
 */
using RuleMatchCallback = std::function<void(
    const FirewallRule& rule,
    const ConnectionAttempt& attempt
)>;

/**
 * @brief Callback for rule changes.
 * @param rule The changed rule
 * @param isAdded True if added, false if removed
 */
using RuleChangeCallback = std::function<void(
    const FirewallRule& rule,
    bool isAdded
)>;

/**
 * @brief Callback for blocked connections.
 * @param attempt The blocked connection
 * @param blockReason Reason for blocking
 */
using BlockedConnectionCallback = std::function<void(
    const ConnectionAttempt& attempt,
    std::wstring_view blockReason
)>;

/**
 * @brief Callback for application network events.
 * @param appPath Application path
 * @param stats Current statistics
 */
using ApplicationNetworkCallback = std::function<void(
    const std::wstring& appPath,
    const ApplicationNetworkStats& stats
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FirewallManager
 * @brief Enterprise-grade firewall policy management and enforcement.
 *
 * Thread Safety:
 * All public methods are thread-safe. WFP transactions ensure atomicity.
 *
 * Usage Example:
 * @code
 * auto& fw = FirewallManager::Instance();
 * 
 * // Initialize
 * auto config = FirewallManagerConfig::CreateHighSecurity();
 * fw.Initialize(config);
 * 
 * // Block a malicious IP
 * auto rule = FirewallRule::CreateBlockIP(L"192.168.1.100", RuleDirection::BOTH);
 * rule.name = L"Block Malicious IP";
 * fw.AddRule(rule);
 * 
 * // Block an application
 * fw.BlockApplication(L"C:\\Malware\\bad.exe");
 * 
 * // Enable geo-blocking
 * fw.BlockCountry("RU");
 * fw.BlockCountry("CN");
 * 
 * // Enable stealth mode
 * fw.SetStealthMode(StealthMode::ENHANCED);
 * @endcode
 */
class FirewallManager {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance.
     * @return Reference to the singleton.
     */
    static FirewallManager& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the firewall manager.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FirewallManagerConfig& config);

    /**
     * @brief Starts firewall enforcement.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops firewall enforcement.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if firewall is active.
     * @return True if running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Gets current configuration.
     * @return Current config.
     */
    [[nodiscard]] FirewallManagerConfig GetConfig() const;

    /**
     * @brief Updates configuration.
     * @param config New configuration.
     * @return True if successful.
     */
    bool UpdateConfig(const FirewallManagerConfig& config);

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds a new firewall rule.
     * @param rule The rule to add.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t AddRule(const FirewallRule& rule);

    /**
     * @brief Adds a rule (legacy interface).
     * @param rule Legacy rule format.
     * @return True if added.
     */
    bool AddRule(const FirewallRuleLegacy& rule);

    /**
     * @brief Removes a rule by ID.
     * @param ruleId Rule ID.
     * @return True if removed.
     */
    bool RemoveRule(uint64_t ruleId);

    /**
     * @brief Updates an existing rule.
     * @param ruleId Rule ID to update.
     * @param rule New rule definition.
     * @return True if updated.
     */
    bool UpdateRule(uint64_t ruleId, const FirewallRule& rule);

    /**
     * @brief Enables or disables a rule.
     * @param ruleId Rule ID.
     * @param enabled True to enable.
     * @return True if changed.
     */
    bool SetRuleEnabled(uint64_t ruleId, bool enabled);

    /**
     * @brief Gets a rule by ID.
     * @param ruleId Rule ID.
     * @return Rule, or nullopt if not found.
     */
    [[nodiscard]] std::optional<FirewallRule> GetRule(uint64_t ruleId) const;

    /**
     * @brief Gets all rules.
     * @param enabledOnly Only return enabled rules.
     * @return Vector of rules.
     */
    [[nodiscard]] std::vector<FirewallRule> GetAllRules(bool enabledOnly = false) const;

    /**
     * @brief Gets rules by type.
     * @param type Rule type.
     * @return Vector of matching rules.
     */
    [[nodiscard]] std::vector<FirewallRule> GetRulesByType(RuleType type) const;

    /**
     * @brief Gets rules for an application.
     * @param appPath Application path.
     * @return Vector of rules.
     */
    [[nodiscard]] std::vector<FirewallRule> GetRulesForApplication(
        const std::wstring& appPath
    ) const;

    /**
     * @brief Clears all temporary firewall blocks (legacy).
     */
    void ResetFirewall();

    /**
     * @brief Removes all non-system rules.
     */
    void ClearAllRules();

    /**
     * @brief Removes all temporary rules.
     */
    void ClearTemporaryRules();

    // ========================================================================
    // APPLICATION CONTROL
    // ========================================================================

    /**
     * @brief Blocks an application from network access.
     * @param appPath Application path.
     * @param direction Direction to block.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t BlockApplication(
        const std::wstring& appPath,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Allows an application network access.
     * @param appPath Application path.
     * @param direction Direction to allow.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t AllowApplication(
        const std::wstring& appPath,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Removes all rules for an application.
     * @param appPath Application path.
     * @return Number of rules removed.
     */
    uint32_t RemoveApplicationRules(const std::wstring& appPath);

    /**
     * @brief Checks if an application is blocked.
     * @param appPath Application path.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsApplicationBlocked(const std::wstring& appPath) const;

    /**
     * @brief Gets statistics for an application.
     * @param appPath Application path.
     * @return Statistics, or nullopt if not tracked.
     */
    [[nodiscard]] std::optional<ApplicationNetworkStats> GetApplicationStats(
        const std::wstring& appPath
    ) const;

    // ========================================================================
    // IP BLOCKING
    // ========================================================================

    /**
     * @brief Blocks an IP address.
     * @param ip IP address string.
     * @param direction Direction.
     * @param durationMs Duration (0 = permanent).
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t BlockIP(
        const std::wstring& ip,
        RuleDirection direction = RuleDirection::BOTH,
        uint32_t durationMs = 0
    );

    /**
     * @brief Blocks an IP range (CIDR).
     * @param cidr CIDR notation (e.g., "192.168.1.0/24").
     * @param direction Direction.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t BlockIPRange(
        const std::wstring& cidr,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Unblocks an IP address.
     * @param ip IP address.
     * @return True if unblocked.
     */
    bool UnblockIP(const std::wstring& ip);

    /**
     * @brief Checks if an IP is blocked.
     * @param ip IP address.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsIPBlocked(const std::wstring& ip) const;

    /**
     * @brief Gets all blocked IPs.
     * @return Vector of blocked IP strings.
     */
    [[nodiscard]] std::vector<std::wstring> GetBlockedIPs() const;

    // ========================================================================
    // PORT MANAGEMENT
    // ========================================================================

    /**
     * @brief Blocks a port.
     * @param port Port number.
     * @param protocol Protocol.
     * @param direction Direction.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t BlockPort(
        uint16_t port,
        RuleProtocol protocol = RuleProtocol::TCP,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Blocks a port range.
     * @param range Port range.
     * @param protocol Protocol.
     * @param direction Direction.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t BlockPortRange(
        const PortRange& range,
        RuleProtocol protocol = RuleProtocol::TCP,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Unblocks a port.
     * @param port Port number.
     * @param protocol Protocol.
     * @return True if unblocked.
     */
    bool UnblockPort(uint16_t port, RuleProtocol protocol = RuleProtocol::TCP);

    /**
     * @brief Checks if a port is blocked.
     * @param port Port number.
     * @param protocol Protocol.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsPortBlocked(
        uint16_t port,
        RuleProtocol protocol = RuleProtocol::TCP
    ) const;

    /**
     * @brief Opens a port for a service.
     * @param service Service type.
     * @param direction Direction.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t OpenServicePort(
        ServiceType service,
        RuleDirection direction = RuleDirection::INBOUND
    );

    // ========================================================================
    // GEO-BLOCKING
    // ========================================================================

    /**
     * @brief Blocks traffic from/to a country.
     * @param countryCode ISO 3166-1 alpha-2 code.
     * @param direction Direction.
     * @return True if blocked.
     */
    bool BlockCountry(
        const std::string& countryCode,
        RuleDirection direction = RuleDirection::BOTH
    );

    /**
     * @brief Unblocks a country.
     * @param countryCode Country code.
     * @return True if unblocked.
     */
    bool UnblockCountry(const std::string& countryCode);

    /**
     * @brief Sets allowed countries (blocks all others).
     * @param countryCodes List of allowed country codes.
     */
    void SetAllowedCountries(const std::vector<std::string>& countryCodes);

    /**
     * @brief Clears country-based restrictions.
     */
    void ClearGeoRestrictions();

    /**
     * @brief Gets geographic info for an IP.
     * @param ip IP address.
     * @return Geo info, or nullopt if not found.
     */
    [[nodiscard]] std::optional<GeoIPEntry> GetGeoInfo(const std::wstring& ip) const;

    /**
     * @brief Gets blocked countries.
     * @return Vector of blocked country codes.
     */
    [[nodiscard]] std::vector<std::string> GetBlockedCountries() const;

    // ========================================================================
    // STEALTH MODE
    // ========================================================================

    /**
     * @brief Sets stealth mode.
     * @param mode Stealth mode level.
     * @return True if changed.
     */
    bool SetStealthMode(StealthMode mode);

    /**
     * @brief Gets current stealth mode.
     * @return Current mode.
     */
    [[nodiscard]] StealthMode GetStealthMode() const noexcept;

    // ========================================================================
    // NETWORK PROFILES
    // ========================================================================

    /**
     * @brief Gets the current network profile.
     * @return Current profile.
     */
    [[nodiscard]] NetworkProfile GetCurrentProfile() const;

    /**
     * @brief Sets rules for a specific profile.
     * @param profile Network profile.
     * @param rules Rules for the profile.
     * @return True if set.
     */
    bool SetProfileRules(
        NetworkProfile profile,
        const std::vector<FirewallRule>& rules
    );

    // ========================================================================
    // EMERGENCY ACTIONS
    // ========================================================================

    /**
     * @brief Enables emergency lockdown (blocks all traffic).
     * @param reason Reason for lockdown.
     * @return True if activated.
     */
    bool EnableLockdown(std::wstring_view reason = L"");

    /**
     * @brief Disables emergency lockdown.
     * @return True if deactivated.
     */
    bool DisableLockdown();

    /**
     * @brief Checks if lockdown is active.
     * @return True if in lockdown.
     */
    [[nodiscard]] bool IsLockdownActive() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a connection attempt callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterConnectionAttemptCallback(ConnectionAttemptCallback callback);

    /**
     * @brief Registers a rule match callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterRuleMatchCallback(RuleMatchCallback callback);

    /**
     * @brief Registers a rule change callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterRuleChangeCallback(RuleChangeCallback callback);

    /**
     * @brief Registers a blocked connection callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterBlockedConnectionCallback(BlockedConnectionCallback callback);

    /**
     * @brief Registers an application network callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterApplicationCallback(ApplicationNetworkCallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId Callback ID.
     * @return True if unregistered.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================

    /**
     * @brief Exports rules to a file.
     * @param filePath Output file path.
     * @param format Format ("json", "xml", "wfw").
     * @return True if exported.
     */
    bool ExportRules(const std::wstring& filePath, std::wstring_view format = L"json") const;

    /**
     * @brief Imports rules from a file.
     * @param filePath Input file path.
     * @param merge True to merge, false to replace.
     * @return Number of rules imported.
     */
    uint32_t ImportRules(const std::wstring& filePath, bool merge = true);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Gets current statistics.
     * @return Reference to statistics.
     */
    [[nodiscard]] const FirewallStatistics& GetStatistics() const noexcept;

    /**
     * @brief Resets statistics.
     */
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Performs diagnostic check.
     * @return True if healthy.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Tests if WFP is operational.
     * @return True if WFP is working.
     */
    [[nodiscard]] bool TestWFP() const;

    /**
     * @brief Exports diagnostic data.
     * @param outputPath Output path.
     * @return True if exported.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    FirewallManager();
    ~FirewallManager();

    // Non-copyable, non-movable
    FirewallManager(const FirewallManager&) = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;
    FirewallManager(FirewallManager&&) = delete;
    FirewallManager& operator=(FirewallManager&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<FirewallManagerImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
