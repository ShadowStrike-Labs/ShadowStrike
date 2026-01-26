/**
 * ============================================================================
 * ShadowStrike Core Network - DNS MONITOR (The Guide)
 * ============================================================================
 *
 * @file DNSMonitor.hpp
 * @brief Enterprise-grade DNS traffic monitoring and threat detection system.
 *
 * This module provides comprehensive DNS visibility and security by intercepting,
 * analyzing, and filtering DNS traffic. It detects DNS-based attacks, tunneling,
 * DGA domains, and DNS poisoning attempts.
 *
 * Key Capabilities:
 * =================
 * 1. DNS QUERY INTERCEPTION
 *    - Capture all DNS queries via ETW (Microsoft-Windows-DNS-Client)
 *    - WFP packet inspection for DNS traffic
 *    - Hook-based interception (Winsock/DNS API)
 *    - Support for standard DNS (UDP/53, TCP/53)
 *    - Support for DoH (DNS over HTTPS) detection
 *    - Support for DoT (DNS over TLS) detection
 *
 * 2. DNS RESPONSE VALIDATION
 *    - Cross-verification with trusted resolvers
 *    - DNSSEC validation support
 *    - DNS spoofing/poisoning detection
 *    - Response integrity verification
 *    - TTL anomaly detection
 *
 * 3. DGA DETECTION (Domain Generation Algorithm)
 *    - Entropy-based analysis
 *    - N-gram frequency analysis
 *    - Character distribution analysis
 *    - Machine learning-based classification
 *    - Known DGA family detection
 *
 * 4. DNS TUNNELING DETECTION
 *    - Query length analysis
 *    - TXT record abuse detection
 *    - Query frequency analysis
 *    - Subdomain entropy analysis
 *    - Payload extraction patterns
 *
 * 5. THREAT INTELLIGENCE INTEGRATION
 *    - Real-time domain reputation checks
 *    - Known malicious domain blocking
 *    - Category-based filtering (malware, phishing, C2)
 *    - Sinkholing support
 *
 * 6. DNS CACHE MANAGEMENT
 *    - Local DNS cache inspection
 *    - Cache poisoning detection
 *    - Forced cache flush capability
 *    - Custom DNS entries injection
 *
 * DNS Attack Coverage:
 * ====================
 * - DNS Spoofing/Poisoning: Response validation
 * - DNS Tunneling: Traffic pattern analysis
 * - DNS Amplification: Query rate limiting
 * - DNS Rebinding: Response filtering
 * - DGA Malware: Algorithmic detection
 * - Fast Flux: IP rotation detection
 * - Domain Shadowing: Subdomain analysis
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1071.004: Application Layer Protocol - DNS
 * - T1568.002: Dynamic Resolution - Domain Generation Algorithms
 * - T1568.001: Dynamic Resolution - Fast Flux DNS
 * - T1048.003: Exfiltration Over Alternative Protocol
 * - T1583.001: Acquire Infrastructure - Domains
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         DNSMonitor                                  │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │QueryCapture  │  │ResponseValid │  │     DGADetector          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - ETW        │  │ - CrossCheck │  │ - Entropy                │  │
 *   │  │ - WFP        │  │ - DNSSEC     │  │ - N-gram                 │  │
 *   │  │ - Hooks      │  │ - Integrity  │  │ - ML Model               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │TunnelDetect  │  │ReputationChk │  │     CacheManager         │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Length     │  │ - ThreatIntel│  │ - Inspection             │  │
 *   │  │ - Frequency  │  │ - Categories │  │ - Flush                  │  │
 *   │  │ - TXT Abuse  │  │ - Sinkhole   │  │ - Injection              │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - DNS cache uses concurrent data structures
 * - Statistics use atomic operations
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see Utils/NetworkUtils.hpp for DNS resolution utilities
 * @see ThreatIntel/ThreatIntelManager.hpp for domain reputation
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // DNS resolution utilities
#include "../../Utils/StringUtils.hpp"        // Domain parsing
#include "../../Utils/CacheManager.hpp"       // DNS cache management
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Domain reputation
#include "../../PatternStore/PatternStore.hpp" // DGA pattern matching
#include "../../Whitelist/WhiteListStore.hpp" // Trusted domains

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
class DNSMonitorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace DNSConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // DNS protocol constants
    constexpr uint16_t DNS_PORT_UDP = 53;
    constexpr uint16_t DNS_PORT_TCP = 53;
    constexpr uint16_t DOH_PORT = 443;
    constexpr uint16_t DOT_PORT = 853;
    constexpr uint16_t MAX_DOMAIN_LENGTH = 253;
    constexpr uint16_t MAX_LABEL_LENGTH = 63;
    constexpr uint16_t MAX_UDP_PAYLOAD = 512;
    constexpr uint16_t MAX_EDNS_PAYLOAD = 4096;

    // Cache limits
    constexpr size_t MAX_CACHE_ENTRIES = 100000;
    constexpr size_t MAX_QUERY_HISTORY = 50000;
    constexpr size_t MAX_BLOCKED_DOMAINS = 100000;
    constexpr uint32_t DEFAULT_CACHE_TTL_SEC = 300;          // 5 minutes
    constexpr uint32_t NEGATIVE_CACHE_TTL_SEC = 60;          // 1 minute

    // DGA detection thresholds
    constexpr double DGA_ENTROPY_THRESHOLD = 3.5;
    constexpr double DGA_CONSONANT_RATIO_MAX = 0.8;
    constexpr uint32_t DGA_MIN_LENGTH = 8;
    constexpr double DGA_ML_THRESHOLD = 0.7;

    // Tunneling detection thresholds
    constexpr size_t TUNNEL_QUERY_LENGTH_THRESHOLD = 50;
    constexpr uint32_t TUNNEL_QUERY_RATE_THRESHOLD = 100;    // Per minute
    constexpr double TUNNEL_SUBDOMAIN_ENTROPY = 4.0;
    constexpr size_t TUNNEL_TXT_SIZE_THRESHOLD = 200;

    // Timing
    constexpr uint32_t VALIDATION_TIMEOUT_MS = 5000;
    constexpr uint32_t STATS_UPDATE_INTERVAL_MS = 5000;
    constexpr uint32_t CLEANUP_INTERVAL_MS = 60000;

    // Trusted resolvers
    constexpr std::string_view GOOGLE_DNS_PRIMARY = "8.8.8.8";
    constexpr std::string_view GOOGLE_DNS_SECONDARY = "8.8.4.4";
    constexpr std::string_view CLOUDFLARE_DNS = "1.1.1.1";
    constexpr std::string_view QUAD9_DNS = "9.9.9.9";

}  // namespace DNSConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum DNSRecordType
 * @brief DNS resource record types.
 */
enum class DNSRecordType : uint16_t {
    A = 1,                   ///< IPv4 address
    NS = 2,                  ///< Name server
    CNAME = 5,               ///< Canonical name
    SOA = 6,                 ///< Start of authority
    PTR = 12,                ///< Pointer
    MX = 15,                 ///< Mail exchange
    TXT = 16,                ///< Text record
    AAAA = 28,               ///< IPv6 address
    SRV = 33,                ///< Service locator
    NAPTR = 35,              ///< Naming authority pointer
    DS = 43,                 ///< Delegation signer
    RRSIG = 46,              ///< DNSSEC signature
    NSEC = 47,               ///< Next secure
    DNSKEY = 48,             ///< DNSSEC key
    NSEC3 = 50,              ///< Next secure v3
    HTTPS = 65,              ///< HTTPS binding
    ANY = 255,               ///< Any record
    CAA = 257                ///< Certification authority authorization
};

/**
 * @enum DNSResponseCode
 * @brief DNS response codes (RCODE).
 */
enum class DNSResponseCode : uint8_t {
    NOERROR = 0,             ///< No error
    FORMERR = 1,             ///< Format error
    SERVFAIL = 2,            ///< Server failure
    NXDOMAIN = 3,            ///< Non-existent domain
    NOTIMP = 4,              ///< Not implemented
    REFUSED = 5,             ///< Query refused
    YXDOMAIN = 6,            ///< Name exists when it should not
    YXRRSET = 7,             ///< RR set exists when it should not
    NXRRSET = 8,             ///< RR set does not exist
    NOTAUTH = 9,             ///< Not authorized
    NOTZONE = 10             ///< Name not in zone
};

/**
 * @enum DNSQueryClass
 * @brief DNS query classes.
 */
enum class DNSQueryClass : uint16_t {
    IN = 1,                  ///< Internet
    CS = 2,                  ///< CSNET (obsolete)
    CH = 3,                  ///< Chaos
    HS = 4,                  ///< Hesiod
    ANY = 255                ///< Any class
};

/**
 * @enum DNSProtocol
 * @brief DNS transport protocol.
 */
enum class DNSProtocol : uint8_t {
    UDP = 0,                 ///< Standard UDP
    TCP = 1,                 ///< TCP (for large responses)
    DOH = 2,                 ///< DNS over HTTPS
    DOT = 3,                 ///< DNS over TLS
    DOQ = 4                  ///< DNS over QUIC
};

/**
 * @enum DomainCategory
 * @brief Domain categorization.
 */
enum class DomainCategory : uint8_t {
    UNKNOWN = 0,
    BENIGN = 1,
    MALWARE = 2,             ///< Known malware domain
    PHISHING = 3,            ///< Phishing site
    C2 = 4,                  ///< Command and control
    SPAM = 5,                ///< Spam source
    ADULT = 6,               ///< Adult content
    GAMBLING = 7,            ///< Gambling site
    CRYPTOMINING = 8,        ///< Cryptomining pool
    BOTNET = 9,              ///< Botnet infrastructure
    RANSOMWARE = 10,         ///< Ransomware infrastructure
    DGA = 11,                ///< DGA-generated domain
    SINKHOLED = 12,          ///< Sinkholed domain
    PARKED = 13,             ///< Parked domain
    NEWLY_REGISTERED = 14,   ///< Recently registered
    TYPOSQUATTING = 15       ///< Typosquatting domain
};

/**
 * @enum DGAFamily
 * @brief Known DGA malware families.
 */
enum class DGAFamily : uint8_t {
    UNKNOWN = 0,
    CONFICKER = 1,
    CRYPTOLOCKER = 2,
    DYRE = 3,
    EMOTET = 4,
    GAMEOVER = 5,
    GOZI = 6,
    LOCKY = 7,
    MATSNU = 8,
    MUROFET = 9,
    NECURS = 10,
    NEWGOZ = 11,
    NYMAIM = 12,
    PADCRYPT = 13,
    PYKSPA = 14,
    QAKBOT = 15,
    RAMDO = 16,
    RANBYUS = 17,
    RAMNIT = 18,
    ROVNIX = 19,
    SHIFU = 20,
    SIMDA = 21,
    SISRON = 22,
    SUPPOBOX = 23,
    SYMMI = 24,
    TINBA = 25,
    TORPIG = 26,
    URLZONE = 27,
    VAWTRAK = 28,
    VIRUT = 29
};

/**
 * @enum DNSFilterAction
 * @brief Action for DNS filtering.
 */
enum class DNSFilterAction : uint8_t {
    ALLOW = 0,
    BLOCK = 1,               ///< Return NXDOMAIN
    SINKHOLE = 2,            ///< Redirect to sinkhole
    LOG_ONLY = 3,            ///< Allow but log
    REDIRECT = 4,            ///< Redirect to specific IP
    DELAY = 5                ///< Delay response
};

/**
 * @enum DNSThreatType
 * @brief DNS-based threat types.
 */
enum class DNSThreatType : uint8_t {
    NONE = 0,
    POISONING = 1,           ///< DNS cache poisoning
    TUNNELING = 2,           ///< DNS tunneling/exfiltration
    DGA_DOMAIN = 3,          ///< DGA-generated domain
    FAST_FLUX = 4,           ///< Fast flux network
    DOMAIN_SHADOWING = 5,    ///< Compromised subdomain
    REBINDING = 6,           ///< DNS rebinding attack
    AMPLIFICATION = 7,       ///< DNS amplification
    TYPOSQUATTING = 8,       ///< Typosquatting/homograph
    KNOWN_BAD = 9            ///< Known malicious domain
};

/**
 * @enum ValidationResult
 * @brief DNS response validation result.
 */
enum class ValidationResult : uint8_t {
    VALID = 0,
    INVALID = 1,
    SPOOFED = 2,
    TIMEOUT = 3,
    MISMATCH = 4,
    DNSSEC_FAIL = 5,
    ERROR = 6
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct DNSQuery
 * @brief DNS query information.
 */
struct alignas(64) DNSQuery {
    // Query identity
    uint64_t queryId{ 0 };
    uint16_t transactionId{ 0 };

    // Query details
    std::string domain;
    DNSRecordType recordType{ DNSRecordType::A };
    DNSQueryClass queryClass{ DNSQueryClass::IN };
    DNSProtocol protocol{ DNSProtocol::UDP };

    // Source
    uint32_t pid{ 0 };
    std::wstring processName;
    std::wstring processPath;

    // Network
    std::string resolverIp;
    uint16_t resolverPort{ DNSConstants::DNS_PORT_UDP };
    std::string sourceIp;
    uint16_t sourcePort{ 0 };

    // Timing
    std::chrono::system_clock::time_point timestamp;

    // Flags
    bool isRecursive{ true };
    bool usesEDNS{ false };
    bool usesDNSSEC{ false };
};

/**
 * @struct DNSResourceRecord
 * @brief DNS resource record from response.
 */
struct alignas(64) DNSResourceRecord {
    std::string name;
    DNSRecordType type{ DNSRecordType::A };
    DNSQueryClass recordClass{ DNSQueryClass::IN };
    uint32_t ttl{ 0 };

    // Record data (varies by type)
    std::variant<
        std::string,                             // A, AAAA (IP string), CNAME, NS, PTR, TXT
        std::vector<std::string>,                // Multiple TXT records
        uint16_t,                                // MX preference
        std::pair<uint16_t, std::string>         // MX (priority, exchange)
    > data;

    // For A/AAAA records
    std::string GetIPString() const;

    // For TXT records
    std::vector<std::string> GetTXTRecords() const;
};

/**
 * @struct DNSResponse
 * @brief DNS response information.
 */
struct alignas(128) DNSResponse {
    // Response identity
    uint64_t queryId{ 0 };                       ///< Matching query ID
    uint16_t transactionId{ 0 };

    // Response details
    std::string domain;
    DNSResponseCode responseCode{ DNSResponseCode::NOERROR };
    bool isAuthoritative{ false };
    bool isTruncated{ false };
    bool isRecursionAvailable{ false };

    // Records
    std::vector<DNSResourceRecord> answers;
    std::vector<DNSResourceRecord> authorities;
    std::vector<DNSResourceRecord> additionals;

    // DNSSEC
    bool isDNSSECValid{ false };
    bool hasDNSSECRecords{ false };

    // Timing
    std::chrono::system_clock::time_point timestamp;
    std::chrono::microseconds latency{ 0 };

    // Validation
    ValidationResult validationResult{ ValidationResult::VALID };
    std::wstring validationMessage;
};

/**
 * @struct DNSRequest
 * @brief Combined DNS request/response (legacy compatibility).
 */
struct alignas(64) DNSRequest {
    std::string domain;
    std::string resolvedIp;
    uint32_t processId{ 0 };
    std::wstring processName;
    std::chrono::system_clock::time_point timestamp;
    bool wasBlocked{ false };
    std::wstring blockReason;
};

/**
 * @struct DGAAnalysis
 * @brief DGA detection analysis results.
 */
struct alignas(64) DGAAnalysis {
    std::string domain;

    // Entropy analysis
    double entropy{ 0.0 };
    double labelEntropy{ 0.0 };                  ///< Per-label entropy

    // Character analysis
    double consonantRatio{ 0.0 };
    double vowelRatio{ 0.0 };
    double digitRatio{ 0.0 };
    double hyphenRatio{ 0.0 };

    // N-gram analysis
    double bigramFrequency{ 0.0 };
    double trigramFrequency{ 0.0 };
    uint32_t uncommonBigrams{ 0 };

    // Length analysis
    size_t totalLength{ 0 };
    size_t maxLabelLength{ 0 };
    size_t labelCount{ 0 };

    // ML score
    double mlScore{ 0.0 };                       ///< 0-1 DGA probability
    std::wstring mlModelUsed;

    // Result
    bool isDGA{ false };
    double confidence{ 0.0 };                    ///< 0-1 confidence
    DGAFamily detectedFamily{ DGAFamily::UNKNOWN };
};

/**
 * @struct TunnelingAnalysis
 * @brief DNS tunneling detection analysis.
 */
struct alignas(64) TunnelingAnalysis {
    std::string baseDomain;
    uint32_t pid{ 0 };

    // Query patterns
    uint32_t queryCount{ 0 };                    ///< In analysis window
    uint32_t queriesPerMinute{ 0 };
    double avgQueryLength{ 0.0 };
    double maxQueryLength{ 0.0 };

    // Subdomain analysis
    uint32_t uniqueSubdomains{ 0 };
    double subdomainEntropy{ 0.0 };
    double avgSubdomainLength{ 0.0 };

    // TXT record analysis
    uint32_t txtQueries{ 0 };
    double avgTxtResponseSize{ 0.0 };

    // Data volume
    uint64_t estimatedDataOut{ 0 };              ///< Encoded in queries
    uint64_t estimatedDataIn{ 0 };               ///< In TXT responses

    // Result
    bool isTunneling{ false };
    double confidence{ 0.0 };
    std::wstring tunnelingType;                  ///< e.g., "iodine", "dnscat2"
};

/**
 * @struct DNSCacheEntry
 * @brief Cached DNS resolution.
 */
struct alignas(64) DNSCacheEntry {
    std::string domain;
    DNSRecordType recordType{ DNSRecordType::A };
    std::vector<DNSResourceRecord> records;

    std::chrono::system_clock::time_point cachedAt;
    std::chrono::system_clock::time_point expiresAt;
    uint32_t ttl{ 0 };

    // Source
    std::string resolverIp;
    bool isNegativeCache{ false };               ///< NXDOMAIN cached

    // Validation
    ValidationResult lastValidation{ ValidationResult::VALID };
    std::chrono::system_clock::time_point lastValidated;

    // Statistics
    std::atomic<uint64_t> hitCount{ 0 };
    std::chrono::system_clock::time_point lastAccess;
};

/**
 * @struct DomainReputation
 * @brief Domain reputation information.
 */
struct alignas(64) DomainReputation {
    std::string domain;
    DomainCategory category{ DomainCategory::UNKNOWN };
    uint8_t riskScore{ 0 };                      ///< 0-100

    // Threat intelligence
    bool isKnownBad{ false };
    std::wstring threatName;
    std::vector<std::wstring> tags;

    // Metadata
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    uint64_t globalPrevalence{ 0 };
    uint32_t ageInDays{ 0 };

    // WHOIS data (if available)
    std::wstring registrar;
    std::wstring registrationDate;
    std::wstring registrantCountry;

    // Source
    std::wstring source;                         ///< Feed/database source
    std::chrono::system_clock::time_point updatedAt;
};

/**
 * @struct DNSFilterRule
 * @brief DNS filtering rule.
 */
struct alignas(64) DNSFilterRule {
    // Rule identity
    uint64_t ruleId{ 0 };
    std::wstring name;
    std::wstring description;

    // Match criteria
    std::string domainPattern;                   ///< Supports wildcards (*.example.com)
    bool isRegex{ false };
    std::optional<DomainCategory> categoryMatch;
    std::optional<uint8_t> minRiskScore;
    std::optional<uint32_t> pidMatch;
    std::optional<std::wstring> processMatch;

    // Action
    DNSFilterAction action{ DNSFilterAction::BLOCK };
    std::string sinkholeTo;                      ///< For SINKHOLE action
    std::string redirectTo;                      ///< For REDIRECT action

    // Timing
    bool isTemporary{ false };
    std::chrono::system_clock::time_point expiresAt;

    // Metadata
    std::chrono::system_clock::time_point createdAt;
    std::wstring createdBy;
    bool isEnabled{ true };
    uint32_t priority{ 1000 };

    // Statistics
    std::atomic<uint64_t> hitCount{ 0 };

    [[nodiscard]] bool Matches(const std::string& domain) const;
};

/**
 * @struct DNSEvent
 * @brief DNS monitoring event.
 */
struct alignas(64) DNSEvent {
    // Event identity
    uint64_t eventId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    enum class Type : uint8_t {
        QUERY = 0,
        RESPONSE = 1,
        BLOCKED = 2,
        POISONING_DETECTED = 3,
        TUNNELING_DETECTED = 4,
        DGA_DETECTED = 5,
        CACHE_POISONED = 6,
        VALIDATION_FAILED = 7
    } type{ Type::QUERY };

    // Domain
    std::string domain;

    // Process context
    uint32_t pid{ 0 };
    std::wstring processName;

    // Details
    std::variant<
        DNSQuery,                                // QUERY
        DNSResponse,                             // RESPONSE
        DNSFilterRule,                           // BLOCKED
        ValidationResult,                        // POISONING_DETECTED, VALIDATION_FAILED
        TunnelingAnalysis,                       // TUNNELING_DETECTED
        DGAAnalysis                              // DGA_DETECTED
    > details;
};

/**
 * @struct DNSMonitorConfig
 * @brief Configuration for DNS monitoring.
 */
struct alignas(64) DNSMonitorConfig {
    // Feature toggles
    bool enabled{ true };
    bool captureQueries{ true };
    bool captureResponses{ true };
    bool validateResponses{ true };
    bool detectDGA{ true };
    bool detectTunneling{ true };
    bool checkReputation{ true };
    bool enableFiltering{ true };
    bool enableCaching{ true };

    // Capture methods
    bool useETW{ true };
    bool useWFP{ true };
    bool useHooks{ false };                      ///< More invasive

    // Validation settings
    std::vector<std::string> trustedResolvers;
    uint32_t validationTimeoutMs{ DNSConstants::VALIDATION_TIMEOUT_MS };
    bool validateAllResponses{ false };          ///< Performance impact
    bool requireDNSSEC{ false };

    // DGA detection
    double dgaEntropyThreshold{ DNSConstants::DGA_ENTROPY_THRESHOLD };
    double dgaMLThreshold{ DNSConstants::DGA_ML_THRESHOLD };
    bool useDGAML{ true };

    // Tunneling detection
    size_t tunnelingQueryThreshold{ DNSConstants::TUNNEL_QUERY_LENGTH_THRESHOLD };
    uint32_t tunnelingRateThreshold{ DNSConstants::TUNNEL_QUERY_RATE_THRESHOLD };
    uint32_t tunnelingWindowMs{ 60000 };

    // Cache settings
    size_t maxCacheEntries{ DNSConstants::MAX_CACHE_ENTRIES };
    uint32_t defaultTTLSec{ DNSConstants::DEFAULT_CACHE_TTL_SEC };
    uint32_t negativeTTLSec{ DNSConstants::NEGATIVE_CACHE_TTL_SEC };

    // Performance
    uint32_t maxQueriesPerSecond{ 10000 };
    bool enableSampling{ false };
    uint32_t sampleRate{ 100 };                  ///< 1 in N

    // Logging
    bool logAllQueries{ false };
    bool logBlockedOnly{ true };
    bool logResponses{ false };

    // Factory methods
    static DNSMonitorConfig CreateDefault() noexcept;
    static DNSMonitorConfig CreateHighSecurity() noexcept;
    static DNSMonitorConfig CreatePerformance() noexcept;
    static DNSMonitorConfig CreateForensic() noexcept;
};

/**
 * @struct DNSStatistics
 * @brief DNS monitoring statistics.
 */
struct alignas(128) DNSStatistics {
    // Query statistics
    std::atomic<uint64_t> totalQueries{ 0 };
    std::atomic<uint64_t> queriesA{ 0 };
    std::atomic<uint64_t> queriesAAAA{ 0 };
    std::atomic<uint64_t> queriesTXT{ 0 };
    std::atomic<uint64_t> queriesMX{ 0 };
    std::atomic<uint64_t> queriesOther{ 0 };

    // Response statistics
    std::atomic<uint64_t> totalResponses{ 0 };
    std::atomic<uint64_t> responsesNoError{ 0 };
    std::atomic<uint64_t> responsesNXDomain{ 0 };
    std::atomic<uint64_t> responsesServFail{ 0 };
    std::atomic<uint64_t> responsesRefused{ 0 };

    // Filtering statistics
    std::atomic<uint64_t> domainsBlocked{ 0 };
    std::atomic<uint64_t> domainsSinkholed{ 0 };
    std::atomic<uint64_t> domainsRedirected{ 0 };

    // Threat statistics
    std::atomic<uint64_t> dgaDetections{ 0 };
    std::atomic<uint64_t> tunnelingDetections{ 0 };
    std::atomic<uint64_t> poisoningDetections{ 0 };
    std::atomic<uint64_t> validationFailures{ 0 };

    // Cache statistics
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };
    std::atomic<uint32_t> cacheSize{ 0 };

    // Performance
    std::atomic<uint64_t> avgLatencyUs{ 0 };
    std::atomic<uint64_t> maxLatencyUs{ 0 };
    std::atomic<uint64_t> queriesPerSecond{ 0 };

    // Errors
    std::atomic<uint64_t> errorCount{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for DNS query events.
 */
using DNSQueryCallback = std::function<void(const DNSQuery& query)>;

/**
 * @brief Callback for DNS response events.
 */
using DNSResponseCallback = std::function<void(const DNSResponse& response)>;

/**
 * @brief Callback for DNS events.
 */
using DNSEventCallback = std::function<void(const DNSEvent& event)>;

/**
 * @brief Callback for DGA detection.
 */
using DGADetectionCallback = std::function<void(
    const std::string& domain,
    const DGAAnalysis& analysis
)>;

/**
 * @brief Callback for tunneling detection.
 */
using TunnelingDetectionCallback = std::function<void(
    const std::string& domain,
    const TunnelingAnalysis& analysis
)>;

/**
 * @brief Callback for poisoning detection.
 */
using PoisoningDetectionCallback = std::function<void(
    const std::string& domain,
    const std::string& expectedIp,
    const std::string& actualIp
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DNSMonitor
 * @brief Enterprise-grade DNS monitoring and threat detection system.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& monitor = DNSMonitor::Instance();
 * 
 * // Configure
 * auto config = DNSMonitorConfig::CreateHighSecurity();
 * config.trustedResolvers = {"8.8.8.8", "1.1.1.1"};
 * monitor.Initialize(config);
 * 
 * // Register DGA callback
 * monitor.RegisterDGACallback([](const std::string& domain, const DGAAnalysis& analysis) {
 *     if (analysis.isDGA) {
 *         BlockDomain(domain);
 *     }
 * });
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // Check if a domain might be DGA
 * auto analysis = monitor.AnalyzeDGA("xvkdf8s9df.com");
 * @endcode
 */
class DNSMonitor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance.
     * @return Reference to the singleton.
     */
    [[nodiscard]] static DNSMonitor& Instance() noexcept;

    /**
     * @brief Checks if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the DNS monitor.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const DNSMonitorConfig& config);

    /**
     * @brief Start capturing local DNS queries.
     */
    void Start();

    /**
     * @brief Stops DNS monitoring.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if DNS monitor is initialized.
     * @return True if initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Checks if monitoring is active.
     * @return True if running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Gets current configuration.
     * @return Current config.
     */
    [[nodiscard]] DNSMonitorConfig GetConfig() const;

    /**
     * @brief Updates configuration.
     * @param config New configuration.
     * @return True if successful.
     */
    bool UpdateConfig(const DNSMonitorConfig& config);

    // ========================================================================
    // DNS VALIDATION
    // ========================================================================

    /**
     * @brief Check if a DNS resolution was spoofed (legacy interface).
     * @param domain Domain name.
     * @param ip Resolved IP.
     * @return True if poisoned/spoofed.
     */
    [[nodiscard]] bool IsPoisoned(const std::string& domain, const std::string& ip);

    /**
     * @brief Validates a DNS response against trusted resolvers.
     * @param domain Domain name.
     * @param response The response to validate.
     * @return Validation result.
     */
    [[nodiscard]] ValidationResult ValidateResponse(
        const std::string& domain,
        const DNSResponse& response
    );

    /**
     * @brief Cross-checks resolution with trusted resolvers.
     * @param domain Domain name.
     * @param ips IPs to validate.
     * @return True if valid.
     */
    [[nodiscard]] bool CrossValidate(
        const std::string& domain,
        const std::vector<std::string>& ips
    );

    // ========================================================================
    // DGA DETECTION
    // ========================================================================

    /**
     * @brief Analyzes a domain for DGA characteristics.
     * @param domain Domain to analyze.
     * @return DGA analysis results.
     */
    [[nodiscard]] DGAAnalysis AnalyzeDGA(const std::string& domain) const;

    /**
     * @brief Checks if a domain is likely DGA-generated.
     * @param domain Domain to check.
     * @return True if likely DGA.
     */
    [[nodiscard]] bool IsDGA(const std::string& domain) const;

    /**
     * @brief Gets the DGA family for a domain.
     * @param domain Domain to check.
     * @return DGA family, or UNKNOWN.
     */
    [[nodiscard]] DGAFamily GetDGAFamily(const std::string& domain) const;

    // ========================================================================
    // TUNNELING DETECTION
    // ========================================================================

    /**
     * @brief Analyzes DNS traffic for tunneling.
     * @param baseDomain Base domain to analyze.
     * @param pid Optional process ID filter.
     * @return Tunneling analysis results.
     */
    [[nodiscard]] TunnelingAnalysis AnalyzeTunneling(
        const std::string& baseDomain,
        std::optional<uint32_t> pid = std::nullopt
    ) const;

    /**
     * @brief Checks if tunneling is detected for a domain.
     * @param baseDomain Base domain.
     * @return True if tunneling detected.
     */
    [[nodiscard]] bool IsTunneling(const std::string& baseDomain) const;

    // ========================================================================
    // DOMAIN REPUTATION
    // ========================================================================

    /**
     * @brief Gets reputation for a domain.
     * @param domain Domain name.
     * @return Reputation information.
     */
    [[nodiscard]] DomainReputation GetReputation(const std::string& domain) const;

    /**
     * @brief Checks if a domain is known malicious.
     * @param domain Domain name.
     * @return True if malicious.
     */
    [[nodiscard]] bool IsMalicious(const std::string& domain) const;

    /**
     * @brief Gets the category for a domain.
     * @param domain Domain name.
     * @return Domain category.
     */
    [[nodiscard]] DomainCategory GetCategory(const std::string& domain) const;

    // ========================================================================
    // FILTERING
    // ========================================================================

    /**
     * @brief Adds a domain filter rule.
     * @param rule The filter rule.
     * @return Rule ID, or 0 on failure.
     */
    [[nodiscard]] uint64_t AddFilterRule(const DNSFilterRule& rule);

    /**
     * @brief Removes a filter rule.
     * @param ruleId Rule ID.
     * @return True if removed.
     */
    bool RemoveFilterRule(uint64_t ruleId);

    /**
     * @brief Blocks a domain.
     * @param domain Domain to block.
     * @param reason Reason for blocking.
     * @return True if blocked.
     */
    bool BlockDomain(const std::string& domain, std::wstring_view reason = L"");

    /**
     * @brief Unblocks a domain.
     * @param domain Domain to unblock.
     * @return True if unblocked.
     */
    bool UnblockDomain(const std::string& domain);

    /**
     * @brief Sinkholes a domain.
     * @param domain Domain to sinkhole.
     * @param sinkholeTo IP to redirect to.
     * @return True if successful.
     */
    bool SinkholeDomain(const std::string& domain, const std::string& sinkholeTo);

    /**
     * @brief Gets all filter rules.
     * @return Vector of filter rules.
     */
    [[nodiscard]] std::vector<DNSFilterRule> GetFilterRules() const;

    /**
     * @brief Checks if a domain is blocked.
     * @param domain Domain to check.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsBlocked(const std::string& domain) const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Queries the DNS cache.
     * @param domain Domain to look up.
     * @param recordType Record type.
     * @return Cached entry, or nullopt.
     */
    [[nodiscard]] std::optional<DNSCacheEntry> QueryCache(
        const std::string& domain,
        DNSRecordType recordType = DNSRecordType::A
    ) const;

    /**
     * @brief Adds an entry to the cache.
     * @param entry Cache entry.
     */
    void AddCacheEntry(const DNSCacheEntry& entry);

    /**
     * @brief Invalidates a cache entry.
     * @param domain Domain to invalidate.
     */
    void InvalidateCache(const std::string& domain);

    /**
     * @brief Flushes the entire cache.
     */
    void FlushCache();

    /**
     * @brief Gets cache size.
     * @return Number of entries.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    /**
     * @brief Inspects system DNS cache for poisoning.
     * @return Vector of suspicious entries.
     */
    [[nodiscard]] std::vector<DNSCacheEntry> InspectSystemCache() const;

    // ========================================================================
    // QUERY HISTORY
    // ========================================================================

    /**
     * @brief Gets recent DNS queries.
     * @param maxCount Maximum queries to return.
     * @param pid Optional process filter.
     * @return Vector of queries.
     */
    [[nodiscard]] std::vector<DNSQuery> GetRecentQueries(
        size_t maxCount = 100,
        std::optional<uint32_t> pid = std::nullopt
    ) const;

    /**
     * @brief Gets queries for a specific domain.
     * @param domain Domain to search.
     * @return Vector of matching queries.
     */
    [[nodiscard]] std::vector<DNSQuery> GetQueriesForDomain(const std::string& domain) const;

    /**
     * @brief Gets top queried domains.
     * @param count Number of domains.
     * @return Vector of (domain, count) pairs.
     */
    [[nodiscard]] std::vector<std::pair<std::string, uint64_t>> GetTopDomains(
        size_t count = 10
    ) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a DNS query callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterQueryCallback(DNSQueryCallback callback);

    /**
     * @brief Registers a DNS response callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterResponseCallback(DNSResponseCallback callback);

    /**
     * @brief Registers a DNS event callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterEventCallback(DNSEventCallback callback);

    /**
     * @brief Registers a DGA detection callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterDGACallback(DGADetectionCallback callback);

    /**
     * @brief Registers a tunneling detection callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterTunnelingCallback(TunnelingDetectionCallback callback);

    /**
     * @brief Registers a poisoning detection callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterPoisoningCallback(PoisoningDetectionCallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId Callback ID.
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
    [[nodiscard]] const DNSStatistics& GetStatistics() const noexcept;

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
     * @brief Exports diagnostic data.
     * @param outputPath Output path.
     * @return True if successful.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

    /**
     * @brief Performs self-test of DNS monitor functionality.
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
     * @brief Calculates Shannon entropy of a string.
     * @param str String to analyze.
     * @return Entropy value.
     */
    [[nodiscard]] static double CalculateEntropy(std::string_view str);

    /**
     * @brief Extracts base domain from FQDN.
     * @param fqdn Fully qualified domain name.
     * @return Base domain (e.g., "example.com").
     */
    [[nodiscard]] static std::string GetBaseDomain(const std::string& fqdn);

    /**
     * @brief Checks if a domain is a valid format.
     * @param domain Domain to validate.
     * @return True if valid.
     */
    [[nodiscard]] static bool IsValidDomain(std::string_view domain);

    /**
     * @brief Gets record type name.
     * @param type Record type.
     * @return Type name string.
     */
    [[nodiscard]] static std::string_view GetRecordTypeName(DNSRecordType type) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    DNSMonitor();
    ~DNSMonitor();

    // Non-copyable, non-movable
    DNSMonitor(const DNSMonitor&) = delete;
    DNSMonitor& operator=(const DNSMonitor&) = delete;
    DNSMonitor(DNSMonitor&&) = delete;
    DNSMonitor& operator=(DNSMonitor&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<DNSMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetRecordTypeName(DNSRecordType type) noexcept;
[[nodiscard]] std::string_view GetResponseCodeName(DNSResponseCode code) noexcept;
[[nodiscard]] std::string_view GetProtocolName(DNSProtocol protocol) noexcept;
[[nodiscard]] std::string_view GetDomainCategoryName(DomainCategory category) noexcept;
[[nodiscard]] std::string_view GetThreatTypeName(DNSThreatType threat) noexcept;
[[nodiscard]] std::string_view GetDGAFamilyName(DGAFamily family) noexcept;
[[nodiscard]] std::string_view GetFilterActionName(DNSFilterAction action) noexcept;
[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept;

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
