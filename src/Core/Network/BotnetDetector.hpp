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
 * ShadowStrike Core Network - BOTNET DETECTOR (The Network Sentry)
 * ============================================================================
 *
 * @file BotnetDetector.hpp
 * @brief Enterprise-grade botnet and C2 (Command & Control) detection engine.
 *
 * This module provides comprehensive detection of botnet infections through
 * analysis of network behavior patterns, C2 communication signatures, and
 * machine learning-based anomaly detection.
 *
 * Key Capabilities:
 * =================
 * 1. BEACONING DETECTION
 *    - Constant-interval heartbeat detection
 *    - Jittered beacon analysis
 *    - Statistical interval analysis
 *    - Sleep timer fingerprinting
 *    - Multi-connection correlation
 *
 * 2. C2 PROTOCOL DETECTION
 *    - HTTP-based C2 (Cobalt Strike, Meterpreter, etc.)
 *    - DNS-based C2 tunneling
 *    - IRC C2 patterns
 *    - Custom binary protocols
 *    - Encrypted channel detection
 *
 * 3. DGA DETECTION
 *    - Domain Generation Algorithm detection
 *    - Entropy-based analysis
 *    - N-gram frequency analysis
 *    - ML-based classification
 *    - Dictionary word detection
 *
 * 4. BOTNET FAMILY IDENTIFICATION
 *    - Behavioral fingerprinting
 *    - Protocol signature matching
 *    - C2 infrastructure correlation
 *    - YARA-based detection
 *    - Threat intelligence integration
 *
 * 5. PEER-TO-PEER BOTNET DETECTION
 *    - P2P overlay network detection
 *    - Super-peer identification
 *    - DHT-based C2 detection
 *    - Decentralized botnet patterns
 *
 * Detection Architecture:
 * =======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        BotnetDetector                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │BeaconAnalyzer│  │ C2Detector   │  │     DGAAnalyzer          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Intervals  │  │ - HTTP C2    │  │ - Entropy Analysis       │  │
 *   │  │ - Jitter     │  │ - DNS C2     │  │ - N-gram Analysis        │  │
 *   │  │ - Patterns   │  │ - IRC C2     │  │ - ML Classification      │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │FamilyDetect  │  │ P2PDetector  │  │   ThreatIntelCorrelator  │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Signatures │  │ - DHT        │  │ - IoC Matching           │  │
 *   │  │ - Behaviors  │  │ - Super-peer │  │ - C2 Infrastructure      │  │
 *   │  │ - YARA       │  │ - Overlay    │  │ - Attribution            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Supported Botnet Families:
 * ==========================
 * - Cobalt Strike Beacons
 * - Meterpreter/Metasploit
 * - Emotet
 * - TrickBot
 * - QakBot (QBot)
 * - Dridex
 * - IcedID
 * - BazarLoader
 * - Ryuk/Conti
 * - Zeus variants
 * - Mirai variants
 * - Custom/Unknown
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1071: Application Layer Protocol
 * - T1071.001: Web Protocols
 * - T1071.004: DNS
 * - T1095: Non-Application Layer Protocol
 * - T1568: Dynamic Resolution
 * - T1568.002: Domain Generation Algorithms
 * - T1573: Encrypted Channel
 * - T1102: Web Service
 * - T1090: Proxy
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Lock-free statistics updates
 * - Concurrent connection analysis
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see NetworkMonitor.hpp for connection tracking
 * @see DNSMonitor.hpp for DNS analysis
 * @see ThreatIntel for C2 indicators
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/StringUtils.hpp"        // Domain analysis
#include "../../PatternStore/PatternStore.hpp" // C2/DGA patterns
#include "../../SignatureStore/SignatureStore.hpp" // Botnet signatures
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // C2 infrastructure IOCs
#include "../../Whitelist/WhiteListStore.hpp" // Trusted infrastructure

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
class BotnetDetectorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace BotnetDetectorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Beaconing thresholds
    constexpr double BEACON_INTERVAL_VARIANCE_THRESHOLD = 0.10;  // 10% variance
    constexpr uint32_t MIN_BEACON_SAMPLES = 5;
    constexpr uint32_t MAX_BEACON_INTERVAL_MS = 3600000;          // 1 hour
    constexpr uint32_t MIN_BEACON_INTERVAL_MS = 100;              // 100ms
    constexpr double JITTER_DETECTION_THRESHOLD = 0.05;           // 5% jitter
    constexpr double BEACON_CONFIDENCE_THRESHOLD = 0.75;

    // DGA thresholds
    constexpr double DGA_ENTROPY_THRESHOLD = 3.5;
    constexpr size_t DGA_MIN_LENGTH = 6;
    constexpr size_t DGA_MAX_LENGTH = 64;
    constexpr double DGA_CONFIDENCE_THRESHOLD = 0.80;

    // Analysis limits
    constexpr size_t MAX_TRACKED_CONNECTIONS = 50000;
    constexpr size_t MAX_BEACON_HISTORY = 1000;
    constexpr size_t MAX_DGA_CACHE_SIZE = 100000;
    constexpr uint32_t CONNECTION_TIMEOUT_MS = 7200000;           // 2 hours

    // C2 detection
    constexpr size_t MIN_C2_PATTERN_MATCH = 3;
    constexpr double C2_CONFIDENCE_THRESHOLD = 0.70;

}  // namespace BotnetDetectorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum BotnetFamily
 * @brief Known botnet families.
 */
enum class BotnetFamily : uint16_t {
    UNKNOWN = 0,

    // APT/Targeted
    COBALT_STRIKE = 100,
    METERPRETER = 101,
    EMPIRE = 102,
    POWERSHELL_EMPIRE = 103,
    COVENANT = 104,
    SILVER_C2 = 105,
    MYTHIC = 106,
    BRUTE_RATEL = 107,

    // Banking trojans
    EMOTET = 200,
    TRICKBOT = 201,
    QAKBOT = 202,
    DRIDEX = 203,
    ICEDID = 204,
    GOZI_URSNIF = 205,
    ZEUS = 206,
    ZLOADER = 207,

    // Ransomware loaders
    BAZARLOADER = 300,
    RYUK_LOADER = 301,
    CONTI_LOADER = 302,
    LOCKBIT_LOADER = 303,
    BLACKCAT_LOADER = 304,

    // IoT botnets
    MIRAI = 400,
    GAFGYT = 401,
    HAJIME = 402,
    MOZI = 403,

    // Legacy
    CONFICKER = 500,
    GAMEOVER_ZEUS = 501,
    NECURS = 502,
    CUTWAIL = 503,

    // Modern
    SOLARWINDS_SUNBURST = 600,
    HAFNIUM = 601,

    // Generic categories
    GENERIC_HTTP_C2 = 900,
    GENERIC_DNS_C2 = 901,
    GENERIC_IRC_C2 = 902,
    GENERIC_P2P = 903,
    CUSTOM = 999
};

/**
 * @enum C2Protocol
 * @brief Command and Control protocol types.
 */
enum class C2Protocol : uint8_t {
    UNKNOWN = 0,
    HTTP_GET = 1,
    HTTP_POST = 2,
    HTTPS = 3,
    DNS_TXT = 4,
    DNS_A = 5,
    DNS_CNAME = 6,
    DNS_MX = 7,
    IRC = 8,
    CUSTOM_TCP = 9,
    CUSTOM_UDP = 10,
    ICMP = 11,
    WEBSOCKET = 12,
    DOH = 13,                  // DNS over HTTPS
    DOT = 14,                  // DNS over TLS
    P2P = 15,
    TOR = 16,
    SMB = 17,
    ENCRYPTED_CUSTOM = 18
};

/**
 * @enum BeaconType
 * @brief Type of beaconing behavior.
 */
enum class BeaconType : uint8_t {
    NONE = 0,
    CONSTANT = 1,              // Fixed interval
    JITTERED = 2,              // Fixed interval with jitter
    RANDOMIZED = 3,            // Random intervals within range
    EXPONENTIAL = 4,           // Exponential backoff
    HYBRID = 5,                // Multiple patterns combined
    DEAD_DROP = 6              // Checking external dead drop
};

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection.
 */
enum class DetectionConfidence : uint8_t {
    NONE = 0,
    LOW = 1,                   // < 50%
    MEDIUM = 2,                // 50-75%
    HIGH = 3,                  // 75-90%
    CRITICAL = 4               // > 90%
};

/**
 * @enum ThreatSeverity
 * @brief Severity of detected threat.
 */
enum class ThreatSeverity : uint8_t {
    INFO = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

/**
 * @enum BotnetAction
 * @brief Recommended action for detected botnet.
 */
enum class BotnetAction : uint8_t {
    MONITOR = 0,               // Continue monitoring
    ALERT = 1,                 // Generate alert
    BLOCK_CONNECTION = 2,      // Block specific connection
    ISOLATE_HOST = 3,          // Isolate infected host
    TERMINATE_PROCESS = 4,     // Kill associated process
    QUARANTINE = 5             // Full quarantine
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct BeaconAnalysis
 * @brief Analysis of beaconing behavior.
 */
struct alignas(64) BeaconAnalysis {
    // Detection result
    bool isBeaconing{ false };
    BeaconType beaconType{ BeaconType::NONE };
    double confidence{ 0.0 };

    // Timing analysis
    double averageIntervalMs{ 0.0 };
    double intervalVariance{ 0.0 };
    double standardDeviation{ 0.0 };
    double jitterPercent{ 0.0 };
    double minIntervalMs{ 0.0 };
    double maxIntervalMs{ 0.0 };

    // Beacon characteristics
    uint32_t beaconCount{ 0 };
    uint32_t missedBeacons{ 0 };
    size_t avgPayloadSize{ 0 };
    bool hasConsistentSize{ false };

    // Time series
    std::vector<std::chrono::system_clock::time_point> beaconTimes;
    std::vector<double> intervals;

    // Pattern
    std::string patternSignature;
    std::string matchedFamily;
};

/**
 * @struct DGAAnalysis
 * @brief Domain Generation Algorithm analysis.
 */
struct alignas(64) DGAAnalysis {
    // Detection result
    bool isDGA{ false };
    double confidence{ 0.0 };

    // Domain analysis
    std::string domain;
    double entropy{ 0.0 };
    double consonantRatio{ 0.0 };
    double vowelRatio{ 0.0 };
    double numericRatio{ 0.0 };
    uint32_t length{ 0 };

    // N-gram analysis
    double bigramFrequency{ 0.0 };
    double trigramFrequency{ 0.0 };
    double commonBigramRatio{ 0.0 };

    // Dictionary analysis
    bool containsWord{ false };
    uint32_t longestWord{ 0 };
    double pronounceabilityScore{ 0.0 };

    // ML classification
    double mlScore{ 0.0 };
    std::string mlClassifier;

    // Attribution
    std::string likelyFamily;
    std::string dgaAlgorithm;
};

/**
 * @struct C2Detection
 * @brief C2 communication detection result.
 */
struct alignas(128) C2Detection {
    // Detection result
    bool isC2{ false };
    DetectionConfidence confidence{ DetectionConfidence::NONE };
    ThreatSeverity severity{ ThreatSeverity::INFO };

    // Protocol
    C2Protocol protocol{ C2Protocol::UNKNOWN };
    uint16_t port{ 0 };
    std::string protocolDetails;

    // Destination
    std::string destination;
    std::string resolvedIP;
    std::string sni;
    std::string ja3Hash;

    // C2 characteristics
    bool isEncrypted{ false };
    bool usesProxy{ false };
    bool usesCDN{ false };
    bool usesTor{ false };

    // Pattern matching
    std::vector<std::string> matchedSignatures;
    std::vector<std::string> matchedYaraRules;

    // Family identification
    BotnetFamily family{ BotnetFamily::UNKNOWN };
    std::string familyVariant;
    double familyConfidence{ 0.0 };

    // Infrastructure
    std::vector<std::string> relatedDomains;
    std::vector<std::string> relatedIPs;
    std::string campaignId;
};

/**
 * @struct ConnectionBehavior
 * @brief Behavioral profile of a connection.
 */
struct alignas(128) ConnectionBehavior {
    // Connection identity
    uint64_t connectionId{ 0 };
    uint32_t processId{ 0 };
    std::string processName;
    std::string processPath;

    // Endpoint
    std::string remoteIP;
    uint16_t remotePort{ 0 };
    std::string remoteDomain;

    // Timing
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::chrono::milliseconds totalDuration{ 0 };

    // Traffic
    uint64_t bytesSent{ 0 };
    uint64_t bytesReceived{ 0 };
    uint64_t packetsSent{ 0 };
    uint64_t packetsReceived{ 0 };
    double avgPacketSize{ 0.0 };

    // Behavior flags
    bool hasBeaconing{ false };
    bool hasDGA{ false };
    bool hasC2Pattern{ false };
    bool hasDataExfiltration{ false };

    // Analysis results
    BeaconAnalysis beaconAnalysis;
    std::vector<DGAAnalysis> dgaAnalyses;
    std::vector<C2Detection> c2Detections;

    // Risk
    uint8_t riskScore{ 0 };               // 0-100
    std::vector<std::string> riskFactors;
};

/**
 * @struct BotnetAlert
 * @brief Alert for botnet detection.
 */
struct alignas(256) BotnetAlert {
    // Alert identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Severity
    ThreatSeverity severity{ ThreatSeverity::MEDIUM };
    DetectionConfidence confidence{ DetectionConfidence::MEDIUM };
    BotnetAction recommendedAction{ BotnetAction::ALERT };

    // Detection details
    BotnetFamily family{ BotnetFamily::UNKNOWN };
    std::string familyName;
    std::string detection;
    std::string description;

    // Affected endpoint
    uint32_t processId{ 0 };
    std::string processName;
    std::string processPath;
    std::string username;
    std::string hostname;

    // Network details
    std::string remoteIP;
    uint16_t remotePort{ 0 };
    std::string remoteDomain;
    C2Protocol c2Protocol{ C2Protocol::UNKNOWN };

    // Evidence
    std::vector<std::string> indicators;
    std::vector<std::string> matchedSignatures;
    BeaconAnalysis beaconInfo;
    DGAAnalysis dgaInfo;

    // MITRE ATT&CK
    std::vector<std::string> mitreTechniques;

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct P2PBotnetInfo
 * @brief P2P botnet specific information.
 */
struct alignas(64) P2PBotnetInfo {
    bool isP2P{ false };
    double confidence{ 0.0 };

    // Topology
    std::string overlayType;              // DHT, custom, etc.
    std::vector<std::string> knownPeers;
    bool isSuperPeer{ false };

    // Communication
    uint16_t p2pPort{ 0 };
    std::string protocol;
    bool encrypted{ false };

    // Behavior
    uint32_t uniquePeerCount{ 0 };
    double peerChurnRate{ 0.0 };
    std::chrono::milliseconds avgPeerLifetime{ 0 };
};

/**
 * @struct BotnetSignature
 * @brief Signature for botnet detection.
 */
struct alignas(64) BotnetSignature {
    uint64_t signatureId{ 0 };
    std::string name;
    BotnetFamily family{ BotnetFamily::UNKNOWN };

    // Pattern
    std::string pattern;                  // Regex or byte pattern
    bool isRegex{ false };
    bool isCaseSensitive{ false };

    // Context
    C2Protocol protocol{ C2Protocol::UNKNOWN };
    std::vector<uint16_t> ports;

    // Metadata
    ThreatSeverity severity{ ThreatSeverity::MEDIUM };
    std::string description;
    std::vector<std::string> references;

    bool enabled{ true };
};

/**
 * @struct BotnetDetectorConfig
 * @brief Configuration for botnet detector.
 */
struct alignas(64) BotnetDetectorConfig {
    // Feature toggles
    bool enabled{ true };
    bool enableBeaconDetection{ true };
    bool enableC2Detection{ true };
    bool enableDGADetection{ true };
    bool enableFamilyIdentification{ true };
    bool enableP2PDetection{ true };

    // Thresholds
    double beaconConfidenceThreshold{ BotnetDetectorConstants::BEACON_CONFIDENCE_THRESHOLD };
    double dgaConfidenceThreshold{ BotnetDetectorConstants::DGA_CONFIDENCE_THRESHOLD };
    double c2ConfidenceThreshold{ BotnetDetectorConstants::C2_CONFIDENCE_THRESHOLD };
    uint32_t minBeaconSamples{ BotnetDetectorConstants::MIN_BEACON_SAMPLES };

    // Limits
    size_t maxTrackedConnections{ BotnetDetectorConstants::MAX_TRACKED_CONNECTIONS };
    size_t maxBeaconHistory{ BotnetDetectorConstants::MAX_BEACON_HISTORY };
    uint32_t connectionTimeoutMs{ BotnetDetectorConstants::CONNECTION_TIMEOUT_MS };

    // ThreatIntel integration
    bool useThreatIntel{ true };
    bool checkJA3Reputation{ true };
    bool checkDomainReputation{ true };
    bool checkIPReputation{ true };

    // Actions
    BotnetAction defaultAction{ BotnetAction::ALERT };
    bool autoBlockKnownC2{ false };
    bool autoIsolateHighSeverity{ false };

    // ML settings
    bool useMLClassification{ true };
    std::string mlModelPath;

    // Logging
    bool logAllConnections{ false };
    bool logAlertsOnly{ true };

    // Factory methods
    static BotnetDetectorConfig CreateDefault() noexcept;
    static BotnetDetectorConfig CreateHighSecurity() noexcept;
    static BotnetDetectorConfig CreatePerformance() noexcept;
    static BotnetDetectorConfig CreateForensic() noexcept;
};

/**
 * @struct BotnetDetectorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) BotnetDetectorStatistics {
    // Connection statistics
    std::atomic<uint64_t> totalConnectionsAnalyzed{ 0 };
    std::atomic<uint32_t> activeConnections{ 0 };
    std::atomic<uint64_t> connectionsTimedOut{ 0 };

    // Detection statistics
    std::atomic<uint64_t> beaconingDetected{ 0 };
    std::atomic<uint64_t> dgaDomainsDetected{ 0 };
    std::atomic<uint64_t> c2Detected{ 0 };
    std::atomic<uint64_t> p2pBotnetsDetected{ 0 };

    // Family statistics
    std::atomic<uint64_t> knownFamiliesDetected{ 0 };
    std::atomic<uint64_t> unknownFamiliesDetected{ 0 };

    // Alert statistics
    std::atomic<uint64_t> alertsGenerated{ 0 };
    std::atomic<uint64_t> criticalAlerts{ 0 };
    std::atomic<uint64_t> falsePositives{ 0 };

    // Action statistics
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> hostsIsolated{ 0 };
    std::atomic<uint64_t> processesTerminated{ 0 };

    // ThreatIntel statistics
    std::atomic<uint64_t> threatIntelMatches{ 0 };
    std::atomic<uint64_t> ja3Matches{ 0 };
    std::atomic<uint64_t> domainMatches{ 0 };

    // Performance
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };
    std::atomic<uint64_t> maxAnalysisTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for botnet alerts.
 */
using BotnetAlertCallback = std::function<void(const BotnetAlert& alert)>;

/**
 * @brief Callback for beacon detection.
 */
using BeaconCallback = std::function<void(
    uint64_t connectionId,
    const BeaconAnalysis& analysis
)>;

/**
 * @brief Callback for DGA detection.
 */
using DGACallback = std::function<void(
    const std::string& domain,
    const DGAAnalysis& analysis
)>;

/**
 * @brief Callback for C2 detection.
 */
using C2Callback = std::function<void(
    uint64_t connectionId,
    const C2Detection& detection
)>;

/**
 * @brief Callback for family identification.
 */
using FamilyCallback = std::function<void(
    uint64_t connectionId,
    BotnetFamily family,
    double confidence
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class BotnetDetector
 * @brief Enterprise-grade botnet and C2 detection engine.
 *
 * Thread Safety:
 * All public methods are thread-safe. Concurrent analysis supported.
 *
 * Usage Example:
 * @code
 * auto& detector = BotnetDetector::Instance();
 * 
 * // Initialize
 * auto config = BotnetDetectorConfig::CreateHighSecurity();
 * detector.Initialize(config);
 * 
 * // Register alert callback
 * detector.RegisterAlertCallback([](const BotnetAlert& alert) {
 *     HandleBotnetAlert(alert);
 * });
 * 
 * // Check for beaconing
 * auto analysis = detector.AnalyzeBeaconing(pid, remoteIP);
 * if (analysis.isBeaconing) {
 *     TakeAction(analysis);
 * }
 * @endcode
 */
class BotnetDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static BotnetDetector& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the botnet detector.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const BotnetDetectorConfig& config);

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
    // BEACONING DETECTION
    // ========================================================================

    /**
     * @brief Checks if connection exhibits beaconing behavior.
     * @param pid Process ID.
     * @param remoteIp Remote IP address.
     * @return True if beaconing detected.
     */
    [[nodiscard]] bool IsBeaconing(uint32_t pid, const std::string& remoteIp);

    /**
     * @brief Full beacon analysis for connection.
     * @param pid Process ID.
     * @param remoteIP Remote IP address.
     * @return Detailed beacon analysis.
     */
    [[nodiscard]] BeaconAnalysis AnalyzeBeaconing(
        uint32_t pid,
        const std::string& remoteIP
    );

    /**
     * @brief Records connection event for beacon analysis.
     * @param pid Process ID.
     * @param remoteIP Remote IP.
     * @param remotePort Remote port.
     * @param bytesSent Bytes sent.
     * @param bytesReceived Bytes received.
     */
    void RecordConnectionEvent(
        uint32_t pid,
        const std::string& remoteIP,
        uint16_t remotePort,
        uint64_t bytesSent,
        uint64_t bytesReceived
    );

    // ========================================================================
    // DGA DETECTION
    // ========================================================================

    /**
     * @brief Checks if domain is DGA-generated.
     * @param domain Domain name.
     * @return True if likely DGA.
     */
    [[nodiscard]] bool IsDGADomain(const std::string& domain);

    /**
     * @brief Full DGA analysis.
     * @param domain Domain name.
     * @return Detailed DGA analysis.
     */
    [[nodiscard]] DGAAnalysis AnalyzeDGA(const std::string& domain);

    /**
     * @brief Batch DGA analysis.
     * @param domains Vector of domains.
     * @return Map of domain to analysis.
     */
    [[nodiscard]] std::unordered_map<std::string, DGAAnalysis> AnalyzeDGABatch(
        const std::vector<std::string>& domains
    );

    // ========================================================================
    // C2 DETECTION
    // ========================================================================

    /**
     * @brief Detects C2 communication.
     * @param connectionId Connection ID.
     * @return C2 detection result.
     */
    [[nodiscard]] C2Detection DetectC2(uint64_t connectionId);

    /**
     * @brief Analyzes payload for C2 patterns.
     * @param payload Payload data.
     * @param protocol Expected protocol.
     * @return C2 detection result.
     */
    [[nodiscard]] C2Detection AnalyzePayloadForC2(
        std::span<const uint8_t> payload,
        C2Protocol protocol
    );

    /**
     * @brief Checks JA3 fingerprint against known C2.
     * @param ja3Hash JA3 hash.
     * @return Optional botnet family if match.
     */
    [[nodiscard]] std::optional<BotnetFamily> CheckJA3(const std::string& ja3Hash);

    // ========================================================================
    // FAMILY IDENTIFICATION
    // ========================================================================

    /**
     * @brief Identifies botnet family.
     * @param connectionId Connection ID.
     * @return Identified family with confidence.
     */
    [[nodiscard]] std::pair<BotnetFamily, double> IdentifyFamily(uint64_t connectionId);

    /**
     * @brief Gets family name.
     * @param family Botnet family.
     * @return Family name string.
     */
    [[nodiscard]] static std::string_view GetFamilyName(BotnetFamily family) noexcept;

    // ========================================================================
    // P2P DETECTION
    // ========================================================================

    /**
     * @brief Detects P2P botnet behavior.
     * @param pid Process ID.
     * @return P2P botnet info.
     */
    [[nodiscard]] P2PBotnetInfo DetectP2PBotnet(uint32_t pid);

    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets connection behavior profile.
     * @param connectionId Connection ID.
     * @return Connection behavior, or nullopt.
     */
    [[nodiscard]] std::optional<ConnectionBehavior> GetConnectionBehavior(
        uint64_t connectionId
    ) const;

    /**
     * @brief Gets all suspicious connections.
     * @param minRiskScore Minimum risk score (0-100).
     * @return Vector of suspicious connections.
     */
    [[nodiscard]] std::vector<ConnectionBehavior> GetSuspiciousConnections(
        uint8_t minRiskScore = 50
    ) const;

    /**
     * @brief Clears old connection data.
     * @param maxAgeMs Maximum age in milliseconds.
     * @return Number of connections cleared.
     */
    size_t PurgeOldConnections(uint32_t maxAgeMs);

    // ========================================================================
    // SIGNATURE MANAGEMENT
    // ========================================================================

    /**
     * @brief Loads botnet signatures.
     * @param signaturePath Path to signature file.
     * @return Number of signatures loaded.
     */
    size_t LoadSignatures(const std::wstring& signaturePath);

    /**
     * @brief Adds custom signature.
     * @param signature Signature to add.
     * @return Signature ID.
     */
    [[nodiscard]] uint64_t AddSignature(const BotnetSignature& signature);

    /**
     * @brief Removes signature.
     * @param signatureId Signature ID.
     * @return True if removed.
     */
    bool RemoveSignature(uint64_t signatureId);

    /**
     * @brief Gets signature count.
     * @return Number of active signatures.
     */
    [[nodiscard]] size_t GetSignatureCount() const noexcept;

    // ========================================================================
    // ACTIONS
    // ========================================================================

    /**
     * @brief Blocks connection.
     * @param connectionId Connection ID.
     * @return True if blocked.
     */
    bool BlockConnection(uint64_t connectionId);

    /**
     * @brief Isolates host.
     * @param hostname Hostname to isolate.
     * @return True if isolated.
     */
    bool IsolateHost(const std::string& hostname);

    /**
     * @brief Terminates infected process.
     * @param pid Process ID.
     * @param force Force termination.
     * @return True if terminated.
     */
    bool TerminateProcess(uint32_t pid, bool force = false);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAlertCallback(BotnetAlertCallback callback);
    [[nodiscard]] uint64_t RegisterBeaconCallback(BeaconCallback callback);
    [[nodiscard]] uint64_t RegisterDGACallback(DGACallback callback);
    [[nodiscard]] uint64_t RegisterC2Callback(C2Callback callback);
    [[nodiscard]] uint64_t RegisterFamilyCallback(FamilyCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const BotnetDetectorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;
    bool ExportAlerts(const std::wstring& outputPath, uint32_t lastHours = 24) const;

private:
    BotnetDetector();
    ~BotnetDetector();

    BotnetDetector(const BotnetDetector&) = delete;
    BotnetDetector& operator=(const BotnetDetector&) = delete;

    std::unique_ptr<BotnetDetectorImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
