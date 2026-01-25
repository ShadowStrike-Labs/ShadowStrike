/**
 * ============================================================================
 * ShadowStrike Core Network - DDOS PROTECTION (The Floodgate)
 * ============================================================================
 *
 * @file DDosProtection.hpp
 * @brief Enterprise-grade DDoS detection, mitigation, and traffic shaping.
 *
 * This module provides comprehensive protection against denial-of-service
 * attacks through multi-layer detection, intelligent rate limiting, and
 * automated mitigation using Windows Filtering Platform (WFP).
 *
 * Key Capabilities:
 * =================
 * 1. FLOOD DETECTION
 *    - SYN flood detection (half-open tracking)
 *    - UDP flood detection
 *    - ICMP flood detection
 *    - HTTP flood detection
 *    - DNS amplification detection
 *    - Slowloris detection
 *
 * 2. RATE LIMITING
 *    - Per-IP rate limiting
 *    - Per-port rate limiting
 *    - Per-process rate limiting
 *    - Global connection limits
 *    - Bandwidth throttling
 *
 * 3. TRAFFIC ANALYSIS
 *    - Baseline traffic modeling
 *    - Anomaly detection
 *    - Attack pattern recognition
 *    - Traffic profiling
 *
 * 4. MITIGATION
 *    - WFP rule injection
 *    - Connection reset
 *    - IP blackholing
 *    - SYN cookies
 *    - Bandwidth allocation
 *
 * 5. ADAPTIVE DEFENSE
 *    - Dynamic threshold adjustment
 *    - Attack severity scaling
 *    - Recovery detection
 *    - Whitelist protection
 *
 * Detection Architecture:
 * =======================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        DDosProtection                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │FloodDetector │  │ RateLimiter  │  │    TrafficAnalyzer       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - SYN Flood  │  │ - Per-IP     │  │ - Baseline Model         │  │
 *   │  │ - UDP Flood  │  │ - Per-Port   │  │ - Anomaly Detection      │  │
 *   │  │ - ICMP Flood │  │ - Per-PID    │  │ - Pattern Recognition    │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │WFPMitigator  │  │ AdaptiveCtrl │  │    AttackResponseMgr     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - IP Block   │  │ - Thresholds │  │ - Severity Assessment    │  │
 *   │  │ - Rate Limit │  │ - Recovery   │  │ - Response Coordination  │  │
 *   │  │ - SYN Cookie │  │ - Scaling    │  │ - Incident Logging       │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Attack Types Detected:
 * ======================
 * Layer 3/4 Attacks:
 * - TCP SYN Flood
 * - TCP ACK Flood
 * - TCP RST Flood
 * - UDP Flood
 * - ICMP Flood (Ping of Death)
 * - Smurf Attack
 * - IP Fragmentation Attack
 * - Land Attack
 * - Teardrop Attack
 *
 * Layer 7 Attacks:
 * - HTTP GET/POST Flood
 * - Slowloris
 * - Slow POST
 * - DNS Query Flood
 * - DNS Amplification
 * - NTP Amplification
 * - SSDP Amplification
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1498: Network Denial of Service
 * - T1498.001: Direct Network Flood
 * - T1498.002: Reflection Amplification
 * - T1499: Endpoint Denial of Service
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Lock-free rate limiting counters
 * - Concurrent traffic processing
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see NetworkMonitor.hpp for traffic monitoring
 * @see FirewallManager.hpp for rule management
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/ProcessUtils.hpp"       // Process identification
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Attacker IP reputation
#include "../../Whitelist/WhiteListStore.hpp" // Trusted IPs

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
class DDosProtectionImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace DDosProtectionConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // SYN flood thresholds
    constexpr uint32_t SYN_FLOOD_THRESHOLD_PER_SEC = 1000;
    constexpr uint32_t HALF_OPEN_THRESHOLD = 10000;
    constexpr uint32_t SYN_COOKIE_THRESHOLD = 5000;

    // UDP flood thresholds
    constexpr uint32_t UDP_FLOOD_THRESHOLD_PER_SEC = 5000;
    constexpr size_t UDP_FLOOD_BANDWIDTH_MBPS = 100;

    // ICMP thresholds
    constexpr uint32_t ICMP_FLOOD_THRESHOLD_PER_SEC = 500;
    constexpr size_t ICMP_MAX_PACKET_SIZE = 1500;

    // HTTP thresholds
    constexpr uint32_t HTTP_REQUESTS_PER_SEC = 100;
    constexpr uint32_t SLOWLORIS_TIMEOUT_SEC = 60;

    // Rate limiting
    constexpr uint32_t DEFAULT_RATE_LIMIT_PPS = 10000;
    constexpr uint32_t DEFAULT_BANDWIDTH_MBPS = 1000;
    constexpr uint32_t RATE_WINDOW_MS = 1000;

    // Tracking limits
    constexpr size_t MAX_TRACKED_IPS = 100000;
    constexpr size_t MAX_HALF_OPEN_CONNECTIONS = 50000;
    constexpr uint32_t IP_TRACKING_TIMEOUT_SEC = 300;

    // Mitigation
    constexpr uint32_t BLACKLIST_DURATION_SEC = 3600;             // 1 hour
    constexpr uint32_t MITIGATION_COOLDOWN_SEC = 60;

}  // namespace DDosProtectionConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum AttackType
 * @brief Type of DDoS attack.
 */
enum class AttackType : uint16_t {
    NONE = 0,

    // Layer 3 attacks
    IP_FLOOD = 100,
    IP_FRAGMENTATION = 101,
    ICMP_FLOOD = 102,
    SMURF = 103,

    // Layer 4 attacks
    SYN_FLOOD = 200,
    SYN_ACK_FLOOD = 201,
    ACK_FLOOD = 202,
    RST_FLOOD = 203,
    FIN_FLOOD = 204,
    UDP_FLOOD = 205,
    REFLECTION = 206,

    // Layer 7 attacks
    HTTP_GET_FLOOD = 300,
    HTTP_POST_FLOOD = 301,
    SLOWLORIS = 302,
    SLOW_POST = 303,
    HTTP_FRAGMENTED = 304,

    // DNS attacks
    DNS_QUERY_FLOOD = 400,
    DNS_AMPLIFICATION = 401,
    DNS_REFLECTION = 402,

    // Amplification
    NTP_AMPLIFICATION = 500,
    SSDP_AMPLIFICATION = 501,
    MEMCACHED_AMPLIFICATION = 502,
    CHARGEN_AMPLIFICATION = 503,

    // Protocol exploits
    LAND_ATTACK = 600,
    TEARDROP = 601,
    PING_OF_DEATH = 602,
    SOCKSTRESS = 603,

    // Combined/Unknown
    MULTI_VECTOR = 900,
    UNKNOWN = 999
};

/**
 * @enum AttackSeverity
 * @brief Severity level of attack.
 */
enum class AttackSeverity : uint8_t {
    NONE = 0,
    LOW = 1,               // Minor traffic anomaly
    MEDIUM = 2,            // Noticeable impact
    HIGH = 3,              // Significant service degradation
    CRITICAL = 4           // Service unavailable
};

/**
 * @enum MitigationAction
 * @brief Actions to mitigate attacks.
 */
enum class MitigationAction : uint8_t {
    NONE = 0,
    RATE_LIMIT = 1,            // Limit traffic rate
    THROTTLE = 2,              // Reduce bandwidth
    BLOCK_IP = 3,              // Block specific IP
    BLOCK_SUBNET = 4,          // Block entire subnet
    BLACKHOLE = 5,             // Null route
    SYN_COOKIES = 6,           // Enable SYN cookies
    CONNECTION_RESET = 7,      // Reset connections
    GEOGRAPHIC_BLOCK = 8,      // Block by country
    CHALLENGE = 9,             // CAPTCHA/challenge
    ALERT_ONLY = 10            // No action, alert only
};

/**
 * @enum ProtectionLevel
 * @brief Protection intensity level.
 */
enum class ProtectionLevel : uint8_t {
    DISABLED = 0,
    MINIMAL = 1,           // Basic detection only
    STANDARD = 2,          // Balanced protection
    AGGRESSIVE = 3,        // Proactive blocking
    PARANOID = 4           // Maximum protection
};

/**
 * @enum AttackPhase
 * @brief Current phase of attack lifecycle.
 */
enum class AttackPhase : uint8_t {
    NONE = 0,
    DETECTION = 1,         // Attack detected
    ESCALATING = 2,        // Attack intensity increasing
    PEAK = 3,              // Maximum intensity
    DECLINING = 4,         // Attack subsiding
    RECOVERY = 5           // System recovering
};

/**
 * @enum TrafficDirection
 * @brief Direction of traffic.
 */
enum class TrafficDirection : uint8_t {
    INBOUND = 1,
    OUTBOUND = 2,
    BOTH = 3
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct TrafficMetrics
 * @brief Real-time traffic metrics.
 */
struct alignas(64) TrafficMetrics {
    // Packet rates
    std::atomic<uint64_t> packetsPerSecond{ 0 };
    std::atomic<uint64_t> bytesPerSecond{ 0 };
    std::atomic<uint64_t> connectionsPerSecond{ 0 };

    // TCP metrics
    std::atomic<uint64_t> synPacketsPerSecond{ 0 };
    std::atomic<uint64_t> synAckPacketsPerSecond{ 0 };
    std::atomic<uint64_t> ackPacketsPerSecond{ 0 };
    std::atomic<uint64_t> finPacketsPerSecond{ 0 };
    std::atomic<uint64_t> rstPacketsPerSecond{ 0 };
    std::atomic<uint32_t> halfOpenConnections{ 0 };

    // UDP metrics
    std::atomic<uint64_t> udpPacketsPerSecond{ 0 };
    std::atomic<uint64_t> udpBytesPerSecond{ 0 };

    // ICMP metrics
    std::atomic<uint64_t> icmpPacketsPerSecond{ 0 };

    // HTTP metrics
    std::atomic<uint64_t> httpRequestsPerSecond{ 0 };
    std::atomic<uint32_t> activeHttpConnections{ 0 };

    // DNS metrics
    std::atomic<uint64_t> dnsQueriesPerSecond{ 0 };

    // Totals
    std::atomic<uint64_t> totalPackets{ 0 };
    std::atomic<uint64_t> totalBytes{ 0 };
    std::atomic<uint64_t> totalConnections{ 0 };

    void Reset() noexcept;
};

/**
 * @struct TrafficBaseline
 * @brief Statistical baseline for traffic.
 */
struct alignas(64) TrafficBaseline {
    // Packet statistics
    double avgPacketsPerSecond{ 0.0 };
    double stdDevPacketsPerSecond{ 0.0 };
    double maxPacketsPerSecond{ 0.0 };

    // Byte statistics
    double avgBytesPerSecond{ 0.0 };
    double stdDevBytesPerSecond{ 0.0 };
    double maxBytesPerSecond{ 0.0 };

    // Connection statistics
    double avgConnectionsPerSecond{ 0.0 };
    double stdDevConnectionsPerSecond{ 0.0 };
    double avgHalfOpenConnections{ 0.0 };

    // Protocol-specific
    double avgSynRate{ 0.0 };
    double avgUdpRate{ 0.0 };
    double avgIcmpRate{ 0.0 };
    double avgHttpRate{ 0.0 };

    // Timing
    std::chrono::system_clock::time_point calculatedAt;
    std::chrono::hours samplePeriod{ 24 };
    uint64_t sampleCount{ 0 };

    bool isValid{ false };
};

/**
 * @struct AttackInfo
 * @brief Information about detected attack.
 */
struct alignas(256) AttackInfo {
    // Identity
    uint64_t attackId{ 0 };
    AttackType type{ AttackType::NONE };
    AttackSeverity severity{ AttackSeverity::NONE };
    AttackPhase phase{ AttackPhase::NONE };

    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastUpdate;
    std::chrono::system_clock::time_point endTime;
    std::chrono::milliseconds duration{ 0 };

    // Traffic metrics during attack
    uint64_t peakPacketsPerSecond{ 0 };
    uint64_t peakBytesPerSecond{ 0 };
    uint64_t peakConnectionsPerSecond{ 0 };
    uint64_t totalPackets{ 0 };
    uint64_t totalBytes{ 0 };

    // Source analysis
    uint32_t uniqueSourceIPs{ 0 };
    std::vector<std::string> topSourceIPs;
    std::vector<std::string> sourceSubnets;
    std::vector<std::string> sourceCountries;
    bool isDistributed{ false };

    // Target analysis
    std::vector<uint16_t> targetedPorts;
    std::vector<std::string> targetedServices;

    // Mitigation status
    std::vector<MitigationAction> appliedMitigations;
    bool isMitigated{ false };
    double mitigationEffectiveness{ 0.0 };

    // Impact
    uint32_t droppedConnections{ 0 };
    uint32_t blockedIPs{ 0 };
    double serviceImpactPercent{ 0.0 };

    // Description
    std::string description;
    std::vector<std::string> indicators;
};

/**
 * @struct IPTrackingInfo
 * @brief Tracking information for an IP address.
 */
struct alignas(64) IPTrackingInfo {
    std::string ipAddress;

    // Traffic
    std::atomic<uint64_t> packetsTotal{ 0 };
    std::atomic<uint64_t> bytesTotal{ 0 };
    std::atomic<uint64_t> packetsInWindow{ 0 };
    std::atomic<uint64_t> connectionsInWindow{ 0 };

    // TCP tracking
    std::atomic<uint32_t> synPackets{ 0 };
    std::atomic<uint32_t> halfOpenConnections{ 0 };

    // Timing
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::chrono::system_clock::time_point windowStart;

    // Status
    bool isRateLimited{ false };
    bool isBlocked{ false };
    bool isWhitelisted{ false };
    std::chrono::system_clock::time_point blockedUntil;

    // Risk
    uint8_t riskScore{ 0 };
    std::vector<std::string> violations;
};

/**
 * @struct RateLimitRule
 * @brief Rate limiting rule configuration.
 */
struct alignas(64) RateLimitRule {
    uint64_t ruleId{ 0 };
    std::string name;

    // Scope
    std::string ipAddress;                    // Empty for global
    std::string subnet;
    uint16_t port{ 0 };                       // 0 for all
    uint32_t processId{ 0 };                  // 0 for all

    // Limits
    uint32_t packetsPerSecond{ 0 };
    uint64_t bytesPerSecond{ 0 };
    uint32_t connectionsPerSecond{ 0 };
    uint32_t synPerSecond{ 0 };

    // Actions
    MitigationAction exceedAction{ MitigationAction::RATE_LIMIT };
    uint32_t blockDurationSec{ 60 };

    // Status
    bool enabled{ true };
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
    bool isPermanent{ true };
};

/**
 * @struct MitigationResult
 * @brief Result of mitigation action.
 */
struct alignas(64) MitigationResult {
    uint64_t mitigationId{ 0 };
    MitigationAction action{ MitigationAction::NONE };

    // Target
    std::string targetIP;
    std::string targetSubnet;
    uint16_t targetPort{ 0 };

    // Status
    bool success{ false };
    std::string errorMessage;

    // Timing
    std::chrono::system_clock::time_point appliedAt;
    std::chrono::system_clock::time_point expiresAt;

    // Effect
    uint64_t packetsDropped{ 0 };
    uint64_t bytesDropped{ 0 };
    uint32_t connectionsBlocked{ 0 };
};

/**
 * @struct HalfOpenConnection
 * @brief Half-open TCP connection tracking.
 */
struct alignas(32) HalfOpenConnection {
    std::array<uint8_t, 16> srcIP{ 0 };
    uint16_t srcPort{ 0 };
    uint16_t dstPort{ 0 };
    uint32_t sequenceNumber{ 0 };
    std::chrono::system_clock::time_point synTime;
    bool isIPv6{ false };
};

/**
 * @struct DDosAlert
 * @brief Alert for DDoS detection.
 */
struct alignas(256) DDosAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Attack info
    uint64_t attackId{ 0 };
    AttackType attackType{ AttackType::NONE };
    AttackSeverity severity{ AttackSeverity::NONE };
    AttackPhase phase{ AttackPhase::NONE };

    // Description
    std::string title;
    std::string description;

    // Metrics
    uint64_t currentPacketsPerSecond{ 0 };
    uint64_t currentBytesPerSecond{ 0 };
    double deviationFromBaseline{ 0.0 };

    // Source
    std::string primarySourceIP;
    std::vector<std::string> topSources;
    uint32_t uniqueSources{ 0 };

    // Action
    MitigationAction recommendedAction{ MitigationAction::NONE };
    std::vector<MitigationAction> appliedActions;

    // Context
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct DDosProtectionConfig
 * @brief Configuration for DDoS protection.
 */
struct alignas(64) DDosProtectionConfig {
    // Main settings
    bool enabled{ true };
    ProtectionLevel level{ ProtectionLevel::STANDARD };

    // Detection
    bool enableSynFloodDetection{ true };
    bool enableUdpFloodDetection{ true };
    bool enableIcmpFloodDetection{ true };
    bool enableHttpFloodDetection{ true };
    bool enableDnsFloodDetection{ true };
    bool enableAmplificationDetection{ true };
    bool enableSlowlorisDetection{ true };

    // Thresholds (0 = use defaults)
    uint32_t synFloodThreshold{ 0 };
    uint32_t udpFloodThreshold{ 0 };
    uint32_t icmpFloodThreshold{ 0 };
    uint32_t httpFloodThreshold{ 0 };
    double anomalyDeviationThreshold{ 3.0 };    // Standard deviations

    // Rate limiting
    bool enableRateLimiting{ true };
    uint32_t defaultRateLimitPPS{ DDosProtectionConstants::DEFAULT_RATE_LIMIT_PPS };
    uint32_t defaultBandwidthMbps{ DDosProtectionConstants::DEFAULT_BANDWIDTH_MBPS };

    // Mitigation
    bool autoMitigate{ true };
    bool enableSynCookies{ true };
    uint32_t blacklistDurationSec{ DDosProtectionConstants::BLACKLIST_DURATION_SEC };
    MitigationAction defaultAction{ MitigationAction::RATE_LIMIT };

    // Tracking limits
    size_t maxTrackedIPs{ DDosProtectionConstants::MAX_TRACKED_IPS };
    size_t maxHalfOpenConnections{ DDosProtectionConstants::MAX_HALF_OPEN_CONNECTIONS };

    // Whitelist
    std::vector<std::string> whitelistedIPs;
    std::vector<std::string> whitelistedSubnets;

    // Baseline
    bool enableBaselineModeling{ true };
    std::chrono::hours baselineSamplePeriod{ 24 };

    // Logging
    bool logAllPackets{ false };
    bool logAttacksOnly{ true };

    // Factory methods
    static DDosProtectionConfig CreateDefault() noexcept;
    static DDosProtectionConfig CreateHighSecurity() noexcept;
    static DDosProtectionConfig CreatePerformance() noexcept;
    static DDosProtectionConfig CreateMinimal() noexcept;
};

/**
 * @struct DDosProtectionStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) DDosProtectionStatistics {
    // Traffic statistics
    std::atomic<uint64_t> totalPacketsProcessed{ 0 };
    std::atomic<uint64_t> totalBytesProcessed{ 0 };
    std::atomic<uint64_t> totalConnectionsTracked{ 0 };

    // Detection statistics
    std::atomic<uint64_t> attacksDetected{ 0 };
    std::atomic<uint64_t> synFloodsDetected{ 0 };
    std::atomic<uint64_t> udpFloodsDetected{ 0 };
    std::atomic<uint64_t> icmpFloodsDetected{ 0 };
    std::atomic<uint64_t> httpFloodsDetected{ 0 };
    std::atomic<uint64_t> amplificationAttacks{ 0 };

    // Mitigation statistics
    std::atomic<uint64_t> packetsDropped{ 0 };
    std::atomic<uint64_t> bytesDropped{ 0 };
    std::atomic<uint64_t> connectionsBlocked{ 0 };
    std::atomic<uint64_t> ipsBlacklisted{ 0 };
    std::atomic<uint64_t> synCookiesSent{ 0 };

    // Rate limiting
    std::atomic<uint64_t> rateLimitHits{ 0 };
    std::atomic<uint32_t> activeRateLimits{ 0 };

    // Tracking
    std::atomic<uint32_t> trackedIPs{ 0 };
    std::atomic<uint32_t> halfOpenConnections{ 0 };

    // Alerts
    std::atomic<uint64_t> alertsGenerated{ 0 };
    std::atomic<uint64_t> criticalAlerts{ 0 };

    // Current state
    std::atomic<bool> underAttack{ false };
    std::atomic<uint8_t> currentSeverity{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for attack detection.
 */
using AttackCallback = std::function<void(const AttackInfo& attack)>;

/**
 * @brief Callback for DDoS alerts.
 */
using DDosAlertCallback = std::function<void(const DDosAlert& alert)>;

/**
 * @brief Callback for mitigation events.
 */
using MitigationCallback = std::function<void(const MitigationResult& result)>;

/**
 * @brief Callback for IP blocking.
 */
using BlockCallback = std::function<void(
    const std::string& ip,
    MitigationAction action,
    uint32_t durationSec
)>;

/**
 * @brief Callback for severity change.
 */
using SeverityCallback = std::function<void(
    AttackSeverity oldSeverity,
    AttackSeverity newSeverity
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DDosProtection
 * @brief Enterprise-grade DDoS detection and mitigation.
 *
 * Thread Safety:
 * All public methods are thread-safe. Lock-free packet processing.
 *
 * Usage Example:
 * @code
 * auto& ddos = DDosProtection::Instance();
 * 
 * // Initialize
 * auto config = DDosProtectionConfig::CreateHighSecurity();
 * ddos.Initialize(config);
 * 
 * // Register attack callback
 * ddos.RegisterAttackCallback([](const AttackInfo& attack) {
 *     LogAttack(attack);
 * });
 * 
 * // Start protection
 * ddos.Start();
 * 
 * // Check status
 * if (ddos.IsUnderAttack()) {
 *     ddos.Mitigate();
 * }
 * @endcode
 */
class DDosProtection {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static DDosProtection& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes DDoS protection.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const DDosProtectionConfig& config);

    /**
     * @brief Starts protection threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops protection threads.
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
    // ATTACK DETECTION
    // ========================================================================

    /**
     * @brief Checks if currently under attack.
     * @return True if attack detected.
     */
    [[nodiscard]] bool IsUnderAttack();

    /**
     * @brief Gets current attack information.
     * @return Attack info, or nullopt if no attack.
     */
    [[nodiscard]] std::optional<AttackInfo> GetCurrentAttack() const;

    /**
     * @brief Gets current attack severity.
     * @return Attack severity level.
     */
    [[nodiscard]] AttackSeverity GetCurrentSeverity() const noexcept;

    /**
     * @brief Detects specific attack type.
     * @param type Attack type to check.
     * @return True if attack type detected.
     */
    [[nodiscard]] bool DetectAttack(AttackType type) const;

    // ========================================================================
    // MITIGATION
    // ========================================================================

    /**
     * @brief Applies automatic mitigation.
     */
    void Mitigate();

    /**
     * @brief Applies specific mitigation action.
     * @param action Action to apply.
     * @param targetIP Target IP (empty for global).
     * @return Mitigation result.
     */
    [[nodiscard]] MitigationResult ApplyMitigation(
        MitigationAction action,
        const std::string& targetIP = ""
    );

    /**
     * @brief Blocks an IP address.
     * @param ip IP address to block.
     * @param durationSec Block duration in seconds (0 = permanent).
     * @return True if blocked.
     */
    bool BlockIP(const std::string& ip, uint32_t durationSec = 0);

    /**
     * @brief Blocks a subnet.
     * @param subnet Subnet CIDR notation.
     * @param durationSec Block duration.
     * @return True if blocked.
     */
    bool BlockSubnet(const std::string& subnet, uint32_t durationSec = 0);

    /**
     * @brief Unblocks an IP address.
     * @param ip IP to unblock.
     * @return True if unblocked.
     */
    bool UnblockIP(const std::string& ip);

    /**
     * @brief Clears all mitigations.
     */
    void ClearAllMitigations();

    // ========================================================================
    // RATE LIMITING
    // ========================================================================

    /**
     * @brief Adds rate limit rule.
     * @param rule Rate limit rule.
     * @return Rule ID.
     */
    [[nodiscard]] uint64_t AddRateLimitRule(const RateLimitRule& rule);

    /**
     * @brief Removes rate limit rule.
     * @param ruleId Rule ID.
     * @return True if removed.
     */
    bool RemoveRateLimitRule(uint64_t ruleId);

    /**
     * @brief Rate limits a specific IP.
     * @param ip IP address.
     * @param packetsPerSecond Packet limit.
     * @return True if applied.
     */
    bool RateLimitIP(const std::string& ip, uint32_t packetsPerSecond);

    /**
     * @brief Checks if IP is rate limited.
     * @param ip IP address.
     * @return True if rate limited.
     */
    [[nodiscard]] bool IsRateLimited(const std::string& ip) const;

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================

    /**
     * @brief Gets current traffic metrics.
     * @return Traffic metrics.
     */
    [[nodiscard]] TrafficMetrics GetCurrentMetrics() const;

    /**
     * @brief Gets traffic baseline.
     * @return Traffic baseline, or nullopt.
     */
    [[nodiscard]] std::optional<TrafficBaseline> GetBaseline() const;

    /**
     * @brief Recalculates traffic baseline.
     */
    void RecalculateBaseline();

    /**
     * @brief Gets IP tracking information.
     * @param ip IP address.
     * @return Tracking info, or nullopt.
     */
    [[nodiscard]] std::optional<IPTrackingInfo> GetIPInfo(const std::string& ip) const;

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds IP to whitelist.
     * @param ip IP address.
     * @return True if added.
     */
    bool AddToWhitelist(const std::string& ip);

    /**
     * @brief Removes IP from whitelist.
     * @param ip IP address.
     * @return True if removed.
     */
    bool RemoveFromWhitelist(const std::string& ip);

    /**
     * @brief Checks if IP is whitelisted.
     * @param ip IP address.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(const std::string& ip) const;

    // ========================================================================
    // ATTACK HISTORY
    // ========================================================================

    /**
     * @brief Gets attack history.
     * @param maxCount Maximum number of attacks.
     * @return Vector of past attacks.
     */
    [[nodiscard]] std::vector<AttackInfo> GetAttackHistory(size_t maxCount = 100) const;

    /**
     * @brief Gets attacks in time range.
     * @param start Start time.
     * @param end End time.
     * @return Vector of attacks.
     */
    [[nodiscard]] std::vector<AttackInfo> GetAttacksInRange(
        std::chrono::system_clock::time_point start,
        std::chrono::system_clock::time_point end
    ) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAttackCallback(AttackCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(DDosAlertCallback callback);
    [[nodiscard]] uint64_t RegisterMitigationCallback(MitigationCallback callback);
    [[nodiscard]] uint64_t RegisterBlockCallback(BlockCallback callback);
    [[nodiscard]] uint64_t RegisterSeverityCallback(SeverityCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const DDosProtectionStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;
    bool ExportAttackReport(const std::wstring& outputPath, uint64_t attackId) const;

private:
    DDosProtection();
    ~DDosProtection();

    DDosProtection(const DDosProtection&) = delete;
    DDosProtection& operator=(const DDosProtection&) = delete;

    std::unique_ptr<DDosProtectionImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
