/**
 * ============================================================================
 * ShadowStrike Real-Time - ZERO HOUR PROTECTION (The First Responder)
 * ============================================================================
 *
 * @file ZeroHourProtection.hpp
 * @brief Enterprise-grade zero-day and outbreak protection system.
 *
 * This module provides comprehensive protection during the critical window
 * when new threats emerge before signatures are available. It combines
 * cloud-based verdict caching, aggressive heuristics, machine learning
 * inference, and outbreak intelligence to protect against unknown threats.
 *
 * Key Capabilities:
 * =================
 * 1. CLOUD VERDICT SYSTEM
 *    - Real-time cloud hash lookups for unknown files
 *    - Verdict caching with TTL management
 *    - Hold-and-scan for files pending cloud response
 *    - Fallback strategies when cloud is unreachable
 *    - Multi-cloud redundancy (primary/backup services)
 *
 * 2. OUTBREAK MODE
 *    - Global threat level monitoring
 *    - Automatic sensitivity escalation during outbreaks
 *    - File blocking for unknowns during high-threat periods
 *    - Geographic outbreak correlation
 *    - Industry-specific threat feeds
 *
 * 3. MICRO-SIGNATURE UPDATES
 *    - Rapid signature deployment (5-minute intervals)
 *    - Delta updates for minimal bandwidth
 *    - Emergency signature push mechanism
 *    - Signature rollback capability
 *    - Version coherency verification
 *
 * 4. ADAPTIVE HEURISTICS
 *    - Dynamic sensitivity adjustment
 *    - Behavioral thresholds based on threat landscape
 *    - ML model weight adjustment for emerging threats
 *    - Targeted rule activation for specific malware families
 *
 * 5. FILE HOLD SYSTEM
 *    - Deferred execution for unknown files
 *    - Timeout-based automatic decisions
 *    - User notification and override options
 *    - Process queuing during verdict wait
 *    - Emergency release mechanism
 *
 * 6. THREAT INTELLIGENCE INTEGRATION
 *    - IOC feeds with zero-hour indicators
 *    - Campaign tracking and correlation
 *    - Threat actor TTPs monitoring
 *    - Predictive threat modeling
 *
 * Protection Timeline:
 * ====================
 *   T+0    : New threat released into the wild
 *   T+0-5m : Cloud detection (hash seen globally)
 *   T+5-15m: Micro-signature deployed to endpoints
 *   T+15-1h: Full signature with metadata available
 *   T+1-24h: Behavioral patterns added to ML models
 *
 *   Zero Hour Protection covers T+0 to T+24h window
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1204: User Execution (Prevention via hold)
 * - T1566: Phishing (Zero-day attachment blocking)
 * - T1027: Obfuscated Files (Cloud detonation)
 * - T1059: Command Scripting (Script hold/analysis)
 * - T1486: Data Encrypted (Ransomware outbreak response)
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                      ZeroHourProtection                             │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │CloudVerdict  │  │ OutbreakMgr  │  │    MicroSigUpdater       │  │
 *   │  │ Manager      │  │              │  │                          │  │
 *   │  │ - Lookups    │  │ - ThreatLvl  │  │ - DeltaUpdates           │  │
 *   │  │ - Caching    │  │ - Escalation │  │ - EmergencyPush          │  │
 *   │  │ - Fallback   │  │ - GeoCorrel  │  │ - Rollback               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │FileHoldMgr   │  │AdaptiveHeur  │  │   ThreatFeedIntegrator   │  │
 *   │  │              │  │ istics       │  │                          │  │
 *   │  │ - Pending    │  │ - Sensitivity│  │ - IOCFeeds               │  │
 *   │  │ - Timeouts   │  │ - MLWeights  │  │ - Campaigns              │  │
 *   │  │ - Verdicts   │  │ - Rules      │  │ - Predictions            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                    ┌───────────────┼───────────────┐
 *                    ▼               ▼               ▼
 *            ┌──────────────┐ ┌──────────┐ ┌─────────────────┐
 *            │ CloudService │ │ThreatDB  │ │ SignatureStore  │
 *            └──────────────┘ └──────────┘ └─────────────────┘
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Verdict cache uses concurrent data structures
 * - Outbreak state changes are atomic
 * - Hold queue supports concurrent access
 *
 * Performance Considerations:
 * ===========================
 * - Local verdict cache before cloud lookup
 * - Async cloud queries for non-blocking operation
 * - Batch cloud queries for efficiency
 * - Pre-fetch for frequently accessed file types
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see ThreatIntel/ThreatIntelManager.hpp for IOC management
 * @see SignatureStore/SignatureStore.hpp for signature management
 * @see Utils/CryptoUtils.hpp for hash computations
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/HashUtils.hpp"             // File hashing
#include "../Utils/CacheManager.hpp"          // Verdict caching
#include "../ThreatIntel/ThreatIntelLookup.hpp"  // Cloud lookups
#include "../SignatureStore/SignatureStore.hpp" // Rapid signature updates
#include "../Whitelist/WhiteListStore.hpp"    // Known-good files

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
#include <queue>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <future>
#include <span>

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class ZeroHourProtectionImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace ZeroHourConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Timing constants
    constexpr uint32_t DEFAULT_CLOUD_TIMEOUT_MS = 5000;          // 5 seconds
    constexpr uint32_t FAST_CLOUD_TIMEOUT_MS = 1000;             // 1 second for cached
    constexpr uint32_t EMERGENCY_TIMEOUT_MS = 500;               // 0.5 seconds
    constexpr uint32_t DEFAULT_HOLD_TIMEOUT_MS = 30000;          // 30 seconds max hold
    constexpr uint32_t MICRO_SIG_INTERVAL_MS = 300000;           // 5 minutes
    constexpr uint32_t EMERGENCY_SIG_CHECK_MS = 60000;           // 1 minute during outbreak
    constexpr uint32_t OUTBREAK_CHECK_INTERVAL_MS = 60000;       // 1 minute
    constexpr uint32_t CACHE_CLEANUP_INTERVAL_MS = 300000;       // 5 minutes

    // Cache settings
    constexpr size_t MAX_VERDICT_CACHE_SIZE = 1000000;           // 1M entries
    constexpr size_t MAX_PENDING_FILES = 10000;                  // Max files on hold
    constexpr uint32_t VERDICT_CACHE_TTL_CLEAN_MS = 86400000;    // 24 hours for clean
    constexpr uint32_t VERDICT_CACHE_TTL_MALICIOUS_MS = 604800000; // 7 days for malware
    constexpr uint32_t VERDICT_CACHE_TTL_UNKNOWN_MS = 3600000;   // 1 hour for unknown

    // Outbreak thresholds
    constexpr uint32_t OUTBREAK_THRESHOLD_DETECTIONS = 100;      // Per minute globally
    constexpr uint32_t OUTBREAK_THRESHOLD_UNIQUE_HASHES = 50;    // New unique threats
    constexpr double OUTBREAK_SENSITIVITY_MULTIPLIER = 1.5;      // Heuristic boost

    // File size limits
    constexpr uint64_t MAX_CLOUD_SUBMIT_SIZE = 100ULL * 1024 * 1024;  // 100 MB
    constexpr uint64_t QUICK_ANALYSIS_SIZE = 5ULL * 1024 * 1024;      // 5 MB

    // Micro-signature settings
    constexpr size_t MAX_MICRO_SIG_BATCH = 1000;                 // Max sigs per update
    constexpr uint32_t MAX_ROLLBACK_VERSIONS = 10;               // Keep last 10 versions

    // ML model settings
    constexpr float DEFAULT_ML_THRESHOLD = 0.7f;                 // 70% confidence
    constexpr float OUTBREAK_ML_THRESHOLD = 0.5f;                // Lower threshold during outbreak
    constexpr size_t MAX_ML_MODELS = 10;                         // Max loaded models

}  // namespace ZeroHourConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ThreatLevel
 * @brief Global threat level indicating current security posture.
 */
enum class ThreatLevel : uint8_t {
    NORMAL = 0,              ///< Standard operations
    ELEVATED = 1,            ///< Increased activity detected
    HIGH = 2,                ///< Significant threat activity
    CRITICAL = 3,            ///< Active outbreak in progress
    LOCKDOWN = 4,            ///< Maximum protection (blocks unknowns)
    CUSTOM = 5               ///< Custom threat level profile
};

/**
 * @enum CloudVerdict
 * @brief Verdict returned from cloud analysis.
 */
enum class CloudVerdict : uint8_t {
    UNKNOWN = 0,             ///< Never seen before
    CLEAN = 1,               ///< Known good
    SUSPICIOUS = 2,          ///< Behavioral anomalies
    MALICIOUS = 3,           ///< Confirmed malware
    PUA = 4,                 ///< Potentially Unwanted Application
    RISKWARE = 5,            ///< Legal but risky software
    PENDING = 6,             ///< Analysis in progress
    ERROR = 7,               ///< Lookup failed
    WHITELISTED = 8,         ///< Explicitly trusted
    BLACKLISTED = 9          ///< Explicitly blocked
};

/**
 * @enum HoldReason
 * @brief Reason a file is being held for analysis.
 */
enum class HoldReason : uint8_t {
    UNKNOWN_HASH = 0,        ///< Hash not in any database
    CLOUD_PENDING = 1,       ///< Waiting for cloud response
    DETONATION_PENDING = 2,  ///< Submitted for sandbox analysis
    SIGNATURE_PENDING = 3,   ///< Waiting for micro-signature
    ML_ANALYSIS = 4,         ///< ML model analysis in progress
    OUTBREAK_HOLD = 5,       ///< Blocked due to outbreak mode
    ADMIN_HOLD = 6,          ///< Manually held by administrator
    POLICY_HOLD = 7          ///< Policy requires explicit approval
};

/**
 * @enum HoldDecision
 * @brief Decision for a held file after analysis.
 */
enum class HoldDecision : uint8_t {
    ALLOW = 0,               ///< File is safe, release hold
    BLOCK = 1,               ///< File is malicious, deny execution
    QUARANTINE = 2,          ///< Move to quarantine
    DELETE = 3,              ///< Delete immediately
    TIMEOUT_ALLOW = 4,       ///< Timeout reached, allow (policy)
    TIMEOUT_BLOCK = 5,       ///< Timeout reached, block (policy)
    USER_OVERRIDE = 6,       ///< User requested override
    ADMIN_RELEASE = 7        ///< Administrator released
};

/**
 * @enum OutbreakType
 * @brief Type of outbreak detected.
 */
enum class OutbreakType : uint8_t {
    NONE = 0,
    RANSOMWARE = 1,          ///< Encryption-based attack
    WORM = 2,                ///< Self-propagating malware
    TROJAN = 3,              ///< Remote access/backdoor
    CRYPTOMINER = 4,         ///< Cryptocurrency mining
    BOTNET = 5,              ///< Command and control
    APT = 6,                 ///< Advanced persistent threat
    SUPPLY_CHAIN = 7,        ///< Software supply chain attack
    ZERO_DAY = 8,            ///< Unknown vulnerability exploit
    PHISHING_CAMPAIGN = 9,   ///< Mass phishing operation
    MIXED = 10               ///< Multiple threat types
};

/**
 * @enum MicroSigType
 * @brief Type of micro-signature update.
 */
enum class MicroSigType : uint8_t {
    HASH_ONLY = 0,           ///< Simple hash signature
    PATTERN = 1,             ///< Byte pattern signature
    BEHAVIOR = 2,            ///< Behavioral indicator
    YARA = 3,                ///< YARA rule
    ML_WEIGHT = 4,           ///< ML model weight update
    IOC = 5,                 ///< Indicator of compromise
    RULE = 6                 ///< Detection rule
};

/**
 * @enum CloudServiceStatus
 * @brief Status of cloud service connectivity.
 */
enum class CloudServiceStatus : uint8_t {
    CONNECTED = 0,           ///< Normal operation
    DEGRADED = 1,            ///< Partial connectivity
    DISCONNECTED = 2,        ///< No connectivity
    RATE_LIMITED = 3,        ///< Rate limit exceeded
    AUTHENTICATION_ERROR = 4, ///< Auth failure
    MAINTENANCE = 5          ///< Scheduled maintenance
};

/**
 * @enum FallbackPolicy
 * @brief Policy when cloud is unavailable.
 */
enum class FallbackPolicy : uint8_t {
    ALLOW_UNKNOWN = 0,       ///< Allow unknowns (less secure)
    BLOCK_UNKNOWN = 1,       ///< Block unknowns (more secure)
    HOLD_TIMEOUT = 2,        ///< Hold until timeout, then decide
    LOCAL_ONLY = 3,          ///< Use only local signatures
    HEURISTICS_ONLY = 4,     ///< Rely on heuristics
    ASK_USER = 5             ///< Prompt user for decision
};

/**
 * @enum HeuristicMode
 * @brief Heuristic sensitivity mode.
 */
enum class HeuristicMode : uint8_t {
    MINIMAL = 0,             ///< Lowest sensitivity (fewer FPs)
    STANDARD = 1,            ///< Balanced detection
    AGGRESSIVE = 2,          ///< Higher sensitivity
    MAXIMUM = 3,             ///< Highest sensitivity (more FPs)
    OUTBREAK = 4             ///< Dynamic outbreak-adjusted
};

/**
 * @enum FileCategory
 * @brief Category of file for differentiated handling.
 */
enum class FileCategory : uint8_t {
    UNKNOWN = 0,
    EXECUTABLE = 1,          ///< PE, ELF, Mach-O
    SCRIPT = 2,              ///< PS1, BAT, VBS, JS
    DOCUMENT = 3,            ///< Office, PDF
    ARCHIVE = 4,             ///< ZIP, RAR, 7z
    INSTALLER = 5,           ///< MSI, Setup.exe
    DRIVER = 6,              ///< SYS, kernel modules
    DLL = 7,                 ///< Dynamic libraries
    FIRMWARE = 8,            ///< UEFI, embedded
    MACRO = 9,               ///< Office macros
    EMAIL_ATTACHMENT = 10    ///< From email context
};

/**
 * @enum CloudQueryPriority
 * @brief Priority level for cloud queries.
 */
enum class CloudQueryPriority : uint8_t {
    LOW = 0,                 ///< Background, can batch
    NORMAL = 1,              ///< Standard priority
    HIGH = 2,                ///< User waiting
    CRITICAL = 3,            ///< Blocking execution
    EMERGENCY = 4            ///< Outbreak-related
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct FileHash
 * @brief Multi-algorithm hash of a file.
 */
struct alignas(8) FileHash {
    std::array<uint8_t, 32> sha256{ 0 };
    std::array<uint8_t, 16> md5{ 0 };
    std::array<uint8_t, 4> imphash{ 0 };       ///< Import hash (PE files)
    std::array<uint8_t, 32> fuzzyHash{ 0 };     ///< Fuzzy hash
    std::array<uint8_t, 32> tlsh{ 0 };         ///< Trend Micro LSH
    
    bool hasImphash{ false };
    bool hasFuzzyHash{ false };
    bool hasTlsh{ false };

    // String representations (computed on demand)
    std::wstring GetSHA256String() const;
    std::wstring GetMD5String() const;
};

/**
 * @struct CloudVerdictResult
 * @brief Complete result from cloud verdict lookup.
 */
struct alignas(64) CloudVerdictResult {
    // Primary verdict
    CloudVerdict verdict{ CloudVerdict::UNKNOWN };
    uint8_t confidence{ 0 };                   ///< 0-100 confidence score

    // Timing
    std::chrono::system_clock::time_point queryTime;
    std::chrono::system_clock::time_point verdictTime;
    std::chrono::microseconds latency{ 0 };

    // Threat details (if malicious)
    std::wstring threatName;
    std::wstring threatFamily;
    std::wstring threatCategory;
    std::vector<std::wstring> mitreIds;

    // Metadata
    uint64_t globalPrevalence{ 0 };            ///< How many times seen globally
    uint64_t firstSeen{ 0 };                   ///< Unix timestamp first seen
    uint64_t lastSeen{ 0 };                    ///< Unix timestamp last seen
    std::wstring vendor;                       ///< Which cloud service responded

    // Cache info
    bool fromCache{ false };
    std::chrono::system_clock::time_point cacheExpiry;

    // Error handling
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;
};

/**
 * @struct HeldFile
 * @brief Information about a file being held for analysis.
 */
struct alignas(64) HeldFile {
    // Identity
    uint64_t holdId{ 0 };
    std::wstring filePath;
    FileHash hash;

    // Hold context
    HoldReason reason{ HoldReason::UNKNOWN_HASH };
    std::chrono::system_clock::time_point holdTime;
    std::chrono::system_clock::time_point timeoutTime;
    
    // Process context
    uint32_t requestingPid{ 0 };
    std::wstring requestingProcess;
    uint32_t requestingTid{ 0 };

    // File metadata
    FileCategory category{ FileCategory::UNKNOWN };
    uint64_t fileSize{ 0 };
    std::wstring originalName;
    std::wstring publisher;
    bool isSigned{ false };

    // Status
    bool isAnalyzing{ false };
    std::wstring analysisStatus;
    uint8_t analysisProgress{ 0 };             ///< 0-100

    // Decision (when available)
    std::optional<HoldDecision> decision;
    std::optional<CloudVerdictResult> cloudResult;
    std::wstring decisionReason;
};

/**
 * @struct OutbreakInfo
 * @brief Information about an active outbreak.
 */
struct alignas(64) OutbreakInfo {
    // Identity
    uint64_t outbreakId{ 0 };
    std::wstring name;
    OutbreakType type{ OutbreakType::NONE };

    // Timing
    std::chrono::system_clock::time_point detectedAt;
    std::chrono::system_clock::time_point lastUpdated;
    std::chrono::system_clock::time_point estimatedEnd;

    // Severity
    ThreatLevel recommendedLevel{ ThreatLevel::ELEVATED };
    uint8_t severity{ 0 };                     ///< 1-10 severity score

    // Scope
    std::vector<std::wstring> affectedRegions;
    std::vector<std::wstring> affectedIndustries;
    uint64_t globalVictimCount{ 0 };
    uint64_t localVictimCount{ 0 };            ///< In customer's environment

    // Indicators
    std::vector<FileHash> knownHashes;
    std::vector<std::wstring> knownIPs;
    std::vector<std::wstring> knownDomains;
    std::vector<std::wstring> knownFileNames;
    std::vector<std::wstring> yaraRules;

    // Response
    std::wstring mitigationGuidance;
    std::vector<std::wstring> recommendedActions;
    bool autoResponseEnabled{ false };
};

/**
 * @struct MicroSignature
 * @brief A rapid-deployed signature for emerging threats.
 */
struct alignas(64) MicroSignature {
    // Identity
    uint64_t signatureId{ 0 };
    uint32_t version{ 0 };
    MicroSigType type{ MicroSigType::HASH_ONLY };

    // Timestamp
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;

    // Content (varies by type)
    std::variant<
        FileHash,                              // HASH_ONLY
        std::vector<uint8_t>,                  // PATTERN
        std::wstring,                          // BEHAVIOR, YARA, RULE
        std::vector<float>                     // ML_WEIGHT
    > content;

    // Metadata
    std::wstring threatName;
    std::wstring description;
    uint8_t severity{ 0 };
    bool isEmergency{ false };
    uint64_t relatedOutbreakId{ 0 };

    // Targeting
    std::vector<FileCategory> targetCategories;
    std::vector<std::wstring> targetExtensions;
};

/**
 * @struct MicroSigUpdatePackage
 * @brief Package of micro-signatures for batch update.
 */
struct alignas(64) MicroSigUpdatePackage {
    // Package identity
    uint64_t packageId{ 0 };
    uint32_t baseVersion{ 0 };
    uint32_t targetVersion{ 0 };
    bool isDelta{ true };                      ///< Delta vs full update

    // Signatures
    std::vector<MicroSignature> additions;
    std::vector<uint64_t> removals;            ///< Signature IDs to remove

    // Package metadata
    std::chrono::system_clock::time_point timestamp;
    uint64_t packageSize{ 0 };
    std::array<uint8_t, 32> sha256{ 0 };       ///< Package integrity
    std::vector<uint8_t> signature;            ///< Digital signature

    // Urgency
    bool isEmergency{ false };
    ThreatLevel requiredLevel{ ThreatLevel::NORMAL };
};

/**
 * @struct AdaptiveHeuristicConfig
 * @brief Configuration for adaptive heuristics during zero-hour protection.
 */
struct alignas(64) AdaptiveHeuristicConfig {
    // Mode
    HeuristicMode mode{ HeuristicMode::STANDARD };
    bool autoAdjust{ true };                   ///< Auto-adjust based on threat level

    // Sensitivity multipliers by category
    std::unordered_map<FileCategory, float> categoryMultipliers;

    // ML thresholds
    float mlDetectionThreshold{ ZeroHourConstants::DEFAULT_ML_THRESHOLD };
    float mlBlockThreshold{ 0.9f };
    bool useEnsemble{ true };                  ///< Combine multiple ML models

    // Behavioral thresholds
    uint32_t maxApiCallsPerSecond{ 1000 };
    uint32_t maxFileOperationsPerSecond{ 500 };
    uint32_t maxRegistryOperationsPerSecond{ 200 };
    uint32_t maxNetworkConnectionsPerMinute{ 100 };

    // Outbreak adjustments
    float outbreakSensitivityMultiplier{ ZeroHourConstants::OUTBREAK_SENSITIVITY_MULTIPLIER };

    // Factory methods
    static AdaptiveHeuristicConfig CreateDefault() noexcept;
    static AdaptiveHeuristicConfig CreateAggressive() noexcept;
    static AdaptiveHeuristicConfig CreateConservative() noexcept;
    static AdaptiveHeuristicConfig CreateOutbreak() noexcept;
};

/**
 * @struct CloudServiceConfig
 * @brief Configuration for cloud service connectivity.
 */
struct alignas(64) CloudServiceConfig {
    // Primary service
    std::wstring primaryEndpoint;
    std::wstring apiKey;
    std::wstring customerId;

    // Backup services
    std::vector<std::wstring> backupEndpoints;

    // Timeouts
    uint32_t connectionTimeoutMs{ ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS };
    uint32_t queryTimeoutMs{ ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS };

    // Retry policy
    uint32_t maxRetries{ 3 };
    uint32_t retryDelayMs{ 1000 };
    bool useExponentialBackoff{ true };

    // Rate limiting
    uint32_t maxQueriesPerSecond{ 100 };
    uint32_t maxQueriesPerMinute{ 3000 };
    uint32_t batchSize{ 50 };                  ///< Hashes per batch query

    // Fallback
    FallbackPolicy fallbackPolicy{ FallbackPolicy::HOLD_TIMEOUT };

    // Security
    bool requireTLS12{ true };
    bool verifyCertificate{ true };
    std::wstring certificatePinning;           ///< Pin to specific cert

    // Proxy
    bool useProxy{ false };
    std::wstring proxyHost;
    uint16_t proxyPort{ 0 };
    std::wstring proxyUsername;
    std::wstring proxyPassword;
};

/**
 * @struct ZeroHourProtectionConfig
 * @brief Complete configuration for zero-hour protection.
 */
struct alignas(64) ZeroHourProtectionConfig {
    // Feature toggles
    bool enabled{ true };
    bool cloudLookupEnabled{ true };
    bool holdUnknownFiles{ true };
    bool microSignaturesEnabled{ true };
    bool adaptiveHeuristicsEnabled{ true };
    bool outbreakModeEnabled{ true };

    // Hold settings
    uint32_t holdTimeoutMs{ ZeroHourConstants::DEFAULT_HOLD_TIMEOUT_MS };
    HoldDecision timeoutDecision{ HoldDecision::TIMEOUT_ALLOW };
    bool allowUserOverride{ false };
    bool notifyOnHold{ true };

    // Cloud service
    CloudServiceConfig cloudConfig;

    // Signature updates
    uint32_t microSigIntervalMs{ ZeroHourConstants::MICRO_SIG_INTERVAL_MS };
    bool autoApplyEmergencySigs{ true };
    uint32_t maxRollbackVersions{ ZeroHourConstants::MAX_ROLLBACK_VERSIONS };

    // Heuristics
    AdaptiveHeuristicConfig heuristicConfig;

    // Outbreak response
    ThreatLevel autoEscalateLevel{ ThreatLevel::HIGH };
    bool autoLockdownOnCritical{ true };
    uint32_t outbreakCheckIntervalMs{ ZeroHourConstants::OUTBREAK_CHECK_INTERVAL_MS };

    // Cache settings
    size_t maxVerdictCacheSize{ ZeroHourConstants::MAX_VERDICT_CACHE_SIZE };
    uint32_t cleanVerdictTTLMs{ ZeroHourConstants::VERDICT_CACHE_TTL_CLEAN_MS };
    uint32_t maliciousVerdictTTLMs{ ZeroHourConstants::VERDICT_CACHE_TTL_MALICIOUS_MS };
    uint32_t unknownVerdictTTLMs{ ZeroHourConstants::VERDICT_CACHE_TTL_UNKNOWN_MS };

    // File size limits
    uint64_t maxCloudSubmitSize{ ZeroHourConstants::MAX_CLOUD_SUBMIT_SIZE };
    uint64_t quickAnalysisSize{ ZeroHourConstants::QUICK_ANALYSIS_SIZE };

    // Exclusions
    std::vector<std::wstring> excludedPaths;
    std::vector<std::wstring> excludedExtensions;
    std::vector<std::wstring> excludedPublishers;

    // Factory methods
    static ZeroHourProtectionConfig CreateDefault() noexcept;
    static ZeroHourProtectionConfig CreateEnterprise() noexcept;
    static ZeroHourProtectionConfig CreateHighSecurity() noexcept;
    static ZeroHourProtectionConfig CreatePerformance() noexcept;
};

/**
 * @struct ZeroHourStatistics
 * @brief Runtime statistics for zero-hour protection.
 */
struct alignas(64) ZeroHourStatistics {
    // Cloud operations
    std::atomic<uint64_t> totalCloudQueries{ 0 };
    std::atomic<uint64_t> cloudCacheHits{ 0 };
    std::atomic<uint64_t> cloudCacheMisses{ 0 };
    std::atomic<uint64_t> cloudTimeouts{ 0 };
    std::atomic<uint64_t> cloudErrors{ 0 };

    // Verdicts
    std::atomic<uint64_t> verdictsClean{ 0 };
    std::atomic<uint64_t> verdictsMalicious{ 0 };
    std::atomic<uint64_t> verdictsSuspicious{ 0 };
    std::atomic<uint64_t> verdictsUnknown{ 0 };
    std::atomic<uint64_t> verdictsPUA{ 0 };

    // Hold operations
    std::atomic<uint64_t> filesHeld{ 0 };
    std::atomic<uint64_t> filesReleased{ 0 };
    std::atomic<uint64_t> filesBlocked{ 0 };
    std::atomic<uint64_t> holdTimeouts{ 0 };
    std::atomic<uint64_t> userOverrides{ 0 };
    std::atomic<uint32_t> currentHeldFiles{ 0 };

    // Signature updates
    std::atomic<uint64_t> microSigUpdates{ 0 };
    std::atomic<uint64_t> emergencySigUpdates{ 0 };
    std::atomic<uint64_t> signaturesApplied{ 0 };
    std::atomic<uint32_t> currentSigVersion{ 0 };

    // Outbreak tracking
    std::atomic<uint64_t> outbreakModeActivations{ 0 };
    std::atomic<uint64_t> outbreakDetections{ 0 };
    std::atomic<uint64_t> outbreakBlockedFiles{ 0 };
    std::atomic<uint8_t> currentThreatLevel{ 0 };

    // Performance
    std::atomic<uint64_t> totalQueryTimeUs{ 0 };
    std::atomic<uint64_t> avgQueryTimeUs{ 0 };
    std::atomic<uint64_t> maxQueryTimeUs{ 0 };

    // Errors
    std::atomic<uint64_t> errorCount{ 0 };

    void Reset() noexcept;
};

/**
 * @struct FileAnalysisRequest
 * @brief Request to analyze a file through zero-hour protection.
 */
struct alignas(64) FileAnalysisRequest {
    // File information
    std::wstring filePath;
    FileHash hash;
    FileCategory category{ FileCategory::UNKNOWN };
    uint64_t fileSize{ 0 };

    // Context
    uint32_t requestingPid{ 0 };
    std::wstring requestingProcess;
    bool isExecutionAttempt{ false };          ///< File is about to execute
    bool isFromEmail{ false };
    bool isFromBrowser{ false };
    bool isFromRemovable{ false };

    // Options
    CloudQueryPriority priority{ CloudQueryPriority::NORMAL };
    bool allowHold{ true };
    bool synchronous{ false };                 ///< Wait for result
    uint32_t timeoutMs{ ZeroHourConstants::DEFAULT_HOLD_TIMEOUT_MS };

    // Callback (if async)
    std::function<void(const CloudVerdictResult&)> callback;
};

/**
 * @struct FileAnalysisResult
 * @brief Result of zero-hour file analysis.
 */
struct alignas(64) FileAnalysisResult {
    // Primary result
    bool shouldAllow{ false };
    CloudVerdict verdict{ CloudVerdict::UNKNOWN };
    std::wstring threatName;

    // Details
    CloudVerdictResult cloudResult;
    bool wasHeld{ false };
    uint64_t holdId{ 0 };
    HoldDecision holdDecision{ HoldDecision::ALLOW };

    // Source of decision
    enum class Source : uint8_t {
        CLOUD_LOOKUP = 0,
        LOCAL_CACHE = 1,
        MICRO_SIGNATURE = 2,
        HEURISTIC = 3,
        ML_MODEL = 4,
        WHITELIST = 5,
        OUTBREAK_POLICY = 6,
        FALLBACK_POLICY = 7,
        USER_OVERRIDE = 8
    } source{ Source::CLOUD_LOOKUP };

    // Timing
    std::chrono::microseconds totalTime{ 0 };
    std::chrono::microseconds cloudTime{ 0 };
    std::chrono::microseconds holdTime{ 0 };

    // Error handling
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for verdict updates.
 * @param filePath The file path
 * @param result The analysis result
 */
using VerdictCallback = std::function<void(
    const std::wstring& filePath,
    const FileAnalysisResult& result
)>;

/**
 * @brief Callback for file hold events.
 * @param heldFile Information about the held file
 */
using FileHoldCallback = std::function<void(
    const HeldFile& heldFile
)>;

/**
 * @brief Callback for outbreak events.
 * @param outbreak Information about the outbreak
 * @param isNew True if this is a new outbreak
 */
using OutbreakCallback = std::function<void(
    const OutbreakInfo& outbreak,
    bool isNew
)>;

/**
 * @brief Callback for threat level changes.
 * @param previousLevel Previous threat level
 * @param newLevel New threat level
 * @param reason Reason for the change
 */
using ThreatLevelCallback = std::function<void(
    ThreatLevel previousLevel,
    ThreatLevel newLevel,
    std::wstring_view reason
)>;

/**
 * @brief Callback for signature update events.
 * @param package The update package that was applied
 * @param success Whether the update succeeded
 */
using SignatureUpdateCallback = std::function<void(
    const MicroSigUpdatePackage& package,
    bool success
)>;

/**
 * @brief Callback for cloud service status changes.
 * @param previousStatus Previous status
 * @param newStatus New status
 */
using CloudStatusCallback = std::function<void(
    CloudServiceStatus previousStatus,
    CloudServiceStatus newStatus
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class ZeroHourProtection
 * @brief Enterprise-grade zero-day and outbreak protection system.
 *
 * This class provides comprehensive protection against unknown and
 * emerging threats during the critical zero-hour window before
 * signatures are available.
 *
 * Thread Safety:
 * All public methods are thread-safe and can be called concurrently.
 *
 * Usage Example:
 * @code
 * auto& zhp = ZeroHourProtection::Instance();
 * 
 * // Initialize with enterprise config
 * auto config = ZeroHourProtectionConfig::CreateEnterprise();
 * zhp.Initialize(config);
 * 
 * // Check if a file should be allowed
 * FileAnalysisRequest request;
 * request.filePath = L"C:\\Users\\user\\Downloads\\unknown.exe";
 * request.priority = CloudQueryPriority::HIGH;
 * 
 * auto result = zhp.AnalyzeFile(request);
 * if (result.shouldAllow) {
 *     // Proceed with execution
 * } else {
 *     // Block and notify
 * }
 * @endcode
 */
class ZeroHourProtection {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance of ZeroHourProtection.
     * @return Reference to the singleton instance.
     */
    static ZeroHourProtection& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the zero-hour protection system.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    bool Initialize(const ZeroHourProtectionConfig& config);

    /**
     * @brief Shuts down the system gracefully.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if the system is initialized.
     * @return True if initialized and ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Gets the current configuration.
     * @return Current configuration (copy for thread safety).
     */
    [[nodiscard]] ZeroHourProtectionConfig GetConfig() const;

    /**
     * @brief Updates configuration at runtime.
     * @param config New configuration settings.
     * @return True if update succeeded.
     */
    bool UpdateConfig(const ZeroHourProtectionConfig& config);

    // ========================================================================
    // OUTBREAK MODE CONTROL
    // ========================================================================

    /**
     * @brief Sets the global outbreak mode.
     * @param active True to activate outbreak mode.
     * @param reason Reason for the change.
     */
    void SetOutbreakMode(bool active, std::wstring_view reason = L"");

    /**
     * @brief Checks if outbreak mode is active.
     * @return True if in outbreak mode.
     */
    [[nodiscard]] bool IsOutbreakModeActive() const noexcept;

    /**
     * @brief Gets the current threat level.
     * @return Current threat level.
     */
    [[nodiscard]] ThreatLevel GetThreatLevel() const noexcept;

    /**
     * @brief Sets the threat level manually.
     * @param level New threat level.
     * @param reason Reason for the change.
     */
    void SetThreatLevel(ThreatLevel level, std::wstring_view reason = L"");

    /**
     * @brief Gets active outbreak information.
     * @return Vector of active outbreaks.
     */
    [[nodiscard]] std::vector<OutbreakInfo> GetActiveOutbreaks() const;

    /**
     * @brief Acknowledges an outbreak.
     * @param outbreakId The outbreak ID.
     * @return True if acknowledged.
     */
    bool AcknowledgeOutbreak(uint64_t outbreakId);

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes a file through zero-hour protection.
     * @param request Analysis request with file details.
     * @return Analysis result.
     */
    [[nodiscard]] FileAnalysisResult AnalyzeFile(const FileAnalysisRequest& request);

    /**
     * @brief Quick check if a file should be held for analysis.
     * @param filePath The file path.
     * @return True if the file should be held.
     */
    [[nodiscard]] bool ShouldHoldFile(const std::wstring& filePath);

    /**
     * @brief Gets the cloud verdict for a file hash.
     * @param hash The file hash.
     * @param timeout Timeout in milliseconds.
     * @return Cloud verdict result.
     */
    [[nodiscard]] CloudVerdictResult GetCloudVerdict(
        const FileHash& hash,
        uint32_t timeout = ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS
    );

    /**
     * @brief Batch queries cloud verdicts for multiple hashes.
     * @param hashes Vector of file hashes.
     * @param timeout Timeout for the entire batch.
     * @return Map of hash to verdict result.
     */
    [[nodiscard]] std::unordered_map<std::wstring, CloudVerdictResult> GetCloudVerdictBatch(
        const std::vector<FileHash>& hashes,
        uint32_t timeout = ZeroHourConstants::DEFAULT_CLOUD_TIMEOUT_MS * 2
    );

    /**
     * @brief Submits a file for cloud sandbox analysis.
     * @param filePath The file path.
     * @param priority Submission priority.
     * @return Submission ID for tracking, or 0 on failure.
     */
    [[nodiscard]] uint64_t SubmitForDetonation(
        const std::wstring& filePath,
        CloudQueryPriority priority = CloudQueryPriority::NORMAL
    );

    // ========================================================================
    // HOLD MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets information about a held file.
     * @param holdId The hold ID.
     * @return Held file information, or nullopt if not found.
     */
    [[nodiscard]] std::optional<HeldFile> GetHeldFile(uint64_t holdId) const;

    /**
     * @brief Gets information about a held file by path.
     * @param filePath The file path.
     * @return Held file information, or nullopt if not held.
     */
    [[nodiscard]] std::optional<HeldFile> GetHeldFileByPath(const std::wstring& filePath) const;

    /**
     * @brief Lists all currently held files.
     * @return Vector of held file information.
     */
    [[nodiscard]] std::vector<HeldFile> GetAllHeldFiles() const;

    /**
     * @brief Releases a held file with a specified decision.
     * @param holdId The hold ID.
     * @param decision The decision for the file.
     * @param reason Reason for the decision.
     * @return True if released successfully.
     */
    bool ReleaseHeldFile(
        uint64_t holdId,
        HoldDecision decision,
        std::wstring_view reason = L""
    );

    /**
     * @brief Releases all held files with a decision.
     * @param decision The decision for all files.
     * @param reason Reason for the mass release.
     * @return Number of files released.
     */
    uint32_t ReleaseAllHeldFiles(
        HoldDecision decision,
        std::wstring_view reason = L""
    );

    // ========================================================================
    // MICRO-SIGNATURE MANAGEMENT
    // ========================================================================

    /**
     * @brief Checks for and downloads micro-signature updates.
     * @param force Force check even if not due.
     * @return True if updates were applied.
     */
    bool CheckForSignatureUpdates(bool force = false);

    /**
     * @brief Applies a micro-signature update package.
     * @param package The update package.
     * @return True if applied successfully.
     */
    bool ApplySignatureUpdate(const MicroSigUpdatePackage& package);

    /**
     * @brief Rolls back to a previous signature version.
     * @param targetVersion Target version to roll back to.
     * @return True if rollback succeeded.
     */
    bool RollbackSignatures(uint32_t targetVersion);

    /**
     * @brief Gets the current signature version.
     * @return Current version number.
     */
    [[nodiscard]] uint32_t GetSignatureVersion() const noexcept;

    /**
     * @brief Gets available rollback versions.
     * @return Vector of available versions.
     */
    [[nodiscard]] std::vector<uint32_t> GetAvailableRollbackVersions() const;

    // ========================================================================
    // ADAPTIVE HEURISTICS
    // ========================================================================

    /**
     * @brief Gets the current heuristic configuration.
     * @return Current heuristic config.
     */
    [[nodiscard]] AdaptiveHeuristicConfig GetHeuristicConfig() const;

    /**
     * @brief Updates heuristic configuration.
     * @param config New heuristic configuration.
     * @return True if updated successfully.
     */
    bool UpdateHeuristicConfig(const AdaptiveHeuristicConfig& config);

    /**
     * @brief Gets the effective ML threshold for the current threat level.
     * @return Current ML threshold.
     */
    [[nodiscard]] float GetEffectiveMLThreshold() const noexcept;

    // ========================================================================
    // CLOUD SERVICE MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets the current cloud service status.
     * @return Current status.
     */
    [[nodiscard]] CloudServiceStatus GetCloudStatus() const noexcept;

    /**
     * @brief Tests connectivity to the cloud service.
     * @return True if connected and responsive.
     */
    [[nodiscard]] bool TestCloudConnectivity();

    /**
     * @brief Forces reconnection to the cloud service.
     * @return True if reconnection succeeded.
     */
    bool ReconnectCloud();

    /**
     * @brief Gets cloud service latency statistics.
     * @return Average latency in milliseconds.
     */
    [[nodiscard]] uint32_t GetCloudLatency() const noexcept;

    // ========================================================================
    // VERDICT CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Queries the local verdict cache.
     * @param hash The file hash.
     * @return Cached verdict, or nullopt if not cached.
     */
    [[nodiscard]] std::optional<CloudVerdictResult> QueryCache(const FileHash& hash) const;

    /**
     * @brief Adds or updates a verdict in the cache.
     * @param hash The file hash.
     * @param verdict The verdict result.
     */
    void UpdateCache(const FileHash& hash, const CloudVerdictResult& verdict);

    /**
     * @brief Invalidates a specific cache entry.
     * @param hash The file hash.
     */
    void InvalidateCacheEntry(const FileHash& hash);

    /**
     * @brief Clears the entire verdict cache.
     */
    void ClearCache() noexcept;

    /**
     * @brief Gets the current cache size.
     * @return Number of entries in cache.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a callback for verdict events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterVerdictCallback(VerdictCallback callback);

    /**
     * @brief Registers a callback for file hold events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterFileHoldCallback(FileHoldCallback callback);

    /**
     * @brief Registers a callback for outbreak events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterOutbreakCallback(OutbreakCallback callback);

    /**
     * @brief Registers a callback for threat level changes.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterThreatLevelCallback(ThreatLevelCallback callback);

    /**
     * @brief Registers a callback for signature updates.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterSignatureUpdateCallback(SignatureUpdateCallback callback);

    /**
     * @brief Registers a callback for cloud status changes.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterCloudStatusCallback(CloudStatusCallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId The callback ID.
     * @return True if unregistered successfully.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS AND DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Gets current runtime statistics.
     * @return Reference to statistics structure.
     */
    [[nodiscard]] const ZeroHourStatistics& GetStatistics() const noexcept;

    /**
     * @brief Resets all statistics counters.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Performs a self-diagnostic check.
     * @return True if all systems are operational.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Exports diagnostic data for troubleshooting.
     * @param outputPath Output file path.
     * @return True if export succeeded.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    ZeroHourProtection();
    ~ZeroHourProtection();

    // Non-copyable, non-movable
    ZeroHourProtection(const ZeroHourProtection&) = delete;
    ZeroHourProtection& operator=(const ZeroHourProtection&) = delete;
    ZeroHourProtection(ZeroHourProtection&&) = delete;
    ZeroHourProtection& operator=(ZeroHourProtection&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<ZeroHourProtectionImpl> m_impl;

    // Legacy compatibility
    std::atomic<bool> m_outbreakMode{ false };
};

}  // namespace RealTime
}  // namespace ShadowStrike
