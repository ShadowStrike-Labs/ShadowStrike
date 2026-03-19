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
 * ShadowStrike Core FileSystem - FILE REPUTATION (The Cloud Judge)
 * ============================================================================
 *
 * @file FileReputation.hpp
 * @brief Enterprise-grade hybrid reputation engine for file trust assessment.
 *
 * This module provides comprehensive file reputation checking combining local
 * caches, cloud lookups, threat intelligence, and behavioral analysis to
 * answer: "Is this file safe?"
 *
 * Key Capabilities:
 * =================
 * 1. LOCAL LOOKUP
 *    - Whitelist (known good)
 *    - Blacklist (known bad)
 *    - Graylist (suspicious)
 *    - Certificate trust
 *
 * 2. CLOUD INTEGRATION
 *    - Global prevalence
 *    - First-seen/last-seen
 *    - Community verdicts
 *    - Machine learning scores
 *
 * 3. THREAT INTELLIGENCE
 *    - IOC matching
 *    - YARA patterns
 *    - Malware family identification
 *    - Campaign tracking
 *
 * 4. BEHAVIORAL ANALYSIS
 *    - Historical behavior
 *    - Parent-child relationships
 *    - Network activity correlation
 *    - Anomaly scoring
 *
 * 5. CERTIFICATE ANALYSIS
 *    - Authenticode validation
 *    - Certificate reputation
 *    - Known bad signers
 *    - Timestamp verification
 *
 * Reputation Architecture:
 * ========================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        FileReputation                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ LocalCache   │  │ CloudService │  │    ThreatIntelEngine     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Whitelist  │  │ - Prevalence │  │ - IOCs                   │  │
 *   │  │ - Blacklist  │  │ - ML Score   │  │ - Patterns               │  │
 *   │  │ - History    │  │ - Community  │  │ - Families               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ CertAnalyzer │  │ BehaviorCorr │  │    ReputationScorer      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Authenticde│  │ - History    │  │ - Weighted scoring       │  │
 *   │  │ - Revocation │  │ - Relations  │  │ - Confidence             │  │
 *   │  │ - Trust chain│  │ - Network    │  │ - Classification         │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Lookup Priority:
 * ================
 * 1. Local whitelist (fast, trusted) - <1ms
 * 2. Local blacklist (fast, definitive) - <1ms
 * 3. Certificate verification - ~10ms
 * 4. Local ThreatIntel - ~5ms
 * 5. Cloud lookup - ~100ms
 * 6. Behavioral correlation - varies
 *
 * Integration Points:
 * ===================
 * - HashStore: Hash computation and caching
 * - ThreatIntel: IOC and pattern matching
 * - Whitelist: Known good files
 * - CloudAPI: Global reputation service
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see HashStore.hpp for hash management
 * @see ThreatIntelDatabase.hpp for threat data
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File path utilities
#include "../../Utils/HashUtils.hpp"          // Hash computation
#include "../../Utils/CertUtils.hpp"          // Certificate verification
#include "../../Utils/CacheManager.hpp"       // LRU caching
#include "../../HashStore/HashStore.hpp"      // Hash lookups
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Threat intelligence
#include "../../ThreatIntel/ReputationCache.hpp"    // Reputation caching
#include "../../Whitelist/WhiteListStore.hpp" // Whitelisted files

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class FileReputationImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileReputationConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Score ranges
    constexpr int8_t SCORE_MALWARE = -100;
    constexpr int8_t SCORE_SUSPICIOUS = -50;
    constexpr int8_t SCORE_UNKNOWN = 0;
    constexpr int8_t SCORE_SAFE = 50;
    constexpr int8_t SCORE_TRUSTED = 100;

    // Timeouts
    constexpr uint32_t LOCAL_LOOKUP_TIMEOUT_MS = 10;
    constexpr uint32_t CLOUD_LOOKUP_TIMEOUT_MS = 5000;
    constexpr uint32_t DEFAULT_CACHE_TTL_HOURS = 24;

    // Limits
    constexpr size_t MAX_CACHE_SIZE = 1000000;
    constexpr size_t MAX_PENDING_QUERIES = 10000;

}  // namespace FileReputationConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ReputationLevel
 * @brief Overall reputation classification.
 */
enum class ReputationLevel : uint8_t {
    KnownMalware = 0,              // Confirmed malicious
    HighlyMalicious = 1,           // Strong malware indicators
    Suspicious = 2,                // Suspicious characteristics
    PotentiallyUnwanted = 3,       // PUP/Adware
    Unknown = 4,                   // Never seen before
    LowPrevalence = 5,             // Rare but not malicious
    KnownSafe = 6,                 // High prevalence, clean
    Trusted = 7,                   // Signed by trusted vendor
    MicrosoftSigned = 8            // Signed by Microsoft
};

/**
 * @enum ReputationSource
 * @brief Source of reputation data.
 */
enum class ReputationSource : uint8_t {
    Unknown = 0,
    LocalWhitelist = 1,
    LocalBlacklist = 2,
    LocalGraylist = 3,
    LocalHistory = 4,
    CertificateAnalysis = 5,
    ThreatIntelligence = 6,
    CloudPrevalence = 7,
    CloudMLScore = 8,
    CloudCommunity = 9,
    BehavioralAnalysis = 10,
    ManualOverride = 11
};

/**
 * @enum QueryMode
 * @brief Reputation query mode.
 */
enum class QueryMode : uint8_t {
    LocalOnly = 0,                 // Fast, local sources only
    CloudEnabled = 1,              // Include cloud lookup
    Comprehensive = 2              // All sources, behavioral
};

/**
 * @enum CachePolicy
 * @brief Caching behavior.
 */
enum class CachePolicy : uint8_t {
    NoCache = 0,
    CachePositive = 1,             // Cache safe/trusted only
    CacheNegative = 2,             // Cache malicious only
    CacheAll = 3
};

/**
 * @enum TrustLevel
 * @brief Certificate trust level.
 */
enum class TrustLevel : uint8_t {
    Untrusted = 0,
    Unknown = 1,
    BasicTrust = 2,                // Valid signature
    ExtendedTrust = 3,             // EV certificate
    SystemTrust = 4,               // Microsoft/OS vendor
    UserTrust = 5                  // User-added trust
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PrevalenceData
 * @brief File prevalence information.
 */
struct alignas(32) PrevalenceData {
    uint64_t globalSeenCount{ 0 };
    uint64_t organizationSeenCount{ 0 };
    uint64_t machineSeenCount{ 0 };

    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::chrono::system_clock::time_point firstSeenOrg;

    double globalPrevalence{ 0.0 };        // Percentage
    double organizationPrevalence{ 0.0 };

    bool isNew{ false };                   // First time seen
    bool isRare{ false };                  // Low prevalence
};

/**
 * @struct CertificateReputation
 * @brief Certificate-based reputation.
 */
struct alignas(64) CertificateReputation {
    bool isSigned{ false };
    bool isValidSignature{ false };
    bool isTimestamped{ false };

    TrustLevel trustLevel{ TrustLevel::Unknown };
    std::wstring signerName;
    std::wstring issuerName;
    std::wstring thumbprint;

    std::chrono::system_clock::time_point validFrom;
    std::chrono::system_clock::time_point validTo;
    bool isExpired{ false };
    bool isRevoked{ false };

    // Signer reputation
    int8_t signerReputation{ 0 };          // -100 to +100
    bool isKnownBadSigner{ false };
    std::string signerCategory;            // "Microsoft", "Known Vendor", etc.

    // Trust reasons
    std::vector<std::string> trustReasons;
    std::vector<std::string> untristReasons;
};

/**
 * @struct ThreatIntelMatch
 * @brief Threat intelligence match.
 */
struct alignas(64) ThreatIntelMatch {
    std::string matchType;                 // Hash, Pattern, IOC
    std::string matchValue;
    std::string threatName;
    std::string malwareFamily;

    std::string severity;                  // Critical, High, Medium, Low
    std::string mitreId;
    std::vector<std::string> tags;

    std::chrono::system_clock::time_point addedDate;
    std::string source;                    // Feed name
    double confidence{ 0.0 };
};

/**
 * @struct BehavioralContext
 * @brief Behavioral reputation context.
 */
struct alignas(64) BehavioralContext {
    // Historical behavior
    uint32_t executionCount{ 0 };
    uint32_t cleanExecutions{ 0 };
    uint32_t suspiciousExecutions{ 0 };

    // Parent/child relationships
    std::vector<std::wstring> knownParents;
    std::vector<std::wstring> knownChildren;

    // Network activity
    bool hasNetworkActivity{ false };
    bool hasC2Communication{ false };
    std::vector<std::string> contactedDomains;

    // File operations
    bool createsExecutables{ false };
    bool modifiesSystemFiles{ false };
    bool hasRansomwareBehavior{ false };

    // Score adjustments
    int8_t behaviorScore{ 0 };             // -50 to +50 adjustment
};

/**
 * @struct CloudReputation
 * @brief Cloud-based reputation data.
 */
struct alignas(64) CloudReputation {
    bool querySuccessful{ false };
    std::chrono::milliseconds queryLatency{ 0 };

    // ML-based scoring
    double mlScore{ 0.0 };                 // 0.0 to 1.0 (malicious probability)
    double mlConfidence{ 0.0 };            // Model confidence
    std::string mlModel;                   // Model version

    // Community verdicts
    uint32_t communityClean{ 0 };
    uint32_t communitySuspicious{ 0 };
    uint32_t communityMalicious{ 0 };

    // Additional metadata
    std::vector<std::string> detectionNames;
    std::string category;                  // Malware type if detected
    std::string familyName;
};

/**
 * @struct ReputationResult
 * @brief Complete reputation result.
 */
struct alignas(256) ReputationResult {
    // Primary result
    ReputationLevel level{ ReputationLevel::Unknown };
    int8_t score{ 0 };                     // -100 to +100
    double confidence{ 0.0 };              // 0.0 to 1.0

    // Classification
    bool isMalicious{ false };
    bool isSuspicious{ false };
    bool isTrusted{ false };
    bool isWhitelisted{ false };
    bool isBlacklisted{ false };

    // Sources
    ReputationSource primarySource{ ReputationSource::Unknown };
    std::vector<ReputationSource> contributingSources;

    // Detailed data
    PrevalenceData prevalence;
    CertificateReputation certificate;
    std::vector<ThreatIntelMatch> threatMatches;
    BehavioralContext behavior;
    CloudReputation cloud;

    // Hash information
    std::string sha256;
    std::string sha1;
    std::string md5;

    // Threat details (if malicious)
    std::string threatName;
    std::string malwareFamily;
    std::string mitreTechniques;

    // Recommendations
    std::string recommendation;            // "Allow", "Block", "Investigate"
    std::vector<std::string> reasons;

    // Metadata
    std::chrono::system_clock::time_point queryTime;
    std::chrono::milliseconds totalLatency{ 0 };
    bool fromCache{ false };
    std::chrono::system_clock::time_point cacheExpiry;
};

/**
 * @struct ReputationQuery
 * @brief Query parameters.
 */
struct alignas(64) ReputationQuery {
    // File identification
    std::wstring filePath;
    std::string sha256;
    std::string sha1;
    std::string md5;

    // Query options
    QueryMode mode{ QueryMode::CloudEnabled };
    CachePolicy cachePolicy{ CachePolicy::CacheAll };
    uint32_t timeoutMs{ FileReputationConstants::CLOUD_LOOKUP_TIMEOUT_MS };

    // Context
    std::wstring parentProcess;
    uint32_t parentPid{ 0 };
    bool isUserInitiated{ false };
};

/**
 * @struct FileReputationConfig
 * @brief Configuration for reputation service.
 */
struct alignas(64) FileReputationConfig {
    // Query settings
    QueryMode defaultMode{ QueryMode::CloudEnabled };
    uint32_t cloudTimeout{ FileReputationConstants::CLOUD_LOOKUP_TIMEOUT_MS };
    bool allowOfflineMode{ true };

    // Cache settings
    CachePolicy cachePolicy{ CachePolicy::CacheAll };
    size_t maxCacheSize{ FileReputationConstants::MAX_CACHE_SIZE };
    uint32_t cacheTTLHours{ FileReputationConstants::DEFAULT_CACHE_TTL_HOURS };

    // Scoring thresholds
    int8_t malwareThreshold{ -70 };
    int8_t suspiciousThreshold{ -30 };
    int8_t trustedThreshold{ 70 };

    // Cloud settings
    std::wstring cloudEndpoint;
    std::string apiKey;
    bool submitUnknown{ true };

    // Behavioral
    bool enableBehavioralAnalysis{ true };
    bool trackFileHistory{ true };

    // Factory methods
    static FileReputationConfig CreateDefault() noexcept;
    static FileReputationConfig CreateOffline() noexcept;
    static FileReputationConfig CreateHighSecurity() noexcept;
};

/**
 * @struct FileReputationStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) FileReputationStatistics {
    // Query statistics
    std::atomic<uint64_t> totalQueries{ 0 };
    std::atomic<uint64_t> localHits{ 0 };
    std::atomic<uint64_t> cloudQueries{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };

    // Result statistics
    std::atomic<uint64_t> maliciousDetected{ 0 };
    std::atomic<uint64_t> suspiciousDetected{ 0 };
    std::atomic<uint64_t> unknownFiles{ 0 };
    std::atomic<uint64_t> trustedFiles{ 0 };

    // Performance
    std::atomic<uint64_t> averageLatencyUs{ 0 };
    std::atomic<uint64_t> maxLatencyUs{ 0 };
    std::atomic<uint64_t> cloudFailures{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for async reputation result.
 */
using ReputationCallback = std::function<void(const ReputationResult& result)>;

/**
 * @brief Callback for unknown file detection.
 */
using UnknownFileCallback = std::function<void(const std::wstring& filePath, const std::string& hash)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileReputation
 * @brief Enterprise-grade file reputation service.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& reputation = FileReputation::Instance();
 * 
 * // Configure
 * auto config = FileReputationConfig::CreateHighSecurity();
 * reputation.Initialize(config);
 * 
 * // Check file
 * auto result = reputation.CheckFile(L"C:\\Downloads\\suspicious.exe");
 * 
 * if (result.isMalicious) {
 *     LOG_ALERT << "Malicious file: " << result.threatName;
 *     quarantine.Add(filePath);
 * } else if (result.isSuspicious) {
 *     LOG_WARNING << "Suspicious file - investigating...";
 *     analyzer.DeepScan(filePath);
 * }
 * 
 * // Check by hash (faster if already computed)
 * auto hashResult = reputation.CheckHash(sha256);
 * 
 * // Async batch check
 * reputation.CheckFilesAsync(files, [](const ReputationResult& result) {
 *     // Process result
 * });
 * @endcode
 */
class FileReputation {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static FileReputation& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the reputation service.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FileReputationConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // REPUTATION QUERIES
    // ========================================================================

    /**
     * @brief Gets reputation of file on disk.
     * @param filePath Path to file.
     * @param mode Query mode.
     * @return Reputation result.
     */
    [[nodiscard]] ReputationResult CheckFile(
        const std::wstring& filePath,
        QueryMode mode = QueryMode::CloudEnabled);

    /**
     * @brief Gets reputation by SHA256 hash.
     * @param sha256 SHA256 hash.
     * @param mode Query mode.
     * @return Reputation result.
     */
    [[nodiscard]] ReputationResult CheckHash(
        std::string_view sha256,
        QueryMode mode = QueryMode::CloudEnabled);

    /**
     * @brief Gets reputation by multiple hashes.
     * @param sha256 SHA256 hash.
     * @param sha1 SHA1 hash.
     * @param md5 MD5 hash.
     * @param mode Query mode.
     * @return Reputation result.
     */
    [[nodiscard]] ReputationResult CheckHashes(
        std::string_view sha256,
        std::string_view sha1,
        std::string_view md5,
        QueryMode mode = QueryMode::CloudEnabled);

    /**
     * @brief Advanced query with full context.
     * @param query Query parameters.
     * @return Reputation result.
     */
    [[nodiscard]] ReputationResult Query(const ReputationQuery& query);

    /**
     * @brief Async file check.
     * @param filePath Path to file.
     * @param callback Result callback.
     */
    void CheckFileAsync(const std::wstring& filePath, ReputationCallback callback);

    /**
     * @brief Batch file check.
     * @param filePaths Vector of paths.
     * @return Vector of results.
     */
    [[nodiscard]] std::vector<ReputationResult> CheckFiles(
        const std::vector<std::wstring>& filePaths);

    /**
     * @brief Async batch file check.
     * @param filePaths Vector of paths.
     * @param callback Per-file callback.
     */
    void CheckFilesAsync(
        const std::vector<std::wstring>& filePaths,
        ReputationCallback callback);

    // ========================================================================
    // LOCAL DATABASE MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds file to whitelist.
     * @param sha256 Hash to whitelist.
     * @param reason Reason for whitelisting.
     * @return True if added.
     */
    bool AddToWhitelist(std::string_view sha256, std::string_view reason);

    /**
     * @brief Removes from whitelist.
     * @param sha256 Hash to remove.
     * @return True if removed.
     */
    bool RemoveFromWhitelist(std::string_view sha256);

    /**
     * @brief Adds file to blacklist.
     * @param sha256 Hash to blacklist.
     * @param threatName Threat name.
     * @return True if added.
     */
    bool AddToBlacklist(std::string_view sha256, std::string_view threatName);

    /**
     * @brief Removes from blacklist.
     * @param sha256 Hash to remove.
     * @return True if removed.
     */
    bool RemoveFromBlacklist(std::string_view sha256);

    /**
     * @brief Checks if hash is whitelisted.
     * @param sha256 Hash to check.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(std::string_view sha256) const;

    /**
     * @brief Checks if hash is blacklisted.
     * @param sha256 Hash to check.
     * @return True if blacklisted.
     */
    [[nodiscard]] bool IsBlacklisted(std::string_view sha256) const;

    // ========================================================================
    // CERTIFICATE REPUTATION
    // ========================================================================

    /**
     * @brief Gets certificate reputation.
     * @param filePath Path to signed file.
     * @return Certificate reputation.
     */
    [[nodiscard]] CertificateReputation GetCertificateReputation(
        const std::wstring& filePath) const;

    /**
     * @brief Gets reputation by certificate thumbprint.
     * @param thumbprint Certificate thumbprint.
     * @return Trust level.
     */
    [[nodiscard]] TrustLevel GetCertificateTrust(std::string_view thumbprint) const;

    /**
     * @brief Adds trusted certificate.
     * @param thumbprint Certificate thumbprint.
     * @param reason Trust reason.
     * @return True if added.
     */
    bool AddTrustedCertificate(std::string_view thumbprint, std::string_view reason);

    /**
     * @brief Adds untrusted certificate.
     * @param thumbprint Certificate thumbprint.
     * @param reason Untrust reason.
     * @return True if added.
     */
    bool AddUntrustedCertificate(std::string_view thumbprint, std::string_view reason);

    // ========================================================================
    // CLOUD SUBMISSION
    // ========================================================================

    /**
     * @brief Submits unknown file for analysis.
     * @param filePath Path to file.
     * @return True if submitted.
     */
    bool SubmitForAnalysis(const std::wstring& filePath);

    /**
     * @brief Submits file metadata only.
     * @param filePath Path to file.
     * @return True if submitted.
     */
    bool SubmitMetadata(const std::wstring& filePath);

    /**
     * @brief Reports false positive.
     * @param sha256 Hash of file.
     * @param reason Reason for report.
     * @return True if reported.
     */
    bool ReportFalsePositive(std::string_view sha256, std::string_view reason);

    /**
     * @brief Reports false negative.
     * @param sha256 Hash of file.
     * @param threatName Threat name if known.
     * @return True if reported.
     */
    bool ReportFalseNegative(std::string_view sha256, std::string_view threatName);

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Clears reputation cache.
     */
    void ClearCache() noexcept;

    /**
     * @brief Gets cache size.
     * @return Number of cached entries.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    /**
     * @brief Preloads cache from file.
     * @param cachePath Path to cache file.
     * @return Number loaded.
     */
    size_t PreloadCache(const std::wstring& cachePath);

    /**
     * @brief Saves cache to file.
     * @param cachePath Path to cache file.
     * @return True if saved.
     */
    bool SaveCache(const std::wstring& cachePath) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterUnknownFileCallback(UnknownFileCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileReputationStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // CLOUD STATUS
    // ========================================================================

    /**
     * @brief Checks if cloud service is available.
     * @return True if available.
     */
    [[nodiscard]] bool IsCloudAvailable() const noexcept;

    /**
     * @brief Gets cloud service latency.
     * @return Average latency in ms.
     */
    [[nodiscard]] uint32_t GetCloudLatency() const noexcept;

private:
    FileReputation();
    ~FileReputation();

    FileReputation(const FileReputation&) = delete;
    FileReputation& operator=(const FileReputation&) = delete;

    std::unique_ptr<FileReputationImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
