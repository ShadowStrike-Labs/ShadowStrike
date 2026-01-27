/**
 * ============================================================================
 * ShadowStrike NGAV - SAFE BROWSING API
 * ============================================================================
 *
 * @file SafeBrowsingAPI.hpp
 * @brief Enterprise-grade Safe Browsing API for real-time URL/hash reputation
 *        checking with multi-tier caching and threat intelligence integration.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. URL REPUTATION
 *    - Real-time URL checking against threat intelligence
 *    - Domain reputation scoring
 *    - Phishing detection
 *    - Malware URL blocking
 *
 * 2. HASH REPUTATION
 *    - File hash reputation checking (SHA256, MD5, SHA1)
 *    - Known malware hash database
 *    - PUA (Potentially Unwanted Application) detection
 *
 * 3. MULTI-TIER CACHING
 *    - L1: Thread-local cache (<10ns)
 *    - L2: Shared LRU cache (<50ns)
 *    - L3: ThreatIntel lookup (<500ns)
 *    - L4: External API query (<50ms, async)
 *
 * PERFORMANCE TARGETS:
 * ====================
 * - Cache hit lookup: <50ns
 * - Full lookup with cache miss: <1ms
 * - Batch lookup: 10K URLs/second
 * - Memory usage: <100MB for 1M cached entries
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <future>
#include <span>

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../ThreatIntel/ThreatIntelLookup.hpp"
#include "../Utils/Logger.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class SafeBrowsingAPIImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SafeBrowsingConstants {

    /// @brief Version
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum URL length
    inline constexpr size_t MAX_URL_LENGTH = 8192;

    /// @brief Maximum hash length (SHA256 hex = 64 chars)
    inline constexpr size_t MAX_HASH_LENGTH = 128;

    /// @brief Default cache size
    inline constexpr size_t DEFAULT_CACHE_SIZE = 100000;

    /// @brief Default cache TTL (seconds)
    inline constexpr uint32_t DEFAULT_CACHE_TTL_SECONDS = 300;

    /// @brief Batch lookup max size
    inline constexpr size_t MAX_BATCH_SIZE = 1000;

    /// @brief Lookup timeout (milliseconds)
    inline constexpr uint32_t LOOKUP_TIMEOUT_MS = 5000;

}  // namespace SafeBrowsingConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using SystemTimePoint = std::chrono::system_clock::time_point;
using SteadyTimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Threat severity level
 */
enum class ThreatSeverity : uint8_t {
    None        = 0,    ///< No threat
    Low         = 1,    ///< Low severity (PUA, adware)
    Medium      = 2,    ///< Medium severity (suspicious)
    High        = 3,    ///< High severity (malware)
    Critical    = 4     ///< Critical (ransomware, APT)
};

/**
 * @brief Lookup source
 */
enum class LookupSource : uint8_t {
    Cache           = 0,    ///< From local cache
    LocalDatabase   = 1,    ///< From local threat database
    ThreatIntel     = 2,    ///< From ThreatIntel engine
    ExternalAPI     = 3,    ///< From external API
    Heuristic       = 4     ///< From heuristic analysis
};

/**
 * @brief Module status
 */
enum class SafeBrowsingStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,    ///< Running with limited functionality
    Stopped         = 4,
    Error           = 5
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Configuration for SafeBrowsing operations
 */
struct SafeBrowsingConfig {
    /// @brief Enable real-time protection
    bool enableRealTimeProtection = true;

    /// @brief Enable local cache
    bool enableLocalCache = true;

    /// @brief Maximum cache entries
    size_t maxCacheEntries = SafeBrowsingConstants::DEFAULT_CACHE_SIZE;

    /// @brief Cache TTL
    std::chrono::seconds cacheTTL{SafeBrowsingConstants::DEFAULT_CACHE_TTL_SECONDS};

    /// @brief Block suspicious URLs
    bool blockSuspicious = true;

    /// @brief Block known malware
    bool blockKnownMalware = true;

    /// @brief Enable phishing protection
    bool enablePhishingProtection = true;

    /// @brief Enable PUA detection
    bool enablePUADetection = true;

    /// @brief Minimum confidence threshold (0-100)
    uint8_t minConfidenceThreshold = 80;

    /// @brief Enable async lookups
    bool enableAsyncLookups = true;

    /// @brief Lookup timeout
    std::chrono::milliseconds lookupTimeout{SafeBrowsingConstants::LOOKUP_TIMEOUT_MS};

    /// @brief Fail-closed mode (block on error)
    bool failClosed = false;

    /// @brief Enable telemetry
    bool enableTelemetry = true;

    /// @brief Verbose logging
    bool verboseLogging = false;

    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Result of a URL or Hash check
 */
struct SafeBrowsingResult {
    /// @brief Is the resource safe
    bool isSafe = true;

    /// @brief Is known malicious
    bool isMalicious = false;

    /// @brief Is suspicious
    bool isSuspicious = false;

    /// @brief Is phishing
    bool isPhishing = false;

    /// @brief Is PUA
    bool isPUA = false;

    /// @brief Threat category
    ThreatIntel::ThreatCategory category = ThreatIntel::ThreatCategory::Unknown;

    /// @brief Reputation level
    ThreatIntel::ReputationLevel reputation = ThreatIntel::ReputationLevel::Unknown;

    /// @brief Threat severity
    ThreatSeverity severity = ThreatSeverity::None;

    /// @brief Threat name
    std::string threatName;

    /// @brief Threat family
    std::string threatFamily;

    /// @brief Details/description
    std::string details;

    /// @brief Confidence score (0-100)
    uint8_t confidence = 0;

    /// @brief Threat score (0-100)
    uint8_t threatScore = 0;

    /// @brief Lookup source
    LookupSource source = LookupSource::Cache;

    /// @brief Lookup latency (microseconds)
    uint64_t latencyUs = 0;

    /// @brief Check timestamp
    SystemTimePoint checkTime;

    /// @brief First seen timestamp (if known)
    std::optional<SystemTimePoint> firstSeen;

    /// @brief Last seen timestamp (if known)
    std::optional<SystemTimePoint> lastSeen;

    /// @brief MITRE ATT&CK techniques (if applicable)
    std::vector<std::string> mitreTechniques;

    /// @brief Related IOCs
    std::vector<std::string> relatedIOCs;

    /**
     * @brief Check if should block
     */
    [[nodiscard]] bool ShouldBlock() const noexcept;

    /**
     * @brief Check if should warn
     */
    [[nodiscard]] bool ShouldWarn() const noexcept;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Batch lookup result
 */
struct BatchLookupResult {
    /// @brief Individual results (same order as input)
    std::vector<SafeBrowsingResult> results;

    /// @brief Total lookup time (microseconds)
    uint64_t totalLatencyUs = 0;

    /// @brief Number of cache hits
    size_t cacheHits = 0;

    /// @brief Number of threats found
    size_t threatsFound = 0;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Safe browsing statistics
 */
struct SafeBrowsingStatistics {
    /// @brief Total lookups performed
    std::atomic<uint64_t> totalLookups{0};

    /// @brief URL lookups
    std::atomic<uint64_t> urlLookups{0};

    /// @brief Hash lookups
    std::atomic<uint64_t> hashLookups{0};

    /// @brief Domain lookups
    std::atomic<uint64_t> domainLookups{0};

    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{0};

    /// @brief Cache misses
    std::atomic<uint64_t> cacheMisses{0};

    /// @brief Malicious detected
    std::atomic<uint64_t> maliciousDetected{0};

    /// @brief Suspicious detected
    std::atomic<uint64_t> suspiciousDetected{0};

    /// @brief Phishing detected
    std::atomic<uint64_t> phishingDetected{0};

    /// @brief PUA detected
    std::atomic<uint64_t> puaDetected{0};

    /// @brief Total blocked
    std::atomic<uint64_t> totalBlocked{0};

    /// @brief Lookup errors
    std::atomic<uint64_t> lookupErrors{0};

    /// @brief Total processing time (microseconds)
    std::atomic<uint64_t> totalProcessingTimeUs{0};

    /// @brief Start time
    SteadyTimePoint startTime = std::chrono::steady_clock::now();

    /**
     * @brief Reset all statistics
     */
    void Reset() noexcept;

    /**
     * @brief Get cache hit ratio
     */
    [[nodiscard]] double GetCacheHitRatio() const noexcept;

    /**
     * @brief Get average lookup time (microseconds)
     */
    [[nodiscard]] double GetAverageLookupTimeUs() const noexcept;

    /**
     * @brief Get lookups per second
     */
    [[nodiscard]] double GetLookupsPerSecond() const noexcept;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Callback for threat detection events
using ThreatDetectedCallback = std::function<void(const std::string& url, const SafeBrowsingResult& result)>;

/// @brief Callback for lookup completion (async)
using LookupCompleteCallback = std::function<void(const SafeBrowsingResult& result)>;

// ============================================================================
// SAFE BROWSING API CLASS
// ============================================================================

/**
 * @class SafeBrowsingAPI
 * @brief Enterprise-grade Safe Browsing API
 *
 * Provides real-time URL and hash reputation checking for web browsers.
 * Implements multi-tier caching, thread-safety, and integration with the
 * central Threat Intelligence engine.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& api = SafeBrowsingAPI::Instance();
 *
 *     SafeBrowsingConfig config;
 *     config.enableRealTimeProtection = true;
 *     config.blockKnownMalware = true;
 *
 *     if (!api.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize SafeBrowsingAPI");
 *     }
 *
 *     auto result = api.CheckUrl("https://suspicious-site.com/malware.exe");
 *     if (!result.isSafe) {
 *         // Block the request
 *     }
 * @endcode
 */
class SafeBrowsingAPI final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static SafeBrowsingAPI& Instance() noexcept;

    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // Non-copyable, non-movable
    SafeBrowsingAPI(const SafeBrowsingAPI&) = delete;
    SafeBrowsingAPI& operator=(const SafeBrowsingAPI&) = delete;
    SafeBrowsingAPI(SafeBrowsingAPI&&) = delete;
    SafeBrowsingAPI& operator=(SafeBrowsingAPI&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Initialize the API
     * @param config Configuration settings
     * @param threatLookup Optional pointer to existing ThreatIntelLookup
     * @return true if initialized successfully
     */
    [[nodiscard]] bool Initialize(
        const SafeBrowsingConfig& config = {},
        ThreatIntel::ThreatIntelLookup* threatLookup = nullptr
    );

    /**
     * @brief Shutdown and cleanup resources
     */
    void Shutdown();

    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Get current status
     */
    [[nodiscard]] SafeBrowsingStatus GetStatus() const noexcept;

    // ========================================================================
    // URL CHECKING
    // ========================================================================

    /**
     * @brief Check if a URL is safe
     * @param url URL to check
     * @return Result of the check
     */
    [[nodiscard]] SafeBrowsingResult CheckUrl(std::string_view url);

    /**
     * @brief Asynchronously check if a URL is safe
     * @param url URL to check
     * @return Future result of the check
     */
    [[nodiscard]] std::future<SafeBrowsingResult> CheckUrlAsync(std::string url);

    /**
     * @brief Check URL with callback
     * @param url URL to check
     * @param callback Callback when complete
     */
    void CheckUrlWithCallback(std::string url, LookupCompleteCallback callback);

    /**
     * @brief Batch check URLs
     * @param urls URLs to check
     * @return Batch result
     */
    [[nodiscard]] BatchLookupResult CheckUrls(std::span<const std::string> urls);

    /**
     * @brief Batch check URLs async
     * @param urls URLs to check
     * @return Future batch result
     */
    [[nodiscard]] std::future<BatchLookupResult> CheckUrlsAsync(std::vector<std::string> urls);

    // ========================================================================
    // DOMAIN CHECKING
    // ========================================================================

    /**
     * @brief Check if a domain is safe
     * @param domain Domain to check
     * @return Result of the check
     */
    [[nodiscard]] SafeBrowsingResult CheckDomain(std::string_view domain);

    /**
     * @brief Check multiple domains
     * @param domains Domains to check
     * @return Batch result
     */
    [[nodiscard]] BatchLookupResult CheckDomains(std::span<const std::string> domains);

    // ========================================================================
    // HASH CHECKING
    // ========================================================================

    /**
     * @brief Check if a file hash is safe
     * @param hash Hash string (SHA256, MD5, etc.)
     * @return Result of the check
     */
    [[nodiscard]] SafeBrowsingResult CheckHash(std::string_view hash);

    /**
     * @brief Batch check hashes
     * @param hashes Hashes to check
     * @return Batch result
     */
    [[nodiscard]] BatchLookupResult CheckHashes(std::span<const std::string> hashes);

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @brief Update configuration at runtime
     */
    [[nodiscard]] bool UpdateConfig(const SafeBrowsingConfig& config);

    /**
     * @brief Get current configuration
     */
    [[nodiscard]] SafeBrowsingConfig GetConfig() const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Clear the local cache
     */
    void ClearCache();

    /**
     * @brief Get cache size
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    /**
     * @brief Preload URLs into cache
     */
    void PreloadCache(std::span<const std::string> urls);

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Register threat detection callback
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatDetectedCallback callback);

    /**
     * @brief Unregister threat detection callback
     */
    void UnregisterThreatCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Get statistics
     */
    [[nodiscard]] SafeBrowsingStatistics GetStatistics() const;

    /**
     * @brief Reset statistics
     */
    void ResetStatistics();

    /**
     * @brief Get statistics as JSON string
     */
    [[nodiscard]] std::string GetStatisticsJson() const;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================

    SafeBrowsingAPI();
    ~SafeBrowsingAPI();

    // ========================================================================
    // PIMPL
    // ========================================================================

    std::unique_ptr<SafeBrowsingAPIImpl> m_impl;

    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================

    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get severity name
 */
[[nodiscard]] std::string_view GetSeverityName(ThreatSeverity severity) noexcept;

/**
 * @brief Get lookup source name
 */
[[nodiscard]] std::string_view GetLookupSourceName(LookupSource source) noexcept;

/**
 * @brief Get status name
 */
[[nodiscard]] std::string_view GetStatusName(SafeBrowsingStatus status) noexcept;

}  // namespace WebBrowser
}  // namespace ShadowStrike
