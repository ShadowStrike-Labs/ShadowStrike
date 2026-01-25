/**
 * ============================================================================
 * ShadowStrike NGAV - SAFE BROWSING API MODULE
 * ============================================================================
 *
 * @file SafeBrowsingAPI.hpp
 * @brief Enterprise-grade integration with external threat intelligence APIs
 *        for real-time URL and content reputation checking.
 *
 * Provides comprehensive integration with Google Safe Browsing, Microsoft
 * SmartScreen, and other threat intelligence services for URL verification.
 *
 * SUPPORTED SERVICES:
 * ===================
 *
 * 1. GOOGLE SAFE BROWSING API V4
 *    - Lookup API (real-time)
 *    - Update API (local database)
 *    - Full hashes lookup
 *    - Threat list updates
 *
 * 2. MICROSOFT SMARTSCREEN
 *    - URL reputation
 *    - Application reputation
 *    - Download verification
 *    - SmartScreen filter
 *
 * 3. VIRUSTOTAL API
 *    - URL scanning
 *    - Domain reports
 *    - Hash lookups
 *    - File reputation
 *
 * 4. SHADOWSTRIKE CLOUD
 *    - Proprietary threat feed
 *    - Real-time IOC updates
 *    - Custom threat lists
 *    - Community reports
 *
 * FEATURES:
 * =========
 * - Local hash prefix caching
 * - Bloom filter for quick checks
 * - Rate limiting compliance
 * - Automatic failover
 * - Async queries
 * - Batch lookup support
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for local IOCs
 * - BrowserProtection for URL filtering
 * - DownloadBlocker for file reputation
 *
 * @note Requires API keys for external services.
 * @note Thread-safe singleton design.
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
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <future>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

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

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Google Safe Browsing API endpoint
    inline constexpr const char* GOOGLE_SB_API_URL = 
        "https://safebrowsing.googleapis.com/v4";
    
    /// @brief VirusTotal API endpoint
    inline constexpr const char* VIRUSTOTAL_API_URL = 
        "https://www.virustotal.com/vtapi/v2";
    
    /// @brief ShadowStrike Cloud endpoint
    inline constexpr const char* SHADOWSTRIKE_API_URL = 
        "https://api.shadowstrike.security/v1/reputation";
    
    /// @brief Default cache size
    inline constexpr size_t DEFAULT_CACHE_SIZE = 100000;
    
    /// @brief Cache TTL (seconds)
    inline constexpr uint32_t DEFAULT_CACHE_TTL = 3600;
    
    /// @brief Request timeout (ms)
    inline constexpr uint32_t DEFAULT_TIMEOUT_MS = 5000;
    
    /// @brief Max batch size for Google SB
    inline constexpr size_t GOOGLE_SB_MAX_BATCH = 500;
    
    /// @brief Hash prefix length
    inline constexpr size_t HASH_PREFIX_LENGTH = 4;

    /// @brief Google Safe Browsing threat types
    inline constexpr const char* GSB_THREAT_TYPES[] = {
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
    };

    /// @brief Google Safe Browsing platform types
    inline constexpr const char* GSB_PLATFORM_TYPES[] = {
        "ANY_PLATFORM",
        "WINDOWS",
        "ALL_PLATFORMS"
    };

}  // namespace SafeBrowsingConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief API provider type
 */
enum class APIProvider : uint8_t {
    None            = 0,
    GoogleSB        = 1,    ///< Google Safe Browsing
    SmartScreen     = 2,    ///< Microsoft SmartScreen
    VirusTotal      = 3,    ///< VirusTotal
    ShadowStrike    = 4,    ///< ShadowStrike Cloud
    Local           = 5     ///< Local database only
};

/**
 * @brief Threat type (Google Safe Browsing compatible)
 */
enum class ThreatType : uint8_t {
    Unknown                         = 0,
    Malware                         = 1,
    SocialEngineering               = 2,    // Phishing
    UnwantedSoftware                = 3,
    PotentiallyHarmfulApplication   = 4,
    ThreatTypeUnspecified          = 5
};

/**
 * @brief Platform type
 */
enum class PlatformType : uint8_t {
    AnyPlatform     = 0,
    Windows         = 1,
    Linux           = 2,
    Android         = 3,
    OSX             = 4,
    iOS             = 5,
    Chrome          = 6,
    AllPlatforms    = 7
};

/**
 * @brief Reputation verdict
 */
enum class ReputationVerdict : uint8_t {
    Safe            = 0,
    Unknown         = 1,
    Suspicious      = 2,
    Malicious       = 3,
    Phishing        = 4,
    PUP             = 5,    // Potentially Unwanted Program
    Error           = 255
};

/**
 * @brief Query status
 */
enum class QueryStatus : uint8_t {
    Success         = 0,
    NotFound        = 1,
    Error           = 2,
    Timeout         = 3,
    RateLimited     = 4,
    InvalidKey      = 5,
    NetworkError    = 6,
    CacheHit        = 7
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Querying        = 3,
    Updating        = 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief API credentials
 */
struct APICredentials {
    /// @brief Google Safe Browsing API key
    std::string googleAPIKey;
    
    /// @brief VirusTotal API key
    std::string virusTotalAPIKey;
    
    /// @brief ShadowStrike API key
    std::string shadowStrikeAPIKey;
    
    /// @brief Client ID (for Google)
    std::string clientId = "ShadowStrike-NGAV";
    
    /// @brief Client version
    std::string clientVersion = "3.0.0";
    
    [[nodiscard]] bool HasGoogleKey() const noexcept;
    [[nodiscard]] bool HasVirusTotalKey() const noexcept;
};

/**
 * @brief Threat match from Safe Browsing
 */
struct ThreatMatch {
    /// @brief Threat type
    ThreatType threatType = ThreatType::Unknown;
    
    /// @brief Platform type
    PlatformType platformType = PlatformType::AnyPlatform;
    
    /// @brief Threat entry type
    std::string threatEntryType;
    
    /// @brief Matched URL/hash
    std::string threat;
    
    /// @brief Cache duration (seconds)
    uint32_t cacheDuration = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief URL lookup result
 */
struct URLLookupResult {
    /// @brief URL queried
    std::string url;
    
    /// @brief Verdict
    ReputationVerdict verdict = ReputationVerdict::Unknown;
    
    /// @brief Query status
    QueryStatus status = QueryStatus::Success;
    
    /// @brief Threat matches
    std::vector<ThreatMatch> threatMatches;
    
    /// @brief Provider used
    APIProvider provider = APIProvider::None;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Categories
    std::vector<std::string> categories;
    
    /// @brief From cache
    bool fromCache = false;
    
    /// @brief Query time
    std::chrono::milliseconds queryTime{0};
    
    /// @brief Cache expiry
    SystemTimePoint cacheExpiry;
    
    /// @brief Error message (if any)
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Hash lookup result
 */
struct HashLookupResult {
    /// @brief Hash queried
    std::string hash;
    
    /// @brief Hash type (SHA256, MD5, etc.)
    std::string hashType;
    
    /// @brief Verdict
    ReputationVerdict verdict = ReputationVerdict::Unknown;
    
    /// @brief Query status
    QueryStatus status = QueryStatus::Success;
    
    /// @brief Detection count (VirusTotal)
    int detectionCount = 0;
    
    /// @brief Total engines
    int totalEngines = 0;
    
    /// @brief Detection names
    std::vector<std::string> detectionNames;
    
    /// @brief File type
    std::string fileType;
    
    /// @brief First seen
    SystemTimePoint firstSeen;
    
    /// @brief Last analysis
    SystemTimePoint lastAnalysis;
    
    /// @brief Provider used
    APIProvider provider = APIProvider::None;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Batch lookup result
 */
struct BatchLookupResult {
    /// @brief Total URLs queried
    size_t totalQueried = 0;
    
    /// @brief Malicious count
    size_t maliciousCount = 0;
    
    /// @brief Safe count
    size_t safeCount = 0;
    
    /// @brief Unknown count
    size_t unknownCount = 0;
    
    /// @brief Individual results
    std::vector<URLLookupResult> results;
    
    /// @brief Total query time
    std::chrono::milliseconds totalTime{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Cache entry
 */
struct CacheEntry {
    /// @brief URL or hash
    std::string key;
    
    /// @brief Verdict
    ReputationVerdict verdict = ReputationVerdict::Unknown;
    
    /// @brief Risk score
    int riskScore = 0;
    
    /// @brief Insert time
    TimePoint insertTime;
    
    /// @brief Expiry time
    TimePoint expiryTime;
    
    /// @brief Provider
    APIProvider provider = APIProvider::None;
    
    [[nodiscard]] bool IsExpired() const noexcept;
};

/**
 * @brief Statistics
 */
struct SafeBrowsingStatistics {
    std::atomic<uint64_t> totalQueries{0};
    std::atomic<uint64_t> maliciousFound{0};
    std::atomic<uint64_t> safeFound{0};
    std::atomic<uint64_t> unknownFound{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> apiErrors{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> rateLimited{0};
    std::atomic<uint64_t> googleSBQueries{0};
    std::atomic<uint64_t> virusTotalQueries{0};
    std::atomic<uint64_t> smartScreenQueries{0};
    std::atomic<uint64_t> localQueries{0};
    std::array<std::atomic<uint64_t>, 8> byProvider{};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SafeBrowsingConfiguration {
    /// @brief Enable API
    bool enabled = true;
    
    /// @brief Enable Google Safe Browsing
    bool enableGoogleSB = true;
    
    /// @brief Enable VirusTotal
    bool enableVirusTotal = false;
    
    /// @brief Enable SmartScreen
    bool enableSmartScreen = true;
    
    /// @brief Enable ShadowStrike Cloud
    bool enableShadowStrike = true;
    
    /// @brief Enable local database
    bool enableLocalDB = true;
    
    /// @brief Enable caching
    bool enableCaching = true;
    
    /// @brief Cache size
    size_t cacheSize = SafeBrowsingConstants::DEFAULT_CACHE_SIZE;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTTL = SafeBrowsingConstants::DEFAULT_CACHE_TTL;
    
    /// @brief Request timeout (ms)
    uint32_t timeoutMs = SafeBrowsingConstants::DEFAULT_TIMEOUT_MS;
    
    /// @brief Max retries
    int maxRetries = 2;
    
    /// @brief Fallback to local on API failure
    bool fallbackToLocal = true;
    
    /// @brief API credentials
    APICredentials credentials;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using LookupCallback = std::function<void(const URLLookupResult&)>;
using HashCallback = std::function<void(const HashLookupResult&)>;
using BatchCallback = std::function<void(const BatchLookupResult&)>;
using UpdateCallback = std::function<void(bool success, const std::string& message)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SAFE BROWSING API CLASS
// ============================================================================

/**
 * @class SafeBrowsingAPI
 * @brief Enterprise Safe Browsing API integration
 */
class SafeBrowsingAPI final {
public:
    [[nodiscard]] static SafeBrowsingAPI& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SafeBrowsingAPI(const SafeBrowsingAPI&) = delete;
    SafeBrowsingAPI& operator=(const SafeBrowsingAPI&) = delete;
    SafeBrowsingAPI(SafeBrowsingAPI&&) = delete;
    SafeBrowsingAPI& operator=(SafeBrowsingAPI&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SafeBrowsingConfiguration& config = {});
    [[nodiscard]] bool Initialize(const std::string& googleApiKey);  // Simplified
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const SafeBrowsingConfiguration& config);
    [[nodiscard]] SafeBrowsingConfiguration GetConfiguration() const;
    
    /// @brief Set API credentials
    [[nodiscard]] bool SetCredentials(const APICredentials& credentials);

    // ========================================================================
    // URL LOOKUPS
    // ========================================================================
    
    /// @brief Check if URL is malicious (simple API)
    [[nodiscard]] bool IsUrlMalicious(const std::string& url);
    
    /// @brief Lookup URL reputation
    [[nodiscard]] URLLookupResult LookupURL(const std::string& url);
    
    /// @brief Lookup URL asynchronously
    [[nodiscard]] std::future<URLLookupResult> LookupURLAsync(const std::string& url);
    
    /// @brief Batch lookup URLs
    [[nodiscard]] BatchLookupResult LookupURLBatch(const std::vector<std::string>& urls);
    
    /// @brief Batch lookup asynchronously
    [[nodiscard]] std::future<BatchLookupResult> LookupURLBatchAsync(
        const std::vector<std::string>& urls);

    // ========================================================================
    // HASH LOOKUPS
    // ========================================================================
    
    /// @brief Lookup file hash
    [[nodiscard]] HashLookupResult LookupHash(const std::string& hash);
    
    /// @brief Lookup hash asynchronously
    [[nodiscard]] std::future<HashLookupResult> LookupHashAsync(const std::string& hash);
    
    /// @brief Batch lookup hashes
    [[nodiscard]] std::vector<HashLookupResult> LookupHashBatch(
        const std::vector<std::string>& hashes);

    // ========================================================================
    // PROVIDER-SPECIFIC
    // ========================================================================
    
    /// @brief Query Google Safe Browsing directly
    [[nodiscard]] URLLookupResult QueryGoogleSB(const std::string& url);
    
    /// @brief Query VirusTotal directly
    [[nodiscard]] URLLookupResult QueryVirusTotal(const std::string& url);
    
    /// @brief Query SmartScreen directly
    [[nodiscard]] URLLookupResult QuerySmartScreen(const std::string& url);

    // ========================================================================
    // DATABASE UPDATES
    // ========================================================================
    
    /// @brief Update local threat database
    [[nodiscard]] bool UpdateLocalDatabase();
    
    /// @brief Get last update time
    [[nodiscard]] SystemTimePoint GetLastUpdateTime() const;
    
    /// @brief Check if update needed
    [[nodiscard]] bool IsUpdateNeeded() const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /// @brief Clear cache
    void ClearCache();
    
    /// @brief Get cache size
    [[nodiscard]] size_t GetCacheSize() const;
    
    /// @brief Get cache hit rate
    [[nodiscard]] double GetCacheHitRate() const;
    
    /// @brief Prune expired entries
    [[nodiscard]] size_t PruneCache();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterLookupCallback(LookupCallback callback);
    void RegisterHashCallback(HashCallback callback);
    void RegisterUpdateCallback(UpdateCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SafeBrowsingStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SafeBrowsingAPI();
    ~SafeBrowsingAPI();
    
    std::unique_ptr<SafeBrowsingAPIImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAPIProviderName(APIProvider provider) noexcept;
[[nodiscard]] std::string_view GetThreatTypeName(ThreatType type) noexcept;
[[nodiscard]] std::string_view GetPlatformTypeName(PlatformType type) noexcept;
[[nodiscard]] std::string_view GetReputationVerdictName(ReputationVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetQueryStatusName(QueryStatus status) noexcept;

/// @brief Compute URL hash for Safe Browsing
[[nodiscard]] std::string ComputeURLHash(const std::string& url);

/// @brief Compute hash prefix
[[nodiscard]] std::string ComputeHashPrefix(const std::string& fullHash);

/// @brief Canonicalize URL (Google SB format)
[[nodiscard]] std::string CanonicalizeURL(const std::string& url);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SAFEBROWSING_CHECK(url) \
    ::ShadowStrike::WebBrowser::SafeBrowsingAPI::Instance().IsUrlMalicious(url)

#define SS_SAFEBROWSING_LOOKUP(url) \
    ::ShadowStrike::WebBrowser::SafeBrowsingAPI::Instance().LookupURL(url)

#define SS_SAFEBROWSING_HASH(hash) \
    ::ShadowStrike::WebBrowser::SafeBrowsingAPI::Instance().LookupHash(hash)
