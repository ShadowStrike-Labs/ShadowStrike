/**
 * @file ThreatIntelFeedManager.hpp
 * @brief Enterprise-Grade Threat Intelligence Feed Management System
 *
 * High-performance feed management supporting multiple commercial and open-source
 * threat intelligence providers with automatic synchronization, rate limiting,
 * deduplication, and intelligent caching.
 *
 * Supported Feed Sources:
 * - Commercial: VirusTotal, CrowdStrike, Recorded Future, Mandiant, Shodan
 * - Open Source: AlienVault OTX, AbuseIPDB, MISP, ThreatFox, URLhaus, MalwareBazaar
 * - Government: CISA, MITRE ATT&CK, NIST NVD
 * - Custom: STIX/TAXII, CSV, JSON feeds
 *
 * Features:
 * - Concurrent feed synchronization with thread pool
 * - Automatic rate limiting per provider
 * - OAuth2/API key authentication
 * - Exponential backoff with jitter for retries
 * - Delta/incremental updates
 * - Feed health monitoring and alerting
 * - Deduplication across multiple feeds
 * - Priority-based scheduling
 * - Bandwidth throttling
 *
 * Performance Targets:
 * - Feed sync: 100K+ IOCs/second ingestion
 * - API response parsing: < 1ms per response
 * - Rate limit compliance: 100% accuracy
 * - Memory efficiency: Streaming parsing for large feeds
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2025 ShadowStrike Project
 * @version 1.0.0
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <thread>
#include <future>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <variant>
#include <span>

namespace ShadowStrike {
namespace ThreatIntel {

// Forward declarations
class ThreatIntelDatabase;
class ThreatIntelStore;

// ============================================================================
// FEED CONFIGURATION ENUMERATIONS
// ============================================================================

/**
 * @brief Feed synchronization status
 */
enum class FeedSyncStatus : uint8_t {
    Unknown = 0,        ///< Status not determined
    Disabled = 1,       ///< Feed is disabled
    Idle = 2,           ///< Feed is idle, waiting for next sync
    Syncing = 3,        ///< Currently synchronizing
    Parsing = 4,        ///< Parsing received data
    Storing = 5,        ///< Storing parsed IOCs
    Error = 6,          ///< Feed in error state
    RateLimited = 7,    ///< Currently rate limited
    Paused = 8,         ///< Manually paused
    Initializing = 9    ///< Initial setup in progress
};

/**
 * @brief Convert FeedSyncStatus to string
 */
[[nodiscard]] constexpr const char* FeedStatusToString(FeedSyncStatus status) noexcept {
    switch (status) {
        case FeedSyncStatus::Unknown:       return "Unknown";
        case FeedSyncStatus::Disabled:      return "Disabled";
        case FeedSyncStatus::Idle:          return "Idle";
        case FeedSyncStatus::Syncing:       return "Syncing";
        case FeedSyncStatus::Parsing:       return "Parsing";
        case FeedSyncStatus::Storing:       return "Storing";
        case FeedSyncStatus::Error:         return "Error";
        case FeedSyncStatus::RateLimited:   return "Rate Limited";
        case FeedSyncStatus::Paused:        return "Paused";
        case FeedSyncStatus::Initializing:  return "Initializing";
        default:                        return "Unknown";
    }
}

/**
 * @brief Feed protocol/format type
 */
enum class FeedProtocol : uint8_t {
    REST_API = 0,       ///< Standard REST API (JSON/XML)
    STIX_TAXII = 1,     ///< STIX/TAXII 2.x protocol
    MISP_API = 2,       ///< MISP REST API
    CSV_HTTP = 3,       ///< CSV over HTTP
    JSON_HTTP = 4,      ///< JSON over HTTP
    RSS_ATOM = 5,       ///< RSS/Atom feed
    SYSLOG = 6,         ///< Syslog ingestion
    FILE_WATCH = 7,     ///< Local file monitoring
    WEBHOOK = 8,        ///< Incoming webhook
    CUSTOM = 9          ///< Custom protocol handler
};

/**
 * @brief Convert FeedProtocol to string
 */
[[nodiscard]] constexpr const char* FeedProtocolToString(FeedProtocol protocol) noexcept {
    switch (protocol) {
        case FeedProtocol::REST_API:    return "REST API";
        case FeedProtocol::STIX_TAXII:  return "STIX/TAXII";
        case FeedProtocol::MISP_API:    return "MISP API";
        case FeedProtocol::CSV_HTTP:    return "CSV over HTTP";
        case FeedProtocol::JSON_HTTP:   return "JSON over HTTP";
        case FeedProtocol::RSS_ATOM:    return "RSS/Atom";
        case FeedProtocol::SYSLOG:      return "Syslog";
        case FeedProtocol::FILE_WATCH:  return "File Watch";
        case FeedProtocol::WEBHOOK:     return "Webhook";
        case FeedProtocol::CUSTOM:      return "Custom";
        default:                        return "Unknown";
    }
}

/**
 * @brief Authentication method for feed access
 */
enum class AuthMethod : uint8_t {
    None = 0,           ///< No authentication required
    ApiKey = 1,         ///< API key in header/query
    BasicAuth = 2,      ///< HTTP Basic Authentication
    BearerToken = 3,    ///< OAuth2 Bearer Token
    OAuth2 = 4,         ///< Full OAuth2 flow
    Certificate = 5,    ///< Client certificate
    HMAC = 6,           ///< HMAC signature
    Custom = 7          ///< Custom authentication
};

/**
 * @brief Convert AuthMethod to string
 */
[[nodiscard]] constexpr const char* AuthMethodToString(AuthMethod method) noexcept {
    switch (method) {
        case AuthMethod::None:          return "None";
        case AuthMethod::ApiKey:        return "API Key";
        case AuthMethod::BasicAuth:     return "Basic Auth";
        case AuthMethod::BearerToken:   return "Bearer Token";
        case AuthMethod::OAuth2:        return "OAuth2";
        case AuthMethod::Certificate:   return "Certificate";
        case AuthMethod::HMAC:          return "HMAC";
        case AuthMethod::Custom:        return "Custom";
        default:                        return "Unknown";
    }
}

/**
 * @brief Feed priority level for scheduling
 */
enum class FeedPriority : uint8_t {
    Critical = 0,       ///< Highest priority (e.g., active threat)
    High = 1,           ///< High priority feeds
    Normal = 2,         ///< Default priority
    Low = 3,            ///< Low priority/bulk feeds
    Background = 4      ///< Background sync only
};

/**
 * @brief Sync trigger type
 */
enum class SyncTrigger : uint8_t {
    Scheduled = 0,      ///< Regular scheduled sync
    Manual = 1,         ///< User-initiated sync
    Webhook = 2,        ///< Triggered by webhook
    Alert = 3,          ///< Triggered by alert
    Startup = 4,        ///< Initial startup sync
    Recovery = 5        ///< Error recovery sync
};

// ============================================================================
// FEED CONFIGURATION STRUCTURES
// ============================================================================

/**
 * @brief Rate limiting configuration
 */
struct RateLimitConfig {
    uint32_t requestsPerMinute = 60;        ///< Max requests per minute
    uint32_t requestsPerHour = 1000;        ///< Max requests per hour
    uint32_t requestsPerDay = 10000;        ///< Max requests per day
    uint32_t burstLimit = 10;               ///< Max burst requests
    uint32_t minIntervalMs = 100;           ///< Minimum interval between requests (ms)
    bool useTokenBucket = true;             ///< Use token bucket algorithm
    bool respectRetryAfter = true;          ///< Honor Retry-After header
    
    // Runtime state (not persisted)
    mutable std::atomic<uint32_t> currentMinuteCount{0};
    mutable std::atomic<uint32_t> currentHourCount{0};
    mutable std::atomic<uint32_t> currentDayCount{0};
    mutable std::atomic<uint64_t> lastRequestTime{0};
    mutable std::atomic<uint64_t> retryAfterTime{0};
    
    // Default constructor
    RateLimitConfig() = default;
    
    // Copy constructor - copies config but resets runtime state
    RateLimitConfig(const RateLimitConfig& other) noexcept
        : requestsPerMinute(other.requestsPerMinute)
        , requestsPerHour(other.requestsPerHour)
        , requestsPerDay(other.requestsPerDay)
        , burstLimit(other.burstLimit)
        , minIntervalMs(other.minIntervalMs)
        , useTokenBucket(other.useTokenBucket)
        , respectRetryAfter(other.respectRetryAfter)
        , currentMinuteCount(0)
        , currentHourCount(0)
        , currentDayCount(0)
        , lastRequestTime(0)
        , retryAfterTime(0) {}
    
    // Copy assignment - copies config but resets runtime state
    RateLimitConfig& operator=(const RateLimitConfig& other) noexcept {
        if (this != &other) {
            requestsPerMinute = other.requestsPerMinute;
            requestsPerHour = other.requestsPerHour;
            requestsPerDay = other.requestsPerDay;
            burstLimit = other.burstLimit;
            minIntervalMs = other.minIntervalMs;
            useTokenBucket = other.useTokenBucket;
            respectRetryAfter = other.respectRetryAfter;
            currentMinuteCount.store(0, std::memory_order_relaxed);
            currentHourCount.store(0, std::memory_order_relaxed);
            currentDayCount.store(0, std::memory_order_relaxed);
            lastRequestTime.store(0, std::memory_order_relaxed);
            retryAfterTime.store(0, std::memory_order_relaxed);
        }
        return *this;
    }
    
    // Move constructor
    RateLimitConfig(RateLimitConfig&& other) noexcept
        : requestsPerMinute(other.requestsPerMinute)
        , requestsPerHour(other.requestsPerHour)
        , requestsPerDay(other.requestsPerDay)
        , burstLimit(other.burstLimit)
        , minIntervalMs(other.minIntervalMs)
        , useTokenBucket(other.useTokenBucket)
        , respectRetryAfter(other.respectRetryAfter)
        , currentMinuteCount(other.currentMinuteCount.load(std::memory_order_relaxed))
        , currentHourCount(other.currentHourCount.load(std::memory_order_relaxed))
        , currentDayCount(other.currentDayCount.load(std::memory_order_relaxed))
        , lastRequestTime(other.lastRequestTime.load(std::memory_order_relaxed))
        , retryAfterTime(other.retryAfterTime.load(std::memory_order_relaxed)) {}
    
    // Move assignment
    RateLimitConfig& operator=(RateLimitConfig&& other) noexcept {
        if (this != &other) {
            requestsPerMinute = other.requestsPerMinute;
            requestsPerHour = other.requestsPerHour;
            requestsPerDay = other.requestsPerDay;
            burstLimit = other.burstLimit;
            minIntervalMs = other.minIntervalMs;
            useTokenBucket = other.useTokenBucket;
            respectRetryAfter = other.respectRetryAfter;
            currentMinuteCount.store(other.currentMinuteCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            currentHourCount.store(other.currentHourCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            currentDayCount.store(other.currentDayCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastRequestTime.store(other.lastRequestTime.load(std::memory_order_relaxed), std::memory_order_relaxed);
            retryAfterTime.store(other.retryAfterTime.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }
};

/**
 * @brief Retry/backoff configuration
 */
struct RetryConfig {
    uint32_t maxRetries = 5;                ///< Maximum retry attempts
    uint32_t initialDelayMs = 1000;         ///< Initial retry delay (ms)
    uint32_t maxDelayMs = 300000;           ///< Maximum retry delay (5 min)
    double backoffMultiplier = 2.0;         ///< Exponential backoff factor
    double jitterFactor = 0.25;             ///< Random jitter factor (0-1)
    bool retryOnTimeout = true;             ///< Retry on timeout errors
    bool retryOnServerError = true;         ///< Retry on 5xx errors
    bool retryOnRateLimit = true;           ///< Retry after rate limit
    
    /// @brief Calculate delay for given attempt with jitter
    [[nodiscard]] uint32_t CalculateDelay(uint32_t attempt) const noexcept;
};

/**
 * @brief Authentication credentials (encrypted at rest)
 */
struct AuthCredentials {
    AuthMethod method = AuthMethod::None;
    
    // API Key authentication
    std::string apiKey;
    std::string apiKeyHeader = "X-Api-Key";  ///< Header name for API key
    bool apiKeyInQuery = false;              ///< Put API key in query string
    std::string apiKeyQueryParam = "apikey"; ///< Query parameter name
    
    // Basic authentication
    std::string username;
    std::string password;
    
    // OAuth2 configuration
    std::string clientId;
    std::string clientSecret;
    std::string tokenUrl;
    std::string scope;
    std::string accessToken;                 ///< Current access token
    uint64_t tokenExpiry = 0;               ///< Token expiration timestamp
    std::string refreshToken;               ///< OAuth2 refresh token
    
    // Certificate authentication
    std::string certPath;
    std::string keyPath;
    std::string keyPassword;
    
    // HMAC authentication
    std::string hmacSecret;
    std::string hmacAlgorithm = "SHA256";
    
    /// @brief Check if credentials are configured
    [[nodiscard]] bool IsConfigured() const noexcept;
    
    /// @brief Check if token needs refresh
    [[nodiscard]] bool NeedsTokenRefresh() const noexcept;
    
    /// @brief Clear sensitive data
    void Clear() noexcept;
};

/**
 * @brief Feed endpoint configuration
 */
struct FeedEndpoint {
    std::string baseUrl;                    ///< Base URL for the feed
    std::string path;                       ///< API path/endpoint
    std::string method = "GET";             ///< HTTP method
    std::unordered_map<std::string, std::string> headers;  ///< Additional headers
    std::unordered_map<std::string, std::string> queryParams; ///< Query parameters
    std::string requestBody;                ///< Request body template (for POST)
    std::string contentType = "application/json";
    
    /// @brief Get full URL with parameters
    [[nodiscard]] std::string GetFullUrl() const;
    
    /// @brief Build URL with pagination
    [[nodiscard]] std::string GetPaginatedUrl(uint64_t offset, uint32_t limit) const;
};

/**
 * @brief Parser configuration for feed responses
 */
struct ParserConfig {
    std::string iocPath;                    ///< JSON path to IOC array (e.g., "$.data.indicators")
    std::string valuePath;                  ///< Path to IOC value field
    std::string typePath;                   ///< Path to IOC type field
    std::string confidencePath;             ///< Path to confidence score
    std::string reputationPath;             ///< Path to reputation/severity
    std::string categoryPath;               ///< Path to threat category
    std::string firstSeenPath;              ///< Path to first seen timestamp
    std::string lastSeenPath;               ///< Path to last seen timestamp
    std::string descriptionPath;            ///< Path to description
    std::string tagsPath;                   ///< Path to tags array
    
    // Pagination support
    std::string nextPagePath;               ///< Path to next page URL/token
    std::string totalCountPath;             ///< Path to total count
    std::string hasMorePath;                ///< Path to "has more" boolean
    
    // Type mapping
    std::unordered_map<std::string, IOCType> typeMapping;  ///< Source type -> IOCType
    
    // Value transformation
    bool lowercaseValues = false;           ///< Convert values to lowercase
    bool trimWhitespace = true;             ///< Trim whitespace from values
    bool skipInvalid = true;                ///< Skip invalid entries
    
    // CSV-specific
    char csvDelimiter = ',';
    char csvQuote = '"';
    bool csvHasHeader = true;
    int csvValueColumn = 0;
    int csvTypeColumn = -1;
};

/**
 * @brief Complete feed configuration
 */
struct ThreatFeedConfig {
    /// @brief Unique feed identifier
    std::string feedId;
    
    /// @brief Human-readable feed name
    std::string name;
    
    /// @brief Feed description
    std::string description;
    
    /// @brief Associated threat intel source
    ThreatIntelSource source = ThreatIntelSource::CustomFeed;
    
    /// @brief Feed protocol type
    FeedProtocol protocol = FeedProtocol::REST_API;
    
    /// @brief Feed priority
    FeedPriority priority = FeedPriority::Normal;
    
    /// @brief Whether feed is enabled
    bool enabled = true;
    
    /// @brief Endpoint configuration
    FeedEndpoint endpoint;
    
    /// @brief Authentication credentials
    AuthCredentials auth;
    
    /// @brief Rate limiting configuration
    RateLimitConfig rateLimit;
    
    /// @brief Retry configuration
    RetryConfig retry;
    
    /// @brief Parser configuration
    ParserConfig parser;
    
    /// @brief Sync interval in seconds (0 = manual only)
    uint32_t syncIntervalSeconds = 3600;    ///< Default: 1 hour
    
    /// @brief Minimum sync interval (prevents too-frequent syncs)
    uint32_t minSyncIntervalSeconds = 60;   ///< Default: 1 minute
    
    /// @brief Maximum IOCs to fetch per sync
    uint32_t maxIOCsPerSync = 100000;
    
    /// @brief Connection timeout in milliseconds
    uint32_t connectionTimeoutMs = 30000;
    
    /// @brief Read timeout in milliseconds
    uint32_t readTimeoutMs = 60000;
    
    /// @brief Whether to use delta/incremental updates
    bool deltaUpdates = true;
    
    /// @brief Whether to verify SSL certificates
    bool verifySsl = true;
    
    /// @brief Proxy configuration (empty = no proxy)
    std::string proxyUrl;
    
    /// @brief User agent string
    std::string userAgent = "ShadowStrike-ThreatIntel/1.0";
    
    /// @brief Default TTL for IOCs from this feed (seconds)
    uint32_t defaultTtlSeconds = 86400;     ///< Default: 24 hours
    
    /// @brief Default confidence level for IOCs from this feed
    ConfidenceLevel defaultConfidence = ConfidenceLevel::Medium;
    
    /// @brief Default reputation for IOCs from this feed
    ReputationLevel defaultReputation = ReputationLevel::Suspicious;
    
    /// @brief IOC types to fetch (empty = all)
    std::vector<IOCType> allowedTypes;
    
    /// @brief Tags to apply to all IOCs from this feed
    std::vector<std::string> defaultTags;
    
    /// @brief Created timestamp
    uint64_t createdTime = 0;
    
    /// @brief Last modified timestamp
    uint64_t modifiedTime = 0;
    
    /// @brief Validate configuration
    [[nodiscard]] bool Validate(std::string* errorMsg = nullptr) const;
    
    /// @brief Create default config for known source
    [[nodiscard]] static ThreatFeedConfig CreateDefault(ThreatIntelSource source);
    
    /// @brief Create VirusTotal feed config
    [[nodiscard]] static ThreatFeedConfig CreateVirusTotal(const std::string& apiKey);
    
    /// @brief Create AlienVault OTX feed config
    [[nodiscard]] static ThreatFeedConfig CreateAlienVaultOTX(const std::string& apiKey);
    
    /// @brief Create AbuseIPDB feed config
    [[nodiscard]] static ThreatFeedConfig CreateAbuseIPDB(const std::string& apiKey);
    
    /// @brief Create URLhaus feed config (no auth required)
    [[nodiscard]] static ThreatFeedConfig CreateURLhaus();
    
    /// @brief Create MalwareBazaar feed config
    [[nodiscard]] static ThreatFeedConfig CreateMalwareBazaar();
    
    /// @brief Create ThreatFox feed config
    [[nodiscard]] static ThreatFeedConfig CreateThreatFox(const std::string& apiKey = "");
    
    /// @brief Create MISP feed config
    [[nodiscard]] static ThreatFeedConfig CreateMISP(const std::string& baseUrl, const std::string& apiKey);
    
    /// @brief Create generic STIX/TAXII feed config
    [[nodiscard]] static ThreatFeedConfig CreateSTIXTAXII(
        const std::string& discoveryUrl,
        const std::string& apiRoot,
        const std::string& collectionId
    );
    
    /// @brief Create generic CSV feed config
    [[nodiscard]] static ThreatFeedConfig CreateCSVFeed(
        const std::string& url,
        int valueColumn,
        IOCType iocType
    );
};

// ============================================================================
// FEED STATISTICS & MONITORING
// ============================================================================

/**
 * @brief Statistics for a single feed
 */
struct FeedStats {
    /// @brief Current status
    std::atomic<FeedSyncStatus> status{FeedSyncStatus::Unknown};
    
    /// @brief Last successful sync timestamp
    std::atomic<uint64_t> lastSuccessfulSync{0};
    
    /// @brief Last sync attempt timestamp
    std::atomic<uint64_t> lastSyncAttempt{0};
    
    /// @brief Last error timestamp
    std::atomic<uint64_t> lastErrorTime{0};
    
    /// @brief Last error message
    std::string lastErrorMessage;
    mutable std::mutex errorMutex;
    
    /// @brief Total successful syncs
    std::atomic<uint64_t> totalSuccessfulSyncs{0};
    
    /// @brief Total failed syncs
    std::atomic<uint64_t> totalFailedSyncs{0};
    
    /// @brief Total IOCs fetched all-time
    std::atomic<uint64_t> totalIOCsFetched{0};
    
    /// @brief IOCs fetched in last sync
    std::atomic<uint64_t> lastSyncIOCCount{0};
    
    /// @brief New IOCs in last sync (not duplicates)
    std::atomic<uint64_t> lastSyncNewIOCs{0};
    
    /// @brief Updated IOCs in last sync
    std::atomic<uint64_t> lastSyncUpdatedIOCs{0};
    
    /// @brief Total bytes downloaded
    std::atomic<uint64_t> totalBytesDownloaded{0};
    
    /// @brief Last sync duration in milliseconds
    std::atomic<uint64_t> lastSyncDurationMs{0};
    
    /// @brief Average sync duration in milliseconds
    std::atomic<uint64_t> avgSyncDurationMs{0};
    
    /// @brief Current consecutive error count
    std::atomic<uint32_t> consecutiveErrors{0};
    
    /// @brief Current retry attempt
    std::atomic<uint32_t> currentRetryAttempt{0};
    
    /// @brief Next scheduled sync timestamp
    std::atomic<uint64_t> nextScheduledSync{0};
    
    /// @brief Sync progress (0-100)
    std::atomic<uint8_t> syncProgress{0};
    
    /// @brief Current sync phase description
    std::string currentPhase;
    mutable std::mutex phaseMutex;
    
    // Default constructor
    FeedStats() = default;
    
    // Copy constructor - copies atomics and strings
    FeedStats(const FeedStats& other)
        : status(other.status.load(std::memory_order_relaxed))
        , lastSuccessfulSync(other.lastSuccessfulSync.load(std::memory_order_relaxed))
        , lastSyncAttempt(other.lastSyncAttempt.load(std::memory_order_relaxed))
        , lastErrorTime(other.lastErrorTime.load(std::memory_order_relaxed))
        , totalSuccessfulSyncs(other.totalSuccessfulSyncs.load(std::memory_order_relaxed))
        , totalFailedSyncs(other.totalFailedSyncs.load(std::memory_order_relaxed))
        , totalIOCsFetched(other.totalIOCsFetched.load(std::memory_order_relaxed))
        , lastSyncIOCCount(other.lastSyncIOCCount.load(std::memory_order_relaxed))
        , lastSyncNewIOCs(other.lastSyncNewIOCs.load(std::memory_order_relaxed))
        , lastSyncUpdatedIOCs(other.lastSyncUpdatedIOCs.load(std::memory_order_relaxed))
        , totalBytesDownloaded(other.totalBytesDownloaded.load(std::memory_order_relaxed))
        , lastSyncDurationMs(other.lastSyncDurationMs.load(std::memory_order_relaxed))
        , avgSyncDurationMs(other.avgSyncDurationMs.load(std::memory_order_relaxed))
        , consecutiveErrors(other.consecutiveErrors.load(std::memory_order_relaxed))
        , currentRetryAttempt(other.currentRetryAttempt.load(std::memory_order_relaxed))
        , nextScheduledSync(other.nextScheduledSync.load(std::memory_order_relaxed))
        , syncProgress(other.syncProgress.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lock1(other.errorMutex);
        lastErrorMessage = other.lastErrorMessage;
        std::lock_guard<std::mutex> lock2(other.phaseMutex);
        currentPhase = other.currentPhase;
    }
    
    // Copy assignment
    FeedStats& operator=(const FeedStats& other) {
        if (this != &other) {
            status.store(other.status.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSuccessfulSync.store(other.lastSuccessfulSync.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncAttempt.store(other.lastSyncAttempt.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastErrorTime.store(other.lastErrorTime.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalSuccessfulSyncs.store(other.totalSuccessfulSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalFailedSyncs.store(other.totalFailedSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalIOCsFetched.store(other.totalIOCsFetched.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncIOCCount.store(other.lastSyncIOCCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncNewIOCs.store(other.lastSyncNewIOCs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncUpdatedIOCs.store(other.lastSyncUpdatedIOCs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalBytesDownloaded.store(other.totalBytesDownloaded.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncDurationMs.store(other.lastSyncDurationMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            avgSyncDurationMs.store(other.avgSyncDurationMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            consecutiveErrors.store(other.consecutiveErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
            currentRetryAttempt.store(other.currentRetryAttempt.load(std::memory_order_relaxed), std::memory_order_relaxed);
            nextScheduledSync.store(other.nextScheduledSync.load(std::memory_order_relaxed), std::memory_order_relaxed);
            syncProgress.store(other.syncProgress.load(std::memory_order_relaxed), std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lock1(other.errorMutex);
                std::lock_guard<std::mutex> lock2(errorMutex);
                lastErrorMessage = other.lastErrorMessage;
            }
            {
                std::lock_guard<std::mutex> lock1(other.phaseMutex);
                std::lock_guard<std::mutex> lock2(phaseMutex);
                currentPhase = other.currentPhase;
            }
        }
        return *this;
    }
    
    // Move constructor
    FeedStats(FeedStats&& other) noexcept
        : status(other.status.load(std::memory_order_relaxed))
        , lastSuccessfulSync(other.lastSuccessfulSync.load(std::memory_order_relaxed))
        , lastSyncAttempt(other.lastSyncAttempt.load(std::memory_order_relaxed))
        , lastErrorTime(other.lastErrorTime.load(std::memory_order_relaxed))
        , lastErrorMessage(std::move(other.lastErrorMessage))
        , totalSuccessfulSyncs(other.totalSuccessfulSyncs.load(std::memory_order_relaxed))
        , totalFailedSyncs(other.totalFailedSyncs.load(std::memory_order_relaxed))
        , totalIOCsFetched(other.totalIOCsFetched.load(std::memory_order_relaxed))
        , lastSyncIOCCount(other.lastSyncIOCCount.load(std::memory_order_relaxed))
        , lastSyncNewIOCs(other.lastSyncNewIOCs.load(std::memory_order_relaxed))
        , lastSyncUpdatedIOCs(other.lastSyncUpdatedIOCs.load(std::memory_order_relaxed))
        , totalBytesDownloaded(other.totalBytesDownloaded.load(std::memory_order_relaxed))
        , lastSyncDurationMs(other.lastSyncDurationMs.load(std::memory_order_relaxed))
        , avgSyncDurationMs(other.avgSyncDurationMs.load(std::memory_order_relaxed))
        , consecutiveErrors(other.consecutiveErrors.load(std::memory_order_relaxed))
        , currentRetryAttempt(other.currentRetryAttempt.load(std::memory_order_relaxed))
        , nextScheduledSync(other.nextScheduledSync.load(std::memory_order_relaxed))
        , syncProgress(other.syncProgress.load(std::memory_order_relaxed))
        , currentPhase(std::move(other.currentPhase)) {}
    
    // Move assignment
    FeedStats& operator=(FeedStats&& other) noexcept {
        if (this != &other) {
            status.store(other.status.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSuccessfulSync.store(other.lastSuccessfulSync.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncAttempt.store(other.lastSyncAttempt.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastErrorTime.store(other.lastErrorTime.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastErrorMessage = std::move(other.lastErrorMessage);
            totalSuccessfulSyncs.store(other.totalSuccessfulSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalFailedSyncs.store(other.totalFailedSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalIOCsFetched.store(other.totalIOCsFetched.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncIOCCount.store(other.lastSyncIOCCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncNewIOCs.store(other.lastSyncNewIOCs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncUpdatedIOCs.store(other.lastSyncUpdatedIOCs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalBytesDownloaded.store(other.totalBytesDownloaded.load(std::memory_order_relaxed), std::memory_order_relaxed);
            lastSyncDurationMs.store(other.lastSyncDurationMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            avgSyncDurationMs.store(other.avgSyncDurationMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            consecutiveErrors.store(other.consecutiveErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
            currentRetryAttempt.store(other.currentRetryAttempt.load(std::memory_order_relaxed), std::memory_order_relaxed);
            nextScheduledSync.store(other.nextScheduledSync.load(std::memory_order_relaxed), std::memory_order_relaxed);
            syncProgress.store(other.syncProgress.load(std::memory_order_relaxed), std::memory_order_relaxed);
            currentPhase = std::move(other.currentPhase);
        }
        return *this;
    }
    
    /// @brief Get error message thread-safely
    [[nodiscard]] std::string GetLastError() const;
    
    /// @brief Set error message thread-safely
    void SetLastError(const std::string& error);
    
    /// @brief Get current phase thread-safely
    [[nodiscard]] std::string GetCurrentPhase() const;
    
    /// @brief Set current phase thread-safely
    void SetCurrentPhase(const std::string& phase);
    
    /// @brief Calculate success rate
    [[nodiscard]] double GetSuccessRate() const noexcept;
    
    /// @brief Check if feed is healthy
    [[nodiscard]] bool IsHealthy() const noexcept;
    
    /// @brief Reset statistics
    void Reset() noexcept;
};

/**
 * @brief Aggregated statistics for all feeds
 */
struct FeedManagerStats {
    /// @brief Total configured feeds
    std::atomic<uint32_t> totalFeeds{0};
    
    /// @brief Currently enabled feeds
    std::atomic<uint32_t> enabledFeeds{0};
    
    /// @brief Currently syncing feeds
    std::atomic<uint32_t> syncingFeeds{0};
    
    /// @brief Feeds in error state
    std::atomic<uint32_t> errorFeeds{0};
    
    /// @brief Total syncs completed
    std::atomic<uint64_t> totalSyncsCompleted{0};
    
    /// @brief Total IOCs fetched across all feeds
    std::atomic<uint64_t> totalIOCsFetched{0};
    
    /// @brief Total bytes downloaded across all feeds
    std::atomic<uint64_t> totalBytesDownloaded{0};
    
    /// @brief Uptime in seconds
    std::atomic<uint64_t> uptimeSeconds{0};
    
    /// @brief Start timestamp
    uint64_t startTime = 0;
};

// ============================================================================
// SYNC RESULT & EVENTS
// ============================================================================

/**
 * @brief Result of a feed synchronization
 */
struct SyncResult {
    bool success = false;
    std::string feedId;
    SyncTrigger trigger = SyncTrigger::Scheduled;
    
    // Timing
    uint64_t startTime = 0;
    uint64_t endTime = 0;
    uint64_t durationMs = 0;
    
    // Counts
    uint64_t totalFetched = 0;
    uint64_t newIOCs = 0;
    uint64_t updatedIOCs = 0;
    uint64_t duplicateIOCs = 0;
    uint64_t invalidIOCs = 0;
    uint64_t expiredIOCs = 0;
    
    // Network stats
    uint64_t bytesDownloaded = 0;
    uint32_t httpRequests = 0;
    uint32_t httpErrors = 0;
    
    // Error info
    std::string errorCode;
    std::string errorMessage;
    uint32_t retryAttempts = 0;
    
    // Pagination info
    bool hasMore = false;
    std::string nextPageToken;
    
    /// @brief Check if sync was successful
    [[nodiscard]] bool IsSuccess() const noexcept { return success; }
    
    /// @brief Get IOCs per second rate
    [[nodiscard]] double GetIOCsPerSecond() const noexcept;
};

/**
 * @brief Feed event type for notifications
 */
enum class FeedEventType : uint8_t {
    SyncStarted = 0,
    SyncCompleted = 1,
    SyncFailed = 2,
    SyncProgress = 3,
    RateLimited = 4,
    ErrorRecovered = 5,
    FeedEnabled = 6,
    FeedDisabled = 7,
    FeedAdded = 8,
    FeedRemoved = 9,
    FeedConfigChanged = 10,
    AuthRefreshed = 11,
    HealthWarning = 12
};

/**
 * @brief Feed event notification
 */
struct FeedEvent {
    FeedEventType type;
    std::string feedId;
    uint64_t timestamp;
    std::string message;
    std::optional<SyncResult> syncResult;
    
    /// @brief Create event
    static FeedEvent Create(FeedEventType type, const std::string& feedId, const std::string& msg = "");
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Sync progress callback
using SyncProgressCallback = std::function<bool(
    const std::string& feedId,
    uint64_t processed,
    uint64_t total,
    const std::string& phase
)>;

/// @brief Sync completion callback
using SyncCompletionCallback = std::function<void(const SyncResult& result)>;

/// @brief Feed event callback
using FeedEventCallback = std::function<void(const FeedEvent& event)>;

/// @brief IOC received callback (for streaming)
using IOCReceivedCallback = std::function<bool(const IOCEntry& entry)>;

/// @brief Authentication refresh callback
using AuthRefreshCallback = std::function<bool(AuthCredentials& credentials)>;

// ============================================================================
// FEED PARSER INTERFACE
// ============================================================================

/**
 * @brief Abstract interface for feed parsers
 */
class IFeedParser {
public:
    virtual ~IFeedParser() = default;
    
    /// @brief Parse feed response and extract IOCs
    [[nodiscard]] virtual bool Parse(
        std::span<const uint8_t> data,
        std::vector<IOCEntry>& outEntries,
        const ParserConfig& config
    ) = 0;
    
    /// @brief Parse streaming response
    [[nodiscard]] virtual bool ParseStreaming(
        std::span<const uint8_t> data,
        IOCReceivedCallback callback,
        const ParserConfig& config
    ) = 0;
    
    /// @brief Get pagination info from response
    [[nodiscard]] virtual std::optional<std::string> GetNextPageToken(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) = 0;
    
    /// @brief Get total count from response
    [[nodiscard]] virtual std::optional<uint64_t> GetTotalCount(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) = 0;
    
    /// @brief Get last error
    [[nodiscard]] virtual std::string GetLastError() const = 0;
};

/**
 * @brief JSON feed parser implementation
 */
class JsonFeedParser : public IFeedParser {
public:
    JsonFeedParser() = default;
    ~JsonFeedParser() override = default;
    
    [[nodiscard]] bool Parse(
        std::span<const uint8_t> data,
        std::vector<IOCEntry>& outEntries,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] bool ParseStreaming(
        std::span<const uint8_t> data,
        IOCReceivedCallback callback,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<std::string> GetNextPageToken(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<uint64_t> GetTotalCount(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::string GetLastError() const override { return m_lastError; }
    
private:
    std::string m_lastError;
    
    /// @brief Parse IOC entry from JSON object
    [[nodiscard]] bool ParseIOCEntry(
        const void* jsonObject,
        IOCEntry& entry,
        const ParserConfig& config
    );
    
    /// @brief Extract value at JSON path
    [[nodiscard]] std::optional<std::string> ExtractJsonPath(
        const void* root,
        const std::string& path
    );
};

/**
 * @brief CSV feed parser implementation
 */
class CsvFeedParser : public IFeedParser {
public:
    CsvFeedParser() = default;
    ~CsvFeedParser() override = default;
    
    [[nodiscard]] bool Parse(
        std::span<const uint8_t> data,
        std::vector<IOCEntry>& outEntries,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] bool ParseStreaming(
        std::span<const uint8_t> data,
        IOCReceivedCallback callback,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<std::string> GetNextPageToken(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<uint64_t> GetTotalCount(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::string GetLastError() const override { return m_lastError; }
    
private:
    std::string m_lastError;
    
    /// @brief Parse single CSV line
    [[nodiscard]] std::vector<std::string> ParseLine(
        std::string_view line,
        char delimiter,
        char quote
    );
};

/**
 * @brief STIX 2.1 feed parser implementation
 */
class StixFeedParser : public IFeedParser {
public:
    StixFeedParser() = default;
    ~StixFeedParser() override = default;
    
    [[nodiscard]] bool Parse(
        std::span<const uint8_t> data,
        std::vector<IOCEntry>& outEntries,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] bool ParseStreaming(
        std::span<const uint8_t> data,
        IOCReceivedCallback callback,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<std::string> GetNextPageToken(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::optional<uint64_t> GetTotalCount(
        std::span<const uint8_t> data,
        const ParserConfig& config
    ) override;
    
    [[nodiscard]] std::string GetLastError() const override { return m_lastError; }
    
private:
    std::string m_lastError;
    
    /// @brief Parse STIX indicator pattern
    [[nodiscard]] bool ParseSTIXPattern(
        const std::string& pattern,
        IOCEntry& entry
    );
    
    /// @brief Map STIX type to IOCType
    [[nodiscard]] std::optional<IOCType> MapSTIXTypeToIOCType(const std::string& stixType);
};

// ============================================================================
// HTTP CLIENT INTERFACE
// ============================================================================

/**
 * @brief HTTP response structure
 */
struct HttpResponse {
    int statusCode = 0;
    std::string statusMessage;
    std::unordered_map<std::string, std::string> headers;
    std::vector<uint8_t> body;
    std::string error;
    uint64_t downloadTimeMs = 0;
    uint64_t contentLength = 0;
    
    /// @brief Check if response is successful (2xx)
    [[nodiscard]] bool IsSuccess() const noexcept {
        return statusCode >= 200 && statusCode < 300;
    }
    
    /// @brief Check if rate limited (429)
    [[nodiscard]] bool IsRateLimited() const noexcept {
        return statusCode == 429;
    }
    
    /// @brief Check if server error (5xx)
    [[nodiscard]] bool IsServerError() const noexcept {
        return statusCode >= 500 && statusCode < 600;
    }
    
    /// @brief Get Retry-After header value in seconds
    [[nodiscard]] std::optional<uint32_t> GetRetryAfter() const;
};

/**
 * @brief HTTP request configuration
 */
struct HttpRequest {
    std::string url;
    std::string method = "GET";
    std::unordered_map<std::string, std::string> headers;
    std::vector<uint8_t> body;
    uint32_t timeoutMs = 30000;
    bool followRedirects = true;
    uint32_t maxRedirects = 5;
    bool verifySsl = true;
    std::string proxyUrl;
    std::string userAgent;
    
    /// @brief Create GET request
    [[nodiscard]] static HttpRequest Get(const std::string& url);
    
    /// @brief Create POST request
    [[nodiscard]] static HttpRequest Post(const std::string& url, const std::string& body);
};

/**
 * @brief Abstract HTTP client interface
 */
class IHttpClient {
public:
    virtual ~IHttpClient() = default;
    
    /// @brief Execute HTTP request
    [[nodiscard]] virtual HttpResponse Execute(const HttpRequest& request) = 0;
    
    /// @brief Execute request asynchronously
    [[nodiscard]] virtual std::future<HttpResponse> ExecuteAsync(const HttpRequest& request) = 0;
    
    /// @brief Set default headers
    virtual void SetDefaultHeaders(const std::unordered_map<std::string, std::string>& headers) = 0;
    
    /// @brief Set proxy
    virtual void SetProxy(const std::string& proxyUrl) = 0;
    
    /// @brief Get last error
    [[nodiscard]] virtual std::string GetLastError() const = 0;
};

// ============================================================================
// FEED MANAGER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade Threat Intelligence Feed Manager
 *
 * Thread-safe feed management with concurrent synchronization,
 * automatic rate limiting, and comprehensive monitoring.
 *
 * @example
 * @code
 * ThreatIntelFeedManager manager;
 * 
 * // Configure and start
 * FeedManagerConfig config;
 * config.maxConcurrentSyncs = 4;
 * manager.Initialize(config);
 * 
 * // Add feeds
 * manager.AddFeed(ThreatFeedConfig::CreateVirusTotal("your-api-key"));
 * manager.AddFeed(ThreatFeedConfig::CreateURLhaus());
 * 
 * // Set event callback
 * manager.SetEventCallback([](const FeedEvent& event) {
 *     std::cout << "Feed event: " << event.message << std::endl;
 * });
 * 
 * // Start automatic synchronization
 * manager.Start();
 * 
 * // Manual sync specific feed
 * auto result = manager.SyncFeed("virustotal");
 * 
 * // Stop
 * manager.Stop();
 * @endcode
 */
class ThreatIntelFeedManager {
public:
    /**
     * @brief Manager configuration
     */
    struct Config {
        /// @brief Maximum concurrent feed syncs
        uint32_t maxConcurrentSyncs = 4;
        
        /// @brief Worker thread count (0 = auto)
        uint32_t workerThreads = 0;
        
        /// @brief Global rate limit (requests/minute, 0 = unlimited)
        uint32_t globalRateLimitPerMinute = 0;
        
        /// @brief Maximum total IOCs to store
        uint64_t maxTotalIOCs = 100000000;  // 100 million
        
        /// @brief Enable automatic cleanup of expired IOCs
        bool autoCleanupExpired = true;
        
        /// @brief Cleanup interval in seconds
        uint32_t cleanupIntervalSeconds = 3600;
        
        /// @brief Enable feed health monitoring
        bool enableHealthMonitoring = true;
        
        /// @brief Health check interval in seconds
        uint32_t healthCheckIntervalSeconds = 300;
        
        /// @brief Maximum consecutive errors before disabling feed
        uint32_t maxConsecutiveErrors = 10;
        
        /// @brief Data directory for feed cache
        std::filesystem::path dataDirectory;
        
        /// @brief Enable persistent feed state
        bool persistState = true;
        
        /// @brief Validate configuration
        [[nodiscard]] bool Validate(std::string* errorMsg = nullptr) const;
    };
    
    // ========================================================================
    // CONSTRUCTORS & LIFECYCLE
    // ========================================================================
    
    /**
     * @brief Default constructor
     */
    ThreatIntelFeedManager();
    
    /**
     * @brief Destructor - ensures clean shutdown
     */
    ~ThreatIntelFeedManager();
    
    // Non-copyable, movable
    ThreatIntelFeedManager(const ThreatIntelFeedManager&) = delete;
    ThreatIntelFeedManager& operator=(const ThreatIntelFeedManager&) = delete;
    ThreatIntelFeedManager(ThreatIntelFeedManager&&) noexcept;
    ThreatIntelFeedManager& operator=(ThreatIntelFeedManager&&) noexcept;
    
    // ========================================================================
    // INITIALIZATION & LIFECYCLE
    // ========================================================================
    
    /**
     * @brief Initialize feed manager with configuration
     * @param config Manager configuration
     * @return true if initialized successfully
     */
    [[nodiscard]] bool Initialize(const Config& config);
    
    /**
     * @brief Start automatic feed synchronization
     * @return true if started successfully
     */
    [[nodiscard]] bool Start();
    
    /**
     * @brief Stop feed synchronization gracefully
     * @param timeoutMs Maximum wait time for ongoing syncs
     * @return true if stopped cleanly
     */
    bool Stop(uint32_t timeoutMs = 30000);
    
    /**
     * @brief Check if manager is running
     */
    [[nodiscard]] bool IsRunning() const noexcept;
    
    /**
     * @brief Shutdown and release resources
     */
    void Shutdown();
    
    // ========================================================================
    // FEED MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add new feed configuration
     * @param config Feed configuration
     * @return true if added successfully
     */
    [[nodiscard]] bool AddFeed(const ThreatFeedConfig& config);
    
    /**
     * @brief Add multiple feeds
     * @param configs Feed configurations
     * @return Number of feeds added successfully
     */
    uint32_t AddFeeds(std::span<const ThreatFeedConfig> configs);
    
    /**
     * @brief Remove feed by ID
     * @param feedId Feed identifier
     * @return true if removed
     */
    bool RemoveFeed(const std::string& feedId);
    
    /**
     * @brief Update feed configuration
     * @param feedId Feed identifier
     * @param config New configuration
     * @return true if updated
     */
    bool UpdateFeed(const std::string& feedId, const ThreatFeedConfig& config);
    
    /**
     * @brief Get feed configuration
     * @param feedId Feed identifier
     * @return Feed configuration if found
     */
    [[nodiscard]] std::optional<ThreatFeedConfig> GetFeedConfig(const std::string& feedId) const;
    
    /**
     * @brief Get all feed configurations
     */
    [[nodiscard]] std::vector<ThreatFeedConfig> GetAllFeedConfigs() const;
    
    /**
     * @brief Get feed IDs
     */
    [[nodiscard]] std::vector<std::string> GetFeedIds() const;
    
    /**
     * @brief Check if feed exists
     */
    [[nodiscard]] bool HasFeed(const std::string& feedId) const;
    
    /**
     * @brief Enable feed
     */
    bool EnableFeed(const std::string& feedId);
    
    /**
     * @brief Disable feed
     */
    bool DisableFeed(const std::string& feedId);
    
    /**
     * @brief Check if feed is enabled
     */
    [[nodiscard]] bool IsFeedEnabled(const std::string& feedId) const;
    
    // ========================================================================
    // SYNCHRONIZATION
    // ========================================================================
    
    /**
     * @brief Manually sync specific feed
     * @param feedId Feed identifier
     * @param progressCallback Optional progress callback
     * @return Sync result
     */
    [[nodiscard]] SyncResult SyncFeed(
        const std::string& feedId,
        SyncProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Sync feed asynchronously
     * @param feedId Feed identifier
     * @param completionCallback Callback on completion
     * @return Future with sync result
     */
    [[nodiscard]] std::future<SyncResult> SyncFeedAsync(
        const std::string& feedId,
        SyncCompletionCallback completionCallback = nullptr
    );
    
    /**
     * @brief Sync all enabled feeds
     * @param progressCallback Optional progress callback
     * @return Map of feed ID to sync result
     */
    [[nodiscard]] std::unordered_map<std::string, SyncResult> SyncAllFeeds(
        SyncProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Sync all feeds asynchronously
     */
    void SyncAllFeedsAsync(SyncCompletionCallback completionCallback = nullptr);
    
    /**
     * @brief Cancel ongoing sync for feed
     */
    bool CancelSync(const std::string& feedId);
    
    /**
     * @brief Cancel all ongoing syncs
     */
    void CancelAllSyncs();
    
    /**
     * @brief Check if feed is currently syncing
     */
    [[nodiscard]] bool IsSyncing(const std::string& feedId) const;
    
    /**
     * @brief Get currently syncing feed count
     */
    [[nodiscard]] uint32_t GetSyncingCount() const noexcept;
    
    // ========================================================================
    // STATISTICS & MONITORING
    // ========================================================================
    
    /**
     * @brief Get statistics for specific feed
     */
    [[nodiscard]] const FeedStats* GetFeedStats(const std::string& feedId) const;
    
    /**
     * @brief Get aggregated manager statistics
     */
    [[nodiscard]] const FeedManagerStats& GetManagerStats() const noexcept;
    
    /**
     * @brief Get feed status
     */
    [[nodiscard]] FeedSyncStatus GetFeedStatus(const std::string& feedId) const;
    
    /**
     * @brief Get all feeds with specific status
     */
    [[nodiscard]] std::vector<std::string> GetFeedsByStatus(FeedSyncStatus status) const;
    
    /**
     * @brief Check overall health
     */
    [[nodiscard]] bool IsHealthy() const noexcept;
    
    /**
     * @brief Get health report
     */
    [[nodiscard]] std::string GetHealthReport() const;
    
    // ========================================================================
    // CALLBACKS & EVENTS
    // ========================================================================
    
    /**
     * @brief Set event callback for all feed events
     */
    void SetEventCallback(FeedEventCallback callback);
    
    /**
     * @brief Set progress callback for sync operations
     */
    void SetProgressCallback(SyncProgressCallback callback);
    
    /**
     * @brief Set custom authentication refresh callback
     */
    void SetAuthRefreshCallback(AuthRefreshCallback callback);
    
    // ========================================================================
    // DATA ACCESS
    // ========================================================================
    
    /**
     * @brief Set target database for storing IOCs
     */
    void SetTargetDatabase(std::shared_ptr<ThreatIntelDatabase> database);
    
    /**
     * @brief Set target store for storing IOCs
     */
    void SetTargetStore(std::shared_ptr<ThreatIntelStore> store);
    
    /**
     * @brief Set custom HTTP client
     */
    void SetHttpClient(std::shared_ptr<IHttpClient> client);
    
    /**
     * @brief Register custom parser for protocol
     */
    void RegisterParser(FeedProtocol protocol, std::shared_ptr<IFeedParser> parser);
    
    // ========================================================================
    // PERSISTENCE
    // ========================================================================
    
    /**
     * @brief Save feed configurations to file
     */
    [[nodiscard]] bool SaveConfigs(const std::filesystem::path& path) const;
    
    /**
     * @brief Load feed configurations from file
     */
    [[nodiscard]] bool LoadConfigs(const std::filesystem::path& path);
    
    /**
     * @brief Save feed state (last sync times, etc.)
     */
    [[nodiscard]] bool SaveState(const std::filesystem::path& path) const;
    
    /**
     * @brief Load feed state
     */
    [[nodiscard]] bool LoadState(const std::filesystem::path& path);
    
    /**
     * @brief Export configuration to JSON
     */
    [[nodiscard]] std::string ExportConfigsToJson() const;
    
    /**
     * @brief Import configuration from JSON
     */
    [[nodiscard]] bool ImportConfigsFromJson(const std::string& json);
    
private:
    // ========================================================================
    // INTERNAL TYPES
    // ========================================================================
    
    struct FeedContext {
        ThreatFeedConfig config;
        FeedStats stats;
        std::unique_ptr<RateLimitConfig> rateLimit;
        std::atomic<bool> cancelRequested{false};
        std::atomic<bool> syncInProgress{false};
        std::chrono::steady_clock::time_point lastSyncStart;
    };
    
    struct SyncTask {
        std::string feedId;
        SyncTrigger trigger;
        FeedPriority priority;
        SyncProgressCallback progressCallback;
        SyncCompletionCallback completionCallback;
        std::chrono::steady_clock::time_point scheduledTime;
        
        bool operator<(const SyncTask& other) const {
            if (priority != other.priority) {
                return priority > other.priority;  // Lower enum = higher priority
            }
            return scheduledTime > other.scheduledTime;
        }
    };
    
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================
    
    /// @brief Worker thread main loop
    void WorkerThread();
    
    /// @brief Scheduler thread main loop
    void SchedulerThread();
    
    /// @brief Health monitor thread main loop
    void HealthMonitorThread();
    
    /// @brief Execute sync for feed
    [[nodiscard]] SyncResult ExecuteSync(
        FeedContext& context,
        SyncTrigger trigger,
        SyncProgressCallback progressCallback
    );
    
    /// @brief Fetch data from feed endpoint
    [[nodiscard]] HttpResponse FetchFeedData(
        FeedContext& context,
        const std::string& url,
        uint64_t offset = 0
    );
    
    /// @brief Parse feed response
    [[nodiscard]] bool ParseFeedResponse(
        FeedContext& context,
        const HttpResponse& response,
        std::vector<IOCEntry>& outEntries
    );
    
    /// @brief Store parsed IOCs
    [[nodiscard]] bool StoreIOCs(
        FeedContext& context,
        const std::vector<IOCEntry>& entries,
        SyncResult& result
    );
    
    /// @brief Apply rate limiting
    [[nodiscard]] bool WaitForRateLimit(FeedContext& context);
    
    /// @brief Handle authentication
    [[nodiscard]] bool PrepareAuthentication(FeedContext& context, HttpRequest& request);
    
    /// @brief Refresh OAuth2 token if needed
    [[nodiscard]] bool RefreshOAuth2Token(FeedContext& context);
    
    /// @brief Calculate retry delay with jitter
    [[nodiscard]] uint32_t CalculateRetryDelay(const FeedContext& context, uint32_t attempt);
    
    /// @brief Get or create parser for protocol
    [[nodiscard]] IFeedParser* GetParser(FeedProtocol protocol);
    
    /// @brief Emit feed event
    void EmitEvent(FeedEventType type, const std::string& feedId, const std::string& message = "");
    
    /// @brief Schedule next sync for feed
    void ScheduleNextSync(FeedContext& context);
    
    /// @brief Update manager statistics
    void UpdateManagerStats();
    
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================
    
    /// @brief Configuration
    Config m_config;
    
    /// @brief Feed contexts (feedId -> context)
    std::unordered_map<std::string, std::unique_ptr<FeedContext>> m_feeds;
    mutable std::shared_mutex m_feedsMutex;
    
    /// @brief Sync task queue
    std::priority_queue<SyncTask> m_taskQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    
    /// @brief Worker threads
    std::vector<std::thread> m_workerThreads;
    
    /// @brief Scheduler thread
    std::thread m_schedulerThread;
    
    /// @brief Health monitor thread
    std::thread m_healthThread;
    
    /// @brief Running flag
    std::atomic<bool> m_running{false};
    
    /// @brief Shutdown flag
    std::atomic<bool> m_shutdown{false};
    
    /// @brief Initialized flag
    std::atomic<bool> m_initialized{false};
    
    /// @brief Manager statistics
    FeedManagerStats m_stats;
    
    /// @brief Target database
    std::shared_ptr<ThreatIntelDatabase> m_database;
    
    /// @brief Target store
    std::shared_ptr<ThreatIntelStore> m_store;
    
    /// @brief HTTP client
    std::shared_ptr<IHttpClient> m_httpClient;
    
    /// @brief Parsers by protocol
    std::unordered_map<FeedProtocol, std::shared_ptr<IFeedParser>> m_parsers;
    std::mutex m_parsersMutex;
    
    /// @brief Event callback
    FeedEventCallback m_eventCallback;
    std::mutex m_eventMutex;
    
    /// @brief Progress callback
    SyncProgressCallback m_progressCallback;
    std::mutex m_progressMutex;
    
    /// @brief Auth refresh callback
    AuthRefreshCallback m_authRefreshCallback;
    std::mutex m_authMutex;
    
    /// @brief Active sync count
    std::atomic<uint32_t> m_activeSyncCount{0};
    
    /// @brief Maximum concurrent syncs
    static constexpr uint32_t MAX_CONCURRENT_SYNCS = 4;
    
    /// @brief Sync concurrency limiter mutex
    std::mutex m_syncLimiterMutex;
    
    /// @brief Sync concurrency condition variable
    std::condition_variable m_syncLimiterCv;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get current Unix timestamp in seconds
 */
[[nodiscard]] inline uint64_t GetCurrentTimestamp() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

/**
 * @brief Parse duration string (e.g., "1h", "30m", "1d")
 */
[[nodiscard]] std::optional<uint32_t> ParseDurationString(std::string_view duration);

/**
 * @brief Format duration for display
 */
[[nodiscard]] std::string FormatDuration(uint64_t seconds);

/**
 * @brief Validate URL format
 */
[[nodiscard]] bool IsValidUrl(std::string_view url);

/**
 * @brief Detect IOC type from string value
 */
[[nodiscard]] std::optional<IOCType> DetectIOCType(std::string_view value);

} // namespace ThreatIntel
} // namespace ShadowStrike
