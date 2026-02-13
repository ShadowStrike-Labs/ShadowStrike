/**
 * @file ThreatIntelStore.hpp
 * @brief Enterprise-grade Threat Intelligence Store - Main facade class
 *
 * This is the primary interface for the ShadowStrike Threat Intelligence module.
 * Provides unified access to:
 * - IOC (Indicator of Compromise) lookups with sub-microsecond performance
 * - Multiple threat feed management (VirusTotal, AlienVault OTX, CrowdStrike, etc.)
 * - Memory-mapped persistent storage for nanosecond-level access
 * - STIX 2.1 / TAXII 2.1 protocol support
 * - Real-time reputation scoring
 * - Batch operations for high-throughput scanning
 *
 * Architecture follows CrowdStrike Falcon and Microsoft Defender design patterns
 * suitable for Microsoft, Apple, Google-level enterprise deployments.
 *
 * Performance Targets:
 * - Hash lookup: <100ns average
 * - IP lookup: <500ns average
 * - Domain lookup: <1µs average
 * - Batch lookup (1000 items): <1ms
 * - Feed update: <10s for 1M entries
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include"ThreatIntelImporter.hpp"
#include"ThreatIntelFeedManager.hpp"
#include "ThreatIntelExporter.hpp"
#include"ThreatIntelLookup.hpp"
#include "ReputationCache.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#include <span>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <thread>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Forward Declarations
// ============================================================================

class ThreatIntelStore;
class FeedManager;
class STIXParser;
class TAXIIClient;

// ============================================================================
// Store Configuration
// ============================================================================

/**
 * @brief Configuration for ThreatIntelStore
 *
 * Enterprise-grade configuration with sensible defaults for high-performance
 * threat intelligence operations.
 */
struct StoreConfig {
    // Database file path (memory-mapped)
    std::wstring databasePath;
    
    // Cache configuration for the in-memory reputation cache
    CacheOptions cacheOptions;
    
    // Simple cache enable flag (uses cacheOptions internally)
    bool enableCache = true;
    
    // Simple cache capacity (overrides cacheOptions.totalCapacity if set)
    size_t cacheCapacity = 0;  // 0 = use cacheOptions.totalCapacity
    
    // Maximum database size (0 = auto-grow)
    size_t maxDatabaseSize = 0;
    
    // Initial database size for pre-allocation
    size_t initialDatabaseSize = 100 * 1024 * 1024; // 100 MB
    
    // Maximum IOC entries
    size_t maxIOCEntries = 50000000; // 50 million
    
    // Enable write-ahead logging for crash recovery
    bool enableWAL = true;
    
    // WAL file path (if empty, derived from databasePath)
    std::wstring walPath;
    
    // Flush WAL to disk interval
    std::chrono::seconds walFlushInterval = std::chrono::seconds(30);
    
    // Enable automatic feed updates (alias for enableAutoFeedUpdate)
    bool enableAutoFeedUpdates = true;
    
    // Enable automatic feed updates
    bool enableAutoFeedUpdate = true;
    
    // Enable statistics collection
    bool enableStatistics = true;
    
    // Feed update interval
    std::chrono::hours feedUpdateInterval = std::chrono::hours(1);
    
    // Maximum concurrent feed downloads
    size_t maxConcurrentFeedDownloads = 4;
    
    // Network timeout for feed downloads
    std::chrono::seconds feedDownloadTimeout = std::chrono::seconds(300);
    
    // Enable compression for stored data
    bool enableCompression = false;
    
    // Enable integrity verification on load
    bool verifyIntegrityOnLoad = true;
    
    // Background worker thread count
    size_t workerThreadCount = 0; // 0 = auto-detect
    
    // Enable STIX 2.1 format support
    bool enableSTIXSupport = true;
    
    // Enable TAXII 2.1 protocol support
    bool enableTAXIISupport = true;
    
    // Statistics collection interval
    std::chrono::seconds statsCollectionInterval = std::chrono::seconds(60);
    
    /**
     * @brief Create default configuration
     * 
     * Creates a configuration with sensible defaults for most use cases.
     * The database path is set to a temporary directory for convenience.
     * For production deployments, specify an explicit databasePath.
     */
    static StoreConfig CreateDefault() {
        StoreConfig config;
        config.cacheOptions = CacheOptions{};
        
        // Generate a unique temp directory path for the database
        // TITANIUM: Use a deterministic temp path for default configuration
        wchar_t tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) > 0) {
            // Create a unique database filename based on process ID
            config.databasePath = std::wstring(tempPath) + L"ShadowStrike_ThreatIntel_" 
                + std::to_wstring(GetCurrentProcessId()) + L".tidb";
        } else {
            // Fallback to current directory if temp path unavailable
            config.databasePath = L".\\ShadowStrike_ThreatIntel.tidb";
        }
        
        return config;
    }
    
    /**
     * @brief Create high-performance configuration
     * Optimized for enterprise deployments with maximum throughput
     * 
     * @note Uses a temporary database path by default. For production,
     *       specify an explicit databasePath after calling this method.
     */
    static StoreConfig CreateHighPerformance() {
        StoreConfig config = CreateDefault(); // Start with default (includes temp path)
        config.cacheOptions.shardCount = 256;
        config.cacheOptions.totalCapacity = config.cacheOptions.shardCount * 65536; // 16,777,216 entries
        config.cacheOptions.positiveTTL = CacheConfig::DEFAULT_TTL_SECONDS * 2;
        config.cacheOptions.negativeTTL = 600;
        config.cacheOptions.bloomExpectedElements = config.cacheOptions.totalCapacity * 2;
        config.cacheOptions.bloomFalsePositiveRate = 0.005;
        config.cacheOptions.autoEvictionIntervalSeconds = 30;
        config.initialDatabaseSize = 1024 * 1024 * 1024; // 1 GB
        config.maxIOCEntries = 100000000; // 100 million
        config.workerThreadCount = std::thread::hardware_concurrency();
        config.maxConcurrentFeedDownloads = 8;
        
        // Update database path to indicate high-perf variant
        wchar_t tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) > 0) {
            config.databasePath = std::wstring(tempPath) + L"ShadowStrike_ThreatIntel_HighPerf_" 
                + std::to_wstring(GetCurrentProcessId()) + L".tidb";
        }
        
        return config;
    }
    
    /**
     * @brief Create low memory configuration
     * For embedded or resource-constrained environments
     * 
     * @note Uses a temporary database path by default. For production,
     *       specify an explicit databasePath after calling this method.
     */
    static StoreConfig CreateLowMemory() {
        StoreConfig config = CreateDefault(); // Start with default (includes temp path)
        config.cacheOptions.shardCount = 16;
        config.cacheOptions.totalCapacity = config.cacheOptions.shardCount * 4096; // 65,536 entries
        config.cacheOptions.positiveTTL = 1800;
        config.cacheOptions.negativeTTL = 120;
        config.cacheOptions.bloomExpectedElements = config.cacheOptions.totalCapacity;
        config.initialDatabaseSize = 10 * 1024 * 1024; // 10 MB
        config.maxIOCEntries = 1000000; // 1 million
        config.enableCompression = true;
        config.workerThreadCount = 2;
        config.maxConcurrentFeedDownloads = 1;
        
        // Update database path to indicate low-memory variant
        wchar_t tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath) > 0) {
            config.databasePath = std::wstring(tempPath) + L"ShadowStrike_ThreatIntel_LowMem_" 
                + std::to_wstring(GetCurrentProcessId()) + L".tidb";
        }
        
        return config;
    }
};

// ============================================================================
// Query Options and Results
// ============================================================================

/**
 * @brief Options for IOC lookup operations via ThreatIntelStore
 * 
 * @note This is a higher-level options struct for ThreatIntelStore API.
 * Distinguished from ThreatIntelFormat::LookupOptions and ThreatIntelLookup::LookupOptions.
 */
struct StoreLookupOptions {
    // Check cache before database
    bool useCache = true;
    
    // Update cache with result
    bool updateCache = true;
    
    // Include metadata in result
    bool includeMetadata = true;
    
    // Include confidence scoring
    bool includeConfidence = true;
    
    // Include source attribution
    bool includeSourceAttribution = true;
    
    // Maximum age of cached entry to accept
    std::chrono::seconds maxCacheAge = std::chrono::hours(24);
    
    // Minimum confidence threshold (0-100)
    uint8_t minConfidenceThreshold = 0;
    
    // Required source flags (bitmask)
    uint32_t requiredSources = 0;
    
    // IOC types to search (empty = all)
    std::vector<IOCType> iocTypesFilter;
    
    // Reputation levels to include
    std::vector<ReputationLevel> reputationFilter;
    
    /**
     * @brief Create options for fastest lookup
     */
    [[nodiscard]] static StoreLookupOptions FastLookup() noexcept {
        StoreLookupOptions opts;
        opts.includeMetadata = false;
        opts.includeSourceAttribution = false;
        return opts;
    }
    
    /**
     * @brief Create options for detailed lookup
     */
    [[nodiscard]] static StoreLookupOptions DetailedLookup() noexcept {
        StoreLookupOptions opts;
        opts.includeMetadata = true;
        opts.includeConfidence = true;
        opts.includeSourceAttribution = true;
        return opts;
    }
};

/**
 * @brief Result of an IOC lookup via ThreatIntelStore
 * 
 * Contains comprehensive information about a threat intelligence lookup.
 * Thread-safe for reading after construction.
 * 
 * @note Distinguished from ThreatIntelFormat::LookupResult which is lower-level.
 */
struct StoreLookupResult {
    // Whether the IOC was found
    bool found = false;
    
    // Whether result came from cache
    bool fromCache = false;
    
    // Lookup latency in nanoseconds
    uint64_t latencyNs = 0;
    
    // Reputation information
    ReputationLevel reputation = ReputationLevel::Unknown;
    ConfidenceLevel confidence = ConfidenceLevel::None;
    ThreatCategory category = ThreatCategory::Unknown;
    
    // Source that provided the intelligence
    ThreatIntelSource primarySource = ThreatIntelSource::Unknown;
    uint32_t sourceFlags = 0; // Bitmask of all sources
    
    // Score (0-100, higher = more malicious)
    uint8_t score = 0;
    
    // First and last seen timestamps
    uint64_t firstSeen = 0;
    uint64_t lastSeen = 0;
    
    // Full IOC entry (if includeMetadata was true)
    std::optional<IOCEntry> entry;
    
    // STIX bundle ID if from STIX source
    std::optional<std::string> stixBundleId;
    
    // Related indicators (if available)
    std::vector<std::pair<IOCType, std::string>> relatedIndicators;
    
    // Default constructor - initializes to "not found" state
    StoreLookupResult() noexcept = default;
    
    // Copy and move operations (vectors may throw but we handle gracefully)
    StoreLookupResult(const StoreLookupResult&) = default;
    StoreLookupResult& operator=(const StoreLookupResult&) = default;
    StoreLookupResult(StoreLookupResult&&) noexcept = default;
    StoreLookupResult& operator=(StoreLookupResult&&) noexcept = default;
    
    /**
     * @brief Check if IOC is malicious
     * @return true if found and reputation is Malicious or HighRisk
     */
    [[nodiscard]] bool IsMalicious() const noexcept {
        return found && (reputation == ReputationLevel::Malicious ||
                         reputation == ReputationLevel::HighRisk);
    }
    
    /**
     * @brief Check if IOC is suspicious
     * @return true if found and reputation indicates suspicion
     */
    [[nodiscard]] bool IsSuspicious() const noexcept {
        return found && (reputation == ReputationLevel::Suspicious ||
                         reputation == ReputationLevel::HighRisk ||
                         reputation == ReputationLevel::Malicious);
    }
    
    /**
     * @brief Check if IOC is known-good
     * @return true if found and reputation is Safe or Trusted
     */
    [[nodiscard]] bool IsKnownGood() const noexcept {
        return found && (reputation == ReputationLevel::Safe ||
                 reputation == ReputationLevel::Trusted);
    }
};

/**
 * @brief Result of a batch lookup operation via ThreatIntelStore
 * 
 * Aggregates results from multiple IOC lookups into a single response.
 * Provides summary statistics and per-item results.
 * 
 * @note The results vector index corresponds to the input index.
 * Distinguished from ThreatIntelFormat::BatchLookupResult.
 */
struct StoreBatchLookupResult {
    // Total items processed
    size_t totalProcessed = 0;
    
    // Items found in database
    size_t foundCount = 0;
    
    // Items found in cache
    size_t cacheHits = 0;
    
    // Items found in database (not cache)
    size_t databaseHits = 0;
    
    // Items not found
    size_t notFoundCount = 0;
    
    // Malicious items found
    size_t maliciousCount = 0;
    
    // Suspicious items found
    size_t suspiciousCount = 0;
    
    // Total processing time
    std::chrono::nanoseconds totalTime{0};
    
    // Average lookup time per item
    std::chrono::nanoseconds averageTimePerItem{0};
    
    // Individual results (index matches input index)
    std::vector<StoreLookupResult> results;
    
    // Default constructor
    StoreBatchLookupResult() noexcept = default;
    
    // Copy/move operations (vector may throw on copy but we mark noexcept for move)
    StoreBatchLookupResult(const StoreBatchLookupResult&) = default;
    StoreBatchLookupResult& operator=(const StoreBatchLookupResult&) = default;
    StoreBatchLookupResult(StoreBatchLookupResult&&) noexcept = default;
    StoreBatchLookupResult& operator=(StoreBatchLookupResult&&) noexcept = default;
    
    /**
     * @brief Calculate the cache hit rate for this batch
     * @return Cache hit rate as a percentage (0.0 to 1.0)
     */
    [[nodiscard]] double GetCacheHitRate() const noexcept {
        return totalProcessed > 0 ? 
            static_cast<double>(cacheHits) / static_cast<double>(totalProcessed) : 0.0;
    }
    
    /**
     * @brief Check if any malicious IOCs were found
     */
    [[nodiscard]] bool HasMalicious() const noexcept {
        return maliciousCount > 0;
    }
};

// ============================================================================
// Feed Configuration
// ============================================================================

/**
 * @brief Types of threat intelligence feeds
 */
enum class FeedType : uint8_t {
    Unknown = 0,
    STIX_TAXII,      // STIX 2.1 via TAXII 2.1
    STIX_File,       // STIX 2.1 JSON file
    CSV,             // CSV format
    JSON,            // Generic JSON format
    PlainText,       // One IOC per line
    MISP,            // MISP format
    OpenIOC,         // OpenIOC XML format
    YARA,            // YARA rules
    Sigma,           // Sigma rules
    Custom           // Custom parser
};

/**
 * @brief Authentication methods for feeds
 */
enum class FeedAuthType : uint8_t {
    None = 0,
    APIKey,
    BasicAuth,
    BearerToken,
    OAuth2,
    Certificate,
    Custom
};

/**
 * @brief Configuration for a threat intelligence feed (high-level API)
 * 
 * @note Distinguished from ThreatIntelFormat::FeedConfig which is a binary packed struct.
 * This is the user-facing configuration structure for feed management.
 */
struct FeedConfiguration {
    // Unique feed identifier
    std::string feedId;
    
    // Human-readable name
    std::string name;
    
    // Feed description
    std::string description;
    
    // Feed type
    FeedType type = FeedType::Unknown;
    
    // Feed URL or file path
    std::string url;
    
    // Alternative URLs for failover
    std::vector<std::string> alternativeUrls;
    
    // Authentication type
    FeedAuthType authType = FeedAuthType::None;
    
    // API key or credentials
    std::string apiKey;
    std::string username;
    std::string password;
    
    // OAuth2 configuration
    std::string oauth2TokenUrl;
    std::string oauth2ClientId;
    std::string oauth2ClientSecret;
    std::string oauth2Scope;
    
    // Certificate paths for mTLS
    std::string clientCertPath;
    std::string clientKeyPath;
    std::string caCertPath;
    
    // Update interval
    std::chrono::hours updateInterval = std::chrono::hours(1);
    
    // Enable/disable feed
    bool enabled = true;
    
    // Priority (higher = more trusted)
    uint8_t priority = 50;
    
    // Download timeout
    std::chrono::seconds timeout = std::chrono::seconds(300);
    
    // Maximum entries to import from this feed
    size_t maxEntries = 0; // 0 = unlimited
    
    // IOC types to import (empty = all)
    std::vector<IOCType> allowedIOCTypes;
    
    // Minimum confidence to import
    ConfidenceLevel minConfidence = ConfidenceLevel::None;
    
    // Tags to apply to entries from this feed
    std::vector<std::string> tags;
    
    // Custom headers for HTTP requests
    std::vector<std::pair<std::string, std::string>> customHeaders;
    
    // TAXII-specific configuration
    std::string taxiiCollectionId;
    std::string taxiiApiRoot;
    
    // Signature verification (for signed feeds)
    bool verifySignature = false;
    std::string signatureKeyPath;
    
    /**
     * @brief Create VirusTotal feed configuration
     */
    [[nodiscard]] static FeedConfiguration CreateVirusTotal(const std::string& apiKey) {
        FeedConfiguration config;
        config.feedId = "virustotal";
        config.name = "VirusTotal";
        config.description = "VirusTotal threat intelligence feed";
        config.type = FeedType::JSON;
        config.url = "https://www.virustotal.com/api/v3/intelligence/feeds";
        config.authType = FeedAuthType::APIKey;
        config.apiKey = apiKey;
        config.priority = 90;
        return config;
    }
    
    /**
     * @brief Create AlienVault OTX feed configuration
     */
    [[nodiscard]] static FeedConfiguration CreateAlienVaultOTX(const std::string& apiKey) {
        FeedConfiguration config;
        config.feedId = "alienvault_otx";
        config.name = "AlienVault OTX";
        config.description = "AlienVault Open Threat Exchange";
        config.type = FeedType::JSON;
        config.url = "https://otx.alienvault.com/api/v1/pulses/subscribed";
        config.authType = FeedAuthType::APIKey;
        config.apiKey = apiKey;
        config.customHeaders.push_back({"X-OTX-API-KEY", apiKey});
        config.priority = 80;
        return config;
    }
    
    /**
     * @brief Create Abuse.ch feeds configuration
     */
    [[nodiscard]] static FeedConfiguration CreateAbuseCH(const std::string& feedName) {
        FeedConfiguration config;
        config.feedId = "abusech_" + feedName;
        config.name = "Abuse.ch " + feedName;
        config.type = FeedType::PlainText;
        config.authType = FeedAuthType::None;
        config.priority = 75;
        
        if (feedName == "urlhaus") {
            config.url = "https://urlhaus.abuse.ch/downloads/csv_recent/";
            config.type = FeedType::CSV;
        } else if (feedName == "threatfox") {
            config.url = "https://threatfox.abuse.ch/export/json/recent/";
            config.type = FeedType::JSON;
        } else if (feedName == "feodotracker") {
            config.url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";
            config.type = FeedType::CSV;
        } else if (feedName == "sslbl") {
            config.url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv";
            config.type = FeedType::CSV;
        }
        
        return config;
    }
    
    /**
     * @brief Create MISP feed configuration
     */
    [[nodiscard]] static FeedConfiguration CreateMISP(const std::string& serverUrl, const std::string& apiKey) {
        FeedConfiguration config;
        config.feedId = "misp";
        config.name = "MISP";
        config.description = "Malware Information Sharing Platform";
        config.type = FeedType::MISP;
        config.url = serverUrl + "/events/restSearch";
        config.authType = FeedAuthType::APIKey;
        config.apiKey = apiKey;
        config.customHeaders.push_back({"Authorization", apiKey});
        config.customHeaders.push_back({"Accept", "application/json"});
        config.priority = 85;
        return config;
    }
};

/**
 * @brief Status of a feed
 */
struct FeedStatus {
    std::string feedId;
    bool enabled = false;
    bool isUpdating = false;
    
    std::chrono::system_clock::time_point lastUpdateTime;
    std::chrono::system_clock::time_point nextUpdateTime;
    std::chrono::system_clock::time_point lastSuccessTime;
    
    size_t totalEntriesImported = 0;
    size_t lastImportCount = 0;
    size_t errorCount = 0;
    
    std::string lastError;
    
    // Download statistics
    size_t totalBytesDownloaded = 0;
    std::chrono::milliseconds lastDownloadDuration{0};
};

// ============================================================================
// Import/Export Options
// ============================================================================

/**
 * @brief Simplified options for importing threat intelligence data via ThreatIntelStore
 * 
 * @note For advanced import options, use ThreatIntelImporter::ImportOptions directly.
 */
struct StoreImportOptions {
    // Overwrite existing entries
    bool overwriteExisting = true;
    
    // Update cache with imported entries
    bool updateCache = true;
    
    // Validate entries before import
    bool validateEntries = true;
    
    // Source attribution for imported data
    ThreatIntelSource source = ThreatIntelSource::Unknown;
    
    // Tags to apply to imported entries
    std::vector<std::string> tags;
    
    // Minimum confidence to import
    ConfidenceLevel minConfidence = ConfidenceLevel::None;
    
    // IOC types to import (empty = all)
    std::vector<IOCType> allowedIOCTypes;
    
    // Maximum entries to import (0 = unlimited)
    size_t maxEntries = 0;
    
    // Skip duplicate entries
    bool skipDuplicates = true;
    
    // Apply TTL to imported entries
    std::chrono::seconds defaultTTL = std::chrono::hours(24 * 30); // 30 days
    
    // Progress callback
    std::function<void(size_t processed, size_t total)> progressCallback;
};

/**
 * @brief Simplified options for exporting threat intelligence data via ThreatIntelStore
 * 
 * @note For advanced export options, use ThreatIntelExporter::ExportOptions directly.
 */
struct StoreExportOptions {
    // Export format
    enum class Format : uint8_t {
        STIX21,       // STIX 2.1 JSON
        CSV,          // CSV format
        JSON,         // Custom JSON format
        PlainText,    // One IOC per line
        MISP          // MISP format
    } format = Format::STIX21;
    
    // IOC types to export (empty = all)
    std::vector<IOCType> iocTypesFilter;
    
    // Reputation levels to export
    std::vector<ReputationLevel> reputationFilter;
    
    // Minimum confidence to export
    ConfidenceLevel minConfidence = ConfidenceLevel::None;
    
    // Sources to export (empty = all)
    std::vector<ThreatIntelSource> sourceFilter;
    
    // Time range filter
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    
    // Maximum entries to export (0 = unlimited)
    size_t maxEntries = 0;
    
    // Include metadata
    bool includeMetadata = true;
    
    // Compress output
    bool compress = false;
    
    // Progress callback
    std::function<void(size_t processed, size_t total)> progressCallback;
};

// ============================================================================
// Statistics
// ============================================================================

/**
 * @brief Comprehensive statistics for the threat intelligence store
 * 
 * Contains both regular and atomic counters for thread-safe access to
 * frequently updated metrics. Use the copy/move operations to safely
 * retrieve a snapshot of the statistics.
 * 
 * @note Atomic members use relaxed memory ordering for performance
 * @note Thread-safe for reading individual atomic counters
 */
struct StoreStatistics {
    // Database statistics
    size_t totalIOCEntries = 0;
    size_t totalHashEntries = 0;
    size_t totalIPEntries = 0;
    size_t totalDomainEntries = 0;
    size_t totalURLEntries = 0;
    size_t totalEmailEntries = 0;
    size_t totalOtherEntries = 0;
    
    // Size statistics
    size_t databaseSizeBytes = 0;
    size_t memorySizeBytes = 0;
    size_t cacheSizeBytes = 0;
    
    // Performance statistics (atomic for thread-safe updates)
    std::atomic<uint64_t> totalLookups{0};
    std::atomic<uint64_t> successfulLookups{0};  // Lookups that found an entry
    std::atomic<uint64_t> failedLookups{0};      // Lookups that did not find an entry
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> databaseHits{0};
    std::atomic<uint64_t> databaseMisses{0};
    
    // Timing statistics (in nanoseconds)
    std::atomic<uint64_t> totalLookupTimeNs{0};
    std::atomic<uint64_t> minLookupTimeNs{UINT64_MAX};
    std::atomic<uint64_t> maxLookupTimeNs{0};
    
    // Feed statistics
    size_t activeFeedsCount = 0;
    size_t feedUpdatesPending = 0;
    size_t totalFeedErrors = 0;
    
    // Import/export statistics (atomic for thread-safe updates)
    std::atomic<uint64_t> totalImportedEntries{0};
    std::atomic<uint64_t> totalExportedEntries{0};
    
    // Timestamps
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastUpdateAt;
    std::chrono::system_clock::time_point lastLookupAt;

    /// @brief Default constructor - initializes all values safely
    StoreStatistics() noexcept {
        // Atomic members are already initialized via member initializers
        // Non-atomic members initialized to zero/default values
    }
    
    StoreStatistics(const StoreStatistics& other) noexcept { CopyFrom(other); }
    StoreStatistics& operator=(const StoreStatistics& other) noexcept {
        if (this != &other) {
            CopyFrom(other);
        }
        return *this;
    }
    StoreStatistics(StoreStatistics&& other) noexcept { CopyFrom(other); }
    StoreStatistics& operator=(StoreStatistics&& other) noexcept {
        if (this != &other) {
            CopyFrom(other);
        }
        return *this;
    }
    
    /**
     * @brief Calculate cache hit rate
     */
    [[nodiscard]] double CacheHitRate() const noexcept {
        const uint64_t total = cacheHits.load() + cacheMisses.load();
        return total > 0 ? static_cast<double>(cacheHits.load()) / total : 0.0;
    }
    
    /**
     * @brief Calculate average lookup time in nanoseconds
     */
    [[nodiscard]] uint64_t AverageLookupTimeNs() const noexcept {
        const uint64_t lookups = totalLookups.load();
        return lookups > 0 ? totalLookupTimeNs.load() / lookups : 0;
    }

private:
    void CopyFrom(const StoreStatistics& other) noexcept {
        totalIOCEntries = other.totalIOCEntries;
        totalHashEntries = other.totalHashEntries;
        totalIPEntries = other.totalIPEntries;
        totalDomainEntries = other.totalDomainEntries;
        totalURLEntries = other.totalURLEntries;
        totalEmailEntries = other.totalEmailEntries;
        totalOtherEntries = other.totalOtherEntries;
        databaseSizeBytes = other.databaseSizeBytes;
        memorySizeBytes = other.memorySizeBytes;
        cacheSizeBytes = other.cacheSizeBytes;
        activeFeedsCount = other.activeFeedsCount;
        feedUpdatesPending = other.feedUpdatesPending;
        totalFeedErrors = other.totalFeedErrors;
        createdAt = other.createdAt;
        lastUpdateAt = other.lastUpdateAt;
        lastLookupAt = other.lastLookupAt;

        totalLookups.store(other.totalLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        successfulLookups.store(other.successfulLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        failedLookups.store(other.failedLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheHits.store(other.cacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheMisses.store(other.cacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
        databaseHits.store(other.databaseHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
        databaseMisses.store(other.databaseMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalLookupTimeNs.store(other.totalLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);
        minLookupTimeNs.store(other.minLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);
        maxLookupTimeNs.store(other.maxLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalImportedEntries.store(
            other.totalImportedEntries.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
        totalExportedEntries.store(
            other.totalExportedEntries.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
    }
};

// ============================================================================
// Event Callbacks
// ============================================================================

/**
 * @brief Event types for store callbacks
 * 
 * Defines all possible events that can be fired by the threat intelligence store.
 * Subscribe using RegisterEventCallback to receive notifications.
 */
enum class StoreEventType : uint8_t {
    IOCAdded,                 ///< Single IOC entry added
    IOCUpdated,               ///< IOC entry updated
    IOCRemoved,               ///< IOC entry removed
    DataImported,             ///< Bulk data import completed
    FeedUpdateStarted,        ///< Feed update process started
    FeedUpdateCompleted,      ///< Feed update completed successfully
    FeedUpdateFailed,         ///< Feed update failed
    CacheEviction,            ///< Cache entries evicted
    DatabaseCompacted,        ///< Database compaction completed
    IntegrityCheckCompleted,  ///< Integrity verification finished
    Error                     ///< General error event
};

/**
 * @brief Event data for store callbacks
 * 
 * Contains all information about an event fired by the store.
 * Event handlers receive a const reference to this structure.
 */
struct StoreEvent {
    StoreEventType type;                                ///< Event type
    std::chrono::system_clock::time_point timestamp;    ///< When event occurred
    
    // For IOC events
    std::optional<IOCEntry> entry;     ///< IOC entry (if applicable)
    std::optional<IOCType> iocType;    ///< IOC type (if applicable)
    
    // For feed events
    std::string feedId;                ///< Feed identifier (if feed event)
    size_t entriesAffected = 0;        ///< Number of entries affected
    
    // Error information
    std::string errorMessage;          ///< Error description (if error event)
    int errorCode = 0;                 ///< Error code (if error event)
    
    /**
     * @brief Check if this is an error event
     */
    [[nodiscard]] bool IsError() const noexcept {
        return type == StoreEventType::Error || 
               type == StoreEventType::FeedUpdateFailed;
    }
    
    /**
     * @brief Check if this is an IOC modification event
     */
    [[nodiscard]] bool IsIOCEvent() const noexcept {
        return type == StoreEventType::IOCAdded ||
               type == StoreEventType::IOCUpdated ||
               type == StoreEventType::IOCRemoved;
    }
};

using StoreEventCallback = std::function<void(const StoreEvent&)>;

// ============================================================================
// ThreatIntelStore Class
// ============================================================================

/**
 * @brief Enterprise-grade Threat Intelligence Store
 *
 * Main facade class providing unified access to all threat intelligence
 * functionality. This class is thread-safe and optimized for high-performance
 * concurrent access.
 *
 * Usage:
 * @code
 * auto store = std::make_unique<ThreatIntelStore>();
 * if (store->Initialize(config)) {
 *     // Add feed
 *     store->AddFeed(FeedConfig::CreateVirusTotal(apiKey));
 *     store->StartFeedUpdates();
 *     
 *     // Lookup hash
 *     auto result = store->LookupHash("SHA256", hashValue);
 *     if (result.IsMalicious()) {
 *         // Handle malicious file
 *     }
 * }
 * @endcode
 */
class ThreatIntelStore final {
public:
    /// @brief Default constructor - creates an uninitialized store
    ThreatIntelStore();
    
    /// @brief Destructor - automatically calls Shutdown() if initialized
    ~ThreatIntelStore();
    
    // Non-copyable, non-movable (owns unique resources)
    ThreatIntelStore(const ThreatIntelStore&) = delete;
    ThreatIntelStore& operator=(const ThreatIntelStore&) = delete;
    ThreatIntelStore(ThreatIntelStore&&) = delete;
    ThreatIntelStore& operator=(ThreatIntelStore&&) = delete;
    
    // =========================================================================
    // Initialization
    // =========================================================================
    
    /**
     * @brief Initialize the store with configuration
     * @param config Store configuration
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(const StoreConfig& config);
    
    /**
     * @brief Initialize with default configuration
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize();
    
    /**
     * @brief Shutdown the store and release resources
     */
    void Shutdown();
    
    /**
     * @brief Check if store is initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    // =========================================================================
    // IOC Lookups
    // =========================================================================
    
    /**
     * @brief Lookup a file hash
     * @param algorithm Hash algorithm ("MD5", "SHA1", "SHA256", "FUZZY", "TLSH")
     * @param hashValue Hash value as hex string
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupHash(
        std::string_view algorithm,
        std::string_view hashValue,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a hash by binary value
     * @param hashHigh High 64 bits of hash
     * @param hashLow Low 64 bits of hash
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupHash(
        uint64_t hashHigh,
        uint64_t hashLow,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup an IPv4 address
     * @param address IPv4 address (e.g., "192.168.1.1" or 0xC0A80101)
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupIPv4(
        std::string_view address,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup an IPv4 address by numeric value
     * @param address IPv4 address as 32-bit integer
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupIPv4(
        uint32_t address,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup an IPv6 address
     * @param address IPv6 address string
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupIPv6(
        std::string_view address,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup an IPv6 address by binary value
     * @param addressHigh High 64 bits
     * @param addressLow Low 64 bits
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupIPv6(
        uint64_t addressHigh,
        uint64_t addressLow,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a domain name
     * @param domain Domain name (e.g., "malware.example.com")
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupDomain(
        std::string_view domain,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a URL
     * @param url Full URL
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupURL(
        std::string_view url,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup an email address
     * @param email Email address
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupEmail(
        std::string_view email,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a JA3/JA3S fingerprint
     * @param fingerprint JA3/JA3S hash
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupJA3(
        std::string_view fingerprint,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a CVE identifier
     * @param cveId CVE ID (e.g., "CVE-2024-1234")
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupCVE(
        std::string_view cveId,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Lookup a generic IOC
     * @param iocType Type of IOC
     * @param value IOC value
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] StoreLookupResult LookupIOC(
        IOCType iocType,
        std::string_view value,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    // =========================================================================
    // Batch Lookups
    // =========================================================================
    
    /**
     * @brief Batch lookup multiple hashes
     * @param algorithm Hash algorithm
     * @param hashes Vector of hash values
     * @param options Lookup options
     * @return Batch lookup result
     */
    [[nodiscard]] StoreBatchLookupResult BatchLookupHashes(
        std::string_view algorithm,
        std::span<const std::string> hashes,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Batch lookup multiple IPv4 addresses
     * @param addresses Vector of IPv4 addresses
     * @param options Lookup options
     * @return Batch lookup result
     */
    [[nodiscard]] StoreBatchLookupResult BatchLookupIPv4(
        std::span<const std::string> addresses,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Batch lookup multiple domains
     * @param domains Vector of domain names
     * @param options Lookup options
     * @return Batch lookup result
     */
    [[nodiscard]] StoreBatchLookupResult BatchLookupDomains(
        std::span<const std::string> domains,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    /**
     * @brief Batch lookup multiple IOCs of mixed types
     * @param iocs Vector of (type, value) pairs
     * @param options Lookup options
     * @return Batch lookup result
     */
    [[nodiscard]] StoreBatchLookupResult BatchLookupIOCs(
        std::span<const std::pair<IOCType, std::string>> iocs,
        const StoreLookupOptions& options = StoreLookupOptions{}) noexcept;
    
    // =========================================================================
    // IOC Management
    // =========================================================================
    
    /**
     * @brief Add a new IOC entry
     * @param entry IOC entry to add
     * @return true if added successfully
     */
    [[nodiscard]] bool AddIOC(const IOCEntry& entry) noexcept;
    
    /**
     * @brief Add a new IOC with minimal parameters
     * @param type IOC type
     * @param value IOC value
     * @param reputation Reputation level
     * @param source Source of intelligence
     * @return true if added successfully
     */
    [[nodiscard]] bool AddIOC(
        IOCType type,
        std::string_view value,
        ReputationLevel reputation,
        ThreatIntelSource source = ThreatIntelSource::InternalAnalysis) noexcept;
    
    /**
     * @brief Update an existing IOC entry
     * @param entry Updated IOC entry
     * @return true if updated successfully
     */
    [[nodiscard]] bool UpdateIOC(const IOCEntry& entry) noexcept;
    
    /**
     * @brief Remove an IOC entry
     * @param type IOC type
     * @param value IOC value
     * @return true if removed successfully
     */
    [[nodiscard]] bool RemoveIOC(IOCType type, std::string_view value) noexcept;
    
    /**
     * @brief Bulk add IOC entries
     * @param entries Vector of IOC entries
     * @return Number of entries successfully added
     */
    [[nodiscard]] size_t BulkAddIOCs(std::span<const IOCEntry> entries) noexcept;
    
    /**
     * @brief Result of bulk IOC add operation with statistics
     * 
     * Provides accurate count of new, updated, skipped, and error entries
     * without using heuristics.
     */
    struct BulkAddStatsResult {
        size_t totalProcessed = 0;      ///< Total entries processed
        size_t newEntries = 0;          ///< New unique entries added
        size_t updatedEntries = 0;      ///< Existing entries updated
        size_t skippedEntries = 0;      ///< Entries skipped (filtered/invalid)
        size_t errorCount = 0;          ///< Entries that failed to add
        
        /// @brief Total successful (new + updated)
        [[nodiscard]] size_t GetSuccessCount() const noexcept {
            return newEntries + updatedEntries;
        }
    };
    
    /**
     * @brief Bulk add IOC entries with detailed statistics
     * @param entries Span of IOC entries to add
     * @return BulkAddStatsResult with accurate counts
     * 
     * Unlike BulkAddIOCs, this method tracks exactly which entries were
     * newly added vs updated vs skipped, enabling accurate sync reporting.
     * 
     * @note Thread-safe with internal locking
     */
    [[nodiscard]] BulkAddStatsResult BulkAddIOCsWithStats(std::span<const IOCEntry> entries) noexcept;
    
    /**
     * @brief Check if an IOC exists
     * @param type IOC type
     * @param value IOC value
     * @return true if IOC exists
     */
    [[nodiscard]] bool HasIOC(IOCType type, std::string_view value) const noexcept;
    
    // =========================================================================
    // Feed Management
    // =========================================================================
    
    /**
     * @brief Add a threat intelligence feed
     * @param config Feed configuration
     * @return true if feed added successfully
     */
    [[nodiscard]] bool AddFeed(const FeedConfig& config) noexcept;

    /**
     * @brief Converts high-level FeedConfiguration into the internal structure expected by FeedManager.
     * Type-safe mapping for FeedManager
     */
	[[nodiscard]] bool AddFeed(const FeedConfiguration& config) noexcept;
    
    /**
     * @brief Remove a feed
     * @param feedId Feed identifier
     * @return true if removed
     */
    [[nodiscard]] bool RemoveFeed(const std::string& feedId) noexcept;
    
    /**
     * @brief Enable a feed
     * @param feedId Feed identifier
     * @return true if enabled
     */
    [[nodiscard]] bool EnableFeed(const std::string& feedId) noexcept;
    
    /**
     * @brief Disable a feed
     * @param feedId Feed identifier
     * @return true if disabled
     */
    [[nodiscard]] bool DisableFeed(const std::string& feedId) noexcept;
    
    /**
     * @brief Update a specific feed immediately
     * @param feedId Feed identifier
     * @return true if update started
     */
    [[nodiscard]] bool UpdateFeed(const std::string& feedId) noexcept;
    
    /**
     * @brief Update all enabled feeds
     * @return Number of feeds updated
     */
    [[nodiscard]] size_t UpdateAllFeeds() noexcept;
    
    /**
     * @brief Get feed status
     * @param feedId Feed identifier
     * @return Feed status if found
     */
    [[nodiscard]] std::optional<FeedStatus> GetFeedStatus(const std::string& feedId) const noexcept;
    
    /**
     * @brief Get all feed statuses
     * @return Vector of feed statuses
     */
    [[nodiscard]] std::vector<FeedStatus> GetAllFeedStatuses() const noexcept;
    
    /**
     * @brief Start automatic feed update background thread
     */
    void StartFeedUpdates() noexcept;
    
    /**
     * @brief Stop automatic feed updates
     */
    void StopFeedUpdates() noexcept;
    
    // =========================================================================
    // Import/Export
    // =========================================================================
    
    /**
     * @brief Import threat intelligence from a STIX 2.1 file
     * @param filePath Path to STIX JSON file
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportSTIX(
        const std::wstring& filePath,
        const ImportOptions& options = ImportOptions{}) noexcept;
    
    /**
     * @brief Import threat intelligence from a CSV file
     * @param filePath Path to CSV file
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportCSV(
        const std::wstring& filePath,
        const ImportOptions& options = ImportOptions{}) noexcept;
    
    /**
     * @brief Import threat intelligence from a JSON file
     * @param filePath Path to JSON file
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportJSON(
        const std::wstring& filePath,
        const ImportOptions& options = ImportOptions{}) noexcept;
    
    /**
     * @brief Import threat intelligence from a plain text file
     * @param filePath Path to text file (one IOC per line)
     * @param iocType Type of IOCs in file
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportPlainText(
        const std::wstring& filePath,
        IOCType iocType,
        const ImportOptions& options = ImportOptions{}) noexcept;
    
    /**
     * @brief Export threat intelligence to a file
     * @param filePath Output file path
     * @param options Export options
     * @return Export result
     */
    [[nodiscard]] ExportResult Export(
        const std::wstring& filePath,
        const ExportOptions& options = ExportOptions{}) noexcept;
    
    // =========================================================================
    // Maintenance Operations
    // =========================================================================
    
    /**
     * @brief Compact the database to reclaim space
     * @return Number of bytes reclaimed
     */
    [[nodiscard]] size_t Compact() noexcept;
    
    /**
     * @brief Verify database integrity
     * @return true if integrity check passed
     */
    [[nodiscard]] bool VerifyIntegrity() const noexcept;
    
    /**
     * @brief Rebuild database indexes
     * @return true if rebuild succeeded
     */
    [[nodiscard]] bool RebuildIndexes() noexcept;
    
    /**
     * @brief Flush all pending writes to disk
     */
    void Flush() noexcept;
    
    /**
     * @brief Evict expired entries from cache
     * @return Number of entries evicted
     */
    [[nodiscard]] size_t EvictExpiredEntries() noexcept;
    
    /**
     * @brief Remove entries older than specified age
     * @param maxAge Maximum age of entries to keep
     * @return Number of entries removed
     */
    [[nodiscard]] size_t PurgeOldEntries(std::chrono::hours maxAge) noexcept;
    
    // =========================================================================
    // Statistics and Monitoring
    // =========================================================================
    
    /**
     * @brief Get comprehensive statistics
     */
    [[nodiscard]] StoreStatistics GetStatistics() const noexcept;
    
    /**
     * @brief Get cache statistics
     */
    [[nodiscard]] CacheStatistics GetCacheStatistics() const noexcept;
    
    /**
     * @brief Reset performance counters
     */
    void ResetStatistics() noexcept;
    
    // =========================================================================
    // Event Handling
    // =========================================================================
    
    /**
     * @brief Register an event callback
     * @param callback Callback function
     * @return Callback ID for unregistering
     */
    [[nodiscard]] size_t RegisterEventCallback(StoreEventCallback callback) noexcept;
    
    /**
     * @brief Unregister an event callback
     * @param callbackId Callback ID returned from RegisterEventCallback
     */
    void UnregisterEventCallback(size_t callbackId) noexcept;
    
private:
    // Internal implementation using Pimpl pattern for ABI stability
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Atomic initialization flag
    std::atomic<bool> m_isInitialized{false};
};

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * @brief Create a threat intelligence store with default configuration
 */
[[nodiscard]] std::unique_ptr<ThreatIntelStore> CreateThreatIntelStore();

/**
 * @brief Create a threat intelligence store with specified configuration
 */
[[nodiscard]] std::unique_ptr<ThreatIntelStore> CreateThreatIntelStore(const StoreConfig& config);

/**
 * @brief Create a high-performance threat intelligence store
 */
[[nodiscard]] std::unique_ptr<ThreatIntelStore> CreateHighPerformanceThreatIntelStore();

/**
 * @brief Create a low-memory threat intelligence store
 */
[[nodiscard]] std::unique_ptr<ThreatIntelStore> CreateLowMemoryThreatIntelStore();

} // namespace ThreatIntel
} // namespace ShadowStrike
