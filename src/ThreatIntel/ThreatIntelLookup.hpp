/*
 * ============================================================================
 * ShadowStrike ThreatIntelLookup - UNIFIED LOOKUP INTERFACE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade unified lookup interface for all threat intelligence queries.
 * This is the primary entry point for real-time threat detection and analysis.
 * Integrates all ThreatIntel subsystems into a single, optimized API.
 *
 * Key Features:
 * - Unified API for all IOC types (IP, domain, hash, URL, etc.)
 * - Multi-tier lookup strategy: Cache → Index → Database → External APIs
 * - Sub-microsecond lookups for cached entries
 * - Automatic cache warming and prefetching
 * - Batch operations with SIMD optimization
 * - Contextual enrichment with MITRE ATT&CK, CVE data
 * - Real-time reputation scoring with confidence levels
 * - Automatic fallback to external threat feeds on cache miss
 * - Query result aggregation from multiple sources
 * - Performance monitoring and adaptive optimization
 *
 * Performance Targets (CrowdStrike Falcon / Microsoft Defender ATP quality):
 * - Cache hit: < 50ns average
 * - Index hit: < 100ns average
 * - Database hit: < 500ns average
 * - External API call: < 50ms average (async)
 * - Batch lookup (1000 items): < 50µs for cached, < 1ms for indexed
 * - Memory overhead: < 100MB for 10M IOCs
 * - Throughput: > 1M lookups/second on modern CPU
 *
 * Thread Safety:
 * - Lock-free reads for cache and index lookups
 * - Read-write lock for database updates
 * - Atomic statistics with memory_order_relaxed
 * - Thread-local caching for hot paths
 *
 * Lookup Strategy:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ 1. Thread-Local Cache (< 20ns)                                     │
 * │    └─> Hot entries, per-thread LRU                                 │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ 2. Shared Memory Cache (< 50ns)                                    │
 * │    └─> ReputationCache with SeqLock, Bloom filter                  │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ 3. Index Lookup (< 100ns)                                          │
 * │    └─> ThreatIntelIndex with specialized data structures           │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ 4. Database Query (< 500ns)                                        │
 * │    └─> Memory-mapped database with zero-copy reads                 │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ 5. External API Query (< 50ms, async)                              │
 * │    └─> VirusTotal, AbuseIPDB, etc. with result caching             │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * - Scanner Engine: Real-time file/network scanning
 * - Behavioral Detection: Process/network behavior analysis
 * - Firewall: Network traffic filtering
 * - Email Gateway: Email security scanning
 * - Web Protection: URL filtering and safe browsing
 *
 * This module is designed for billion-dollar enterprise deployments.
 * Every operation is optimized for maximum performance and reliability.
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include "ThreatIntelIndex.hpp"
#include "ThreatIntelStore.hpp"
#include "ThreatIntelDatabase.hpp"
#include "ThreatIntelIOCManager.hpp"
#include "ReputationCache.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ThreatIntelLookup;
class LookupEngine;
class QueryOptimizer;
class ResultAggregator;
class ExternalAPIClient;

// ============================================================================
// LOOKUP CONFIGURATION
// ============================================================================

/**
 * @brief Configuration for ThreatIntelLookup
 */
struct LookupConfig {
    /// @brief Enable multi-tier lookup strategy
    bool enableMultiTier{true};
    
    /// @brief Enable thread-local caching
    bool enableThreadLocalCache{true};
    
    /// @brief Thread-local cache size per thread
    size_t threadLocalCacheSize{1024};
    
    /// @brief Enable automatic cache warming
    bool enableCacheWarming{true};
    
    /// @brief Enable prefetching for batch operations
    bool enablePrefetching{true};
    
    /// @brief Enable SIMD optimization for batch lookups
    bool enableSIMD{true};
    
    /// @brief Enable external API fallback
    bool enableExternalAPI{false};
    
    /// @brief External API timeout in milliseconds
    uint32_t externalAPITimeout{5000};
    
    /// @brief Maximum concurrent external API requests
    uint32_t maxConcurrentAPIRequests{10};
    
    /// @brief Enable contextual enrichment (MITRE, CVE, etc.)
    bool enableEnrichment{true};
    
    /// @brief Enable query result caching
    bool enableResultCache{true};
    
    /// @brief Result cache TTL in seconds
    uint32_t resultCacheTTL{300};
    
    /// @brief Enable adaptive optimization
    bool enableAdaptiveOptimization{true};
    
    /// @brief Performance monitoring interval in seconds
    uint32_t monitoringInterval{60};
    
    /// @brief Enable query logging for analytics
    bool enableQueryLogging{false};
    
    /// @brief Query log retention in hours
    uint32_t queryLogRetention{24};
    
    /**
     * @brief Create default configuration
     */
    [[nodiscard]] static LookupConfig CreateDefault() noexcept {
        return LookupConfig{};
    }
    
    /**
     * @brief Create high-performance configuration
     */
    [[nodiscard]] static LookupConfig CreateHighPerformance() noexcept {
        LookupConfig config;
        config.enableThreadLocalCache = true;
        config.threadLocalCacheSize = 4096;
        config.enableCacheWarming = true;
        config.enablePrefetching = true;
        config.enableSIMD = true;
        config.enableAdaptiveOptimization = true;
        return config;
    }
    
    /**
     * @brief Create low-latency configuration
     */
    [[nodiscard]] static LookupConfig CreateLowLatency() noexcept {
        LookupConfig config;
        config.enableMultiTier = false;  // Cache only
        config.enableThreadLocalCache = true;
        config.threadLocalCacheSize = 8192;
        config.enableExternalAPI = false;
        config.enableEnrichment = false;
        return config;
    }
};

// ============================================================================
// LOOKUP OPTIONS
// ============================================================================

/**
 * @brief Options for individual lookup operations via ThreatIntelLookup
 * 
 * @note This is the options struct for the unified lookup interface.
 * Distinguished from StoreLookupOptions in ThreatIntelStore.hpp.
 */
struct UnifiedLookupOptions {
    /// @brief Maximum lookup tiers to try (1=cache only, 5=all including external)
    uint8_t maxLookupTiers{4};
    
    /// @brief Minimum confidence threshold (0-100)
    uint8_t minConfidence{0};
    
    /// @brief Cache result after lookup
    bool cacheResult{true};
    
    /// @brief Include metadata in result
    bool includeMetadata{true};
    
    /// @brief Include source attribution
    bool includeSourceAttribution{true};
    
    /// @brief Include related IOCs
    bool includeRelatedIOCs{false};
    
    /// @brief Include MITRE ATT&CK mapping
    bool includeMitreMapping{false};
    
    /// @brief Include CVE references
    bool includeCVEReferences{false};
    
    /// @brief Include STIX bundle
    bool includeSTIXBundle{false};
    
    /// @brief Query external APIs on cache miss
    bool queryExternalAPI{false};
    
    /// @brief Validate input IOC format before lookup (enterprise security feature)
    bool validateInput{true};
    
    /// @brief Timeout for this specific query (milliseconds, 0=use default)
    uint32_t timeoutMs{0};
    
    /// @brief Reputation filter (empty = no filter)
    std::vector<ReputationLevel> reputationFilter;
    
    /// @brief Source filter (empty = no filter)
    std::vector<ThreatIntelSource> sourceFilter;
    
    /**
     * @brief Create options for fastest lookup
     */
    [[nodiscard]] static UnifiedLookupOptions FastestLookup() noexcept {
        UnifiedLookupOptions opts;
        opts.maxLookupTiers = 2;  // Cache + Index only
        opts.cacheResult = true;
        opts.includeMetadata = false;
        opts.includeSourceAttribution = false;
        opts.includeRelatedIOCs = false;
        opts.includeMitreMapping = false;
        opts.includeCVEReferences = false;
        opts.includeSTIXBundle = false;
        opts.queryExternalAPI = false;
        return opts;
    }
    
    /**
     * @brief Create options for detailed lookup
     */
    [[nodiscard]] static UnifiedLookupOptions DetailedLookup() noexcept {
        UnifiedLookupOptions opts;
        opts.maxLookupTiers = 5;  // All tiers including external
        opts.includeMetadata = true;
        opts.includeSourceAttribution = true;
        opts.includeRelatedIOCs = true;
        opts.includeMitreMapping = true;
        opts.includeCVEReferences = true;
        opts.includeSTIXBundle = false;
        opts.queryExternalAPI = false;  // Don't auto-query external by default
        return opts;
    }
    
    /**
     * @brief Create options for malware analysis
     */
    [[nodiscard]] static UnifiedLookupOptions MalwareAnalysis() noexcept {
        UnifiedLookupOptions opts;
        opts.maxLookupTiers = 5;
        opts.includeMetadata = true;
        opts.includeSourceAttribution = true;
        opts.includeRelatedIOCs = true;
        opts.includeMitreMapping = true;
        opts.includeCVEReferences = true;
        opts.includeSTIXBundle = true;
        opts.queryExternalAPI = true;
        opts.timeoutMs = 30000;  // 30 seconds for thorough analysis
        return opts;
    }
};

// ============================================================================
// LOOKUP RESULT
// ============================================================================

/**
 * @brief Result of a threat intelligence lookup
 */
struct ThreatLookupResult {
    /// @brief Whether IOC was found
    bool found{false};
    
    /// @brief Which tier provided the result
    enum class Source : uint8_t {
        None = 0,
        ThreadLocalCache = 1,
        SharedCache = 2,
        Index = 3,
        Database = 4,
        ExternalAPI = 5
    } source{Source::None};
    
    /// @brief Lookup latency in nanoseconds
    uint64_t latencyNs{0};
    
    /// @brief Error code (0 = no error, non-zero = error occurred)
    uint32_t errorCode{0};
    
    /// @brief Error message (empty if no error)
    std::string errorMessage;
    
    /// @brief IOC type
    IOCType type{IOCType::Reserved};
    
    /// @brief Reputation information
    ReputationLevel reputation{ReputationLevel::Unknown};
    ConfidenceLevel confidence{ConfidenceLevel::None};
    ThreatCategory category{ThreatCategory::Unknown};
    
    /// @brief Threat score (0-100, higher = more dangerous)
    uint8_t threatScore{0};
    
    /// @brief Primary threat intelligence source
    ThreatIntelSource primarySource{ThreatIntelSource::Unknown};
    
    /// @brief Bitmask of all sources that confirmed this IOC
    uint32_t sourceFlags{0};
    
    /// @brief Number of sources confirming this threat
    uint16_t sourceCount{0};
    
    /// @brief First and last seen timestamps (Unix epoch)
    uint64_t firstSeen{0};
    uint64_t lastSeen{0};
    
    /// @brief Expiration timestamp (0 = never expires)
    uint64_t expiresAt{0};
    
    /// @brief Full IOC entry (if includeMetadata was true)
    std::optional<IOCEntry> entry;
    
    /// @brief Description of the threat
    std::string description;
    
    /// @brief Tags associated with this IOC
    std::vector<std::string> tags;
    
    /// @brief Related IOCs (if requested)
    struct RelatedIOC {
        IOCType type;
        std::string value;
        std::string relationship;  // "related", "derived_from", "targets", etc.
    };
    std::vector<RelatedIOC> relatedIOCs;
    
    /// @brief MITRE ATT&CK techniques (if requested)
    std::vector<std::string> mitreTechniques;
    
    /// @brief CVE references (if requested)
    std::vector<std::string> cveReferences;
    
    /// @brief STIX bundle ID (if available)
    std::optional<std::string> stixBundleId;
    
    /// @brief External API results (if queried)
    struct ExternalResult {
        ThreatIntelSource source;
        ReputationLevel reputation;
        ConfidenceLevel confidence;
        uint8_t score;
        std::string details;
        uint64_t queryLatencyMs;
    };
    std::vector<ExternalResult> externalResults;
    
    /**
     * @brief Check if IOC is malicious
     */
    [[nodiscard]] bool IsMalicious() const noexcept {
        return found && (reputation == ReputationLevel::Malicious || 
                        reputation == ReputationLevel::Critical ||
                        threatScore >= 70);
    }
    
    /**
     * @brief Check if IOC is suspicious
     */
    [[nodiscard]] bool IsSuspicious() const noexcept {
        return found && (reputation == ReputationLevel::Suspicious ||
                        reputation == ReputationLevel::HighRisk ||
                        (threatScore >= 40 && threatScore < 70));
    }
    
    /**
     * @brief Check if IOC is safe
     */
    [[nodiscard]] bool IsSafe() const noexcept {
        return found && (reputation == ReputationLevel::Safe ||
                        reputation == ReputationLevel::Trusted ||
                        threatScore < 20);
    }
    
    /**
     * @brief Check if result should trigger alert
     */
    [[nodiscard]] bool ShouldAlert() const noexcept {
        return IsMalicious() || (IsSuspicious() && confidence >= ConfidenceLevel::Medium);
    }
    
    /**
     * @brief Check if result should block
     */
    [[nodiscard]] bool ShouldBlock() const noexcept {
        return IsMalicious() && confidence >= ConfidenceLevel::High;
    }
    
    /**
     * @brief Get string representation of source
     */
    [[nodiscard]] const char* GetSourceString() const noexcept {
        switch (source) {
            case Source::ThreadLocalCache: return "ThreadLocalCache";
            case Source::SharedCache:      return "SharedCache";
            case Source::Index:            return "Index";
            case Source::Database:         return "Database";
            case Source::ExternalAPI:      return "ExternalAPI";
            default:                       return "None";
        }
    }
};

// ============================================================================
// BATCH LOOKUP RESULT
// ============================================================================

/**
 * @brief Result of a batch lookup operation
 */
struct BatchLookupResult {
    /// @brief Total items processed
    size_t totalProcessed{0};
    
    /// @brief Items found
    size_t foundCount{0};
    
    /// @brief Items not found
    size_t notFoundCount{0};
    
    /// @brief Tier breakdown
    size_t threadLocalCacheHits{0};
    size_t sharedCacheHits{0};
    size_t indexHits{0};
    size_t databaseHits{0};
    size_t externalAPIHits{0};
    
    /// @brief Threat level breakdown
    size_t maliciousCount{0};
    size_t suspiciousCount{0};
    size_t safeCount{0};
    size_t unknownCount{0};
    
    /// @brief Timing statistics (nanoseconds)
    uint64_t totalLatencyNs{0};
    uint64_t minLatencyNs{UINT64_MAX};
    uint64_t maxLatencyNs{0};
    uint64_t avgLatencyNs{0};
    
    /// @brief Individual results (index matches input)
    std::vector<ThreatLookupResult> results;
    
    /**
     * @brief Calculate cache hit rate
     */
    [[nodiscard]] double CacheHitRate() const noexcept {
        if (totalProcessed == 0) return 0.0;
        const size_t cacheHits = threadLocalCacheHits + sharedCacheHits;
        return static_cast<double>(cacheHits) / totalProcessed * 100.0;
    }
    
    /**
     * @brief Calculate threat detection rate
     */
    [[nodiscard]] double ThreatDetectionRate() const noexcept {
        if (foundCount == 0) return 0.0;
        return static_cast<double>(maliciousCount + suspiciousCount) / foundCount * 100.0;
    }
};

// ============================================================================
// LOOKUP STATISTICS
// ============================================================================

/**
 * @brief Comprehensive statistics for lookup operations
 */
struct LookupStatistics {
    /// @brief Total lookups performed
    std::atomic<uint64_t> totalLookups{0};
    
    /// @brief Successful lookups
    std::atomic<uint64_t> successfulLookups{0};
    
    /// @brief Failed lookups
    std::atomic<uint64_t> failedLookups{0};
    
    /// @brief Tier hit counters
    std::atomic<uint64_t> threadLocalCacheHits{0};
    std::atomic<uint64_t> sharedCacheHits{0};
    std::atomic<uint64_t> indexHits{0};
    std::atomic<uint64_t> databaseHits{0};
    std::atomic<uint64_t> externalAPIHits{0};
    
    /// @brief Timing statistics (nanoseconds)
    std::atomic<uint64_t> totalLatencyNs{0};
    std::atomic<uint64_t> minLatencyNs{UINT64_MAX};
    std::atomic<uint64_t> maxLatencyNs{0};
    
    /// @brief Threat detection counters
    std::atomic<uint64_t> maliciousDetections{0};
    std::atomic<uint64_t> suspiciousDetections{0};
    std::atomic<uint64_t> safeResults{0};
    
    /// @brief Per-IOC-type counters
    std::array<std::atomic<uint64_t>, 32> lookupsByType{};
    
    /// @brief Batch operation counters
    std::atomic<uint64_t> batchOperations{0};
    std::atomic<uint64_t> totalBatchItems{0};
    
    /// @brief External API statistics
    std::atomic<uint64_t> externalAPIRequests{0};
    std::atomic<uint64_t> externalAPIErrors{0};
    std::atomic<uint64_t> externalAPITimeouts{0};
    
    /// @brief Cache management statistics
    std::atomic<uint64_t> bloomFilterRejects{0};    ///< Bloom filter definite negatives
    std::atomic<uint64_t> cacheInsertions{0};       ///< Cache entry insertions
    std::atomic<uint64_t> cacheEvictions{0};        ///< Cache entry evictions
    std::atomic<uint64_t> cacheExpirations{0};      ///< Expired entry evictions
    
    /// @brief Last reset timestamp
    std::atomic<uint64_t> lastResetTime{0};
    
    // Default constructor
    LookupStatistics() = default;
    
    // Copy constructor for atomic members
    LookupStatistics(const LookupStatistics& other) noexcept
        : totalLookups(other.totalLookups.load(std::memory_order_relaxed))
        , successfulLookups(other.successfulLookups.load(std::memory_order_relaxed))
        , failedLookups(other.failedLookups.load(std::memory_order_relaxed))
        , threadLocalCacheHits(other.threadLocalCacheHits.load(std::memory_order_relaxed))
        , sharedCacheHits(other.sharedCacheHits.load(std::memory_order_relaxed))
        , indexHits(other.indexHits.load(std::memory_order_relaxed))
        , databaseHits(other.databaseHits.load(std::memory_order_relaxed))
        , externalAPIHits(other.externalAPIHits.load(std::memory_order_relaxed))
        , totalLatencyNs(other.totalLatencyNs.load(std::memory_order_relaxed))
        , minLatencyNs(other.minLatencyNs.load(std::memory_order_relaxed))
        , maxLatencyNs(other.maxLatencyNs.load(std::memory_order_relaxed))
        , maliciousDetections(other.maliciousDetections.load(std::memory_order_relaxed))
        , suspiciousDetections(other.suspiciousDetections.load(std::memory_order_relaxed))
        , safeResults(other.safeResults.load(std::memory_order_relaxed))
        , batchOperations(other.batchOperations.load(std::memory_order_relaxed))
        , totalBatchItems(other.totalBatchItems.load(std::memory_order_relaxed))
        , externalAPIRequests(other.externalAPIRequests.load(std::memory_order_relaxed))
        , externalAPIErrors(other.externalAPIErrors.load(std::memory_order_relaxed))
        , externalAPITimeouts(other.externalAPITimeouts.load(std::memory_order_relaxed))
        , bloomFilterRejects(other.bloomFilterRejects.load(std::memory_order_relaxed))
        , cacheInsertions(other.cacheInsertions.load(std::memory_order_relaxed))
        , cacheEvictions(other.cacheEvictions.load(std::memory_order_relaxed))
        , cacheExpirations(other.cacheExpirations.load(std::memory_order_relaxed))
        , lastResetTime(other.lastResetTime.load(std::memory_order_relaxed))
    {
        for (size_t i = 0; i < lookupsByType.size(); ++i) {
            lookupsByType[i].store(other.lookupsByType[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
    }
    
    /**
     * @brief Calculate average lookup latency
     */
    [[nodiscard]] uint64_t GetAverageLatencyNs() const noexcept {
        const uint64_t total = totalLookups.load(std::memory_order_relaxed);
        if (total == 0) return 0;
        return totalLatencyNs.load(std::memory_order_relaxed) / total;
    }
    
    /**
     * @brief Calculate overall cache hit rate
     */
    [[nodiscard]] double GetCacheHitRate() const noexcept {
        const uint64_t total = totalLookups.load(std::memory_order_relaxed);
        if (total == 0) return 0.0;
        const uint64_t cacheHits = threadLocalCacheHits.load(std::memory_order_relaxed) +
                                   sharedCacheHits.load(std::memory_order_relaxed);
        return static_cast<double>(cacheHits) / total * 100.0;
    }
    
    /**
     * @brief Calculate threat detection rate
     */
    [[nodiscard]] double GetThreatDetectionRate() const noexcept {
        const uint64_t found = successfulLookups.load(std::memory_order_relaxed);
        if (found == 0) return 0.0;
        const uint64_t threats = maliciousDetections.load(std::memory_order_relaxed) +
                                 suspiciousDetections.load(std::memory_order_relaxed);
        return static_cast<double>(threats) / found * 100.0;
    }
    
    /**
     * @brief Reset all statistics
     */
    void Reset() noexcept {
        totalLookups.store(0, std::memory_order_relaxed);
        successfulLookups.store(0, std::memory_order_relaxed);
        failedLookups.store(0, std::memory_order_relaxed);
        threadLocalCacheHits.store(0, std::memory_order_relaxed);
        sharedCacheHits.store(0, std::memory_order_relaxed);
        indexHits.store(0, std::memory_order_relaxed);
        databaseHits.store(0, std::memory_order_relaxed);
        externalAPIHits.store(0, std::memory_order_relaxed);
        totalLatencyNs.store(0, std::memory_order_relaxed);
        minLatencyNs.store(UINT64_MAX, std::memory_order_relaxed);
        maxLatencyNs.store(0, std::memory_order_relaxed);
        maliciousDetections.store(0, std::memory_order_relaxed);
        suspiciousDetections.store(0, std::memory_order_relaxed);
        safeResults.store(0, std::memory_order_relaxed);
        batchOperations.store(0, std::memory_order_relaxed);
        totalBatchItems.store(0, std::memory_order_relaxed);
        externalAPIRequests.store(0, std::memory_order_relaxed);
        externalAPIErrors.store(0, std::memory_order_relaxed);
        externalAPITimeouts.store(0, std::memory_order_relaxed);
        bloomFilterRejects.store(0, std::memory_order_relaxed);
        cacheInsertions.store(0, std::memory_order_relaxed);
        cacheEvictions.store(0, std::memory_order_relaxed);
        cacheExpirations.store(0, std::memory_order_relaxed);
        
        for (auto& counter : lookupsByType) {
            counter.store(0, std::memory_order_relaxed);
        }
        
        lastResetTime.store(
            static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count()),
            std::memory_order_relaxed
        );
    }
};

// ============================================================================
// THREATINTELLOOKUP CLASS
// ============================================================================

/**
 * @brief Unified threat intelligence lookup interface
 * 
 * Main facade for all threat intelligence queries. Provides optimized
 * multi-tier lookup strategy with automatic fallback and caching.
 * 
 * Thread-safe for concurrent operations. Lock-free for read-heavy workloads.
 * 
 * Usage:
 * @code
 * auto lookup = std::make_unique<ThreatIntelLookup>();
 * if (lookup->Initialize(config, store, index, iocManager, cache)) {
 *     // Single lookup
 *     auto result = lookup->LookupIPv4("192.168.1.100");
 *     if (result.IsMalicious()) {
 *         // Handle threat
 *     }
 *     
 *     // Batch lookup
 *     std::vector<std::string> hashes = {...};
 *     auto batchResult = lookup->BatchLookupHashes(hashes);
 * }
 * @endcode
 */
class ThreatIntelLookup {
public:
    ThreatIntelLookup();
    ~ThreatIntelLookup();
    
    // Non-copyable, non-movable
    ThreatIntelLookup(const ThreatIntelLookup&) = delete;
    ThreatIntelLookup& operator=(const ThreatIntelLookup&) = delete;
    ThreatIntelLookup(ThreatIntelLookup&&) = delete;
    ThreatIntelLookup& operator=(ThreatIntelLookup&&) = delete;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /**
     * @brief Initialize lookup system with all subsystems
     * @param config Lookup configuration
     * @param store Threat intel store instance
     * @param index Index instance
     * @param iocManager IOC manager instance
     * @param cache Reputation cache instance
     * @return Success or error code
     */
    [[nodiscard]] bool Initialize(
        const LookupConfig& config,
        ThreatIntelStore* store,
        ThreatIntelIndex* index,
        ThreatIntelIOCManager* iocManager,
        ReputationCache* cache
    ) noexcept;
    
    /**
     * @brief Check if lookup system is initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Shutdown and release resources
     */
    void Shutdown() noexcept;
    
    // ========================================================================
    // IPv4 LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup IPv4 address
     * @param ipv4 IPv4 address string (e.g., "192.168.1.1")
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupIPv4(
        std::string_view ipv4,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup IPv4 address (binary format)
     */
    [[nodiscard]] ThreatLookupResult LookupIPv4(
        const IPv4Address& addr,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup IPv4 address (uint32_t network byte order)
     */
    [[nodiscard]] ThreatLookupResult LookupIPv4(
        uint32_t ipv4,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // IPv6 LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup IPv6 address
     * @param ipv6 IPv6 address string
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupIPv6(
        std::string_view ipv6,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup IPv6 address (binary format)
     */
    [[nodiscard]] ThreatLookupResult LookupIPv6(
        const IPv6Address& addr,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // DOMAIN LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup domain name
     * @param domain Domain name (e.g., "example.com")
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupDomain(
        std::string_view domain,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // URL LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup URL
     * @param url Full URL or URL pattern
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupURL(
        std::string_view url,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // HASH LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup file hash (auto-detect algorithm)
     * @param hash Hash string (hex)
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupHash(
        std::string_view hash,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup MD5 hash
     */
    [[nodiscard]] ThreatLookupResult LookupMD5(
        std::string_view md5,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup SHA1 hash
     */
    [[nodiscard]] ThreatLookupResult LookupSHA1(
        std::string_view sha1,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup SHA256 hash
     */
    [[nodiscard]] ThreatLookupResult LookupSHA256(
        std::string_view sha256,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Lookup with HashValue structure
     */
    [[nodiscard]] ThreatLookupResult LookupHash(
        const HashValue& hashValue,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // EMAIL LOOKUPS
    // ========================================================================
    
    /**
     * @brief Lookup email address
     * @param email Email address
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult LookupEmail(
        std::string_view email,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // GENERIC LOOKUPS
    // ========================================================================
    
    /**
     * @brief Generic lookup by IOC type and value
     * @param type IOC type
     * @param value IOC value
     * @param options Lookup options
     * @return Lookup result
     */
    [[nodiscard]] ThreatLookupResult Lookup(
        IOCType type,
        std::string_view value,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // BATCH LOOKUPS
    // ========================================================================
    
    /**
     * @brief Batch lookup IPv4 addresses
     * @param addresses IPv4 address strings
     * @param options Lookup options
     * @return Batch lookup result
     */
    [[nodiscard]] BatchLookupResult BatchLookupIPv4(
        std::span<const std::string_view> addresses,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Batch lookup domains
     */
    [[nodiscard]] BatchLookupResult BatchLookupDomains(
        std::span<const std::string_view> domains,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Batch lookup hashes
     */
    [[nodiscard]] BatchLookupResult BatchLookupHashes(
        std::span<const std::string_view> hashes,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Batch lookup URLs
     */
    [[nodiscard]] BatchLookupResult BatchLookupURLs(
        std::span<const std::string_view> urls,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    /**
     * @brief Generic batch lookup
     */
    [[nodiscard]] BatchLookupResult BatchLookup(
        IOCType type,
        std::span<const std::string_view> values,
        const UnifiedLookupOptions& options = UnifiedLookupOptions::FastestLookup()
    ) noexcept;
    
    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Warm cache with commonly accessed IOCs
     * @param count Number of entries to pre-load
     * @return Number of entries cached
     */
    [[nodiscard]] size_t WarmCache(size_t count = 10000) noexcept;
    
    /**
     * @brief Invalidate cache entry
     */
    void InvalidateCacheEntry(IOCType type, std::string_view value) noexcept;
    
    /**
     * @brief Clear all caches
     */
    void ClearAllCaches() noexcept;
    
    /**
     * @brief Get cache statistics
     */
    [[nodiscard]] CacheStatistics GetCacheStatistics() const noexcept;
    
    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================
    
    /**
     * @brief Get comprehensive lookup statistics
     */
    [[nodiscard]] LookupStatistics GetStatistics() const noexcept;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics() noexcept;
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] const LookupConfig& GetConfiguration() const noexcept;
    
    /**
     * @brief Update configuration at runtime
     */
    void UpdateConfiguration(const LookupConfig& config) noexcept;
    
    /**
     * @brief Get memory usage in bytes
     */
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    
    /**
     * @brief Get current throughput (lookups/second)
     */
    [[nodiscard]] double GetThroughput() const noexcept;
    
private:
    // Pimpl idiom for ABI stability
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ThreatIntel
} // namespace ShadowStrike
