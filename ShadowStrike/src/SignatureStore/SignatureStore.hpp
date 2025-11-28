/*
 * ============================================================================
 * ShadowStrike SignatureStore - UNIFIED SIGNATURE DATABASE FACADE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Main orchestration layer for all signature storage and matching
 * Unified interface for hash lookups, pattern scanning, and YARA rules
 * Ultra-high performance with intelligent query routing
 *
 * Target Performance Metrics (Per Query):
 * ???????????????????????????????????????????????????
 * ? Hash Lookup:     < 1?s   (sub-microsecond)     ?
 * ? Pattern Scan:    < 10ms  (10MB file)           ?
 * ? YARA Scan:       < 50ms  (10MB file, 1K rules) ?
 * ? Combined Scan:   < 60ms  (all methods)         ?
 * ???????????????????????????????????????????????????
 *
 * Architecture:
 * ????????????????????????????????????????????
 * ?       SignatureStore (Facade)            ?
 * ????????????????????????????????????????????
 * ?  ??????????????  ??????????????         ?
 * ?  ? HashStore  ?  ?PatternStore?         ?
 * ?  ??????????????  ??????????????         ?
 * ?  ???????????????????????????????        ?
 * ?  ?    YaraRuleStore            ?        ?
 * ?  ???????????????????????????????        ?
 * ????????????????????????????????????????????
 * ?    Query Router & Cache Manager          ?
 * ????????????????????????????????????????????
 * ?    Memory-Mapped Database File           ?
 * ????????????????????????????????????????????
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once

#include "SignatureFormat.hpp"
#include "HashStore.hpp"
#include "PatternStore.hpp"
#include "YaraRuleStore.hpp"
#include "SignatureIndex.hpp"
#include "SignatureBuilder.hpp"
#include "../Utils/Logger.hpp"

#include <memory>
#include <string>
#include <vector>
#include <span>
#include <atomic>
#include <shared_mutex>
#include <functional>
#include <optional>
#include <chrono>

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// UNIFIED SCAN OPTIONS
// ============================================================================

struct ScanOptions {
    // Method selection
    bool enableHashLookup{true};
    bool enablePatternScan{true};
    bool enableYaraScan{true};
    
    // Performance controls
    uint32_t timeoutMilliseconds{10000};                  // 10 second default
    uint32_t maxResults{1000};                            // Max detections to return
    bool stopOnFirstMatch{false};                         // Fast mode
    
    // Threading
    uint32_t threadCount{0};                              // 0 = auto-detect
    bool parallelExecution{true};                         // Run methods in parallel
    
    // Filtering
    ThreatLevel minThreatLevel{ThreatLevel::Info};
    std::vector<std::string> tagFilter;                   // Only match these tags
    std::vector<HashType> hashTypesEnabled;               // Empty = all types
    
    // Caching
    bool enableResultCache{true};
    bool enableQueryCache{true};
    
    // YARA-specific
    YaraScanOptions yaraOptions;
    
    // Pattern-specific
    QueryOptions patternOptions;
    
    // Advanced
    bool capturePerformanceMetrics{false};                // Detailed profiling
};

// ============================================================================
// UNIFIED SCAN RESULT
// ============================================================================

struct ScanResult {
    // Matched signatures
    std::vector<DetectionResult> detections;              // All detection results
    
    // Method-specific results
    std::vector<DetectionResult> hashMatches;
    std::vector<DetectionResult> patternMatches;
    std::vector<YaraMatch> yaraMatches;
    
    // Scan metadata
    uint64_t totalBytesScanned{0};
    uint64_t scanTimeMicroseconds{0};
    bool timedOut{false};
    bool stoppedEarly{false};                             // Due to stopOnFirstMatch
    
    // Performance breakdown (if capturePerformanceMetrics enabled)
    struct PerformanceBreakdown {
        uint64_t hashLookupMicroseconds{0};
        uint64_t patternScanMicroseconds{0};
        uint64_t yaraScanMicroseconds{0};
        uint64_t cacheCheckMicroseconds{0};
        uint64_t resultMergingMicroseconds{0};
    } performance;
    
    // Cache statistics
    bool cacheHit{false};
    
    // Convenience methods
    [[nodiscard]] bool HasDetections() const noexcept {
        return !detections.empty();
    }
    
    [[nodiscard]] ThreatLevel GetMaxThreatLevel() const noexcept {
        ThreatLevel max = ThreatLevel::Info;
        for (const auto& det : detections) {
            if (static_cast<uint8_t>(det.threatLevel) > static_cast<uint8_t>(max)) {
                max = det.threatLevel;
            }
        }
        return max;
    }
    
    [[nodiscard]] size_t GetDetectionCount() const noexcept {
        return detections.size();
    }
};

// ============================================================================
// SIGNATURE STORE (Main Facade)
// ============================================================================

class SignatureStore {
public:
    SignatureStore();
    ~SignatureStore();

    // Disable copy, enable move
    SignatureStore(const SignatureStore&) = delete;
    SignatureStore& operator=(const SignatureStore&) = delete;
    SignatureStore(SignatureStore&&) noexcept = default;
    SignatureStore& operator=(SignatureStore&&) noexcept = default;

    // ========================================================================
    // INITIALIZATION & LIFECYCLE
    // ========================================================================

    // Initialize from database file
    [[nodiscard]] StoreError Initialize(
        const std::wstring& databasePath,
        bool readOnly = true
    ) noexcept;

    // Initialize with custom component paths
    [[nodiscard]] StoreError InitializeMulti(
        const std::wstring& hashDatabasePath,
        const std::wstring& patternDatabasePath,
        const std::wstring& yaraDatabasePath,
        bool readOnly = true
    ) noexcept;

    // Close all databases
    void Close() noexcept;

    // Check if initialized
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // Get initialization status for each component
    struct InitializationStatus {
        bool hashStoreReady{false};
        bool patternStoreReady{false};
        bool yaraStoreReady{false};
        bool allReady{false};
    };

    [[nodiscard]] InitializationStatus GetStatus() const noexcept;

    // ========================================================================
    // SCANNING OPERATIONS (Unified Interface)
    // ========================================================================

    // Scan memory buffer (all methods)
    [[nodiscard]] ScanResult ScanBuffer(
        std::span<const uint8_t> buffer,
        const ScanOptions& options = {}
    ) const noexcept;

    // Scan file (memory-mapped for large files)
    [[nodiscard]] ScanResult ScanFile(
        const std::wstring& filePath,
        const ScanOptions& options = {}
    ) const noexcept;

    // Scan multiple files (batch processing)
    [[nodiscard]] std::vector<ScanResult> ScanFiles(
        std::span<const std::wstring> filePaths,
        const ScanOptions& options = {},
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) const noexcept;

    // Scan directory (recursive)
    [[nodiscard]] std::vector<ScanResult> ScanDirectory(
        const std::wstring& directoryPath,
        bool recursive = true,
        const ScanOptions& options = {},
        std::function<void(const std::wstring& file)> fileCallback = nullptr
    ) const noexcept;

    // Scan process memory
    [[nodiscard]] ScanResult ScanProcess(
        uint32_t processId,
        const ScanOptions& options = {}
    ) const noexcept;

    // Incremental scanning (streaming)
    class StreamScanner {
    public:
        StreamScanner() = default;
        ~StreamScanner() = default;

        void Reset() noexcept;
        
        [[nodiscard]] ScanResult FeedChunk(
            std::span<const uint8_t> chunk
        ) noexcept;

        [[nodiscard]] ScanResult Finalize() noexcept;

        [[nodiscard]] size_t GetBytesProcessed() const noexcept {
            return m_bytesProcessed;
        }

    private:
        friend class SignatureStore;
        const SignatureStore* m_store{nullptr};
        std::vector<uint8_t> m_buffer;
        ScanOptions m_options;
        size_t m_bytesProcessed{0};
    };

    [[nodiscard]] StreamScanner CreateStreamScanner(
        const ScanOptions& options = {}
    ) const noexcept;

    // ========================================================================
    // SPECIFIC QUERY METHODS (Individual Components)
    // ========================================================================

    // Hash lookup only
    [[nodiscard]] std::optional<DetectionResult> LookupHash(
        const HashValue& hash
    ) const noexcept;

    [[nodiscard]] std::optional<DetectionResult> LookupHashString(
        const std::string& hashStr,
        HashType type
    ) const noexcept;

    // Compute and lookup file hash
    [[nodiscard]] std::optional<DetectionResult> LookupFileHash(
        const std::wstring& filePath,
        HashType type
    ) const noexcept;

    // Pattern scan only
    [[nodiscard]] std::vector<DetectionResult> ScanPatterns(
        std::span<const uint8_t> buffer,
        const QueryOptions& options = {}
    ) const noexcept;

    // YARA scan only
    [[nodiscard]] std::vector<YaraMatch> ScanYara(
        std::span<const uint8_t> buffer,
        const YaraScanOptions& options = {}
    ) const noexcept;

    // ========================================================================
    // SIGNATURE MANAGEMENT (Write Operations)
    // ========================================================================

    // Add hash signature
    [[nodiscard]] StoreError AddHash(
        const HashValue& hash,
        const std::string& name,
        ThreatLevel threatLevel,
        const std::string& description = "",
        const std::vector<std::string>& tags = {}
    ) noexcept;

    // Add pattern signature
    [[nodiscard]] StoreError AddPattern(
        const std::string& patternString,
        const std::string& name,
        ThreatLevel threatLevel,
        const std::string& description = "",
        const std::vector<std::string>& tags = {}
    ) noexcept;

    // Add YARA rule
    [[nodiscard]] StoreError AddYaraRule(
        const std::string& ruleSource,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Remove signatures
    [[nodiscard]] StoreError RemoveHash(const HashValue& hash) noexcept;
    [[nodiscard]] StoreError RemovePattern(uint64_t signatureId) noexcept;
    [[nodiscard]] StoreError RemoveYaraRule(const std::string& ruleName) noexcept;

    // ========================================================================
    // BULK OPERATIONS
    // ========================================================================

    // Import from various formats
    [[nodiscard]] StoreError ImportHashes(
        const std::wstring& filePath,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;

    [[nodiscard]] StoreError ImportPatterns(
        const std::wstring& filePath
    ) noexcept;

    [[nodiscard]] StoreError ImportYaraRules(
        const std::wstring& filePath,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Export to various formats
    [[nodiscard]] StoreError ExportHashes(
        const std::wstring& outputPath,
        HashType typeFilter = HashType::MD5
    ) const noexcept;

    [[nodiscard]] StoreError ExportPatterns(
        const std::wstring& outputPath
    ) const noexcept;

    [[nodiscard]] StoreError ExportYaraRules(
        const std::wstring& outputPath
    ) const noexcept;

    // ========================================================================
    // STATISTICS & MONITORING
    // ========================================================================

    struct GlobalStatistics {
        // Component statistics
        HashStore::HashStoreStatistics hashStats;
        PatternStore::PatternStoreStatistics patternStats;
        YaraRuleStore::YaraStoreStatistics yaraStats;
        
        // Global metrics
        uint64_t totalScans{0};
        uint64_t totalDetections{0};
        uint64_t averageScanTimeMicroseconds{0};
        uint64_t peakScanTimeMicroseconds{0};
        
        // Database sizes
        uint64_t totalDatabaseSize{0};
        uint64_t hashDatabaseSize{0};
        uint64_t patternDatabaseSize{0};
        uint64_t yaraDatabaseSize{0};
        
        // Cache performance
        uint64_t queryCacheHits{0};
        uint64_t queryCacheMisses{0};
        uint64_t resultCacheHits{0};
        uint64_t resultCacheMisses{0};
        double cacheHitRate{0.0};
        
        // System resources
        uint64_t peakMemoryUsageBytes{0};
        uint32_t activeThreads{0};
    };

    [[nodiscard]] GlobalStatistics GetGlobalStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // Get component-specific statistics
    [[nodiscard]] HashStore::HashStoreStatistics GetHashStatistics() const noexcept;
    [[nodiscard]] PatternStore::PatternStoreStatistics GetPatternStatistics() const noexcept;
    [[nodiscard]] YaraRuleStore::YaraStoreStatistics GetYaraStatistics() const noexcept;

    // ========================================================================
    // MAINTENANCE & OPTIMIZATION
    // ========================================================================

    // Rebuild all indices
    [[nodiscard]] StoreError Rebuild() noexcept;

    // Compact all databases
    [[nodiscard]] StoreError Compact() noexcept;

    // Verify integrity of all databases
    [[nodiscard]] StoreError Verify(
        std::function<void(const std::string&)> logCallback = nullptr
    ) const noexcept;

    // Flush changes to disk
    [[nodiscard]] StoreError Flush() noexcept;

    // Optimize based on usage patterns
    [[nodiscard]] StoreError OptimizeByUsage() noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    // Enable/disable components
    void SetHashStoreEnabled(bool enabled) noexcept;
    void SetPatternStoreEnabled(bool enabled) noexcept;
    void SetYaraStoreEnabled(bool enabled) noexcept;

    // Enable/disable caching
    void SetQueryCacheEnabled(bool enabled) noexcept;
    void SetResultCacheEnabled(bool enabled) noexcept;

    // Set cache sizes
    void SetQueryCacheSize(size_t entries) noexcept;
    void SetResultCacheSize(size_t entries) noexcept;

    // Clear caches
    void ClearQueryCache() noexcept;
    void ClearResultCache() noexcept;
    void ClearAllCaches() noexcept;

    // Set thread pool size
    void SetThreadPoolSize(uint32_t threadCount) noexcept;

    // ========================================================================
    // ADVANCED FEATURES
    // ========================================================================

    // Register detection callback (real-time notifications)
    using DetectionCallback = std::function<void(const DetectionResult&)>;
    void RegisterDetectionCallback(DetectionCallback callback) noexcept;
    void UnregisterDetectionCallback() noexcept;

    // Enable performance profiling
    void SetProfilingEnabled(bool enabled) noexcept {
        m_profilingEnabled.store(enabled, std::memory_order_release);
    }

    // Get database paths
    [[nodiscard]] std::wstring GetHashDatabasePath() const noexcept;
    [[nodiscard]] std::wstring GetPatternDatabasePath() const noexcept;
    [[nodiscard]] std::wstring GetYaraDatabasePath() const noexcept;

    // Get database headers
    [[nodiscard]] const SignatureDatabaseHeader* GetHashHeader() const noexcept;
    [[nodiscard]] const SignatureDatabaseHeader* GetPatternHeader() const noexcept;
    [[nodiscard]] const SignatureDatabaseHeader* GetYaraHeader() const noexcept;

    // Warmup caches (preload hot data)
    void WarmupCaches() noexcept;

    // ========================================================================
    // FACTORY METHODS
    // ========================================================================

    // Create new database using builder
    [[nodiscard]] static StoreError CreateDatabase(
        const std::wstring& outputPath,
        const BuildConfiguration& config
    ) noexcept;

    // Merge multiple databases
    [[nodiscard]] static StoreError MergeDatabases(
        std::span<const std::wstring> sourcePaths,
        const std::wstring& outputPath
    ) noexcept;

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] ScanResult ExecuteScan(
        std::span<const uint8_t> buffer,
        const ScanOptions& options
    ) const noexcept;

    [[nodiscard]] ScanResult ExecuteParallelScan(
        std::span<const uint8_t> buffer,
        const ScanOptions& options
    ) const noexcept;

    [[nodiscard]] ScanResult ExecuteSequentialScan(
        std::span<const uint8_t> buffer,
        const ScanOptions& options
    ) const noexcept;

    [[nodiscard]] std::optional<ScanResult> CheckQueryCache(
        std::span<const uint8_t> buffer
    ) const noexcept;

    void AddToQueryCache(
        std::span<const uint8_t> buffer,
        const ScanResult& result
    ) const noexcept;

    void MergeResults(
        ScanResult& target,
        const std::vector<DetectionResult>& source
    ) const noexcept;

    void NotifyDetection(const DetectionResult& detection) const noexcept;

    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    // Component stores
    std::unique_ptr<HashStore> m_hashStore;
    std::unique_ptr<PatternStore> m_patternStore;
    std::unique_ptr<YaraRuleStore> m_yaraStore;

    // Initialization state
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_readOnly{true};

    // Component enable flags
    std::atomic<bool> m_hashStoreEnabled{true};
    std::atomic<bool> m_patternStoreEnabled{true};
    std::atomic<bool> m_yaraStoreEnabled{true};

    // Caching
    std::atomic<bool> m_queryCacheEnabled{true};
    std::atomic<bool> m_resultCacheEnabled{true};
    
    struct QueryCacheEntry {
        std::array<uint8_t, 32> bufferHash;               // SHA-256 of buffer
        ScanResult result;
        uint64_t timestamp;
    };
    static constexpr size_t QUERY_CACHE_SIZE = 1000;
   // mutable std::array<QueryCacheEntry, QUERY_CACHE_SIZE> m_queryCache{};
	mutable std::vector<QueryCacheEntry> m_queryCache{};
    mutable std::atomic<uint64_t> m_queryCacheAccessCounter{0};

    // Statistics
    mutable std::atomic<uint64_t> m_totalScans{0};
    mutable std::atomic<uint64_t> m_totalDetections{0};
    mutable std::atomic<uint64_t> m_queryCacheHits{0};
    mutable std::atomic<uint64_t> m_queryCacheMisses{0};

    // Detection callback
    DetectionCallback m_detectionCallback;
    mutable std::mutex m_callbackMutex;

    // Configuration
    std::atomic<bool> m_profilingEnabled{false};
    uint32_t m_threadPoolSize{0};

    // Synchronization
    mutable std::shared_mutex m_globalLock;

    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};
};

// ============================================================================
// GLOBAL FUNCTIONS
// ============================================================================

namespace Store {

// Get version information
[[nodiscard]] std::string GetVersion() noexcept;

// Get build information
[[nodiscard]] std::string GetBuildInfo() noexcept;

// Get supported hash types
[[nodiscard]] std::vector<HashType> GetSupportedHashTypes() noexcept;

// Check if YARA is available
[[nodiscard]] bool IsYaraAvailable() noexcept;

// Get YARA version
[[nodiscard]] std::string GetYaraVersion() noexcept;

} // namespace Store

} // namespace SignatureStore
} // namespace ShadowStrike
