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
 * ╔═══════════════════════════════════════════════════╗
 * ║ Hash Lookup:     < 1μs   (sub-microsecond)       ║
 * ║ Pattern Scan:    < 10ms  (10MB file)             ║
 * ║ YARA Scan:       < 50ms  (10MB file, 1K rules)   ║
 * ║ Combined Scan:   < 60ms  (all methods)           ║
 * ╚═══════════════════════════════════════════════════╝
 *
 * Architecture:
 * ┌──────────────────────────────────────────┐
 * │       SignatureStore (Facade)            │
 * ├──────────────────────────────────────────┤
 * │  ┌────────────┐  ┌────────────┐         │
 * │  │ HashStore  │  │PatternStore│         │
 * │  └────────────┘  └────────────┘         │
 * │  ┌─────────────────────────────┐        │
 * │  │    YaraRuleStore            │        │
 * │  └─────────────────────────────┘        │
 * ├──────────────────────────────────────────┤
 * │    Query Router & Cache Manager          │
 * ├──────────────────────────────────────────┤
 * │    Memory-Mapped Database File           │
 * └──────────────────────────────────────────┘
 *
 * Performance Standards: Enterprise antivirus quality
 * 
 * TITANIUM HARDENING APPLIED:
 * - Thread safety: All operations are thread-safe with proper lock hierarchy
 * - Resource limits: Buffer sizes, file counts, recursion depth are bounded
 * - Path security: Null injection, traversal, symlink attacks prevented
 * - Memory safety: Overflow checks, bounds validation, RAII everywhere
 * - Exception safety: All public methods are noexcept with internal try-catch
 * - DoS protection: Timeouts, max results, circuit breakers implemented
 *
 * LOCK HIERARCHY (acquire in this order to prevent deadlocks):
 * 1. m_globalLock (for initialization/shutdown/rebuild)
 * 2. m_cacheLock (for query cache operations)
 * 3. m_callbackMutex (for detection callback)
 *
 * ============================================================================
 */

#pragma once

#include "SignatureFormat.hpp"
#include "HashStore.hpp"
#include "PatternStore.hpp"
#include "SignatureIndex.hpp"
#include "SignatureBuilder.hpp"
#include "YaraRuleStore.hpp"
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

	//forward declarations
    struct YaraMatch;
    class YaraRuleStore;

// ============================================================================
// TITANIUM RESOURCE LIMITS
// ============================================================================

namespace TitaniumLimits {
    // Buffer and file size limits
    constexpr size_t MAX_SCAN_BUFFER_SIZE = 500 * 1024 * 1024;      // 500MB max buffer
    constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;             // 100MB max file
    constexpr size_t MAX_CACHEABLE_SIZE = 100 * 1024 * 1024;        // 100MB max for caching
    
    // Path limits
    constexpr size_t MAX_PATH_LENGTH = 32767;                        // Windows extended path limit
    
    // Batch operation limits
    constexpr size_t MAX_BATCH_FILES = 100000;                       // Max files in batch scan
    constexpr size_t MAX_DIRECTORY_FILES = 1000000;                  // Max files in directory scan
    constexpr size_t MAX_RECURSION_DEPTH = 100;                      // Max directory recursion
    constexpr size_t MAX_SOURCE_DATABASES = 1000;                    // Max databases to merge
    
    // Cache limits
    constexpr size_t MAX_CACHE_ENTRIES = 10000;                      // Max cache entries
    constexpr size_t MAX_CACHED_DETECTIONS = 10000;                  // Max detections per cache entry
    
    // Result limits
    constexpr size_t DEFAULT_MAX_RESULTS = 1000;                     // Default max results
    constexpr size_t ABSOLUTE_MAX_RESULTS = 100000;                  // Absolute max results
    
    // Timeout limits
    constexpr uint32_t DEFAULT_TIMEOUT_MS = 10000;                   // 10 seconds default
    constexpr uint32_t MIN_TIMEOUT_MS = 100;                         // 100ms minimum
    constexpr uint32_t MAX_TIMEOUT_MS = 3600000;                     // 1 hour maximum
    
    // Stream scanner limits
    constexpr size_t STREAM_SCAN_THRESHOLD = 10 * 1024 * 1024;      // 10MB scan threshold
    constexpr size_t MAX_SINGLE_CHUNK_SIZE = 50 * 1024 * 1024;      // 50MB max chunk
}

// ============================================================================
// UNIFIED SCAN OPTIONS
// ============================================================================

struct ScanOptions {
    // Method selection
    bool enableHashLookup{true};
    bool enablePatternScan{true};
    bool enableYaraScan{true};
    
    // Performance controls
    uint32_t timeoutMilliseconds{TitaniumLimits::DEFAULT_TIMEOUT_MS};  // 10 second default
    uint32_t maxResults{TitaniumLimits::DEFAULT_MAX_RESULTS};          // Max detections to return
    bool stopOnFirstMatch{false};                                       // Fast mode
    
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
    
    // ========================================================================
    // TITANIUM: Validation helper
    // ========================================================================
    [[nodiscard]] bool Validate() const noexcept {
        // Timeout validation
        if (timeoutMilliseconds > TitaniumLimits::MAX_TIMEOUT_MS) {
            return false;
        }
        
        // Max results validation
        if (maxResults > TitaniumLimits::ABSOLUTE_MAX_RESULTS) {
            return false;
        }
        
        return true;
    }
    
    // TITANIUM: Get validated timeout
    [[nodiscard]] uint32_t GetValidatedTimeout() const noexcept {
        if (timeoutMilliseconds == 0) {
            return TitaniumLimits::DEFAULT_TIMEOUT_MS;
        }
        if (timeoutMilliseconds < TitaniumLimits::MIN_TIMEOUT_MS) {
            return TitaniumLimits::MIN_TIMEOUT_MS;
        }
        if (timeoutMilliseconds > TitaniumLimits::MAX_TIMEOUT_MS) {
            return TitaniumLimits::MAX_TIMEOUT_MS;
        }
        return timeoutMilliseconds;
    }
    
    // TITANIUM: Get validated max results
    [[nodiscard]] uint32_t GetValidatedMaxResults() const noexcept {
        if (maxResults == 0) {
            return TitaniumLimits::DEFAULT_MAX_RESULTS;
        }
        if (maxResults > TitaniumLimits::ABSOLUTE_MAX_RESULTS) {
            return TitaniumLimits::ABSOLUTE_MAX_RESULTS;
        }
        return maxResults;
    }
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
    
    // TITANIUM: Error tracking
    uint32_t errorCount{0};                               // Number of errors during scan
    std::string lastError;                                // Last error message
    
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
    
    // ========================================================================
    // CONVENIENCE METHODS
    // ========================================================================
    
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
    
    // TITANIUM: Check if scan completed successfully
    [[nodiscard]] bool IsSuccessful() const noexcept {
        return !timedOut && errorCount == 0;
    }
    
    // TITANIUM: Check if any critical-level detection found
    [[nodiscard]] bool HasCriticalDetection() const noexcept {
        for (const auto& det : detections) {
            if (det.threatLevel == ThreatLevel::Critical) {
                return true;
            }
        }
        return false;
    }
    
    // TITANIUM: Get detections filtered by threat level
    [[nodiscard]] std::vector<DetectionResult> GetDetectionsByLevel(ThreatLevel level) const noexcept {
        std::vector<DetectionResult> filtered;
        for (const auto& det : detections) {
            if (det.threatLevel == level) {
                filtered.push_back(det);
            }
        }
        return filtered;
    }
    
    // TITANIUM: Get scan throughput in MB/s
    [[nodiscard]] double GetThroughputMBps() const noexcept {
        if (scanTimeMicroseconds == 0) {
            return 0.0;
        }
        double bytesPerMicrosecond = static_cast<double>(totalBytesScanned) / scanTimeMicroseconds;
        return bytesPerMicrosecond; // bytes/µs = MB/s
    }
    
    // TITANIUM: Clear all results (useful for reuse)
    void Clear() noexcept {
        detections.clear();
        hashMatches.clear();
        patternMatches.clear();
        yaraMatches.clear();
        totalBytesScanned = 0;
        scanTimeMicroseconds = 0;
        timedOut = false;
        stoppedEarly = false;
        errorCount = 0;
        lastError.clear();
        performance = PerformanceBreakdown{};
        cacheHit = false;
    }
};

// ============================================================================
// SIGNATURE STORE (Main Facade)
// ============================================================================

class SignatureStore {
public:
    SignatureStore();
    ~SignatureStore();

    // Disable copy AND move - class contains mutex, shared_mutex and atomics that cannot be safely moved
    SignatureStore(const SignatureStore&) = delete;
    SignatureStore& operator=(const SignatureStore&) = delete;
    SignatureStore(SignatureStore&&) = delete;
    SignatureStore& operator=(SignatureStore&&) = delete;

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

        std::optional<HashValue> ComputeFileHash(
            const std::wstring& filePath,
            HashType type
        ) const noexcept;

        bool CompareHashes(const HashValue& a, const HashValue& b) const noexcept;

        std::optional<HashValue> ComputeBufferHash(
            std::span<const uint8_t> buffer,
            HashType type
        ) const noexcept;
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
	mutable std::vector<QueryCacheEntry> m_queryCache{};
    mutable std::atomic<uint64_t> m_queryCacheAccessCounter{0};
    mutable std::shared_mutex m_cacheLock;                // FIX: Separate lock for cache operations (better performance)

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
