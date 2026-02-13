/*
 * ============================================================================
 * ShadowStrike HashStore - LIGHTNING-FAST HASH DATABASE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance hash storage and lookup system
 * Memory-mapped with perfect hash indexing for O(1) lookups
 * Target: < 1?s average hash lookup (sub-microsecond)
 *
 * Supported Hashes:
 * - MD5 (malware hashes)
 * - SHA-1 (legacy signatures)
 * - SHA-256 (modern signatures)
 * - SHA-512 (high-security)
 * - ImpHash (PE import hashes)
 * - CTPH Fuzzy hash (context-triggered piecewise)
 * - TLSH (Trend Micro Locality Sensitive Hash)
 *
 * Architecture:
 * ???????????????????????????????????????????
 * ? Hash Type Buckets (segregated by type) ?
 * ???????????????????????????????????????????
 * ? B+Tree Index per bucket (O(log N))     ?
 * ???????????????????????????????????????????
 * ? Bloom Filter (false positive filter)   ?
 * ???????????????????????????????????????????
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once

#include "../SignatureStore/SignatureFormat.hpp"
#include"../Utils/HashUtils.hpp"
#include "../SignatureStore/SignatureIndex.hpp"
#include <memory>
#include <unordered_map>
#include <atomic>
#include <shared_mutex>
#include <bitset>

namespace ShadowStrike {
namespace HashStore {

    // Import types from SignatureStore namespace
    using namespace ShadowStrike::SignatureStore;

// ============================================================================
// BLOOM FILTER (Fast Negative Lookups)
// ============================================================================

class BloomFilter {
public:
    explicit BloomFilter(size_t expectedElements = 1'000'000, double falsePositiveRate = 0.01);
    ~BloomFilter() = default;

    // Add element
    void Add(uint64_t hash) noexcept;

    // Check if element might exist (false positives possible)
    [[nodiscard]] bool MightContain(uint64_t hash) const noexcept;

    // Clear all bits
    void Clear() noexcept;

    // Statistics
    [[nodiscard]] size_t GetSize() const noexcept { return m_bits.size(); }
    [[nodiscard]] size_t GetHashFunctions() const noexcept { return m_numHashes; }
    [[nodiscard]] double EstimatedFillRate() const noexcept;

private:
    std::vector<std::atomic<uint64_t>> m_bits;            // Bit array (atomic for thread-safety)
    size_t m_numHashes{0};                                // Number of hash functions
    size_t m_size{0};                                     // Bit array size

    [[nodiscard]] uint64_t Hash(uint64_t value, size_t seed) const noexcept;
};

// ============================================================================
// HASH BUCKET (Per-Type Storage)
// ============================================================================

class HashBucket {
public:
    explicit HashBucket(HashType type);
    ~HashBucket();

    // Disable copy, enable move
    HashBucket(const HashBucket&) = delete;
    HashBucket& operator=(const HashBucket&) = delete;
    HashBucket(HashBucket&&) noexcept = default;
    HashBucket& operator=(HashBucket&&) noexcept = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t bucketOffset,
        uint64_t bucketSize
    ) noexcept;

    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;

    // ========================================================================
    // QUERY OPERATIONS
    // ========================================================================

    // Lookup hash (< 1?s average)
    [[nodiscard]] std::optional<uint64_t> Lookup(
        const HashValue& hash
    ) const noexcept;

    // Batch lookup (cache-optimized)
    void BatchLookup(
        std::span<const HashValue> hashes,
        std::vector<std::optional<uint64_t>>& results
    ) const noexcept;

    // Check existence (bloom filter fast path)
    [[nodiscard]] bool Contains(const HashValue& hash) const noexcept;

    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================

    [[nodiscard]] StoreError Insert(
        const HashValue& hash,
        uint64_t signatureOffset
    ) noexcept;

    [[nodiscard]] StoreError Remove(
        const HashValue& hash
    ) noexcept;

    [[nodiscard]] StoreError BatchInsert(
        std::span<const std::pair<HashValue, uint64_t>> entries
    ) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    struct BucketStatistics {
        uint64_t totalHashes{0};
        uint64_t bloomFilterHits{0};                      // Fast path
        uint64_t bloomFilterMisses{0};
        uint64_t indexLookups{0};
        uint64_t averageLookupNanoseconds{0};
    };

    [[nodiscard]] BucketStatistics GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    std::unique_ptr<SignatureIndex> m_index;
    std::unique_ptr<BloomFilter> m_bloomFilter;

private:
    HashType m_type;
    
    
    const MemoryMappedView* m_view{nullptr};
    uint64_t m_bucketOffset{0};
    uint64_t m_bucketSize{0};

    mutable std::atomic<uint64_t> m_lookupCount{0};
    mutable std::atomic<uint64_t> m_bloomHits{0};
    mutable std::atomic<uint64_t> m_bloomMisses{0};
  
    
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// HASH STORE (Main Interface)
// ============================================================================

class HashStore {
public:
    HashStore();
    ~HashStore();

    // Disable copy, enable move
    HashStore(const HashStore&) = delete;
    HashStore& operator=(const HashStore&) = delete;
    HashStore(HashStore&&) noexcept = default;
    HashStore& operator=(HashStore&&) noexcept = default;

    // ========================================================================
    // INITIALIZATION & LIFECYCLE
    // ========================================================================

    // Initialize from existing database file
    [[nodiscard]] StoreError Initialize(
        const std::wstring& databasePath,
        bool readOnly = true
    ) noexcept;

    // Create new empty database
    [[nodiscard]] StoreError CreateNew(
        const std::wstring& databasePath,
        uint64_t initialSizeBytes = 100 * 1024 * 1024   // 100MB default
    ) noexcept;

    // Close database and release resources
    void Close() noexcept;

    // Check if initialized
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // HASH QUERY OPERATIONS (Ultra-Fast)
    // ========================================================================

    // Lookup single hash (< 1?s target)
    [[nodiscard]] std::optional<DetectionResult> LookupHash(
        const HashValue& hash
    ) const noexcept;

    // Lookup by string (convenience method)
    [[nodiscard]] std::optional<DetectionResult> LookupHashString(
        const std::string& hashStr,
        HashType type
    ) const noexcept;

    // Batch lookup (optimized for scanning multiple files)
    [[nodiscard]] std::vector<DetectionResult> BatchLookup(
        std::span<const HashValue> hashes,
        const QueryOptions& options = {}
    ) const noexcept;

    // Check if hash exists (bloom filter fast path)
    [[nodiscard]] bool Contains(const HashValue& hash) const noexcept;

    // Fuzzy hash matching (CTPH/TLSH)
    [[nodiscard]] std::vector<DetectionResult> FuzzyMatch(
        const HashValue& hash,
        uint32_t similarityThreshold = 80              // 0-100
    ) const noexcept;

    // ========================================================================
    // HASH MANAGEMENT (Write Operations)
    // ========================================================================

    // Add new hash signature
    [[nodiscard]] StoreError AddHash(
        const HashValue& hash,
        const std::string& signatureName,
        ThreatLevel threatLevel,
        const std::string& description = "",
        const std::vector<std::string>& tags = {}
    ) noexcept;

    // Add multiple hashes (bulk import)
    [[nodiscard]] StoreError AddHashBatch(
        std::span<const HashValue> hashes,
        std::span<const std::string> signatureNames,
        std::span<const ThreatLevel> threatLevels
    ) noexcept;

    // Remove hash from database
    [[nodiscard]] StoreError RemoveHash(
        const HashValue& hash
    ) noexcept;

    // Update hash metadata
    [[nodiscard]] StoreError UpdateHashMetadata(
        const HashValue& hash,
        const std::string& newDescription,
        const std::vector<std::string>& newTags
    ) noexcept;

    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================

    // Import hashes from text file (one per line: TYPE:HASH:NAME:LEVEL)
    [[nodiscard]] StoreError ImportFromFile(
        const std::wstring& filePath,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;

    // Export all hashes to text file
    [[nodiscard]] StoreError ExportToFile(
        const std::wstring& filePath,
        HashType typeFilter = HashType::MD5
    ) const noexcept;

    // Import from JSON (structured format)
    [[nodiscard]] StoreError ImportFromJson(
        const std::string& jsonData
    ) noexcept;

    // Export to JSON
    [[nodiscard]] std::string ExportToJson(
        HashType typeFilter = HashType::MD5,
        uint32_t maxEntries = UINT32_MAX
    ) const noexcept;

    // ========================================================================
    // STATISTICS & MONITORING
    // ========================================================================

    struct HashStoreStatistics {
        std::unordered_map<HashType, uint64_t> countsByType;
        uint64_t totalHashes{0};
        uint64_t totalLookups{0};
        uint64_t cacheHits{0};
        uint64_t cacheMisses{0};
        uint64_t bloomFilterSaves{0};                     // Bloom prevented full lookup
        uint64_t averageLookupNanoseconds{0};
        uint64_t peakLookupNanoseconds{0};
        uint64_t databaseSizeBytes{0};
        double cacheHitRate{0.0};
        double bloomFilterEfficiency{0.0};
    };

    [[nodiscard]] HashStoreStatistics GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // Get per-type statistics
    [[nodiscard]] HashBucket::BucketStatistics GetBucketStatistics(
        HashType type
    ) const noexcept;

    // ========================================================================
    // MAINTENANCE
    // ========================================================================

    // Rebuild all indices (optimize after many updates)
    [[nodiscard]] StoreError Rebuild() noexcept;

    // Compact database (remove fragmentation)
    [[nodiscard]] StoreError Compact() noexcept;

    // Verify database integrity
    [[nodiscard]] StoreError Verify(
        std::function<void(const std::string&)> logCallback = nullptr
    ) const noexcept;

    // Flush changes to disk
    StoreError Flush() noexcept;

    void ClearCache() noexcept;

    // ========================================================================
    // ADVANCED FEATURES
    // ========================================================================

    // Enable/disable query result caching
    void SetCachingEnabled(bool enabled) noexcept {
        m_cachingEnabled.store(enabled, std::memory_order_release);
    }

    // Set bloom filter parameters (must be called before Initialize)
    void SetBloomFilterConfig(
        size_t expectedElements,
        double falsePositiveRate
    ) noexcept;

    // Get database file path
    [[nodiscard]] std::wstring GetDatabasePath() const noexcept {
        return m_databasePath;
    }

    // Get database header (read-only)
    [[nodiscard]] const SignatureDatabaseHeader* GetHeader() const noexcept;

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] StoreError OpenMemoryMapping(
        const std::wstring& path,
        bool readOnly
    ) noexcept;

    void CloseMemoryMapping() noexcept;

    [[nodiscard]] StoreError InitializeBuckets() noexcept;

    [[nodiscard]] HashBucket* GetBucket(HashType type) noexcept;
    [[nodiscard]] const HashBucket* GetBucket(HashType type) const noexcept;

    [[nodiscard]] uint64_t AllocateSignatureEntry(size_t size) noexcept;

    [[nodiscard]] DetectionResult BuildDetectionResult(
        const HashValue& hash,
        uint64_t signatureOffset
    ) const noexcept;

    // Query result cache with SeqLock for lock-free reads
    struct alignas(64) CacheEntry {  // Cache-line aligned to prevent false sharing
        mutable std::atomic<uint64_t> seqlock{0};         // SeqLock: odd = writing, even = valid
        HashValue hash{};
        std::optional<DetectionResult> result;
        uint64_t timestamp{0};                            // For LRU eviction
    };

    [[nodiscard]] std::optional<DetectionResult> GetFromCache(
        const HashValue& hash
    ) const noexcept;

    void AddToCache(
        const HashValue& hash,
        const std::optional<DetectionResult>& result
    ) const noexcept;

  

    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    std::wstring m_databasePath;
    MemoryMappedView m_mappedView{};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_readOnly{true};

    // Hash type buckets
    std::unordered_map<HashType, std::unique_ptr<HashBucket>> m_buckets;

    // Query result cache (LRU)
    // Note: Reduced to 256 for faster initialization while still providing
    // effective caching for hot lookups. Atomic seqlock provides lock-free reads.
    static constexpr size_t CACHE_SIZE = 256;
    mutable std::array<CacheEntry, CACHE_SIZE> m_queryCache{};  // Zero-initialized by default
    mutable std::atomic<uint64_t> m_cacheAccessCounter{0};
    std::atomic<bool> m_cachingEnabled{true};

    // Statistics
    mutable std::atomic<uint64_t> m_totalLookups{0};
    mutable std::atomic<uint64_t> m_cacheHits{0};
    mutable std::atomic<uint64_t> m_cacheMisses{0};
    mutable std::atomic<uint64_t> m_totalMatches{ 0 };      // Fuzzy matching results counter


    // Bloom filter configuration
    size_t m_bloomExpectedElements{1'000'000};
    double m_bloomFalsePositiveRate{0.01};

    // Synchronization
    mutable std::shared_mutex m_globalLock;

    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};
};




} // namespace SignatureStore
} // namespace ShadowStrike
