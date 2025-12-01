/*
 * ============================================================================
 * ShadowStrike WhitelistStore - ENTERPRISE-GRADE WHITELIST ENGINE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance whitelist storage and lookup system
 * Memory-mapped with B+Tree indexing for O(log N) lookups
 * Bloom filters for nanosecond-level negative lookups
 *
 * Target Performance:
 * - Hash lookup: < 100ns average (with bloom filter pre-check)
 * - Path lookup: < 500ns average (with Trie index)
 * - Bloom filter check: < 20ns
 * - Cache hit: < 50ns
 *
 * Features:
 * - Hash-based whitelisting (MD5/SHA1/SHA256/SHA512/ImpHash)
 * - Path-based whitelisting (exact, prefix, suffix, glob, regex)
 * - Certificate thumbprint whitelisting
 * - Publisher/vendor name whitelisting
 * - Expiration support with automatic purge
 * - Policy-based management
 * - Audit logging (who added what, when)
 * - Concurrent read/write access
 * - Hot reload (double-buffering for atomic updates)
 * - Import/Export (JSON, CSV)
 *
 * Architecture:
 * ┌───────────────────────────────────────────────────────────────────────┐
 * │                         WhitelistStore                                 │
 * ├───────────────────────────────────────────────────────────────────────┤
 * │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐      │
 * │ │ BloomFilter │ │ HashBucket  │ │ PathIndex   │ │ QueryCache  │      │
 * │ │ (Fast neg)  │ │ (B+Tree)    │ │ (Trie)      │ │ (LRU+SeqLock│      │
 * │ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘      │
 * ├───────────────────────────────────────────────────────────────────────┤
 * │                    MemoryMappedView (Zero-copy)                        │
 * └───────────────────────────────────────────────────────────────────────┘
 *
 * Performance Standards: CrowdStrike Falcon / Kaspersky / Bitdefender quality
 *
 * ============================================================================
 */

#pragma once

#include "WhiteListFormat.hpp"
#include <memory>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <functional>
#include <string>
#include <string_view>

namespace ShadowStrike {
namespace Whitelist {

// Forward declarations
class BloomFilter;
class HashIndex;
class PathIndex;
class CertificateIndex;
class PublisherIndex;
class StringPool;

// ============================================================================
// BLOOM FILTER (Nanosecond-level negative lookups)
// ============================================================================

/// @brief High-performance Bloom filter for fast negative lookups
/// @note Thread-safe via atomic operations (no locks needed for reads)
class BloomFilter {
public:
    /// @brief Construct bloom filter with expected elements and target false positive rate
    /// @param expectedElements Expected number of elements to add
    /// @param falsePositiveRate Target false positive rate (0.0 - 1.0)
    explicit BloomFilter(
        size_t expectedElements = 1'000'000,
        double falsePositiveRate = 0.0001  // 0.01%
    );
    
    ~BloomFilter() = default;
    
    // Disable copy (large memory footprint)
    BloomFilter(const BloomFilter&) = delete;
    BloomFilter& operator=(const BloomFilter&) = delete;
    
    // Enable move
    BloomFilter(BloomFilter&&) noexcept = default;
    BloomFilter& operator=(BloomFilter&&) noexcept = default;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /// @brief Initialize from memory-mapped region
    /// @param data Pointer to bloom filter bit array
    /// @param bitCount Number of bits in the filter
    /// @param hashFunctions Number of hash functions used
    /// @return True if initialization succeeded
    [[nodiscard]] bool Initialize(
        const void* data,
        size_t bitCount,
        size_t hashFunctions
    ) noexcept;
    
    /// @brief Initialize for building (allocates memory)
    [[nodiscard]] bool InitializeForBuild() noexcept;
    
    // ========================================================================
    // OPERATIONS
    // ========================================================================
    
    /// @brief Add element to filter (thread-safe via atomics)
    /// @param hash 64-bit hash of element
    void Add(uint64_t hash) noexcept;
    
    /// @brief Add hash value to filter
    /// @param hashValue HashValue structure
    void Add(const HashValue& hashValue) noexcept {
        Add(hashValue.FastHash());
    }
    
    /// @brief Check if element might exist (false positives possible)
    /// @param hash 64-bit hash of element
    /// @return False = definitely not in set, True = might be in set
    [[nodiscard]] bool MightContain(uint64_t hash) const noexcept;
    
    /// @brief Check if hash value might exist
    [[nodiscard]] bool MightContain(const HashValue& hashValue) const noexcept {
        return MightContain(hashValue.FastHash());
    }
    
    /// @brief Clear all bits (not thread-safe)
    void Clear() noexcept;
    
    /// @brief Serialize to byte array
    /// @param[out] data Output buffer
    /// @param[out] size Size of data
    /// @return True if serialization succeeded
    [[nodiscard]] bool Serialize(std::vector<uint8_t>& data) const;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /// @brief Get number of bits in filter
    [[nodiscard]] size_t GetBitCount() const noexcept { return m_bitCount; }
    
    /// @brief Get number of hash functions
    [[nodiscard]] size_t GetHashFunctions() const noexcept { return m_numHashes; }
    
    /// @brief Get memory usage in bytes
    [[nodiscard]] size_t GetMemoryUsage() const noexcept { 
        return m_bits.size() * sizeof(std::atomic<uint64_t>); 
    }
    
    /// @brief Estimate fill rate (0.0 - 1.0)
    [[nodiscard]] double EstimatedFillRate() const noexcept;
    
    /// @brief Estimate current false positive rate
    [[nodiscard]] double EstimatedFalsePositiveRate() const noexcept;
    
private:
    /// @brief Compute hash with seed (double hashing scheme)
    [[nodiscard]] uint64_t Hash(uint64_t value, size_t seed) const noexcept;
    
    /// @brief Calculate optimal parameters
    void CalculateOptimalParameters(size_t expectedElements, double falsePositiveRate);
    
    std::vector<std::atomic<uint64_t>> m_bits;  ///< Bit array (atomic for thread-safety)
    const uint64_t* m_mappedBits{nullptr};      ///< Pointer to memory-mapped bits
    size_t m_bitCount{0};                        ///< Number of bits
    size_t m_numHashes{0};                       ///< Number of hash functions
    size_t m_expectedElements{0};                ///< Expected element count
    double m_targetFPR{0.0001};                  ///< Target false positive rate
    bool m_isMemoryMapped{false};                ///< Using memory-mapped storage
    mutable std::atomic<uint64_t> m_elementsAdded{0}; ///< Elements added (estimate)
};

// ============================================================================
// HASH INDEX (B+Tree for hash lookups)
// ============================================================================

/// @brief B+Tree index for hash-based lookups
/// @note Provides O(log N) lookup time
class HashIndex {
public:
    HashIndex();
    ~HashIndex();
    
    // Disable copy
    HashIndex(const HashIndex&) = delete;
    HashIndex& operator=(const HashIndex&) = delete;
    
    // Enable move
    HashIndex(HashIndex&&) noexcept;
    HashIndex& operator=(HashIndex&&) noexcept;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /// @brief Initialize from memory-mapped region
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    /// @brief Create new index in memory
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // QUERY OPERATIONS
    // ========================================================================
    
    /// @brief Lookup hash and return entry offset
    /// @param hash Hash value to look up
    /// @return Entry offset if found, nullopt otherwise
    [[nodiscard]] std::optional<uint64_t> Lookup(const HashValue& hash) const noexcept;
    
    /// @brief Check if hash exists (without fetching offset)
    [[nodiscard]] bool Contains(const HashValue& hash) const noexcept;
    
    /// @brief Batch lookup for multiple hashes (cache-friendly)
    void BatchLookup(
        std::span<const HashValue> hashes,
        std::vector<std::optional<uint64_t>>& results
    ) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    /// @brief Insert hash with entry offset
    [[nodiscard]] StoreError Insert(
        const HashValue& hash,
        uint64_t entryOffset
    ) noexcept;
    
    /// @brief Remove hash from index
    [[nodiscard]] StoreError Remove(const HashValue& hash) noexcept;
    
    /// @brief Batch insert (more efficient than individual inserts)
    [[nodiscard]] StoreError BatchInsert(
        std::span<const std::pair<HashValue, uint64_t>> entries
    ) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetEntryCount() const noexcept { return m_entryCount.load(); }
    [[nodiscard]] uint64_t GetNodeCount() const noexcept { return m_nodeCount.load(); }
    [[nodiscard]] uint32_t GetTreeDepth() const noexcept { return m_treeDepth; }
    
private:
    /// @brief Find leaf node containing key
    [[nodiscard]] const BPlusTreeNode* FindLeaf(uint64_t key) const noexcept;
    
    /// @brief Find leaf node (mutable version for inserts)
    [[nodiscard]] BPlusTreeNode* FindLeafMutable(uint64_t key) noexcept;
    
    /// @brief Split node when full
    [[nodiscard]] StoreError SplitNode(BPlusTreeNode* node) noexcept;
    
    /// @brief Allocate new node
    [[nodiscard]] BPlusTreeNode* AllocateNode() noexcept;
    
    const MemoryMappedView* m_view{nullptr};
    void* m_baseAddress{nullptr};
    uint64_t m_rootOffset{0};
    uint64_t m_indexOffset{0};
    uint64_t m_indexSize{0};
    uint64_t m_nextNodeOffset{0};
    uint32_t m_treeDepth{0};
    std::atomic<uint64_t> m_entryCount{0};
    std::atomic<uint64_t> m_nodeCount{0};
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// PATH INDEX (Compressed Trie for path matching)
// ============================================================================

/// @brief Compressed Trie index for path-based lookups
/// @note Supports exact match, prefix, suffix, and glob patterns
class PathIndex {
public:
    PathIndex();
    ~PathIndex();
    
    // Disable copy
    PathIndex(const PathIndex&) = delete;
    PathIndex& operator=(const PathIndex&) = delete;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // QUERY OPERATIONS
    // ========================================================================
    
    /// @brief Lookup path and return matching entry offsets
    [[nodiscard]] std::vector<uint64_t> Lookup(
        std::wstring_view path,
        PathMatchMode mode = PathMatchMode::Exact
    ) const noexcept;
    
    /// @brief Check if path matches any pattern
    [[nodiscard]] bool Contains(
        std::wstring_view path,
        PathMatchMode mode = PathMatchMode::Exact
    ) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    [[nodiscard]] StoreError Insert(
        std::wstring_view path,
        PathMatchMode mode,
        uint64_t entryOffset
    ) noexcept;
    
    [[nodiscard]] StoreError Remove(
        std::wstring_view path,
        PathMatchMode mode
    ) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetPathCount() const noexcept { return m_pathCount.load(); }
    [[nodiscard]] uint64_t GetNodeCount() const noexcept { return m_nodeCount.load(); }
    
private:
    struct TrieNode;
    
    const MemoryMappedView* m_view{nullptr};
    void* m_baseAddress{nullptr};
    uint64_t m_rootOffset{0};
    uint64_t m_indexOffset{0};
    uint64_t m_indexSize{0};
    std::atomic<uint64_t> m_pathCount{0};
    std::atomic<uint64_t> m_nodeCount{0};
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// QUERY CACHE (LRU with SeqLock for lock-free reads)
// ============================================================================

/// @brief Query result cache entry with SeqLock for lock-free concurrent reads
/// @note Aligned to cache line to prevent false sharing
struct alignas(CACHE_LINE_SIZE) CacheEntry {
    /// @brief SeqLock: odd = writing, even = valid for reading
    mutable std::atomic<uint64_t> seqlock{0};
    
    /// @brief Cached hash value
    HashValue hash{};
    
    /// @brief Cached lookup result
    LookupResult result{};
    
    /// @brief Access timestamp for LRU eviction
    uint64_t accessTime{0};
    
    /// @brief Check if entry is valid (not being written)
    [[nodiscard]] bool IsValid() const noexcept {
        return (seqlock.load(std::memory_order_acquire) & 1) == 0;
    }
    
    /// @brief Begin write (acquire lock)
    void BeginWrite() noexcept {
        seqlock.fetch_add(1, std::memory_order_release);
    }
    
    /// @brief End write (release lock)
    void EndWrite() noexcept {
        seqlock.fetch_add(1, std::memory_order_release);
    }
};

// ============================================================================
// STRING POOL (Deduplicated string storage)
// ============================================================================

/// @brief Deduplicated string storage for paths, descriptions, etc.
class StringPool {
public:
    StringPool();
    ~StringPool();
    
    // Disable copy
    StringPool(const StringPool&) = delete;
    StringPool& operator=(const StringPool&) = delete;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // OPERATIONS
    // ========================================================================
    
    /// @brief Get string at offset
    [[nodiscard]] std::string_view GetString(uint32_t offset, uint16_t length) const noexcept;
    
    /// @brief Get wide string at offset
    [[nodiscard]] std::wstring_view GetWideString(uint32_t offset, uint16_t length) const noexcept;
    
    /// @brief Add string and return offset (deduplicates)
    [[nodiscard]] std::optional<uint32_t> AddString(std::string_view str) noexcept;
    
    /// @brief Add wide string and return offset
    [[nodiscard]] std::optional<uint32_t> AddWideString(std::wstring_view str) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetUsedSize() const noexcept { return m_usedSize.load(); }
    [[nodiscard]] uint64_t GetTotalSize() const noexcept { return m_totalSize; }
    [[nodiscard]] uint64_t GetStringCount() const noexcept { return m_stringCount.load(); }
    
private:
    const MemoryMappedView* m_view{nullptr};
    void* m_baseAddress{nullptr};
    uint64_t m_poolOffset{0};
    uint64_t m_totalSize{0};
    std::atomic<uint64_t> m_usedSize{0};
    std::atomic<uint64_t> m_stringCount{0};
    std::unordered_map<uint64_t, uint32_t> m_deduplicationMap; // hash -> offset
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// WHITELIST STORE (Main Interface)
// ============================================================================

/// @brief Main whitelist store class - enterprise-grade implementation
/// @note Thread-safe for concurrent access
class WhitelistStore {
public:
    WhitelistStore();
    ~WhitelistStore();
    
    // Disable copy
    WhitelistStore(const WhitelistStore&) = delete;
    WhitelistStore& operator=(const WhitelistStore&) = delete;
    
    // Enable move
    WhitelistStore(WhitelistStore&&) noexcept;
    WhitelistStore& operator=(WhitelistStore&&) noexcept;
    
    // ========================================================================
    // INITIALIZATION & LIFECYCLE
    // ========================================================================
    
    /// @brief Load existing whitelist database
    /// @param databasePath Path to database file
    /// @param readOnly Open in read-only mode
    /// @return Error code
    [[nodiscard]] StoreError Load(
        const std::wstring& databasePath,
        bool readOnly = true
    ) noexcept;
    
    /// @brief Create new whitelist database
    /// @param databasePath Path for new database file
    /// @param initialSizeBytes Initial size in bytes
    /// @return Error code
    [[nodiscard]] StoreError Create(
        const std::wstring& databasePath,
        uint64_t initialSizeBytes = 100 * 1024 * 1024  // 100MB default
    ) noexcept;
    
    /// @brief Save changes to disk
    [[nodiscard]] StoreError Save() noexcept;
    
    /// @brief Close database and release resources
    void Close() noexcept;
    
    /// @brief Check if store is initialized
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }
    
    /// @brief Check if store is read-only
    [[nodiscard]] bool IsReadOnly() const noexcept {
        return m_readOnly.load(std::memory_order_acquire);
    }
    
    // ========================================================================
    // QUERY OPERATIONS (Ultra-Fast Lookups)
    // ========================================================================
    
    /// @brief Check if file hash is whitelisted (< 100ns target)
    /// @param hash Hash value to check
    /// @param options Query options
    /// @return Lookup result
    [[nodiscard]] LookupResult IsHashWhitelisted(
        const HashValue& hash,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Check if file hash (string) is whitelisted
    [[nodiscard]] LookupResult IsHashWhitelisted(
        const std::string& hashString,
        HashAlgorithm algorithm,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Check if file path is whitelisted (< 500ns target)
    [[nodiscard]] LookupResult IsPathWhitelisted(
        std::wstring_view path,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Check if certificate thumbprint is whitelisted
    [[nodiscard]] LookupResult IsCertificateWhitelisted(
        const std::array<uint8_t, 32>& thumbprint,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Check if publisher name is whitelisted
    [[nodiscard]] LookupResult IsPublisherWhitelisted(
        std::wstring_view publisherName,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Batch lookup for multiple hashes (optimized for scanning)
    [[nodiscard]] std::vector<LookupResult> BatchLookupHashes(
        std::span<const HashValue> hashes,
        const QueryOptions& options = {}
    ) const noexcept;
    
    /// @brief Comprehensive whitelist check (checks all applicable types)
    /// @param filePath File path
    /// @param fileHash File hash (optional)
    /// @param certThumbprint Certificate thumbprint (optional)
    /// @param publisher Publisher name (optional)
    /// @param options Query options
    /// @return Lookup result (first match wins)
    [[nodiscard]] LookupResult IsWhitelisted(
        std::wstring_view filePath,
        const HashValue* fileHash = nullptr,
        const std::array<uint8_t, 32>* certThumbprint = nullptr,
        std::wstring_view publisher = {},
        const QueryOptions& options = {}
    ) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    /// @brief Add hash to whitelist
    [[nodiscard]] StoreError AddHash(
        const HashValue& hash,
        WhitelistReason reason,
        std::wstring_view description = {},
        uint64_t expirationTime = 0,  // 0 = never expires
        uint32_t policyId = 0
    ) noexcept;
    
    /// @brief Add hash from string
    [[nodiscard]] StoreError AddHash(
        const std::string& hashString,
        HashAlgorithm algorithm,
        WhitelistReason reason,
        std::wstring_view description = {},
        uint64_t expirationTime = 0,
        uint32_t policyId = 0
    ) noexcept;
    
    /// @brief Add path to whitelist
    [[nodiscard]] StoreError AddPath(
        std::wstring_view path,
        PathMatchMode matchMode,
        WhitelistReason reason,
        std::wstring_view description = {},
        uint64_t expirationTime = 0,
        uint32_t policyId = 0
    ) noexcept;
    
    /// @brief Add certificate thumbprint to whitelist
    [[nodiscard]] StoreError AddCertificate(
        const std::array<uint8_t, 32>& thumbprint,
        WhitelistReason reason,
        std::wstring_view description = {},
        uint64_t expirationTime = 0,
        uint32_t policyId = 0
    ) noexcept;
    
    /// @brief Add publisher to whitelist
    [[nodiscard]] StoreError AddPublisher(
        std::wstring_view publisherName,
        WhitelistReason reason,
        std::wstring_view description = {},
        uint64_t expirationTime = 0,
        uint32_t policyId = 0
    ) noexcept;
    
    /// @brief Remove entry by ID
    [[nodiscard]] StoreError RemoveEntry(uint64_t entryId) noexcept;
    
    /// @brief Remove hash from whitelist
    [[nodiscard]] StoreError RemoveHash(const HashValue& hash) noexcept;
    
    /// @brief Remove path from whitelist
    [[nodiscard]] StoreError RemovePath(
        std::wstring_view path,
        PathMatchMode matchMode
    ) noexcept;
    
    /// @brief Batch add entries (transactional)
    [[nodiscard]] StoreError BatchAdd(
        std::span<const WhitelistEntry> entries
    ) noexcept;
    
    /// @brief Update entry flags
    [[nodiscard]] StoreError UpdateEntryFlags(
        uint64_t entryId,
        WhitelistFlags flags
    ) noexcept;
    
    /// @brief Revoke entry (soft delete)
    [[nodiscard]] StoreError RevokeEntry(uint64_t entryId) noexcept;
    
    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================
    
    /// @brief Import entries from JSON file
    [[nodiscard]] StoreError ImportFromJSON(
        const std::wstring& filePath,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;
    
    /// @brief Import entries from JSON string
    [[nodiscard]] StoreError ImportFromJSONString(
        std::string_view jsonData,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;
    
    /// @brief Import entries from CSV file
    [[nodiscard]] StoreError ImportFromCSV(
        const std::wstring& filePath,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;
    
    /// @brief Export entries to JSON file
    [[nodiscard]] StoreError ExportToJSON(
        const std::wstring& filePath,
        WhitelistEntryType typeFilter = WhitelistEntryType::Reserved,  // Reserved = all types
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) const noexcept;
    
    /// @brief Export entries to JSON string
    [[nodiscard]] std::string ExportToJSONString(
        WhitelistEntryType typeFilter = WhitelistEntryType::Reserved,
        uint32_t maxEntries = UINT32_MAX
    ) const noexcept;
    
    /// @brief Export entries to CSV file
    [[nodiscard]] StoreError ExportToCSV(
        const std::wstring& filePath,
        WhitelistEntryType typeFilter = WhitelistEntryType::Reserved,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) const noexcept;
    
    // ========================================================================
    // MAINTENANCE
    // ========================================================================
    
    /// @brief Purge expired entries
    [[nodiscard]] StoreError PurgeExpired() noexcept;
    
    /// @brief Compact database (remove fragmentation)
    [[nodiscard]] StoreError Compact() noexcept;
    
    /// @brief Rebuild all indices
    [[nodiscard]] StoreError RebuildIndices() noexcept;
    
    /// @brief Verify database integrity
    [[nodiscard]] StoreError VerifyIntegrity(
        std::function<void(const std::string&)> logCallback = nullptr
    ) const noexcept;
    
    /// @brief Update database checksum
    [[nodiscard]] StoreError UpdateChecksum() noexcept;
    
    /// @brief Clear query cache
    void ClearCache() noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /// @brief Get store statistics
    [[nodiscard]] WhitelistStatistics GetStatistics() const noexcept;
    
    /// @brief Get entry by ID
    [[nodiscard]] std::optional<WhitelistEntry> GetEntry(uint64_t entryId) const noexcept;
    
    /// @brief Get all entries (paginated)
    [[nodiscard]] std::vector<WhitelistEntry> GetEntries(
        size_t offset = 0,
        size_t limit = 1000,
        WhitelistEntryType typeFilter = WhitelistEntryType::Reserved
    ) const noexcept;
    
    /// @brief Get entry count
    [[nodiscard]] uint64_t GetEntryCount() const noexcept;
    
    /// @brief Get database path
    [[nodiscard]] const std::wstring& GetDatabasePath() const noexcept {
        return m_databasePath;
    }
    
    /// @brief Get database header
    [[nodiscard]] const WhitelistDatabaseHeader* GetHeader() const noexcept;
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /// @brief Enable/disable query caching
    void SetCachingEnabled(bool enabled) noexcept {
        m_cachingEnabled.store(enabled, std::memory_order_release);
    }
    
    /// @brief Enable/disable bloom filter
    void SetBloomFilterEnabled(bool enabled) noexcept {
        m_bloomFilterEnabled.store(enabled, std::memory_order_release);
    }
    
    /// @brief Set cache size
    void SetCacheSize(size_t entries) noexcept;
    
    /// @brief Register callback for entry matches (for audit logging)
    using MatchCallback = std::function<void(const LookupResult&, std::wstring_view context)>;
    void SetMatchCallback(MatchCallback callback) noexcept {
        std::lock_guard lock(m_callbackMutex);
        m_matchCallback = std::move(callback);
    }
    
private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================
    
    /// @brief Initialize indices after loading
    [[nodiscard]] StoreError InitializeIndices() noexcept;
    
    /// @brief Lookup in query cache (SeqLock read)
    [[nodiscard]] std::optional<LookupResult> GetFromCache(const HashValue& hash) const noexcept;
    
    /// @brief Add result to cache
    void AddToCache(const HashValue& hash, const LookupResult& result) const noexcept;
    
    /// @brief Allocate new entry
    [[nodiscard]] WhitelistEntry* AllocateEntry() noexcept;
    
    /// @brief Get next entry ID
    [[nodiscard]] uint64_t GetNextEntryId() noexcept;
    
    /// @brief Update header statistics
    void UpdateHeaderStats() noexcept;
    
    /// @brief Record lookup timing
    void RecordLookupTime(uint64_t nanoseconds) const noexcept;
    
    /// @brief Invoke match callback if set
    void NotifyMatch(const LookupResult& result, std::wstring_view context) const noexcept;
    
    // ========================================================================
    // INTERNAL STATE
    // ========================================================================
    
    std::wstring m_databasePath;
    MemoryMappedView m_mappedView{};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_readOnly{true};
    
    // Indices
    std::unique_ptr<BloomFilter> m_hashBloomFilter;
    std::unique_ptr<BloomFilter> m_pathBloomFilter;
    std::unique_ptr<HashIndex> m_hashIndex;
    std::unique_ptr<PathIndex> m_pathIndex;
    std::unique_ptr<StringPool> m_stringPool;
    
    // Query cache (LRU with SeqLock)
    static constexpr size_t DEFAULT_CACHE_SIZE = QUERY_CACHE_SIZE;
    mutable std::vector<CacheEntry> m_queryCache;
    mutable std::atomic<uint64_t> m_cacheAccessCounter{0};
    std::atomic<bool> m_cachingEnabled{true};
    std::atomic<bool> m_bloomFilterEnabled{true};
    
    // Entry allocation
    std::atomic<uint64_t> m_nextEntryId{1};
    std::atomic<uint64_t> m_entryDataUsed{0};
    
    // Statistics (atomic for thread-safety)
    mutable std::atomic<uint64_t> m_totalLookups{0};
    mutable std::atomic<uint64_t> m_cacheHits{0};
    mutable std::atomic<uint64_t> m_cacheMisses{0};
    mutable std::atomic<uint64_t> m_bloomHits{0};
    mutable std::atomic<uint64_t> m_bloomRejects{0};
    mutable std::atomic<uint64_t> m_totalHits{0};
    mutable std::atomic<uint64_t> m_totalMisses{0};
    mutable std::atomic<uint64_t> m_totalLookupTimeNs{0};
    mutable std::atomic<uint64_t> m_minLookupTimeNs{UINT64_MAX};
    mutable std::atomic<uint64_t> m_maxLookupTimeNs{0};
    
    // Synchronization
    mutable std::shared_mutex m_globalLock;      // For major operations
    mutable std::mutex m_entryAllocMutex;        // For entry allocation
    mutable std::mutex m_callbackMutex;          // For callback
    
    // Callbacks
    MatchCallback m_matchCallback;
    
    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};
};

// ============================================================================
// BUILDER PATTERN FOR COMPLEX WHITELIST ENTRIES
// ============================================================================

/// @brief Builder for constructing whitelist entries with validation
/// @note Move-only builder to handle non-copyable WhitelistEntry with std::atomic
/// @solution Use in-place construction via callback or explicit member setup
class WhitelistEntryBuilder {
public:
    WhitelistEntryBuilder() = default;
    
    // Move-only semantics
    WhitelistEntryBuilder(WhitelistEntryBuilder&&) = default;
    WhitelistEntryBuilder& operator=(WhitelistEntryBuilder&&) = default;
    
    // Disable copy
    WhitelistEntryBuilder(const WhitelistEntryBuilder&) = delete;
    WhitelistEntryBuilder& operator=(const WhitelistEntryBuilder&) = delete;
    
    /// @brief Set entry type
    WhitelistEntryBuilder& SetType(WhitelistEntryType type) noexcept {
        m_type = type;
        return *this;
    }
    
    /// @brief Set reason
    WhitelistEntryBuilder& SetReason(WhitelistReason reason) noexcept {
        m_reason = reason;
        return *this;
    }
    
    /// @brief Set hash
    WhitelistEntryBuilder& SetHash(const HashValue& hash) noexcept {
        m_hash = hash;
        return *this;
    }
    
    /// @brief Set flags
    WhitelistEntryBuilder& SetFlags(WhitelistFlags flags) noexcept {
        m_flags = flags;
        return *this;
    }
    
    /// @brief Add flag
    WhitelistEntryBuilder& AddFlag(WhitelistFlags flag) noexcept {
        m_flags = m_flags | flag;
        return *this;
    }
    
    /// @brief Set expiration (Unix timestamp)
    WhitelistEntryBuilder& SetExpiration(uint64_t timestamp) noexcept {
        m_expirationTime = timestamp;
        if (timestamp > 0) {
            m_flags = m_flags | WhitelistFlags::HasExpiration;
        }
        return *this;
    }
    
    /// @brief Set expiration (duration from now)
    WhitelistEntryBuilder& SetExpirationDuration(std::chrono::seconds duration) noexcept {
        auto now = std::chrono::system_clock::now();
        auto expiry = now + duration;
        m_expirationTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                expiry.time_since_epoch()
            ).count()
        );
        m_flags = m_flags | WhitelistFlags::HasExpiration;
        return *this;
    }
    
    /// @brief Set policy ID
    WhitelistEntryBuilder& SetPolicyId(uint32_t policyId) noexcept {
        m_policyId = policyId;
        return *this;
    }
    
    /// @brief Set path match mode
    WhitelistEntryBuilder& SetPathMatchMode(PathMatchMode mode) noexcept {
        m_matchMode = mode;
        return *this;
    }
    
    /// @brief Apply builder configuration to an existing WhitelistEntry
    /// @note Safe method that avoids copy/move constructor issues
    /// @param[out] entry Target entry to configure
    void ApplyTo(WhitelistEntry& entry) const noexcept {
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()
        ).count();
        uint64_t currentTime = static_cast<uint64_t>(epoch);
        
        // Initialize all members explicitly (safe approach)
        entry.entryId = 0;  // Will be set by store when adding
        entry.type = m_type;
        entry.reason = m_reason;
        entry.matchMode = m_matchMode;
        entry.reserved1 = 0;
        entry.flags = m_flags;
        entry.hashAlgorithm = m_hash.algorithm;
        entry.hashLength = m_hash.length;
        entry.hashReserved[0] = 0;
        entry.hashReserved[1] = 0;
        
        // Copy hash data safely
        std::memcpy(entry.hashData.data(), m_hash.data.data(), 
                   std::min<size_t>(m_hash.length, entry.hashData.size()));
        
        entry.createdTime = currentTime;
        entry.modifiedTime = currentTime;
        entry.expirationTime = m_expirationTime;
        entry.pathOffset = 0;
        entry.pathLength = 0;
        entry.descriptionOffset = 0;
        entry.descriptionLength = 0;
        entry.createdByOffset = 0;
        entry.policyId = m_policyId;
        entry.hitCount.store(0, std::memory_order_release);
        entry.reserved2[0] = 0;
        entry.reserved2[1] = 0;
    }
    
    // Deleted to prevent accidental copies
    [[nodiscard]] WhitelistEntry Build() const noexcept = delete;
    
    /// @brief Build entry by applying to reference
    /// @param[out] entry Pre-allocated entry to populate
    /// @return Reference to the populated entry
    WhitelistEntry& BuildInto(WhitelistEntry& entry) const noexcept {
        ApplyTo(entry);
        return entry;
    }
    
private:
    // Configuration data (trivially copyable)
    WhitelistEntryType m_type{WhitelistEntryType::Reserved};
    WhitelistReason m_reason{WhitelistReason::Custom};
    PathMatchMode m_matchMode{PathMatchMode::Exact};
    WhitelistFlags m_flags{WhitelistFlags::Enabled};
    HashValue m_hash{};
    uint64_t m_expirationTime{0};
    uint32_t m_policyId{0};
};

} // namespace Whitelist
} // namespace ShadowStrike
