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
 * Thread Safety:
 * - All public methods are thread-safe unless explicitly documented otherwise
 * - Uses reader-writer locks for concurrent read access
 * - SeqLock pattern for lock-free cache reads
 * - Atomic operations for statistics counters
 *
 * Security Considerations:
 * - All input paths are normalized and validated
 * - Bounds checking on all index operations
 * - No raw pointer arithmetic without validation
 * - CRC32/SHA256 integrity verification
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
#include <span>
#include <optional>
#include <chrono>
#include <array>

namespace ShadowStrike {
namespace Whitelist {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class BloomFilter;
class HashIndex;
class PathIndex;
class CertificateIndex;
class PublisherIndex;
class StringPool;

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

/// @brief Maximum expected bloom filter elements (for validation)
inline constexpr size_t MAX_BLOOM_EXPECTED_ELEMENTS = 100'000'000;

/// @brief Minimum bloom filter false positive rate
inline constexpr double MIN_BLOOM_FPR = 0.000001;  // 0.0001%

/// @brief Maximum bloom filter false positive rate  
inline constexpr double MAX_BLOOM_FPR = 0.1;       // 10%

/// @brief Default bloom filter hash function count
inline constexpr size_t DEFAULT_BLOOM_HASH_COUNT = 7;

/// @brief Minimum bloom filter bits (1MB)
inline constexpr size_t MIN_BLOOM_BITS = 8ULL * 1024 * 1024;

/// @brief Maximum bloom filter bits (64MB)
inline constexpr size_t MAX_BLOOM_BITS = 512ULL * 1024 * 1024;

/// @brief Minimum hash count for bloom filter
inline constexpr size_t MIN_BLOOM_HASHES = 3;

/// @brief Maximum hash count for bloom filter  
inline constexpr size_t MAX_BLOOM_HASHES = 16;

// ============================================================================
// BLOOM FILTER STATISTICS (for GetDetailedStats)
// ============================================================================

/**
 * @brief Detailed statistics for BloomFilter monitoring and diagnostics
 */
struct BloomFilterStats {
    size_t bitCount = 0;              ///< Total number of bits in filter
    size_t hashFunctions = 0;         ///< Number of hash functions
    size_t expectedElements = 0;      ///< Expected element count (design parameter)
    uint64_t elementsAdded = 0;       ///< Approximate number of elements added
    size_t memoryBytes = 0;           ///< Current memory usage in bytes
    size_t allocatedBytes = 0;        ///< Total allocated bytes (may be > memoryBytes)
    double targetFPR = 0.0;           ///< Target false positive rate
    double estimatedFPR = 0.0;        ///< Estimated current false positive rate
    double fillRate = 0.0;            ///< Proportion of bits set (0.0 - 1.0)
    double loadFactor = 0.0;          ///< elementsAdded / expectedElements
    bool isMemoryMapped = false;      ///< Using external memory-mapped storage
    bool isReady = false;             ///< Filter is initialized and ready for use
};

// ============================================================================
// BLOOM FILTER (Nanosecond-level negative lookups)
// ============================================================================

/**
 * @brief High-performance Bloom filter for fast negative lookups
 * 
 * Thread-safety: 
 * - Add() is thread-safe via atomic OR operations
 * - MightContain() is lock-free and safe for concurrent reads
 * - Clear() is NOT thread-safe and requires external synchronization
 * 
 * Performance:
 * - Add: O(k) where k = number of hash functions
 * - MightContain: O(k) with early termination on first zero bit
 * 
 * Memory: Configurable from 1MB to 64MB bit array
 */
class BloomFilter {
public:
    /// @brief Construct bloom filter with expected elements and target false positive rate
    /// @param expectedElements Expected number of elements to add (clamped to valid range)
    /// @param falsePositiveRate Target false positive rate (0.0 - 1.0, clamped to valid range)
    /// @note Parameters are automatically clamped to safe ranges
    explicit BloomFilter(
        size_t expectedElements = 1'000'000,
        double falsePositiveRate = 0.0001  // 0.01%
    );
    
    /// @brief Default destructor - releases bit array memory
    ~BloomFilter() = default;
    
    // ========================================================================
    // NON-COPYABLE (large memory footprint, atomic members)
    // ========================================================================
    BloomFilter(const BloomFilter&) = delete;
    BloomFilter& operator=(const BloomFilter&) = delete;
    
    // ========================================================================
    // MOVABLE
    // ========================================================================
    BloomFilter(BloomFilter&& other) noexcept;
    BloomFilter& operator=(BloomFilter&& other) noexcept;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /**
     * @brief Initialize from memory-mapped region (read-only mode)
     * @param data Pointer to bloom filter bit array (must remain valid)
     * @param bitCount Number of bits in the filter (must be > 0)
     * @param hashFunctions Number of hash functions used (3-16)
     * @return True if initialization succeeded, false on invalid parameters
     * @note Does NOT take ownership of the memory
     */
    [[nodiscard]] bool Initialize(
        const void* data,
        size_t bitCount,
        size_t hashFunctions
    ) noexcept;
    
    /**
     * @brief Initialize for building (allocates internal memory)
     * @return True if allocation succeeded, false on out-of-memory
     * @note Call after constructor to allocate the bit array
     */
    [[nodiscard]] bool InitializeForBuild() noexcept;
    
    // ========================================================================
    // OPERATIONS
    // ========================================================================
    
    /**
     * @brief Add element to filter (thread-safe via atomics)
     * @param hash 64-bit hash of element
     * @note No-op if filter is memory-mapped or not initialized
     */
    void Add(uint64_t hash) noexcept;
    
    /**
     * @brief Add hash value to filter
     * @param hashValue HashValue structure
     */
    void Add(const HashValue& hashValue) noexcept {
        if (!hashValue.IsEmpty()) {
            Add(hashValue.FastHash());
        }
    }
    
    /**
     * @brief Check if element might exist (false positives possible)
     * @param hash 64-bit hash of element
     * @return False = definitely not in set, True = might be in set
     * @note Returns true (conservative) if not initialized
     */
    [[nodiscard]] bool MightContain(uint64_t hash) const noexcept;
    
    /**
     * @brief Check if hash value might exist
     * @param hashValue HashValue structure
     * @return False = definitely not in set, True = might be in set
     */
    [[nodiscard]] bool MightContain(const HashValue& hashValue) const noexcept {
        if (hashValue.IsEmpty()) {
            return false;  // Empty hash is never in the filter
        }
        return MightContain(hashValue.FastHash());
    }
    
    /**
     * @brief Clear all bits (NOT thread-safe)
     * @note Requires external synchronization if other threads may access
     */
    void Clear() noexcept;
    
    /**
     * @brief Serialize to byte array
     * @param[out] data Output buffer (resized to fit)
     * @return True if serialization succeeded, false if memory-mapped or empty
     * @throws std::bad_alloc if allocation fails
     */
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
        return m_isMemoryMapped ? 0 : (m_bits.size() * sizeof(std::atomic<uint64_t>)); 
    }
    
    /// @brief Get expected element count
    [[nodiscard]] size_t GetExpectedElements() const noexcept { return m_expectedElements; }
    
    /// @brief Get target false positive rate
    [[nodiscard]] double GetTargetFPR() const noexcept { return m_targetFPR; }
    
    /// @brief Get elements added count (approximate)
    [[nodiscard]] uint64_t GetElementsAdded() const noexcept { 
        return m_elementsAdded.load(std::memory_order_relaxed); 
    }
    
    /// @brief Check if using memory-mapped storage
    [[nodiscard]] bool IsMemoryMapped() const noexcept { return m_isMemoryMapped; }
    
    /// @brief Check if filter is initialized and ready
    [[nodiscard]] bool IsReady() const noexcept {
        return m_bitCount > 0 && m_numHashes > 0 && 
               (m_isMemoryMapped ? (m_mappedBits != nullptr) : !m_bits.empty());
    }
    
    /// @brief Estimate fill rate (0.0 - 1.0)
    [[nodiscard]] double EstimatedFillRate() const noexcept;
    
    /// @brief Estimate current false positive rate
    [[nodiscard]] double EstimatedFalsePositiveRate() const noexcept;
    
    // ========================================================================
    // BATCH OPERATIONS (Enterprise Feature)
    // ========================================================================
    
    /**
     * @brief Add multiple elements efficiently
     * @param hashes Span of hash values to add
     * @return Number of elements successfully added
     * @note Thread-safe, uses cache-optimized access patterns
     */
    [[nodiscard]] size_t BatchAdd(std::span<const uint64_t> hashes) noexcept;
    
    /**
     * @brief Query multiple elements efficiently
     * @param hashes Span of hash values to query
     * @param results Output span for results (true = might contain, false = definitely not)
     * @return Number of elements that might be contained (positive results)
     * @note Thread-safe, uses prefetching for better cache behavior
     */
    [[nodiscard]] size_t BatchQuery(
        std::span<const uint64_t> hashes,
        std::span<bool> results
    ) const noexcept;
    
    /**
     * @brief Get detailed statistics about the bloom filter
     * @return BloomFilterStats structure with all metrics
     */
    [[nodiscard]] struct BloomFilterStats GetDetailedStats() const noexcept;
    
private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================
    
    /**
     * @brief Compute hash with seed (double hashing scheme)
     * @param value Input value to hash
     * @param seed Seed for this hash iteration
     * @return Combined hash value
     */
    [[nodiscard]] uint64_t Hash(uint64_t value, size_t seed) const noexcept;
    
    /**
     * @brief Calculate optimal parameters for given constraints
     * @param expectedElements Expected number of elements
     * @param falsePositiveRate Target FPR
     */
    void CalculateOptimalParameters(size_t expectedElements, double falsePositiveRate) noexcept;
    
    // ========================================================================
    // MEMBER DATA
    // ========================================================================
    
    std::vector<std::atomic<uint64_t>> m_bits;  ///< Bit array (atomic for thread-safety)
    const uint64_t* m_mappedBits{nullptr};      ///< Pointer to memory-mapped bits (not owned)
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

/**
 * @brief B+Tree index for hash-based lookups
 * 
 * Provides O(log N) lookup time with cache-friendly node layout.
 * 
 * Thread-safety:
 * - All query operations use shared_lock (concurrent reads allowed)
 * - Modification operations use unique_lock (exclusive access)
 * 
 * Memory layout:
 * - Header: 64 bytes (root offset, node count, entry count, next node, depth)
 * - Nodes: sizeof(BPlusTreeNode) each, aligned to cache line
 * 
 * Limitations:
 * - Maximum tree depth: 32 levels
 * - Maximum keys per node: BPlusTreeNode::MAX_KEYS
 */
class HashIndex {
public:
    HashIndex();
    ~HashIndex();
    
    // ========================================================================
    // NON-COPYABLE
    // ========================================================================
    HashIndex(const HashIndex&) = delete;
    HashIndex& operator=(const HashIndex&) = delete;
    
    // ========================================================================
    // MOVABLE
    // ========================================================================
    HashIndex(HashIndex&& other) noexcept;
    HashIndex& operator=(HashIndex&& other) noexcept;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /**
     * @brief Initialize from memory-mapped region (read-only)
     * @param view Valid memory-mapped view
     * @param offset Offset within view to index data
     * @param size Size of index region in bytes
     * @return Success or error code with message
     */
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    /**
     * @brief Create new index in writable memory
     * @param baseAddress Writable memory base address
     * @param availableSize Available space in bytes
     * @param[out] usedSize Actual bytes used after creation
     * @return Success or error code with message
     */
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // QUERY OPERATIONS
    // ========================================================================
    
    /**
     * @brief Lookup hash and return entry offset
     * @param hash Hash value to look up
     * @return Entry offset if found, nullopt otherwise
     * @note Thread-safe (shared lock)
     */
    [[nodiscard]] std::optional<uint64_t> Lookup(const HashValue& hash) const noexcept;
    
    /**
     * @brief Check if hash exists (without fetching offset)
     * @param hash Hash value to check
     * @return True if hash exists in index
     */
    [[nodiscard]] bool Contains(const HashValue& hash) const noexcept;
    
    /**
     * @brief Batch lookup for multiple hashes (cache-friendly)
     * @param hashes Span of hash values to look up
     * @param[out] results Vector of results (resized to match input)
     * @note More efficient than individual lookups due to lock amortization
     */
    void BatchLookup(
        std::span<const HashValue> hashes,
        std::vector<std::optional<uint64_t>>& results
    ) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    /**
     * @brief Insert hash with entry offset
     * @param hash Hash value to insert
     * @param entryOffset Offset of associated entry
     * @return Success or error code
     * @note Thread-safe (exclusive lock), updates existing if duplicate
     */
    [[nodiscard]] StoreError Insert(
        const HashValue& hash,
        uint64_t entryOffset
    ) noexcept;
    
    /**
     * @brief Remove hash from index
     * @param hash Hash value to remove
     * @return Success or error code
     */
    [[nodiscard]] StoreError Remove(const HashValue& hash) noexcept;
    
    /**
     * @brief Batch insert (more efficient than individual inserts)
     * @param entries Span of (hash, offset) pairs
     * @return Success or first error encountered
     */
    [[nodiscard]] StoreError BatchInsert(
        std::span<const std::pair<HashValue, uint64_t>> entries
    ) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetEntryCount() const noexcept { 
        return m_entryCount.load(std::memory_order_acquire); 
    }
    [[nodiscard]] uint64_t GetNodeCount() const noexcept { 
        return m_nodeCount.load(std::memory_order_acquire); 
    }
    [[nodiscard]] uint32_t GetTreeDepth() const noexcept { return m_treeDepth; }
    
    /// @brief Check if index is initialized
    [[nodiscard]] bool IsReady() const noexcept {
        return (m_view != nullptr) || (m_baseAddress != nullptr);
    }
    
    /// @brief Check if index is writable
    [[nodiscard]] bool IsWritable() const noexcept {
        return m_baseAddress != nullptr;
    }
    
private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================
    
    /// @brief Find leaf node containing key (const version)
    [[nodiscard]] const BPlusTreeNode* FindLeaf(uint64_t key) const noexcept;
    
    /// @brief Find leaf node (mutable version for inserts)
    [[nodiscard]] BPlusTreeNode* FindLeafMutable(uint64_t key) noexcept;
    
    /// @brief Split node when full
    [[nodiscard]] StoreError SplitNode(BPlusTreeNode* node) noexcept;
    
    /// @brief Allocate new node from available space
    [[nodiscard]] BPlusTreeNode* AllocateNode() noexcept;
    
    /// @brief Validate offset is within bounds
    [[nodiscard]] bool IsOffsetValid(uint64_t offset) const noexcept;
    
    // ========================================================================
    // MEMBER DATA
    // ========================================================================
    
    const MemoryMappedView* m_view{nullptr};  ///< Read-only view (not owned)
    void* m_baseAddress{nullptr};              ///< Writable base (not owned)
    uint64_t m_rootOffset{0};                  ///< Offset of root node
    uint64_t m_indexOffset{0};                 ///< Offset within view/base
    uint64_t m_indexSize{0};                   ///< Total index size
    uint64_t m_nextNodeOffset{0};              ///< Next free node offset
    uint32_t m_treeDepth{0};                   ///< Current tree depth
    std::atomic<uint64_t> m_entryCount{0};     ///< Number of entries
    std::atomic<uint64_t> m_nodeCount{0};      ///< Number of nodes
    mutable std::shared_mutex m_rwLock;         ///< Reader-writer lock
    
    /// @brief Maximum tree depth to prevent infinite loops
    static constexpr uint32_t MAX_TREE_DEPTH = 32;
};

// ============================================================================
// PATH INDEX (Compressed Trie for path matching)
// ============================================================================

/**
 * @brief Compressed Trie index for path-based lookups
 * 
 * Supports multiple match modes:
 * - Exact: Full path must match exactly
 * - Prefix: Path starts with pattern
 * - Suffix: Path ends with pattern
 * - Glob: Wildcard matching (* and ?)
 * - Regex: Full regular expression (when enabled)
 * 
 * Thread-safety:
 * - All query operations use shared_lock
 * - Modification operations use unique_lock
 */
class PathIndex {
public:
    PathIndex();
    ~PathIndex();
    
    // ========================================================================
    // NON-COPYABLE
    // ========================================================================
    PathIndex(const PathIndex&) = delete;
    PathIndex& operator=(const PathIndex&) = delete;
    
    // ========================================================================
    // MOVABLE
    // ========================================================================
    PathIndex(PathIndex&& other) noexcept;
    PathIndex& operator=(PathIndex&& other) noexcept;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /**
     * @brief Initialize from memory-mapped region
     * @param view Valid memory-mapped view
     * @param offset Offset within view to index data
     * @param size Size of index region in bytes
     * @return Success or error code
     */
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    /**
     * @brief Create new index in writable memory
     * @param baseAddress Writable memory base address
     * @param availableSize Available space in bytes
     * @param[out] usedSize Actual bytes used after creation
     * @return Success or error code
     */
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // QUERY OPERATIONS
    // ========================================================================
    
    /**
     * @brief Lookup path and return matching entry offsets
     * @param path Path to look up (normalized internally)
     * @param mode Match mode (Exact, Prefix, Suffix, Glob)
     * @return Vector of matching entry offsets (may be empty)
     */
    [[nodiscard]] std::vector<uint64_t> Lookup(
        std::wstring_view path,
        PathMatchMode mode = PathMatchMode::Exact
    ) const noexcept;
    
    /**
     * @brief Check if path matches any pattern
     * @param path Path to check
     * @param mode Match mode
     * @return True if any match exists
     */
    [[nodiscard]] bool Contains(
        std::wstring_view path,
        PathMatchMode mode = PathMatchMode::Exact
    ) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    /**
     * @brief Insert path with entry offset
     * @param path Path pattern to insert
     * @param mode Match mode for this pattern
     * @param entryOffset Associated entry offset
     * @return Success or error code
     */
    [[nodiscard]] StoreError Insert(
        std::wstring_view path,
        PathMatchMode mode,
        uint64_t entryOffset
    ) noexcept;
    
    /**
     * @brief Remove path from index
     * @param path Path pattern to remove
     * @param mode Match mode of the pattern
     * @return Success or error code
     */
    [[nodiscard]] StoreError Remove(
        std::wstring_view path,
        PathMatchMode mode
    ) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetPathCount() const noexcept { 
        return m_pathCount.load(std::memory_order_acquire); 
    }
    [[nodiscard]] uint64_t GetNodeCount() const noexcept { 
        return m_nodeCount.load(std::memory_order_acquire); 
    }
    
    /// @brief Check if index is initialized
    [[nodiscard]] bool IsReady() const noexcept {
        return (m_view != nullptr) || (m_baseAddress != nullptr);
    }
    
private:
    // ========================================================================
    // INTERNAL TYPES
    // ========================================================================
    struct TrieNode;
    
    // ========================================================================
    // MEMBER DATA
    // ========================================================================
    
    const MemoryMappedView* m_view{nullptr};  ///< Read-only view (not owned)
    void* m_baseAddress{nullptr};              ///< Writable base (not owned)
    uint64_t m_rootOffset{0};                  ///< Offset of root node
    uint64_t m_indexOffset{0};                 ///< Offset within view/base
    uint64_t m_indexSize{0};                   ///< Total index size
    std::atomic<uint64_t> m_pathCount{0};      ///< Number of paths
    std::atomic<uint64_t> m_nodeCount{0};      ///< Number of nodes
    mutable std::shared_mutex m_rwLock;         ///< Reader-writer lock
};

// ============================================================================
// QUERY CACHE (LRU with SeqLock for lock-free reads)
// ============================================================================

/**
 * @brief Query result cache entry with SeqLock for lock-free concurrent reads
 * 
 * SeqLock Protocol:
 * - Writers: BeginWrite() -> modify -> EndWrite()
 * - Readers: read seqlock -> read data -> verify seqlock unchanged
 * 
 * @note Aligned to cache line to prevent false sharing
 */
struct alignas(CACHE_LINE_SIZE) CacheEntry {
    /// @brief SeqLock: odd = writing, even = valid for reading
    mutable std::atomic<uint64_t> seqlock{0};
    
    /// @brief Cached hash value
    HashValue hash{};
    
    /// @brief Cached lookup result
    LookupResult result{};
    
    /// @brief Access timestamp for LRU eviction
    uint64_t accessTime{0};
    
    /// @brief Padding to ensure cache line alignment
    uint8_t _padding[8]{};
    
    /**
     * @brief Check if entry is valid (not being written)
     * @return True if seqlock is even (no writer active)
     */
    [[nodiscard]] bool IsValid() const noexcept {
        return (seqlock.load(std::memory_order_acquire) & 1ULL) == 0;
    }
    
    /**
     * @brief Begin write (acquire lock)
     * @note Must be followed by EndWrite() even if write fails
     */
    void BeginWrite() noexcept {
        // Increment to odd value (writer active)
        seqlock.fetch_add(1, std::memory_order_release);
        // Memory barrier to ensure visibility
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }
    
    /**
     * @brief End write (release lock)
     * @note Must be called after BeginWrite()
     */
    void EndWrite() noexcept {
        // Memory barrier before incrementing
        std::atomic_thread_fence(std::memory_order_seq_cst);
        // Increment to even value (writer done)
        seqlock.fetch_add(1, std::memory_order_release);
    }
    
    /**
     * @brief Get current sequence number for read validation
     * @return Current seqlock value
     */
    [[nodiscard]] uint64_t GetSequence() const noexcept {
        return seqlock.load(std::memory_order_acquire);
    }
    
    /**
     * @brief Validate read was consistent
     * @param startSeq Sequence number from before read
     * @return True if data is consistent (no concurrent write)
     */
    [[nodiscard]] bool ValidateRead(uint64_t startSeq) const noexcept {
        std::atomic_thread_fence(std::memory_order_acquire);
        return (startSeq & 1ULL) == 0 && 
               seqlock.load(std::memory_order_acquire) == startSeq;
    }
    
    /// @brief Reset entry to default state
    void Reset() noexcept {
        BeginWrite();
        hash = HashValue{};
        result = LookupResult{};
        accessTime = 0;
        EndWrite();
    }
};

// Verify cache entry fits in reasonable cache lines
static_assert(sizeof(CacheEntry) <= 4 * CACHE_LINE_SIZE, 
    "CacheEntry should fit in 4 cache lines or less");

// ============================================================================
// STRING POOL (Deduplicated string storage)
// ============================================================================

/**
 * @brief Deduplicated string storage for paths, descriptions, etc.
 * 
 * Features:
 * - FNV-1a hash-based deduplication
 * - Supports both narrow (UTF-8) and wide (UTF-16) strings
 * - Thread-safe with reader-writer lock
 * 
 * Layout:
 * - Header: 32 bytes (used size, string count, reserved)
 * - Data: Contiguous string storage with null terminators
 */
class StringPool {
public:
    StringPool();
    ~StringPool();
    
    // ========================================================================
    // NON-COPYABLE
    // ========================================================================
    StringPool(const StringPool&) = delete;
    StringPool& operator=(const StringPool&) = delete;
    
    // ========================================================================
    // MOVABLE
    // ========================================================================
    StringPool(StringPool&& other) noexcept;
    StringPool& operator=(StringPool&& other) noexcept;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /**
     * @brief Initialize from memory-mapped region
     * @param view Valid memory-mapped view
     * @param offset Offset within view to pool data
     * @param size Size of pool region in bytes
     * @return Success or error code
     */
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t offset,
        uint64_t size
    ) noexcept;
    
    /**
     * @brief Create new pool in writable memory
     * @param baseAddress Writable memory base address
     * @param availableSize Available space in bytes
     * @param[out] usedSize Actual bytes used after creation
     * @return Success or error code
     */
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;
    
    // ========================================================================
    // OPERATIONS
    // ========================================================================
    
    /**
     * @brief Get string at offset
     * @param offset Offset within pool
     * @param length Length in bytes
     * @return String view (empty if invalid offset)
     * @note Returned view is valid only while pool exists
     */
    [[nodiscard]] std::string_view GetString(uint32_t offset, uint16_t length) const noexcept;
    
    /**
     * @brief Get wide string at offset
     * @param offset Offset within pool
     * @param length Length in bytes (NOT characters)
     * @return Wide string view (empty if invalid offset)
     */
    [[nodiscard]] std::wstring_view GetWideString(uint32_t offset, uint16_t length) const noexcept;
    
    /**
     * @brief Add string and return offset (deduplicates)
     * @param str String to add
     * @return Offset if successful, nullopt if pool full
     * @note Empty strings return nullopt
     */
    [[nodiscard]] std::optional<uint32_t> AddString(std::string_view str) noexcept;
    
    /**
     * @brief Add wide string and return offset
     * @param str Wide string to add
     * @return Offset if successful, nullopt if pool full
     */
    [[nodiscard]] std::optional<uint32_t> AddWideString(std::wstring_view str) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] uint64_t GetUsedSize() const noexcept { 
        return m_usedSize.load(std::memory_order_acquire); 
    }
    [[nodiscard]] uint64_t GetTotalSize() const noexcept { return m_totalSize; }
    [[nodiscard]] uint64_t GetStringCount() const noexcept { 
        return m_stringCount.load(std::memory_order_acquire); 
    }
     [[nodiscard]] uint64_t GetfreeSpace() const noexcept {
        uint64_t used = m_usedSize.load(std::memory_order_acquire);
        return (used < m_totalSize) ? (m_totalSize - used) : 0;
    }
    
    /// @brief Check if pool is initialized
    [[nodiscard]] bool IsReady() const noexcept {
        return (m_view != nullptr) || (m_baseAddress != nullptr);
    }
    
private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================
    
    /// @brief Compute FNV-1a hash for deduplication
    [[nodiscard]] static uint64_t ComputeHash(const void* data, size_t length) noexcept;
    
    // ========================================================================
    // MEMBER DATA
    // ========================================================================
    
    const MemoryMappedView* m_view{nullptr};   ///< Read-only view (not owned)
    void* m_baseAddress{nullptr};               ///< Writable base (not owned)
    uint64_t m_poolOffset{0};                   ///< Offset within view/base
     uint64_t m_totalSize{0};                ///< Total pool size
    std::atomic<uint64_t> m_usedSize{0};        ///< Bytes used
    std::atomic<uint64_t> m_stringCount{0};     ///< Number of unique strings
    std::unordered_map<uint64_t, uint32_t> m_deduplicationMap; ///< hash -> offset
    mutable std::shared_mutex m_rwLock;          ///< Reader-writer lock
    
    /// @brief Header size for pool metadata
    static constexpr uint64_t HEADER_SIZE = 32;
    
    /// @brief Maximum string size to store
    static constexpr size_t MAX_STRING_SIZE = 64 * 1024;  // 64KB
};

// ============================================================================
// WHITELIST STORE (Main Interface)
// ============================================================================

/**
 * @brief Main whitelist store class - enterprise-grade implementation
 * 
 * Provides high-performance whitelist operations with:
 * - < 100ns hash lookup (with bloom filter pre-check)
 * - < 500ns path lookup (with trie index)
 * - Thread-safe concurrent access
 * - Memory-mapped storage for zero-copy reads
 * - LRU query cache with SeqLock
 * 
 * Thread Safety:
 * - All public methods are thread-safe
 * - Query methods use shared locks (concurrent reads)
 * - Modification methods use exclusive locks
 * - Statistics use atomic counters
 * 
 * Lifecycle:
 * 1. Construct WhitelistStore()
 * 2. Call Load() or Create()
 * 3. Perform operations
 * 4. Call Save() to persist changes (if writable)
 * 5. Call Close() or let destructor handle cleanup
 */
class WhitelistStore {
public:
    // ========================================================================
    // CONSTRUCTION / DESTRUCTION
    // ========================================================================
    
    /// @brief Default constructor - creates uninitialized store
    WhitelistStore();
    
    /// @brief Destructor - closes database and releases resources
    ~WhitelistStore();
    
    // ========================================================================
    // NON-COPYABLE
    // ========================================================================
    WhitelistStore(const WhitelistStore&) = delete;
    WhitelistStore& operator=(const WhitelistStore&) = delete;
    
    // ========================================================================
    // MOVABLE
    // ========================================================================
    WhitelistStore(WhitelistStore&& other) noexcept;
    WhitelistStore& operator=(WhitelistStore&& other) noexcept;
    
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
    [[nodiscard]] std::optional<Whitelist::WhitelistEntry> GetEntry(uint64_t entryId) const noexcept;
    
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

/**
 * @brief Builder for constructing whitelist entries with validation
 * 
 * Provides fluent API for building WhitelistEntry objects safely.
 * Avoids copy/move constructor issues with std::atomic members.
 * 
 * Usage:
 * @code
 * WhitelistEntry entry;
 * WhitelistEntryBuilder()
 *     .SetType(WhitelistEntryType::FileHash)
 *     .SetReason(WhitelistReason::TrustedVendor)
 *     .SetHash(hashValue)
 *     .SetExpirationDuration(std::chrono::hours(24 * 30))
 *     .ApplyTo(entry);
 * @endcode
 * 
 * @note Move-only to prevent accidental copies
 */
class WhitelistEntryBuilder {
public:
    /// @brief Default constructor - initializes with safe defaults
    WhitelistEntryBuilder() = default;
    
    /// @brief Destructor
    ~WhitelistEntryBuilder() = default;
    
    // ========================================================================
    // MOVE-ONLY SEMANTICS
    // ========================================================================
    WhitelistEntryBuilder(WhitelistEntryBuilder&&) noexcept = default;
    WhitelistEntryBuilder& operator=(WhitelistEntryBuilder&&) noexcept = default;
    
    // ========================================================================
    // NON-COPYABLE
    // ========================================================================
    WhitelistEntryBuilder(const WhitelistEntryBuilder&) = delete;
    WhitelistEntryBuilder& operator=(const WhitelistEntryBuilder&) = delete;
    
    // ========================================================================
    // FLUENT SETTERS
    // ========================================================================
    
    /**
     * @brief Set entry type
     * @param type Entry type (FileHash, FilePath, etc.)
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetType(WhitelistEntryType type) noexcept {
        m_type = type;
        return *this;
    }
    
    /**
     * @brief Set reason for whitelisting
     * @param reason Whitelist reason
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetReason(WhitelistReason reason) noexcept {
        m_reason = reason;
        return *this;
    }
    
    /**
     * @brief Set hash value
     * @param hash Hash value to set
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetHash(const HashValue& hash) noexcept {
        m_hash = hash;
        return *this;
    }
    
    /**
     * @brief Set entry flags
     * @param flags Flags to set (replaces existing)
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetFlags(WhitelistFlags flags) noexcept {
        m_flags = flags;
        return *this;
    }
    
    /**
     * @brief Add a flag (OR with existing)
     * @param flag Flag to add
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& AddFlag(WhitelistFlags flag) noexcept {
        m_flags = m_flags | flag;
        return *this;
    }
    
    /**
     * @brief Remove a flag (AND with complement)
     * @param flag Flag to remove
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& RemoveFlag(WhitelistFlags flag) noexcept {
        m_flags = static_cast<WhitelistFlags>(
            static_cast<uint32_t>(m_flags) & ~static_cast<uint32_t>(flag)
        );
        return *this;
    }
    
    /**
     * @brief Set expiration (Unix timestamp)
     * @param timestamp Unix timestamp (0 = never expires)
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetExpiration(uint64_t timestamp) noexcept {
        m_expirationTime = timestamp;
        if (timestamp > 0) {
            m_flags = m_flags | WhitelistFlags::HasExpiration;
        } else {
            RemoveFlag(WhitelistFlags::HasExpiration);
        }
        return *this;
    }
    
    /**
     * @brief Set expiration (duration from now)
     * @param duration Time until expiration
     * @return Reference to this builder
     * @note Automatically adds HasExpiration flag
     */
    WhitelistEntryBuilder& SetExpirationDuration(std::chrono::seconds duration) noexcept {
        if (duration.count() <= 0) {
            m_expirationTime = 0;
            RemoveFlag(WhitelistFlags::HasExpiration);
            return *this;
        }
        
        auto now = std::chrono::system_clock::now();
        auto expiry = now + duration;
        auto epochSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            expiry.time_since_epoch()
        ).count();
        
        // Validate timestamp is reasonable (not in distant past/future)
        constexpr int64_t MIN_EPOCH = 1577836800LL;  // 2020-01-01
        constexpr int64_t MAX_EPOCH = 4102444800LL;  // 2100-01-01
        
        if (epochSeconds < MIN_EPOCH || epochSeconds > MAX_EPOCH) {
            // Clamp to valid range
            epochSeconds = std::clamp(epochSeconds, MIN_EPOCH, MAX_EPOCH);
        }
        
        m_expirationTime = static_cast<uint64_t>(epochSeconds);
        m_flags = m_flags | WhitelistFlags::HasExpiration;
        return *this;
    }
    
    /**
     * @brief Set policy ID
     * @param policyId Policy identifier
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetPolicyId(uint32_t policyId) noexcept {
        m_policyId = policyId;
        return *this;
    }
    
    /**
     * @brief Set path match mode
     * @param mode Match mode (Exact, Prefix, Suffix, Glob, Regex)
     * @return Reference to this builder
     */
    WhitelistEntryBuilder& SetPathMatchMode(PathMatchMode mode) noexcept {
        m_matchMode = mode;
        return *this;
    }
    
    // ========================================================================
    // BUILD METHODS
    // ========================================================================
    
    /**
     * @brief Apply builder configuration to an existing WhitelistEntry
     * @param[out] entry Target entry to configure
     * @note Safe method that avoids copy/move constructor issues
     */
    void ApplyTo(WhitelistEntry& entry) const noexcept {
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto epochSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()
        ).count();
        uint64_t currentTime = static_cast<uint64_t>(epochSeconds);
        
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
        
        // Copy hash data safely with bounds check
        const size_t copySize = std::min<size_t>(
            static_cast<size_t>(m_hash.length), 
            entry.hashData.size()
        );
        
        if (copySize > 0) {
            std::memcpy(entry.hashData.data(), m_hash.data.data(), copySize);
        }
        
        // Zero remaining hash bytes
        if (copySize < entry.hashData.size()) {
            std::memset(
                entry.hashData.data() + copySize, 
                0, 
                entry.hashData.size() - copySize
            );
        }
        
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
    
    /**
     * @brief Build entry by applying to reference
     * @param[out] entry Pre-allocated entry to populate
     * @return Reference to the populated entry
     */
    WhitelistEntry& BuildInto(WhitelistEntry& entry) const noexcept {
        ApplyTo(entry);
        return entry;
    }
    
    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    /**
     * @brief Validate builder configuration
     * @return True if configuration is valid for the entry type
     */
    [[nodiscard]] bool IsValid() const noexcept {
        // Check type is not reserved
        if (m_type == WhitelistEntryType::Reserved) {
            return false;
        }
        
        // For hash types, require valid hash
        if (m_type == WhitelistEntryType::FileHash ||
            m_type == WhitelistEntryType::Certificate) {
            if (m_hash.IsEmpty()) {
                return false;
            }
        }
        
        // Validate expiration if set
        if (HasFlag(m_flags, WhitelistFlags::HasExpiration)) {
            if (m_expirationTime == 0) {
                return false;  // HasExpiration flag set but no expiration time
            }
        }
        
        return true;
    }
    
    /**
     * @brief Get validation error message
     * @return Error message if invalid, empty string if valid
     */
    [[nodiscard]] std::string GetValidationError() const noexcept {
        if (m_type == WhitelistEntryType::Reserved) {
            return "Entry type cannot be Reserved";
        }
        
        if ((m_type == WhitelistEntryType::FileHash || 
             m_type == WhitelistEntryType::Certificate) && m_hash.IsEmpty()) {
            return "Hash required for FileHash/Certificate type";
        }
        
        if (HasFlag(m_flags, WhitelistFlags::HasExpiration) && m_expirationTime == 0) {
            return "HasExpiration flag set but no expiration time";
        }
        
        return {};
    }
    
    // ========================================================================
    // DELETED - Prevent Build() returning by value
    // ========================================================================
    [[nodiscard]] WhitelistEntry Build() const noexcept = delete;
    
private:
    // ========================================================================
    // MEMBER DATA (all trivially copyable)
    // ========================================================================
    
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
