/*
 * ============================================================================
 * ShadowStrike SignatureIndex - ULTRA-FAST B+TREE INDEXING ENGINE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-performance B+Tree indexing for O(log N) hash lookups
 * Memory-mapped with lock-free reads, optimized for CPU cache
 * Target: < 500ns average lookup time
 *
 * Architecture:
 * - Cache-aligned B+Tree nodes (CACHE_LINE_SIZE * N)
 * - Lock-free concurrent reads (RCU-like semantics)
 * - Copy-on-write for updates (MVCC)
 * - Leaf node linked list for range queries
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once

#include "SignatureFormat.hpp"
#include <memory>
#include <shared_mutex>
#include <atomic>
#include <functional>
#include <optional>

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// B+TREE INDEX MANAGER
// ============================================================================

class SignatureIndex {
public:
    // Constructor & Destructor
    SignatureIndex() = default;
    ~SignatureIndex();

    // Disable copy AND move - class contains mutex and atomics that cannot be safely moved
    SignatureIndex(const SignatureIndex&) = delete;
    SignatureIndex& operator=(const SignatureIndex&) = delete;
    SignatureIndex(SignatureIndex&&) = delete;
    SignatureIndex& operator=(SignatureIndex&&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    // Initialize from existing memory-mapped database
    [[nodiscard]] StoreError Initialize(
         const MemoryMappedView& view,
        uint64_t indexOffset,
        uint64_t indexSize
    ) noexcept;

    // Create new empty index (for building)
    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;

    // Verify index integrity (checksum, structure validation)
    [[nodiscard]] StoreError Verify() const noexcept;

    // ========================================================================
    // QUERY OPERATIONS (Lock-Free Reads)
    // ========================================================================

    // Lookup by hash (fastest path: < 500ns average)
    [[nodiscard]] std::optional<uint64_t> Lookup(
        const HashValue& hash
    ) const noexcept;

    // Lookup by hash fast-hash value (pre-computed)
    [[nodiscard]] std::optional<uint64_t> LookupByFastHash(
        uint64_t fastHash
    ) const noexcept;

    // Range query: find all hashes in [minHash, maxHash]
    [[nodiscard]] std::vector<uint64_t> RangeQuery(
        uint64_t minFastHash,
        uint64_t maxFastHash,
        uint32_t maxResults = 1000
    ) const noexcept;

    // Batch lookup (optimized for cache locality)
    void BatchLookup(
        std::span<const HashValue> hashes,
        std::vector<std::optional<uint64_t>>& results
    ) const noexcept;

    // ========================================================================
    // MODIFICATION OPERATIONS (COW with Write Lock)
    // ========================================================================

    // Insert new hash -> signature mapping
    [[nodiscard]] StoreError Insert(
        const HashValue& hash,
        uint64_t signatureOffset
    ) noexcept;

    // Remove hash from index
    [[nodiscard]] StoreError Remove(
        const HashValue& hash
    ) noexcept;

    // Batch insert (optimized for bulk loading)
    [[nodiscard]] StoreError BatchInsert(
        std::span<const std::pair<HashValue, uint64_t>> entries
    ) noexcept;

    // Update existing entry (change offset)
    [[nodiscard]] StoreError Update(
        const HashValue& hash,
        uint64_t newSignatureOffset
    ) noexcept;

    // ========================================================================
    // TRAVERSAL & ITERATION
    // ========================================================================

    // Iterate all entries in sorted order (uses leaf linked list)
    void ForEach(
        std::function<bool(uint64_t fastHash, uint64_t signatureOffset)> callback
    ) const noexcept;

    // Iterate entries matching predicate
    void ForEachIf(
        std::function<bool(uint64_t fastHash)> predicate,
        std::function<bool(uint64_t fastHash, uint64_t signatureOffset)> callback
    ) const noexcept;

    // ========================================================================
    // STATISTICS & PROFILING
    // ========================================================================

    struct IndexStatistics {
        uint64_t totalEntries{0};
        uint64_t totalNodes{0};
        uint64_t leafNodes{0};
        uint64_t internalNodes{0};
        uint32_t treeHeight{0};
        double averageFillRate{0.0};                      // Node fill percentage
        uint64_t totalMemoryBytes{0};
        
        // Performance metrics
        uint64_t totalLookups{0};
        uint64_t cacheHits{0};                            // Node cache hits
        uint64_t cacheMisses{0};
        uint64_t averageLookupNanoseconds{0};
    };

    [[nodiscard]] IndexStatistics GetStatistics() const noexcept;

    // Reset statistics counters
    void ResetStatistics() noexcept;

    // ========================================================================
    // MAINTENANCE
    // ========================================================================

    // Rebuild index for optimal performance (after many updates)
    [[nodiscard]] StoreError Rebuild() noexcept;

    // Compact index (remove fragmentation)
    [[nodiscard]] StoreError Compact() noexcept;

    // Flush changes to disk (if writable mapping)
    [[nodiscard]] StoreError Flush() noexcept;

    // ========================================================================
    // DEBUGGING & VALIDATION
    // ========================================================================

    // Dump tree structure (for debugging)
    void DumpTree(std::function<void(const std::string&)> output) const noexcept;

    // Validate tree invariants (expensive)
    [[nodiscard]] bool ValidateInvariants(std::string& errorMessage) const noexcept;

private:
    // ========================================================================
    // INTERNAL NODE MANAGEMENT
    // ========================================================================

    // Node cache entry (for frequently accessed nodes)
    struct CachedNode {
        const BPlusTreeNode* node{nullptr};
        uint64_t accessCount{0};
        uint64_t lastAccessTime{0};                       // QueryPerformanceCounter
    };

    // Find leaf node containing hash
    [[nodiscard]] const BPlusTreeNode* FindLeaf(
        uint64_t fastHash
    ) const noexcept;

    // Find insertion point in node
    [[nodiscard]] uint32_t FindInsertionPoint(
        const BPlusTreeNode* node,
        uint64_t fastHash
    ) const noexcept;

    // Split node during insertion
    [[nodiscard]] StoreError SplitNode(
        BPlusTreeNode* node,
        uint64_t& splitKey,
        BPlusTreeNode** newNode
    ) noexcept;

    // Merge nodes during deletion
    [[nodiscard]] StoreError MergeNodes(
        BPlusTreeNode* left,
        BPlusTreeNode* right
    ) noexcept;

    // Allocate new node from pool
    [[nodiscard]] BPlusTreeNode* AllocateNode(
        bool isLeaf
    ) noexcept;

    // Free node back to pool
    void FreeNode(BPlusTreeNode* node) noexcept;

    // ========================================================================
    // NODE CACHE MANAGEMENT
    // ========================================================================

    // Get node from cache or load from memory
    [[nodiscard]] const BPlusTreeNode* GetNode(
        uint32_t nodeOffset
    ) const noexcept;

    // Invalidate cache entry
    void InvalidateCacheEntry(uint32_t nodeOffset) noexcept;

    // Clear entire cache
    void ClearCache() noexcept;

    // ========================================================================
    // COPY-ON-WRITE MANAGEMENT
    // ========================================================================

    // Clone node for modification
    [[nodiscard]] BPlusTreeNode* CloneNode(
        const BPlusTreeNode* original
    ) noexcept;

    // Commit COW transaction
    [[nodiscard]] StoreError CommitCOW() noexcept;

    // Rollback COW transaction
    void RollbackCOW() noexcept;

    // ========================================================================
    // INTERNAL LOOKUP (no lock - caller must hold lock)
    // ========================================================================

    // Internal lookup without acquiring lock (for use when lock already held)
    [[nodiscard]] std::optional<uint64_t> LookupByFastHashInternal(
        uint64_t fastHash
    ) const noexcept;

    // ========================================================================
    // INTERNAL MODIFICATION (no lock - caller must hold exclusive lock)
    // ========================================================================

    // Internal insert without acquiring lock (for BatchInsert/Rebuild - avoids deadlock)
    // Caller must hold exclusive lock (m_rwLock) before calling
    [[nodiscard]] StoreError InsertInternal(
        const HashValue& hash,
        uint64_t signatureOffset
    ) noexcept;

    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    // Memory mapping
    const MemoryMappedView* m_view{nullptr};
    void* m_baseAddress{nullptr};
    uint64_t m_indexOffset{0};
    uint64_t m_indexSize{0};
    uint64_t m_currentOffset{ 0 };

    // Return a mutable pointer to the memory-mapped view only if the underlying view exists
        // and is not marked readOnly. This centralizes the const_cast and enforces a runtime check.
    MemoryMappedView* MutableView() noexcept {
        if (!m_view) return nullptr;
        if (m_view->readOnly) return nullptr;
        return const_cast<MemoryMappedView*>(m_view);
        
    }


    // Tree root
    std::atomic<uint32_t> m_rootOffset{0};
    std::atomic<uint32_t> m_treeHeight{0};

    // Statistics
    mutable std::atomic<uint64_t> m_totalLookups{0};
    mutable std::atomic<uint64_t> m_cacheHits{0};
    mutable std::atomic<uint64_t> m_cacheMisses{0};
    std::atomic<uint64_t> m_totalEntries{0};

    // Node cache (LRU with lock-free reads)
    static constexpr size_t CACHE_SIZE = 1024;            // Cache 1024 hot nodes
    mutable std::array<CachedNode, CACHE_SIZE> m_nodeCache{};
    mutable std::atomic<uint64_t> m_cacheAccessCounter{0};
    mutable std::shared_mutex m_cacheLock;                // Protects cache writes

    // Synchronization (readers-writer lock, readers don't block)
    mutable std::shared_mutex m_rwLock;

    // COW state for updates
    std::vector<std::unique_ptr<BPlusTreeNode>> m_cowNodes;
    std::atomic<bool> m_inCOWTransaction{false};          // Atomic for thread safety

    // Performance monitoring
    mutable LARGE_INTEGER m_perfFrequency{};
    
    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    // Binary search in node keys
    [[nodiscard]] static uint32_t BinarySearch(
        const std::array<uint64_t, BPlusTreeNode::MAX_KEYS>& keys,
        uint32_t keyCount,
        uint64_t target
    ) noexcept;

    // Get current time in nanoseconds (for profiling)
    [[nodiscard]] static uint64_t GetCurrentTimeNs() noexcept;

    // Hash function for node cache
    [[nodiscard]] static size_t HashNodeOffset(uint32_t offset) noexcept;
};

// ============================================================================
// PATTERN TRIE INDEX (for byte pattern searches)
// ============================================================================

class PatternIndex {
public:
    PatternIndex() = default;
    ~PatternIndex();

    // Disable copy AND move - class contains mutex and atomics
    PatternIndex(const PatternIndex&) = delete;
    PatternIndex& operator=(const PatternIndex&) = delete;
    PatternIndex(PatternIndex&&) = delete;
    PatternIndex& operator=(PatternIndex&&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        uint64_t indexOffset,
        uint64_t indexSize
    ) noexcept;

    [[nodiscard]] StoreError CreateNew(
        void* baseAddress,
        uint64_t availableSize,
        uint64_t& usedSize
    ) noexcept;

    // ========================================================================
    // PATTERN SEARCH (High Performance)
    // ========================================================================

    // Search buffer for any matching patterns
    [[nodiscard]] std::vector<DetectionResult> Search(
        std::span<const uint8_t> buffer,
        const QueryOptions& options = {}
    ) const noexcept;

    // Incremental search (for streaming)
    class SearchContext {
    public:
        SearchContext() = default;
        ~SearchContext() = default;

        void Reset() noexcept;
        [[nodiscard]] std::vector<DetectionResult> Feed(
            std::span<const uint8_t> chunk
        ) noexcept;

    private:
        friend class PatternIndex;
        std::vector<uint8_t> m_buffer;
       
        size_t m_position{0};
    };

    [[nodiscard]] SearchContext CreateSearchContext() const noexcept;

    // ========================================================================
    // PATTERN MANAGEMENT
    // ========================================================================

    [[nodiscard]] StoreError AddPattern(
        const PatternEntry& pattern,
        std::span<const uint8_t> patternData
    ) noexcept;

    [[nodiscard]] StoreError RemovePattern(
        uint64_t signatureId
    ) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    struct PatternStatistics {
        uint64_t totalPatterns{0};
        uint64_t totalNodes{0};
        uint64_t averagePatternLength{0};
        uint64_t totalSearches{0};
        uint64_t totalMatches{0};
        uint64_t averageSearchTimeMicroseconds{0};
    };

    [[nodiscard]] PatternStatistics GetStatistics() const noexcept;

private:
    // Trie node structure (optimized for cache)
    struct alignas(CACHE_LINE_SIZE) TrieNode {
        std::array<uint32_t, 256> children{};             // Byte value -> child offset
        uint32_t patternOffset{0};                        // If terminal: pattern data offset
        uint32_t hitCount{0};                             // Statistics
        uint8_t depth{0};
        uint8_t reserved[7]{};
    };

    const MemoryMappedView* m_view{nullptr};
    void* m_baseAddress{nullptr};
    uint64_t m_indexOffset{0};
    uint64_t m_indexSize{0};

    LARGE_INTEGER m_perfFrequency{};

  
    std::atomic<uint32_t> m_rootOffset{0};
    mutable std::atomic<uint64_t> m_totalSearches{0};
    mutable std::atomic<uint64_t> m_totalMatches{0};
    
    mutable std::shared_mutex m_rwLock;
};

} // namespace SignatureStore
} // namespace ShadowStrike
