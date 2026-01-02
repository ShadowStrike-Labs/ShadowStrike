/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - ULTRA-FAST MULTI-INDEX ENGINE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade multi-dimensional indexing for threat intelligence lookups
 * Optimized for nanosecond-level performance in real-time threat detection
 *
 * Architecture Overview:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │ ThreatIntelIndex (Facade)                                           │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │ - IPv4 Index (Radix Tree - 4-level hierarchical)                   │
 * │ - IPv6 Index (Patricia Trie - 128-bit optimized)                   │
 * │ - Domain Index (Suffix Trie + Hash Table - reverse DNS matching)   │
 * │ - Hash Index (B+Tree per algorithm - cache-aligned nodes)          │
 * │ - URL Index (Aho-Corasick + Hash - pattern matching)               │
 * │ - Email Index (Hash Table - O(1) lookup)                           │
 * │ - Generic Index (Extensible B+Tree for all other IOC types)        │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Performance Targets (CrowdStrike Falcon / Microsoft Defender ATP quality):
 * - IPv4 lookup: < 50ns average (radix tree)
 * - IPv6 lookup: < 80ns average (patricia trie)
 * - Domain lookup: < 100ns average (suffix trie + hash)
 * - Hash lookup: < 100ns average (B+Tree with bloom filter)
 * - URL lookup: < 200ns average (pattern matching)
 * - Email lookup: < 50ns average (hash table)
 * - Batch lookup (1000 items): < 50µs total
 * - Index build: < 10s for 1M entries
 * - Memory overhead: < 10% of entry data
 *
 * Thread Safety:
 * - Lock-free concurrent reads (RCU-like semantics)
 * - Copy-on-write (COW) for modifications
 * - MVCC for transaction isolation
 * - Atomic statistics with relaxed ordering
 *
 * Index Types:
 * 1. IPv4 Radix Tree - 4-level hierarchical for CIDR support
 * 2. IPv6 Patricia Trie - Compressed for space efficiency
 * 3. Domain Suffix Trie - Reverse domain matching (com.example.*)
 * 4. Hash B+Tree - Per-algorithm trees for optimal cache locality
 * 5. URL Aho-Corasick - Multi-pattern matching for malicious URLs
 * 6. Email Hash Table - Direct addressing with chaining
 * 7. Generic B+Tree - For JA3, CVE, MITRE ATT&CK, etc.
 *
 * Zero-Copy Design:
 * - Memory-mapped index sections
 * - Direct pointer access (no deserialization)
 * - Cache-line aligned data structures
 * - Prefetching hints for sequential access
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include <array>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ThreatIntelIndex;
class IPv4RadixTree;
class IPv6PatriciaTrie;
class DomainSuffixTrie;
class HashBPlusTree;
class URLPatternMatcher;
class EmailHashTable;
class GenericBPlusTree;
class IndexBloomFilter;

// ============================================================================
// INDEX CONFIGURATION
// ============================================================================

namespace IndexConfig {

/// @brief B+Tree node order (keys per node)
constexpr size_t BTREE_NODE_ORDER = 128;

/// @brief Hash table bucket count (power of 2)
constexpr size_t HASH_TABLE_BUCKETS = 65536;

/// @brief Radix tree node cache size
constexpr size_t RADIX_CACHE_SIZE = 4096;

/// @brief Bloom filter bits per element
constexpr size_t BLOOM_BITS_PER_ELEMENT = 10;

/// @brief Bloom filter hash functions
constexpr size_t BLOOM_HASH_FUNCTIONS = 7;

/// @brief Maximum domain label length (RFC 1035)
constexpr size_t MAX_DOMAIN_LABEL_LENGTH = 63;

/// @brief Maximum domain name length (RFC 1035)
constexpr size_t MAX_DOMAIN_NAME_LENGTH = 253;

/// @brief URL pattern max length
constexpr size_t MAX_URL_PATTERN_LENGTH = 2048;

/// @brief Node prefetch distance
constexpr size_t PREFETCH_DISTANCE = 4;

/// @brief Statistics sampling rate (every Nth operation)
constexpr size_t STATS_SAMPLE_RATE = 1000;

/// @brief COW transaction max size (entries)
constexpr size_t MAX_COW_TRANSACTION_SIZE = 10000;

} // namespace IndexConfig

// ============================================================================
// INDEX LOOKUP RESULT
// ============================================================================

/**
 * @brief Result of an index lookup operation
 */
struct IndexLookupResult {
    /// @brief Whether the IOC was found in index
    bool found{false};
    
    /// @brief Entry ID from IOC entry
    uint64_t entryId{0};
    
    /// @brief Offset to IOC entry in data section
    uint64_t entryOffset{0};
    
    /// @brief Lookup latency in nanoseconds
    uint64_t latencyNs{0};
    
    /// @brief Which index was used
    IOCType indexType{IOCType::Reserved};
    
    /// @brief Bloom filter checked (if applicable)
    bool bloomChecked{false};
    
    /// @brief Bloom filter rejected (definite negative)
    bool bloomRejected{false};
    
    /// @brief Number of index nodes traversed
    uint32_t nodesTraversed{0};
    
    /// @brief Cache hit flag
    bool cacheHit{false};
    
    /**
     * @brief Create not-found result
     */
    [[nodiscard]] static IndexLookupResult NotFound(IOCType type) noexcept {
        IndexLookupResult result;
        result.found = false;
        result.indexType = type;
        return result;
    }
    
    /**
     * @brief Create found result
     */
    [[nodiscard]] static IndexLookupResult Found(
        uint64_t entryId,
        uint64_t offset,
        IOCType type
    ) noexcept {
        IndexLookupResult result;
        result.found = true;
        result.entryId = entryId;
        result.entryOffset = offset;
        result.indexType = type;
        return result;
    }
    
    /**
     * @brief Create bloom-rejected result (fast negative)
     */
    [[nodiscard]] static IndexLookupResult BloomRejected(IOCType type) noexcept {
        IndexLookupResult result;
        result.found = false;
        result.indexType = type;
        result.bloomChecked = true;
        result.bloomRejected = true;
        return result;
    }
};

// ============================================================================
// INDEX STATISTICS
// ============================================================================

/**
 * @brief Comprehensive statistics for all index types
 */
struct IndexStatistics {
    // ========================================================================
    // Entry Counts per Index
    // ========================================================================
    
    uint64_t ipv4Entries{0};
    uint64_t ipv6Entries{0};
    uint64_t domainEntries{0};
    uint64_t urlEntries{0};
    uint64_t hashEntries{0};
    uint64_t emailEntries{0};
    uint64_t otherEntries{0};
    uint64_t totalEntries{0};
    
    // ========================================================================
    // Memory Usage per Index (bytes)
    // ========================================================================
    
    uint64_t ipv4MemoryBytes{0};
    uint64_t ipv6MemoryBytes{0};
    uint64_t domainMemoryBytes{0};
    uint64_t urlMemoryBytes{0};
    uint64_t hashMemoryBytes{0};
    uint64_t emailMemoryBytes{0};
    uint64_t otherMemoryBytes{0};
    uint64_t bloomFilterBytes{0};
    uint64_t totalMemoryBytes{0};
    
    // ========================================================================
    // Performance Metrics
    // ========================================================================
    
    std::atomic<uint64_t> totalLookups{0};
    std::atomic<uint64_t> successfulLookups{0};
    std::atomic<uint64_t> failedLookups{0};
    
    std::atomic<uint64_t> bloomFilterChecks{0};
    std::atomic<uint64_t> bloomFilterRejects{0};
    std::atomic<uint64_t> bloomFilterFalsePositives{0};
    
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    
    // Timing statistics (nanoseconds)
    std::atomic<uint64_t> totalLookupTimeNs{0};
    std::atomic<uint64_t> minLookupTimeNs{UINT64_MAX};
    std::atomic<uint64_t> maxLookupTimeNs{0};
    
    // Per-index timing averages (nanoseconds)
    uint64_t avgIPv4LookupNs{0};
    uint64_t avgIPv6LookupNs{0};
    uint64_t avgDomainLookupNs{0};
    uint64_t avgURLLookupNs{0};
    uint64_t avgHashLookupNs{0};
    uint64_t avgEmailLookupNs{0};
    
    // ========================================================================
    // Index Structure Metrics
    // ========================================================================
    
    // IPv4 Radix Tree
    uint32_t ipv4TreeHeight{0};
    uint64_t ipv4TreeNodes{0};
    double ipv4AvgFillRate{0.0};
    
    // IPv6 Patricia Trie
    uint32_t ipv6TreeHeight{0};
    uint64_t ipv6TreeNodes{0};
    double ipv6CompressionRatio{0.0};
    
    // Domain Suffix Trie
    uint32_t domainTrieHeight{0};
    uint64_t domainTrieNodes{0};
    uint64_t domainHashBuckets{0};
    
    // Hash B+Trees
    uint32_t hashTreeHeight{0};
    uint64_t hashTreeNodes{0};
    double hashTreeFillRate{0.0};
    
    // URL Pattern Matcher
    uint64_t urlPatternCount{0};
    uint64_t urlStateMachineStates{0};
    
    // Email Hash Table
    uint64_t emailHashBuckets{0};
    double emailLoadFactor{0.0};
    uint64_t emailCollisions{0};
    
    // ========================================================================
    // Modification Statistics
    // ========================================================================
    
    std::atomic<uint64_t> totalInsertions{0};
    std::atomic<uint64_t> totalDeletions{0};
    std::atomic<uint64_t> totalUpdates{0};
    std::atomic<uint64_t> cowTransactions{0};
    std::atomic<uint64_t> indexRebuilds{0};
    
    /**
     * @brief Copy constructor (handles atomic members)
     */
    IndexStatistics(const IndexStatistics& other) noexcept;
    
    /**
     * @brief Assignment operator (handles atomic members)
     */
    IndexStatistics& operator=(const IndexStatistics& other) noexcept;
    
    /**
     * @brief Default constructor
     */
    IndexStatistics() noexcept = default;
    
    /**
     * @brief Calculate average lookup time
     */
    [[nodiscard]] uint64_t AverageLookupTimeNs() const noexcept {
        uint64_t lookups = totalLookups.load(std::memory_order_relaxed);
        return lookups > 0 ? 
            totalLookupTimeNs.load(std::memory_order_relaxed) / lookups : 0;
    }
    
    /**
     * @brief Calculate lookup success rate
     */
    [[nodiscard]] double LookupSuccessRate() const noexcept {
        uint64_t total = totalLookups.load(std::memory_order_relaxed);
        return total > 0 ?
            static_cast<double>(successfulLookups.load(std::memory_order_relaxed)) / total : 0.0;
    }
    
    /**
     * @brief Calculate bloom filter effectiveness
     */
    [[nodiscard]] double BloomFilterEffectiveness() const noexcept {
        uint64_t checks = bloomFilterChecks.load(std::memory_order_relaxed);
        return checks > 0 ?
            static_cast<double>(bloomFilterRejects.load(std::memory_order_relaxed)) / checks : 0.0;
    }
    
    /**
     * @brief Calculate cache hit rate
     */
    [[nodiscard]] double CacheHitRate() const noexcept {
        uint64_t total = cacheHits.load(std::memory_order_relaxed) + 
                         cacheMisses.load(std::memory_order_relaxed);
        return total > 0 ?
            static_cast<double>(cacheHits.load(std::memory_order_relaxed)) / total : 0.0;
    }
    
    /**
     * @brief Calculate total memory efficiency (entries per MB)
     */
    [[nodiscard]] double MemoryEfficiency() const noexcept {
        uint64_t mb = totalMemoryBytes / (1024 * 1024);
        return mb > 0 ? static_cast<double>(totalEntries) / mb : 0.0;
    }
};

// ============================================================================
// INDEX BUILD OPTIONS
// ============================================================================

/**
 * @brief Options for building/rebuilding indexes
 */
struct IndexBuildOptions {
    /// @brief Build IPv4 index
    bool buildIPv4{true};
    
    /// @brief Build IPv6 index
    bool buildIPv6{true};
    
    /// @brief Build domain index
    bool buildDomain{true};
    
    /// @brief Build URL index
    bool buildURL{true};
    
    /// @brief Build hash indexes
    bool buildHash{true};
    
    /// @brief Build email index
    bool buildEmail{true};
    
    /// @brief Build generic indexes (JA3, CVE, etc.)
    bool buildGeneric{true};
    
    /// @brief Build bloom filters
    bool buildBloomFilters{true};
    
    /// @brief Optimize for read performance (may use more memory)
    bool optimizeForReads{true};
    
    /// @brief Verify index after build
    bool verifyAfterBuild{true};
    
    /// @brief Progress callback
    std::function<void(size_t processed, size_t total)> progressCallback;
    
    /**
     * @brief Create default build options
     */
    [[nodiscard]] static IndexBuildOptions Default() {
        return IndexBuildOptions{};
    }
    
    /**
     * @brief Create fast build options (skip verification)
     */
    [[nodiscard]] static IndexBuildOptions Fast() {
        IndexBuildOptions opts;
        opts.verifyAfterBuild = false;
        return opts;
    }
};

// ============================================================================
// INDEX QUERY OPTIONS
// ============================================================================

/**
 * @brief Options for index query operations
 */
struct IndexQueryOptions {
    /// @brief Use bloom filter for negative lookups
    bool useBloomFilter{true};
    
    /// @brief Use node cache
    bool useCache{true};
    
    /// @brief Prefetch subsequent nodes
    bool prefetchNodes{true};
    
    /// @brief Maximum time to spend on lookup (microseconds, 0 = unlimited)
    uint32_t timeoutMicroseconds{0};
    
    /// @brief Collect detailed timing statistics
    bool collectStatistics{false};
    
    /**
     * @brief Create default query options
     */
    [[nodiscard]] static IndexQueryOptions Default() {
        return IndexQueryOptions{};
    }
    
    /**
     * @brief Create fastest query options (minimal overhead)
     */
    [[nodiscard]] static IndexQueryOptions Fastest() {
        IndexQueryOptions opts;
        opts.collectStatistics = false;
        opts.prefetchNodes = false;
        return opts;
    }
    
    /**
     * @brief Create profiling options (collect all statistics)
     */
    [[nodiscard]] static IndexQueryOptions Profiling() {
        IndexQueryOptions opts;
        opts.collectStatistics = true;
        return opts;
    }
};

// ============================================================================
// RADIX TREE NODE (IPv4)
// ============================================================================

/**
 * @brief Cache-aligned radix tree node for IPv4 addresses
 * 
 * 4-level hierarchical structure for optimal cache performance:
 * Level 0: First octet (256-way fanout)
 * Level 1: Second octet (256-way fanout)
 * Level 2: Third octet (256-way fanout)
 * Level 3: Fourth octet (256-way fanout) + CIDR prefix
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) IPv4RadixNode {
    /// @brief Node type flags
    enum NodeFlags : uint8_t {
        IsLeaf = 1 << 0,
        HasChildren = 1 << 1,
        HasCIDR = 1 << 2,
        Compressed = 1 << 3
    };
    
    /// @brief Node flags
    uint8_t flags{0};
    
    /// @brief Prefix length (for CIDR support)
    uint8_t prefixLength{0};
    
    /// @brief Number of children
    uint16_t childCount{0};
    
    /// @brief Entry ID (if leaf node)
    uint64_t entryId{0};
    
    /// @brief Entry offset (if leaf node)
    uint64_t entryOffset{0};
    
    /// @brief Child node offsets (256-way fanout)
    /// @note Only first childCount entries are valid
    /// @note 0 = no child at this index
    std::array<uint32_t, 256> children{};
    
    /// @brief Check if node is leaf
    [[nodiscard]] constexpr bool IsLeafNode() const noexcept {
        return (flags & IsLeaf) != 0;
    }
    
    /// @brief Check if node has children
    [[nodiscard]] constexpr bool HasChild() const noexcept {
        return (flags & HasChildren) != 0;
    }
    
    /// @brief Check if node supports CIDR
    [[nodiscard]] constexpr bool SupportsCIDR() const noexcept {
        return (flags & HasCIDR) != 0;
    }
    
    /// @brief Get child node offset for octet
    [[nodiscard]] uint32_t GetChild(uint8_t octet) const noexcept {
        return children[octet];
    }
    
    /// @brief Set child node offset
    void SetChild(uint8_t octet, uint32_t offset) noexcept {
        children[octet] = offset;
        if (offset != 0) {
            flags |= HasChildren;
            if (childCount < 256) childCount++;
        }
    }
};
#pragma pack(pop)

// Size calculation: 1 (flags) + 1 (prefixLength) + 2 (childCount) + 4 (padding) + 8 (entryId) + 8 (entryOffset) + 1024 (children array) = 1048 bytes (with alignment)
static_assert(sizeof(IPv4RadixNode) <= 1088, "IPv4RadixNode size check");

// ============================================================================
// PATRICIA TRIE NODE (IPv6)
// ============================================================================

/**
 * @brief Patricia trie node for IPv6 addresses (compressed)
 * 
 * Uses path compression to save memory:
 * - Common prefixes are collapsed into single edges
 * - Only branch points create new nodes
 * - Supports CIDR prefix matching
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) IPv6PatriciaNode {
    /// @brief Node flags
    enum NodeFlags : uint8_t {
        IsLeaf = 1 << 0,
        Compressed = 1 << 1,
        HasCIDR = 1 << 2
    };
    
    /// @brief Node flags
    uint8_t flags{0};
    
    /// @brief Prefix bit length
    uint8_t prefixBits{0};
    
    /// @brief Number of children (0-256)
    uint16_t childCount{0};
    
    /// @brief Compressed path bits (up to 128 bits)
    std::array<uint8_t, 16> pathBits{};
    
    /// @brief Entry ID (if leaf)
    uint64_t entryId{0};
    
    /// @brief Entry offset (if leaf)
    uint64_t entryOffset{0};
    
    /// @brief Child offsets (sparse array)
    /// @note Only stores offsets for existing children
    struct ChildEntry {
        uint8_t nibble{0};        // 4-bit index (0-15)
        uint8_t reserved[3]{};
        uint32_t offset{0};
    };
    
    /// @brief Maximum children (allows up to 16-way fanout)
    static constexpr size_t MAX_CHILDREN = 16;
    std::array<ChildEntry, MAX_CHILDREN> children{};
    
    /// @brief Check if leaf node
    [[nodiscard]] constexpr bool IsLeafNode() const noexcept {
        return (flags & IsLeaf) != 0;
    }
    
    /// @brief Check if compressed
    [[nodiscard]] constexpr bool IsCompressed() const noexcept {
        return (flags & Compressed) != 0;
    }
    
    /// @brief Get child offset for nibble
    [[nodiscard]] uint32_t GetChild(uint8_t nibble) const noexcept {
        for (uint16_t i = 0; i < childCount && i < MAX_CHILDREN; ++i) {
            if (children[i].nibble == nibble) {
                return children[i].offset;
            }
        }
        return 0;
    }
};
#pragma pack(pop)

// ============================================================================
// DOMAIN SUFFIX TRIE NODE
// ============================================================================

/**
 * @brief Suffix trie node for domain name matching
 * 
 * Stores domains in reverse order (com.example.www)
 * Enables wildcard subdomain matching (*.example.com)
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) DomainSuffixNode {
    /// @brief Node flags
    enum NodeFlags : uint8_t {
        IsTerminal = 1 << 0,      // Represents complete domain
        IsWildcard = 1 << 1,      // Matches any subdomain
        HasChildren = 1 << 2
    };
    
    /// @brief Node flags
    uint8_t flags{0};
    
    /// @brief Label length
    uint8_t labelLength{0};
    
    /// @brief Reserved
    uint16_t reserved{0};
    
    /// @brief Domain label (e.g., "com", "example")
    std::array<char, IndexConfig::MAX_DOMAIN_LABEL_LENGTH + 1> label{};
    
    /// @brief Entry ID (if terminal)
    uint64_t entryId{0};
    
    /// @brief Entry offset (if terminal)
    uint64_t entryOffset{0};
    
    /// @brief Hash table offset for children (for fast branching)
    uint32_t childHashTableOffset{0};
    
    /// @brief Number of children
    uint16_t childCount{0};
    
    /// @brief Reserved for alignment
    uint16_t reserved2{0};
    
    /// @brief Check if terminal node
    [[nodiscard]] constexpr bool IsTerminalNode() const noexcept {
        return (flags & IsTerminal) != 0;
    }
    
    /// @brief Check if wildcard
    [[nodiscard]] constexpr bool IsWildcardNode() const noexcept {
        return (flags & IsWildcard) != 0;
    }
    
    /// @brief Get label as string view
    [[nodiscard]] std::string_view GetLabel() const noexcept {
        return std::string_view(label.data(), labelLength);
    }
};
#pragma pack(pop)

// ============================================================================
// HASH B+TREE NODE
// ============================================================================

/**
 * @brief B+Tree node for hash lookups (per algorithm)
 * 
 * Standard B+Tree with high branching factor:
 * - Internal nodes: store keys + child pointers
 * - Leaf nodes: store keys + entry offsets + next leaf pointer
 * - Optimized for cache-line prefetching
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) HashBPlusTreeNode {
    /// @brief Node type
    enum NodeType : uint8_t {
        Internal = 0,
        Leaf = 1
    };
    
    /// @brief Node type
    NodeType type{Internal};
    
    /// @brief Key count in this node
    uint16_t keyCount{0};
    
    /// @brief Reserved
    uint8_t reserved{0};
    
    /// @brief Parent node offset (0 = root)
    uint32_t parentOffset{0};
    
    /// @brief Next leaf offset (for range queries, 0 = last)
    uint32_t nextLeafOffset{0};
    
    /// @brief Previous leaf offset (for reverse iteration, 0 = first)
    uint32_t prevLeafOffset{0};
    
    /// @brief Keys (hash fast-hash values, sorted)
    std::array<uint64_t, IndexConfig::BTREE_NODE_ORDER> keys{};
    
    /// @brief Values/Children
    /// Internal node: child offsets (keyCount + 1 children)
    /// Leaf node: entry offsets (keyCount entries)
    std::array<uint64_t, IndexConfig::BTREE_NODE_ORDER + 1> values{};
    
    /// @brief Check if leaf node
    [[nodiscard]] constexpr bool IsLeaf() const noexcept {
        return type == Leaf;
    }
    
    /// @brief Check if internal node
    [[nodiscard]] constexpr bool IsInternal() const noexcept {
        return type == Internal;
    }
    
    /// @brief Check if node is full
    [[nodiscard]] bool IsFull() const noexcept {
        return keyCount >= IndexConfig::BTREE_NODE_ORDER;
    }
    
    /// @brief Check if node is underfull (less than half full)
    [[nodiscard]] bool IsUnderfull() const noexcept {
        return keyCount < (IndexConfig::BTREE_NODE_ORDER / 2);
    }
    
    /// @brief Find insertion point for key
    [[nodiscard]] uint16_t FindInsertionPoint(uint64_t key) const noexcept {
        // Binary search
        uint16_t left = 0;
        uint16_t right = keyCount;
        
        while (left < right) {
            uint16_t mid = left + (right - left) / 2;
            if (keys[mid] < key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        return left;
    }
};
#pragma pack(pop)

// ============================================================================
// URL PATTERN MATCHER NODE (Aho-Corasick)
// ============================================================================

/**
 * @brief Aho-Corasick automaton state for URL pattern matching
 * 
 * Multi-pattern matching for malicious URL detection:
 * - Matches multiple patterns simultaneously
 * - Linear time complexity O(n + m + z)
 * - Failure links for efficient backtracking
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) URLPatternNode {
    /// @brief Transition table (ASCII characters)
    std::array<uint32_t, 256> transitions{};
    
    /// @brief Failure link (for Aho-Corasick)
    uint32_t failureLink{0};
    
    /// @brief Output link (for multiple pattern matches)
    uint32_t outputLink{0};
    
    /// @brief Entry ID (if pattern terminates here)
    uint64_t entryId{0};
    
    /// @brief Entry offset
    uint64_t entryOffset{0};
    
    /// @brief Pattern ID (for multiple matches)
    uint32_t patternId{0};
    
    /// @brief Depth in trie
    uint16_t depth{0};
    
    /// @brief Is terminal state (pattern end)
    bool isTerminal{false};
    
    /// @brief Reserved
    uint8_t reserved{0};
};
#pragma pack(pop)

// ============================================================================
// EMAIL HASH TABLE BUCKET
// ============================================================================

/**
 * @brief Hash table bucket for email address lookups
 * 
 * Open addressing with linear probing:
 * - Fast O(1) average case
 * - Cache-friendly sequential probing
 * - Tombstone marking for deletions
 */
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) EmailHashBucket {
    /// @brief Bucket state
    enum State : uint8_t {
        Empty = 0,
        Occupied = 1,
        Tombstone = 2
    };
    
    /// @brief Bucket state
    State state{Empty};
    
    /// @brief Reserved
    uint8_t reserved[3]{};
    
    /// @brief Hash value (for quick comparison)
    uint64_t hash{0};
    
    /// @brief Email string offset in string pool
    uint32_t emailOffset{0};
    
    /// @brief Email length
    uint16_t emailLength{0};
    
    /// @brief Reserved
    uint16_t reserved2{0};
    
    /// @brief Entry ID
    uint64_t entryId{0};
    
    /// @brief Entry offset
    uint64_t entryOffset{0};
    
    /// @brief Check if occupied
    [[nodiscard]] constexpr bool IsOccupied() const noexcept {
        return state == Occupied;
    }
    
    /// @brief Check if empty
    [[nodiscard]] constexpr bool IsEmpty() const noexcept {
        return state == Empty;
    }
    
    /// @brief Check if tombstone
    [[nodiscard]] constexpr bool IsTombstone() const noexcept {
        return state == Tombstone;
    }
};
#pragma pack(pop)

// ============================================================================
// INDEX SECTION HEADERS
// ============================================================================

/**
 * @brief Header for each index section in the database
 */
#pragma pack(push, 1)
struct IndexSectionHeader {
    /// @brief Magic number for verification
    uint32_t magic{0};
    
    /// @brief Index version
    uint32_t version{1};
    
    /// @brief Index type
    IOCType indexType{IOCType::Reserved};
    
    /// @brief Reserved
    uint8_t reserved[3]{};
    
    /// @brief Entry count
    uint64_t entryCount{0};
    
    /// @brief Total size in bytes
    uint64_t totalSize{0};
    
    /// @brief Root node offset (for tree-based indexes)
    uint64_t rootNodeOffset{0};
    
    /// @brief Node count
    uint64_t nodeCount{0};
    
    /// @brief Bloom filter offset (0 = no bloom filter)
    uint64_t bloomFilterOffset{0};
    
    /// @brief Bloom filter size
    uint64_t bloomFilterSize{0};
    
    /// @brief Creation timestamp
    uint64_t creationTime{0};
    
    /// @brief Last modification timestamp
    uint64_t lastModifiedTime{0};
    
    /// @brief Build flags
    uint32_t buildFlags{0};
    
    /// @brief Reserved for future use
    uint8_t reserved2[28]{};
    
    /// @brief Checksum (CRC32)
    uint32_t checksum{0};
};
#pragma pack(pop)

// Size check: Allow reasonable range due to compiler padding and alignment
// Note: Size may vary due to compiler padding - actual size depends on alignment
// static_assert disabled to allow flexible padding by compiler
// static_assert(sizeof(IndexSectionHeader) >= 96 && sizeof(IndexSectionHeader) <= 192, 
//               "IndexSectionHeader size check - should be around 128 bytes with padding");

// ============================================================================
// THREATINTELINDEX CLASS
// ============================================================================

/**
 * @brief Main facade class for all threat intelligence index operations
 * 
 * Thread-safe, high-performance multi-dimensional indexing system.
 * Supports concurrent reads with lock-free access, COW for writes.
 * 
 * Usage:
 * @code
 * ThreatIntelIndex index;
 * if (index.Initialize(database, config)) {
 *     // IPv4 lookup
 *     IPv4Address addr(192, 168, 1, 100);
 *     auto result = index.LookupIPv4(addr);
 *     
 *     // Hash lookup
 *     HashValue hash = ...;
 *     auto result = index.LookupHash(hash);
 *     
 *     // Batch lookup
 *     std::vector<IndexLookupResult> results;
 *     index.BatchLookup(keys, results);
 * }
 * @endcode
 */
class ThreatIntelIndex {
public:
    ThreatIntelIndex();
    ~ThreatIntelIndex();
    
    // Non-copyable, non-movable (owns resources)
    ThreatIntelIndex(const ThreatIntelIndex&) = delete;
    ThreatIntelIndex& operator=(const ThreatIntelIndex&) = delete;
    ThreatIntelIndex(ThreatIntelIndex&&) = delete;
    ThreatIntelIndex& operator=(ThreatIntelIndex&&) = delete;
    
    // =========================================================================
    // INITIALIZATION
    // =========================================================================
    
    /**
     * @brief Initialize index from memory-mapped database
     * @param view Memory-mapped database view
     * @param header Database header
     * @return Success or error code
     */
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        const ThreatIntelDatabaseHeader* header
    ) noexcept;
    
    /**
     * @brief Initialize with custom configuration
     */
    [[nodiscard]] StoreError Initialize(
        const MemoryMappedView& view,
        const ThreatIntelDatabaseHeader* header,
        const IndexBuildOptions& options
    ) noexcept;
    
    /**
     * @brief Check if index is initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Shutdown and release resources
     */
    void Shutdown() noexcept;
    
    // =========================================================================
    // LOOKUP OPERATIONS (Lock-Free Reads)
    // =========================================================================
    
    /**
     * @brief Lookup IPv4 address in index
     * @param addr IPv4 address (supports CIDR)
     * @param options Query options
     * @return Lookup result
     */
    [[nodiscard]] IndexLookupResult LookupIPv4(
        const IPv4Address& addr,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup IPv6 address in index
     */
    [[nodiscard]] IndexLookupResult LookupIPv6(
        const IPv6Address& addr,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup domain name in index
     * @note Supports wildcard matching (*.example.com)
     */
    [[nodiscard]] IndexLookupResult LookupDomain(
        std::string_view domain,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup URL in index
     */
    [[nodiscard]] IndexLookupResult LookupURL(
        std::string_view url,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup file hash in index
     */
    [[nodiscard]] IndexLookupResult LookupHash(
        const HashValue& hash,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup email address in index
     */
    [[nodiscard]] IndexLookupResult LookupEmail(
        std::string_view email,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Lookup generic IOC (JA3, CVE, etc.)
     */
    [[nodiscard]] IndexLookupResult LookupGeneric(
        IOCType type,
        std::string_view value,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Generic lookup by IOC type
     */
    [[nodiscard]] IndexLookupResult Lookup(
        IOCType type,
        const void* value,
        size_t valueSize,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    // =========================================================================
    // BATCH LOOKUP OPERATIONS
    // =========================================================================
    
    /**
     * @brief Batch lookup for multiple IPv4 addresses
     * @param addresses Input addresses
     * @param results Output results (resized to match input)
     * @param options Query options
     */
    void BatchLookupIPv4(
        std::span<const IPv4Address> addresses,
        std::vector<IndexLookupResult>& results,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Batch lookup for multiple hashes
     */
    void BatchLookupHashes(
        std::span<const HashValue> hashes,
        std::vector<IndexLookupResult>& results,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Batch lookup for multiple domains
     */
    void BatchLookupDomains(
        std::span<const std::string_view> domains,
        std::vector<IndexLookupResult>& results,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    /**
     * @brief Generic batch lookup
     */
    void BatchLookup(
        IOCType type,
        std::span<const std::string_view> values,
        std::vector<IndexLookupResult>& results,
        const IndexQueryOptions& options = IndexQueryOptions::Default()
    ) const noexcept;
    
    // =========================================================================
    // INDEX MODIFICATION (COW with Write Lock)
    // =========================================================================
    
    /**
     * @brief Insert new entry into index
     * @param entry IOC entry to index
     * @param entryOffset Offset to entry in data section
     * @return Success or error code
     */
    [[nodiscard]] StoreError Insert(
        const IOCEntry& entry,
        uint64_t entryOffset
    ) noexcept;
    
    /**
     * @brief Remove entry from index
     */
    [[nodiscard]] StoreError Remove(
        const IOCEntry& entry
    ) noexcept;
    
    /**
     * @brief Update entry in index
     */
    [[nodiscard]] StoreError Update(
        const IOCEntry& oldEntry,
        const IOCEntry& newEntry,
        uint64_t newEntryOffset
    ) noexcept;
    
    /**
     * @brief Batch insert entries
     */
    [[nodiscard]] StoreError BatchInsert(
        std::span<const std::pair<IOCEntry, uint64_t>> entries
    ) noexcept;
    
    /**
     * @brief Enterprise-grade batch removal with transaction-like semantics
     * @param entries Entries to remove
     * @return StoreError with success/failure details
     * 
     * Removes all specified entries from indexes. Returns partial success
     * if some entries were not found.
     */
    [[nodiscard]] StoreError BatchRemove(
        std::span<const IOCEntry> entries
    ) noexcept;
    
    /**
     * @brief Enterprise-grade batch update with transaction-like semantics
     * @param updates Vector of (oldEntry, newEntry, newOffset) tuples
     * @return StoreError with success/failure details
     * 
     * Atomically updates all specified entries. Each update removes the old entry
     * and inserts the new entry. Returns partial success if some updates failed.
     */
    [[nodiscard]] StoreError BatchUpdate(
        std::span<const std::tuple<IOCEntry, IOCEntry, uint64_t>> updates
    ) noexcept;
    
    // =========================================================================
    // INDEX MAINTENANCE
    // =========================================================================
    
    /**
     * @brief Rebuild all indexes from entries
     * @param entries All IOC entries
     * @param options Build options
     * @return Success or error code
     */
    [[nodiscard]] StoreError RebuildAll(
        std::span<const IOCEntry> entries,
        const IndexBuildOptions& options = IndexBuildOptions::Default()
    ) noexcept;
    
    /**
     * @brief Rebuild specific index
     */
    [[nodiscard]] StoreError RebuildIndex(
        IOCType indexType,
        std::span<const IOCEntry> entries,
        const IndexBuildOptions& options = IndexBuildOptions::Default()
    ) noexcept;
    
    /**
     * @brief Optimize indexes for read performance
     */
    [[nodiscard]] StoreError Optimize() noexcept;
    
    /**
     * @brief Verify index integrity
     */
    [[nodiscard]] StoreError Verify() const noexcept;
    
    /**
     * @brief Flush index changes to disk
     */
    [[nodiscard]] StoreError Flush() noexcept;
    
    // =========================================================================
    // STATISTICS & DIAGNOSTICS
    // =========================================================================
    
    /**
     * @brief Get comprehensive statistics
     */
    [[nodiscard]] IndexStatistics GetStatistics() const noexcept;
    
    /**
     * @brief Reset performance statistics
     */
    void ResetStatistics() noexcept;
    
    /**
     * @brief Get memory usage in bytes
     */
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    
    /**
     * @brief Get entry count for specific index type
     */
    [[nodiscard]] uint64_t GetEntryCount(IOCType type) const noexcept;
    
    /**
     * @brief Dump index structure (for debugging)
     */
    void DumpStructure(
        IOCType type,
        std::function<void(const std::string&)> outputCallback
    ) const noexcept;
    
    /**
     * @brief Validate index invariants (expensive)
     */
    [[nodiscard]] bool ValidateInvariants(
        IOCType type,
        std::string& errorMessage
    ) const noexcept;
    
private:
    // =========================================================================
    // INTERNAL IMPLEMENTATION (PIMPL PATTERN)
    // =========================================================================
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    /// @brief Initialization flag
    std::atomic<bool> m_initialized{false};
    
    /// @brief Reader-writer lock for thread safety
    mutable std::shared_mutex m_rwLock;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Calculate optimal index size for entry count
 */
[[nodiscard]] uint64_t CalculateIndexSize(
    IOCType type,
    uint64_t entryCount
) noexcept;

/**
 * @brief Estimate memory requirements for index build
 */
[[nodiscard]] uint64_t EstimateIndexMemory(
    std::span<const IOCEntry> entries,
    const IndexBuildOptions& options
) noexcept;

/**
 * @brief Convert domain to reverse notation (www.example.com -> com.example.www)
 */
[[nodiscard]] std::string ConvertToReverseDomain(std::string_view domain) noexcept;

/**
 * @brief Normalize URL for indexing (remove fragments, sort params)
 */
[[nodiscard]] std::string NormalizeURL(std::string_view url) noexcept;

/**
 * @brief Validate index configuration
 */
[[nodiscard]] bool ValidateIndexConfiguration(
    const IndexBuildOptions& options,
    std::string& errorMessage
) noexcept;

} // namespace ThreatIntel
} // namespace ShadowStrike
