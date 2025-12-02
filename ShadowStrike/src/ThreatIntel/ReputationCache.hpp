/*
 * ============================================================================
 * ShadowStrike ReputationCache - ULTRA-HIGH PERFORMANCE THREAT INTEL CACHE
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade, lock-free read path reputation cache for threat intelligence
 * Designed for real-time malware detection at scale (millions of lookups/second)
 *
 * Architecture Highlights:
 * - SeqLock for lock-free reads (< 50ns read latency target)
 * - Cache-line aligned entries to prevent false sharing
 * - Bloom filter for O(1) negative lookups (< 20ns)
 * - LRU eviction with O(1) operations via intrusive linked list
 * - TTL-based automatic expiration
 * - Sharded design for horizontal scalability
 * - NUMA-aware memory allocation (optional)
 * - Lock-free statistics collection
 *
 * Performance Targets:
 * - Cache hit lookup: < 50ns average
 * - Cache miss (bloom reject): < 20ns
 * - Cache miss (full lookup): < 100ns
 * - Insertion: < 500ns (with eviction)
 * - Memory overhead: < 5% of cached data
 *
 * Thread Safety:
 * - Multiple concurrent readers: Lock-free via SeqLock
 * - Single writer per shard: Mutex protected
 * - Statistics: Atomic counters with relaxed ordering
 *
 * Performance Standards: CrowdStrike Falcon / Microsoft Defender ATP quality
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ReputationCache;
class CacheShard;
class BloomFilter;

// ============================================================================
// CACHE CONFIGURATION CONSTANTS
// ============================================================================

namespace CacheConfig {

/// @brief Default number of cache shards (power of 2 for fast modulo)
constexpr size_t DEFAULT_SHARD_COUNT = 64;

/// @brief Default entries per shard
constexpr size_t DEFAULT_ENTRIES_PER_SHARD = 16384;

/// @brief Total default cache capacity
constexpr size_t DEFAULT_CACHE_CAPACITY = DEFAULT_SHARD_COUNT * DEFAULT_ENTRIES_PER_SHARD;

/// @brief Default TTL in seconds (1 hour)
constexpr uint32_t DEFAULT_TTL_SECONDS = 3600;

/// @brief Minimum TTL (1 minute)
constexpr uint32_t MIN_TTL_SECONDS = 60;

/// @brief Maximum TTL (7 days)
constexpr uint32_t MAX_TTL_SECONDS = 604800;

/// @brief Bloom filter bits per element (for ~1% false positive rate)
constexpr size_t BLOOM_BITS_PER_ELEMENT = 10;

/// @brief Number of bloom filter hash functions
constexpr size_t BLOOM_HASH_FUNCTIONS = 7;

/// @brief Cache line size for alignment
constexpr size_t CACHE_LINE_SIZE = 64;

/// @brief Maximum key size for inline storage
constexpr size_t MAX_INLINE_KEY_SIZE = 64;

/// @brief Statistics sampling interval (every Nth operation)
constexpr size_t STATS_SAMPLE_INTERVAL = 1000;

/// @brief SeqLock retry limit before falling back to mutex
constexpr size_t SEQLOCK_MAX_RETRIES = 100;

/// @brief Pre-warm batch size
constexpr size_t PREWARM_BATCH_SIZE = 1000;

} // namespace CacheConfig

// ============================================================================
// CACHE KEY STRUCTURE
// ============================================================================

/// @brief Unified cache key supporting all IOC types
struct alignas(8) CacheKey {
    /// @brief IOC type for this key
    IOCType type{IOCType::Reserved};
    
    /// @brief Key length in bytes
    uint8_t length{0};
    
    /// @brief Reserved for alignment
    uint8_t reserved[2]{};
    
    /// @brief Pre-computed hash for fast lookup
    uint32_t hash{0};
    
    /// @brief Inline key data (for small keys like IPs, hashes)
    std::array<uint8_t, CacheConfig::MAX_INLINE_KEY_SIZE> data{};
    
    /// @brief Default constructor
    CacheKey() noexcept = default;
    
    /// @brief Construct from IPv4 address
    explicit CacheKey(const IPv4Address& addr) noexcept
        : type(IOCType::IPv4), length(sizeof(IPv4Address)) {
        std::memcpy(data.data(), &addr, sizeof(IPv4Address));
        ComputeHash();
    }
    
    /// @brief Construct from IPv6 address
    explicit CacheKey(const IPv6Address& addr) noexcept
        : type(IOCType::IPv6), length(sizeof(IPv6Address)) {
        std::memcpy(data.data(), &addr, sizeof(IPv6Address));
        ComputeHash();
    }
    
    /// @brief Construct from hash value
    explicit CacheKey(const HashValue& hashVal) noexcept
        : type(IOCType::FileHash), length(static_cast<uint8_t>(4 + hashVal.length)) {
        // Store algorithm + length + data
        data[0] = static_cast<uint8_t>(hashVal.algorithm);
        data[1] = hashVal.length;
        data[2] = 0;
        data[3] = 0;
        std::memcpy(data.data() + 4, hashVal.data.data(), hashVal.length);
        ComputeHash();
    }
    
    /// @brief Construct from string (domain, URL, email, etc.)
    CacheKey(IOCType iocType, std::string_view str) noexcept
        : type(iocType) {
        length = static_cast<uint8_t>(std::min(str.length(), CacheConfig::MAX_INLINE_KEY_SIZE));
        std::memcpy(data.data(), str.data(), length);
        ComputeHash();
    }
    
    /// @brief Construct from raw bytes
    CacheKey(IOCType iocType, const void* bytes, size_t len) noexcept
        : type(iocType), length(static_cast<uint8_t>(std::min(len, CacheConfig::MAX_INLINE_KEY_SIZE))) {
        std::memcpy(data.data(), bytes, length);
        ComputeHash();
    }
    
    /// @brief Compute FNV-1a hash
    void ComputeHash() noexcept {
        uint32_t h = 2166136261u;  // FNV offset basis
        h ^= static_cast<uint32_t>(type);
        h *= 16777619u;  // FNV prime
        for (size_t i = 0; i < length; ++i) {
            h ^= data[i];
            h *= 16777619u;
        }
        hash = h;
    }
    
    /// @brief Equality comparison
    [[nodiscard]] bool operator==(const CacheKey& other) const noexcept {
        if (hash != other.hash || type != other.type || length != other.length) {
            return false;
        }
        return std::memcmp(data.data(), other.data.data(), length) == 0;
    }
    
    [[nodiscard]] bool operator!=(const CacheKey& other) const noexcept {
        return !(*this == other);
    }
    
    /// @brief Get shard index (for sharded cache)
    [[nodiscard]] size_t GetShardIndex(size_t shardCount) const noexcept {
        // Use high bits of hash for better distribution
        return (hash >> 16) & (shardCount - 1);
    }
    
    /// @brief Get bloom filter hash seeds
    [[nodiscard]] std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> GetBloomHashes() const noexcept {
        std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> hashes{};
        
        // Use double hashing technique: h(i) = h1 + i * h2
        uint64_t h1 = hash;
        uint64_t h2 = 0;
        
        // Compute second hash
        for (size_t i = 0; i < length; ++i) {
            h2 = h2 * 31 + data[i];
        }
        h2 |= 1;  // Ensure odd for better distribution
        
        for (size_t i = 0; i < CacheConfig::BLOOM_HASH_FUNCTIONS; ++i) {
            hashes[i] = h1 + i * h2;
        }
        
        return hashes;
    }
    
    /// @brief Check if key is valid
    [[nodiscard]] bool IsValid() const noexcept {
        return type != IOCType::Reserved && length > 0;
    }
};

static_assert(sizeof(CacheKey) <= 80, "CacheKey must be <= 80 bytes");
static_assert(alignof(CacheKey) == 8, "CacheKey must be 8-byte aligned");

// ============================================================================
// CACHE VALUE STRUCTURE
// ============================================================================

/// @brief Cached reputation lookup result
struct alignas(8) CacheValue {
    /// @brief Entry ID from the main store (for full lookup if needed)
    uint64_t entryId{0};
    
    /// @brief Reputation level
    ReputationLevel reputation{ReputationLevel::Unknown};
    
    /// @brief Confidence level
    ConfidenceLevel confidence{ConfidenceLevel::None};
    
    /// @brief Threat category
    ThreatCategory category{ThreatCategory::Unknown};
    
    /// @brief Should block flag
    bool shouldBlock{false};
    
    /// @brief Should alert flag
    bool shouldAlert{false};
    
    /// @brief Is the result valid (false = negative cache / not found)
    bool isPositive{false};
    
    /// @brief Reserved
    uint8_t reserved{0};
    
    /// @brief Source of intelligence
    ThreatIntelSource source{ThreatIntelSource::Unknown};
    
    /// @brief Reserved for alignment
    uint16_t reserved2{0};
    
    /// @brief Expiration timestamp (Unix epoch seconds)
    uint32_t expirationTime{0};
    
    /// @brief Insertion timestamp
    uint32_t insertionTime{0};
    
    /// @brief Default constructor
    CacheValue() noexcept = default;
    
    /// @brief Construct positive result from LookupResult
        explicit CacheValue(const LookupResult& result, uint32_t ttlSeconds) noexcept
                : reputation(result.reputation),
                    confidence(result.confidence),
                    category(result.category),
                    shouldBlock(result.IsMalicious()),
                    shouldAlert(result.IsSuspicious()),
                    isPositive(result.found),
                    source(result.primarySource) {
                entryId = 0;
        auto now = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        insertionTime = now;
        expirationTime = now + ttlSeconds;
    }
    
    /// @brief Construct negative cache entry (IOC not found)
    static CacheValue NegativeResult(uint32_t ttlSeconds) noexcept {
        CacheValue v;
        v.isPositive = false;
        v.reputation = ReputationLevel::Unknown;
        auto now = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        v.insertionTime = now;
        v.expirationTime = now + ttlSeconds;
        return v;
    }
    
    /// @brief Check if entry is expired
    [[nodiscard]] bool IsExpired() const noexcept {
        auto now = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        return now >= expirationTime;
    }
    
    /// @brief Get remaining TTL in seconds
    [[nodiscard]] uint32_t GetRemainingTTL() const noexcept {
        auto now = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        return (now < expirationTime) ? (expirationTime - now) : 0;
    }
    
    /// @brief Get age in seconds
    [[nodiscard]] uint32_t GetAge() const noexcept {
        auto now = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        return now - insertionTime;
    }
};

static_assert(sizeof(CacheValue) == 32, "CacheValue must be 32 bytes");

// ============================================================================
// SEQLOCK-PROTECTED CACHE ENTRY
// ============================================================================

/// @brief Cache entry with SeqLock for lock-free reads
/// @note Cache-line aligned to prevent false sharing between entries
struct alignas(CacheConfig::CACHE_LINE_SIZE) CacheEntry {
    /// @brief SeqLock for lock-free reads
    /// @note Odd value = write in progress, Even value = stable
    mutable std::atomic<uint64_t> seqlock{0};
    
    /// @brief LRU doubly-linked list pointers (indices, not pointers for cache-friendliness)
    uint32_t lruPrev{UINT32_MAX};
    uint32_t lruNext{UINT32_MAX};
    
    /// @brief Cache key
    CacheKey key{};
    
    /// @brief Cached value
    CacheValue value{};
    
    /// @brief Access counter for frequency-based eviction (optional)
    mutable std::atomic<uint16_t> accessCount{0};
    
    /// @brief Is this slot occupied?
    std::atomic<bool> occupied{false};
    
    /// @brief Reserved for alignment
    uint8_t padding[5]{};
    
    /// @brief Default constructor
    CacheEntry() noexcept = default;
    
    // Disable copy (due to atomics)
    CacheEntry(const CacheEntry&) = delete;
    CacheEntry& operator=(const CacheEntry&) = delete;
    
    // Disable move (cache entries are fixed in place)
    CacheEntry(CacheEntry&&) = delete;
    CacheEntry& operator=(CacheEntry&&) = delete;
    
    /// @brief Begin read operation (returns sequence number)
    [[nodiscard]] uint64_t BeginRead() const noexcept {
        return seqlock.load(std::memory_order_acquire);
    }
    
    /// @brief Validate read operation (check if data changed during read)
    [[nodiscard]] bool ValidateRead(uint64_t seq) const noexcept {
        std::atomic_thread_fence(std::memory_order_acquire);
        uint64_t current = seqlock.load(std::memory_order_relaxed);
        // Valid if sequence hasn't changed AND was even (no write in progress)
        return (current == seq) && ((seq & 1) == 0);
    }
    
    /// @brief Begin write operation (acquires seqlock)
    void BeginWrite() noexcept {
        uint64_t expected = seqlock.load(std::memory_order_relaxed);
        // Spin until we get an even value and can increment to odd
        while (true) {
            if ((expected & 1) == 0) {
                if (seqlock.compare_exchange_weak(expected, expected + 1,
                                                   std::memory_order_acquire,
                                                   std::memory_order_relaxed)) {
                    break;
                }
            } else {
                expected = seqlock.load(std::memory_order_relaxed);
            }
            // Brief pause to reduce contention
            _mm_pause();
        }
    }
    
    /// @brief End write operation (releases seqlock)
    void EndWrite() noexcept {
        seqlock.fetch_add(1, std::memory_order_release);
    }
    
    /// @brief Increment access count (for LFU hybrid)
    void Touch() const noexcept {
        // Saturating increment
        uint16_t current = accessCount.load(std::memory_order_relaxed);
        if (current < UINT16_MAX) {
            accessCount.store(current + 1, std::memory_order_relaxed);
        }
    }
    
    /// @brief Clear entry
    void Clear() noexcept {
        BeginWrite();
        key = CacheKey{};
        value = CacheValue{};
        lruPrev = UINT32_MAX;
        lruNext = UINT32_MAX;
        accessCount.store(0, std::memory_order_relaxed);
        occupied.store(false, std::memory_order_release);
        EndWrite();
    }
};

// Verify cache entry fits in expected size (should be 2 cache lines = 128 bytes)
static_assert(sizeof(CacheEntry) <= 256, "CacheEntry too large");
static_assert(sizeof(CacheEntry) % CacheConfig::CACHE_LINE_SIZE == 0, 
              "CacheEntry must be multiple of cache line size");

// ============================================================================
// BLOOM FILTER
// ============================================================================

/// @brief High-performance bloom filter for fast negative lookups
class BloomFilter {
public:
    /// @brief Construct with expected elements and false positive rate
    /// @param expectedElements Expected number of elements
    /// @param falsePositiveRate Target false positive rate (0.0 - 1.0)
    explicit BloomFilter(
        size_t expectedElements = CacheConfig::DEFAULT_CACHE_CAPACITY,
        double falsePositiveRate = 0.01
    );
    
    /// @brief Destructor
    ~BloomFilter() = default;
    
    // Disable copy
    BloomFilter(const BloomFilter&) = delete;
    BloomFilter& operator=(const BloomFilter&) = delete;
    
    // Enable move
    BloomFilter(BloomFilter&&) noexcept = default;
    BloomFilter& operator=(BloomFilter&&) noexcept = default;
    
    // ========================================================================
    // OPERATIONS
    // ========================================================================
    
    /// @brief Add key to bloom filter (thread-safe)
    void Add(const CacheKey& key) noexcept;
    
    /// @brief Add using pre-computed hashes (thread-safe)
    void Add(const std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS>& hashes) noexcept;
    
    /// @brief Check if key might exist (thread-safe)
    /// @return true if key might exist, false if definitely not present
    [[nodiscard]] bool MightContain(const CacheKey& key) const noexcept;
    
    /// @brief Check using pre-computed hashes (thread-safe)
    [[nodiscard]] bool MightContain(
        const std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS>& hashes
    ) const noexcept;
    
    /// @brief Clear all bits (thread-safe but invalidates concurrent reads)
    void Clear() noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /// @brief Get filter size in bits
    [[nodiscard]] size_t GetBitCount() const noexcept { return m_bitCount; }
    
    /// @brief Get filter size in bytes
    [[nodiscard]] size_t GetByteCount() const noexcept { return m_data.size() * sizeof(uint64_t); }
    
    /// @brief Get number of hash functions
    [[nodiscard]] size_t GetHashFunctions() const noexcept { return CacheConfig::BLOOM_HASH_FUNCTIONS; }
    
    /// @brief Estimate current fill rate
    [[nodiscard]] double EstimateFillRate() const noexcept;
    
    /// @brief Estimate current false positive rate
    [[nodiscard]] double EstimateFalsePositiveRate() const noexcept;
    
    /// @brief Get number of elements added
    [[nodiscard]] size_t GetElementCount() const noexcept {
        return m_elementCount.load(std::memory_order_relaxed);
    }
    
private:
    /// @brief Bit array (using atomic for thread-safe bit operations)
    std::vector<std::atomic<uint64_t>> m_data;
    
    /// @brief Total bit count
    size_t m_bitCount{0};
    
    /// @brief Element count
    std::atomic<size_t> m_elementCount{0};
    
    /// @brief Set bit at index (thread-safe)
    void SetBit(size_t index) noexcept;
    
    /// @brief Test bit at index (thread-safe)
    [[nodiscard]] bool TestBit(size_t index) const noexcept;
};

// ============================================================================
// CACHE SHARD
// ============================================================================

/// @brief Single shard of the cache (for reduced contention)
class CacheShard {
public:
    /// @brief Construct shard with capacity
    explicit CacheShard(size_t capacity);
    
    /// @brief Destructor
    ~CacheShard();
    
    // Disable copy and move (complex internal state)
    CacheShard(const CacheShard&) = delete;
    CacheShard& operator=(const CacheShard&) = delete;
    CacheShard(CacheShard&&) = delete;
    CacheShard& operator=(CacheShard&&) = delete;
    
    // ========================================================================
    // LOOKUP OPERATIONS
    // ========================================================================
    
    /// @brief Look up key in shard (lock-free read path)
    /// @param key Cache key
    /// @param[out] value Output value if found
    /// @return true if found and not expired
    [[nodiscard]] bool Lookup(const CacheKey& key, CacheValue& value) const noexcept;
    
    /// @brief Check if key exists (without returning value)
    [[nodiscard]] bool Contains(const CacheKey& key) const noexcept;
    
    // ========================================================================
    // MODIFICATION OPERATIONS
    // ========================================================================
    
    /// @brief Insert or update entry
    /// @param key Cache key
    /// @param value Cache value
    /// @return true if inserted, false if updated existing
    bool Insert(const CacheKey& key, const CacheValue& value) noexcept;
    
    /// @brief Remove entry by key
    /// @param key Cache key
    /// @return true if removed
    bool Remove(const CacheKey& key) noexcept;
    
    /// @brief Clear all entries
    void Clear() noexcept;
    
    /// @brief Evict expired entries
    /// @return Number of entries evicted
    size_t EvictExpired() noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /// @brief Get current entry count
    [[nodiscard]] size_t GetEntryCount() const noexcept {
        return m_entryCount.load(std::memory_order_relaxed);
    }
    
    /// @brief Get shard capacity
    [[nodiscard]] size_t GetCapacity() const noexcept { return m_capacity; }
    
    /// @brief Get hit count
    [[nodiscard]] uint64_t GetHitCount() const noexcept {
        return m_hitCount.load(std::memory_order_relaxed);
    }
    
    /// @brief Get miss count
    [[nodiscard]] uint64_t GetMissCount() const noexcept {
        return m_missCount.load(std::memory_order_relaxed);
    }
    
    /// @brief Reset statistics
    void ResetStatistics() noexcept;
    
private:
    /// @brief Cache entries array
    std::unique_ptr<CacheEntry[]> m_entries;
    
    /// @brief Shard capacity
    size_t m_capacity{0};
    
    /// @brief Current entry count
    std::atomic<size_t> m_entryCount{0};
    
    /// @brief Hash table for O(1) lookup (maps hash -> entry index)
    std::unique_ptr<std::atomic<uint32_t>[]> m_hashTable;
    
    /// @brief Hash table size (power of 2)
    size_t m_hashTableSize{0};
    
    /// @brief LRU list head (most recently used)
    uint32_t m_lruHead{UINT32_MAX};
    
    /// @brief LRU list tail (least recently used)
    uint32_t m_lruTail{UINT32_MAX};
    
    /// @brief Free list head
    uint32_t m_freeHead{0};
    
    /// @brief Mutex for write operations
    mutable std::mutex m_writeMutex;
    
    /// @brief Statistics
    mutable std::atomic<uint64_t> m_hitCount{0};
    mutable std::atomic<uint64_t> m_missCount{0};
    mutable std::atomic<uint64_t> m_evictionCount{0};
    mutable std::atomic<uint64_t> m_insertCount{0};
    
    /// @brief Find entry by key (returns index or UINT32_MAX)
    [[nodiscard]] uint32_t FindEntry(const CacheKey& key) const noexcept;
    
    /// @brief Allocate free entry (may trigger eviction)
    [[nodiscard]] uint32_t AllocateEntry() noexcept;
    
    /// @brief Free an entry
    void FreeEntry(uint32_t index) noexcept;
    
    /// @brief Move entry to front of LRU list
    void TouchLRU(uint32_t index) noexcept;
    
    /// @brief Remove entry from LRU list
    void RemoveFromLRU(uint32_t index) noexcept;
    
    /// @brief Add entry to front of LRU list
    void AddToLRUFront(uint32_t index) noexcept;
    
    /// @brief Evict least recently used entry
    [[nodiscard]] uint32_t EvictLRU() noexcept;
    
    /// @brief Get hash table slot for key
    [[nodiscard]] size_t GetHashSlot(const CacheKey& key) const noexcept;
};

// ============================================================================
// CACHE STATISTICS
// ============================================================================

/// @brief Cache performance statistics
struct CacheStatistics {
    /// @brief Total entries in cache
    size_t totalEntries{0};
    
    /// @brief Total cache capacity
    size_t totalCapacity{0};
    
    /// @brief Cache utilization (0.0 - 1.0)
    double utilization{0.0};
    
    /// @brief Total lookup operations
    uint64_t totalLookups{0};
    
    /// @brief Cache hits
    uint64_t cacheHits{0};
    
    /// @brief Cache misses
    uint64_t cacheMisses{0};
    
    /// @brief Bloom filter rejections (definite negative)
    uint64_t bloomRejects{0};
    
    /// @brief Cache insertions
    uint64_t insertions{0};
    
    /// @brief Cache evictions
    uint64_t evictions{0};
    
    /// @brief Expired entry evictions
    uint64_t expirations{0};
    
    /// @brief Hit rate (0.0 - 1.0)
    double hitRate{0.0};
    
    /// @brief Bloom filter effectiveness (rejection rate)
    double bloomEffectiveness{0.0};
    
    /// @brief Average lookup time (nanoseconds)
    uint64_t avgLookupTimeNs{0};
    
    /// @brief P99 lookup time (nanoseconds)
    uint64_t p99LookupTimeNs{0};
    
    /// @brief Memory usage in bytes
    size_t memoryUsageBytes{0};
    
    /// @brief Bloom filter memory in bytes
    size_t bloomFilterBytes{0};
    
    /// @brief Bloom filter estimated fill rate
    double bloomFillRate{0.0};
    
    /// @brief Bloom filter estimated false positive rate
    double bloomFalsePositiveRate{0.0};
};

// ============================================================================
// CACHE OPTIONS
// ============================================================================

/// @brief Configuration options for ReputationCache
struct CacheOptions {
    /// @brief Number of shards (must be power of 2)
    size_t shardCount{CacheConfig::DEFAULT_SHARD_COUNT};
    
    /// @brief Total cache capacity
    size_t totalCapacity{CacheConfig::DEFAULT_CACHE_CAPACITY};
    
    /// @brief Default TTL for positive results (seconds)
    uint32_t positiveTTL{CacheConfig::DEFAULT_TTL_SECONDS};
    
    /// @brief Default TTL for negative results (seconds)
    uint32_t negativeTTL{300};  // 5 minutes for negative cache
    
    /// @brief Enable bloom filter for fast negative lookups
    bool enableBloomFilter{true};
    
    /// @brief Bloom filter expected elements
    size_t bloomExpectedElements{CacheConfig::DEFAULT_CACHE_CAPACITY * 2};
    
    /// @brief Bloom filter target false positive rate
    double bloomFalsePositiveRate{0.01};
    
    /// @brief Enable statistics collection
    bool enableStatistics{true};
    
    /// @brief Enable automatic expired entry eviction
    bool enableAutoEviction{true};
    
    /// @brief Auto eviction interval (seconds)
    uint32_t autoEvictionIntervalSeconds{60};
    
    /// @brief Validate options
    [[nodiscard]] bool Validate() const noexcept {
        // Shard count must be power of 2
        if (shardCount == 0 || (shardCount & (shardCount - 1)) != 0) {
            return false;
        }
        
        // Reasonable capacity
        if (totalCapacity < shardCount) {
            return false;
        }
        
        // TTL within limits
        if (positiveTTL < CacheConfig::MIN_TTL_SECONDS || 
            positiveTTL > CacheConfig::MAX_TTL_SECONDS) {
            return false;
        }
        
        if (negativeTTL < CacheConfig::MIN_TTL_SECONDS || 
            negativeTTL > CacheConfig::MAX_TTL_SECONDS) {
            return false;
        }
        
        // Bloom filter rate valid
        if (enableBloomFilter && 
            (bloomFalsePositiveRate <= 0.0 || bloomFalsePositiveRate >= 1.0)) {
            return false;
        }
        
        return true;
    }
};

// ============================================================================
// REPUTATION CACHE (Main Interface)
// ============================================================================

/// @brief High-performance thread-safe reputation cache
class ReputationCache {
public:
    /// @brief Construct with default options
    ReputationCache();
    
    /// @brief Construct with custom options
    explicit ReputationCache(const CacheOptions& options);
    
    /// @brief Destructor
    ~ReputationCache();
    
    // Disable copy (complex internal state)
    ReputationCache(const ReputationCache&) = delete;
    ReputationCache& operator=(const ReputationCache&) = delete;
    
    // Disable move (would invalidate shard pointers)
    ReputationCache(ReputationCache&&) = delete;
    ReputationCache& operator=(ReputationCache&&) = delete;
    
    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    
    /// @brief Initialize cache (must call before use)
    [[nodiscard]] StoreError Initialize() noexcept;
    
    /// @brief Check if cache is initialized
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }
    
    /// @brief Shutdown cache
    void Shutdown() noexcept;
    
    // ========================================================================
    // LOOKUP OPERATIONS (Lock-free read path)
    // ========================================================================
    
    /// @brief Look up IPv4 address
    /// @param addr IPv4 address
    /// @param[out] value Output value if found
    /// @return true if found in cache
    [[nodiscard]] bool Lookup(const IPv4Address& addr, CacheValue& value) const noexcept;
    
    /// @brief Look up IPv6 address
    [[nodiscard]] bool Lookup(const IPv6Address& addr, CacheValue& value) const noexcept;
    
    /// @brief Look up hash value
    [[nodiscard]] bool Lookup(const HashValue& hash, CacheValue& value) const noexcept;
    
    /// @brief Look up domain
    [[nodiscard]] bool LookupDomain(std::string_view domain, CacheValue& value) const noexcept;
    
    /// @brief Look up URL
    [[nodiscard]] bool LookupURL(std::string_view url, CacheValue& value) const noexcept;
    
    /// @brief Look up email
    [[nodiscard]] bool LookupEmail(std::string_view email, CacheValue& value) const noexcept;
    
    /// @brief Generic lookup by key
    [[nodiscard]] bool Lookup(const CacheKey& key, CacheValue& value) const noexcept;
    
    /// @brief Quick check if key might exist (bloom filter only)
    /// @return false if definitely not in cache (fast path)
    [[nodiscard]] bool MightContain(const CacheKey& key) const noexcept;
    
    // ========================================================================
    // BATCH LOOKUP
    // ========================================================================
    
    /// @brief Batch lookup for multiple keys
    /// @param keys Input keys
    /// @param[out] values Output values (parallel to keys)
    /// @param[out] found Output flags (parallel to keys)
    void BatchLookup(
        std::span<const CacheKey> keys,
        std::span<CacheValue> values,
        std::span<bool> found
    ) const noexcept;
    
    // ========================================================================
    // INSERTION OPERATIONS
    // ========================================================================
    
    /// @brief Insert IPv4 result
    void Insert(const IPv4Address& addr, const CacheValue& value) noexcept;
    
    /// @brief Insert IPv6 result
    void Insert(const IPv6Address& addr, const CacheValue& value) noexcept;
    
    /// @brief Insert hash result
    void Insert(const HashValue& hash, const CacheValue& value) noexcept;
    
    /// @brief Insert domain result
    void InsertDomain(std::string_view domain, const CacheValue& value) noexcept;
    
    /// @brief Insert URL result
    void InsertURL(std::string_view url, const CacheValue& value) noexcept;
    
    /// @brief Insert email result
    void InsertEmail(std::string_view email, const CacheValue& value) noexcept;
    
    /// @brief Generic insert by key
    void Insert(const CacheKey& key, const CacheValue& value) noexcept;
    
    /// @brief Insert from LookupResult
    void Insert(const CacheKey& key, const LookupResult& result) noexcept;
    
    /// @brief Insert negative result (IOC not found)
    void InsertNegative(const CacheKey& key) noexcept;
    
    // ========================================================================
    // REMOVAL OPERATIONS
    // ========================================================================
    
    /// @brief Remove entry by key
    /// @return true if entry was removed
    bool Remove(const CacheKey& key) noexcept;
    
    /// @brief Clear all entries
    void Clear() noexcept;
    
    /// @brief Evict expired entries from all shards
    /// @return Total number of entries evicted
    size_t EvictExpired() noexcept;
    
    // ========================================================================
    // PRE-WARMING
    // ========================================================================
    
    /// @brief Pre-warm cache with entries
    /// @param keys Keys to pre-warm
    /// @param values Values for keys
    void PreWarm(
        std::span<const CacheKey> keys,
        std::span<const CacheValue> values
    ) noexcept;
    
    /// @brief Pre-warm callback type
    using PreWarmCallback = std::function<bool(const CacheKey&, CacheValue&)>;
    
    /// @brief Pre-warm with callback (for lazy loading)
    /// @param keys Keys to pre-warm
    /// @param callback Callback to fetch values
    void PreWarm(
        std::span<const CacheKey> keys,
        const PreWarmCallback& callback
    ) noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /// @brief Get cache statistics
    [[nodiscard]] CacheStatistics GetStatistics() const noexcept;
    
    /// @brief Reset all statistics
    void ResetStatistics() noexcept;
    
    /// @brief Get total entry count
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    
    /// @brief Get total capacity
    [[nodiscard]] size_t GetCapacity() const noexcept;
    
    /// @brief Get memory usage in bytes
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /// @brief Get current options (read-only after initialization)
    [[nodiscard]] const CacheOptions& GetOptions() const noexcept { return m_options; }
    
    /// @brief Set positive TTL (affects new insertions only)
    void SetPositiveTTL(uint32_t seconds) noexcept;
    
    /// @brief Set negative TTL (affects new insertions only)
    void SetNegativeTTL(uint32_t seconds) noexcept;
    
private:
    /// @brief Configuration options
    CacheOptions m_options;
    
    /// @brief Initialization flag
    std::atomic<bool> m_initialized{false};
    
    /// @brief Cache shards
    std::vector<std::unique_ptr<CacheShard>> m_shards;
    
    /// @brief Bloom filter for fast negative lookups
    std::unique_ptr<BloomFilter> m_bloomFilter;
    
    /// @brief Current positive TTL
    std::atomic<uint32_t> m_positiveTTL;
    
    /// @brief Current negative TTL
    std::atomic<uint32_t> m_negativeTTL;
    
    /// @brief Global statistics
    mutable std::atomic<uint64_t> m_totalLookups{0};
    mutable std::atomic<uint64_t> m_bloomRejects{0};
    
    /// @brief Get shard for key
    [[nodiscard]] CacheShard* GetShard(const CacheKey& key) noexcept;
    [[nodiscard]] const CacheShard* GetShard(const CacheKey& key) const noexcept;
};

} // namespace ThreatIntel
} // namespace ShadowStrike
