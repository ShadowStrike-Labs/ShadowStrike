/*
 * ============================================================================
 * ShadowStrike ThreatIntelLookup - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * Enterprise-grade implementation of unified threat intelligence lookup.
 * Optimized for nanosecond-level performance with multi-tier caching.
 *
 * ============================================================================
 */

#include "ThreatIntelLookup.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <execution>
#include <limits>
#include <sstream>
#include <unordered_map>

#ifdef _WIN32
#  include <intrin.h>
#  include <immintrin.h>  // SIMD intrinsics
#endif

// Branch prediction hints
#ifdef _MSC_VER
#  define LIKELY(x)   (x)
#  define UNLIKELY(x) (x)
#else
#  define LIKELY(x)   __builtin_expect(!!(x), 1)
#  define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

// Prefetch hints
#ifdef _MSC_VER
#  define PREFETCH_READ(addr)  _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#  define PREFETCH_WRITE(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#else
#  define PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
#  define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
#endif

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// THREAD-LOCAL CACHE IMPLEMENTATION
// ============================================================================

/**
 * @brief Thread-local LRU cache for hot entries
 * 
 * Each thread maintains its own small cache to avoid contention.
 * Uses intrusive linked list for O(1) LRU operations.
 */
class alignas(64) ThreadLocalCache {
public:
    explicit ThreadLocalCache(size_t capacity)
        : m_capacity(capacity)
        , m_entries(capacity)
        , m_head(nullptr)
        , m_tail(nullptr)
        , m_size(0)
    {
        // Initialize free list
        for (size_t i = 0; i < capacity; ++i) {
            m_freeList.push_back(&m_entries[i]);
        }
    }
    
    /**
     * @brief Lookup entry in thread-local cache
     */
    [[nodiscard]] std::optional<ThreatLookupResult> Lookup(
        IOCType type,
        std::string_view value
    ) noexcept {
        const uint32_t hash = ComputeHash(type, value);
        
        // Linear probe in thread-local cache
        for (auto* entry = m_head; entry != nullptr; entry = entry->next) {
            if (entry->hash == hash && entry->type == type && entry->value == value) {
                // Move to front (MRU)
                if (entry != m_head) {
                    MoveToFront(entry);
                }
                
                ++m_hits;
                return entry->result;
            }
        }
        
        ++m_misses;
        return std::nullopt;
    }
    
    /**
     * @brief Insert entry into thread-local cache
     */
    void Insert(
        IOCType type,
        std::string_view value,
        const ThreatLookupResult& result
    ) noexcept {
        const uint32_t hash = ComputeHash(type, value);
        
        // Check if already exists
        for (auto* entry = m_head; entry != nullptr; entry = entry->next) {
            if (entry->hash == hash && entry->type == type && entry->value == value) {
                entry->result = result;
                MoveToFront(entry);
                return;
            }
        }
        
        // Get entry from free list or evict LRU
        CacheEntry* entry = nullptr;
        if (!m_freeList.empty()) {
            entry = m_freeList.back();
            m_freeList.pop_back();
        } else {
            // Evict LRU
            entry = m_tail;
            Unlink(entry);
        }
        
        // Fill entry
        entry->hash = hash;
        entry->type = type;
        entry->value = std::string(value);
        entry->result = result;
        
        // Insert at head
        InsertAtHead(entry);
    }
    
    /**
     * @brief Clear cache
     */
    void Clear() noexcept {
        m_head = nullptr;
        m_tail = nullptr;
        m_size = 0;
        m_freeList.clear();
        
        for (auto& entry : m_entries) {
            m_freeList.push_back(&entry);
        }
    }
    
    /**
     * @brief Get hit rate
     */
    [[nodiscard]] double GetHitRate() const noexcept {
        const uint64_t total = m_hits + m_misses;
        return total > 0 ? static_cast<double>(m_hits) / total * 100.0 : 0.0;
    }

private:
    struct CacheEntry {
        uint32_t hash{0};
        IOCType type{IOCType::Reserved};
        std::string value;
        ThreatLookupResult result;
        CacheEntry* prev{nullptr};
        CacheEntry* next{nullptr};
    };
    
    /**
     * @brief Compute FNV-1a hash
     */
    [[nodiscard]] static uint32_t ComputeHash(IOCType type, std::string_view value) noexcept {
        uint32_t hash = 2166136261u;
        hash ^= static_cast<uint32_t>(type);
        hash *= 16777619u;
        
        for (char c : value) {
            hash ^= static_cast<uint8_t>(c);
            hash *= 16777619u;
        }
        
        return hash;
    }
    
    void MoveToFront(CacheEntry* entry) noexcept {
        if (entry == m_head) return;
        
        Unlink(entry);
        InsertAtHead(entry);
    }
    
    void Unlink(CacheEntry* entry) noexcept {
        if (entry->prev) {
            entry->prev->next = entry->next;
        } else {
            m_head = entry->next;
        }
        
        if (entry->next) {
            entry->next->prev = entry->prev;
        } else {
            m_tail = entry->prev;
        }
        
        --m_size;
    }
    
    void InsertAtHead(CacheEntry* entry) noexcept {
        entry->prev = nullptr;
        entry->next = m_head;
        
        if (m_head) {
            m_head->prev = entry;
        } else {
            m_tail = entry;
        }
        
        m_head = entry;
        ++m_size;
    }
    
    const size_t m_capacity;
    std::vector<CacheEntry> m_entries;
    std::vector<CacheEntry*> m_freeList;
    CacheEntry* m_head;
    CacheEntry* m_tail;
    size_t m_size;
    
    uint64_t m_hits{0};
    uint64_t m_misses{0};
};

// ============================================================================
// QUERY OPTIMIZER
// ============================================================================

/**
 * @brief Optimizes lookup queries based on runtime statistics
 */
class QueryOptimizer {
public:
    QueryOptimizer() = default;
    
    /**
     * @brief Determine optimal lookup strategy based on IOC type and history
     */
    [[nodiscard]] uint8_t GetOptimalTiers(IOCType type) const noexcept {
        // Hash lookups are fastest through index
        if (type == IOCType::FileHash) {
            return 3;  // Cache + Index + Database
        }
        
        // IP lookups benefit from all tiers
        if (type == IOCType::IPv4 || type == IOCType::IPv6) {
            return 4;  // Cache + Index + Database + (optional external)
        }
        
        // Domain/URL lookups may need external verification
        if (type == IOCType::Domain || type == IOCType::URL) {
            return 4;
        }
        
        // Default: use cache + index + database
        return 3;
    }
    
    /**
     * @brief Should we prefetch for this query
     */
    [[nodiscard]] bool ShouldPrefetch(size_t batchSize) const noexcept {
        return batchSize >= 10;  // Prefetch for batch >= 10
    }
};

// ============================================================================
// RESULT AGGREGATOR
// ============================================================================

/**
 * @brief Aggregates results from multiple sources
 */
class ResultAggregator {
public:
    /**
     * @brief Merge results from multiple threat intel sources
     */
    [[nodiscard]] static ThreatLookupResult MergeResults(
        const std::vector<ThreatLookupResult>& results
    ) noexcept {
        if (results.empty()) {
            return ThreatLookupResult{};
        }
        
        if (results.size() == 1) {
            return results[0];
        }
        
        // Aggregate results
        ThreatLookupResult merged = results[0];
        
        // Take highest reputation score
        uint8_t maxScore = 0;
        for (const auto& result : results) {
            if (result.threatScore > maxScore) {
                maxScore = result.threatScore;
                merged.reputation = result.reputation;
                merged.category = result.category;
            }
        }
        merged.threatScore = maxScore;
        
        // Aggregate confidence (average weighted by score)
        uint32_t totalWeight = 0;
        uint32_t weightedConfidence = 0;
        for (const auto& result : results) {
            const uint32_t weight = result.threatScore + 1;
            weightedConfidence += static_cast<uint32_t>(result.confidence) * weight;
            totalWeight += weight;
        }
        if (totalWeight > 0) {
            merged.confidence = static_cast<ConfidenceLevel>(weightedConfidence / totalWeight);
        }
        
        // Merge source flags
        merged.sourceFlags = 0;
        merged.sourceCount = 0;
        for (const auto& result : results) {
            merged.sourceFlags |= result.sourceFlags;
            merged.sourceCount += result.sourceCount;
        }
        
        // Take earliest first seen, latest last seen
        merged.firstSeen = UINT64_MAX;
        merged.lastSeen = 0;
        for (const auto& result : results) {
            if (result.firstSeen < merged.firstSeen) {
                merged.firstSeen = result.firstSeen;
            }
            if (result.lastSeen > merged.lastSeen) {
                merged.lastSeen = result.lastSeen;
            }
        }
        
        // Merge tags (deduplicate)
        std::unordered_set<std::string> uniqueTags;
        for (const auto& result : results) {
            for (const auto& tag : result.tags) {
                uniqueTags.insert(tag);
            }
        }
        merged.tags.assign(uniqueTags.begin(), uniqueTags.end());
        
        return merged;
    }
    
    /**
     * @brief Calculate aggregated threat score from multiple indicators
     */
    [[nodiscard]] static uint8_t CalculateThreatScore(
        ReputationLevel reputation,
        ConfidenceLevel confidence,
        uint16_t sourceCount
    ) noexcept {
        // Base score from reputation (0-100)
        uint16_t score = static_cast<uint16_t>(reputation);
        
        // Adjust by confidence (multiply by confidence factor)
        const double confidenceFactor = static_cast<double>(confidence) / 100.0;
        score = static_cast<uint16_t>(score * confidenceFactor);
        
        // Boost score if multiple sources confirm
        if (sourceCount > 1) {
            const uint16_t sourceBonus = std::min<uint16_t>(sourceCount - 1, 10) * 2;
            score = std::min<uint16_t>(score + sourceBonus, 100);
        }
        
        return static_cast<uint8_t>(std::min<uint16_t>(score, 100));
    }
};

// ============================================================================
// LOOKUP ENGINE (Core Implementation)
// ============================================================================

/**
 * @brief Core lookup engine with multi-tier strategy
 */
class LookupEngine {
public:
    LookupEngine(
        ThreatIntelStore* store,
        ThreatIntelIndex* index,
        ThreatIntelIOCManager* iocManager,
        ReputationCache* cache
    ) noexcept
        : m_store(store)
        , m_index(index)
        , m_iocManager(iocManager)
        , m_cache(cache)
    {}
    
    /**
     * @brief Execute multi-tier lookup
     */
    [[nodiscard]] ThreatLookupResult ExecuteLookup(
        IOCType type,
        std::string_view value,
        const LookupOptions& options,
        ThreadLocalCache* tlCache
    ) noexcept {
        const auto startTime = std::chrono::high_resolution_clock::now();
        
        ThreatLookupResult result;
        result.type = type;
        
        // Tier 1: Thread-Local Cache (< 20ns)
        if (LIKELY(tlCache != nullptr && options.maxLookupTiers >= 1)) {
            const auto cachedResult = tlCache->Lookup(type, value);
            if (cachedResult.has_value()) {
                result = cachedResult.value();
                result.source = ThreatLookupResult::Source::ThreadLocalCache;
                
                const auto endTime = std::chrono::high_resolution_clock::now();
                result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    endTime - startTime
                ).count();
                
                return result;
            }
        }
        
        // Tier 2: Shared Memory Cache (< 50ns)
        if (LIKELY(m_cache != nullptr && options.maxLookupTiers >= 2)) {
            result = LookupInCache(type, value);
            if (result.found) {
                result.source = ThreatLookupResult::Source::SharedCache;
                
                // Cache in thread-local cache
                if (tlCache != nullptr && options.cacheResult) {
                    tlCache->Insert(type, value, result);
                }
                
                const auto endTime = std::chrono::high_resolution_clock::now();
                result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    endTime - startTime
                ).count();
                
                return result;
            }
        }
        
        // Tier 3: Index Lookup (< 100ns)
        if (LIKELY(m_index != nullptr && options.maxLookupTiers >= 3)) {
            result = LookupInIndex(type, value, options);
            if (result.found) {
                result.source = ThreatLookupResult::Source::Index;
                
                // Update caches
                if (options.cacheResult) {
                    if (tlCache != nullptr) {
                        tlCache->Insert(type, value, result);
                    }
                    if (m_cache != nullptr) {
                        CacheResult(type, value, result);
                    }
                }
                
                const auto endTime = std::chrono::high_resolution_clock::now();
                result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    endTime - startTime
                ).count();
                
                return result;
            }
        }
        
        // Tier 4: Database Query (< 500ns)
        if (LIKELY(m_store != nullptr && options.maxLookupTiers >= 4)) {
            result = LookupInDatabase(type, value, options);
            if (result.found) {
                result.source = ThreatLookupResult::Source::Database;
                
                // Update caches
                if (options.cacheResult) {
                    if (tlCache != nullptr) {
                        tlCache->Insert(type, value, result);
                    }
                    if (m_cache != nullptr) {
                        CacheResult(type, value, result);
                    }
                }
                
                const auto endTime = std::chrono::high_resolution_clock::now();
                result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    endTime - startTime
                ).count();
                
                return result;
            }
        }
        
        // Tier 5: External API Query (< 50ms, async)
        if (UNLIKELY(options.queryExternalAPI && options.maxLookupTiers >= 5)) {
            result = LookupViaExternalAPI(type, value, options);
            if (result.found) {
                result.source = ThreatLookupResult::Source::ExternalAPI;
                
                // Cache external results
                if (options.cacheResult) {
                    if (tlCache != nullptr) {
                        tlCache->Insert(type, value, result);
                    }
                    if (m_cache != nullptr) {
                        CacheResult(type, value, result);
                    }
                }
            }
        }
        
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - startTime
        ).count();
        
        return result;
    }

private:
    /**
     * @brief Lookup in shared memory cache
     */
    [[nodiscard]] ThreatLookupResult LookupInCache(
        IOCType type,
        std::string_view value
    ) noexcept {
        ThreatLookupResult result;
        result.type = type;
        result.found = false;
        
        if (m_cache == nullptr) {
            return result;
        }
        
        // Create cache key
        CacheKey key(type, value);
        
        // TODO: Lookup in cache when API is defined
        // For now, return not found
        (void)key;  // Suppress unused warning
        
        return result;
    }
    
    /**
     * @brief Lookup in index
     */
    [[nodiscard]] ThreatLookupResult LookupInIndex(
        IOCType type,
        std::string_view value,
        const LookupOptions& options
    ) noexcept {
        ThreatLookupResult result;
        result.type = type;
        result.found = false;
        
        if (m_index == nullptr) {
            return result;
        }
        
        IndexQueryOptions indexOpts = IndexQueryOptions::Default();
        indexOpts.useBloomFilter = true;
        indexOpts.prefetchNodes = true;
        
        IndexLookupResult indexResult;
        
        // Route to appropriate index based on type
        switch (type) {
            case IOCType::IPv4: {
                IPv4Address addr = ParseIPv4(value);
                indexResult = m_index->LookupIPv4(addr, indexOpts);
                break;
            }
            case IOCType::IPv6: {
                IPv6Address addr = ParseIPv6(value);
                indexResult = m_index->LookupIPv6(addr, indexOpts);
                break;
            }
            case IOCType::Domain: {
                indexResult = m_index->LookupDomain(value, indexOpts);
                break;
            }
            case IOCType::URL: {
                indexResult = m_index->LookupURL(value, indexOpts);
                break;
            }
            case IOCType::FileHash: {
                HashValue hash = ParseHash(value);
                indexResult = m_index->LookupHash(hash, indexOpts);
                break;
            }
            case IOCType::Email: {
                indexResult = m_index->LookupEmail(value, indexOpts);
                break;
            }
            default: {
                indexResult = m_index->LookupGeneric(type, value, indexOpts);
                break;
            }
        }
        
        if (indexResult.found) {
            result.found = true;
            
            // Need to fetch full entry if metadata requested
            if (options.includeMetadata && m_store != nullptr) {
                // TODO: Fetch IOC entry from store using indexResult.entryId
                // result.entry = m_store->GetEntry(indexResult.entryId);
            }
        }
        
        return result;
    }
    
    /**
     * @brief Lookup in database
     */
    [[nodiscard]] ThreatLookupResult LookupInDatabase(
        IOCType type,
        std::string_view value,
        const LookupOptions& options
    ) noexcept {
        ThreatLookupResult result;
        result.type = type;
        result.found = false;
        
        if (m_store == nullptr) {
            return result;
        }
        
        // Use store lookup
        // TODO: Implement store lookup when ThreatIntelStore API is available
        (void)options;  // Suppress unused warning
        
        // TODO: Implement actual store lookup
        // auto storeResult = m_store->Lookup(type, value, storeOpts);
        
        return result;
    }
    
    /**
     * @brief Lookup via external APIs
     */
    [[nodiscard]] ThreatLookupResult LookupViaExternalAPI(
        IOCType type,
        std::string_view value,
        const LookupOptions& options
    ) noexcept {
        ThreatLookupResult result;
        result.type = type;
        result.found = false;
        
        // TODO: Implement external API queries
        // - VirusTotal
        // - AbuseIPDB
        // - etc.
        
        return result;
    }
    
    /**
     * @brief Cache result
     */
    void CacheResult(
        IOCType type,
        std::string_view value,
        const ThreatLookupResult& result
    ) noexcept {
        if (m_cache == nullptr || !result.found) {
            return;
        }
        
        // TODO: Cache result when ReputationCache API is fully integrated
        (void)type;
        (void)value;
        (void)result;
    }
    
    /**
     * @brief Parse IPv4 address from string
     */
    [[nodiscard]] static IPv4Address ParseIPv4(std::string_view ipv4) noexcept {
        IPv4Address addr{};
        
        // Simple parser (TODO: use more robust parser)
        unsigned int octets[4] = {0};
        int count = std::sscanf(ipv4.data(), "%u.%u.%u.%u", 
                               &octets[0], &octets[1], &octets[2], &octets[3]);
        
        if (count == 4) {
            addr.address = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
            addr.prefixLength = 32;
        }
        
        return addr;
    }
    
    /**
     * @brief Parse IPv6 address from string
     */
    [[nodiscard]] static IPv6Address ParseIPv6(std::string_view ipv6) noexcept {
        IPv6Address addr{};
        // TODO: Implement IPv6 parser
        return addr;
    }
    
    /**
     * @brief Parse hash from hex string
     */
    [[nodiscard]] static HashValue ParseHash(std::string_view hexHash) noexcept {
        HashValue hash{};
        
        // Determine algorithm by length
        const size_t len = hexHash.length();
        if (len == 32) {
            hash.algorithm = HashAlgorithm::MD5;
            hash.length = 16;
        } else if (len == 40) {
            hash.algorithm = HashAlgorithm::SHA1;
            hash.length = 20;
        } else if (len == 64) {
            hash.algorithm = HashAlgorithm::SHA256;
            hash.length = 32;
        } else if (len == 128) {
            hash.algorithm = HashAlgorithm::SHA512;
            hash.length = 64;
        } else {
            return hash;
        }
        
        // Parse hex string to bytes
        for (size_t i = 0; i < hash.length && i * 2 < hexHash.length(); ++i) {
            const char high = hexHash[i * 2];
            const char low = hexHash[i * 2 + 1];
            
            auto hexDigit = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            
            hash.data[i] = (hexDigit(high) << 4) | hexDigit(low);
        }
        
        return hash;
    }
    
    ThreatIntelStore* m_store;
    ThreatIntelIndex* m_index;
    ThreatIntelIOCManager* m_iocManager;
    ReputationCache* m_cache;
};

// ============================================================================
// THREATINTELLOOKUP::IMPL (PIMPL IMPLEMENTATION)
// ============================================================================

class ThreatIntelLookup::Impl {
public:
    Impl() = default;
    ~Impl() = default;
    
    [[nodiscard]] bool Initialize(
        const LookupConfig& config,
        ThreatIntelStore* store,
        ThreatIntelIndex* index,
        ThreatIntelIOCManager* iocManager,
        ReputationCache* cache
    ) noexcept {
        std::lock_guard lock(m_mutex);
        
        if (m_initialized) {
            return false;
        }
        
        m_config = config;
        m_store = store;
        m_index = index;
        m_iocManager = iocManager;
        m_cache = cache;
        
        // Initialize lookup engine
        m_engine = std::make_unique<LookupEngine>(store, index, iocManager, cache);
        
        // Initialize query optimizer
        m_optimizer = std::make_unique<QueryOptimizer>();
        
        // Initialize thread-local caches if enabled
        if (m_config.enableThreadLocalCache) {
            // Thread-local caches will be created on-demand per thread
            m_threadLocalCacheSize = m_config.threadLocalCacheSize;
        }
        
        m_initialized = true;
        
        return true;
    }
    
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized;
    }
    
    void Shutdown() noexcept {
        std::lock_guard lock(m_mutex);
        
        if (!m_initialized) {
            return;
        }
        
        // Clear thread-local caches
        for (auto& pair : m_threadLocalCaches) {
            delete pair.second;
        }
        m_threadLocalCaches.clear();
        
        m_engine.reset();
        m_optimizer.reset();
        
        m_initialized = false;
    }
    
    [[nodiscard]] ThreatLookupResult ExecuteLookup(
        IOCType type,
        std::string_view value,
        const LookupOptions& options
    ) noexcept {
        if (UNLIKELY(!m_initialized)) {
            return ThreatLookupResult{};
        }
        
        const auto startTime = std::chrono::high_resolution_clock::now();
        
        // Get or create thread-local cache
        ThreadLocalCache* tlCache = nullptr;
        if (m_config.enableThreadLocalCache) {
            tlCache = GetOrCreateThreadLocalCache();
        }
        
        // Execute lookup through engine
        auto result = m_engine->ExecuteLookup(type, value, options, tlCache);
        
        // Update statistics
        UpdateStatistics(result);
        
        const auto endTime = std::chrono::high_resolution_clock::now();
        result.latencyNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - startTime
        ).count();
        
        return result;
    }
    
    [[nodiscard]] BatchLookupResult ExecuteBatchLookup(
        IOCType type,
        std::span<const std::string_view> values,
        const LookupOptions& options
    ) noexcept {
        BatchLookupResult batchResult;
        batchResult.totalProcessed = values.size();
        batchResult.results.reserve(values.size());
        
        if (UNLIKELY(!m_initialized || values.empty())) {
            return batchResult;
        }
        
        const auto startTime = std::chrono::high_resolution_clock::now();
        
        // Get thread-local cache
        ThreadLocalCache* tlCache = nullptr;
        if (m_config.enableThreadLocalCache) {
            tlCache = GetOrCreateThreadLocalCache();
        }
        
        // Determine if we should use parallel execution
        const bool useParallel = values.size() >= 100 && m_config.enableSIMD;
        
        if (useParallel) {
            // Parallel batch lookup
            std::vector<ThreatLookupResult> results(values.size());
            
            std::for_each(
                std::execution::par_unseq,
                values.begin(), values.end(),
                [&](std::string_view value) {
                    const size_t index = &value - &values[0];
                    results[index] = m_engine->ExecuteLookup(type, value, options, tlCache);
                }
            );
            
            batchResult.results = std::move(results);
        } else {
            // Sequential batch lookup
            for (const auto& value : values) {
                auto result = m_engine->ExecuteLookup(type, value, options, tlCache);
                batchResult.results.push_back(std::move(result));
            }
        }
        
        // Aggregate statistics
        for (const auto& result : batchResult.results) {
            if (result.found) {
                ++batchResult.foundCount;
                
                switch (result.source) {
                    case ThreatLookupResult::Source::ThreadLocalCache:
                        ++batchResult.threadLocalCacheHits;
                        break;
                    case ThreatLookupResult::Source::SharedCache:
                        ++batchResult.sharedCacheHits;
                        break;
                    case ThreatLookupResult::Source::Index:
                        ++batchResult.indexHits;
                        break;
                    case ThreatLookupResult::Source::Database:
                        ++batchResult.databaseHits;
                        break;
                    case ThreatLookupResult::Source::ExternalAPI:
                        ++batchResult.externalAPIHits;
                        break;
                    default:
                        break;
                }
                
                if (result.IsMalicious()) {
                    ++batchResult.maliciousCount;
                } else if (result.IsSuspicious()) {
                    ++batchResult.suspiciousCount;
                } else if (result.IsSafe()) {
                    ++batchResult.safeCount;
                } else {
                    ++batchResult.unknownCount;
                }
            } else {
                ++batchResult.notFoundCount;
                ++batchResult.unknownCount;
            }
            
            batchResult.totalLatencyNs += result.latencyNs;
            batchResult.minLatencyNs = std::min(batchResult.minLatencyNs, result.latencyNs);
            batchResult.maxLatencyNs = std::max(batchResult.maxLatencyNs, result.latencyNs);
            
            // Update global statistics
            UpdateStatistics(result);
        }
        
        if (batchResult.totalProcessed > 0) {
            batchResult.avgLatencyNs = batchResult.totalLatencyNs / batchResult.totalProcessed;
        }
        
        const auto endTime = std::chrono::high_resolution_clock::now();
        const uint64_t totalTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
            endTime - startTime
        ).count();
        
        // Update batch statistics
        m_statistics.batchOperations.fetch_add(1, std::memory_order_relaxed);
        m_statistics.totalBatchItems.fetch_add(values.size(), std::memory_order_relaxed);
        
        return batchResult;
    }
    
    [[nodiscard]] const LookupConfig& GetConfiguration() const noexcept {
        return m_config;
    }
    
    void UpdateConfiguration(const LookupConfig& config) noexcept {
        std::lock_guard lock(m_mutex);
        m_config = config;
    }
    
    [[nodiscard]] LookupStatistics GetStatistics() const noexcept {
        return m_statistics;
    }
    
    void ResetStatistics() noexcept {
        m_statistics.Reset();
    }
    
    [[nodiscard]] size_t GetMemoryUsage() const noexcept {
        size_t total = sizeof(*this);
        
        // Add thread-local cache memory
        std::lock_guard lock(m_mutex);
        total += m_threadLocalCaches.size() * m_threadLocalCacheSize * 256;  // Approximate
        
        return total;
    }

private:
    ThreadLocalCache* GetOrCreateThreadLocalCache() noexcept {
        const std::thread::id threadId = std::this_thread::get_id();
        
        {
            std::shared_lock readLock(m_cacheMutex);
            auto it = m_threadLocalCaches.find(threadId);
            if (it != m_threadLocalCaches.end()) {
                return it->second;
            }
        }
        
        // Create new thread-local cache
        std::lock_guard writeLock(m_cacheMutex);
        
        // Double-check after acquiring write lock
        auto it = m_threadLocalCaches.find(threadId);
        if (it != m_threadLocalCaches.end()) {
            return it->second;
        }
        
        auto* cache = new ThreadLocalCache(m_threadLocalCacheSize);
        m_threadLocalCaches[threadId] = cache;
        
        return cache;
    }
    
    void UpdateStatistics(const ThreatLookupResult& result) noexcept {
        m_statistics.totalLookups.fetch_add(1, std::memory_order_relaxed);
        
        if (result.found) {
            m_statistics.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            
            switch (result.source) {
                case ThreatLookupResult::Source::ThreadLocalCache:
                    m_statistics.threadLocalCacheHits.fetch_add(1, std::memory_order_relaxed);
                    break;
                case ThreatLookupResult::Source::SharedCache:
                    m_statistics.sharedCacheHits.fetch_add(1, std::memory_order_relaxed);
                    break;
                case ThreatLookupResult::Source::Index:
                    m_statistics.indexHits.fetch_add(1, std::memory_order_relaxed);
                    break;
                case ThreatLookupResult::Source::Database:
                    m_statistics.databaseHits.fetch_add(1, std::memory_order_relaxed);
                    break;
                case ThreatLookupResult::Source::ExternalAPI:
                    m_statistics.externalAPIHits.fetch_add(1, std::memory_order_relaxed);
                    break;
                default:
                    break;
            }
            
            if (result.IsMalicious()) {
                m_statistics.maliciousDetections.fetch_add(1, std::memory_order_relaxed);
            } else if (result.IsSuspicious()) {
                m_statistics.suspiciousDetections.fetch_add(1, std::memory_order_relaxed);
            } else if (result.IsSafe()) {
                m_statistics.safeResults.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            m_statistics.failedLookups.fetch_add(1, std::memory_order_relaxed);
        }
        
        // Update timing statistics
        m_statistics.totalLatencyNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
        
        uint64_t currentMin = m_statistics.minLatencyNs.load(std::memory_order_relaxed);
        while (result.latencyNs < currentMin) {
            if (m_statistics.minLatencyNs.compare_exchange_weak(currentMin, result.latencyNs,
                                                                std::memory_order_relaxed)) {
                break;
            }
        }
        
        uint64_t currentMax = m_statistics.maxLatencyNs.load(std::memory_order_relaxed);
        while (result.latencyNs > currentMax) {
            if (m_statistics.maxLatencyNs.compare_exchange_weak(currentMax, result.latencyNs,
                                                                std::memory_order_relaxed)) {
                break;
            }
        }
        
        // Update per-type counters
        const size_t typeIndex = static_cast<size_t>(result.type);
        if (typeIndex < m_statistics.lookupsByType.size()) {
            m_statistics.lookupsByType[typeIndex].fetch_add(1, std::memory_order_relaxed);
        }
    }
    
    // Configuration
    LookupConfig m_config;
    
    // Subsystem pointers
    ThreatIntelStore* m_store{nullptr};
    ThreatIntelIndex* m_index{nullptr};
    ThreatIntelIOCManager* m_iocManager{nullptr};
    ReputationCache* m_cache{nullptr};
    
    // Internal components
    std::unique_ptr<LookupEngine> m_engine;
    std::unique_ptr<QueryOptimizer> m_optimizer;
    
    // Thread-local caches
    mutable std::shared_mutex m_cacheMutex;
    std::unordered_map<std::thread::id, ThreadLocalCache*> m_threadLocalCaches;
    size_t m_threadLocalCacheSize{1024};
    
    // Statistics
    LookupStatistics m_statistics;
    
    // Synchronization
    mutable std::mutex m_mutex;
    bool m_initialized{false};
};

// ============================================================================
// THREATINTELLOOKUP PUBLIC API IMPLEMENTATION
// ============================================================================

ThreatIntelLookup::ThreatIntelLookup()
    : m_impl(std::make_unique<Impl>())
{}

ThreatIntelLookup::~ThreatIntelLookup() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool ThreatIntelLookup::Initialize(
    const LookupConfig& config,
    ThreatIntelStore* store,
    ThreatIntelIndex* index,
    ThreatIntelIOCManager* iocManager,
    ReputationCache* cache
) noexcept {
    return m_impl->Initialize(config, store, index, iocManager, cache);
}

bool ThreatIntelLookup::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void ThreatIntelLookup::Shutdown() noexcept {
    m_impl->Shutdown();
}

// ============================================================================
// IPv4 LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupIPv4(
    std::string_view ipv4,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::IPv4, ipv4, options);
}

ThreatLookupResult ThreatIntelLookup::LookupIPv4(
    const IPv4Address& addr,
    const LookupOptions& options
) noexcept {
    // Convert to string
    char buffer[16];
    const uint8_t a = (addr.address >> 24) & 0xFF;
    const uint8_t b = (addr.address >> 16) & 0xFF;
    const uint8_t c = (addr.address >> 8) & 0xFF;
    const uint8_t d = addr.address & 0xFF;
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", a, b, c, d);
    
    return LookupIPv4(buffer, options);
}

ThreatLookupResult ThreatIntelLookup::LookupIPv4(
    uint32_t ipv4,
    const LookupOptions& options
) noexcept {
    // Convert from network byte order
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&ipv4);
    
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
                  bytes[0], bytes[1], bytes[2], bytes[3]);
    
    return LookupIPv4(buffer, options);
}

// ============================================================================
// IPv6 LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupIPv6(
    std::string_view ipv6,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::IPv6, ipv6, options);
}

ThreatLookupResult ThreatIntelLookup::LookupIPv6(
    const IPv6Address& addr,
    const LookupOptions& options
) noexcept {
    // Convert to string (simplified, TODO: proper IPv6 formatting)
    std::ostringstream oss;
    for (size_t i = 0; i < 8; ++i) {
        if (i > 0) oss << ":";
        const uint16_t hextet = (static_cast<uint16_t>(addr.address[i * 2]) << 8) | addr.address[i * 2 + 1];
        oss << std::hex << hextet;
    }
    
    return LookupIPv6(oss.str(), options);
}

// ============================================================================
// DOMAIN LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupDomain(
    std::string_view domain,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::Domain, domain, options);
}

// ============================================================================
// URL LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupURL(
    std::string_view url,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::URL, url, options);
}

// ============================================================================
// HASH LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupHash(
    std::string_view hash,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::FileHash, hash, options);
}

ThreatLookupResult ThreatIntelLookup::LookupMD5(
    std::string_view md5,
    const LookupOptions& options
) noexcept {
    return LookupHash(md5, options);
}

ThreatLookupResult ThreatIntelLookup::LookupSHA1(
    std::string_view sha1,
    const LookupOptions& options
) noexcept {
    return LookupHash(sha1, options);
}

ThreatLookupResult ThreatIntelLookup::LookupSHA256(
    std::string_view sha256,
    const LookupOptions& options
) noexcept {
    return LookupHash(sha256, options);
}

ThreatLookupResult ThreatIntelLookup::LookupHash(
    const HashValue& hashValue,
    const LookupOptions& options
) noexcept {
    // Convert hash to hex string
    std::ostringstream oss;
    for (size_t i = 0; i < hashValue.length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(hashValue.data[i]);
    }
    
    return LookupHash(oss.str(), options);
}

// ============================================================================
// EMAIL LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::LookupEmail(
    std::string_view email,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(IOCType::Email, email, options);
}

// ============================================================================
// GENERIC LOOKUPS
// ============================================================================

ThreatLookupResult ThreatIntelLookup::Lookup(
    IOCType type,
    std::string_view value,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteLookup(type, value, options);
}

// ============================================================================
// BATCH LOOKUPS
// ============================================================================

BatchLookupResult ThreatIntelLookup::BatchLookupIPv4(
    std::span<const std::string_view> addresses,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteBatchLookup(IOCType::IPv4, addresses, options);
}

BatchLookupResult ThreatIntelLookup::BatchLookupDomains(
    std::span<const std::string_view> domains,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteBatchLookup(IOCType::Domain, domains, options);
}

BatchLookupResult ThreatIntelLookup::BatchLookupHashes(
    std::span<const std::string_view> hashes,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteBatchLookup(IOCType::FileHash, hashes, options);
}

BatchLookupResult ThreatIntelLookup::BatchLookupURLs(
    std::span<const std::string_view> urls,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteBatchLookup(IOCType::URL, urls, options);
}

BatchLookupResult ThreatIntelLookup::BatchLookup(
    IOCType type,
    std::span<const std::string_view> values,
    const LookupOptions& options
) noexcept {
    return m_impl->ExecuteBatchLookup(type, values, options);
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

size_t ThreatIntelLookup::WarmCache(size_t count) noexcept {
    // TODO: Implement cache warming
    return 0;
}

void ThreatIntelLookup::InvalidateCacheEntry(IOCType type, std::string_view value) noexcept {
    // TODO: Implement cache invalidation
}

void ThreatIntelLookup::ClearAllCaches() noexcept {
    // TODO: Implement cache clearing
}

CacheStatistics ThreatIntelLookup::GetCacheStatistics() const noexcept {
    // TODO: Implement cache statistics
    return CacheStatistics{};
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

LookupStatistics ThreatIntelLookup::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void ThreatIntelLookup::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

const LookupConfig& ThreatIntelLookup::GetConfiguration() const noexcept {
    return m_impl->GetConfiguration();
}

void ThreatIntelLookup::UpdateConfiguration(const LookupConfig& config) noexcept {
    m_impl->UpdateConfiguration(config);
}

size_t ThreatIntelLookup::GetMemoryUsage() const noexcept {
    return m_impl->GetMemoryUsage();
}

double ThreatIntelLookup::GetThroughput() const noexcept {
    const auto stats = m_impl->GetStatistics();
    const uint64_t totalLookups = stats.totalLookups.load(std::memory_order_relaxed);
    const uint64_t lastReset = stats.lastResetTime.load(std::memory_order_relaxed);
    
    if (totalLookups == 0 || lastReset == 0) {
        return 0.0;
    }
    
    const auto now = std::chrono::system_clock::now().time_since_epoch().count();
    const double secondsElapsed = static_cast<double>(now - lastReset) / 1'000'000'000.0;
    
    return secondsElapsed > 0.0 ? totalLookups / secondsElapsed : 0.0;
}

} // namespace ThreatIntel
} // namespace ShadowStrike
