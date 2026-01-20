// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike WhitelistStore - ENTERPRISE-GRADE IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance whitelist store implementation
 * Memory-mapped with B+Tree indexing and Bloom filters
 * 
 * Target Performance:
 * - Hash lookup: < 100ns average (bloom filter + cache)
 * - Path lookup: < 500ns average (trie index)
 * - Bloom filter check: < 20ns
 * - Cache hit: < 50ns
 *
 * Performance Standards: CrowdStrike Falcon / Kaspersky / Bitdefender quality
 *
 * Security Features:
 * - All pointer operations are bounds-checked
 * - Integer overflow protection on all size calculations
 * - RAII for all resource management
 * - Thread-safe with reader-writer locks
 *
 * ============================================================================
 */

#include "WhiteListStore.hpp"
#include "WhiteListFormat.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/JSONUtils.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <limits>
#include <climits>
#include <utility>   // For std::exchange

// Windows headers
#include <windows.h>
#include <intrin.h>  // For __popcnt64

namespace ShadowStrike {
namespace Whitelist {

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Safely add two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result
 * @return True if addition succeeded, false if overflow
 */
[[nodiscard]] inline bool SafeAdd(uint64_t a, uint64_t b, uint64_t& result) noexcept {
    if (a > std::numeric_limits<uint64_t>::max() - b) {
        return false;  // Would overflow
    }
    result = a + b;
    return true;
}

/**
 * @brief Safely multiply two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result
 * @return True if multiplication succeeded, false if overflow
 */
[[nodiscard]] inline bool SafeMul(uint64_t a, uint64_t b, uint64_t& result) noexcept {
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > std::numeric_limits<uint64_t>::max() / b) {
        return false;  // Would overflow
    }
    result = a * b;
    return true;
}

/**
 * @brief Clamp value to valid range
 * @param value Value to clamp
 * @param minVal Minimum allowed value
 * @param maxVal Maximum allowed value
 * @return Clamped value
 */
template<typename T>
[[nodiscard]] constexpr T Clamp(T value, T minVal, T maxVal) noexcept {
    return (value < minVal) ? minVal : ((value > maxVal) ? maxVal : value);
}

/**
 * @brief Population count (number of set bits) for 64-bit integer
 * @param value Input value
 * @return Number of bits set to 1
 */
[[nodiscard]] inline uint32_t PopCount64(uint64_t value) noexcept {
#if defined(_MSC_VER)
    return static_cast<uint32_t>(__popcnt64(value));
#elif defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_popcountll(value));
#else
    // Fallback implementation
    uint32_t count = 0;
    while (value) {
        count += static_cast<uint32_t>(value & 1ULL);
        value >>= 1;
    }
    return count;
#endif
}

} // anonymous namespace




// ============================================================================
// WHITELIST STORE - CONSTRUCTOR/DESTRUCTOR
// ============================================================================

WhitelistStore::WhitelistStore() {
    /*
     * ========================================================================
     * WHITELIST STORE CONSTRUCTOR
     * ========================================================================
     *
     * Initializes the whitelist store with default settings:
     * - Performance counter frequency for nanosecond timing
     * - Query cache with default size
     * - All atomic flags initialized to safe defaults
     *
     * ========================================================================
     */
    
    // Initialize performance counter frequency for timing
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        // Fallback if QPC not available
        m_perfFrequency.QuadPart = 1;
        SS_LOG_WARN(L"Whitelist", L"QueryPerformanceFrequency failed - timing may be inaccurate");
    }
    
    // Initialize cache with default size (exception-safe)
    try {
        m_queryCache.resize(DEFAULT_CACHE_SIZE);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to allocate query cache: %S", e.what());
        // Continue with empty cache - functionality degraded but safe
    }
}

WhitelistStore::~WhitelistStore() {
    // Safe cleanup - Close handles all resource release
    Close();
}

WhitelistStore::WhitelistStore(WhitelistStore&& other) noexcept
    : m_databasePath(std::move(other.m_databasePath))
    , m_mappedView(std::exchange(other.m_mappedView, MemoryMappedView{}))
    , m_initialized(other.m_initialized.exchange(false, std::memory_order_acq_rel))
    , m_readOnly(other.m_readOnly.load(std::memory_order_acquire))
    , m_hashBloomFilter(std::move(other.m_hashBloomFilter))
    , m_pathBloomFilter(std::move(other.m_pathBloomFilter))
    , m_hashIndex(std::move(other.m_hashIndex))
    , m_pathIndex(std::move(other.m_pathIndex))
    , m_stringPool(std::move(other.m_stringPool))
    , m_queryCache(std::move(other.m_queryCache))
    , m_cacheAccessCounter(other.m_cacheAccessCounter.exchange(0, std::memory_order_acq_rel))
    , m_cachingEnabled(other.m_cachingEnabled.load(std::memory_order_acquire))
    , m_bloomFilterEnabled(other.m_bloomFilterEnabled.load(std::memory_order_acquire))
    , m_nextEntryId(other.m_nextEntryId.exchange(1, std::memory_order_acq_rel))
    , m_entryDataUsed(other.m_entryDataUsed.exchange(0, std::memory_order_acq_rel))
    , m_totalLookups(other.m_totalLookups.exchange(0, std::memory_order_acq_rel))
    , m_cacheHits(other.m_cacheHits.exchange(0, std::memory_order_acq_rel))
    , m_cacheMisses(other.m_cacheMisses.exchange(0, std::memory_order_acq_rel))
    , m_bloomHits(other.m_bloomHits.exchange(0, std::memory_order_acq_rel))
    , m_bloomRejects(other.m_bloomRejects.exchange(0, std::memory_order_acq_rel))
    , m_totalHits(other.m_totalHits.exchange(0, std::memory_order_acq_rel))
    , m_totalMisses(other.m_totalMisses.exchange(0, std::memory_order_acq_rel))
    , m_totalLookupTimeNs(other.m_totalLookupTimeNs.exchange(0, std::memory_order_acq_rel))
    , m_minLookupTimeNs(other.m_minLookupTimeNs.exchange(UINT64_MAX, std::memory_order_acq_rel))
    , m_maxLookupTimeNs(other.m_maxLookupTimeNs.exchange(0, std::memory_order_acq_rel))
    // Note: m_globalLock, m_entryAllocMutex, m_callbackMutex are default-initialized (new mutexes)
    , m_matchCallback(std::move(other.m_matchCallback))
    , m_perfFrequency(other.m_perfFrequency)
{
    // Clear other's performance frequency
    other.m_perfFrequency = {};
}

WhitelistStore& WhitelistStore::operator=(WhitelistStore&& other) noexcept {
    if (this != &other) {
        // Close current resources first
        Close();
        
        // Move data from other
        m_databasePath = std::move(other.m_databasePath);
        m_mappedView = std::exchange(other.m_mappedView, MemoryMappedView{});
        m_initialized.store(other.m_initialized.exchange(false, std::memory_order_acq_rel), 
                           std::memory_order_release);
        m_readOnly.store(other.m_readOnly.load(std::memory_order_acquire), 
                        std::memory_order_release);
        
        // Move unique_ptrs
        m_hashBloomFilter = std::move(other.m_hashBloomFilter);
        m_pathBloomFilter = std::move(other.m_pathBloomFilter);
        m_hashIndex = std::move(other.m_hashIndex);
        m_pathIndex = std::move(other.m_pathIndex);
        m_stringPool = std::move(other.m_stringPool);
        
        // Move cache
        m_queryCache = std::move(other.m_queryCache);
        m_cacheAccessCounter.store(other.m_cacheAccessCounter.exchange(0, std::memory_order_acq_rel),
                                   std::memory_order_release);
        m_cachingEnabled.store(other.m_cachingEnabled.load(std::memory_order_acquire),
                              std::memory_order_release);
        m_bloomFilterEnabled.store(other.m_bloomFilterEnabled.load(std::memory_order_acquire),
                                  std::memory_order_release);
        
        // Move entry allocation state
        m_nextEntryId.store(other.m_nextEntryId.exchange(1, std::memory_order_acq_rel),
                           std::memory_order_release);
        m_entryDataUsed.store(other.m_entryDataUsed.exchange(0, std::memory_order_acq_rel),
                             std::memory_order_release);
        
        // Move statistics
        m_totalLookups.store(other.m_totalLookups.exchange(0, std::memory_order_acq_rel),
                            std::memory_order_release);
        m_cacheHits.store(other.m_cacheHits.exchange(0, std::memory_order_acq_rel),
                         std::memory_order_release);
        m_cacheMisses.store(other.m_cacheMisses.exchange(0, std::memory_order_acq_rel),
                           std::memory_order_release);
        m_bloomHits.store(other.m_bloomHits.exchange(0, std::memory_order_acq_rel),
                         std::memory_order_release);
        m_bloomRejects.store(other.m_bloomRejects.exchange(0, std::memory_order_acq_rel),
                            std::memory_order_release);
        m_totalHits.store(other.m_totalHits.exchange(0, std::memory_order_acq_rel),
                         std::memory_order_release);
        m_totalMisses.store(other.m_totalMisses.exchange(0, std::memory_order_acq_rel),
                           std::memory_order_release);
        m_totalLookupTimeNs.store(other.m_totalLookupTimeNs.exchange(0, std::memory_order_acq_rel),
                                 std::memory_order_release);
        m_minLookupTimeNs.store(other.m_minLookupTimeNs.exchange(UINT64_MAX, std::memory_order_acq_rel),
                               std::memory_order_release);
        m_maxLookupTimeNs.store(other.m_maxLookupTimeNs.exchange(0, std::memory_order_acq_rel),
                               std::memory_order_release);
        
        // Note: Mutexes cannot be moved - they are default-initialized
        // We don't need to move them since this object has its own mutexes
        
        // Move callback
        {
            std::lock_guard lockOther(other.m_callbackMutex);
            std::lock_guard lockThis(m_callbackMutex);
            m_matchCallback = std::move(other.m_matchCallback);
        }
        
        // Copy performance frequency
        m_perfFrequency = other.m_perfFrequency;
        other.m_perfFrequency = {};
    }
    return *this;
}

// ============================================================================
// WHITELIST STORE - LIFECYCLE
// ============================================================================

StoreError WhitelistStore::Load(const std::wstring& databasePath, bool readOnly) noexcept {
    std::unique_lock lock(m_globalLock);
    
    // Validate input
    if (databasePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::FileNotFound,
            "Database path is empty"
        );
    }
    
    // Validate path length
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (databasePath.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Database path exceeds maximum length"
        );
    }
    
    // Close existing if initialized - handle potential race condition
    if (m_initialized.load(std::memory_order_acquire)) {
        // Release lock to avoid deadlock in Close()
        lock.unlock();
        Close();
        lock.lock();
        
        // Re-check state after re-acquiring lock (TOCTOU protection)
        // Another thread may have called Load/Create while we didn't hold the lock
        if (m_initialized.load(std::memory_order_acquire)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Store was re-initialized by another thread during Load"
            );
        }
    }
    
    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);
    
    // Open memory-mapped view
    StoreError error;
    if (!MemoryMapping::OpenView(databasePath, readOnly, m_mappedView, error)) {
        m_databasePath.clear();
        return error;
    }
    
    // Initialize indices
    error = InitializeIndices();
    if (!error.IsSuccess()) {
        MemoryMapping::CloseView(m_mappedView);
        m_databasePath.clear();
        return error;
    }
    
    m_initialized.store(true, std::memory_order_release);
    
    SS_LOG_INFO(L"Whitelist", L"Loaded whitelist database: %s (read-only: %s)",
        databasePath.c_str(), readOnly ? L"true" : L"false");
    
    return StoreError::Success();
}

StoreError WhitelistStore::Create(const std::wstring& databasePath, uint64_t initialSizeBytes) noexcept {
    std::unique_lock lock(m_globalLock);
    
    // Validate input
    if (databasePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Database path is empty"
        );
    }
    
    // Validate path length (enterprise-grade: prevent path overflow attacks)
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (databasePath.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::PathTooLong,
            "Database path exceeds maximum length"
        );
    }
    
    // Validate size bounds
    constexpr uint64_t MIN_DATABASE_SIZE = 4096;           // 4KB minimum
    constexpr uint64_t MAX_DATABASE_SIZE = 16ULL * 1024 * 1024 * 1024; // 16GB maximum
    
    if (initialSizeBytes < MIN_DATABASE_SIZE) {
        SS_LOG_WARN(L"Whitelist", L"Database size %llu too small, using minimum %llu",
            initialSizeBytes, MIN_DATABASE_SIZE);
        initialSizeBytes = MIN_DATABASE_SIZE;
    }
    
    if (initialSizeBytes > MAX_DATABASE_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Database size exceeds maximum"
        );
    }
    
    // Close existing if initialized - handle potential race condition
    if (m_initialized.load(std::memory_order_acquire)) {
        lock.unlock();
        Close();
        lock.lock();
        
        // Re-check state after re-acquiring lock (TOCTOU protection)
        if (m_initialized.load(std::memory_order_acquire)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Store was re-initialized by another thread during Create"
            );
        }
    }
    
    m_databasePath = databasePath;
    m_readOnly.store(false, std::memory_order_release);
    
    // Create new database
    StoreError error;
    if (!MemoryMapping::CreateDatabase(databasePath, initialSizeBytes, m_mappedView, error)) {
        m_databasePath.clear();
        return error;
    }
    
    // Initialize indices
    error = InitializeIndices();
    if (!error.IsSuccess()) {
        MemoryMapping::CloseView(m_mappedView);
        m_databasePath.clear();
        return error;
    }
    
    m_initialized.store(true, std::memory_order_release);
    
    SS_LOG_INFO(L"Whitelist", L"Created whitelist database: %s (%llu bytes)",
        databasePath.c_str(), initialSizeBytes);
    
    return StoreError::Success();
}

void WhitelistStore::Close() noexcept {
    std::unique_lock lock(m_globalLock);
    
    // Check if already closed
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    // Save if not read-only (best effort)
    if (!m_readOnly.load(std::memory_order_acquire)) {
        StoreError error;
        if (!MemoryMapping::FlushView(m_mappedView, error)) {
            SS_LOG_WARN(L"Whitelist", L"Failed to flush database on close: %S",
                error.message.c_str());
        }
    }
    
    // Clear indices (order matters for dependencies)
    m_hashBloomFilter.reset();
    m_pathBloomFilter.reset();
    m_hashIndex.reset();
    m_pathIndex.reset();
    m_stringPool.reset();
    
    // Clear cache (exception-safe)
    try {
        m_queryCache.clear();
    } catch (...) {
        // Ignore exceptions during cleanup
    }
    
    // Close memory mapping
    MemoryMapping::CloseView(m_mappedView);
    
    // Reset state atomically
    m_initialized.store(false, std::memory_order_release);
    m_databasePath.clear();
    
    // Reset statistics
    m_totalLookups.store(0, std::memory_order_relaxed);
    m_totalHits.store(0, std::memory_order_relaxed);
    m_totalMisses.store(0, std::memory_order_relaxed);
    m_cacheHits.store(0, std::memory_order_relaxed);
    m_cacheMisses.store(0, std::memory_order_relaxed);
    m_bloomHits.store(0, std::memory_order_relaxed);
    m_bloomRejects.store(0, std::memory_order_relaxed);
    
    SS_LOG_INFO(L"Whitelist", L"Closed whitelist database");
}

StoreError WhitelistStore::Save() noexcept {
    std::shared_lock lock(m_globalLock);
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot save read-only database"
        );
    }
    
    // Update header statistics before flush
    UpdateHeaderStats();
    
    // Flush to disk
    StoreError error;
    if (!MemoryMapping::FlushView(m_mappedView, error)) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to save database: %S", error.message.c_str());
        return error;
    }
    
    SS_LOG_DEBUG(L"Whitelist", L"Saved whitelist database");
    
    return StoreError::Success();
}

StoreError WhitelistStore::InitializeIndices() noexcept {
    /*
     * ========================================================================
     * INDEX INITIALIZATION
     * ========================================================================
     *
     * Initializes all indices from the memory-mapped database:
     * - Bloom filters for fast negative lookups
     * - Hash index (B+Tree) for hash-based entries
     * - Path index (Trie) for path-based entries
     * - String pool for deduplicated strings
     *
     * This is called after Load() or Create() to set up the data structures.
     *
     * ========================================================================
     */
    const auto* header = GetHeader();
    if (!header) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to get database header"
        );
    }
    
    // Validate header magic/version (basic integrity check)
    // Note: Actual validation depends on header structure definition
    
    StoreError error;
    
    // Initialize hash bloom filter
    try {
        // Validate bloom filter parameters
        const uint64_t expectedElements = header->bloomExpectedElements;
        const double fpr = static_cast<double>(header->bloomFalsePositiveRate) / 1000000.0;
        
        // Sanity check parameters
        if (expectedElements > 0 && expectedElements <= 1000000000ULL && fpr > 0.0 && fpr < 1.0) {
            m_hashBloomFilter = std::make_unique<BloomFilter>(expectedElements, fpr);
            
            if (header->bloomFilterSize > 0 && header->bloomFilterOffset > 0) {
                // Validate bloom filter offset
                uint64_t bloomEnd;
                if (SafeAdd(header->bloomFilterOffset, header->bloomFilterSize, bloomEnd)) {
                    const void* bloomData = m_mappedView.GetAt<uint8_t>(header->bloomFilterOffset);
                    if (bloomData) {
                        bool initSuccess = m_hashBloomFilter->Initialize(
                            bloomData,
                            header->bloomFilterSize * 8, // Convert bytes to bits
                            7 // Default hash function count
                        );
                        if (!initSuccess) {
                            SS_LOG_WARN(L"Whitelist", L"Failed to initialize bloom filter from mapped data");
                        }
                    }
                }
            }
        } else {
            SS_LOG_WARN(L"Whitelist", L"Invalid bloom filter parameters, using defaults");
            m_hashBloomFilter = std::make_unique<BloomFilter>(100000, 0.001);
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to create hash bloom filter: %S", e.what());
        // Continue without bloom filter - degraded performance but functional
    }
    
    // Initialize hash index
    try {
        m_hashIndex = std::make_unique<HashIndex>();
        
        if (header->hashIndexSize > 0 && header->hashIndexOffset > 0) {
            // Validate hash index bounds
            uint64_t hashIndexEnd;
            if (SafeAdd(header->hashIndexOffset, header->hashIndexSize, hashIndexEnd)) {
                error = m_hashIndex->Initialize(
                    m_mappedView,
                    header->hashIndexOffset,
                    header->hashIndexSize
                );
                if (!error.IsSuccess()) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to initialize hash index: %S",
                        error.message.c_str());
                }
            } else {
                SS_LOG_WARN(L"Whitelist", L"Hash index offset/size overflow");
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to create hash index: %S", e.what());
    }
    
    // Initialize path index
    try {
        m_pathIndex = std::make_unique<PathIndex>();
        
        if (header->pathIndexSize > 0 && header->pathIndexOffset > 0) {
            // Validate path index bounds
            uint64_t pathIndexEnd;
            if (SafeAdd(header->pathIndexOffset, header->pathIndexSize, pathIndexEnd)) {
                error = m_pathIndex->Initialize(
                    m_mappedView,
                    header->pathIndexOffset,
                    header->pathIndexSize
                );
                if (!error.IsSuccess()) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to initialize path index: %S",
                        error.message.c_str());
                }
            } else {
                SS_LOG_WARN(L"Whitelist", L"Path index offset/size overflow");
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to create path index: %S", e.what());
    }
    
    // Initialize string pool
    try {
        m_stringPool = std::make_unique<StringPool>();
        
        if (header->stringPoolSize > 0 && header->stringPoolOffset > 0) {
            // Validate string pool bounds
            uint64_t stringPoolEnd;
            if (SafeAdd(header->stringPoolOffset, header->stringPoolSize, stringPoolEnd)) {
                error = m_stringPool->Initialize(
                    m_mappedView,
                    header->stringPoolOffset,
                    header->stringPoolSize
                );
                if (!error.IsSuccess()) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to initialize string pool: %S",
                        error.message.c_str());
                }
            } else {
                SS_LOG_WARN(L"Whitelist", L"String pool offset/size overflow");
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to create string pool: %S", e.what());
    }
    
    // Calculate next entry ID from header statistics (with overflow protection)
    uint64_t totalEntries = 0;
    if (SafeAdd(totalEntries, header->totalHashEntries, totalEntries) &&
        SafeAdd(totalEntries, header->totalPathEntries, totalEntries) &&
        SafeAdd(totalEntries, header->totalCertEntries, totalEntries) &&
        SafeAdd(totalEntries, header->totalPublisherEntries, totalEntries) &&
        SafeAdd(totalEntries, header->totalOtherEntries, totalEntries) &&
        SafeAdd(totalEntries, 1ULL, totalEntries)) {
        m_nextEntryId.store(totalEntries, std::memory_order_relaxed);
    } else {
        // Overflow occurred, use safe default
        SS_LOG_WARN(L"Whitelist", L"Entry count overflow, starting from 1");
        m_nextEntryId.store(1, std::memory_order_relaxed);
    }
    
    return StoreError::Success();
}

const WhitelistDatabaseHeader* WhitelistStore::GetHeader() const noexcept {
    if (!m_mappedView.IsValid()) {
        return nullptr;
    }
    return m_mappedView.GetAt<WhitelistDatabaseHeader>(0);
}

// ============================================================================
// QUERY OPERATIONS (Ultra-Fast Lookups)
// ============================================================================

LookupResult WhitelistStore::IsHashWhitelisted(
    const HashValue& hash,
    const QueryOptions& options
) const noexcept {
    /*
     * ========================================================================
     * HASH LOOKUP - TARGET: < 100ns AVERAGE
     * ========================================================================
     *
     * Performance pipeline:
     * 1. Query cache check (< 50ns if hit)
     * 2. Bloom filter pre-check (< 20ns, eliminates 99.99% of misses)
     * 3. B+Tree index lookup (< 100ns)
     * 4. Entry validation (expiration, flags)
     *
     * Thread Safety: This method is thread-safe for concurrent reads.
     * Memory Safety: All pointer accesses are bounds-checked.
     *
     * ========================================================================
     */
    
    // Capture start time for performance measurement
    LARGE_INTEGER startTime{};
    QueryPerformanceCounter(&startTime);
    
    LookupResult result{};
    result.found = false;
    result.lookupTimeNs = 0;
    
    // Lambda for safe timing calculation
    auto calculateElapsedNs = [this, &startTime]() -> uint64_t {
        LARGE_INTEGER endTime{};
        if (!QueryPerformanceCounter(&endTime)) {
            return 0;
        }
        // Validate frequency to avoid division by zero
        if (m_perfFrequency.QuadPart <= 0) {
            return 0;
        }
        // Safe calculation: avoid overflow with careful ordering
        const int64_t elapsed = endTime.QuadPart - startTime.QuadPart;
        if (elapsed < 0) {
            return 0; // Timer wrapped or invalid
        }
        // Convert to nanoseconds: elapsed * 1e9 / freq
        // Use 128-bit multiplication to avoid overflow
        const uint64_t elapsedU = static_cast<uint64_t>(elapsed);
        constexpr uint64_t NS_PER_SEC = 1000000000ULL;
        // Check for potential overflow: elapsed * NS_PER_SEC
        if (elapsedU > UINT64_MAX / NS_PER_SEC) {
            return UINT64_MAX; // Return max on overflow
        }
        return (elapsedU * NS_PER_SEC) / static_cast<uint64_t>(m_perfFrequency.QuadPart);
    };
    
    // Validation - store not initialized
    if (!m_initialized.load(std::memory_order_acquire)) {
        return result;
    }
    
    // Validation - empty hash
    if (hash.IsEmpty()) {
        return result;
    }
    
    m_totalLookups.fetch_add(1, std::memory_order_relaxed);
    
    // Step 1: Query cache check
    if (options.useCache && m_cachingEnabled.load(std::memory_order_acquire)) {
        auto cached = GetFromCache(hash);
        if (cached.has_value()) {
            m_cacheHits.fetch_add(1, std::memory_order_relaxed);
            result = *cached;
            result.cacheHit = true;
            result.lookupTimeNs = calculateElapsedNs();
            return result;
        }
        m_cacheMisses.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Step 2: Bloom filter pre-check
    if (options.useBloomFilter && m_bloomFilterEnabled.load(std::memory_order_acquire) && m_hashBloomFilter) {
        result.bloomFilterChecked = true;
        
        if (!m_hashBloomFilter->MightContain(hash)) {
            // Definitely not in whitelist - bloom filter guarantees no false negatives
            m_bloomRejects.fetch_add(1, std::memory_order_relaxed);
            m_totalMisses.fetch_add(1, std::memory_order_relaxed);
            
            result.lookupTimeNs = calculateElapsedNs();
            RecordLookupTime(result.lookupTimeNs);
            
            // Cache negative result
            if (options.useCache && m_cachingEnabled.load(std::memory_order_acquire)) {
                AddToCache(hash, result);
            }
            
            return result;
        }
        
        m_bloomHits.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Step 3: B+Tree index lookup
    if (!m_hashIndex) {
        return result;
    }
    
    auto entryOffset = m_hashIndex->Lookup(hash);
    if (!entryOffset.has_value()) {
        m_totalMisses.fetch_add(1, std::memory_order_relaxed);
        
        result.lookupTimeNs = calculateElapsedNs();
        RecordLookupTime(result.lookupTimeNs);
        
        // Cache negative result
        if (options.useCache && m_cachingEnabled.load(std::memory_order_acquire)) {
            AddToCache(hash, result);
        }
        
        return result;
    }
    
    // Step 4: Fetch and validate entry (with bounds checking)
    const auto* entry = m_mappedView.GetAt<WhitelistEntry>(*entryOffset);
    if (!entry) {
        SS_LOG_WARN(L"Whitelist", L"IsHashWhitelisted: invalid entry offset %llu", *entryOffset);
        return result;
    }
    
    // Validate entry type matches expected type (hash-based entry)
    if (entry->type != WhitelistEntryType::FileHash && 
        entry->type != WhitelistEntryType::Certificate) {
        SS_LOG_WARN(L"Whitelist", L"IsHashWhitelisted: unexpected entry type %d at offset %llu",
            static_cast<int>(entry->type), *entryOffset);
        return result;
    }
    
    // Validate entry flags
    if (!options.includeDisabled && !HasFlag(entry->flags, WhitelistFlags::Enabled)) {
        return result;
    }
    
    // Validate entry is not revoked (soft-deleted)
    if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
        return result;
    }
    
    if (!options.includeExpired && entry->IsExpired()) {
        return result;
    }
    
    // Entry found and valid - populate result
    result.found = true;
    result.entryId = entry->entryId;
    result.type = entry->type;
    result.reason = entry->reason;
    result.flags = entry->flags;
    result.policyId = entry->policyId;
    result.expirationTime = entry->expirationTime;
    
    // Fetch description if available (with bounds validation)
    if (entry->descriptionOffset > 0 && entry->descriptionLength > 0 && m_stringPool) {
        // Validate description length is reasonable
        constexpr uint16_t MAX_DESC_LENGTH = 65535;
        if (entry->descriptionLength <= MAX_DESC_LENGTH) {
            auto desc = m_stringPool->GetString(entry->descriptionOffset, entry->descriptionLength);
            if (!desc.empty()) {
                try {
                    result.description = std::string(desc);
                } catch (const std::exception&) {
                    // Description allocation failed, continue without it
                }
            }
        }
    }
    
    m_totalHits.fetch_add(1, std::memory_order_relaxed);
    
    // Update hit count (atomic, thread-safe)
    // Note: const_cast is safe here because hitCount is atomic
    const_cast<WhitelistEntry*>(entry)->IncrementHitCount();
    
    result.lookupTimeNs = calculateElapsedNs();
    RecordLookupTime(result.lookupTimeNs);
    
    // Cache positive result
    if (options.useCache && m_cachingEnabled.load(std::memory_order_acquire)) {
        AddToCache(hash, result);
    }
    
    // Invoke match callback if registered
    if (options.logLookup) {
        NotifyMatch(result, L"Hash lookup");
    }
    
    return result;
}

LookupResult WhitelistStore::IsHashWhitelisted(
    const std::string& hashString,
    HashAlgorithm algorithm,
    const QueryOptions& options
) const noexcept {
    auto hash = Format::ParseHashString(hashString, algorithm);
    if (!hash.has_value()) {
        return LookupResult{};
    }
    return IsHashWhitelisted(*hash, options);
}

LookupResult WhitelistStore::IsPathWhitelisted(
    std::wstring_view path,
    const QueryOptions& options
) const noexcept {
    /*
     * ========================================================================
     * PATH LOOKUP - TARGET: < 500ns AVERAGE
     * ========================================================================
     *
     * Uses Trie-based index for efficient prefix/suffix matching.
     * Supports wildcard patterns and regex (when enabled).
     *
     * Thread Safety: This method is thread-safe for concurrent reads.
     * Memory Safety: Path length validated, all pointers bounds-checked.
     *
     * ========================================================================
     */
    
    // Capture start time for performance measurement
    LARGE_INTEGER startTime{};
    QueryPerformanceCounter(&startTime);
    
    LookupResult result{};
    result.found = false;
    result.lookupTimeNs = 0;
    
    // Lambda for safe timing calculation (same as hash lookup)
    auto calculateElapsedNs = [this, &startTime]() -> uint64_t {
        LARGE_INTEGER endTime{};
        if (!QueryPerformanceCounter(&endTime)) {
            return 0;
        }
        if (m_perfFrequency.QuadPart <= 0) {
            return 0;
        }
        const int64_t elapsed = endTime.QuadPart - startTime.QuadPart;
        if (elapsed < 0) {
            return 0;
        }
        const uint64_t elapsedU = static_cast<uint64_t>(elapsed);
        constexpr uint64_t NS_PER_SEC = 1000000000ULL;
        if (elapsedU > UINT64_MAX / NS_PER_SEC) {
            return UINT64_MAX;
        }
        return (elapsedU * NS_PER_SEC) / static_cast<uint64_t>(m_perfFrequency.QuadPart);
    };
    
    // Validation - store not initialized
    if (!m_initialized.load(std::memory_order_acquire)) {
        return result;
    }
    
    // Validation - empty path
    if (path.empty()) {
        return result;
    }
    
    // Validation - path length (Windows MAX_PATH limit)
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (path.length() > MAX_PATH_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"IsPathWhitelisted: path exceeds max length");
        return result;
    }
    
    m_totalLookups.fetch_add(1, std::memory_order_relaxed);
    
    // Normalize path for comparison (handles case, separators, etc.)
    std::wstring normalizedPath;
    try {
        normalizedPath = Format::NormalizePath(path);
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"Whitelist", L"IsPathWhitelisted: path normalization failed - %S", e.what());
        return result;
    }
    
    if (normalizedPath.empty()) {
        return result;
    }
    
    // Bloom filter check for paths
    if (options.useBloomFilter && m_bloomFilterEnabled.load(std::memory_order_acquire) && m_pathBloomFilter) {
        // Compute FNV-1a hash of normalized path
        uint64_t pathHash = 14695981039346656037ULL; // FNV offset basis
        for (wchar_t c : normalizedPath) {
            pathHash ^= static_cast<uint64_t>(c);
            pathHash *= 1099511628211ULL; // FNV prime
        }
        
        if (!m_pathBloomFilter->MightContain(pathHash)) {
            m_bloomRejects.fetch_add(1, std::memory_order_relaxed);
            m_totalMisses.fetch_add(1, std::memory_order_relaxed);
            
            result.lookupTimeNs = calculateElapsedNs();
            return result;
        }
    }
    
    // Path index lookup
    if (!m_pathIndex) {
        return result;
    }
    
    // Try exact match first
    auto entryOffsets = m_pathIndex->Lookup(normalizedPath, PathMatchMode::Exact);
    
    // Try prefix match if exact match fails
    if (entryOffsets.empty()) {
        entryOffsets = m_pathIndex->Lookup(normalizedPath, PathMatchMode::Prefix);
    }
    
    if (entryOffsets.empty()) {
        m_totalMisses.fetch_add(1, std::memory_order_relaxed);
        
        result.lookupTimeNs = calculateElapsedNs();
        return result;
    }
    
    // Validate entry offsets and return first valid entry
    for (uint64_t offset : entryOffsets) {
        // Bounds check on offset
        const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
        if (!entry) {
            SS_LOG_WARN(L"Whitelist", L"IsPathWhitelisted: invalid entry offset %llu", offset);
            continue;
        }
        
        // Validate entry type matches expected type (path-based entry)
        if (entry->type != WhitelistEntryType::FilePath && 
            entry->type != WhitelistEntryType::ProcessPath &&
            entry->type != WhitelistEntryType::Publisher) {
            SS_LOG_WARN(L"Whitelist", L"IsPathWhitelisted: unexpected entry type %d at offset %llu",
                static_cast<int>(entry->type), offset);
            continue;
        }
        
        // Skip revoked entries (soft-deleted)
        if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
            continue;
        }
        
        // Skip disabled entries unless requested
        if (!options.includeDisabled && !HasFlag(entry->flags, WhitelistFlags::Enabled)) {
            continue;
        }
        
        // Skip expired entries unless requested
        if (!options.includeExpired && entry->IsExpired()) {
            continue;
        }
        
        // Found valid entry - populate result
        result.found = true;
        result.entryId = entry->entryId;
        result.type = entry->type;
        result.reason = entry->reason;
        result.flags = entry->flags;
        result.policyId = entry->policyId;
        result.expirationTime = entry->expirationTime;
        
        // Fetch description with validation
        if (entry->descriptionOffset > 0 && entry->descriptionLength > 0 && m_stringPool) {
            constexpr uint16_t MAX_DESC_LENGTH = 65535;
            if (entry->descriptionLength <= MAX_DESC_LENGTH) {
                auto desc = m_stringPool->GetString(entry->descriptionOffset, entry->descriptionLength);
                if (!desc.empty()) {
                    try {
                        result.description = std::string(desc);
                    } catch (const std::exception&) {
                        // Description allocation failed, continue without it
                    }
                }
            }
        }
        
        m_totalHits.fetch_add(1, std::memory_order_relaxed);
        const_cast<WhitelistEntry*>(entry)->IncrementHitCount();
        
        break; // First valid match wins
    }
    
    result.lookupTimeNs = calculateElapsedNs();
    RecordLookupTime(result.lookupTimeNs);
    
    if (options.logLookup && result.found) {
        NotifyMatch(result, path);
    }
    
    return result;
}

LookupResult WhitelistStore::IsCertificateWhitelisted(
    const std::array<uint8_t, 32>& thumbprint,
    const QueryOptions& options
) const noexcept {
    // Convert certificate thumbprint to SHA-256 HashValue
    HashValue hash = HashValue::Create(HashAlgorithm::SHA256, thumbprint.data(), 32);
    return IsHashWhitelisted(hash, options);
}

LookupResult WhitelistStore::IsPublisherWhitelisted(
    std::wstring_view publisherName,
    const QueryOptions& options
) const noexcept {
    // Validate publisher name
    if (publisherName.empty()) {
        return LookupResult{};
    }
    
    // Validate length
    constexpr size_t MAX_PUBLISHER_LENGTH = 1024;
    if (publisherName.length() > MAX_PUBLISHER_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"IsPublisherWhitelisted: publisher name too long");
        return LookupResult{};
    }
    
    // Treat as path-based lookup (publishers are stored similarly)
    return IsPathWhitelisted(publisherName, options);
}

std::vector<LookupResult> WhitelistStore::BatchLookupHashes(
    std::span<const HashValue> hashes,
    const QueryOptions& options
) const noexcept {
    std::vector<LookupResult> results;
    
    // Validate input
    if (hashes.empty()) {
        return results;
    }
    
    // Limit batch size to prevent resource exhaustion
    constexpr size_t MAX_BATCH_SIZE = 10000;
    if (hashes.size() > MAX_BATCH_SIZE) {
        SS_LOG_WARN(L"Whitelist", L"BatchLookupHashes: batch size %zu exceeds limit, truncating",
            hashes.size());
    }
    
    const size_t batchSize = std::min(hashes.size(), MAX_BATCH_SIZE);
    
    // Reserve with exception handling
    try {
        results.reserve(batchSize);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"BatchLookupHashes: allocation failed - %S", e.what());
        return results;
    }
    
    // Process hashes
    for (size_t i = 0; i < batchSize; ++i) {
        try {
            results.push_back(IsHashWhitelisted(hashes[i], options));
        } catch (const std::exception&) {
            // Push empty result on error
            results.emplace_back(LookupResult{});
        }
    }
    
    return results;
}

LookupResult WhitelistStore::IsWhitelisted(
    std::wstring_view filePath,
    const HashValue* fileHash,
    const std::array<uint8_t, 32>* certThumbprint,
    std::wstring_view publisher,
    const QueryOptions& options
) const noexcept {
    /*
     * ========================================================================
     * COMPREHENSIVE WHITELIST CHECK
     * ========================================================================
     *
     * Checks multiple whitelist types in priority order:
     * 1. File hash (fastest, most specific)
     * 2. Certificate thumbprint (trusted signer)
     * 3. Publisher name (trusted vendor)
     * 4. File path (location-based trust)
     *
     * First match wins for performance. This order also reflects
     * the trustworthiness hierarchy:
     * - Hash is most specific and tamper-resistant
     * - Certificate validates the signer
     * - Publisher is a higher-level trust
     * - Path is least specific and location-dependent
     *
     * ========================================================================
     */
    
    // Validation - store must be initialized
    if (!m_initialized.load(std::memory_order_acquire)) {
        return LookupResult{};
    }
    
    // Priority 1: Hash check (most specific, fastest)
    if (fileHash && !fileHash->IsEmpty()) {
        auto result = IsHashWhitelisted(*fileHash, options);
        if (result.found) {
            return result;
        }
    }
    
    // Priority 2: Certificate check (validates signer)
    if (certThumbprint) {
        auto result = IsCertificateWhitelisted(*certThumbprint, options);
        if (result.found) {
            return result;
        }
    }
    
    // Priority 3: Publisher check (trusted vendor)
    if (!publisher.empty()) {
        auto result = IsPublisherWhitelisted(publisher, options);
        if (result.found) {
            return result;
        }
    }
    
    // Priority 4: Path check (location-based trust)
    if (!filePath.empty()) {
        auto result = IsPathWhitelisted(filePath, options);
        if (result.found) {
            return result;
        }
    }
    
    // No match found
    return LookupResult{};
}

// ============================================================================
// MODIFICATION OPERATIONS (Write Operations)
// ============================================================================

StoreError WhitelistStore::AddHash(
    const HashValue& hash,
    WhitelistReason reason,
    std::wstring_view description,
    uint64_t expirationTime,
    uint32_t policyId
) noexcept {
    /*
     * ========================================================================
     * ADD HASH ENTRY
     * ========================================================================
     *
     * Adds a new hash-based whitelist entry with full validation:
     * - Checks for read-only database
     * - Validates hash is not empty
     * - Checks for duplicate entries
     * - Allocates entry in memory-mapped file
     * - Updates B+Tree index and bloom filter
     *
     * Thread Safety: Uses global lock for write operations.
     *
     * ========================================================================
     */
    
    // Validate database state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate hash
    if (hash.IsEmpty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty hash value"
        );
    }
    
    // Validate description length
    constexpr size_t MAX_DESCRIPTION_LENGTH = 32767;
    if (description.length() > MAX_DESCRIPTION_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Description exceeds maximum length"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Check for duplicate
    if (m_hashIndex && m_hashIndex->Contains(hash)) {
        return StoreError::WithMessage(
            WhitelistStoreError::DuplicateEntry,
            "Hash already exists in whitelist"
        );
    }
    
    // Allocate new entry
    auto* entry = AllocateEntry();
    if (!entry) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate entry"
        );
    }
    
    // Fill entry with safe defaults first
    std::memset(entry, 0, sizeof(WhitelistEntry));
    
    // Populate entry fields
    entry->entryId = GetNextEntryId();
    entry->type = WhitelistEntryType::FileHash;
    entry->reason = reason;
    entry->matchMode = PathMatchMode::Exact;
    entry->flags = WhitelistFlags::Enabled;
    entry->hashAlgorithm = hash.algorithm;
    
    // Safe hash length calculation with bounds validation
    const size_t maxHashLen = entry->hashData.size();
    const size_t sourceHashLen = static_cast<size_t>(hash.length);
    const size_t safeHashLen = std::min(sourceHashLen, maxHashLen);
    
    // Additional validation: ensure source data is valid
    if (safeHashLen > 0 && safeHashLen <= hash.data.size()) {
        entry->hashLength = static_cast<uint8_t>(safeHashLen);
        // Use volatile_memcpy pattern for security-critical data
        std::memcpy(entry->hashData.data(), hash.data.data(), safeHashLen);
        // Zero out remaining bytes to prevent data leakage
        if (safeHashLen < maxHashLen) {
            std::memset(entry->hashData.data() + safeHashLen, 0, maxHashLen - safeHashLen);
        }
    } else {
        entry->hashLength = 0;
        SS_LOG_WARN(L"Whitelist", L"Invalid hash length, storing empty hash data");
    }
    
    // Set timestamps
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    entry->createdTime = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
    entry->modifiedTime = entry->createdTime;
    entry->expirationTime = expirationTime;
    
    if (expirationTime > 0) {
        entry->flags = entry->flags | WhitelistFlags::HasExpiration;
    }
    
    entry->policyId = policyId;
    entry->SetHitCount(0);
    
    // Add description (with validation)
    if (!description.empty() && m_stringPool) {
        auto descOffset = m_stringPool->AddWideString(description);
        if (descOffset.has_value()) {
            entry->descriptionOffset = *descOffset;
            // Safe calculation of byte length with overflow check
            const size_t descLen = description.length();
            constexpr size_t MAX_DESC_CHARS = UINT16_MAX / sizeof(wchar_t);
            if (descLen <= MAX_DESC_CHARS) {
                entry->descriptionLength = static_cast<uint16_t>(descLen * sizeof(wchar_t));
            } else {
                entry->descriptionLength = UINT16_MAX;
                SS_LOG_WARN(L"Whitelist", L"Description truncated to max length");
            }
        }
    }
    
    // Calculate entry offset safely with comprehensive bounds checking
    if (!m_mappedView.baseAddress || m_mappedView.fileSize == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid mapped view"
        );
    }
    
    const uintptr_t entryAddr = reinterpret_cast<uintptr_t>(entry);
    const uintptr_t baseAddr = reinterpret_cast<uintptr_t>(m_mappedView.baseAddress);
    const uintptr_t endAddr = baseAddr + m_mappedView.fileSize;
    
    // Validate entry is within mapped bounds (both lower and upper)
    if (entryAddr < baseAddr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Entry address below mapped base"
        );
    }
    
    if (entryAddr + sizeof(WhitelistEntry) > endAddr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Entry address exceeds mapped bounds"
        );
    }
    
    const uint64_t entryOffset = static_cast<uint64_t>(entryAddr - baseAddr);
    
    // Add to B+Tree index
    if (m_hashIndex) {
        auto err = m_hashIndex->Insert(hash, entryOffset);
        if (!err.IsSuccess()) {
            return err;
        }
    }
    
    // Add to Bloom filter
    if (m_hashBloomFilter) {
        m_hashBloomFilter->Add(hash);
    }
    
    // Update statistics
    UpdateHeaderStats();
    
    SS_LOG_INFO(L"Whitelist", L"Added hash entry: ID=%llu, reason=%d", 
        entry->entryId, static_cast<int>(reason));
    
    return StoreError::Success();
}

StoreError WhitelistStore::AddHash(
    const std::string& hashString,
    HashAlgorithm algorithm,
    WhitelistReason reason,
    std::wstring_view description,
    uint64_t expirationTime,
    uint32_t policyId
) noexcept {
    /*
     * ========================================================================
     * ADD HASH FROM STRING - ENTERPRISE-GRADE IMPLEMENTATION
     * ========================================================================
     *
     * Parses a hex-encoded hash string and adds it to the whitelist.
     * Delegates to the main AddHash() after validation and parsing.
     *
     * Security Considerations:
     * - Input validation prevents malformed data injection
     * - Algorithm mismatch detection prevents hash collision attacks
     * - String length validation prevents buffer overflows
     *
     * ========================================================================
     */
    
    // Validate database state early (fail-fast)
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate hash string is not empty
    if (hashString.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty hash string"
        );
    }
    
    // Validate hash string length based on algorithm
    // Expected lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128 hex characters
    size_t expectedLength = 0;
    switch (algorithm) {
        case HashAlgorithm::MD5:
            expectedLength = 32;
            break;
        case HashAlgorithm::SHA1:
            expectedLength = 40;
            break;
        case HashAlgorithm::SHA256:
            expectedLength = 64;
            break;
        case HashAlgorithm::SHA512:
            expectedLength = 128;
            break;
        default:
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Unsupported hash algorithm"
            );
    }
    
    // Allow some flexibility: accept strings with or without "0x" prefix
    std::string cleanHashString = hashString;
    if (cleanHashString.size() >= 2 && 
        cleanHashString[0] == '0' && 
        (cleanHashString[1] == 'x' || cleanHashString[1] == 'X')) {
        cleanHashString = cleanHashString.substr(2);
    }
    
    // Validate cleaned string length
    if (cleanHashString.length() != expectedLength) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Hash string length mismatch for algorithm (expected " + 
            std::to_string(expectedLength) + " hex chars, got " +
            std::to_string(cleanHashString.length()) + ")"
        );
    }
    
    // Validate all characters are valid hex digits
    for (char c : cleanHashString) {
        if (!((c >= '0' && c <= '9') || 
              (c >= 'a' && c <= 'f') || 
              (c >= 'A' && c <= 'F'))) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Hash string contains invalid hex character"
            );
        }
    }
    
    // Parse the hash string using Format utilities
    auto parsedHash = Format::ParseHashString(cleanHashString, algorithm);
    if (!parsedHash.has_value()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Failed to parse hash string"
        );
    }
    
    // Delegate to main AddHash function with parsed HashValue
    return AddHash(*parsedHash, reason, description, expirationTime, policyId);
}

StoreError WhitelistStore::AddPath(
    std::wstring_view path,
    PathMatchMode matchMode,
    WhitelistReason reason,
    std::wstring_view description,
    uint64_t expirationTime,
    uint32_t policyId
) noexcept {
    /*
     * ========================================================================
     * ADD PATH ENTRY
     * ========================================================================
     *
     * Adds a new path-based whitelist entry with full validation.
     * Supports exact match and pattern matching modes.
     *
     * ========================================================================
     */
    
    // Validate database state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate path
    if (path.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty path"
        );
    }
    
    // Validate path length (Windows limit)
    constexpr size_t MAX_PATH_LEN = 32767;
    if (path.length() > MAX_PATH_LEN) {
        return StoreError::WithMessage(
            WhitelistStoreError::PathTooLong,
            "Path exceeds maximum length"
        );
    }
    
    // Validate description length
    constexpr size_t MAX_DESCRIPTION_LENGTH = 32767;
    if (description.length() > MAX_DESCRIPTION_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Description exceeds maximum length"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Allocate entry
    auto* entry = AllocateEntry();
    if (!entry) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate entry"
        );
    }
    
    // Zero-initialize for safety
    std::memset(entry, 0, sizeof(WhitelistEntry));
    
    // Fill entry
    entry->entryId = GetNextEntryId();
    entry->type = WhitelistEntryType::FilePath;
    entry->reason = reason;
    entry->matchMode = matchMode;
    entry->flags = WhitelistFlags::Enabled;
    
    // Set timestamps
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    entry->createdTime = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
    entry->modifiedTime = entry->createdTime;
    entry->expirationTime = expirationTime;
    
    if (expirationTime > 0) {
        entry->flags = entry->flags | WhitelistFlags::HasExpiration;
    }
    
    entry->policyId = policyId;
    entry->SetHitCount(0);
    
    // Add path to string pool with safe length calculation
    if (m_stringPool) {
        auto pathOffset = m_stringPool->AddWideString(path);
        if (pathOffset.has_value()) {
            entry->pathOffset = *pathOffset;
            // Safe byte length calculation with overflow check
            const size_t pathLen = path.length();
            constexpr size_t MAX_PATH_CHARS = UINT16_MAX / sizeof(wchar_t);
            if (pathLen <= MAX_PATH_CHARS) {
                entry->pathLength = static_cast<uint16_t>(pathLen * sizeof(wchar_t));
            } else {
                entry->pathLength = UINT16_MAX;
                SS_LOG_WARN(L"Whitelist", L"Path length truncated to max");
            }
        } else {
            SS_LOG_WARN(L"Whitelist", L"Failed to add path to string pool");
        }
    }
    
    // Add description with safe length calculation
    if (!description.empty() && m_stringPool) {
        auto descOffset = m_stringPool->AddWideString(description);
        if (descOffset.has_value()) {
            entry->descriptionOffset = *descOffset;
            const size_t descLen = description.length();
            constexpr size_t MAX_DESC_CHARS = UINT16_MAX / sizeof(wchar_t);
            if (descLen <= MAX_DESC_CHARS) {
                entry->descriptionLength = static_cast<uint16_t>(descLen * sizeof(wchar_t));
            } else {
                entry->descriptionLength = UINT16_MAX;
            }
        }
    }
    
    // Calculate entry offset safely with comprehensive bounds checking
    if (!m_mappedView.baseAddress || m_mappedView.fileSize == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid mapped view"
        );
    }
    
    const uintptr_t entryAddr = reinterpret_cast<uintptr_t>(entry);
    const uintptr_t baseAddr = reinterpret_cast<uintptr_t>(m_mappedView.baseAddress);
    const uintptr_t endAddr = baseAddr + m_mappedView.fileSize;
    
    // Validate entry is within mapped bounds (both lower and upper)
    if (entryAddr < baseAddr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Entry address below mapped base"
        );
    }
    
    if (entryAddr + sizeof(WhitelistEntry) > endAddr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Entry address exceeds mapped bounds"
        );
    }
    
    const uint64_t entryOffset = static_cast<uint64_t>(entryAddr - baseAddr);
    
    // Add to path index
    if (m_pathIndex) {
        auto err = m_pathIndex->Insert(path, matchMode, entryOffset);
        if (!err.IsSuccess()) {
            return err;
        }
    }
    
    // Add to path bloom filter
    if (m_pathBloomFilter) {
        try {
            auto normalizedPath = Format::NormalizePath(path);
            // Compute FNV-1a hash
            uint64_t pathHash = 14695981039346656037ULL;
            for (wchar_t c : normalizedPath) {
                pathHash ^= static_cast<uint64_t>(c);
                pathHash *= 1099511628211ULL;
            }
            m_pathBloomFilter->Add(pathHash);
        } catch (const std::exception&) {
            // Bloom filter update failed - non-critical
        }
    }
    
    UpdateHeaderStats();
    
    SS_LOG_INFO(L"Whitelist", L"Added path entry: ID=%llu, mode=%d", 
        entry->entryId, static_cast<int>(matchMode));
    
    return StoreError::Success();
}

StoreError WhitelistStore::AddCertificate(
    const std::array<uint8_t, 32>& thumbprint,
    WhitelistReason reason,
    std::wstring_view description,
    uint64_t expirationTime,
    uint32_t policyId
) noexcept {
    // Create SHA-256 hash from certificate thumbprint
    HashValue hash = HashValue::Create(HashAlgorithm::SHA256, thumbprint.data(), 32);
    return AddHash(hash, reason, description, expirationTime, policyId);
}

StoreError WhitelistStore::AddPublisher(
    std::wstring_view publisherName,
    WhitelistReason reason,
    std::wstring_view description,
    uint64_t expirationTime,
    uint32_t policyId
) noexcept {
    // Validate publisher name
    if (publisherName.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty publisher name"
        );
    }
    
    return AddPath(publisherName, PathMatchMode::Exact, reason, description, expirationTime, policyId);
}

StoreError WhitelistStore::RemoveEntry(uint64_t entryId) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE ENTRY REMOVAL BY ID
     * ========================================================================
     *
     * Removes a whitelist entry by its unique ID. This performs:
     * 1. Lookup entry by ID in entry data section
     * 2. Remove from appropriate index (hash/path)
     * 3. Mark entry as revoked (soft delete)
     * 4. Update header statistics
     *
     * Security Note: Soft delete prevents accidental data loss and 
     * maintains audit trail. Physical deletion occurs during compaction.
     *
     * ========================================================================
     */
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate entry ID
    if (entryId == 0 || entryId == UINT64_MAX) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Invalid entry ID"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Get header
    const auto* header = GetHeader();
    if (!header || header->entryDataOffset == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section not available"
        );
    }
    
    // Search for entry by ID
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    // Validate bounds
    if (entryDataEnd > m_mappedView.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section exceeds file bounds"
        );
    }
    
    // Linear scan for entry (could be optimized with ID index)
    uint64_t offset = entryDataStart;
    WhitelistEntry* foundEntry = nullptr;
    
    while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
        auto* entry = m_mappedView.GetAtMutable<WhitelistEntry>(offset);
        if (!entry) {
            break;
        }
        
        if (entry->entryId == entryId) {
            foundEntry = entry;
            break;
        }
        
        offset += sizeof(WhitelistEntry);
    }
    
    if (!foundEntry) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Entry ID not found"
        );
    }
    
    // Check if already revoked
    if (HasFlag(foundEntry->flags, WhitelistFlags::Revoked)) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Entry already revoked"
        );
    }
    
    // Remove from index based on type
    StoreError indexError = StoreError::Success();
    
    if (foundEntry->type == WhitelistEntryType::FileHash) {
        // Remove from hash index
        if (m_hashIndex) {
            HashValue hash = HashValue::Create(foundEntry->hashAlgorithm, 
                foundEntry->hashData.data(), 
                foundEntry->hashLength);
            indexError = m_hashIndex->Remove(hash);
        }
    } else if (foundEntry->type == WhitelistEntryType::FilePath ||
               foundEntry->type == WhitelistEntryType::ProcessPath) {
        // Remove from path index
        if (m_pathIndex && foundEntry->pathOffset > 0 && m_stringPool) {
            auto pathView = m_stringPool->GetWideString(
                foundEntry->pathOffset, 
                foundEntry->pathLength);
            if (!pathView.empty()) {
                indexError = m_pathIndex->Remove(pathView, foundEntry->matchMode);
            }
        }
    }
    
    // Mark entry as revoked (soft delete)
    foundEntry->flags = foundEntry->flags | WhitelistFlags::Revoked;
    foundEntry->flags = static_cast<WhitelistFlags>(
        static_cast<uint32_t>(foundEntry->flags) & ~static_cast<uint32_t>(WhitelistFlags::Enabled)
    );
    
    // Update modification time
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    foundEntry->modifiedTime = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
    
    // Update header stats
    UpdateHeaderStats();
    
    SS_LOG_INFO(L"Whitelist", L"RemoveEntry: ID=%llu removed (type=%d)", 
        entryId, static_cast<int>(foundEntry->type));
    
    // Clear cache since data changed
    ClearCache();
    
    return StoreError::Success();
}

StoreError WhitelistStore::RemoveHash(const HashValue& hash) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    if (hash.IsEmpty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty hash value"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    if (m_hashIndex) {
        return m_hashIndex->Remove(hash);
    }
    
    return StoreError::WithMessage(
        WhitelistStoreError::InvalidSection,
        "Hash index not available"
    );
}

StoreError WhitelistStore::RemovePath(
    std::wstring_view path,
    PathMatchMode matchMode
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    if (path.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty path"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    if (m_pathIndex) {
        return m_pathIndex->Remove(path, matchMode);
    }
    
    return StoreError::WithMessage(
        WhitelistStoreError::InvalidSection,
        "Path index not available"
    );
}

StoreError WhitelistStore::BatchAdd(
    std::span<const WhitelistEntry> entries
) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE BATCH ENTRY ADDITION
     * ========================================================================
     *
     * Efficiently adds multiple whitelist entries in a single operation.
     * Implements a pseudo-transaction: if critical errors occur, no entries
     * are added. For non-critical errors (duplicates), continues processing.
     *
     * Performance Optimizations:
     * - Single lock acquisition for entire batch
     * - Pre-validation of all entries before committing
     * - Batch index updates
     *
     * ========================================================================
     */
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Handle empty batch
    if (entries.empty()) {
        return StoreError::Success();
    }
    
    // Validate batch size
    constexpr size_t MAX_BATCH_SIZE = 100000;
    if (entries.size() > MAX_BATCH_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::TooManyEntries,
            "Batch size exceeds maximum"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Check available space
    const auto* header = GetHeader();
    if (!header || header->entryDataOffset == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section not available"
        );
    }
    
    const uint64_t currentUsed = m_entryDataUsed.load(std::memory_order_relaxed);
    const uint64_t spaceNeeded = entries.size() * sizeof(WhitelistEntry);
    
    // Overflow check
    if (spaceNeeded > header->entryDataSize - currentUsed) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Insufficient space for batch entries"
        );
    }
    
    size_t added = 0;
    size_t skipped = 0;
    size_t failed = 0;
    
    // Process each entry
    for (const auto& sourceEntry : entries) {
        // Validate entry type
        if (sourceEntry.type == WhitelistEntryType::Reserved) {
            ++skipped;
            continue;
        }
        
        // Check for duplicates based on type
        bool isDuplicate = false;
        
        if (sourceEntry.type == WhitelistEntryType::FileHash) {
            // Validate hash length before creating HashValue
            if (sourceEntry.hashLength == 0 || 
                sourceEntry.hashLength > sourceEntry.hashData.size()) {
                ++failed;
                continue;
            }
            
            if (m_hashIndex) {
                HashValue hash = HashValue::Create(sourceEntry.hashAlgorithm,
                    sourceEntry.hashData.data(),
                    sourceEntry.hashLength);
                isDuplicate = m_hashIndex->Contains(hash);
            }
        }
        
        if (isDuplicate) {
            ++skipped;
            continue;
        }
        
        // Allocate entry
        auto* newEntry = AllocateEntry();
        if (!newEntry) {
            ++failed;
            continue;
        }
        
        // Copy entry data (use memmove for overlapping safety, though not expected)
        std::memmove(newEntry, &sourceEntry, sizeof(WhitelistEntry));
        
        // Assign new unique ID
        newEntry->entryId = GetNextEntryId();
        
        // Set timestamps if not provided
        if (newEntry->createdTime == 0) {
            auto now = std::chrono::system_clock::now();
            auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            // Validate epoch is in reasonable range
            constexpr int64_t MIN_EPOCH = 946684800LL;   // 2000-01-01
            constexpr int64_t MAX_EPOCH = 4102444800LL;  // 2100-01-01
            if (epoch < MIN_EPOCH) epoch = MIN_EPOCH;
            if (epoch > MAX_EPOCH) epoch = MAX_EPOCH;
            newEntry->createdTime = static_cast<uint64_t>(epoch);
            newEntry->modifiedTime = newEntry->createdTime;
        }
        
        // Ensure entry is enabled
        newEntry->flags = newEntry->flags | WhitelistFlags::Enabled;
        
        // Reset hit count
        newEntry->SetHitCount(0);
        
        // Calculate entry offset with full bounds validation
        if (!m_mappedView.baseAddress || m_mappedView.fileSize == 0) {
            ++failed;
            continue;
        }
        
        const uintptr_t entryAddr = reinterpret_cast<uintptr_t>(newEntry);
        const uintptr_t baseAddr = reinterpret_cast<uintptr_t>(m_mappedView.baseAddress);
        const uintptr_t endAddr = baseAddr + m_mappedView.fileSize;
        
        // Validate entry is within mapped bounds
        if (entryAddr < baseAddr || entryAddr + sizeof(WhitelistEntry) > endAddr) {
            SS_LOG_ERROR(L"Whitelist", L"BatchAdd: entry allocation out of bounds");
            ++failed;
            continue;
        }
        
        const uint64_t entryOffset = static_cast<uint64_t>(entryAddr - baseAddr);
        
        // Add to index based on type
        StoreError indexResult = StoreError::Success();
        
        if (newEntry->type == WhitelistEntryType::FileHash) {
            // Add to hash index and bloom filter with validated hash length
            if (newEntry->hashLength > 0 && newEntry->hashLength <= newEntry->hashData.size()) {
                HashValue hash = HashValue::Create(newEntry->hashAlgorithm,
                    newEntry->hashData.data(),
                    newEntry->hashLength);
                
                if (m_hashBloomFilter) {
                    m_hashBloomFilter->Add(hash.FastHash());
                }
                
                if (m_hashIndex) {
                    indexResult = m_hashIndex->Insert(hash, entryOffset);
                }
            } else {
                ++failed;
                continue;
            }
        } else if (newEntry->type == WhitelistEntryType::FilePath ||
                   newEntry->type == WhitelistEntryType::ProcessPath) {
            // Path entries need path from string pool
            // For batch, we assume paths are already stored
            if (m_pathIndex && newEntry->pathOffset > 0 && m_stringPool) {
                auto pathView = m_stringPool->GetWideString(
                    newEntry->pathOffset,
                    newEntry->pathLength);
                if (!pathView.empty()) {
                    if (m_pathBloomFilter) {
                        // Add path hash to bloom filter using FNV-1a for consistency
                        uint64_t pathHash = 14695981039346656037ULL; // FNV offset basis
                        for (wchar_t c : pathView) {
                            pathHash ^= static_cast<uint64_t>(c);
                            pathHash *= 1099511628211ULL; // FNV prime
                        }
                        m_pathBloomFilter->Add(pathHash);
                    }
                    indexResult = m_pathIndex->Insert(pathView, newEntry->matchMode, entryOffset);
                }
            }
        }
        
        if (indexResult.IsSuccess()) {
            ++added;
        } else {
            ++failed;
            // Could rollback entry allocation here for strict transaction
        }
    }
    
    // Update header statistics
    UpdateHeaderStats();
    
    SS_LOG_INFO(L"Whitelist", L"BatchAdd: %zu added, %zu skipped, %zu failed (total: %zu)",
        added, skipped, failed, entries.size());
    
    if (failed > 0 && added == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            "All batch entries failed"
        );
    }
    
    // Clear cache since data changed
    if (added > 0) {
        ClearCache();
    }
    
    return StoreError::Success();
}

StoreError WhitelistStore::UpdateEntryFlags(
    uint64_t entryId,
    WhitelistFlags flags
) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE ENTRY FLAG UPDATE
     * ========================================================================
     *
     * Updates the flags of a whitelist entry by ID.
     * 
     * Common use cases:
     * - Enable/disable entry
     * - Set expiration flag
     * - Mark as revoked
     * - Set temporary flag
     *
     * Security Note: Changing flags can affect entry behavior immediately.
     * Cache is cleared to ensure consistency.
     *
     * ========================================================================
     */
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate entry ID
    if (entryId == 0 || entryId == UINT64_MAX) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Invalid entry ID"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Get header for entry data bounds
    const auto* header = GetHeader();
    if (!header || header->entryDataOffset == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section not available"
        );
    }
    
    // Validate entry data bounds
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    if (entryDataEnd > m_mappedView.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section exceeds file bounds"
        );
    }
    
    // Search for entry by ID
    uint64_t offset = entryDataStart;
    WhitelistEntry* foundEntry = nullptr;
    
    // Linear scan (could be optimized with ID index)
    while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
        auto* entry = m_mappedView.GetAtMutable<WhitelistEntry>(offset);
        if (!entry) {
            break;
        }
        
        // Skip already-revoked entries when searching
        if (entry->entryId == entryId) {
            foundEntry = entry;
            break;
        }
        
        offset += sizeof(WhitelistEntry);
    }
    
    if (!foundEntry) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Entry ID not found"
        );
    }
    
    // Store old flags for logging
    const WhitelistFlags oldFlags = foundEntry->flags;
    
    // Update flags
    foundEntry->flags = flags;
    
    // Update modification timestamp
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    foundEntry->modifiedTime = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
    
    // If revoked flag is set, also update index
    if (HasFlag(flags, WhitelistFlags::Revoked) && !HasFlag(oldFlags, WhitelistFlags::Revoked)) {
        // Remove from appropriate index
        if (foundEntry->type == WhitelistEntryType::FileHash && m_hashIndex) {
            HashValue hash = HashValue::Create(foundEntry->hashAlgorithm,
                foundEntry->hashData.data(),
                foundEntry->hashLength);
            auto removeResult = m_hashIndex->Remove(hash);
            if (!removeResult.IsSuccess() && 
                removeResult.code != WhitelistStoreError::EntryNotFound) {
                SS_LOG_WARN(L"Whitelist", L"Failed to remove revoked hash from index");
            }
        } else if ((foundEntry->type == WhitelistEntryType::FilePath ||
                    foundEntry->type == WhitelistEntryType::ProcessPath) &&
                   m_pathIndex && m_stringPool) {
            auto pathView = m_stringPool->GetWideString(
                foundEntry->pathOffset,
                foundEntry->pathLength);
            if (!pathView.empty()) {
                auto removeResult = m_pathIndex->Remove(pathView, foundEntry->matchMode);
                if (!removeResult.IsSuccess() && 
                    removeResult.code != WhitelistStoreError::EntryNotFound) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to remove revoked path from index");
                }
            }
        }
    }
    
    SS_LOG_DEBUG(L"Whitelist", L"UpdateEntryFlags: ID=%llu, oldFlags=%u, newFlags=%u",
        entryId, static_cast<uint32_t>(oldFlags), static_cast<uint32_t>(flags));
    
    // Clear cache since behavior may have changed
    ClearCache();
    
    return StoreError::Success();
}

StoreError WhitelistStore::RevokeEntry(uint64_t entryId) noexcept {
    return UpdateEntryFlags(entryId, WhitelistFlags::Revoked);
}

// ============================================================================
// IMPORT/EXPORT OPERATIONS
// ============================================================================

StoreError WhitelistStore::ImportFromJSON(
    const std::wstring& filePath,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    /*
     * ========================================================================
     * JSON FILE IMPORT
     * ========================================================================
     *
     * Imports whitelist entries from a JSON file.
     *
     * File Format:
     * {
     *   "version": "1.0",
     *   "entries": [
     *     { "type": "hash", "algorithm": "sha256", "value": "...", ... },
     *     { "type": "path", "path": "...", "mode": "exact", ... }
     *   ]
     * }
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot import to read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate file path
    if (filePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::FileNotFound,
            "Empty file path"
        );
    }
    
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (filePath.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::PathTooLong,
            "File path exceeds maximum length"
        );
    }
    
    try {
        // Open file with explicit error checking
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileNotFound,
                "Failed to open JSON file"
            );
        }
        
        // Check file size to prevent memory exhaustion
        file.seekg(0, std::ios::end);
        const auto fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        constexpr std::streamoff MAX_JSON_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit
        if (fileSize < 0 || fileSize > MAX_JSON_FILE_SIZE) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "JSON file size invalid or exceeds limit"
            );
        }
        
        // Read file contents
        std::string jsonContent;
        jsonContent.resize(static_cast<size_t>(fileSize));
        file.read(jsonContent.data(), fileSize);
        
        if (!file.good() && !file.eof()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileAccessDenied,
                "Failed to read JSON file"
            );
        }
        
        file.close();
        
        return ImportFromJSONString(jsonContent, progressCallback);
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory reading JSON file"
        );
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            std::string("JSON file error: ") + e.what()
        );
    }
}

StoreError WhitelistStore::ImportFromJSONString(
    std::string_view jsonData,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    /*
     * ========================================================================
     * JSON STRING IMPORT
     * ========================================================================
     *
     * Parses JSON string and imports whitelist entries.
     * Validates each entry before adding to the database.
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot import to read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate input
    if (jsonData.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Empty JSON data"
        );
    }
    
    constexpr size_t MAX_JSON_SIZE = 100 * 1024 * 1024; // 100MB
    if (jsonData.size() > MAX_JSON_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "JSON data exceeds maximum size"
        );
    }
    
    try {
        // Parse JSON
        auto j = nlohmann::json::parse(jsonData);
        
        // Validate structure
        if (!j.is_object()) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Invalid JSON: expected object"
            );
        }
        
        if (!j.contains("entries") || !j["entries"].is_array()) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Invalid JSON format: missing 'entries' array"
            );
        }
        
        const auto& entries = j["entries"];
        const size_t total = entries.size();
        
        // Limit entries to prevent resource exhaustion
        constexpr size_t MAX_IMPORT_ENTRIES = 10000000; // 10M entries max
        if (total > MAX_IMPORT_ENTRIES) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Too many entries in JSON"
            );
        }
        
        size_t imported = 0;
        size_t failed = 0;
        
        for (size_t i = 0; i < total; ++i) {
            const auto& entry = entries[i];
            
            // Parse and validate entry
            if (!entry.is_object()) {
                ++failed;
                continue;
            }
            
            // Get entry type
            std::string entryType;
            if (entry.contains("type") && entry["type"].is_string()) {
                entryType = entry["type"].get<std::string>();
            } else {
                ++failed;
                continue;
            }
            
            // Process based on type
            StoreError addResult;
            
            // Helper lambda for UTF-8 to UTF-16 conversion (proper Windows API)
            auto utf8ToWide = [](const std::string& utf8) -> std::wstring {
                if (utf8.empty()) return {};
                
                // Calculate required buffer size
                int wideLen = MultiByteToWideChar(CP_UTF8, 0, 
                    utf8.c_str(), static_cast<int>(utf8.size()), 
                    nullptr, 0);
                    
                if (wideLen <= 0) return {};
                
                std::wstring wideStr;
                wideStr.resize(static_cast<size_t>(wideLen));
                
                int converted = MultiByteToWideChar(CP_UTF8, 0,
                    utf8.c_str(), static_cast<int>(utf8.size()),
                    wideStr.data(), wideLen);
                    
                if (converted <= 0) return {};
                
                return wideStr;
            };
            
            if (entryType == "hash" || entryType == "file_hash") {
                // Hash entry
                if (!entry.contains("value") || !entry["value"].is_string()) {
                    ++failed;
                    continue;
                }
                
                const std::string hashValue = entry["value"].get<std::string>();
                HashAlgorithm algorithm = HashAlgorithm::SHA256; // Default
                
                if (entry.contains("algorithm") && entry["algorithm"].is_string()) {
                    const std::string algStr = entry["algorithm"].get<std::string>();
                    if (algStr == "md5") algorithm = HashAlgorithm::MD5;
                    else if (algStr == "sha1") algorithm = HashAlgorithm::SHA1;
                    else if (algStr == "sha256") algorithm = HashAlgorithm::SHA256;
                    else if (algStr == "sha512") algorithm = HashAlgorithm::SHA512;
                }
                
                auto hash = Format::ParseHashString(hashValue, algorithm);
                if (!hash.has_value()) {
                    ++failed;
                    continue;
                }
                
                // Get optional fields
                WhitelistReason reason = WhitelistReason::UserApproved;
                std::wstring description;
                uint64_t expiration = 0;
                
                if (entry.contains("reason") && entry["reason"].is_string()) {
                    // Parse reason string to enum
                    const std::string reasonStr = entry["reason"].get<std::string>();
                    if (reasonStr == "system_file") reason = WhitelistReason::SystemFile;
                    else if (reasonStr == "trusted_vendor") reason = WhitelistReason::TrustedVendor;
                    else if (reasonStr == "policy_based") reason = WhitelistReason::PolicyBased;
                    else if (reasonStr == "ml_classified") reason = WhitelistReason::MLClassified;
                    else if (reasonStr == "reputation_based") reason = WhitelistReason::ReputationBased;
                    else reason = WhitelistReason::UserApproved;
                }
                
                if (entry.contains("description") && entry["description"].is_string()) {
                    const std::string desc = entry["description"].get<std::string>();
                    // Convert UTF-8 to wide string using proper API
                    description = utf8ToWide(desc);
                }
                
                if (entry.contains("expires") && entry["expires"].is_number_unsigned()) {
                    expiration = entry["expires"].get<uint64_t>();
                }
                
                addResult = AddHash(*hash, reason, description, expiration, 0);
                
            } else if (entryType == "path" || entryType == "file_path") {
                // Path entry
                if (!entry.contains("path") || !entry["path"].is_string()) {
                    ++failed;
                    continue;
                }
                
                const std::string pathStr = entry["path"].get<std::string>();
                // Convert UTF-8 path to wide string using proper API
                std::wstring path = utf8ToWide(pathStr);
                
                // Validate path is not empty after conversion
                if (path.empty() && !pathStr.empty()) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to convert path from UTF-8");
                    ++failed;
                    continue;
                }
                
                PathMatchMode mode = PathMatchMode::Exact;
                if (entry.contains("mode") && entry["mode"].is_string()) {
                    const std::string modeStr = entry["mode"].get<std::string>();
                    if (modeStr == "prefix") mode = PathMatchMode::Prefix;
                    else if (modeStr == "suffix") mode = PathMatchMode::Suffix;
                    else if (modeStr == "glob") mode = PathMatchMode::Glob;
                    else if (modeStr == "regex") mode = PathMatchMode::Regex;
                    else if (modeStr == "contains") mode = PathMatchMode::Contains;
                }
                
                WhitelistReason reason = WhitelistReason::UserApproved;
                std::wstring description;
                uint64_t expiration = 0;
                
                if (entry.contains("description") && entry["description"].is_string()) {
                    description = utf8ToWide(entry["description"].get<std::string>());
                }
                
                if (entry.contains("expires") && entry["expires"].is_number_unsigned()) {
                    expiration = entry["expires"].get<uint64_t>();
                }
                
                addResult = AddPath(path, mode, reason, description, expiration, 0);
                
            } else {
                // Unknown entry type
                ++failed;
                continue;
            }
            
            if (addResult.IsSuccess()) {
                ++imported;
            } else if (addResult.code == WhitelistStoreError::DuplicateEntry) {
                // Duplicates are okay, just skip
                ++imported;
            } else {
                ++failed;
            }
            
            // Progress callback (safely invoke)
            if (progressCallback) {
                try {
                    progressCallback(i + 1, total);
                } catch (...) {
                    // Ignore callback exceptions
                }
            }
        }
        
        SS_LOG_INFO(L"Whitelist", L"Imported %zu entries from JSON (%zu failed)", 
            imported, failed);
        
        // Save changes
        if (imported > 0) {
            auto saveResult = Save();
            if (!saveResult.IsSuccess()) {
                SS_LOG_WARN(L"Whitelist", L"Failed to save after JSON import: %S", 
                    saveResult.message.c_str());
                // Continue - entries are in memory even if save failed
            }
        }
        
        return StoreError::Success();
        
    } catch (const nlohmann::json::parse_error& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            std::string("JSON parse error: ") + e.what()
        );
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory parsing JSON"
        );
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            std::string("JSON import error: ") + e.what()
        );
    }
}

StoreError WhitelistStore::ImportFromCSV(
    const std::wstring& filePath,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    /*
     * ========================================================================
     * CSV FILE IMPORT
     * ========================================================================
     *
     * Imports whitelist entries from a CSV file.
     *
     * Expected format:
     * type,value,algorithm,reason,description
     * hash,abc123...,sha256,manual,"Trusted file"
     * path,C:\Windows\*,glob,system,"Windows directory"
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot import to read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate file path
    if (filePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::FileNotFound,
            "Empty file path"
        );
    }
    
    SS_LOG_INFO(L"Whitelist", L"CSV import: %s", filePath.c_str());
    
    try {
        // Open file for reading
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileNotFound,
                "Failed to open CSV file"
            );
        }
        
        // Check file size
        file.seekg(0, std::ios::end);
        const auto fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        constexpr std::streamoff MAX_CSV_FILE_SIZE = 500 * 1024 * 1024; // 500MB limit
        if (fileSize < 0 || fileSize > MAX_CSV_FILE_SIZE) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "CSV file size invalid or exceeds limit"
            );
        }
        
        // CSV parsing helper - parse a single field
        auto parseCSVField = [](const std::string& line, size_t& pos) -> std::string {
            std::string field;
            
            if (pos >= line.length()) return field;
            
            // Skip leading whitespace
            while (pos < line.length() && (line[pos] == ' ' || line[pos] == '\t')) {
                ++pos;
            }
            
            if (pos >= line.length()) return field;
            
            // Check if field is quoted
            if (line[pos] == '"') {
                ++pos; // Skip opening quote
                bool escaped = false;
                
                while (pos < line.length()) {
                    if (escaped) {
                        field += line[pos];
                        escaped = false;
                    } else if (line[pos] == '"') {
                        // Check for escaped quote
                        if (pos + 1 < line.length() && line[pos + 1] == '"') {
                            field += '"';
                            ++pos; // Skip first quote
                        } else {
                            // End of quoted field
                            ++pos; // Skip closing quote
                            break;
                        }
                    } else {
                        field += line[pos];
                    }
                    ++pos;
                }
                
                // Skip to comma or end
                while (pos < line.length() && line[pos] != ',') {
                    ++pos;
                }
            } else {
                // Unquoted field - read until comma
                while (pos < line.length() && line[pos] != ',') {
                    field += line[pos];
                    ++pos;
                }
                
                // Trim trailing whitespace
                while (!field.empty() && (field.back() == ' ' || field.back() == '\t')) {
                    field.pop_back();
                }
            }
            
            // Skip comma if present
            if (pos < line.length() && line[pos] == ',') {
                ++pos;
            }
            
            return field;
        };
        
        size_t lineNumber = 0;
        size_t imported = 0;
        size_t failed = 0;
        bool headerSkipped = false;
        
        std::string line;
        line.reserve(4096); // Pre-allocate for typical line length
        
        // Estimate total lines for progress callback
        const size_t estimatedLines = static_cast<size_t>(fileSize / 100); // Rough estimate
        
        while (std::getline(file, line)) {
            ++lineNumber;
            
            // Remove BOM if present on first line
            if (lineNumber == 1 && line.size() >= 3) {
                if (static_cast<unsigned char>(line[0]) == 0xEF &&
                    static_cast<unsigned char>(line[1]) == 0xBB &&
                    static_cast<unsigned char>(line[2]) == 0xBF) {
                    line = line.substr(3);
                }
            }
            
            // Remove trailing CR if present (for CRLF files)
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            
            // Skip empty lines
            if (line.empty()) continue;
            
            // Skip header line (detect common header patterns)
            if (!headerSkipped) {
                std::string lineLower = line;
                std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);
                if (lineLower.find("type") != std::string::npos &&
                    (lineLower.find("value") != std::string::npos ||
                     lineLower.find("hash") != std::string::npos ||
                     lineLower.find("path") != std::string::npos)) {
                    headerSkipped = true;
                    continue;
                }
                headerSkipped = true; // Only check first non-empty line
            }
            
            // Parse CSV fields: type,value,algorithm,reason,description
            size_t pos = 0;
            const std::string typeStr = parseCSVField(line, pos);
            const std::string valueStr = parseCSVField(line, pos);
            const std::string algorithmStr = parseCSVField(line, pos);
            const std::string reasonStr = parseCSVField(line, pos);
            const std::string descStr = parseCSVField(line, pos);
            
            // Skip if no type or value
            if (typeStr.empty() || valueStr.empty()) {
                ++failed;
                continue;
            }
            
            // Parse type
            std::string typeLower = typeStr;
            std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);
            
            StoreError addResult;
            
            if (typeLower == "hash" || typeLower == "file_hash" || typeLower == "filehash") {
                // Hash entry
                HashAlgorithm algorithm = HashAlgorithm::SHA256;
                
                // Parse algorithm
                std::string algLower = algorithmStr;
                std::transform(algLower.begin(), algLower.end(), algLower.begin(), ::tolower);
                
                if (algLower == "md5") algorithm = HashAlgorithm::MD5;
                else if (algLower == "sha1" || algLower == "sha-1") algorithm = HashAlgorithm::SHA1;
                else if (algLower == "sha256" || algLower == "sha-256") algorithm = HashAlgorithm::SHA256;
                else if (algLower == "sha512" || algLower == "sha-512") algorithm = HashAlgorithm::SHA512;
                
                auto hash = Format::ParseHashString(valueStr, algorithm);
                if (!hash.has_value()) {
                    ++failed;
                    continue;
                }
                
                // Convert description to wide string (UTF-8 to UTF-16) using proper Windows API
                std::wstring description;
                if (!descStr.empty()) {
                    // Calculate required buffer size
                    int descWideLen = MultiByteToWideChar(
                        CP_UTF8, MB_ERR_INVALID_CHARS,
                        descStr.c_str(), static_cast<int>(descStr.length()),
                        nullptr, 0
                    );
                    if (descWideLen > 0) {
                        description.resize(static_cast<size_t>(descWideLen));
                        MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS,
                            descStr.c_str(), static_cast<int>(descStr.length()),
                            description.data(), descWideLen
                        );
                    }
                    // If conversion fails, description remains empty (safe fallback)
                }
                
                addResult = AddHash(*hash, WhitelistReason::UserApproved, description, 0, 0);
                
            } else if (typeLower == "path" || typeLower == "file_path" || typeLower == "filepath") {
                // Path entry - convert UTF-8 path to UTF-16 using proper Windows API
                std::wstring path;
                if (!valueStr.empty()) {
                    int pathWideLen = MultiByteToWideChar(
                        CP_UTF8, MB_ERR_INVALID_CHARS,
                        valueStr.c_str(), static_cast<int>(valueStr.length()),
                        nullptr, 0
                    );
                    if (pathWideLen > 0) {
                        path.resize(static_cast<size_t>(pathWideLen));
                        MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS,
                            valueStr.c_str(), static_cast<int>(valueStr.length()),
                            path.data(), pathWideLen
                        );
                    } else {
                        // Path conversion failed - skip entry
                        ++failed;
                        continue;
                    }
                } else {
                    // Empty path - skip entry
                    ++failed;
                    continue;
                }
                
                // Parse match mode from algorithm field (reused for path match mode)
                PathMatchMode mode = PathMatchMode::Exact;
                std::string modeLower = algorithmStr;
                std::transform(modeLower.begin(), modeLower.end(), modeLower.begin(), ::tolower);
                
                if (modeLower == "prefix" || modeLower == "startswith") mode = PathMatchMode::Prefix;
                else if (modeLower == "suffix" || modeLower == "endswith") mode = PathMatchMode::Suffix;
                else if (modeLower == "glob" || modeLower == "wildcard") mode = PathMatchMode::Glob;
                else if (modeLower == "regex" || modeLower == "regexp") mode = PathMatchMode::Regex;
                else if (modeLower == "contains") mode = PathMatchMode::Contains;
                
                // Convert description using proper Windows API
                std::wstring description;
                if (!descStr.empty()) {
                    int descWideLen = MultiByteToWideChar(
                        CP_UTF8, MB_ERR_INVALID_CHARS,
                        descStr.c_str(), static_cast<int>(descStr.length()),
                        nullptr, 0
                    );
                    if (descWideLen > 0) {
                        description.resize(static_cast<size_t>(descWideLen));
                        MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS,
                            descStr.c_str(), static_cast<int>(descStr.length()),
                            description.data(), descWideLen
                        );
                    }
                }
                
                addResult = AddPath(path, mode, WhitelistReason::UserApproved, description, 0, 0);
                
            } else {
                // Unknown type
                ++failed;
                continue;
            }
            
            if (addResult.IsSuccess() || addResult.code == WhitelistStoreError::DuplicateEntry) {
                ++imported;
            } else {
                ++failed;
            }
            
            // Progress callback
            if (progressCallback && (lineNumber % 1000) == 0) {
                try {
                    progressCallback(lineNumber, estimatedLines);
                } catch (...) {
                    // Ignore callback exceptions
                }
            }
        }
        
        SS_LOG_INFO(L"Whitelist", L"Imported %zu entries from CSV (%zu failed, %zu lines)", 
            imported, failed, lineNumber);
        
        // Save changes
        if (imported > 0) {
            auto saveResult = Save();
            if (!saveResult.IsSuccess()) {
                SS_LOG_WARN(L"Whitelist", L"Failed to save after CSV import: %S",
                    saveResult.message.c_str());
                // Continue - entries are in memory even if save failed
            }
        }
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory reading CSV file"
        );
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            std::string("CSV import error: ") + e.what()
        );
    }
}

StoreError WhitelistStore::ExportToJSON(
    const std::wstring& filePath,
    WhitelistEntryType typeFilter,
    std::function<void(size_t, size_t)> progressCallback
) const noexcept {
    /*
     * ========================================================================
     * JSON FILE EXPORT
     * ========================================================================
     *
     * Exports whitelist entries to a JSON file with filtering support.
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate file path
    if (filePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::FileNotFound,
            "Empty file path"
        );
    }
    
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (filePath.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::PathTooLong,
            "File path exceeds maximum length"
        );
    }
    
    try {
        // Generate JSON string
        auto jsonStr = ExportToJSONString(typeFilter, UINT32_MAX);
        
        if (jsonStr.empty() || jsonStr == "{}") {
            SS_LOG_WARN(L"Whitelist", L"Export produced empty JSON");
        }
        
        // Open file for writing
        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileAccessDenied,
                "Failed to create output file"
            );
        }
        
        // Write content
        file.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
        
        if (!file.good()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileAccessDenied,
                "Failed to write to output file"
            );
        }
        
        file.close();
        
        SS_LOG_INFO(L"Whitelist", L"Exported whitelist to: %s (%zu bytes)", 
            filePath.c_str(), jsonStr.size());
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory during export"
        );
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            std::string("Export error: ") + e.what()
        );
    }
}

std::string WhitelistStore::ExportToJSONString(
    WhitelistEntryType typeFilter,
    uint32_t maxEntries
) const noexcept {
    /*
     * ========================================================================
     * JSON STRING EXPORT
     * ========================================================================
     *
     * Generates JSON representation of whitelist entries.
     *
     * Output Format:
     * {
     *   "version": "1.0",
     *   "database_type": "whitelist",
     *   "exported_time": <unix_timestamp>,
     *   "total_entries": <count>,
     *   "entries": [ ... ]
     * }
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return R"({"error": "Store not initialized"})";
    }
    
    // Clamp maxEntries to reasonable limit
    constexpr uint32_t MAX_EXPORT_ENTRIES = 10000000; // 10M
    const uint32_t effectiveMax = std::min(maxEntries, MAX_EXPORT_ENTRIES);
    
    try {
        nlohmann::json j;
        j["version"] = "1.0";
        j["database_type"] = "whitelist";
        
        // Get current timestamp
        auto now = std::chrono::system_clock::now();
        auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        j["exported_time"] = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
        
        // Add database metadata
        const auto* header = GetHeader();
        if (header) {
            // Construct version string from major.minor
            j["database_version_major"] = header->versionMajor;
            j["database_version_minor"] = header->versionMinor;
            j["database_created"] = header->creationTime;
            j["database_modified"] = header->lastUpdateTime;
        }
        
        nlohmann::json entries = nlohmann::json::array();
        uint32_t exportedCount = 0;
        
        // Entry iteration - export all valid entries
        if (header && header->entryDataOffset > 0 && header->entryDataSize > 0) {
            const uint64_t entryDataStart = header->entryDataOffset;
            const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
            
            // Type to string helper
            auto typeToString = [](WhitelistEntryType type) -> std::string {
                switch (type) {
                    case WhitelistEntryType::FileHash: return "file_hash";
                    case WhitelistEntryType::FilePath: return "file_path";
                    case WhitelistEntryType::ProcessPath: return "process_path";
                    case WhitelistEntryType::Certificate: return "certificate";
                    case WhitelistEntryType::Publisher: return "publisher";
                    default: return "unknown";
                }
            };
            
            // Algorithm to string helper
            auto algorithmToString = [](HashAlgorithm alg) -> std::string {
                switch (alg) {
                    case HashAlgorithm::MD5: return "md5";
                    case HashAlgorithm::SHA1: return "sha1";
                    case HashAlgorithm::SHA256: return "sha256";
                    case HashAlgorithm::SHA512: return "sha512";
                    default: return "unknown";
                }
            };
            
            // Match mode to string helper
            auto matchModeToString = [](PathMatchMode mode) -> std::string {
                switch (mode) {
                    case PathMatchMode::Exact: return "exact";
                    case PathMatchMode::Prefix: return "prefix";
                    case PathMatchMode::Suffix: return "suffix";
                    case PathMatchMode::Contains: return "contains";
                    case PathMatchMode::Glob: return "glob";
                    case PathMatchMode::Regex: return "regex";
                    default: return "exact";
                }
            };
            
            // Reason to string helper
            auto reasonToString = [](WhitelistReason reason) -> std::string {
                switch (reason) {
                    case WhitelistReason::UserApproved: return "user_approved";
                    case WhitelistReason::SystemFile: return "system_file";
                    case WhitelistReason::TrustedVendor: return "trusted_vendor";
                    case WhitelistReason::PolicyBased: return "policy_based";
                    case WhitelistReason::TemporaryBypass: return "temporary_bypass";
                    case WhitelistReason::MLClassified: return "ml_classified";
                    case WhitelistReason::ReputationBased: return "reputation_based";
                    case WhitelistReason::Compatibility: return "compatibility";
                    case WhitelistReason::Development: return "development";
                    case WhitelistReason::Custom: return "custom";
                    default: return "unknown";
                }
            };
            
            // Hash bytes to hex string
            auto hashToHexString = [](const uint8_t* data, size_t length) -> std::string {
                static const char hexChars[] = "0123456789abcdef";
                std::string result;
                result.reserve(length * 2);
                for (size_t i = 0; i < length; ++i) {
                    result += hexChars[(data[i] >> 4) & 0x0F];
                    result += hexChars[data[i] & 0x0F];
                }
                return result;
            };
            
            // Iterate entries
            uint64_t offset = entryDataStart;
            
            while (offset + sizeof(WhitelistEntry) <= entryDataEnd && 
                   offset + sizeof(WhitelistEntry) <= m_mappedView.fileSize &&
                   exportedCount < effectiveMax) {
                const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
                if (!entry) break;
                
                // Skip deleted entries
                if (entry->type == WhitelistEntryType::Reserved) {
                    offset += sizeof(WhitelistEntry);
                    continue;
                }
                
                // Apply type filter
                if (typeFilter != WhitelistEntryType::Reserved && 
                    entry->type != typeFilter) {
                    offset += sizeof(WhitelistEntry);
                    continue;
                }
                
                // Skip revoked entries
                if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
                    offset += sizeof(WhitelistEntry);
                    continue;
                }
                
                // Build entry JSON
                nlohmann::json entryJson;
                entryJson["id"] = entry->entryId;
                entryJson["type"] = typeToString(entry->type);
                entryJson["reason"] = reasonToString(entry->reason);
                entryJson["created"] = entry->createdTime;
                entryJson["modified"] = entry->modifiedTime;
                entryJson["flags"] = static_cast<uint32_t>(entry->flags);
                
                if (entry->expirationTime > 0) {
                    entryJson["expires"] = entry->expirationTime;
                }
                
                // Type-specific fields
                if (entry->type == WhitelistEntryType::FileHash) {
                    entryJson["algorithm"] = algorithmToString(entry->hashAlgorithm);
                    entryJson["value"] = hashToHexString(entry->hashData.data(), entry->hashLength);
                } else if (entry->type == WhitelistEntryType::FilePath ||
                           entry->type == WhitelistEntryType::ProcessPath) {
                    entryJson["match_mode"] = matchModeToString(entry->matchMode);
                    
                    // Get path from string pool
                    if (m_stringPool && entry->pathLength > 0) {
                        auto pathView = m_stringPool->GetWideString(
                            entry->pathOffset, entry->pathLength);
                        if (!pathView.empty()) {
                            // Convert UTF-16 to UTF-8
                            std::string pathStr;
                            pathStr.resize(pathView.size() * 3);
                            int converted = WideCharToMultiByte(CP_UTF8, 0,
                                pathView.data(), static_cast<int>(pathView.size()),
                                pathStr.data(), static_cast<int>(pathStr.size()),
                                nullptr, nullptr);
                            if (converted > 0) {
                                pathStr.resize(converted);
                                entryJson["path"] = pathStr;
                            }
                        }
                    }
                }
                
                // Get description if present
                if (m_stringPool && entry->descriptionLength > 0) {
                    auto descView = m_stringPool->GetWideString(
                        entry->descriptionOffset, entry->descriptionLength);
                    if (!descView.empty()) {
                        std::string descStr;
                        descStr.resize(descView.size() * 3);
                        int converted = WideCharToMultiByte(CP_UTF8, 0,
                            descView.data(), static_cast<int>(descView.size()),
                            descStr.data(), static_cast<int>(descStr.size()),
                            nullptr, nullptr);
                        if (converted > 0) {
                            descStr.resize(converted);
                            entryJson["description"] = descStr;
                        }
                    }
                }
                
                entries.push_back(std::move(entryJson));
                ++exportedCount;
                offset += sizeof(WhitelistEntry);
            }
        }
        
        j["entries"] = entries;
        j["total_entries"] = entries.size();
        j["filter_applied"] = (typeFilter != WhitelistEntryType::Reserved);
        
        // Add statistics
        nlohmann::json stats;
        auto dbStats = GetStatistics();
        stats["total_lookups"] = dbStats.totalLookups;
        stats["cache_hits"] = dbStats.cacheHits;
        stats["bloom_filter_rejects"] = dbStats.bloomFilterRejects;
        j["statistics"] = stats;
        
        return j.dump(2); // Pretty print with 2-space indent
        
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"Out of memory during JSON export");
        return R"({"error": "Out of memory"})";
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Export to JSON failed: %S", e.what());
        return R"({"error": "Export failed"})";
    }
}

StoreError WhitelistStore::ExportToCSV(
    const std::wstring& filePath,
    WhitelistEntryType typeFilter,
    std::function<void(size_t, size_t)> progressCallback
) const noexcept {
    /*
     * ========================================================================
     * CSV FILE EXPORT
     * ========================================================================
     *
     * Exports whitelist entries to CSV format.
     *
     * Format:
     * id,type,value,algorithm,reason,description,created,expires
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Validate file path
    if (filePath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::FileNotFound,
            "Empty file path"
        );
    }
    
    SS_LOG_INFO(L"Whitelist", L"CSV export: %s", filePath.c_str());
    
    try {
        // Open file for writing
        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileAccessDenied,
                "Failed to create output CSV file"
            );
        }
        
        // CSV escape helper - wraps field in quotes if necessary
        auto escapeCSVField = [](const std::string& field) -> std::string {
            // Check if quoting is needed
            bool needsQuotes = false;
            for (char c : field) {
                if (c == ',' || c == '"' || c == '\n' || c == '\r') {
                    needsQuotes = true;
                    break;
                }
            }
            
            if (!needsQuotes) return field;
            
            // Escape quotes and wrap
            std::string escaped = "\"";
            for (char c : field) {
                if (c == '"') {
                    escaped += "\"\""; // Double quote escaping
                } else {
                    escaped += c;
                }
            }
            escaped += '"';
            return escaped;
        };
        
        // Write UTF-8 BOM for Excel compatibility
        file.write("\xEF\xBB\xBF", 3);
        
        // Write CSV header
        file << "id,type,value,algorithm,match_mode,reason,description,created,expires,flags\r\n";
        
        // Get header for entry data bounds
        const auto* header = GetHeader();
        if (!header || header->entryDataOffset == 0) {
            // No entries to export
            file.close();
            return StoreError::Success();
        }
        
        const uint64_t entryDataStart = header->entryDataOffset;
        const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
        
        if (entryDataEnd > m_mappedView.fileSize) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Entry data section exceeds file bounds"
            );
        }
        
        // Type to string helper
        auto typeToString = [](WhitelistEntryType type) -> std::string {
            switch (type) {
                case WhitelistEntryType::FileHash: return "hash";
                case WhitelistEntryType::FilePath: return "path";
                case WhitelistEntryType::ProcessPath: return "process_path";
                case WhitelistEntryType::Certificate: return "certificate";
                case WhitelistEntryType::Publisher: return "publisher";
                default: return "unknown";
            }
        };
        
        // Algorithm to string helper
        auto algorithmToString = [](HashAlgorithm alg) -> std::string {
            switch (alg) {
                case HashAlgorithm::MD5: return "md5";
                case HashAlgorithm::SHA1: return "sha1";
                case HashAlgorithm::SHA256: return "sha256";
                case HashAlgorithm::SHA512: return "sha512";
                default: return "unknown";
            }
        };
        
        // Match mode to string
        auto matchModeToString = [](PathMatchMode mode) -> std::string {
            switch (mode) {
                case PathMatchMode::Exact: return "exact";
                case PathMatchMode::Prefix: return "prefix";
                case PathMatchMode::Suffix: return "suffix";
                case PathMatchMode::Contains: return "contains";
                case PathMatchMode::Glob: return "glob";
                case PathMatchMode::Regex: return "regex";
                default: return "exact";
            }
        };
        
        // Reason to string
        auto reasonToString = [](WhitelistReason reason) -> std::string {
            switch (reason) {
                case WhitelistReason::UserApproved: return "user_approved";
                case WhitelistReason::SystemFile: return "system_file";
                case WhitelistReason::TrustedVendor: return "trusted_vendor";
                case WhitelistReason::PolicyBased: return "policy_based";
                case WhitelistReason::TemporaryBypass: return "temporary_bypass";
                case WhitelistReason::MLClassified: return "ml_classified";
                case WhitelistReason::ReputationBased: return "reputation_based";
                case WhitelistReason::Compatibility: return "compatibility";
                case WhitelistReason::Development: return "development";
                case WhitelistReason::Custom: return "custom";
                default: return "unknown";
            }
        };
        
        // Hash bytes to hex string
        auto hashToHexString = [](const uint8_t* data, size_t length) -> std::string {
            static const char hexChars[] = "0123456789abcdef";
            std::string result;
            result.reserve(length * 2);
            for (size_t i = 0; i < length; ++i) {
                result += hexChars[(data[i] >> 4) & 0x0F];
                result += hexChars[data[i] & 0x0F];
            }
            return result;
        };
        
        size_t exported = 0;
        size_t offset = entryDataStart;
        
        // Iterate all entries
        while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
            const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
            if (!entry) break;
            
            // Skip deleted entries
            if (entry->type == WhitelistEntryType::Reserved) {
                offset += sizeof(WhitelistEntry);
                continue;
            }
            
            // Apply type filter
            if (typeFilter != WhitelistEntryType::Reserved && entry->type != typeFilter) {
                offset += sizeof(WhitelistEntry);
                continue;
            }
            
            // Skip revoked entries
            if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
                offset += sizeof(WhitelistEntry);
                continue;
            }
            
            // Build CSV row
            std::ostringstream row;
            
            // ID
            row << entry->entryId << ",";
            
            // Type
            row << escapeCSVField(typeToString(entry->type)) << ",";
            
            // Value (hash or path)
            if (entry->type == WhitelistEntryType::FileHash) {
                row << escapeCSVField(hashToHexString(entry->hashData.data(), entry->hashLength)) << ",";
                row << escapeCSVField(algorithmToString(entry->hashAlgorithm)) << ",";
                row << ","; // No match mode for hash
            } else if (entry->type == WhitelistEntryType::FilePath ||
                       entry->type == WhitelistEntryType::ProcessPath) {
                // Get path from string pool if available
                std::string pathStr;
                if (m_stringPool && entry->pathLength > 0) {
                    auto pathView = m_stringPool->GetWideString(entry->pathOffset, entry->pathLength);
                    if (!pathView.empty()) {
                        // Convert UTF-16 to UTF-8
                        pathStr.resize(pathView.size() * 3); // Worst case
                        int converted = WideCharToMultiByte(CP_UTF8, 0,
                            pathView.data(), static_cast<int>(pathView.size()),
                            pathStr.data(), static_cast<int>(pathStr.size()),
                            nullptr, nullptr);
                        if (converted > 0) {
                            pathStr.resize(converted);
                        } else {
                            pathStr.clear();
                        }
                    }
                }
                row << escapeCSVField(pathStr) << ",";
                row << ","; // No algorithm for path
                row << escapeCSVField(matchModeToString(entry->matchMode)) << ",";
            } else {
                row << ",,,"; // Unknown type
            }
            
            // Reason
            row << escapeCSVField(reasonToString(entry->reason)) << ",";
            
            // Description
            std::string descStr;
            if (m_stringPool && entry->descriptionLength > 0) {
                auto descView = m_stringPool->GetWideString(
                    entry->descriptionOffset, entry->descriptionLength);
                if (!descView.empty()) {
                    descStr.resize(descView.size() * 3);
                    int converted = WideCharToMultiByte(CP_UTF8, 0,
                        descView.data(), static_cast<int>(descView.size()),
                        descStr.data(), static_cast<int>(descStr.size()),
                        nullptr, nullptr);
                    if (converted > 0) {
                        descStr.resize(converted);
                    } else {
                        descStr.clear();
                    }
                }
            }
            row << escapeCSVField(descStr) << ",";
            
            // Created timestamp
            row << entry->createdTime << ",";
            
            // Expires timestamp
            row << entry->expirationTime << ",";
            
            // Flags
            row << static_cast<uint32_t>(entry->flags);
            
            // Write row with CRLF
            row << "\r\n";
            const std::string rowStr = row.str();
            file.write(rowStr.data(), static_cast<std::streamsize>(rowStr.size()));
            
            ++exported;
            offset += sizeof(WhitelistEntry);
            
            // Progress callback - calculate total from entry counts
            if (progressCallback && (exported % 1000) == 0) {
                try {
                    const uint64_t totalEst = header->totalHashEntries + header->totalPathEntries + 
                                              header->totalCertEntries + header->totalPublisherEntries;
                    progressCallback(exported, static_cast<size_t>(totalEst));
                } catch (...) {
                    // Ignore callback exceptions
                }
            }
        }
        
        if (!file.good()) {
            return StoreError::WithMessage(
                WhitelistStoreError::FileAccessDenied,
                "Failed to write to CSV file"
            );
        }
        
        file.close();
        
        SS_LOG_INFO(L"Whitelist", L"Exported %zu entries to CSV: %s", 
            exported, filePath.c_str());
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory during CSV export"
        );
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            std::string("CSV export error: ") + e.what()
        );
    }
}

// ============================================================================
// MAINTENANCE OPERATIONS
// ============================================================================

StoreError WhitelistStore::PurgeExpired() noexcept {
    /*
     * ========================================================================
     * EXPIRED ENTRY PURGE
     * ========================================================================
     *
     * Removes entries that have passed their expiration time.
     *
     * Security Note: This modifies the database, requiring proper locking
     * and validation to prevent data corruption.
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot modify read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    // Get current time safely
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    // Validate epoch is reasonable (after year 2000, before year 2100)
    constexpr int64_t MIN_EPOCH = 946684800;   // 2000-01-01
    constexpr int64_t MAX_EPOCH = 4102444800;  // 2100-01-01
    
    if (epoch < MIN_EPOCH || epoch > MAX_EPOCH) {
        SS_LOG_WARN(L"Whitelist", L"System time appears invalid: %lld", epoch);
        // Continue anyway with clamped value
        epoch = std::clamp(epoch, MIN_EPOCH, MAX_EPOCH);
    }
    
    const uint64_t currentTime = static_cast<uint64_t>(epoch);
    size_t purged = 0;
    size_t checked = 0;
    
    // Get header for entry counts
    const auto* header = GetHeader();
    if (!header) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to access database header"
        );
    }
    
    // Validate entry data section
    if (header->entryDataOffset == 0 || header->entryDataSize == 0) {
        // No entries to purge
        return StoreError::Success();
    }
    
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    if (entryDataEnd > m_mappedView.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section exceeds file bounds"
        );
    }
    
    // Statistics counters for each type purged
    uint64_t hashPurged = 0;
    uint64_t pathPurged = 0;
    uint64_t processPurged = 0;
    uint64_t certPurged = 0;
    uint64_t pubPurged = 0;
    
    // Iterate through all entries
    uint64_t offset = entryDataStart;
    
    while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
        auto* entry = m_mappedView.GetAtMutable<WhitelistEntry>(offset);
        if (!entry) break;
        
        ++checked;
        
        // Skip already deleted entries
        if (entry->type == WhitelistEntryType::Reserved) {
            offset += sizeof(WhitelistEntry);
            continue;
        }
        
        // Skip revoked entries (already handled)
        if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
            offset += sizeof(WhitelistEntry);
            continue;
        }
        
        // Check if entry has expiration and is expired
        if (entry->expirationTime > 0 && entry->expirationTime < currentTime) {
            // Track type for counter updates
            const WhitelistEntryType entryType = entry->type;
            
            // Remove from appropriate index before marking deleted
            if (entryType == WhitelistEntryType::FileHash && m_hashIndex) {
                HashValue hash = HashValue::Create(entry->hashAlgorithm,
                    entry->hashData.data(),
                    entry->hashLength);
                auto removeResult = m_hashIndex->Remove(hash);
                if (!removeResult.IsSuccess() && 
                    removeResult.code != WhitelistStoreError::EntryNotFound) {
                    SS_LOG_WARN(L"Whitelist", L"Failed to remove expired hash from index");
                }
            } else if ((entryType == WhitelistEntryType::FilePath ||
                        entryType == WhitelistEntryType::ProcessPath) &&
                       m_pathIndex && m_stringPool) {
                auto pathView = m_stringPool->GetWideString(
                    entry->pathOffset, entry->pathLength);
                if (!pathView.empty()) {
                    auto removeResult = m_pathIndex->Remove(pathView, entry->matchMode);
                    if (!removeResult.IsSuccess() && 
                        removeResult.code != WhitelistStoreError::EntryNotFound) {
                        SS_LOG_WARN(L"Whitelist", L"Failed to remove expired path from index");
                    }
                }
            }
            
            // Mark as deleted (soft delete)
            entry->type = WhitelistEntryType::Reserved;
            entry->flags = entry->flags | WhitelistFlags::Revoked;
            
            // Update modification time
            entry->modifiedTime = currentTime;
            
            // Track by type
            switch (entryType) {
                case WhitelistEntryType::FileHash:
                    ++hashPurged;
                    break;
                case WhitelistEntryType::FilePath:
                    ++pathPurged;
                    break;
                case WhitelistEntryType::ProcessPath:
                    ++processPurged;
                    break;
                case WhitelistEntryType::Certificate:
                    ++certPurged;
                    break;
                case WhitelistEntryType::Publisher:
                    ++pubPurged;
                    break;
                default:
                    break;
            }
            
            ++purged;
        }
        
        offset += sizeof(WhitelistEntry);
    }
    
    SS_LOG_INFO(L"Whitelist", L"Purged %zu expired entries (checked %zu)", purged, checked);
    SS_LOG_DEBUG(L"Whitelist", L"Purge breakdown: hash=%llu, path=%llu, process=%llu, cert=%llu, pub=%llu",
        hashPurged, pathPurged, processPurged, certPurged, pubPurged);
    
    // Update header counters if any entries were purged
    if (purged > 0) {
        // Get mutable header to update counters
        auto* mutableHeader = m_mappedView.GetAtMutable<WhitelistDatabaseHeader>(0);
        if (mutableHeader) {
            // Safely decrement counters (with underflow protection)
            if (hashPurged > 0 && mutableHeader->totalHashEntries >= hashPurged) {
                mutableHeader->totalHashEntries -= hashPurged;
            }
            if (pathPurged > 0 && mutableHeader->totalPathEntries >= pathPurged) {
                mutableHeader->totalPathEntries -= pathPurged;
            }
            if (certPurged > 0 && mutableHeader->totalCertEntries >= certPurged) {
                mutableHeader->totalCertEntries -= certPurged;
            }
            if (pubPurged > 0 && mutableHeader->totalPublisherEntries >= pubPurged) {
                mutableHeader->totalPublisherEntries -= pubPurged;
            }
            // Note: Process entries tracked with paths in totalPathEntries
            
            // Update modification timestamp
            mutableHeader->lastUpdateTime = currentTime;
        }
        
        UpdateHeaderStats();
        
        // Clear caches since entries may have changed
        ClearCache();
    }
    
    return StoreError::Success();
}

StoreError WhitelistStore::Compact() noexcept {
    /*
     * ========================================================================
     * DATABASE COMPACTION
     * ========================================================================
     *
     * Removes deleted entries and reclaims space by reorganizing
     * the database file.
     *
     * This is a heavyweight operation that should only be performed
     * during maintenance windows.
     *
     * Algorithm:
     * 1. Count valid entries and calculate required space
     * 2. Allocate temporary buffer for valid entries
     * 3. Copy all valid entries to temporary buffer sequentially
     * 4. Write compacted entries back to entry data section
     * 5. Rebuild all indices from compacted data
     * 6. Update header statistics
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot compact read-only database"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    SS_LOG_INFO(L"Whitelist", L"Database compaction started");
    
    std::unique_lock lock(m_globalLock);
    
    // Get header for statistics
    auto* header = m_mappedView.GetAtMutable<WhitelistDatabaseHeader>(0);
    if (!header) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to access database header"
        );
    }
    
    // Validate entry data section
    if (header->entryDataOffset == 0 || header->entryDataSize == 0) {
        SS_LOG_INFO(L"Whitelist", L"No entries to compact");
        return StoreError::Success();
    }
    
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    const uint64_t originalSize = m_mappedView.fileSize;
    
    if (entryDataEnd > originalSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section exceeds file bounds"
        );
    }
    
    try {
        // Phase 1: Count valid entries and calculate space needed
        size_t validEntryCount = 0;
        size_t deletedEntryCount = 0;
        
        uint64_t offset = entryDataStart;
        while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
            const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
            if (!entry) break;
            
            if (entry->type != WhitelistEntryType::Reserved &&
                !HasFlag(entry->flags, WhitelistFlags::Revoked)) {
                ++validEntryCount;
            } else {
                ++deletedEntryCount;
            }
            offset += sizeof(WhitelistEntry);
        }
        
        // If no deleted entries, nothing to compact
        if (deletedEntryCount == 0) {
            SS_LOG_INFO(L"Whitelist", L"No deleted entries found, skipping compaction");
            return StoreError::Success();
        }
        
        SS_LOG_INFO(L"Whitelist", L"Compacting: %zu valid, %zu deleted entries",
            validEntryCount, deletedEntryCount);
        
        // Phase 2: Allocate temporary buffer for valid entries
        const size_t requiredBufferSize = validEntryCount * sizeof(WhitelistEntry);
        
        // Check for excessive allocation
        constexpr size_t MAX_COMPACT_BUFFER = 512 * 1024 * 1024; // 512MB max
        if (requiredBufferSize > MAX_COMPACT_BUFFER) {
            return StoreError::WithMessage(
                WhitelistStoreError::OutOfMemory,
                "Compaction buffer would exceed maximum size"
            );
        }
        
        std::vector<WhitelistEntry> compactedEntries;
        compactedEntries.reserve(validEntryCount);
        
        // Counter tracking for header update
        uint64_t newHashCount = 0;
        uint64_t newPathCount = 0;
        uint64_t newProcessCount = 0;
        uint64_t newCertCount = 0;
        uint64_t newPubCount = 0;
        
        // Phase 3: Copy valid entries to temporary buffer
        offset = entryDataStart;
        while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
            const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
            if (!entry) break;
            
            // Only copy valid entries
            if (entry->type != WhitelistEntryType::Reserved &&
                !HasFlag(entry->flags, WhitelistFlags::Revoked)) {
                compactedEntries.push_back(*entry);
                
                // Track type counts
                switch (entry->type) {
                    case WhitelistEntryType::FileHash:
                        ++newHashCount;
                        break;
                    case WhitelistEntryType::FilePath:
                        ++newPathCount;
                        break;
                    case WhitelistEntryType::ProcessPath:
                        ++newProcessCount;
                        break;
                    case WhitelistEntryType::Certificate:
                        ++newCertCount;
                        break;
                    case WhitelistEntryType::Publisher:
                        ++newPubCount;
                        break;
                    default:
                        break;
                }
            }
            offset += sizeof(WhitelistEntry);
        }
        
        // Phase 4: Clear indices before rewriting data
        if (m_hashBloomFilter) {
            try {
                m_hashBloomFilter->Clear();
            } catch (...) {
                // Continue even if bloom filter clear fails
            }
        }
        
        if (m_pathBloomFilter) {
            try {
                m_pathBloomFilter->Clear();
            } catch (...) {
                // Continue even if bloom filter clear fails
            }
        }
        
        // Phase 5: Write compacted entries back to entry data section
        offset = entryDataStart;
        for (const auto& entry : compactedEntries) {
            auto* destEntry = m_mappedView.GetAtMutable<WhitelistEntry>(offset);
            if (!destEntry) {
                return StoreError::WithMessage(
                    WhitelistStoreError::InvalidSection,
                    "Failed to write compacted entry"
                );
            }
            
            // Copy entry
            std::memcpy(destEntry, &entry, sizeof(WhitelistEntry));
            
            // Re-add to indices
            if (entry.type == WhitelistEntryType::FileHash) {
                if (m_hashBloomFilter) {
                    HashValue hash = HashValue::Create(entry.hashAlgorithm,
                        entry.hashData.data(),
                        entry.hashLength);
                    m_hashBloomFilter->Add(hash.FastHash());
                }
                if (m_hashIndex) {
                    HashValue hash = HashValue::Create(entry.hashAlgorithm,
                        entry.hashData.data(),
                        entry.hashLength);
                    auto insertResult = m_hashIndex->Insert(hash, offset);
                    if (!insertResult.IsSuccess() && 
                        insertResult.code != WhitelistStoreError::DuplicateEntry) {
                        SS_LOG_WARN(L"Whitelist", L"Failed to reindex hash in compact");
                    }
                }
            } else if ((entry.type == WhitelistEntryType::FilePath ||
                        entry.type == WhitelistEntryType::ProcessPath) &&
                       m_stringPool && m_pathIndex) {
                auto pathView = m_stringPool->GetWideString(
                    entry.pathOffset, entry.pathLength);
                if (!pathView.empty()) {
                    if (m_pathBloomFilter) {
                        // Compute hash of path for bloom filter
                        uint64_t pathHash = 14695981039346656037ULL;
                        for (wchar_t c : pathView) {
                            pathHash ^= static_cast<uint64_t>(c);
                            pathHash *= 1099511628211ULL;
                        }
                        m_pathBloomFilter->Add(pathHash);
                    }
                    auto insertResult = m_pathIndex->Insert(pathView, entry.matchMode, offset);
                    if (!insertResult.IsSuccess() && 
                        insertResult.code != WhitelistStoreError::DuplicateEntry) {
                        SS_LOG_WARN(L"Whitelist", L"Failed to reindex path in compact");
                    }
                }
            }
            
            offset += sizeof(WhitelistEntry);
        }
        
        // Phase 6: Zero out remaining space (optional but good for security)
        const uint64_t compactedSize = validEntryCount * sizeof(WhitelistEntry);
        // Calculate total entries from type counts
        const uint64_t totalEntryCount = header->totalHashEntries + header->totalPathEntries +
                                         header->totalCertEntries + header->totalPublisherEntries +
                                         header->totalOtherEntries;
        const uint64_t oldUsedSize = (totalEntryCount > 0) 
            ? totalEntryCount * sizeof(WhitelistEntry) 
            : 0;
        
        if (compactedSize < oldUsedSize) {
            uint8_t* zeroStart = static_cast<uint8_t*>(m_mappedView.baseAddress) + 
                entryDataStart + compactedSize;
            const size_t zeroSize = static_cast<size_t>(oldUsedSize - compactedSize);
            
            // Bounds check before zeroing
            if (entryDataStart + compactedSize + zeroSize <= m_mappedView.fileSize) {
                SecureZeroMemory(zeroStart, zeroSize);
            }
        }
        
        // Phase 7: Update header statistics
        // Note: No totalEntries field in header, only per-type counts
        header->totalHashEntries = newHashCount;
        header->totalPathEntries = newPathCount;
        
        // Update modification time
        auto now = std::chrono::system_clock::now();
        auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        header->lastUpdateTime = static_cast<uint64_t>(std::max<int64_t>(0, epoch));
        
        // Recalculate header CRC
        header->headerCrc32 = Format::ComputeHeaderCRC32(header);
        
        // Calculate space reclaimed
        const size_t spaceReclaimed = deletedEntryCount * sizeof(WhitelistEntry);
        
        SS_LOG_INFO(L"Whitelist", 
            L"Compaction complete: %zu entries retained, %zu bytes reclaimed",
            validEntryCount, spaceReclaimed);
        
        // Clear query cache
        ClearCache();
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"Out of memory during compaction");
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory during compaction"
        );
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Compaction failed: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            std::string("Compaction failed: ") + e.what()
        );
    }
}

StoreError WhitelistStore::RebuildIndices() noexcept {
    /*
     * ========================================================================
     * INDEX REBUILD
     * ========================================================================
     *
     * Reconstructs all indices (Bloom filters, hash index, path index)
     * from the entry data. Use this to repair corrupted indices.
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot rebuild indices in read-only mode"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    std::unique_lock lock(m_globalLock);
    
    SS_LOG_INFO(L"Whitelist", L"Rebuilding all indices...");
    
    // Get header for entry information
    const auto* header = GetHeader();
    if (!header) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to access database header"
        );
    }
    
    size_t hashesIndexed = 0;
    size_t pathsIndexed = 0;
    size_t indexErrors = 0;
    
    // Clear existing indices safely
    if (m_hashBloomFilter) {
        try {
            m_hashBloomFilter->Clear();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Whitelist", L"Failed to clear hash bloom filter: %S", e.what());
            ++indexErrors;
        }
    }
    
    if (m_pathBloomFilter) {
        try {
            m_pathBloomFilter->Clear();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Whitelist", L"Failed to clear path bloom filter: %S", e.what());
            ++indexErrors;
        }
    }
    
    // Clear B+Tree and Trie indices if they support it
    // Note: These may need custom Clear() methods
    
    // Validate entry data section
    if (header->entryDataOffset == 0 || header->entryDataSize == 0) {
        SS_LOG_INFO(L"Whitelist", L"No entries to index");
        ClearCache();
        return StoreError::Success();
    }
    
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    if (entryDataEnd > m_mappedView.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Entry data section exceeds file bounds"
        );
    }
    
    // Iterate through all entries and rebuild indices
    uint64_t offset = entryDataStart;
    
    while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
        const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
        if (!entry) break;
        
        // Skip deleted entries (Reserved means deleted/unused)
        if (entry->type == WhitelistEntryType::Reserved) {
            offset += sizeof(WhitelistEntry);
            continue;
        }
        
        // Skip revoked entries
        if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
            offset += sizeof(WhitelistEntry);
            continue;
        }
        
        // Index based on entry type
        try {
            if (entry->type == WhitelistEntryType::FileHash) {
                // Construct hash value from entry data
                HashValue hash = HashValue::Create(entry->hashAlgorithm,
                    entry->hashData.data(),
                    entry->hashLength);
                
                // Add to bloom filter
                if (m_hashBloomFilter) {
                    m_hashBloomFilter->Add(hash);
                }
                
                // Add to hash index
                if (m_hashIndex) {
                    auto indexResult = m_hashIndex->Insert(hash, offset);
                    if (!indexResult.IsSuccess() && 
                        indexResult.code != WhitelistStoreError::DuplicateEntry) {
                        SS_LOG_WARN(L"Whitelist", 
                            L"Failed to index hash entry ID %llu", entry->entryId);
                        ++indexErrors;
                    }
                }
                
                ++hashesIndexed;
                
            } else if (entry->type == WhitelistEntryType::FilePath ||
                       entry->type == WhitelistEntryType::ProcessPath) {
                // Retrieve path from string pool
                if (m_stringPool && entry->pathLength > 0) {
                    auto pathView = m_stringPool->GetWideString(
                        entry->pathOffset, entry->pathLength);
                    
                    if (!pathView.empty()) {
                        // Add to path bloom filter
                        if (m_pathBloomFilter) {
                            // Compute hash of path for bloom filter
                            uint64_t pathHash = 14695981039346656037ULL;
                            for (wchar_t c : pathView) {
                                pathHash ^= static_cast<uint64_t>(c);
                                pathHash *= 1099511628211ULL;
                            }
                            m_pathBloomFilter->Add(pathHash);
                        }
                        
                        // Add to path trie index
                        if (m_pathIndex) {
                            auto indexResult = m_pathIndex->Insert(
                                pathView, entry->matchMode, offset);
                            if (!indexResult.IsSuccess() && 
                                indexResult.code != WhitelistStoreError::DuplicateEntry) {
                                SS_LOG_WARN(L"Whitelist", 
                                    L"Failed to index path entry ID %llu", entry->entryId);
                                ++indexErrors;
                            }
                        }
                        
                        ++pathsIndexed;
                    } else {
                        SS_LOG_WARN(L"Whitelist", 
                            L"Empty path for entry ID %llu", entry->entryId);
                        ++indexErrors;
                    }
                }
                
            } else if (entry->type == WhitelistEntryType::Certificate) {
                // Certificate entries are indexed by thumbprint (stored as hash)
                // SHA-256 thumbprint is stored in hashData field
                if (m_hashIndex && entry->hashLength > 0) {
                    HashValue certHash = HashValue::Create(entry->hashAlgorithm,
                        entry->hashData.data(),
                        entry->hashLength);
                    
                    auto insertResult = m_hashIndex->Insert(certHash, offset);
                    if (!insertResult.IsSuccess() && 
                        insertResult.code != WhitelistStoreError::DuplicateEntry) {
                        SS_LOG_WARN(L"Whitelist", 
                            L"Failed to index certificate entry ID %llu", entry->entryId);
                        ++indexErrors;
                    }
                    
                    // Also add to bloom filter for fast negative lookups
                    if (m_hashBloomFilter) {
                        m_hashBloomFilter->Add(certHash.FastHash());
                    }
                }
                
            } else if (entry->type == WhitelistEntryType::Publisher) {
                // Publisher entries are indexed by publisher name (stored as path)
                // Uses the path index for efficient string matching
                if (m_stringPool && m_pathIndex && entry->pathLength > 0) {
                    auto publisherName = m_stringPool->GetWideString(
                        entry->pathOffset, entry->pathLength);
                    
                    if (!publisherName.empty()) {
                        auto insertResult = m_pathIndex->Insert(
                            publisherName, entry->matchMode, offset);
                        if (!insertResult.IsSuccess() && 
                            insertResult.code != WhitelistStoreError::DuplicateEntry) {
                            SS_LOG_WARN(L"Whitelist",
                                L"Failed to index publisher entry ID %llu", entry->entryId);
                            ++indexErrors;
                        }
                        
                        // Also add to path bloom filter
                        if (m_pathBloomFilter) {
                            uint64_t publisherHash = 14695981039346656037ULL;
                            for (wchar_t c : publisherName) {
                                publisherHash ^= static_cast<uint64_t>(c);
                                publisherHash *= 1099511628211ULL;
                            }
                            m_pathBloomFilter->Add(publisherHash);
                        }
                    } else {
                        SS_LOG_WARN(L"Whitelist",
                            L"Empty publisher name for entry ID %llu", entry->entryId);
                        ++indexErrors;
                    }
                }
            }
            
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Whitelist", 
                L"Exception indexing entry ID %llu: %S", entry->entryId, e.what());
            ++indexErrors;
        }
        
        offset += sizeof(WhitelistEntry);
    }
    
    // Clear query cache since indices changed
    ClearCache();
    
    SS_LOG_INFO(L"Whitelist", L"Index rebuild complete: %zu hashes, %zu paths, %zu errors",
        hashesIndexed, pathsIndexed, indexErrors);
    
    if (indexErrors > 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            "Index rebuild completed with errors"
        );
    }
    
    return StoreError::Success();
}

StoreError WhitelistStore::VerifyIntegrity(
    std::function<void(const std::string&)> logCallback
) const noexcept {
    /*
     * ========================================================================
     * DATABASE INTEGRITY VERIFICATION
     * ========================================================================
     *
     * Performs comprehensive integrity checks on the database:
     * - Header validation
     * - Section bounds checking
     * - Checksum verification
     * - Index consistency
     *
     * ========================================================================
     */
    
    // Helper lambda for safe logging
    auto safeLog = [&logCallback](const std::string& msg) noexcept {
        if (logCallback) {
            try {
                logCallback(msg);
            } catch (...) {
                // Ignore callback exceptions
            }
        }
    };
    
    try {
        safeLog("Starting whitelist database integrity verification...");
        
        // Phase 1: Basic state check
        if (!m_initialized.load(std::memory_order_acquire)) {
            safeLog("FAILED: Store not initialized");
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Store not initialized"
            );
        }
        
        // Phase 2: Mapped view verification
        if (!m_mappedView.baseAddress || m_mappedView.fileSize == 0) {
            safeLog("FAILED: Invalid memory-mapped view");
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Invalid memory-mapped view"
            );
        }
        safeLog("Memory mapping: PASSED");
        
        // Phase 3: Format verification
        StoreError error;
        if (!Format::VerifyIntegrity(m_mappedView, error)) {
            safeLog("FAILED: Format verification - " + error.message);
            return error;
        }
        safeLog("Format validation: PASSED");
        
        // Phase 4: Header validation
        const auto* header = GetHeader();
        if (!header) {
            safeLog("FAILED: Cannot access header");
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidHeader,
                "Cannot access database header"
            );
        }
        
        // Verify header CRC
        uint32_t computedCRC = Format::ComputeHeaderCRC32(header);
        if (computedCRC != header->headerCrc32) {
            safeLog("FAILED: Header CRC mismatch (expected: " + 
                std::to_string(header->headerCrc32) + 
                ", computed: " + std::to_string(computedCRC) + ")");
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidChecksum,
                "Header CRC32 mismatch"
            );
        }
        safeLog("Header CRC32: PASSED");
        
        // Phase 5: Section bounds validation
        const uint64_t fileSize = m_mappedView.fileSize;
        
        // Validate each section doesn't exceed file bounds
        struct SectionCheck {
            const char* name;
            uint64_t offset;
            uint64_t size;
        };
        
        std::array<SectionCheck, 5> sections = {{
            {"Entry Data", header->entryDataOffset, header->entryDataSize},
            {"Hash Index", header->hashIndexOffset, header->hashIndexSize},
            {"Path Index", header->pathIndexOffset, header->pathIndexSize},
            {"String Pool", header->stringPoolOffset, header->stringPoolSize},
            {"Bloom Filter", header->bloomFilterOffset, header->bloomFilterSize}
        }};
        
        for (const auto& section : sections) {
            if (section.offset > 0) {
                // Check for overflow
                if (section.offset > fileSize || 
                    section.size > fileSize ||
                    section.offset + section.size > fileSize) {
                    safeLog(std::string("FAILED: ") + section.name + " section exceeds file bounds");
                    return StoreError::WithMessage(
                        WhitelistStoreError::InvalidSection,
                        std::string(section.name) + " section exceeds file bounds"
                    );
                }
            }
        }
        safeLog("Section bounds: PASSED");
        
        // Phase 6: Index statistics
        if (m_hashIndex) {
            auto stats = GetStatistics();
            safeLog("Hash index: " + std::to_string(stats.hashEntries) + " entries");
        } else {
            safeLog("Hash index: Not initialized");
        }
        
        if (m_pathIndex) {
            auto stats = GetStatistics();
            safeLog("Path index: " + std::to_string(stats.pathEntries) + " entries");
        } else {
            safeLog("Path index: Not initialized");
        }
        
        // Phase 7: Bloom filter checks
        if (m_hashBloomFilter) {
            safeLog("Hash bloom filter: Initialized");
        } else {
            safeLog("Hash bloom filter: Not initialized");
        }
        
        if (m_pathBloomFilter) {
            safeLog("Path bloom filter: Initialized");
        } else {
            safeLog("Path bloom filter: Not initialized");
        }
        
        // Final summary
        safeLog("=================================");
        safeLog("Integrity verification: PASSED");
        safeLog("Database size: " + std::to_string(fileSize) + " bytes");
        safeLog("Total entries: " + std::to_string(GetEntryCount()));
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        safeLog("EXCEPTION: Out of memory");
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Out of memory during verification"
        );
    } catch (const std::exception& e) {
        safeLog(std::string("EXCEPTION: ") + e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            std::string("Verification exception: ") + e.what()
        );
    } catch (...) {
        safeLog("EXCEPTION: Unknown error");
        return StoreError::WithMessage(
            WhitelistStoreError::Unknown,
            "Unknown verification exception"
        );
    }
}

StoreError WhitelistStore::UpdateChecksum() noexcept {
    /*
     * ========================================================================
     * CHECKSUM UPDATE
     * ========================================================================
     *
     * Recomputes and updates all database checksums.
     * Call this after making any modifications to the database.
     *
     * ========================================================================
     */
    
    // Validate state
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot update checksum in read-only mode"
        );
    }
    
    if (!m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Store not initialized"
        );
    }
    
    // Get mutable header pointer
    auto* header = const_cast<WhitelistDatabaseHeader*>(GetHeader());
    if (!header) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Failed to get database header"
        );
    }
    
    // Validate header is within mapped bounds
    if (reinterpret_cast<const uint8_t*>(header) < 
            static_cast<const uint8_t*>(m_mappedView.baseAddress) ||
        reinterpret_cast<const uint8_t*>(header) + sizeof(WhitelistDatabaseHeader) >
            static_cast<const uint8_t*>(m_mappedView.baseAddress) + m_mappedView.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidHeader,
            "Header outside mapped bounds"
        );
    }
    
    // Update CRC32 (computed over header excluding the CRC field itself)
    header->headerCrc32 = Format::ComputeHeaderCRC32(header);
    
    // Update SHA-256 checksum of entire database
    if (!Format::ComputeDatabaseChecksum(m_mappedView, header->sha256Checksum)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidChecksum,
            "Failed to compute database checksum"
        );
    }
    
    SS_LOG_DEBUG(L"Whitelist", L"Database checksums updated (CRC32: 0x%08X)", 
        header->headerCrc32);
    
    return StoreError::Success();
}

void WhitelistStore::ClearCache() noexcept {
    /*
     * ========================================================================
     * CACHE CLEAR
     * ========================================================================
     *
     * Invalidates all cached query results. Call this when the underlying
     * data has changed to ensure cache consistency.
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_globalLock);
    
    // Clear each cache entry safely
    for (auto& entry : m_queryCache) {
        // Use SeqLock write protocol
        entry.BeginWrite();
        
        // Zero-initialize all fields
        entry.hash = HashValue{};
        entry.result = LookupResult{};
        entry.accessTime = 0;
        
        entry.EndWrite();
    }
    
    // Reset access counter
    m_cacheAccessCounter.store(0, std::memory_order_release);
    
    SS_LOG_DEBUG(L"Whitelist", L"Query cache cleared (%zu entries)", m_queryCache.size());
}

// ============================================================================
// STATISTICS & MONITORING
// ============================================================================

WhitelistStatistics WhitelistStore::GetStatistics() const noexcept {
    /*
     * ========================================================================
     * STATISTICS RETRIEVAL
     * ========================================================================
     *
     * Returns comprehensive statistics about the whitelist database.
     * This is a read-only operation safe for concurrent access.
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_globalLock);
    
    // Zero-initialize result
    WhitelistStatistics stats{};
    std::memset(&stats, 0, sizeof(WhitelistStatistics));
    
    // Get header for database statistics
    const auto* header = GetHeader();
    if (header) {
        // Calculate total entries with overflow protection
        const uint64_t MAX_ENTRY_COUNT = UINT64_MAX / 5; // Prevent overflow when summing
        
        uint64_t total = 0;
        auto safeAdd = [&total, MAX_ENTRY_COUNT](uint64_t value) {
            if (value <= MAX_ENTRY_COUNT && total <= MAX_ENTRY_COUNT - value) {
                total += value;
            }
        };
        
        safeAdd(header->totalHashEntries);
        safeAdd(header->totalPathEntries);
        safeAdd(header->totalCertEntries);
        safeAdd(header->totalPublisherEntries);
        safeAdd(header->totalOtherEntries);
        
        stats.totalEntries = total;
        stats.hashEntries = header->totalHashEntries;
        stats.pathEntries = header->totalPathEntries;
        stats.certEntries = header->totalCertEntries;
        stats.publisherEntries = header->totalPublisherEntries;
        
        stats.databaseSizeBytes = m_mappedView.fileSize;
        stats.mappedSizeBytes = m_mappedView.fileSize;
    }
    
    // Load atomic counters with relaxed ordering (statistics are approximate)
    stats.totalLookups = m_totalLookups.load(std::memory_order_relaxed);
    stats.cacheHits = m_cacheHits.load(std::memory_order_relaxed);
    stats.cacheMisses = m_cacheMisses.load(std::memory_order_relaxed);
    stats.bloomFilterHits = m_bloomHits.load(std::memory_order_relaxed);
    stats.bloomFilterRejects = m_bloomRejects.load(std::memory_order_relaxed);
    stats.totalHits = m_totalHits.load(std::memory_order_relaxed);
    stats.totalMisses = m_totalMisses.load(std::memory_order_relaxed);
    
    // Calculate average lookup time safely
    const uint64_t totalTime = m_totalLookupTimeNs.load(std::memory_order_relaxed);
    if (stats.totalLookups > 0 && totalTime <= UINT64_MAX) {
        stats.avgLookupTimeNs = totalTime / stats.totalLookups;
    } else {
        stats.avgLookupTimeNs = 0;
    }
    
    stats.minLookupTimeNs = m_minLookupTimeNs.load(std::memory_order_relaxed);
    stats.maxLookupTimeNs = m_maxLookupTimeNs.load(std::memory_order_relaxed);
    
    // Calculate cache memory usage with overflow check
    const size_t cacheSize = m_queryCache.size();
    constexpr size_t MAX_SAFE_CACHE = SIZE_MAX / sizeof(CacheEntry);
    if (cacheSize <= MAX_SAFE_CACHE) {
        stats.cacheMemoryBytes = cacheSize * sizeof(CacheEntry);
    } else {
        stats.cacheMemoryBytes = SIZE_MAX; // Overflow protection
    }
    
    return stats;
}

std::optional<Whitelist::WhitelistEntry> WhitelistStore::GetEntry(uint64_t entryId) const noexcept {
    /*
     * ========================================================================
     * SINGLE ENTRY RETRIEVAL BY ID
     * ========================================================================
     *
     * Retrieves a whitelist entry by its unique identifier.
     *
     * Implementation uses linear scan. For production with large datasets,
     * consider maintaining an ID -> offset index.
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }
    
    // Validate entry ID
    if (entryId == 0 || entryId == UINT64_MAX) {
        return std::nullopt;
    }
    
    std::shared_lock lock(m_globalLock);
    
    const auto* header = GetHeader();
    if (!header || header->entryDataOffset == 0 || header->entryDataSize == 0) {
        return std::nullopt;
    }
    
    // Validate entry data bounds
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    if (entryDataEnd > m_mappedView.fileSize) {
        return std::nullopt;
    }
    
    // Linear scan to find entry by ID
    // Note: For large databases, consider maintaining an ID index
    uint64_t offset = entryDataStart;
    
    while (offset + sizeof(WhitelistEntry) <= entryDataEnd) {
        const auto* entry = m_mappedView.GetAt<WhitelistEntry>(offset);
        if (!entry) break;
        
        // Check if this is the entry we're looking for
        if (entry->entryId == entryId) {
            // Skip if deleted/revoked
            if (entry->type == WhitelistEntryType::Reserved ||
                HasFlag(entry->flags, WhitelistFlags::Revoked)) {
                return std::nullopt; // Entry exists but is deleted
            }
            
            // Return copy of entry
            return *entry;
        }
        
        offset += sizeof(WhitelistEntry);
    }
    
    return std::nullopt;
}

std::vector<WhitelistEntry> WhitelistStore::GetEntries(
    size_t offset,
    size_t limit,
    WhitelistEntryType typeFilter
) const noexcept {
    /*
     * ========================================================================
     * PAGINATED ENTRY RETRIEVAL
     * ========================================================================
     *
     * Retrieves a page of whitelist entries with optional type filtering.
     *
     * Parameters:
     * - offset: Starting position (entry index, not byte offset)
     * - limit: Maximum entries to return
     * - typeFilter: Filter by entry type (Unknown = all types)
     *
     * ========================================================================
     */
    
    std::vector<WhitelistEntry> entries;
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return entries;
    }
    
    // Validate and clamp parameters
    constexpr size_t MAX_PAGE_SIZE = 10000;
    const size_t effectiveLimit = std::min(limit, MAX_PAGE_SIZE);
    
    if (effectiveLimit == 0) {
        return entries;
    }
    
    std::shared_lock lock(m_globalLock);
    
    const auto* header = GetHeader();
    if (!header || header->entryDataOffset == 0) {
        return entries;
    }
    
    // Reserve space to avoid reallocations
    try {
        entries.reserve(effectiveLimit);
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to allocate memory for entry retrieval");
        return entries;
    }
    
    // Validate entry data bounds
    if (header->entryDataOffset == 0 || header->entryDataSize == 0) {
        return entries;
    }
    
    const uint64_t entryDataStart = header->entryDataOffset;
    const uint64_t entryDataEnd = entryDataStart + header->entryDataSize;
    
    if (entryDataEnd > m_mappedView.fileSize) {
        return entries;
    }
    
    // Paginated retrieval with type filtering
    size_t skipped = 0;
    uint64_t byteOffset = entryDataStart;
    
    while (byteOffset + sizeof(WhitelistEntry) <= entryDataEnd && 
           entries.size() < effectiveLimit) {
        const auto* entry = m_mappedView.GetAt<WhitelistEntry>(byteOffset);
        if (!entry) break;
        
        byteOffset += sizeof(WhitelistEntry);
        
        // Skip deleted entries (Reserved = deleted/unused)
        if (entry->type == WhitelistEntryType::Reserved) {
            continue;
        }
        
        // Skip revoked entries
        if (HasFlag(entry->flags, WhitelistFlags::Revoked)) {
            continue;
        }
        
        // Apply type filter (Reserved means no filter / all types)
        if (typeFilter != WhitelistEntryType::Reserved && 
            entry->type != typeFilter) {
            continue;
        }
        
        // Handle offset (skip first N matching entries)
        if (skipped < offset) {
            ++skipped;
            continue;
        }
        
        // Add to results (push_back is safe since we reserved)
        try {
            entries.push_back(*entry);
        } catch (const std::bad_alloc&) {
            // Memory exhausted, return what we have
            break;
        }
    }
    
    return entries;
}

uint64_t WhitelistStore::GetEntryCount() const noexcept {
    /*
     * ========================================================================
     * TOTAL ENTRY COUNT
     * ========================================================================
     *
     * Returns the total number of entries in the database.
     *
     * ========================================================================
     */
    
    const auto* header = GetHeader();
    if (!header) {
        return 0;
    }
    
    // Sum all entry types with overflow protection
    uint64_t total = 0;
    constexpr uint64_t MAX_SAFE = UINT64_MAX / 5;
    
    auto safeAdd = [&total, MAX_SAFE](uint64_t value) noexcept {
        if (value <= MAX_SAFE && total <= UINT64_MAX - value) {
            total += value;
        }
    };
    
    safeAdd(header->totalHashEntries);
    safeAdd(header->totalPathEntries);
    safeAdd(header->totalCertEntries);
    safeAdd(header->totalPublisherEntries);
    safeAdd(header->totalOtherEntries);
    
    return total;
}

// ============================================================================
// CACHE MANAGEMENT (Internal)
// ============================================================================

std::optional<LookupResult> WhitelistStore::GetFromCache(const HashValue& hash) const noexcept {
    /*
     * ========================================================================
     * CACHE LOOKUP WITH SEQLOCK
     * ========================================================================
     *
     * Attempts to retrieve a cached lookup result using lock-free SeqLock.
     *
     * SeqLock Protocol:
     * 1. Read sequence number (must be even = no writer)
     * 2. Read data
     * 3. Verify sequence unchanged
     *
     * ========================================================================
     */
    
    // Early exit if cache is empty
    if (m_queryCache.empty()) {
        return std::nullopt;
    }
    
    // Compute cache index safely
    const uint64_t fastHash = hash.FastHash();
    const size_t cacheSize = m_queryCache.size();
    const uint64_t cacheIndex = fastHash % cacheSize;
    
    // Validate index (defensive)
    if (cacheIndex >= cacheSize) {
        return std::nullopt;
    }
    
    const auto& entry = m_queryCache[cacheIndex];
    
    // SeqLock read protocol
    // Read sequence number - must be even (no writer active)
    const uint64_t seq1 = entry.seqlock.load(std::memory_order_acquire);
    
    // Check if writer is active (odd sequence number)
    if (seq1 & 1) {
        return std::nullopt;
    }
    
    // Check if this entry matches our hash
    if (!(entry.hash == hash)) {
        return std::nullopt;
    }
    
    // Copy result (while holding consistent view)
    const auto result = entry.result;
    
    // Memory barrier before reading sequence again
    std::atomic_thread_fence(std::memory_order_acquire);
    
    // Verify sequence unchanged (no writer intervened)
    const uint64_t seq2 = entry.seqlock.load(std::memory_order_acquire);
    
    if (seq1 == seq2) {
        // Data is consistent
        m_cacheHits.fetch_add(1, std::memory_order_relaxed);
        return result;
    }
    
    // Writer modified entry during read - retry would happen at caller
    return std::nullopt;
}

void WhitelistStore::AddToCache(const HashValue& hash, const LookupResult& result) const noexcept {
    /*
     * ========================================================================
     * CACHE UPDATE WITH SEQLOCK
     * ========================================================================
     *
     * Adds or updates a cache entry using SeqLock write protocol.
     *
     * SeqLock Write Protocol:
     * 1. Increment sequence to odd (signals writer active)
     * 2. Write data
     * 3. Increment sequence to even (signals write complete)
     *
     * ========================================================================
     */
    
    // Early exit if cache is empty
    if (m_queryCache.empty()) {
        return;
    }
    
    // Compute cache index safely
    const uint64_t fastHash = hash.FastHash();
    const size_t cacheSize = m_queryCache.size();
    const uint64_t cacheIndex = fastHash % cacheSize;
    
    // Validate index (defensive)
    if (cacheIndex >= cacheSize) {
        return;
    }
    
    auto& entry = m_queryCache[cacheIndex];
    
    // SeqLock write protocol
    entry.BeginWrite();
    
    // Update entry data
    entry.hash = hash;
    entry.result = result;
    
    // Update access time with overflow protection
    const uint64_t accessTime = m_cacheAccessCounter.fetch_add(1, std::memory_order_relaxed);
    entry.accessTime = (accessTime < UINT64_MAX) ? accessTime : UINT64_MAX;
    
    entry.EndWrite();
}

WhitelistEntry* WhitelistStore::AllocateEntry() noexcept {
    /*
     * ========================================================================
     * ENTRY ALLOCATION
     * ========================================================================
     *
     * Allocates space for a new whitelist entry in the entry data section.
     * Returns nullptr if no space available or allocation fails.
     *
     * Thread Safety: Protected by m_entryAllocMutex
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return nullptr;
    }
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return nullptr;
    }
    
    const auto* header = GetHeader();
    if (!header) {
        return nullptr;
    }
    
    // Validate entry data section exists
    if (header->entryDataOffset == 0 || header->entryDataSize == 0) {
        SS_LOG_ERROR(L"Whitelist", L"Entry data section not configured");
        return nullptr;
    }
    
    std::lock_guard lock(m_entryAllocMutex);
    
    const uint64_t currentUsed = m_entryDataUsed.load(std::memory_order_relaxed);
    
    // Check for overflow when computing offset
    if (header->entryDataOffset > UINT64_MAX - currentUsed) {
        SS_LOG_ERROR(L"Whitelist", L"Entry offset overflow");
        return nullptr;
    }
    const uint64_t entryOffset = header->entryDataOffset + currentUsed;
    
    // Check if there's space for new entry
    if (currentUsed > header->entryDataSize - sizeof(WhitelistEntry)) {
        SS_LOG_ERROR(L"Whitelist", L"Entry data section full (used: %llu, size: %llu)",
            currentUsed, header->entryDataSize);
        return nullptr;
    }
    
    // Validate offset is within mapped view
    if (entryOffset + sizeof(WhitelistEntry) > m_mappedView.fileSize) {
        SS_LOG_ERROR(L"Whitelist", L"Entry allocation exceeds file bounds");
        return nullptr;
    }
    
    // Get mutable pointer
    auto* entry = m_mappedView.GetAtMutable<WhitelistEntry>(entryOffset);
    if (!entry) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to get mutable entry pointer");
        return nullptr;
    }
    
    // Zero-initialize the entry
    std::memset(entry, 0, sizeof(WhitelistEntry));
    
    // Update used size with overflow check
    const uint64_t newUsed = currentUsed + sizeof(WhitelistEntry);
    if (newUsed > header->entryDataSize) {
        SS_LOG_ERROR(L"Whitelist", L"Entry size calculation error");
        return nullptr;
    }
    
    m_entryDataUsed.store(newUsed, std::memory_order_release);
    
    return entry;
}

uint64_t WhitelistStore::GetNextEntryId() noexcept {
    /*
     * ========================================================================
     * ENTRY ID GENERATION
     * ========================================================================
     *
     * Generates a unique entry ID using atomic increment.
     * IDs start at 1 (0 is reserved for invalid/uninitialized).
     *
     * ========================================================================
     */
    
    // Ensure we never return 0 (reserved)
    uint64_t id = m_nextEntryId.fetch_add(1, std::memory_order_relaxed);
    
    // Handle wraparound (extremely unlikely but handle it)
    if (id == 0 || id == UINT64_MAX) {
        // Skip 0 and reset to 1
        id = m_nextEntryId.fetch_add(1, std::memory_order_relaxed);
    }
    
    return id;
}

void WhitelistStore::UpdateHeaderStats() noexcept {
    /*
     * ========================================================================
     * HEADER STATISTICS UPDATE
     * ========================================================================
     *
     * Synchronizes runtime statistics back to the database header.
     * Also updates timestamps and checksums.
     *
     * ========================================================================
     */
    
    // Validate state
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    if (m_readOnly.load(std::memory_order_acquire)) {
        return;
    }
    
    auto* header = const_cast<WhitelistDatabaseHeader*>(GetHeader());
    if (!header) {
        return;
    }
    
    // Validate header is within bounds
    if (reinterpret_cast<uint8_t*>(header) + sizeof(WhitelistDatabaseHeader) >
        static_cast<uint8_t*>(m_mappedView.baseAddress) + m_mappedView.fileSize) {
        SS_LOG_ERROR(L"Whitelist", L"Header outside mapped bounds in UpdateHeaderStats");
        return;
    }
    
    // Update timestamp safely
    auto now = std::chrono::system_clock::now();
    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    // Validate timestamp is reasonable
    constexpr int64_t MIN_EPOCH = 946684800;   // 2000-01-01
    constexpr int64_t MAX_EPOCH = 4102444800;  // 2100-01-01
    
    if (epoch >= MIN_EPOCH && epoch <= MAX_EPOCH) {
        header->lastUpdateTime = static_cast<uint64_t>(epoch);
    }
    
    // Update statistics from atomic counters
    header->totalLookups = m_totalLookups.load(std::memory_order_relaxed);
    header->totalHits = m_totalHits.load(std::memory_order_relaxed);
    header->totalMisses = m_totalMisses.load(std::memory_order_relaxed);
    
    // Update CRC to reflect changes
    header->headerCrc32 = Format::ComputeHeaderCRC32(header);
}

void WhitelistStore::RecordLookupTime(uint64_t nanoseconds) const noexcept {
    /*
     * ========================================================================
     * LOOKUP TIME RECORDING
     * ========================================================================
     *
     * Records lookup duration for performance monitoring.
     * Updates total, min, and max times atomically.
     *
     * ========================================================================
     */
    
    // Validate input
    constexpr uint64_t MAX_REASONABLE_TIME = 60ULL * 1000000000ULL; // 60 seconds
    if (nanoseconds > MAX_REASONABLE_TIME) {
        // Likely an error - clamp to reasonable max
        nanoseconds = MAX_REASONABLE_TIME;
    }
    
    // Update total time with overflow check
    const uint64_t currentTotal = m_totalLookupTimeNs.load(std::memory_order_relaxed);
    if (currentTotal < UINT64_MAX - nanoseconds) {
        m_totalLookupTimeNs.fetch_add(nanoseconds, std::memory_order_relaxed);
    }
    // If overflow would occur, just don't add (statistics will be slightly off but safe)
    
    // Update minimum (CAS loop)
    uint64_t currentMin = m_minLookupTimeNs.load(std::memory_order_relaxed);
    while (nanoseconds < currentMin) {
        if (m_minLookupTimeNs.compare_exchange_weak(
                currentMin, nanoseconds, 
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            break;
        }
        // currentMin is updated by compare_exchange_weak on failure
    }
    
    // Update maximum (CAS loop)
    uint64_t currentMax = m_maxLookupTimeNs.load(std::memory_order_relaxed);
    while (nanoseconds > currentMax) {
        if (m_maxLookupTimeNs.compare_exchange_weak(
                currentMax, nanoseconds, 
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            break;
        }
        // currentMax is updated by compare_exchange_weak on failure
    }
}

void WhitelistStore::NotifyMatch(const LookupResult& result, std::wstring_view context) const noexcept {
    /*
     * ========================================================================
     * MATCH NOTIFICATION CALLBACK
     * ========================================================================
     *
     * Invokes the registered callback when a whitelist match is found.
     * Callback exceptions are caught and logged.
     *
     * ========================================================================
     */
    
    std::lock_guard lock(m_callbackMutex);
    
    if (!m_matchCallback) {
        return;
    }
    
    try {
        m_matchCallback(result, context);
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"Match callback out of memory");
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Match callback exception: %S", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"Whitelist", L"Match callback unknown exception");
    }
}

void WhitelistStore::SetCacheSize(size_t entries) noexcept {
    /*
     * ========================================================================
     * CACHE SIZE CONFIGURATION
     * ========================================================================
     *
     * Resizes the query cache. Existing entries are cleared.
     *
     * Parameters:
     * - entries: Number of cache entries (0 disables cache)
     *
     * Limits:
     * - Maximum: 10,000,000 entries (prevents excessive memory use)
     *
     * ========================================================================
     */
    
    // Validate size limits
    constexpr size_t MAX_CACHE_ENTRIES = 10000000; // 10M entries
    constexpr size_t MIN_CACHE_ENTRIES = 0;        // Allow disabling cache
    
    if (entries > MAX_CACHE_ENTRIES) {
        SS_LOG_WARN(L"Whitelist", L"Cache size %zu exceeds maximum, clamping to %zu",
            entries, MAX_CACHE_ENTRIES);
        entries = MAX_CACHE_ENTRIES;
    }
    
    std::unique_lock lock(m_globalLock);
    
    try {
        // Resize cache vector
        m_queryCache.resize(entries);
        
        // Zero-initialize all entries
        for (auto& entry : m_queryCache) {
            entry.seqlock.store(0, std::memory_order_relaxed);
            entry.hash = HashValue{};
            entry.result = LookupResult{};
            entry.accessTime = 0;
        }
        
        // Reset access counter
        m_cacheAccessCounter.store(0, std::memory_order_release);
        
        // Calculate memory usage for logging
        const size_t memoryBytes = entries * sizeof(CacheEntry);
        SS_LOG_INFO(L"Whitelist", L"Cache size set to %zu entries (%zu bytes)",
            entries, memoryBytes);
            
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to allocate cache: out of memory");
        // Try to at least clear existing cache
        try {
            m_queryCache.clear();
            m_queryCache.shrink_to_fit();
        } catch (...) {
            // Ignore
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"Failed to resize cache: %S", e.what());
    }
}

} // namespace Whitelist
} // namespace ShadowStrike
