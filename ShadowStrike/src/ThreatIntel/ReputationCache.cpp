// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include "ReputationCache.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <numeric>
#include <thread>

#include <immintrin.h>

namespace ShadowStrike {
namespace ThreatIntel {
namespace {

constexpr uint32_t kEmptySlot = std::numeric_limits<uint32_t>::max();
constexpr uint32_t kTombstoneSlot = std::numeric_limits<uint32_t>::max() - 1;

[[nodiscard]] uint32_t CurrentUnixSeconds() noexcept {
    using namespace std::chrono;
    return static_cast<uint32_t>(duration_cast<seconds>(
        system_clock::now().time_since_epoch()).count());
}

} // namespace


// ============================================================================
// CacheShard Implementation
// ============================================================================

namespace {
// TITANIUM: Maximum cache shard limits to prevent memory exhaustion
constexpr size_t kMaxShardCapacity = 10'000'000;        // 10 million entries per shard
constexpr size_t kMaxHashTableSize = 1ULL << 25;        // ~33 million slots
constexpr size_t kMinHashTableMultiplier = 2;           // Hash table size = capacity * 2
} // namespace

CacheShard::CacheShard(size_t capacity)
    : m_capacity(std::clamp(capacity, static_cast<size_t>(1), kMaxShardCapacity)) {
    // TITANIUM: Safe hash table size calculation with overflow protection
    const size_t targetSize = m_capacity * kMinHashTableMultiplier;
    const size_t clampedTarget = std::min(targetSize, kMaxHashTableSize);
    const size_t hashTableTarget = std::bit_ceil(std::max<size_t>(clampedTarget, 8));
    m_hashTableSize = std::min(hashTableTarget, kMaxHashTableSize);

    m_entries = std::make_unique<CacheEntry[]>(m_capacity);
    m_hashTable = std::make_unique<std::atomic<uint32_t>[]>(m_hashTableSize);

    for (size_t i = 0; i < m_hashTableSize; ++i) {
        m_hashTable[i].store(kEmptySlot, std::memory_order_relaxed);
    }

    for (uint32_t i = 0; i < m_capacity; ++i) {
        m_entries[i].occupied.store(false, std::memory_order_relaxed);
        m_entries[i].lruPrev = UINT32_MAX;
        m_entries[i].lruNext = (i + 1 < m_capacity) ? i + 1 : UINT32_MAX;
    }

    m_freeHead = 0;
    m_lruHead = UINT32_MAX;
    m_lruTail = UINT32_MAX;
}

CacheShard::~CacheShard() = default;

bool CacheShard::Lookup(const CacheKey& key, CacheValue& value) const noexcept {
    // TITANIUM: Validate input key before lookup
    if (!key.IsValid()) {
        m_missCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    
    // TITANIUM: Ensure cache structures are initialized
    if (!m_entries || !m_hashTable || m_capacity == 0) {
        m_missCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot) {
        m_missCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    
    // TITANIUM: Additional bounds check for defense-in-depth
    if (index >= m_capacity) {
        m_missCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const CacheEntry& entry = m_entries[index];

    for (size_t attempt = 0; attempt < CacheConfig::SEQLOCK_MAX_RETRIES; ++attempt) {
        const uint64_t seq = entry.BeginRead();
        if (seq & 1) {
            _mm_pause();
            continue;
        }

        CacheValue snapshot = entry.value;
        if (!entry.ValidateRead(seq)) {
            continue;
        }

        if (!entry.occupied.load(std::memory_order_acquire) || snapshot.IsExpired()) {
            std::scoped_lock lock(m_writeMutex);
            const_cast<CacheShard*>(this)->FreeEntry(index);
            m_missCount.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        value = snapshot;
        entry.Touch();
        {
            std::scoped_lock lock(m_writeMutex);
            const_cast<CacheShard*>(this)->TouchLRU(index);
        }

        m_hitCount.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    std::scoped_lock lock(m_writeMutex);
    if (!entry.occupied.load(std::memory_order_acquire) || entry.value.IsExpired()) {
        const_cast<CacheShard*>(this)->FreeEntry(index);
        m_missCount.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    value = entry.value;
    entry.Touch();
    const_cast<CacheShard*>(this)->TouchLRU(index);
    m_hitCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool CacheShard::Contains(const CacheKey& key) const noexcept {
    // TITANIUM: Validate key and cache structures
    if (!key.IsValid() || !m_entries || m_capacity == 0) {
        return false;
    }
    
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot || index >= m_capacity) {
        return false;
    }
    const CacheEntry& entry = m_entries[index];
    return entry.occupied.load(std::memory_order_acquire) && !entry.value.IsExpired();
}

bool CacheShard::Insert(const CacheKey& key, const CacheValue& value) noexcept {
    // TITANIUM: Validate key and cache structures
    if (!key.IsValid() || !m_entries || !m_hashTable || m_capacity == 0) {
        return false;
    }
    
    std::scoped_lock lock(m_writeMutex);

    uint32_t index = FindEntry(key);
    if (index != kEmptySlot && index < m_capacity) {
        CacheEntry& entry = m_entries[index];
        entry.BeginWrite();
        entry.value = value;
        entry.key = key;
        entry.occupied.store(true, std::memory_order_release);
        entry.EndWrite();
        TouchLRU(index);
        m_insertCount.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    index = AllocateEntry();
    if (index == UINT32_MAX || index >= m_capacity) {
        return false;
    }
    CacheEntry& entry = m_entries[index];
    entry.BeginWrite();
    entry.key = key;
    entry.value = value;
    entry.occupied.store(true, std::memory_order_release);
    entry.EndWrite();

    // TITANIUM: Safe hash table size with overflow protection
    if (m_hashTableSize == 0) {
        return false;
    }
    const size_t mask = m_hashTableSize - 1;
    size_t slot = GetHashSlot(key);
    for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
        // TITANIUM: Validate slot is in bounds before access
        if (slot >= m_hashTableSize) {
            slot = 0;
        }
        const uint32_t current = m_hashTable[slot].load(std::memory_order_relaxed);
        if (current == kEmptySlot || current == kTombstoneSlot) {
            m_hashTable[slot].store(index, std::memory_order_release);
            break;
        }
        slot = (slot + 1) & mask;
    }

    AddToLRUFront(index);
    m_entryCount.fetch_add(1, std::memory_order_relaxed);
    m_insertCount.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool CacheShard::Remove(const CacheKey& key) noexcept {
    // TITANIUM: Validate key and cache structures
    if (!key.IsValid() || !m_entries || m_capacity == 0) {
        return false;
    }
    
    std::scoped_lock lock(m_writeMutex);
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot || index >= m_capacity) {
        return false;
    }
    FreeEntry(index);
    return true;
}

void CacheShard::Clear() noexcept {
    std::scoped_lock lock(m_writeMutex);

    // TITANIUM: Validate cache structures before clearing
    if (m_hashTable && m_hashTableSize > 0) {
        for (size_t i = 0; i < m_hashTableSize; ++i) {
            m_hashTable[i].store(kEmptySlot, std::memory_order_relaxed);
        }
    }

    if (m_entries && m_capacity > 0) {
        for (uint32_t i = 0; i < m_capacity; ++i) {
            m_entries[i].Clear();
            m_entries[i].occupied.store(false, std::memory_order_relaxed);
            m_entries[i].lruPrev = UINT32_MAX;
            m_entries[i].lruNext = (i + 1 < m_capacity) ? i + 1 : UINT32_MAX;
        }
    }

    m_freeHead = 0;
    m_lruHead = UINT32_MAX;
    m_lruTail = UINT32_MAX;
    m_entryCount.store(0, std::memory_order_relaxed);
    ResetStatistics();
}

size_t CacheShard::EvictExpired() noexcept {
    // TITANIUM: Validate cache structures
    if (!m_entries || m_capacity == 0) {
        return 0;
    }
    
    const uint32_t now = CurrentUnixSeconds();
    size_t evicted = 0;

    std::scoped_lock lock(m_writeMutex);
    for (uint32_t i = 0; i < m_capacity; ++i) {
        CacheEntry& entry = m_entries[i];
        if (!entry.occupied.load(std::memory_order_acquire)) {
            continue;
        }

        if (entry.value.expirationTime <= now || entry.value.IsExpired()) {
            FreeEntry(i);
            ++evicted;
        }
    }

    m_evictionCount.fetch_add(evicted, std::memory_order_relaxed);
    return evicted;
}

void CacheShard::ResetStatistics() noexcept {
    m_hitCount.store(0, std::memory_order_relaxed);
    m_missCount.store(0, std::memory_order_relaxed);
    m_evictionCount.store(0, std::memory_order_relaxed);
    m_insertCount.store(0, std::memory_order_relaxed);
}

uint32_t CacheShard::FindEntry(const CacheKey& key) const noexcept {
    // TITANIUM: Validate hash table is initialized
    if (m_hashTableSize == 0 || !m_hashTable || !m_entries) {
        return kEmptySlot;
    }

    const size_t mask = m_hashTableSize - 1;
    size_t slot = GetHashSlot(key);

    for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
        // TITANIUM: Validate slot is in bounds
        if (slot >= m_hashTableSize) {
            return kEmptySlot;
        }
        
        const uint32_t index = m_hashTable[slot].load(std::memory_order_acquire);
        if (index == kEmptySlot) {
            return kEmptySlot;
        }

        if (index != kTombstoneSlot && index < m_capacity) {
            const CacheEntry& entry = m_entries[index];
            if (entry.occupied.load(std::memory_order_acquire) && entry.key == key) {
                return index;
            }
        }

        slot = (slot + 1) & mask;
    }

    return kEmptySlot;
}

uint32_t CacheShard::AllocateEntry() noexcept {
    // TITANIUM: Validate entries array exists
    if (!m_entries || m_capacity == 0) {
        return UINT32_MAX;
    }
    
    if (m_freeHead == UINT32_MAX) {
        EvictLRU();
    }

    if (m_freeHead == UINT32_MAX || m_freeHead >= m_capacity) {
        return UINT32_MAX;
    }

    const uint32_t index = m_freeHead;
    CacheEntry& entry = m_entries[index];
    m_freeHead = entry.lruNext;
    entry.lruPrev = UINT32_MAX;
    entry.lruNext = UINT32_MAX;
    return index;
}

void CacheShard::FreeEntry(uint32_t index) noexcept {
    // TITANIUM: Validate index and entries array
    if (index >= m_capacity || !m_entries) {
        return;
    }

    CacheEntry& entry = m_entries[index];
    if (!entry.occupied.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    RemoveFromLRU(index);

    // TITANIUM: Validate hash table before tombstone operation
    if (m_hashTable && m_hashTableSize > 0) {
        const size_t mask = m_hashTableSize - 1;
        size_t slot = GetHashSlot(entry.key);
        for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
            // TITANIUM: Bounds check slot before access
            if (slot >= m_hashTableSize) {
                break;
            }
            const uint32_t current = m_hashTable[slot].load(std::memory_order_relaxed);
            if (current == kEmptySlot) {
                break;
            }
            if (current == index) {
                m_hashTable[slot].store(kTombstoneSlot, std::memory_order_release);
                break;
            }
            slot = (slot + 1) & mask;
        }
    }

    entry.key = CacheKey{};
    entry.value = CacheValue{};
    entry.lruNext = m_freeHead;
    entry.lruPrev = UINT32_MAX;
    m_freeHead = index;
    m_entryCount.fetch_sub(1, std::memory_order_relaxed);
}

void CacheShard::TouchLRU(uint32_t index) noexcept {
    // TITANIUM: Validate index and entries array
    if (index >= m_capacity || !m_entries) {
        return;
    }

    RemoveFromLRU(index);
    AddToLRUFront(index);
}

void CacheShard::RemoveFromLRU(uint32_t index) noexcept {
    // TITANIUM: Validate index and entries array
    if (index >= m_capacity || !m_entries) {
        return;
    }
    
    CacheEntry& entry = m_entries[index];
    const uint32_t prev = entry.lruPrev;
    const uint32_t next = entry.lruNext;

    // TITANIUM: Validate prev/next indices before access
    if (prev != UINT32_MAX && prev < m_capacity) {
        m_entries[prev].lruNext = next;
    } else if (prev == UINT32_MAX) {
        m_lruHead = next;
    }

    if (next != UINT32_MAX && next < m_capacity) {
        m_entries[next].lruPrev = prev;
    } else if (next == UINT32_MAX) {
        m_lruTail = prev;
    }

    entry.lruPrev = UINT32_MAX;
    entry.lruNext = UINT32_MAX;
}

void CacheShard::AddToLRUFront(uint32_t index) noexcept {
    // TITANIUM: Validate index and entries array
    if (index >= m_capacity || !m_entries) {
        return;
    }
    
    CacheEntry& entry = m_entries[index];
    entry.lruPrev = UINT32_MAX;
    entry.lruNext = m_lruHead;

    // TITANIUM: Validate m_lruHead before access
    if (m_lruHead != UINT32_MAX && m_lruHead < m_capacity) {
        m_entries[m_lruHead].lruPrev = index;
    }

    m_lruHead = index;
    if (m_lruTail == UINT32_MAX) {
        m_lruTail = index;
    }
}

uint32_t CacheShard::EvictLRU() noexcept {
    // TITANIUM: Validate m_lruTail is valid
    if (m_lruTail == UINT32_MAX || m_lruTail >= m_capacity) {
        return UINT32_MAX;
    }

    const uint32_t victim = m_lruTail;
    FreeEntry(victim);
    return victim;
}

size_t CacheShard::GetHashSlot(const CacheKey& key) const noexcept {
    if (m_hashTableSize == 0) {
        return 0;
    }
    const size_t mask = m_hashTableSize - 1;
    return static_cast<size_t>(key.hash) & mask;
}

// ============================================================================
// ReputationCache Implementation
// ============================================================================

namespace {
// TITANIUM: Maximum cache configuration limits to prevent DoS
constexpr size_t kMaxTotalShards = 1024;               // Maximum number of shards
constexpr size_t kMaxTotalCapacity = 100'000'000;      // 100 million entries max total
constexpr size_t kMaxBloomExpectedElements = 100'000'000;  // 100 million elements
constexpr size_t kMinShardCount = 1;
constexpr size_t kMinTotalCapacity = 1;
} // namespace

ReputationCache::ReputationCache()
    : m_positiveTTL(CacheConfig::DEFAULT_TTL_SECONDS),
      m_negativeTTL(300) {}

ReputationCache::ReputationCache(const CacheOptions& options)
    : m_options(options),
      m_positiveTTL(options.positiveTTL),
      m_negativeTTL(options.negativeTTL) {}

ReputationCache::~ReputationCache() {
    Shutdown();
}

StoreError ReputationCache::Initialize() noexcept {
    if (IsInitialized()) {
        return StoreError::Success();
    }

    if (!m_options.Validate()) {
        return StoreError::WithMessage(
            ThreatIntelError::InvalidEntry,
            "Invalid reputation cache configuration");
    }
    
    // TITANIUM: Apply safety limits to prevent memory exhaustion attacks
    const size_t safeShardCount = std::clamp(m_options.shardCount, kMinShardCount, kMaxTotalShards);
    const size_t safeTotalCapacity = std::clamp(m_options.totalCapacity, kMinTotalCapacity, kMaxTotalCapacity);
    const size_t safeBloomElements = std::min(m_options.bloomExpectedElements, kMaxBloomExpectedElements);

    try {
        m_shards.clear();
        m_shards.reserve(safeShardCount);

        // TITANIUM: Safe division - avoid division by zero
        const size_t baseCapacity = std::max<size_t>(1, safeTotalCapacity / safeShardCount);
        const size_t remainder = safeTotalCapacity % safeShardCount;

        for (size_t i = 0; i < safeShardCount; ++i) {
            const size_t capacity = baseCapacity + (i < remainder ? 1 : 0);
            auto shard = std::make_unique<CacheShard>(capacity);
            if (!shard) {
                Shutdown();
                return StoreError::WithMessage(ThreatIntelError::OutOfMemory, 
                    "Failed to allocate cache shard");
            }
            m_shards.emplace_back(std::move(shard));
        }

        if (m_options.enableBloomFilter) {
            m_bloomFilter = std::make_unique<BloomFilter>(
                safeBloomElements,
                std::clamp(m_options.bloomFalsePositiveRate, 0.0001, 0.5));
        } else {
            m_bloomFilter.reset();
        }

        // TITANIUM: Clamp TTL values to valid ranges
        m_positiveTTL.store(
            std::clamp(m_options.positiveTTL, CacheConfig::MIN_TTL_SECONDS, CacheConfig::MAX_TTL_SECONDS),
            std::memory_order_relaxed);
        m_negativeTTL.store(
            std::clamp(m_options.negativeTTL, CacheConfig::MIN_TTL_SECONDS, CacheConfig::MAX_TTL_SECONDS),
            std::memory_order_relaxed);
        m_totalLookups.store(0, std::memory_order_relaxed);
        m_bloomRejects.store(0, std::memory_order_relaxed);

        m_initialized.store(true, std::memory_order_release);
        return StoreError::Success();
    } catch (const std::bad_alloc&) {
        Shutdown();
        return StoreError::WithMessage(ThreatIntelError::OutOfMemory, 
            "Memory allocation failed during cache initialization");
    } catch (const std::exception& ex) {
        Shutdown();
        return StoreError::WithMessage(ThreatIntelError::OutOfMemory, ex.what());
    }
}

void ReputationCache::Shutdown() noexcept {
    if (!IsInitialized()) {
        return;
    }

    for (auto& shard : m_shards) {
        if (shard) {
            shard->Clear();
        }
    }

    m_shards.clear();
    m_bloomFilter.reset();
    m_initialized.store(false, std::memory_order_release);
}

bool ReputationCache::Lookup(const IPv4Address& addr, CacheValue& value) const noexcept {
    return Lookup(CacheKey(addr), value);
}

bool ReputationCache::Lookup(const IPv6Address& addr, CacheValue& value) const noexcept {
    return Lookup(CacheKey(addr), value);
}

bool ReputationCache::Lookup(const HashValue& hash, CacheValue& value) const noexcept {
    return Lookup(CacheKey(hash), value);
}

bool ReputationCache::LookupDomain(std::string_view domain, CacheValue& value) const noexcept {
    return Lookup(CacheKey(IOCType::Domain, domain), value);
}

bool ReputationCache::LookupURL(std::string_view url, CacheValue& value) const noexcept {
    return Lookup(CacheKey(IOCType::URL, url), value);
}

bool ReputationCache::LookupEmail(std::string_view email, CacheValue& value) const noexcept {
    return Lookup(CacheKey(IOCType::Email, email), value);
}

bool ReputationCache::Lookup(const CacheKey& key, CacheValue& value) const noexcept {
    if (!IsInitialized() || !key.IsValid()) {
        return false;
    }

    m_totalLookups.fetch_add(1, std::memory_order_relaxed);

    if (m_bloomFilter && !m_bloomFilter->MightContain(key)) {
        m_bloomRejects.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const CacheShard* shard = GetShard(key);
    if (!shard) {
        return false;
    }

    return shard->Lookup(key, value);
}

bool ReputationCache::MightContain(const CacheKey& key) const noexcept {
    if (!m_bloomFilter || !key.IsValid()) {
        return true;
    }

    const bool contained = m_bloomFilter->MightContain(key);
    if (!contained) {
        m_bloomRejects.fetch_add(1, std::memory_order_relaxed);
    }
    return contained;
}

void ReputationCache::BatchLookup(
    std::span<const CacheKey> keys,
    std::span<CacheValue> values,
    std::span<bool> found) const noexcept {
    if (values.size() < keys.size() || found.size() < keys.size()) {
        return;
    }

    for (size_t i = 0; i < keys.size(); ++i) {
        found[i] = Lookup(keys[i], values[i]);
    }
}

void ReputationCache::Insert(const IPv4Address& addr, const CacheValue& value) noexcept {
    Insert(CacheKey(addr), value);
}

void ReputationCache::Insert(const IPv6Address& addr, const CacheValue& value) noexcept {
    Insert(CacheKey(addr), value);
}

void ReputationCache::Insert(const HashValue& hash, const CacheValue& value) noexcept {
    Insert(CacheKey(hash), value);
}

void ReputationCache::InsertDomain(std::string_view domain, const CacheValue& value) noexcept {
    Insert(CacheKey(IOCType::Domain, domain), value);
}

void ReputationCache::InsertURL(std::string_view url, const CacheValue& value) noexcept {
    Insert(CacheKey(IOCType::URL, url), value);
}

void ReputationCache::InsertEmail(std::string_view email, const CacheValue& value) noexcept {
    Insert(CacheKey(IOCType::Email, email), value);
}

void ReputationCache::Insert(const CacheKey& key, const CacheValue& value) noexcept {
    if (!IsInitialized() || !key.IsValid()) {
        return;
    }

    CacheShard* shard = GetShard(key);
    if (!shard) {
        return;
    }

    shard->Insert(key, value);

    if (m_bloomFilter) {
        m_bloomFilter->Add(key);
    }
}

void ReputationCache::Insert(const CacheKey& key, const LookupResult& result) noexcept {
    const uint32_t ttl = m_positiveTTL.load(std::memory_order_relaxed);
    Insert(key, CacheValue(result, ttl));
}

void ReputationCache::InsertNegative(const CacheKey& key) noexcept {
    const uint32_t ttl = m_negativeTTL.load(std::memory_order_relaxed);
    Insert(key, CacheValue::NegativeResult(ttl));
}

bool ReputationCache::Remove(const CacheKey& key) noexcept {
    if (!IsInitialized() || !key.IsValid()) {
        return false;
    }

    CacheShard* shard = GetShard(key);
    if (!shard) {
        return false;
    }

    return shard->Remove(key);
}

void ReputationCache::Clear() noexcept {
    if (!IsInitialized()) {
        return;
    }

    for (auto& shard : m_shards) {
        if (shard) {
            shard->Clear();
        }
    }

    if (m_bloomFilter) {
        m_bloomFilter->Clear();
    }

    m_totalLookups.store(0, std::memory_order_relaxed);
    m_bloomRejects.store(0, std::memory_order_relaxed);
}

size_t ReputationCache::EvictExpired() noexcept {
    if (!IsInitialized()) {
        return 0;
    }

    size_t total = 0;
    for (auto& shard : m_shards) {
        if (shard) {
            total += shard->EvictExpired();
        }
    }
    return total;
}

void ReputationCache::PreWarm(std::span<const CacheKey> keys,
                              std::span<const CacheValue> values) noexcept {
    const size_t count = std::min(keys.size(), values.size());
    for (size_t i = 0; i < count; ++i) {
        Insert(keys[i], values[i]);
    }
}

void ReputationCache::PreWarm(std::span<const CacheKey> keys,
                              const PreWarmCallback& callback) noexcept {
    if (!callback) {
        return;
    }

    for (const auto& key : keys) {
        CacheValue value;
        if (callback(key, value)) {
            Insert(key, value);
        }
    }
}

CacheStatistics ReputationCache::GetStatistics() const noexcept {
    CacheStatistics stats{};
    
    // TITANIUM: Safe statistics collection with overflow protection
    stats.totalEntries = GetEntryCount();
    stats.totalCapacity = GetCapacity();
    
    // TITANIUM: Safe division - protect against divide-by-zero
    stats.utilization = (stats.totalCapacity == 0) ? 0.0 :
        static_cast<double>(stats.totalEntries) / static_cast<double>(stats.totalCapacity);
    
    // TITANIUM: Clamp utilization to valid range [0.0, 1.0]
    stats.utilization = std::clamp(stats.utilization, 0.0, 1.0);

    for (const auto& shard : m_shards) {
        if (!shard) {
            continue;
        }
        
        // TITANIUM: Use saturating addition to prevent overflow
        const size_t hits = shard->GetHitCount();
        const size_t misses = shard->GetMissCount();
        const size_t capacity = shard->GetCapacity();
        const size_t entries = shard->GetEntryCount();
        
        // Prevent overflow by checking before adding
        if (stats.cacheHits <= SIZE_MAX - hits) {
            stats.cacheHits += hits;
        } else {
            stats.cacheHits = SIZE_MAX;
        }
        
        if (stats.cacheMisses <= SIZE_MAX - misses) {
            stats.cacheMisses += misses;
        } else {
            stats.cacheMisses = SIZE_MAX;
        }
        
        // TITANIUM: Safe eviction calculation (capacity - entries)
        if (capacity >= entries) {
            const size_t evictable = capacity - entries;
            if (stats.evictions <= SIZE_MAX - evictable) {
                stats.evictions += evictable;
            } else {
                stats.evictions = SIZE_MAX;
            }
        }
    }

    // TITANIUM: Safe calculation of totalLookups
    if (stats.cacheHits <= SIZE_MAX - stats.cacheMisses) {
        stats.totalLookups = stats.cacheHits + stats.cacheMisses;
    } else {
        stats.totalLookups = SIZE_MAX;
    }
    
    stats.bloomRejects = m_bloomRejects.load(std::memory_order_relaxed);
    
    // TITANIUM: Safe hit rate calculation with divide-by-zero protection
    stats.hitRate = (stats.totalLookups == 0) ? 0.0 :
        static_cast<double>(stats.cacheHits) / static_cast<double>(stats.totalLookups);
    
    // TITANIUM: Clamp hit rate to valid range [0.0, 1.0]
    stats.hitRate = std::clamp(stats.hitRate, 0.0, 1.0);

    stats.memoryUsageBytes = GetMemoryUsage();

    if (m_bloomFilter) {
        stats.bloomFilterBytes = m_bloomFilter->GetByteCount();
        stats.bloomFillRate = std::clamp(m_bloomFilter->EstimateFillRate(), 0.0, 1.0);
        stats.bloomFalsePositiveRate = std::clamp(m_bloomFilter->EstimateFalsePositiveRate(), 0.0, 1.0);
    }

    return stats;
}

void ReputationCache::ResetStatistics() noexcept {
    m_totalLookups.store(0, std::memory_order_relaxed);
    m_bloomRejects.store(0, std::memory_order_relaxed);
    for (auto& shard : m_shards) {
        if (shard) {
            shard->ResetStatistics();
        }
    }
}

size_t ReputationCache::GetEntryCount() const noexcept {
    size_t total = 0;
    for (const auto& shard : m_shards) {
        if (shard) {
            total += shard->GetEntryCount();
        }
    }
    return total;
}

size_t ReputationCache::GetCapacity() const noexcept {
    size_t total = 0;
    for (const auto& shard : m_shards) {
        if (shard) {
            total += shard->GetCapacity();
        }
    }
    return total;
}

size_t ReputationCache::GetMemoryUsage() const noexcept {
    size_t total = sizeof(*this);
    
    for (const auto& shard : m_shards) {
        if (!shard) {
            continue;
        }
        
        // TITANIUM: Saturating addition to prevent overflow
        constexpr size_t shardSize = sizeof(CacheShard);
        if (total <= SIZE_MAX - shardSize) {
            total += shardSize;
        } else {
            return SIZE_MAX;
        }
        
        // TITANIUM: Safe multiplication and addition for entry storage
        const size_t capacity = shard->GetCapacity();
        constexpr size_t entrySize = sizeof(CacheEntry);
        
        // Check for multiplication overflow: capacity * entrySize
        if (capacity > 0 && entrySize > SIZE_MAX / capacity) {
            return SIZE_MAX;  // Would overflow
        }
        const size_t entryStorage = capacity * entrySize;
        
        // Check for addition overflow
        if (total > SIZE_MAX - entryStorage) {
            return SIZE_MAX;
        }
        total += entryStorage;
    }

    if (m_bloomFilter) {
        const size_t bloomBytes = m_bloomFilter->GetByteCount();
        if (total <= SIZE_MAX - bloomBytes) {
            total += bloomBytes;
        } else {
            return SIZE_MAX;
        }
    }

    return total;
}

void ReputationCache::SetPositiveTTL(uint32_t seconds) noexcept {
    const uint32_t clamped = std::clamp(seconds,
        CacheConfig::MIN_TTL_SECONDS,
        CacheConfig::MAX_TTL_SECONDS);
    m_positiveTTL.store(clamped, std::memory_order_relaxed);
}

void ReputationCache::SetNegativeTTL(uint32_t seconds) noexcept {
    const uint32_t clamped = std::clamp(seconds,
        CacheConfig::MIN_TTL_SECONDS,
        CacheConfig::MAX_TTL_SECONDS);
    m_negativeTTL.store(clamped, std::memory_order_relaxed);
}

CacheShard* ReputationCache::GetShard(const CacheKey& key) noexcept {
    // TITANIUM: Validate shards vector and key before access
    if (m_shards.empty() || !key.IsValid()) {
        return nullptr;
    }
    
    const size_t shardCount = m_shards.size();
    const size_t index = key.GetShardIndex(shardCount);
    
    // TITANIUM: Double-modulo for safety (GetShardIndex already uses modulo but defense-in-depth)
    const size_t safeIndex = index % shardCount;
    
    // TITANIUM: Validate index is in bounds before access
    if (safeIndex >= m_shards.size()) {
        return nullptr;
    }
    
    return m_shards[safeIndex].get();
}

const CacheShard* ReputationCache::GetShard(const CacheKey& key) const noexcept {
    // TITANIUM: Validate shards vector and key before access
    if (m_shards.empty() || !key.IsValid()) {
        return nullptr;
    }
    
    const size_t shardCount = m_shards.size();
    const size_t index = key.GetShardIndex(shardCount);
    
    // TITANIUM: Double-modulo for safety (GetShardIndex already uses modulo but defense-in-depth)
    const size_t safeIndex = index % shardCount;
    
    // TITANIUM: Validate index is in bounds before access
    if (safeIndex >= m_shards.size()) {
        return nullptr;
    }
    
    return m_shards[safeIndex].get();
}

} // namespace ThreatIntel
} // namespace ShadowStrike
