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
// BloomFilter Implementation
// ============================================================================

BloomFilter::BloomFilter(size_t expectedElements, double falsePositiveRate) {
    if (expectedElements == 0) {
        expectedElements = CacheConfig::DEFAULT_CACHE_CAPACITY;
    }

    if (falsePositiveRate <= 0.0 || falsePositiveRate >= 1.0) {
        falsePositiveRate = 0.01;
    }

    const double ln2 = std::log(2.0);
    const double ln2Squared = ln2 * ln2;
    const double idealBits = -static_cast<double>(expectedElements) *
        std::log(falsePositiveRate) / ln2Squared;
    const double fallbackBits = static_cast<double>(expectedElements) *
        static_cast<double>(CacheConfig::BLOOM_BITS_PER_ELEMENT);

    m_bitCount = std::max<size_t>(64, std::bit_ceil(
        static_cast<size_t>(std::max(idealBits, fallbackBits))));

    const size_t wordCount = (m_bitCount + 63) / 64;
    m_data.resize(wordCount);
    for (auto& word : m_data) {
        word.store(0, std::memory_order_relaxed);
    }

    m_elementCount.store(0, std::memory_order_relaxed);
}

void BloomFilter::Add(const CacheKey& key) noexcept {
    if (!key.IsValid()) {
        return;
    }

    Add(key.GetBloomHashes());
}

void BloomFilter::Add(
    const std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS>& hashes) noexcept {
    for (const uint64_t hash : hashes) {
        const size_t bitIndex = static_cast<size_t>(hash % m_bitCount);
        SetBit(bitIndex);
    }

    m_elementCount.fetch_add(1, std::memory_order_relaxed);
}

bool BloomFilter::MightContain(const CacheKey& key) const noexcept {
    if (!key.IsValid()) {
        return false;
    }

    return MightContain(key.GetBloomHashes());
}

bool BloomFilter::MightContain(
    const std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS>& hashes) const noexcept {
    for (const uint64_t hash : hashes) {
        const size_t bitIndex = static_cast<size_t>(hash % m_bitCount);
        if (!TestBit(bitIndex)) {
            return false;
        }
    }
    return true;
}

void BloomFilter::Clear() noexcept {
    for (auto& word : m_data) {
        word.store(0, std::memory_order_relaxed);
    }
    m_elementCount.store(0, std::memory_order_relaxed);
}

double BloomFilter::EstimateFillRate() const noexcept {
    if (m_bitCount == 0) {
        return 0.0;
    }

    size_t setBits = 0;
    for (const auto& word : m_data) {
        setBits += std::popcount(word.load(std::memory_order_relaxed));
    }

    return static_cast<double>(setBits) / static_cast<double>(m_bitCount);
}

double BloomFilter::EstimateFalsePositiveRate() const noexcept {
    const size_t n = m_elementCount.load(std::memory_order_relaxed);
    if (n == 0 || m_bitCount == 0) {
        return 0.0;
    }

    const double k = static_cast<double>(CacheConfig::BLOOM_HASH_FUNCTIONS);
    const double exponent = -k * static_cast<double>(n) / static_cast<double>(m_bitCount);
    const double base = 1.0 - std::exp(exponent);
    return std::pow(base, k);
}

void BloomFilter::SetBit(size_t index) noexcept {
    const size_t wordIndex = index / 64;
    const uint64_t mask = 1ULL << (index % 64);
    m_data[wordIndex].fetch_or(mask, std::memory_order_relaxed);
}

bool BloomFilter::TestBit(size_t index) const noexcept {
    const size_t wordIndex = index / 64;
    const uint64_t mask = 1ULL << (index % 64);
    const uint64_t value = m_data[wordIndex].load(std::memory_order_relaxed);
    return (value & mask) != 0;
}

// ============================================================================
// CacheShard Implementation
// ============================================================================

CacheShard::CacheShard(size_t capacity)
    : m_capacity(std::max<size_t>(1, capacity)) {
    const size_t hashTableTarget = std::bit_ceil(std::max<size_t>(m_capacity * 2, 8));
    m_hashTableSize = hashTableTarget;

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
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot) {
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
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot) {
        return false;
    }
    const CacheEntry& entry = m_entries[index];
    return entry.occupied.load(std::memory_order_acquire) && !entry.value.IsExpired();
}

bool CacheShard::Insert(const CacheKey& key, const CacheValue& value) noexcept {
    std::scoped_lock lock(m_writeMutex);

    uint32_t index = FindEntry(key);
    if (index != kEmptySlot) {
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
    if (index == UINT32_MAX) {
        return false;
    }
    CacheEntry& entry = m_entries[index];
    entry.BeginWrite();
    entry.key = key;
    entry.value = value;
    entry.occupied.store(true, std::memory_order_release);
    entry.EndWrite();

    const size_t mask = m_hashTableSize - 1;
    size_t slot = GetHashSlot(key);
    for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
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
    std::scoped_lock lock(m_writeMutex);
    const uint32_t index = FindEntry(key);
    if (index == kEmptySlot) {
        return false;
    }
    FreeEntry(index);
    return true;
}

void CacheShard::Clear() noexcept {
    std::scoped_lock lock(m_writeMutex);

    for (size_t i = 0; i < m_hashTableSize; ++i) {
        m_hashTable[i].store(kEmptySlot, std::memory_order_relaxed);
    }

    for (uint32_t i = 0; i < m_capacity; ++i) {
        m_entries[i].Clear();
        m_entries[i].occupied.store(false, std::memory_order_relaxed);
        m_entries[i].lruPrev = UINT32_MAX;
        m_entries[i].lruNext = (i + 1 < m_capacity) ? i + 1 : UINT32_MAX;
    }

    m_freeHead = 0;
    m_lruHead = UINT32_MAX;
    m_lruTail = UINT32_MAX;
    m_entryCount.store(0, std::memory_order_relaxed);
    ResetStatistics();
}

size_t CacheShard::EvictExpired() noexcept {
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
    if (m_hashTableSize == 0) {
        return kEmptySlot;
    }

    const size_t mask = m_hashTableSize - 1;
    size_t slot = GetHashSlot(key);

    for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
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
    if (m_freeHead == UINT32_MAX) {
        EvictLRU();
    }

    if (m_freeHead == UINT32_MAX) {
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
    if (index >= m_capacity) {
        return;
    }

    CacheEntry& entry = m_entries[index];
    if (!entry.occupied.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    RemoveFromLRU(index);

    const size_t mask = m_hashTableSize - 1;
    size_t slot = GetHashSlot(entry.key);
    for (size_t probe = 0; probe < m_hashTableSize; ++probe) {
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

    entry.key = CacheKey{};
    entry.value = CacheValue{};
    entry.lruNext = m_freeHead;
    entry.lruPrev = UINT32_MAX;
    m_freeHead = index;
    m_entryCount.fetch_sub(1, std::memory_order_relaxed);
}

void CacheShard::TouchLRU(uint32_t index) noexcept {
    if (index >= m_capacity) {
        return;
    }

    RemoveFromLRU(index);
    AddToLRUFront(index);
}

void CacheShard::RemoveFromLRU(uint32_t index) noexcept {
    CacheEntry& entry = m_entries[index];
    const uint32_t prev = entry.lruPrev;
    const uint32_t next = entry.lruNext;

    if (prev != UINT32_MAX) {
        m_entries[prev].lruNext = next;
    } else {
        m_lruHead = next;
    }

    if (next != UINT32_MAX) {
        m_entries[next].lruPrev = prev;
    } else {
        m_lruTail = prev;
    }

    entry.lruPrev = UINT32_MAX;
    entry.lruNext = UINT32_MAX;
}

void CacheShard::AddToLRUFront(uint32_t index) noexcept {
    CacheEntry& entry = m_entries[index];
    entry.lruPrev = UINT32_MAX;
    entry.lruNext = m_lruHead;

    if (m_lruHead != UINT32_MAX) {
        m_entries[m_lruHead].lruPrev = index;
    }

    m_lruHead = index;
    if (m_lruTail == UINT32_MAX) {
        m_lruTail = index;
    }
}

uint32_t CacheShard::EvictLRU() noexcept {
    if (m_lruTail == UINT32_MAX) {
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

    try {
        m_shards.clear();
        m_shards.reserve(m_options.shardCount);

        const size_t baseCapacity = std::max<size_t>(1, m_options.totalCapacity / m_options.shardCount);
        const size_t remainder = m_options.totalCapacity % m_options.shardCount;

        for (size_t i = 0; i < m_options.shardCount; ++i) {
            const size_t capacity = baseCapacity + (i < remainder ? 1 : 0);
            m_shards.emplace_back(std::make_unique<CacheShard>(capacity));
        }

        if (m_options.enableBloomFilter) {
            m_bloomFilter = std::make_unique<BloomFilter>(
                m_options.bloomExpectedElements,
                m_options.bloomFalsePositiveRate);
        } else {
            m_bloomFilter.reset();
        }

        m_positiveTTL.store(m_options.positiveTTL, std::memory_order_relaxed);
        m_negativeTTL.store(m_options.negativeTTL, std::memory_order_relaxed);
        m_totalLookups.store(0, std::memory_order_relaxed);
        m_bloomRejects.store(0, std::memory_order_relaxed);

        m_initialized.store(true, std::memory_order_release);
        return StoreError::Success();
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
    stats.totalEntries = GetEntryCount();
    stats.totalCapacity = GetCapacity();
    stats.utilization = stats.totalCapacity == 0 ? 0.0 :
        static_cast<double>(stats.totalEntries) / static_cast<double>(stats.totalCapacity);

    for (const auto& shard : m_shards) {
        if (!shard) {
            continue;
        }
        stats.cacheHits += shard->GetHitCount();
        stats.cacheMisses += shard->GetMissCount();
        stats.evictions += shard->GetCapacity() - shard->GetEntryCount();
    }

    stats.totalLookups = stats.cacheHits + stats.cacheMisses;
    stats.bloomRejects = m_bloomRejects.load(std::memory_order_relaxed);
    stats.hitRate = stats.totalLookups == 0 ? 0.0 :
        static_cast<double>(stats.cacheHits) / static_cast<double>(stats.totalLookups);

    stats.memoryUsageBytes = GetMemoryUsage();

    if (m_bloomFilter) {
        stats.bloomFilterBytes = m_bloomFilter->GetByteCount();
        stats.bloomFillRate = m_bloomFilter->EstimateFillRate();
        stats.bloomFalsePositiveRate = m_bloomFilter->EstimateFalsePositiveRate();
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
        total += sizeof(CacheShard);
        total += shard->GetCapacity() * sizeof(CacheEntry);
    }

    if (m_bloomFilter) {
        total += m_bloomFilter->GetByteCount();
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
    if (m_shards.empty()) {
        return nullptr;
    }
    const size_t index = key.GetShardIndex(m_shards.size());
    return m_shards[index % m_shards.size()].get();
}

const CacheShard* ReputationCache::GetShard(const CacheKey& key) const noexcept {
    if (m_shards.empty()) {
        return nullptr;
    }
    const size_t index = key.GetShardIndex(m_shards.size());
    return m_shards[index % m_shards.size()].get();
}

} // namespace ThreatIntel
} // namespace ShadowStrike
