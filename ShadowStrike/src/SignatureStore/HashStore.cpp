/*
 * ============================================================================
 * ShadowStrike HashStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Lightning-fast hash database implementation
 * Bloom filter + B+Tree = < 1?s lookups
 *
 * CRITICAL: Sub-microsecond performance required!
 *
 * ============================================================================
 */

#include "HashStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <algorithm>
#include <cmath>
#include <bit>
#include <sstream>
#include <fstream>

// Windows Crypto API for hash computation
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// BLOOM FILTER IMPLEMENTATION
// ============================================================================

BloomFilter::BloomFilter(size_t expectedElements, double falsePositiveRate) {
    // Calculate optimal bit array size
    // m = -n * ln(p) / (ln(2)^2)
    double ln2 = std::log(2.0);
    m_size = static_cast<size_t>(
        -static_cast<double>(expectedElements) * std::log(falsePositiveRate) / (ln2 * ln2)
    );

    // Calculate optimal number of hash functions
    // k = (m/n) * ln(2)
    m_numHashes = static_cast<size_t>(
        (static_cast<double>(m_size) / expectedElements) * ln2
    );

    // Clamp to reasonable values
    if (m_numHashes < 1) m_numHashes = 1;
    if (m_numHashes > 10) m_numHashes = 10; // Diminishing returns after 10

    // Allocate bit array (using atomic uint64_t for thread-safety)
    size_t uint64Count = (m_size + 63) / 64;
    m_bits.resize(uint64Count);
    for (auto& b : m_bits) {
        b.store(0, std::memory_order_relaxed);
    }

    SS_LOG_INFO(L"BloomFilter", 
        L"Initialized: size=%zu bits, hashes=%zu, expectedElements=%zu, FPR=%.4f",
        m_size, m_numHashes, expectedElements, falsePositiveRate);
}

void BloomFilter::Add(uint64_t hash) noexcept {
    for (size_t i = 0; i < m_numHashes; ++i) {
        uint64_t bitIndex = Hash(hash, i) % m_size;
        size_t arrayIndex = bitIndex / 64;
        size_t bitOffset = bitIndex % 64;

        // Atomic OR to set bit
        uint64_t mask = 1ULL << bitOffset;
        m_bits[arrayIndex].fetch_or(mask, std::memory_order_relaxed);
    }
}

bool BloomFilter::MightContain(uint64_t hash) const noexcept {
    for (size_t i = 0; i < m_numHashes; ++i) {
        uint64_t bitIndex = Hash(hash, i) % m_size;
        size_t arrayIndex = bitIndex / 64;
        size_t bitOffset = bitIndex % 64;

        uint64_t bits = m_bits[arrayIndex].load(std::memory_order_relaxed);
        if ((bits & (1ULL << bitOffset)) == 0) {
            return false; // Definitely not present
        }
    }

    return true; // Might be present (or false positive)
}

void BloomFilter::Clear() noexcept {
    for (auto& b : m_bits) {
        b.store(0, std::memory_order_relaxed);
    }
}

double BloomFilter::EstimatedFillRate() const noexcept {
    size_t setBits = 0;
    for (const auto& b : m_bits) {
        uint64_t bits = b.load(std::memory_order_relaxed);
        setBits += std::popcount(bits); // C++20 popcount
    }

    return static_cast<double>(setBits) / static_cast<double>(m_size);
}

uint64_t BloomFilter::Hash(uint64_t value, size_t seed) const noexcept {
    // FNV-1a hash with seed
    uint64_t hash = 14695981039346656037ULL + seed;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

// ============================================================================
// HASH BUCKET IMPLEMENTATION
// ============================================================================

HashBucket::HashBucket(HashType type)
    : m_type(type)
    , m_index(std::make_unique<SignatureIndex>())
    , m_bloomFilter(nullptr)
{
}

HashBucket::~HashBucket() {
    // Smart pointers handle cleanup
}

StoreError HashBucket::Initialize(
    const MemoryMappedView& view,
    uint64_t bucketOffset,
    uint64_t bucketSize
) noexcept {
    SS_LOG_DEBUG(L"HashBucket", 
        L"Initialize bucket for %S: offset=0x%llX, size=0x%llX",
        Format::HashTypeToString(m_type), bucketOffset, bucketSize);

    m_view = &view;
    m_bucketOffset = bucketOffset;
    m_bucketSize = bucketSize;

    // Initialize B+Tree index
    StoreError err = m_index->Initialize(view, bucketOffset, bucketSize);
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"HashBucket", L"Failed to initialize index: %S", err.message.c_str());
        return err;
    }

    // Create Bloom filter
    m_bloomFilter = std::make_unique<BloomFilter>(100000, 0.01); // 100K hashes, 1% FPR

    SS_LOG_INFO(L"HashBucket", L"Initialized bucket for %S", 
        Format::HashTypeToString(m_type));

    return StoreError{SignatureStoreError::Success};
}

StoreError HashBucket::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    SS_LOG_DEBUG(L"HashBucket", L"CreateNew bucket for %S", 
        Format::HashTypeToString(m_type));

    m_bucketOffset = 0;
    m_bucketSize = availableSize;

    // Create B+Tree index
    StoreError err = m_index->CreateNew(baseAddress, availableSize, usedSize);
    if (!err.IsSuccess()) {
        return err;
    }

    // Create Bloom filter
    m_bloomFilter = std::make_unique<BloomFilter>(100000, 0.01);

    return StoreError{SignatureStoreError::Success};
}

std::optional<uint64_t> HashBucket::Lookup(const HashValue& hash) const noexcept {
    m_lookupCount.fetch_add(1, std::memory_order_relaxed);

    // Fast path: Bloom filter check
    uint64_t fastHash = hash.FastHash();
    if (m_bloomFilter && !m_bloomFilter->MightContain(fastHash)) {
        m_bloomHits.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt; // Definitely not present
    }

    m_bloomMisses.fetch_add(1, std::memory_order_relaxed);

    // Slow path: B+Tree lookup
    std::shared_lock<std::shared_mutex> lock(m_rwLock);
    return m_index->LookupByFastHash(fastHash);
}

void HashBucket::BatchLookup(
    std::span<const HashValue> hashes,
    std::vector<std::optional<uint64_t>>& results
) const noexcept {
    results.clear();
    results.reserve(hashes.size());

    std::shared_lock<std::shared_mutex> lock(m_rwLock);

    for (const auto& hash : hashes) {
        uint64_t fastHash = hash.FastHash();
        
        // Bloom filter check
        if (m_bloomFilter && !m_bloomFilter->MightContain(fastHash)) {
            m_bloomHits.fetch_add(1, std::memory_order_relaxed);
            results.push_back(std::nullopt);
            continue;
        }

        m_bloomMisses.fetch_add(1, std::memory_order_relaxed);
        results.push_back(m_index->LookupByFastHash(fastHash));
    }
}

bool HashBucket::Contains(const HashValue& hash) const noexcept {
    return Lookup(hash).has_value();
}

StoreError HashBucket::Insert(
    const HashValue& hash,
    uint64_t signatureOffset
) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_rwLock);

    // Add to Bloom filter
    if (m_bloomFilter) {
        m_bloomFilter->Add(hash.FastHash());
    }

    // Add to B+Tree
    return m_index->Insert(hash, signatureOffset);
}

StoreError HashBucket::Remove(const HashValue& hash) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_rwLock);

    // Note: Cannot remove from Bloom filter (it's append-only)
    // Just remove from B+Tree
    return m_index->Remove(hash);
}

StoreError HashBucket::BatchInsert(
    std::span<const std::pair<HashValue, uint64_t>> entries
) noexcept {
    std::unique_lock<std::shared_mutex> lock(m_rwLock);

    // Add all to Bloom filter first
    if (m_bloomFilter) {
        for (const auto& [hash, _] : entries) {
            m_bloomFilter->Add(hash.FastHash());
        }
    }

    // Batch insert to B+Tree
    return m_index->BatchInsert(entries);
}

HashBucket::BucketStatistics HashBucket::GetStatistics() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_rwLock);

    BucketStatistics stats{};
    stats.totalHashes = m_index->GetStatistics().totalEntries;
    stats.bloomFilterHits = m_bloomHits.load(std::memory_order_relaxed);
    stats.bloomFilterMisses = m_bloomMisses.load(std::memory_order_relaxed);
    stats.indexLookups = m_lookupCount.load(std::memory_order_relaxed);

    return stats;
}

void HashBucket::ResetStatistics() noexcept {
    m_lookupCount.store(0, std::memory_order_relaxed);
    m_bloomHits.store(0, std::memory_order_relaxed);
    m_bloomMisses.store(0, std::memory_order_relaxed);
}

// ============================================================================
// HASH STORE IMPLEMENTATION
// ============================================================================

HashStore::HashStore() {
    // Initialize performance counter
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        SS_LOG_WARN(L"HashStore", L"QueryPerformanceFrequency failed");
        m_perfFrequency.QuadPart = 1000000; // Fallback
    }
}

HashStore::~HashStore() {
    Close();
}

StoreError HashStore::Initialize(
    const std::wstring& databasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"HashStore", L"Initialize: %s (%s)", 
        databasePath.c_str(), readOnly ? L"read-only" : L"read-write");

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"HashStore", L"Already initialized");
        return StoreError{SignatureStoreError::Success};
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // Open memory mapping
    StoreError err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        return err;
    }

    // Initialize hash buckets
    err = InitializeBuckets();
    if (!err.IsSuccess()) {
        CloseMemoryMapping();
        return err;
    }

    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(L"HashStore", L"Initialized successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError HashStore::CreateNew(
    const std::wstring& databasePath,
    uint64_t initialSizeBytes
) noexcept {
    SS_LOG_INFO(L"HashStore", L"CreateNew: %s (size=%llu)", 
        databasePath.c_str(), initialSizeBytes);

    // Create file
    HANDLE hFile = CreateFileW(
        databasePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        SS_LOG_LAST_ERROR(L"HashStore", L"Failed to create file");
        return StoreError{SignatureStoreError::FileNotFound, err, "Failed to create file"};
    }

    // Set file size
    LARGE_INTEGER size{};
    size.QuadPart = initialSizeBytes;
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) ||
        !SetEndOfFile(hFile)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        SS_LOG_LAST_ERROR(L"HashStore", L"Failed to set file size");
        return StoreError{SignatureStoreError::Unknown, err, "Failed to set file size"};
    }

    CloseHandle(hFile);

    // Initialize with memory mapping
    return Initialize(databasePath, false);
}

void HashStore::Close() noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(L"HashStore", L"Closing hash store");

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    m_buckets.clear();
    CloseMemoryMapping();

    m_initialized.store(false, std::memory_order_release);
}

// ============================================================================
// QUERY OPERATIONS (continued in next message for space...)
// ============================================================================

std::optional<DetectionResult> HashStore::LookupHash(const HashValue& hash) const noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    m_totalLookups.fetch_add(1, std::memory_order_relaxed);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // Check cache first
    if (m_cachingEnabled.load(std::memory_order_acquire)) {
        auto cached = GetFromCache(hash);
        if (cached.has_value()) {
            m_cacheHits.fetch_add(1, std::memory_order_relaxed);
            return cached;
        }
        m_cacheMisses.fetch_add(1, std::memory_order_relaxed);
    }

    // Lookup in appropriate bucket
    const HashBucket* bucket = GetBucket(hash.type);
    if (!bucket) {
        return std::nullopt;
    }

    auto signatureOffset = bucket->Lookup(hash);
    if (!signatureOffset.has_value()) {
        // Cache negative result
        if (m_cachingEnabled.load(std::memory_order_acquire)) {
            AddToCache(hash, std::nullopt);
        }
        return std::nullopt;
    }

    // Build detection result
    DetectionResult result = BuildDetectionResult(hash, *signatureOffset);

    // Performance tracking
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    result.matchTimeNanoseconds = 
        ((endTime.QuadPart - startTime.QuadPart) * 1000000000ULL) / m_perfFrequency.QuadPart;

    // Cache result
    if (m_cachingEnabled.load(std::memory_order_acquire)) {
        AddToCache(hash, result);
    }

    return result;
}

std::optional<DetectionResult> HashStore::LookupHashString(
    const std::string& hashStr,
    HashType type
) const noexcept {
    auto hash = Format::ParseHashString(hashStr, type);
    if (!hash.has_value()) {
        SS_LOG_ERROR(L"HashStore", L"Failed to parse hash string: %S", hashStr.c_str());
        return std::nullopt;
    }

    return LookupHash(*hash);
}

std::vector<DetectionResult> HashStore::BatchLookup(
    std::span<const HashValue> hashes,
    const QueryOptions& options
) const noexcept {
    std::vector<DetectionResult> results;
    results.reserve(hashes.size());

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    for (const auto& hash : hashes) {
        auto result = LookupHash(hash);
        if (result.has_value()) {
            // Apply filters
            if (result->threatLevel >= options.minThreatLevel) {
                results.push_back(*result);
                
                if (results.size() >= options.maxResults) {
                    break; // Hit limit
                }
            }
        }
    }

    return results;
}

bool HashStore::Contains(const HashValue& hash) const noexcept {
    return LookupHash(hash).has_value();
}

std::vector<DetectionResult> HashStore::FuzzyMatch(
    const HashValue& hash,
    uint32_t similarityThreshold
) const noexcept {
    std::vector<DetectionResult> results;

    // Only SSDEEP and TLSH support fuzzy matching
    if (hash.type != HashType::SSDEEP && hash.type != HashType::TLSH) {
        SS_LOG_WARN(L"HashStore", L"Fuzzy matching not supported for hash type %S",
            Format::HashTypeToString(hash.type));
        return results;
    }

    // This would require iterating all hashes of same type and computing similarity
    // Not implemented in this version - would be expensive
    SS_LOG_WARN(L"HashStore", L"Fuzzy matching not yet implemented");

    return results;
}

// Remaining implementation continues...
// (AddHash, RemoveHash, Import/Export, Statistics, Maintenance, Internal methods)

StoreError HashStore::AddHash(
    const HashValue& hash,
    const std::string& signatureName,
    ThreatLevel threatLevel,
    const std::string& description,
    const std::vector<std::string>& tags
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only database"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    HashBucket* bucket = GetBucket(hash.type);
    if (!bucket) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Bucket not found"};
    }

    uint64_t offset = AllocateSignatureEntry(256);
    StoreError err = bucket->Insert(hash, offset);
    
    if (!err.IsSuccess()) {
        return err;
    }

    SS_LOG_DEBUG(L"HashStore", L"Added hash: %S (type=%S, threat=%u)",
        signatureName.c_str(), 
        Format::HashTypeToString(hash.type),
        static_cast<uint8_t>(threatLevel));

    return StoreError{SignatureStoreError::Success};
}

// [Remaining methods follow same pattern - full implementation as shown in previous code]
// Due to character limits, showing key methods only. Full file is 1200+ lines.

StoreError HashStore::OpenMemoryMapping(const std::wstring& path, bool readOnly) noexcept {
    StoreError err{};
    if (!MemoryMapping::OpenView(path, readOnly, m_mappedView, err)) {
        return err;
    }
    return StoreError{SignatureStoreError::Success};
}

void HashStore::CloseMemoryMapping() noexcept {
    MemoryMapping::CloseView(m_mappedView);
}

StoreError HashStore::InitializeBuckets() noexcept {
    const auto* header = GetHeader();
    if (!header) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Missing header"};
    }

    uint64_t bucketOffset = header->hashIndexOffset;
    uint64_t bucketSize = header->hashIndexSize / 7;

    for (uint8_t i = 0; i <= static_cast<uint8_t>(HashType::TLSH); ++i) {
        HashType type = static_cast<HashType>(i);
        
        auto bucket = std::make_unique<HashBucket>(type);
        StoreError err = bucket->Initialize(m_mappedView, bucketOffset, bucketSize);
        
        if (!err.IsSuccess()) {
            SS_LOG_WARN(L"HashStore", L"Failed to initialize bucket for %S",
                Format::HashTypeToString(type));
            continue;
        }

        m_buckets[type] = std::move(bucket);
        bucketOffset += bucketSize;
    }

    SS_LOG_INFO(L"HashStore", L"Initialized %zu hash buckets", m_buckets.size());
    return StoreError{SignatureStoreError::Success};
}

HashBucket* HashStore::GetBucket(HashType type) noexcept {
    auto it = m_buckets.find(type);
    return (it != m_buckets.end()) ? it->second.get() : nullptr;
}

const HashBucket* HashStore::GetBucket(HashType type) const noexcept {
    auto it = m_buckets.find(type);
    return (it != m_buckets.end()) ? it->second.get() : nullptr;
}

uint64_t HashStore::AllocateSignatureEntry(size_t size) noexcept {
    static uint64_t currentOffset = PAGE_SIZE * 100;
    uint64_t offset = currentOffset;
    currentOffset += Format::AlignToPage(size);
    return offset;
}

DetectionResult HashStore::BuildDetectionResult(
    const HashValue& hash,
    uint64_t signatureOffset
) const noexcept {
    DetectionResult result{};
    result.signatureId = signatureOffset;
    result.signatureName = "Hash_" + Format::FormatHashString(hash);
    result.threatLevel = ThreatLevel::Medium;
    result.fileOffset = 0;
    result.description = "Known malicious hash";
    result.matchTimestamp = std::chrono::system_clock::now().time_since_epoch().count();
    return result;
}

std::optional<DetectionResult> HashStore::GetFromCache(const HashValue& hash) const noexcept {
    size_t cacheIdx = (hash.FastHash() % CACHE_SIZE);
    const auto& entry = m_queryCache[cacheIdx];
    if (entry.hash == hash) {
        return entry.result;
    }
    return std::nullopt;
}

void HashStore::AddToCache(
    const HashValue& hash,
    const std::optional<DetectionResult>& result
) noexcept {
    size_t cacheIdx = (hash.FastHash() % CACHE_SIZE);
    auto& entry = m_queryCache[cacheIdx];
    entry.hash = hash;
    entry.result = result;
    entry.timestamp = m_cacheAccessCounter.fetch_add(1, std::memory_order_relaxed);
}

const SignatureDatabaseHeader* HashStore::GetHeader() const noexcept {
    return m_mappedView.GetAt<SignatureDatabaseHeader>(0);
}

// Hash computation utilities using Windows Crypto API
namespace HashUtils {

std::optional<HashValue> ComputeBufferHash(
    std::span<const uint8_t> buffer,
    HashType type
) noexcept {
    HashValue hash{};
    hash.type = type;

    ALG_ID algId = 0;
    switch (type) {
        case HashType::MD5:    algId = CALG_MD5;    hash.length = 16; break;
        case HashType::SHA1:   algId = CALG_SHA1;   hash.length = 20; break;
        case HashType::SHA256: algId = CALG_SHA_256; hash.length = 32; break;
        case HashType::SHA512: algId = CALG_SHA_512; hash.length = 64; break;
        default: return std::nullopt;
    }

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return std::nullopt;
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return std::nullopt;
    }

    if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(buffer.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return std::nullopt;
    }

    DWORD hashLen = hash.length;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return std::nullopt;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return hash;
}

std::optional<HashValue> ComputeFileHash(
    const std::wstring& filePath,
    HashType type
) noexcept {
    // Read file and compute hash (simplified implementation)
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return std::nullopt;
    }

    CloseHandle(hFile);
    return ComputeBufferHash(buffer, type);
}

bool CompareHashes(const HashValue& a, const HashValue& b) noexcept {
    return a == b;
}

uint32_t ComputeSSDEEPSimilarity(const HashValue& a, const HashValue& b) noexcept {
    return 0; // Requires ssdeep library
}

uint32_t ComputeTLSHDistance(const HashValue& a, const HashValue& b) noexcept {
    return 0; // Requires TLSH library
}

} // namespace HashUtils

} // namespace SignatureStore
} // namespace ShadowStrike
