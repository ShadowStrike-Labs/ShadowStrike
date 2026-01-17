
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include "HashStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/StringUtils.hpp"

namespace ShadowStrike {

	namespace SignatureStore {


        // ============================================================================
        // HASH BUCKET IMPLEMENTATION
        // ============================================================================

        HashBucket::HashBucket(HashType type)
            : m_type(type)
            , m_index(nullptr)
            , m_bloomFilter(nullptr)
            , m_view(nullptr)
            , m_bucketOffset(0)
            , m_bucketSize(0)
            , m_lookupCount(0)
            , m_bloomHits(0)
            , m_bloomMisses(0)
        {
            try {
                m_index = std::make_unique<SignatureIndex>();
            }
            catch (const std::bad_alloc& ex) {
                SS_LOG_ERROR(L"HashBucket",
                    L"Failed to allocate SignatureIndex: %S", ex.what());
                m_index = nullptr;
            }
        }

        HashBucket::~HashBucket() {
            // Smart pointers handle cleanup automatically
            // Explicit reset for deterministic destruction order
            m_bloomFilter.reset();
            m_index.reset();
        }

        StoreError HashBucket::Initialize(
            const MemoryMappedView& view,
            uint64_t bucketOffset,
            uint64_t bucketSize
        ) noexcept {
            SS_LOG_DEBUG(L"HashBucket",
                L"Initialize bucket for %S: offset=0x%llX, size=0x%llX",
                Format::HashTypeToString(m_type), bucketOffset, bucketSize);

            // Validate inputs
            if (!view.IsValid()) {
                SS_LOG_ERROR(L"HashBucket", L"Initialize: Invalid memory mapped view");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid memory mapped view" };
            }

            if (bucketSize == 0) {
                SS_LOG_ERROR(L"HashBucket", L"Initialize: Bucket size is zero");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Bucket size cannot be zero" };
            }

            // Bounds validation
            if (bucketOffset > view.fileSize ||
                bucketSize > view.fileSize - bucketOffset) {
                SS_LOG_ERROR(L"HashBucket",
                    L"Initialize: Bucket bounds exceed file size (offset=%llu, size=%llu, fileSize=%llu)",
                    bucketOffset, bucketSize, view.fileSize);
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Bucket exceeds file bounds" };
            }

            m_view = &view;
            m_bucketOffset = bucketOffset;
            m_bucketSize = bucketSize;

            // Initialize B+Tree index
            if (!m_index) {
                try {
                    m_index = std::make_unique<SignatureIndex>();
                }
                catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"HashBucket", L"Initialize: Failed to allocate index");
                    return StoreError{ SignatureStoreError::Unknown, 0, "Index allocation failed" };
                }
            }

            StoreError err = m_index->Initialize(view, bucketOffset, bucketSize);
            if (!err.IsSuccess()) {
                SS_LOG_ERROR(L"HashBucket", L"Failed to initialize index: %S", err.message.c_str());
                return err;
            }

            // Create Bloom filter with proper exception handling
            try {
                m_bloomFilter = std::make_unique<BloomFilter>(100000, 0.01); // 100K hashes, 1% FPR
            }
            catch (const std::bad_alloc& ex) {
                SS_LOG_ERROR(L"HashBucket",
                    L"Failed to allocate bloom filter: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "Bloom filter allocation failed" };
            }

            SS_LOG_INFO(L"HashBucket", L"Initialized bucket for %S",
                Format::HashTypeToString(m_type));

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError HashBucket::CreateNew(
            void* baseAddress,
            uint64_t availableSize,
            uint64_t& usedSize
        ) noexcept {
            SS_LOG_DEBUG(L"HashBucket", L"CreateNew bucket for %S",
                Format::HashTypeToString(m_type));

            // Validate inputs
            if (baseAddress == nullptr) {
                SS_LOG_ERROR(L"HashBucket", L"CreateNew: Null base address");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Null base address" };
            }

            if (availableSize == 0) {
                SS_LOG_ERROR(L"HashBucket", L"CreateNew: Zero available size");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Zero available size" };
            }

            m_bucketOffset = 0;
            m_bucketSize = availableSize;
            usedSize = 0;  // Initialize output parameter

            // Create B+Tree index
            if (!m_index) {
                try {
                    m_index = std::make_unique<SignatureIndex>();
                }
                catch (const std::bad_alloc&) {
                    SS_LOG_ERROR(L"HashBucket", L"CreateNew: Failed to allocate index");
                    return StoreError{ SignatureStoreError::Unknown, 0, "Index allocation failed" };
                }
            }

            StoreError err = m_index->CreateNew(baseAddress, availableSize, usedSize);
            if (!err.IsSuccess()) {
                SS_LOG_ERROR(L"HashBucket", L"CreateNew: Index creation failed: %S", err.message.c_str());
                return err;
            }

            // Create Bloom filter
            try {
                m_bloomFilter = std::make_unique<BloomFilter>(100000, 0.01);
            }
            catch (const std::bad_alloc& ex) {
                SS_LOG_ERROR(L"HashBucket",
                    L"CreateNew: Bloom filter allocation failed: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "Bloom filter allocation failed" };
            }

            SS_LOG_INFO(L"HashBucket", L"Created new bucket for %S, used %llu bytes",
                Format::HashTypeToString(m_type), usedSize);

            return StoreError{ SignatureStoreError::Success };
        }

        std::optional<uint64_t> HashBucket::Lookup(const HashValue& hash) const noexcept {
            // Validate state
            if (!m_index) {
                SS_LOG_ERROR(L"HashBucket", L"Lookup: Index not initialized");
                return std::nullopt;
            }

            m_lookupCount.fetch_add(1, std::memory_order_relaxed);

            // Fast path: Bloom filter check
            const uint64_t fastHash = hash.FastHash();
            if (m_bloomFilter && !m_bloomFilter->MightContain(fastHash)) {
                m_bloomHits.fetch_add(1, std::memory_order_relaxed);
                return std::nullopt; // Definitely not present
            }

            m_bloomMisses.fetch_add(1, std::memory_order_relaxed);

            // Slow path: B+Tree lookup with read lock
            std::shared_lock<std::shared_mutex> lock(m_rwLock);
            return m_index->LookupByFastHash(fastHash);
        }

        void HashBucket::BatchLookup(
            std::span<const HashValue> hashes,
            std::vector<std::optional<uint64_t>>& results
        ) const noexcept {
            results.clear();

            if (hashes.empty()) {
                return;
            }

            // Validate state
            if (!m_index) {
                SS_LOG_ERROR(L"HashBucket", L"BatchLookup: Index not initialized");
                results.resize(hashes.size(), std::nullopt);
                return;
            }

            try {
                results.reserve(hashes.size());
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"HashBucket", L"BatchLookup: Memory allocation failed");
                return;
            }

            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            for (const auto& hash : hashes) {
                const uint64_t fastHash = hash.FastHash();

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
            // Validate state
            if (!m_index) {
                SS_LOG_ERROR(L"HashBucket", L"Insert: Index not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Index not initialized" };
            }

            std::unique_lock<std::shared_mutex> lock(m_rwLock);

            // Add to Bloom filter first (cannot fail)
            if (m_bloomFilter) {
                m_bloomFilter->Add(hash.FastHash());
            }

            // Add to B+Tree
            return m_index->Insert(hash, signatureOffset);
        }

        StoreError HashBucket::Remove(const HashValue& hash) noexcept {
            // Validate state
            if (!m_index) {
                SS_LOG_ERROR(L"HashBucket", L"Remove: Index not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Index not initialized" };
            }

            std::unique_lock<std::shared_mutex> lock(m_rwLock);

            // Note: Cannot remove from Bloom filter (it's append-only by design)
            // This may cause false positives, but bloom filter is just an optimization
            // The B+Tree is the authoritative source
            return m_index->Remove(hash);
        }

        StoreError HashBucket::BatchInsert(
            std::span<const std::pair<HashValue, uint64_t>> entries
        ) noexcept {
            if (entries.empty()) {
                return StoreError{ SignatureStoreError::Success };
            }

            // Validate state
            if (!m_index) {
                SS_LOG_ERROR(L"HashBucket", L"BatchInsert: Index not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Index not initialized" };
            }

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

            if (m_index) {
                stats.totalHashes = m_index->GetStatistics().totalEntries;
            }

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





	}
}