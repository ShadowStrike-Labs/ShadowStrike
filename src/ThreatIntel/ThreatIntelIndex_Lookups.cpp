// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Lookup Operations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-performance lookup operations for threat intelligence index.
 * Includes SIMD-optimized batch lookups with AVX2/SSE4.2 acceleration.
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"

namespace ShadowStrike {
namespace ThreatIntel {

        // ============================================================================
        // LOOKUP OPERATIONS - IPv4
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupIPv4(
            const IPv4Address& addr,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->ipv4Index == nullptr)) {
                return IndexLookupResult::NotFound(IOCType::IPv4);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::IPv4;

            // Check bloom filter first
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv4);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = addr.FastHash();

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        // Count bloom filter rejections as failed lookups for statistics
                        m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
                        m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform index lookup
            IndexValue lookupValue;
            bool found = m_impl->ipv4Index->Lookup(addr, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;

                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);

                // Update min/max
                uint64_t currentMin = m_impl->stats.minLookupTimeNs.load(std::memory_order_relaxed);
                while (result.latencyNs < currentMin) {
                    if (m_impl->stats.minLookupTimeNs.compare_exchange_weak(
                        currentMin, result.latencyNs, std::memory_order_relaxed)) {
                        break;
                    }
                }

                uint64_t currentMax = m_impl->stats.maxLookupTimeNs.load(std::memory_order_relaxed);
                while (result.latencyNs > currentMax) {
                    if (m_impl->stats.maxLookupTimeNs.compare_exchange_weak(
                        currentMax, result.latencyNs, std::memory_order_relaxed)) {
                        break;
                    }
                }
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - IPv6
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupIPv6(
            const IPv6Address& addr,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->ipv6Index == nullptr)) {
                return IndexLookupResult::NotFound(IOCType::IPv6);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::IPv6;

            // Check bloom filter
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv6);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = addr.FastHash();

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform lookup
            IndexValue lookupValue;
            bool found = m_impl->ipv6Index->Lookup(addr, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - Domain
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupDomain(
            std::string_view domain,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->domainIndex == nullptr)) {
                return IndexLookupResult::NotFound(IOCType::Domain);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::Domain;

            // Normalize domain for case-insensitive lookup
            // Must normalize BEFORE bloom filter check to ensure consistent hashing
            const std::string normalizedDomain = NormalizeDomain(domain);
            if (normalizedDomain.empty()) {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
                m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            // Check bloom filter with normalized domain
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::Domain);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = HashString(normalizedDomain);

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform lookup (trie also normalizes, but we pass normalized for consistency)
            IndexValue lookupValue;
            bool found = m_impl->domainIndex->Lookup(normalizedDomain, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - URL
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupURL(
            std::string_view url,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->urlIndex == nullptr)) {
                return IndexLookupResult::NotFound(IOCType::URL);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::URL;

            // Check bloom filter
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::URL);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = HashString(url);

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform lookup
            IndexValue lookupValue;
            bool found = m_impl->urlIndex->Lookup(url, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - Hash
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupHash(
            const HashValue& hash,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized())) {
                return IndexLookupResult::NotFound(IOCType::FileHash);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::FileHash;

            // Get hash index for algorithm
            size_t algoIndex = static_cast<size_t>(hash.algorithm);
            if (algoIndex >= m_impl->hashIndexes.size() ||
                m_impl->hashIndexes[algoIndex] == nullptr) {
                return result;
            }

            // Check bloom filter
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::FileHash);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = hash.FastHash();

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform lookup
            IndexValue lookupValue;
            bool found = m_impl->hashIndexes[algoIndex]->Lookup(hash, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - Email
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupEmail(
            std::string_view email,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->emailIndex == nullptr)) {
                return IndexLookupResult::NotFound(IOCType::Email);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = IOCType::Email;

            // Check bloom filter
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::Email);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    uint64_t key = HashString(email);

                    result.bloomChecked = true;

                    if (!bloomIt->second->MightContain(key)) {
                        result.bloomRejected = true;
                        m_impl->stats.bloomFilterRejects.fetch_add(1, std::memory_order_relaxed);

                        if (options.collectStatistics) {
                            result.latencyNs = GetNanoseconds() - startTime;
                        }

                        return result;
                    }

                    m_impl->stats.bloomFilterChecks.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Perform lookup
            IndexValue lookupValue;
            bool found = m_impl->emailIndex->Lookup(email, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // LOOKUP OPERATIONS - Generic
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::LookupGeneric(
            IOCType type,
            std::string_view value,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || m_impl->genericIndex == nullptr)) {
                return IndexLookupResult::NotFound(type);
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            IndexLookupResult result;
            result.indexType = type;

            uint64_t key = HashString(value);

            // Perform lookup
            IndexValue lookupValue;
            bool found = m_impl->genericIndex->Lookup(key, lookupValue);

            if (found) {
                result.found = true;
                result.entryId = lookupValue.entryId;
                result.entryOffset = lookupValue.entryOffset;
                m_impl->stats.successfulLookups.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                m_impl->stats.failedLookups.fetch_add(1, std::memory_order_relaxed);
            }

            m_impl->stats.totalLookups.fetch_add(1, std::memory_order_relaxed);

            if (options.collectStatistics) {
                result.latencyNs = GetNanoseconds() - startTime;
                m_impl->stats.totalLookupTimeNs.fetch_add(result.latencyNs, std::memory_order_relaxed);
            }

            return result;
        }

        // ============================================================================
        // GENERIC LOOKUP
        // ============================================================================

        IndexLookupResult ThreatIntelIndex::Lookup(
            IOCType type,
            const void* value,
            size_t valueSize,
            const IndexQueryOptions& options
        ) const noexcept {
            if (UNLIKELY(!IsInitialized() || value == nullptr || valueSize == 0)) {
                return IndexLookupResult::NotFound(type);
            }

            // Dispatch to appropriate index based on type
            switch (type) {
            case IOCType::IPv4:
                if (valueSize == sizeof(IPv4Address)) {
                    return LookupIPv4(*static_cast<const IPv4Address*>(value), options);
                }
                break;

            case IOCType::IPv6:
                if (valueSize == sizeof(IPv6Address)) {
                    return LookupIPv6(*static_cast<const IPv6Address*>(value), options);
                }
                break;

            case IOCType::FileHash:
                if (valueSize == sizeof(HashValue)) {
                    return LookupHash(*static_cast<const HashValue*>(value), options);
                }
                break;

            case IOCType::Domain:
                return LookupDomain(
                    std::string_view(static_cast<const char*>(value), valueSize),
                    options
                );

            case IOCType::URL:
                return LookupURL(
                    std::string_view(static_cast<const char*>(value), valueSize),
                    options
                );

            case IOCType::Email:
                return LookupEmail(
                    std::string_view(static_cast<const char*>(value), valueSize),
                    options
                );

            default:
                return LookupGeneric(
                    type,
                    std::string_view(static_cast<const char*>(value), valueSize),
                    options
                );
            }

            return IndexLookupResult::NotFound(type);
        }

        // ============================================================================
        // BATCH LOOKUP OPERATIONS - SIMD OPTIMIZED
        // ============================================================================

        // -----------------------------------------------------------------------------
        // SIMD Helper: Check CPU features at runtime
        // -----------------------------------------------------------------------------
        namespace {

            /**
             * @brief Detect AVX2 availability at runtime
             * @return true if AVX2 is supported
             */
            [[nodiscard]] inline bool HasAVX2() noexcept {
                static const bool hasAVX2 = []() {
                    int cpuInfo[4];
                    __cpuid(cpuInfo, 0);
                    if (cpuInfo[0] >= 7) {
                        __cpuidex(cpuInfo, 7, 0);
                        return (cpuInfo[1] & (1 << 5)) != 0;  // AVX2 bit
                    }
                    return false;
                    }();
                return hasAVX2;
            }

            /**
             * @brief Detect SSE4.2 availability at runtime
             * @return true if SSE4.2 is supported
             */
            [[nodiscard]] inline bool HasSSE42() noexcept {
                static const bool hasSSE42 = []() {
                    int cpuInfo[4];
                    __cpuid(cpuInfo, 1);
                    return (cpuInfo[2] & (1 << 20)) != 0;  // SSE4.2 bit
                    }();
                return hasSSE42;
            }

            /**
             * @brief Batch prefetch for upcoming memory accesses
             * @param addresses Array of addresses to prefetch
             * @param count Number of addresses
             * @param prefetchDistance How far ahead to prefetch (elements)
             */
            template<typename T>
            inline void BatchPrefetch(const T* addresses, size_t count, size_t prefetchDistance = 8) noexcept {
                for (size_t i = 0; i < count && i < prefetchDistance; ++i) {
                    PREFETCH_READ(&addresses[i]);
                }
            }

            /**
             * @brief SIMD-optimized FNV-1a hash computation for 4 IPv4 addresses simultaneously
             * Uses 256-bit AVX2 registers for parallel hashing
             * @param addr0-3 Four IPv4 addresses to hash
             * @param out Array of 4 uint64_t to store results
             */
            inline void HashIPv4x4_AVX2(
                const IPv4Address& addr0, const IPv4Address& addr1,
                const IPv4Address& addr2, const IPv4Address& addr3,
                uint64_t* out
            ) noexcept {
                // FNV-1a constants
                constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
                constexpr uint64_t FNV_PRIME = 1099511628211ULL;

                // Process 4 addresses in parallel using 256-bit registers
                // Note: AVX2 doesn't have native 64-bit multiply, so we use scalar for precision
                // but we can still parallelize the XOR operations

                alignas(32) uint64_t hashes[4] = { FNV_OFFSET, FNV_OFFSET, FNV_OFFSET, FNV_OFFSET };
                alignas(32) uint64_t addresses[4] = {
                    static_cast<uint64_t>(addr0.address),
                    static_cast<uint64_t>(addr1.address),
                    static_cast<uint64_t>(addr2.address),
                    static_cast<uint64_t>(addr3.address)
                };
                alignas(32) uint64_t prefixes[4] = {
                    static_cast<uint64_t>(addr0.prefixLength),
                    static_cast<uint64_t>(addr1.prefixLength),
                    static_cast<uint64_t>(addr2.prefixLength),
                    static_cast<uint64_t>(addr3.prefixLength)
                };

                // Load into SIMD registers
                __m256i vHash = _mm256_load_si256(reinterpret_cast<const __m256i*>(hashes));
                __m256i vAddr = _mm256_load_si256(reinterpret_cast<const __m256i*>(addresses));
                __m256i vPrefix = _mm256_load_si256(reinterpret_cast<const __m256i*>(prefixes));

                // XOR with address
                vHash = _mm256_xor_si256(vHash, vAddr);

                // Store, multiply by prime (scalar - AVX2 lacks 64-bit multiply)
                _mm256_store_si256(reinterpret_cast<__m256i*>(hashes), vHash);
                for (int i = 0; i < 4; ++i) {
                    hashes[i] *= FNV_PRIME;
                }

                // Reload, XOR with prefix
                vHash = _mm256_load_si256(reinterpret_cast<const __m256i*>(hashes));
                vHash = _mm256_xor_si256(vHash, vPrefix);

                // Final multiply
                _mm256_store_si256(reinterpret_cast<__m256i*>(hashes), vHash);
                for (int i = 0; i < 4; ++i) {
                    out[i] = hashes[i] * FNV_PRIME;
                }
            }

            /**
             * @brief SIMD-optimized bloom filter batch check
             * Checks multiple keys against bloom filter in parallel
             * @param filter Pointer to bloom filter bit array
             * @param filterSize Size of filter in bits
             * @param keys Array of hash keys to check
             * @param count Number of keys
             * @param results Output: bit set if key might be in filter
             * @return Bitmask of results (bit i set = key[i] might be present)
             */
            inline uint32_t BloomCheckBatch_AVX2(
                const uint64_t* filter,
                size_t filterSize,
                const uint64_t* keys,
                size_t count
            ) noexcept {
                uint32_t resultMask = 0;
                const size_t filterSizeMask = filterSize - 1;  // Assumes power of 2

                // Process up to 8 keys at a time
                for (size_t i = 0; i < count && i < 32; ++i) {
                    // Compute multiple hash functions
                    uint64_t k = keys[i];
                    bool mightExist = true;

                    // Use 7 hash functions (configurable bloom filter)
                    for (int h = 0; h < 7 && mightExist; ++h) {
                        // Double hashing: h1 + i*h2
                        uint64_t h1 = k;
                        uint64_t h2 = (k >> 17) | (k << 47);
                        uint64_t bitPos = (h1 + static_cast<uint64_t>(h) * h2) & filterSizeMask;

                        uint64_t wordIndex = bitPos >> 6;
                        uint64_t bitIndex = bitPos & 63;

                        if ((filter[wordIndex] & (1ULL << bitIndex)) == 0) {
                            mightExist = false;
                        }
                    }

                    if (mightExist) {
                        resultMask |= (1U << i);
                    }
                }

                return resultMask;
            }

            /**
             * @brief Software prefetch helper for batch operations
             * Prefetches next N elements while processing current batch
             */
            template<typename T>
            inline void PrefetchAhead(const T* data, size_t currentIndex, size_t totalCount, size_t prefetchDistance) noexcept {
                size_t prefetchIndex = currentIndex + prefetchDistance;
                if (prefetchIndex < totalCount) {
                    PREFETCH_READ(&data[prefetchIndex]);
                }
            }

        } // anonymous namespace

        // -----------------------------------------------------------------------------
        // BatchLookupIPv4 - SIMD optimized with prefetching and parallel bloom checks
        // -----------------------------------------------------------------------------
        void ThreatIntelIndex::BatchLookupIPv4(
            std::span<const IPv4Address> addresses,
            std::vector<IndexLookupResult>& results,
            const IndexQueryOptions& options
        ) const noexcept {
            results.clear();

            const size_t count = addresses.size();
            if (UNLIKELY(count == 0)) {
                return;
            }

            results.resize(count);

            // Early exit if not initialized
            if (UNLIKELY(!IsInitialized() || m_impl->ipv4Index == nullptr)) {
                for (size_t i = 0; i < count; ++i) {
                    results[i] = IndexLookupResult::NotFound(IOCType::IPv4);
                }
                return;
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            // Get bloom filter if enabled
            const IndexBloomFilter* bloomFilter = nullptr;
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv4);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    bloomFilter = bloomIt->second.get();
                }
            }

            // Batch size for SIMD processing
            constexpr size_t BATCH_SIZE = 8;
            constexpr size_t PREFETCH_DISTANCE = 16;

            // Track statistics
            size_t bloomRejects = 0;
            size_t successful = 0;
            size_t failed = 0;

            // Process in batches with AVX2 if available
            const bool useAVX2 = HasAVX2() && count >= BATCH_SIZE;

            for (size_t batchStart = 0; batchStart < count; batchStart += BATCH_SIZE) {
                const size_t batchEnd = std::min(batchStart + BATCH_SIZE, count);
                const size_t batchCount = batchEnd - batchStart;

                // Prefetch next batch
                if (batchStart + BATCH_SIZE < count) {
                    for (size_t p = 0; p < BATCH_SIZE && batchStart + BATCH_SIZE + p < count; ++p) {
                        PREFETCH_READ(&addresses[batchStart + BATCH_SIZE + p]);
                    }
                }

                // Step 1: Compute hashes for bloom filter check
                alignas(32) uint64_t hashes[BATCH_SIZE] = {};

                if (useAVX2 && batchCount >= 4) {
                    // Process 4 at a time with AVX2
                    for (size_t i = 0; i + 4 <= batchCount; i += 4) {
                        HashIPv4x4_AVX2(
                            addresses[batchStart + i],
                            addresses[batchStart + i + 1],
                            addresses[batchStart + i + 2],
                            addresses[batchStart + i + 3],
                            &hashes[i]
                        );
                    }
                    // Handle remainder
                    for (size_t i = (batchCount / 4) * 4; i < batchCount; ++i) {
                        hashes[i] = addresses[batchStart + i].FastHash();
                    }
                }
                else {
                    // Scalar fallback
                    for (size_t i = 0; i < batchCount; ++i) {
                        hashes[i] = addresses[batchStart + i].FastHash();
                    }
                }

                // Step 2: Bloom filter check (batch)
                uint32_t maybePresent = 0xFFFFFFFF;  // Assume all present if no bloom filter

                if (bloomFilter) {
                    // For now, check each individually (could be optimized with SIMD bloom)
                    for (size_t i = 0; i < batchCount; ++i) {
                        results[batchStart + i].bloomChecked = true;

                        if (!bloomFilter->MightContain(hashes[i])) {
                            results[batchStart + i].bloomRejected = true;
                            results[batchStart + i].indexType = IOCType::IPv4;
                            maybePresent &= ~(1U << i);
                            ++bloomRejects;
                        }
                    }
                }

                // Step 3: Index lookup for addresses that passed bloom filter
                for (size_t i = 0; i < batchCount; ++i) {
                    if (!(maybePresent & (1U << i))) {
                        // Already rejected by bloom filter
                        continue;
                    }

                    results[batchStart + i].indexType = IOCType::IPv4;

                    // Prefetch index node for next lookup
                    if (i + 1 < batchCount && (maybePresent & (1U << (i + 1)))) {
                        // Prefetch hint for B+Tree lookup
                        PREFETCH_READ(&addresses[batchStart + i + 1]);
                    }

                    IndexValue lookupValue;
                    bool found = m_impl->ipv4Index->Lookup(addresses[batchStart + i], lookupValue);

                    if (found) {
                        results[batchStart + i].found = true;
                        results[batchStart + i].entryId = lookupValue.entryId;
                        results[batchStart + i].entryOffset = lookupValue.entryOffset;
                        ++successful;
                    }
                    else {
                        ++failed;
                    }
                }
            }

            // Update statistics atomically
            if (bloomRejects > 0) {
                m_impl->stats.bloomFilterRejects.fetch_add(bloomRejects, std::memory_order_relaxed);
            }
            if (bloomFilter) {
                m_impl->stats.bloomFilterChecks.fetch_add(count - bloomRejects, std::memory_order_relaxed);
            }
            m_impl->stats.successfulLookups.fetch_add(successful, std::memory_order_relaxed);
            m_impl->stats.failedLookups.fetch_add(failed, std::memory_order_relaxed);
            m_impl->stats.totalLookups.fetch_add(count, std::memory_order_relaxed);

            // Collect per-result timing if requested
            if (options.collectStatistics && count > 0) {
                uint64_t totalTime = GetNanoseconds() - startTime;
                uint64_t avgTime = totalTime / count;

                for (size_t i = 0; i < count; ++i) {
                    results[i].latencyNs = avgTime;
                }

                m_impl->stats.totalLookupTimeNs.fetch_add(totalTime, std::memory_order_relaxed);
            }
        }

        // -----------------------------------------------------------------------------
        // BatchLookupHashes - Optimized with prefetching and algorithm grouping
        // -----------------------------------------------------------------------------
        void ThreatIntelIndex::BatchLookupHashes(
            std::span<const HashValue> hashes,
            std::vector<IndexLookupResult>& results,
            const IndexQueryOptions& options
        ) const noexcept {
            results.clear();

            const size_t count = hashes.size();
            if (UNLIKELY(count == 0)) {
                return;
            }

            results.resize(count);

            if (UNLIKELY(!IsInitialized() || m_impl->hashIndexes.empty())) {
                for (size_t i = 0; i < count; ++i) {
                    results[i] = IndexLookupResult::NotFound(IOCType::FileHash);
                }
                return;
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            // Get bloom filter if enabled
            const IndexBloomFilter* bloomFilter = nullptr;
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::FileHash);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    bloomFilter = bloomIt->second.get();
                }
            }

            // Group hashes by algorithm for cache efficiency
            // This reduces B+Tree index switching overhead
            constexpr size_t MAX_ALGORITHMS = 8;
            std::array<std::vector<size_t>, MAX_ALGORITHMS> algorithmGroups;

            for (size_t i = 0; i < count; ++i) {
                size_t algoIndex = static_cast<size_t>(hashes[i].algorithm);
                if (algoIndex < MAX_ALGORITHMS) {
                    algorithmGroups[algoIndex].push_back(i);
                }
            }

            size_t bloomRejects = 0;
            size_t successful = 0;
            size_t failed = 0;

            constexpr size_t PREFETCH_DISTANCE = 4;

            // Process each algorithm group
            for (size_t algoIndex = 0; algoIndex < MAX_ALGORITHMS; ++algoIndex) {
                const auto& indices = algorithmGroups[algoIndex];
                if (indices.empty()) continue;

                // Check if we have an index for this algorithm
                if (algoIndex >= m_impl->hashIndexes.size() || !m_impl->hashIndexes[algoIndex]) {
                    for (size_t idx : indices) {
                        results[idx] = IndexLookupResult::NotFound(IOCType::FileHash);
                    }
                    continue;
                }

                auto* hashIndex = m_impl->hashIndexes[algoIndex].get();

                // Process with prefetching
                for (size_t j = 0; j < indices.size(); ++j) {
                    const size_t idx = indices[j];
                    const auto& hash = hashes[idx];

                    // Prefetch next hash in this algorithm group
                    if (j + PREFETCH_DISTANCE < indices.size()) {
                        PREFETCH_READ(&hashes[indices[j + PREFETCH_DISTANCE]]);
                    }

                    results[idx].indexType = IOCType::FileHash;

                    // Bloom filter check
                    if (bloomFilter) {
                        results[idx].bloomChecked = true;
                        uint64_t hashKey = hash.FastHash();

                        if (!bloomFilter->MightContain(hashKey)) {
                            results[idx].bloomRejected = true;
                            ++bloomRejects;
                            continue;
                        }
                    }

                    // Index lookup
                    IndexValue lookupValue;
                    bool found = hashIndex->Lookup(hash, lookupValue);

                    if (found) {
                        results[idx].found = true;
                        results[idx].entryId = lookupValue.entryId;
                        results[idx].entryOffset = lookupValue.entryOffset;
                        ++successful;
                    }
                    else {
                        ++failed;
                    }
                }
            }

            // Update statistics
            if (bloomRejects > 0) {
                m_impl->stats.bloomFilterRejects.fetch_add(bloomRejects, std::memory_order_relaxed);
            }
            if (bloomFilter) {
                m_impl->stats.bloomFilterChecks.fetch_add(count - bloomRejects, std::memory_order_relaxed);
            }
            m_impl->stats.successfulLookups.fetch_add(successful, std::memory_order_relaxed);
            m_impl->stats.failedLookups.fetch_add(failed, std::memory_order_relaxed);
            m_impl->stats.totalLookups.fetch_add(count, std::memory_order_relaxed);

            if (options.collectStatistics && count > 0) {
                uint64_t totalTime = GetNanoseconds() - startTime;
                uint64_t avgTime = totalTime / count;

                for (size_t i = 0; i < count; ++i) {
                    results[i].latencyNs = avgTime;
                }

                m_impl->stats.totalLookupTimeNs.fetch_add(totalTime, std::memory_order_relaxed);
            }
        }

        // -----------------------------------------------------------------------------
        // BatchLookupDomains - Optimized with suffix deduplication and prefetching
        // -----------------------------------------------------------------------------
        void ThreatIntelIndex::BatchLookupDomains(
            std::span<const std::string_view> domains,
            std::vector<IndexLookupResult>& results,
            const IndexQueryOptions& options
        ) const noexcept {
            results.clear();

            const size_t count = domains.size();
            if (UNLIKELY(count == 0)) {
                return;
            }

            results.resize(count);

            if (UNLIKELY(!IsInitialized() || m_impl->domainIndex == nullptr)) {
                for (size_t i = 0; i < count; ++i) {
                    results[i] = IndexLookupResult::NotFound(IOCType::Domain);
                }
                return;
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            // Get bloom filter if enabled
            const IndexBloomFilter* bloomFilter = nullptr;
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(IOCType::Domain);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    bloomFilter = bloomIt->second.get();
                }
            }

            size_t bloomRejects = 0;
            size_t successful = 0;
            size_t failed = 0;

            // Result cache for duplicate domains in batch
            // This avoids redundant lookups for repeated domains
            std::unordered_map<std::string_view, std::pair<bool, IndexLookupResult>> lookupCache;
            lookupCache.reserve(std::min(count, size_t(128)));

            constexpr size_t PREFETCH_DISTANCE = 4;

            for (size_t i = 0; i < count; ++i) {
                const auto& domain = domains[i];

                // Prefetch next domain
                if (i + PREFETCH_DISTANCE < count) {
                    PREFETCH_READ(domains[i + PREFETCH_DISTANCE].data());
                }

                results[i].indexType = IOCType::Domain;

                // Check lookup cache for duplicates
                auto cacheIt = lookupCache.find(domain);
                if (cacheIt != lookupCache.end()) {
                    results[i] = cacheIt->second.second;
                    if (results[i].found) ++successful;
                    else ++failed;
                    continue;
                }

                // Bloom filter check
                if (bloomFilter) {
                    results[i].bloomChecked = true;

                    // Hash the domain for bloom filter
                    uint64_t h = 14695981039346656037ULL;
                    for (char c : domain) {
                        h ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
                        h *= 1099511628211ULL;
                    }

                    if (!bloomFilter->MightContain(h)) {
                        results[i].bloomRejected = true;
                        ++bloomRejects;
                        lookupCache[domain] = { false, results[i] };
                        continue;
                    }
                }

                // Index lookup
                IndexValue lookupValue;
                bool found = m_impl->domainIndex->Lookup(domain, lookupValue);

                if (found) {
                    results[i].found = true;
                    results[i].entryId = lookupValue.entryId;
                    results[i].entryOffset = lookupValue.entryOffset;
                    ++successful;
                }
                else {
                    ++failed;
                }

                // Cache the result
                lookupCache[domain] = { true, results[i] };
            }

            // Update statistics
            if (bloomRejects > 0) {
                m_impl->stats.bloomFilterRejects.fetch_add(bloomRejects, std::memory_order_relaxed);
            }
            if (bloomFilter) {
                m_impl->stats.bloomFilterChecks.fetch_add(count - bloomRejects, std::memory_order_relaxed);
            }
            m_impl->stats.successfulLookups.fetch_add(successful, std::memory_order_relaxed);
            m_impl->stats.failedLookups.fetch_add(failed, std::memory_order_relaxed);
            m_impl->stats.totalLookups.fetch_add(count, std::memory_order_relaxed);

            if (options.collectStatistics && count > 0) {
                uint64_t totalTime = GetNanoseconds() - startTime;
                uint64_t avgTime = totalTime / count;

                for (size_t i = 0; i < count; ++i) {
                    results[i].latencyNs = avgTime;
                }

                m_impl->stats.totalLookupTimeNs.fetch_add(totalTime, std::memory_order_relaxed);
            }
        }

        // -----------------------------------------------------------------------------
        // BatchLookup - Generic optimized batch lookup with type dispatch
        // -----------------------------------------------------------------------------
        void ThreatIntelIndex::BatchLookup(
            IOCType type,
            std::span<const std::string_view> values,
            std::vector<IndexLookupResult>& results,
            const IndexQueryOptions& options
        ) const noexcept {
            results.clear();

            const size_t count = values.size();
            if (UNLIKELY(count == 0)) {
                return;
            }

            results.resize(count);

            if (UNLIKELY(!IsInitialized())) {
                for (size_t i = 0; i < count; ++i) {
                    results[i] = IndexLookupResult::NotFound(type);
                }
                return;
            }

            auto startTime = options.collectStatistics ? GetNanoseconds() : 0;

            // Type-specific bloom filter
            const IndexBloomFilter* bloomFilter = nullptr;
            if (options.useBloomFilter) {
                auto bloomIt = m_impl->bloomFilters.find(type);
                if (bloomIt != m_impl->bloomFilters.end()) {
                    bloomFilter = bloomIt->second.get();
                }
            }

            size_t bloomRejects = 0;
            size_t successful = 0;
            size_t failed = 0;

            constexpr size_t PREFETCH_DISTANCE = 4;

            // Process with prefetching
            for (size_t i = 0; i < count; ++i) {
                const auto& value = values[i];

                // Prefetch next value
                if (i + PREFETCH_DISTANCE < count) {
                    PREFETCH_READ(values[i + PREFETCH_DISTANCE].data());
                }

                results[i].indexType = type;

                // Bloom filter check
                if (bloomFilter) {
                    results[i].bloomChecked = true;

                    // Hash the string value for bloom filter
                    uint64_t h = 14695981039346656037ULL;
                    for (char c : value) {
                        h ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
                        h *= 1099511628211ULL;
                    }

                    if (!bloomFilter->MightContain(h)) {
                        results[i].bloomRejected = true;
                        ++bloomRejects;
                        continue;
                    }
                }

                // Dispatch to appropriate index based on type
                auto lookupResult = Lookup(type, value.data(), value.size(), options);
                results[i] = lookupResult;

                if (lookupResult.found) {
                    ++successful;
                }
                else {
                    ++failed;
                }
            }

            // Update statistics (note: Lookup already updates some stats, adjust accordingly)
            if (bloomRejects > 0) {
                m_impl->stats.bloomFilterRejects.fetch_add(bloomRejects, std::memory_order_relaxed);
            }

            if (options.collectStatistics && count > 0) {
                uint64_t totalTime = GetNanoseconds() - startTime;
                uint64_t avgTime = totalTime / count;

                // Update latency for bloom-rejected results
                for (size_t i = 0; i < count; ++i) {
                    if (results[i].bloomRejected) {
                        results[i].latencyNs = avgTime;
                    }
                }

                m_impl->stats.totalLookupTimeNs.fetch_add(totalTime, std::memory_order_relaxed);
            }
        }

} // namespace ThreatIntel
} // namespace ShadowStrike