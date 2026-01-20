// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"ReputationCache.hpp"
#include<algorithm>

namespace ShadowStrike {
	namespace ThreatIntel {

        // ============================================================================
        // BloomFilter Implementation
        // ============================================================================

        namespace {
            // TITANIUM: Maximum bloom filter size limits to prevent memory exhaustion attacks
            constexpr size_t kMaxBloomFilterBits = 1ULL << 30;      // 1 billion bits (~128MB)
            constexpr size_t kMaxExpectedElements = 100'000'000;    // 100 million elements max
            constexpr double kMinFalsePositiveRate = 0.0001;        // 0.01% minimum
            constexpr double kMaxFalsePositiveRate = 0.5;           // 50% maximum
        } // namespace

        BloomFilter::BloomFilter(size_t expectedElements, double falsePositiveRate) {
            // TITANIUM: Apply bounds to expected elements to prevent DoS
            if (expectedElements == 0) {
                expectedElements = CacheConfig::DEFAULT_CACHE_CAPACITY;
            }
            expectedElements = std::min(expectedElements, kMaxExpectedElements);

            // TITANIUM: Apply bounds to false positive rate
            if (falsePositiveRate <= 0.0 || falsePositiveRate >= 1.0) {
                falsePositiveRate = 0.01;
            }
            falsePositiveRate = std::clamp(falsePositiveRate, kMinFalsePositiveRate, kMaxFalsePositiveRate);

            const double ln2 = std::log(2.0);
            const double ln2Squared = ln2 * ln2;
            const double idealBits = -static_cast<double>(expectedElements) *
                std::log(falsePositiveRate) / ln2Squared;
            const double fallbackBits = static_cast<double>(expectedElements) *
                static_cast<double>(CacheConfig::BLOOM_BITS_PER_ELEMENT);

            // TITANIUM: Clamp bit count to prevent excessive memory allocation
            const size_t rawBitCount = static_cast<size_t>(std::max(idealBits, fallbackBits));
            m_bitCount = std::clamp(std::bit_ceil(std::max<size_t>(64, rawBitCount)),
                static_cast<size_t>(64), kMaxBloomFilterBits);

            const size_t wordCount = (m_bitCount + 63) / 64;

            // TITANIUM: Allocate atomic array using unique_ptr (std::vector<atomic> is invalid)
            try {
                m_data = std::make_unique<std::atomic<uint64_t>[]>(wordCount);
                m_dataSize = wordCount;
            }
            catch (const std::bad_alloc&) {
                // TITANIUM: Graceful degradation - use minimum size on allocation failure
                m_bitCount = 64;
                m_data = std::make_unique<std::atomic<uint64_t>[]>(1);
                m_dataSize = 1;
            }

            // Initialize all bits to zero
            for (size_t i = 0; i < m_dataSize; ++i) {
                m_data[i].store(0, std::memory_order_relaxed);
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
            // TITANIUM: Early exit if bloom filter is not properly initialized
            if (m_bitCount == 0 || !m_data || m_dataSize == 0) {
                return;
            }

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
            // TITANIUM: Early exit if bloom filter is not properly initialized
            if (m_bitCount == 0 || !m_data || m_dataSize == 0) {
                return false;
            }

            for (const uint64_t hash : hashes) {
                const size_t bitIndex = static_cast<size_t>(hash % m_bitCount);
                if (!TestBit(bitIndex)) {
                    return false;
                }
            }
            return true;
        }

        void BloomFilter::Clear() noexcept {
            if (m_data && m_dataSize > 0) {
                for (size_t i = 0; i < m_dataSize; ++i) {
                    m_data[i].store(0, std::memory_order_relaxed);
                }
            }
            m_elementCount.store(0, std::memory_order_relaxed);
        }

        double BloomFilter::EstimateFillRate() const noexcept {
            if (m_bitCount == 0 || !m_data || m_dataSize == 0) {
                return 0.0;
            }

            size_t setBits = 0;
            for (size_t i = 0; i < m_dataSize; ++i) {
                setBits += std::popcount(m_data[i].load(std::memory_order_relaxed));
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
            // TITANIUM: Defensive bounds check to prevent out-of-bounds access
            if (!m_data || m_dataSize == 0) {
                return;
            }

            const size_t wordIndex = index / 64;

            // TITANIUM: Validate wordIndex is within bounds before access
            if (wordIndex >= m_dataSize) {
                return;
            }

            const uint64_t mask = 1ULL << (index % 64);
            m_data[wordIndex].fetch_or(mask, std::memory_order_relaxed);
        }

        bool BloomFilter::TestBit(size_t index) const noexcept {
            // TITANIUM: Defensive bounds check to prevent out-of-bounds access
            if (!m_data || m_dataSize == 0) {
                return false;
            }

            const size_t wordIndex = index / 64;

            // TITANIUM: Validate wordIndex is within bounds before access
            if (wordIndex >= m_dataSize) {
                return false;
            }

            const uint64_t mask = 1ULL << (index % 64);
            const uint64_t value = m_data[wordIndex].load(std::memory_order_relaxed);
            return (value & mask) != 0;
        }


	}
}