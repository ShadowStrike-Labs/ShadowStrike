// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include "HashStore.hpp"
#include "../Utils/Logger.hpp"
#include<bit>

namespace ShadowStrike {
    namespace SignatureStore {



        // ====================================================
        // BloomFilter - Thread-safe, high-performance
        // ====================================================

        BloomFilter::BloomFilter(size_t expectedElements, double falsePositiveRate) {
            // Input validation - prevent DoS and division by zero
            constexpr size_t MIN_EXPECTED_ELEMENTS = 1;
            constexpr size_t MAX_EXPECTED_ELEMENTS = 100'000'000;  // 100M max
            constexpr double MIN_FPR = 0.0001;   // 0.01%
            constexpr double MAX_FPR = 0.5;      // 50%

            if (expectedElements < MIN_EXPECTED_ELEMENTS) {
                expectedElements = MIN_EXPECTED_ELEMENTS;
                SS_LOG_WARN(L"BloomFilter",
                    L"Expected elements too low, clamped to %zu", MIN_EXPECTED_ELEMENTS);
            }
            if (expectedElements > MAX_EXPECTED_ELEMENTS) {
                expectedElements = MAX_EXPECTED_ELEMENTS;
                SS_LOG_WARN(L"BloomFilter",
                    L"Expected elements too high, clamped to %zu", MAX_EXPECTED_ELEMENTS);
            }

            if (falsePositiveRate < MIN_FPR) {
                falsePositiveRate = MIN_FPR;
                SS_LOG_WARN(L"BloomFilter",
                    L"FPR too low, clamped to %.4f", MIN_FPR);
            }
            if (falsePositiveRate > MAX_FPR) {
                falsePositiveRate = MAX_FPR;
                SS_LOG_WARN(L"BloomFilter",
                    L"FPR too high, clamped to %.2f", MAX_FPR);
            }

            const double ln2 = std::log(2.0);
            const double ln2Squared = ln2 * ln2;

            // Calculate optimal bit array size: m = -n * ln(p) / (ln2)^2
            // Guard against overflow with saturation
            const double rawSize = -static_cast<double>(expectedElements) *
                std::log(falsePositiveRate) / ln2Squared;

            constexpr size_t MAX_BIT_SIZE = 1'000'000'000;  // 1 billion bits max (~125MB)
            if (rawSize <= 0.0 || std::isnan(rawSize) || std::isinf(rawSize)) {
                m_size = MIN_EXPECTED_ELEMENTS * 10;  // Fallback
                SS_LOG_WARN(L"BloomFilter",
                    L"Invalid size calculation, using fallback: %zu", m_size);
            }
            else if (rawSize > static_cast<double>(MAX_BIT_SIZE)) {
                m_size = MAX_BIT_SIZE;
                SS_LOG_WARN(L"BloomFilter",
                    L"Size clamped to maximum: %zu bits", MAX_BIT_SIZE);
            }
            else {
                m_size = static_cast<size_t>(rawSize);
            }

            // Ensure minimum size
            if (m_size == 0) {
                m_size = 64;  // Minimum 64 bits (1 uint64_t)
            }

            // Calculate optimal number of hash functions: k = (m/n) * ln2
            const double rawHashes = (static_cast<double>(m_size) /
                static_cast<double>(expectedElements)) * ln2;

            if (rawHashes <= 0.0 || std::isnan(rawHashes) || std::isinf(rawHashes)) {
                m_numHashes = 3;  // Fallback to reasonable default
            }
            else {
                m_numHashes = static_cast<size_t>(std::round(rawHashes));
            }

            // Clamp hash functions to reasonable range
            constexpr size_t MIN_HASHES = 1;
            constexpr size_t MAX_HASHES = 16;
            if (m_numHashes < MIN_HASHES) {
                m_numHashes = MIN_HASHES;
            }
            else if (m_numHashes > MAX_HASHES) {
                m_numHashes = MAX_HASHES;
            }

            // Calculate 64-bit slot count with overflow protection
            // Avoid overflow: (m_size + 63) / 64 could overflow if m_size is near SIZE_MAX
            constexpr size_t MAX_UINT64_COUNT = MAX_BIT_SIZE / 64 + 1;
            size_t uint64Count = 0;
            if (m_size <= SIZE_MAX - 63) {
                uint64Count = (m_size + 63) / 64;
            }
            else {
                // Overflow would occur, use max safe value
                uint64Count = MAX_UINT64_COUNT;
            }

            // Prevent huge allocations
            if (uint64Count > MAX_UINT64_COUNT || uint64Count == 0) {
                SS_LOG_ERROR(L"BloomFilter",
                    L"Bit array size invalid: %zu slots (max: %zu)",
                    uint64Count, MAX_UINT64_COUNT);
                m_size = 64;
                m_numHashes = 3;
                return;
            }

            // Allocate with exception handling
            try {
                std::vector<std::atomic<uint64_t>> fresh(uint64Count);
                m_bits.swap(fresh);
            }
            catch (const std::bad_alloc& ex) {
                SS_LOG_ERROR(L"BloomFilter",
                    L"Memory allocation failed for %zu slots: %S",
                    uint64Count, ex.what());
                m_size = 0;
                m_numHashes = 0;
                return;
            }

            // Atomically zero each element
            for (auto& w : m_bits) {
                w.store(0ULL, std::memory_order_relaxed);
            }

            SS_LOG_INFO(L"BloomFilter",
                L"Initialized: size=%zu bits (%zu slots), hashes=%zu, expectedElements=%zu, FPR=%.4f",
                m_size, m_bits.size(), m_numHashes, expectedElements, falsePositiveRate);
        }


        void BloomFilter::Add(uint64_t hash) noexcept {
            // Early exit if not properly initialized
            if (m_bits.empty() || m_size == 0 || m_numHashes == 0) {
                return;
            }

            const size_t bitsSize = m_bits.size();
            for (size_t i = 0; i < m_numHashes; ++i) {
                const uint64_t hashedValue = Hash(hash, i);
                // Guard against division by zero (m_size validated above, but defense in depth)
                const uint64_t bitIndex = (m_size > 0) ? (hashedValue % m_size) : 0;
                const size_t arrayIndex = static_cast<size_t>(bitIndex / 64);
                const size_t bitOffset = static_cast<size_t>(bitIndex % 64);

                // Bounds check for safety (defense in depth)
                if (arrayIndex >= bitsSize) {
                    SS_LOG_ERROR(L"BloomFilter",
                        L"Add: Array index out of bounds: %zu >= %zu",
                        arrayIndex, bitsSize);
                    return;  // Stop processing on invalid state
                }

                const uint64_t mask = 1ULL << bitOffset;

                // Thread-safe atomic set using fetch_or
                m_bits[arrayIndex].fetch_or(mask, std::memory_order_relaxed);
            }
        }

        bool BloomFilter::MightContain(uint64_t hash) const noexcept {
            // Return false if not properly initialized (safe default)
            if (m_bits.empty() || m_size == 0 || m_numHashes == 0) {
                return false;
            }

            const size_t bitsSize = m_bits.size();
            for (size_t i = 0; i < m_numHashes; ++i) {
                const uint64_t hashedValue = Hash(hash, i);
                // Guard against division by zero
                const uint64_t bitIndex = (m_size > 0) ? (hashedValue % m_size) : 0;
                const size_t arrayIndex = static_cast<size_t>(bitIndex / 64);
                const size_t bitOffset = static_cast<size_t>(bitIndex % 64);

                // Bounds check for safety
                if (arrayIndex >= bitsSize) {
                    SS_LOG_ERROR(L"BloomFilter",
                        L"MightContain: Array index out of bounds: %zu >= %zu",
                        arrayIndex, bitsSize);
                    return false;  // Invalid state, return false to be safe
                }

                // Atomic read with relaxed ordering (sufficient for bloom filter)
                const uint64_t word = m_bits[arrayIndex].load(std::memory_order_relaxed);
                if ((word & (1ULL << bitOffset)) == 0) {
                    return false;  // Definitely not present
                }
            }
            return true;  // Might be present (could be false positive)
        }

        void BloomFilter::Clear() noexcept {
            for (auto& w : m_bits) {
                w.store(0ULL, std::memory_order_relaxed);
            }
        }

        double BloomFilter::EstimatedFillRate() const noexcept {
            if (m_bits.empty() || m_size == 0) {
                return 0.0;
            }

            size_t setBits = 0;
            const size_t bitsSize = m_bits.size();
            for (size_t i = 0; i < bitsSize; ++i) {
                const uint64_t word = m_bits[i].load(std::memory_order_relaxed);
                // popcount returns int, safely convert to size_t
                const int popCount = std::popcount(word);
                if (popCount > 0) {
                    // Guard against overflow (extremely unlikely but defensive)
                    if (setBits <= SIZE_MAX - static_cast<size_t>(popCount)) {
                        setBits += static_cast<size_t>(popCount);
                    }
                }
            }
            // Division by zero already guarded above
            return static_cast<double>(setBits) / static_cast<double>(m_size);
        }

        uint64_t BloomFilter::Hash(uint64_t value, size_t seed) const noexcept {
            // FNV-1a hash with seed - deterministic and fast
            uint64_t hash = 14695981039346656037ULL;

            // Mix in seed first
            hash ^= static_cast<uint64_t>(seed);
            hash *= 1099511628211ULL;

            // Process value bytes
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
            for (size_t i = 0; i < sizeof(uint64_t); ++i) {
                hash ^= bytes[i];
                hash *= 1099511628211ULL;
            }

            return hash;
        }





    }
}