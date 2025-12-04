


/**
 * ============================================================================
 * ShadowStrike WhitelistStore - BLOOM FILTER IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * High-performance probabilistic data structure for nanosecond-level
 * negative lookups in whitelist database.
 *
 * Thread Safety:
 * - Add() is thread-safe via atomic OR operations
 * - MightContain() is lock-free and safe for concurrent reads
 * - Clear() requires external synchronization
 *
 * Performance:
 * - Add: O(k) where k = number of hash functions
 * - MightContain: O(k) with early termination on first zero bit
 * - Memory: Configurable from 1MB to 64MB bit array
 *
 * Algorithm:
 * - Uses enhanced double hashing: h(i) = h1(x) + i*h2(x) + i^2
 * - h1 = FNV-1a hash, h2 = MurmurHash3 finalizer
 * - Optimal parameters calculated using theoretical formulas
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
#include <type_traits>

namespace ShadowStrike::Whitelist {

// ============================================================================
// INTERNAL HELPER FUNCTIONS (LOCAL TO THIS TRANSLATION UNIT)
// ============================================================================

namespace {

/**
 * @brief Safely multiply two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only modified on success)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeMul(T a, T b, T& result) noexcept {
    static_assert(std::is_unsigned_v<T>, "SafeMul requires unsigned type");
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a > std::numeric_limits<T>::max() / b) {
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
 * @note Uses compiler intrinsics when available for optimal performance
 */
[[nodiscard]] inline uint32_t PopCount64(uint64_t value) noexcept {
#if defined(_MSC_VER) && defined(_M_X64)
    return static_cast<uint32_t>(__popcnt64(value));
#elif defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_popcountll(value));
#else
    // Portable fallback using parallel bit counting (Hamming weight)
    value = value - ((value >> 1) & 0x5555555555555555ULL);
    value = (value & 0x3333333333333333ULL) + ((value >> 2) & 0x3333333333333333ULL);
    value = (value + (value >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return static_cast<uint32_t>((value * 0x0101010101010101ULL) >> 56);
#endif
}

/// @brief FNV-1a offset basis constant
constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;

/// @brief FNV-1a prime constant
constexpr uint64_t FNV_PRIME = 1099511628211ULL;

} // anonymous namespace

// ============================================================================
// BLOOM FILTER IMPLEMENTATION
// ============================================================================

/**
 * @brief Construct bloom filter with specified parameters
 * 
 * @param expectedElements Expected number of elements (auto-clamped to valid range)
 * @param falsePositiveRate Target FPR in range [0.000001, 0.1] (auto-clamped)
 * 
 * @note Calculates optimal bit count and hash function count based on parameters
 * @note Does NOT allocate memory - call InitializeForBuild() to allocate
 */
BloomFilter::BloomFilter(size_t expectedElements, double falsePositiveRate)
    : m_expectedElements(Clamp(expectedElements, size_t{1}, MAX_BLOOM_EXPECTED_ELEMENTS))
    , m_targetFPR(Clamp(falsePositiveRate, MIN_BLOOM_FPR, MAX_BLOOM_FPR))
{
    CalculateOptimalParameters(m_expectedElements, m_targetFPR);
}

/**
 * @brief Move constructor - transfers ownership of bit array
 * @param other Source bloom filter (left in valid but empty state)
 */
BloomFilter::BloomFilter(BloomFilter&& other) noexcept
    : m_bits(std::move(other.m_bits))
    , m_mappedBits(other.m_mappedBits)
    , m_bitCount(other.m_bitCount)
    , m_numHashes(other.m_numHashes)
    , m_expectedElements(other.m_expectedElements)
    , m_targetFPR(other.m_targetFPR)
    , m_isMemoryMapped(other.m_isMemoryMapped)
    , m_elementsAdded(other.m_elementsAdded.load(std::memory_order_relaxed))
{
    // Clear source to valid empty state (not just partially clear)
    other.m_mappedBits = nullptr;
    other.m_bitCount = 0;
    other.m_numHashes = 0;
    other.m_isMemoryMapped = false;
    other.m_elementsAdded.store(0, std::memory_order_relaxed);
    other.m_expectedElements = 0;
    other.m_targetFPR = MIN_BLOOM_FPR;
}

/**
 * @brief Move assignment operator
 * @param other Source bloom filter
 * @return Reference to this
 */
BloomFilter& BloomFilter::operator=(BloomFilter&& other) noexcept {
    if (this != &other) {
        // Transfer all state
        m_bits = std::move(other.m_bits);
        m_mappedBits = other.m_mappedBits;
        m_bitCount = other.m_bitCount;
        m_numHashes = other.m_numHashes;
        m_expectedElements = other.m_expectedElements;
        m_targetFPR = other.m_targetFPR;
        m_isMemoryMapped = other.m_isMemoryMapped;
        m_elementsAdded.store(other.m_elementsAdded.load(std::memory_order_relaxed), 
                              std::memory_order_relaxed);
        
        // Clear source to valid empty state
        other.m_mappedBits = nullptr;
        other.m_bitCount = 0;
        other.m_numHashes = 0;
        other.m_isMemoryMapped = false;
        other.m_elementsAdded.store(0, std::memory_order_relaxed);
        other.m_expectedElements = 0;
        other.m_targetFPR = MIN_BLOOM_FPR;
    }
    return *this;
}

/**
 * @brief Calculate optimal bloom filter parameters using theoretical formulas
 * 
 * @param expectedElements Expected number of elements to store
 * @param falsePositiveRate Target false positive probability
 * 
 * Mathematical formulas (from probability theory):
 * - Optimal bits (m) = -(n * ln(p)) / (ln(2)^2)
 * - Optimal hash functions (k) = (m/n) * ln(2)
 * 
 * Where n = expected elements, p = target FPR, m = bits, k = hashes
 */
void BloomFilter::CalculateOptimalParameters(size_t expectedElements, double falsePositiveRate) noexcept {
    // Clamp inputs to safe ranges (defensive - should already be clamped)
    if (expectedElements == 0) {
        expectedElements = 1;
    }
    if (expectedElements > MAX_BLOOM_EXPECTED_ELEMENTS) {
        expectedElements = MAX_BLOOM_EXPECTED_ELEMENTS;
    }
    
    // Validate FPR is a valid finite positive number less than 1
    if (falsePositiveRate <= 0.0 || !std::isfinite(falsePositiveRate)) {
        falsePositiveRate = MIN_BLOOM_FPR;
    }
    if (falsePositiveRate >= 1.0) {
        falsePositiveRate = MAX_BLOOM_FPR;
    }
    
    // Calculate optimal number of bits using formula: m = -(n * ln(p)) / (ln(2)^2)
    const double ln2 = std::log(2.0);
    const double ln2Squared = ln2 * ln2;
    const double n = static_cast<double>(expectedElements);
    const double p = falsePositiveRate;
    
    // Compute optimal bits - guard against edge cases
    double optimalBits = -(n * std::log(p)) / ln2Squared;
    
    // Validate calculation result (could be NaN/Inf if inputs are extreme)
    if (!std::isfinite(optimalBits) || optimalBits <= 0.0) {
        optimalBits = static_cast<double>(MIN_BLOOM_BITS);
        SS_LOG_WARN(L"Whitelist", L"BloomFilter: optimal bits calculation invalid, using minimum");
    }
    
    // Cap at reasonable maximum before conversion to prevent overflow
    if (optimalBits > static_cast<double>(MAX_BLOOM_BITS)) {
        optimalBits = static_cast<double>(MAX_BLOOM_BITS);
    }
    
    // Round up to next multiple of 64 for atomic word alignment
    const uint64_t rawBits = static_cast<uint64_t>(std::ceil(optimalBits));
    m_bitCount = ((rawBits + 63ULL) / 64ULL) * 64ULL;
    
    // Clamp to configured range
    m_bitCount = Clamp(m_bitCount, static_cast<size_t>(MIN_BLOOM_BITS), static_cast<size_t>(MAX_BLOOM_BITS));
    
    // Calculate optimal number of hash functions: k = (m/n) * ln(2)
    double k = (static_cast<double>(m_bitCount) / n) * ln2;
    
    // Validate and clamp hash function count
    if (!std::isfinite(k) || k <= 0.0) {
        k = static_cast<double>(DEFAULT_BLOOM_HASH_COUNT);
        SS_LOG_WARN(L"Whitelist", L"BloomFilter: hash function count calculation invalid, using default");
    }
    
    m_numHashes = static_cast<size_t>(std::round(k));
    m_numHashes = Clamp(m_numHashes, MIN_BLOOM_HASHES, MAX_BLOOM_HASHES);
    
    SS_LOG_DEBUG(L"Whitelist", 
        L"BloomFilter configured: %zu bits (%zu KB), %zu hash functions, expected %zu elements, target FPR %.6f",
        m_bitCount, m_bitCount / 8 / 1024, m_numHashes, expectedElements, falsePositiveRate);
}

/**
 * @brief Initialize bloom filter from memory-mapped region (read-only mode)
 * 
 * @param data Pointer to bloom filter bit array (must remain valid for lifetime)
 * @param bitCount Number of bits in the filter
 * @param hashFunctions Number of hash functions used
 * @return True if initialization succeeded
 * 
 * @note Does NOT take ownership of the memory
 * @note Filter becomes read-only (Add() will be no-op)
 */
bool BloomFilter::Initialize(const void* data, size_t bitCount, size_t hashFunctions) noexcept {
    // Validate data pointer
    if (!data) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: null data pointer");
        return false;
    }
    
    // Validate bit count is within allowed range
    if (bitCount == 0) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: zero bit count");
        return false;
    }
    
    if (bitCount > MAX_BLOOM_BITS) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: bit count %zu exceeds max %zu",
            bitCount, MAX_BLOOM_BITS);
        return false;
    }
    
    // Validate bit count is multiple of 64 (word-aligned)
    if (bitCount % 64 != 0) {
        SS_LOG_WARN(L"Whitelist", L"BloomFilter::Initialize: bit count %zu not 64-aligned, rounding down",
            bitCount);
        bitCount = (bitCount / 64) * 64;
        if (bitCount == 0) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: adjusted bit count is zero");
            return false;
        }
    }
    
    // Validate hash function count
    if (hashFunctions < MIN_BLOOM_HASHES || hashFunctions > MAX_BLOOM_HASHES) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: hash functions %zu out of range [%zu, %zu]",
            hashFunctions, MIN_BLOOM_HASHES, MAX_BLOOM_HASHES);
        return false;
    }
    
    // Clear any existing local storage to free memory
    m_bits.clear();
    m_bits.shrink_to_fit();
    
    // Set up memory-mapped mode
    m_mappedBits = static_cast<const uint64_t*>(data);
    m_bitCount = bitCount;
    m_numHashes = hashFunctions;
    m_isMemoryMapped = true;
    m_elementsAdded.store(0, std::memory_order_relaxed);  // Unknown for mapped filter
    
    SS_LOG_DEBUG(L"Whitelist", 
        L"BloomFilter initialized from memory-mapped region: %zu bits (%zu KB), %zu hash functions",
        m_bitCount, m_bitCount / 8 / 1024, m_numHashes);
    
    return true;
}

/**
 * @brief Initialize bloom filter for building (allocates internal memory)
 * 
 * @return True if allocation succeeded, false on out-of-memory
 * 
 * @note Call after constructor to allocate the bit array
 * @note All bits are initialized to zero
 */
bool BloomFilter::InitializeForBuild() noexcept {
    try {
        // Reset to non-memory-mapped mode
        m_isMemoryMapped = false;
        m_mappedBits = nullptr;
        
        // Calculate word count (64 bits per word)
        const size_t wordCount = (m_bitCount + 63ULL) / 64ULL;
        
        // Validate allocation size won't be excessive
        constexpr size_t MAX_WORD_COUNT = MAX_BLOOM_BITS / 64ULL;
        if (wordCount > MAX_WORD_COUNT) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::InitializeForBuild: word count %zu exceeds max %zu",
                wordCount, MAX_WORD_COUNT);
            return false;
        }
        
        // Validate allocation won't exhaust memory (each word is 8 bytes for atomic<uint64_t>)
        constexpr size_t MAX_ALLOC_BYTES = 128ULL * 1024 * 1024;  // 128MB limit
        const size_t allocBytes = wordCount * sizeof(std::atomic<uint64_t>);
        if (allocBytes > MAX_ALLOC_BYTES) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::InitializeForBuild: allocation %zu bytes exceeds limit",
                allocBytes);
            return false;
        }
        
        // Clear and allocate bit array
        m_bits.clear();
        m_bits.resize(wordCount);
        
        // Zero all bits explicitly (resize should zero-init, but be explicit for security)
        for (auto& word : m_bits) {
            word.store(0, std::memory_order_relaxed);
        }
        
        m_elementsAdded.store(0, std::memory_order_relaxed);
        
        SS_LOG_DEBUG(L"Whitelist", 
            L"BloomFilter allocated for building: %zu bits (%zu KB), %zu words",
            m_bitCount, m_bitCount / 8 / 1024, wordCount);
        
        return true;
        
    } catch (const std::bad_alloc& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::InitializeForBuild: allocation failed - %S", e.what());
        m_bits.clear();
        return false;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::InitializeForBuild failed: %S", e.what());
        m_bits.clear();
        return false;
    }
}

uint64_t BloomFilter::Hash(uint64_t value, size_t seed) const noexcept {
    /*
     * ========================================================================
     * DOUBLE HASHING SCHEME FOR BLOOM FILTER
     * ========================================================================
     *
     * Uses enhanced double hashing: h(i) = h1(x) + i * h2(x) + i^2
     * This provides better distribution than simple double hashing.
     *
     * h1 = FNV-1a hash
     * h2 = MurmurHash3 finalizer
     *
     * ========================================================================
     */
    
    // FNV-1a as h1
    uint64_t h1 = 14695981039346656037ULL;  // FNV offset basis
    uint64_t data = value;
    
    for (int i = 0; i < 8; ++i) {
        h1 ^= (data & 0xFFULL);
        h1 *= 1099511628211ULL;  // FNV prime
        data >>= 8;
    }
    
    // MurmurHash3 finalizer as h2
    uint64_t h2 = value;
    h2 ^= h2 >> 33;
    h2 *= 0xff51afd7ed558ccdULL;
    h2 ^= h2 >> 33;
    h2 *= 0xc4ceb9fe1a85ec53ULL;
    h2 ^= h2 >> 33;
    
    // Enhanced double hashing with quadratic probing
    // h(i) = h1 + i * h2 + i^2
    const uint64_t seedVal = static_cast<uint64_t>(seed);
    const uint64_t seedSq = seedVal * seedVal;  // Safe: seed < 16, so max is 225
    
    return h1 + seedVal * h2 + seedSq;
}

void BloomFilter::Add(uint64_t hash) noexcept {
    /*
     * ========================================================================
     * THREAD-SAFE BLOOM FILTER INSERT
     * ========================================================================
     *
     * Uses atomic OR operations for thread-safety without locks.
     * Memory ordering is relaxed since bloom filter tolerates races.
     * False negatives are impossible, false positives only increase slightly.
     *
     * ========================================================================
     */
    
    // Cannot modify memory-mapped bloom filter
    if (m_isMemoryMapped) {
        SS_LOG_WARN(L"Whitelist", L"Cannot add to memory-mapped bloom filter");
        return;
    }
    
    // Validate state
    if (m_bits.empty() || m_bitCount == 0 || m_numHashes == 0) {
        SS_LOG_DEBUG(L"Whitelist", L"BloomFilter::Add called on uninitialized filter");
        return;
    }
    
    const size_t wordCount = m_bits.size();
    
    // Set bits for each hash function
    for (size_t i = 0; i < m_numHashes; ++i) {
        const uint64_t h = Hash(hash, i);
        const size_t bitIndex = static_cast<size_t>(h % m_bitCount);
        const size_t wordIndex = bitIndex / 64ULL;
        const size_t bitOffset = bitIndex % 64ULL;
        
        // Bounds check (should never fail with correct m_bitCount)
        if (wordIndex >= wordCount) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Add: word index out of bounds");
            continue;
        }
        
        const uint64_t mask = 1ULL << bitOffset;
        
        // Atomic OR - relaxed ordering is fine for bloom filter
        m_bits[wordIndex].fetch_or(mask, std::memory_order_relaxed);
    }
    
    m_elementsAdded.fetch_add(1, std::memory_order_relaxed);
}

bool BloomFilter::MightContain(uint64_t hash) const noexcept {
    /*
     * ========================================================================
     * NANOSECOND-LEVEL BLOOM FILTER LOOKUP
     * ========================================================================
     *
     * Optimized for minimal cache misses:
     * - Early termination on first zero bit
     * - Memory access patterns designed for prefetching
     *
     * ========================================================================
     */
    
    // Get pointer to bit array
    const uint64_t* bits = nullptr;
    size_t wordCount = 0;
    
    if (m_isMemoryMapped) {
        bits = m_mappedBits;
        wordCount = (m_bitCount + 63ULL) / 64ULL;
    } else if (!m_bits.empty()) {
        // Note: We read atomics directly for performance in const method
        bits = reinterpret_cast<const uint64_t*>(m_bits.data());
        wordCount = m_bits.size();
    }
    
    // If not initialized, return true (conservative - assume might contain)
    if (!bits || m_bitCount == 0 || m_numHashes == 0) {
        return true;
    }
    
    // Check all hash positions
    for (size_t i = 0; i < m_numHashes; ++i) {
        const uint64_t h = Hash(hash, i);
        const size_t bitIndex = static_cast<size_t>(h % m_bitCount);
        const size_t wordIndex = bitIndex / 64ULL;
        const size_t bitOffset = bitIndex % 64ULL;
        
        // Bounds check
        if (wordIndex >= wordCount) {
            // Corrupt state - return conservative result
            return true;
        }
        
        const uint64_t mask = 1ULL << bitOffset;
        
        // Read word (atomic for owned bits, direct for mapped)
        uint64_t word;
        if (m_isMemoryMapped) {
            word = bits[wordIndex];
        } else {
            word = m_bits[wordIndex].load(std::memory_order_relaxed);
        }
        
        if ((word & mask) == 0) {
            return false;  // Definitely not in set
        }
    }
    
    return true;  // Might be in set (could be false positive)
}

void BloomFilter::Clear() noexcept {
    if (m_isMemoryMapped) {
        SS_LOG_WARN(L"Whitelist", L"Cannot clear memory-mapped bloom filter");
        return;
    }
    
    // Zero all bits
    for (auto& word : m_bits) {
        word.store(0, std::memory_order_relaxed);
    }
    
    m_elementsAdded.store(0, std::memory_order_relaxed);
}

bool BloomFilter::Serialize(std::vector<uint8_t>& data) const {
    // Cannot serialize memory-mapped filter (already persisted)
    if (m_isMemoryMapped) {
        SS_LOG_WARN(L"Whitelist", L"Cannot serialize memory-mapped bloom filter");
        return false;
    }
    
    if (m_bits.empty()) {
        SS_LOG_WARN(L"Whitelist", L"Cannot serialize empty bloom filter");
        return false;
    }
    
    try {
        // Calculate byte count with overflow check
        uint64_t byteCount;
        if (!SafeMul(static_cast<uint64_t>(m_bits.size()), 
                     static_cast<uint64_t>(sizeof(uint64_t)), 
                     byteCount)) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: size overflow");
            return false;
        }
        
        // Sanity check
        if (byteCount > MAX_BLOOM_BITS / 8) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: size too large");
            return false;
        }
        
        data.resize(static_cast<size_t>(byteCount));
        
        // Copy atomic values
        for (size_t i = 0; i < m_bits.size(); ++i) {
            const uint64_t value = m_bits[i].load(std::memory_order_relaxed);
            std::memcpy(data.data() + i * sizeof(uint64_t), &value, sizeof(uint64_t));
        }
        
        return true;
        
    } catch (const std::bad_alloc& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: allocation failed - %S", e.what());
        return false;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize failed: %S", e.what());
        return false;
    }
}

double BloomFilter::EstimatedFillRate() const noexcept {
    if (m_bitCount == 0) {
        return 0.0;
    }
    
    // Get pointer to bits
    const uint64_t* bits = nullptr;
    size_t wordCount = 0;
    
    if (m_isMemoryMapped) {
        bits = m_mappedBits;
        wordCount = (m_bitCount + 63ULL) / 64ULL;
    } else if (!m_bits.empty()) {
        bits = reinterpret_cast<const uint64_t*>(m_bits.data());
        wordCount = m_bits.size();
    }
    
    if (!bits || wordCount == 0) {
        return 0.0;
    }
    
    // Count set bits using population count
    uint64_t setBits = 0;
    
    for (size_t i = 0; i < wordCount; ++i) {
        uint64_t word;
        if (m_isMemoryMapped) {
            word = bits[i];
        } else {
            word = m_bits[i].load(std::memory_order_relaxed);
        }
        setBits += PopCount64(word);
    }
    
    return static_cast<double>(setBits) / static_cast<double>(m_bitCount);
}

double BloomFilter::EstimatedFalsePositiveRate() const noexcept {
    const double fillRate = EstimatedFillRate();
    
    // Validate inputs for pow calculation
    if (fillRate <= 0.0 || fillRate >= 1.0) {
        return (fillRate >= 1.0) ? 1.0 : 0.0;
    }
    
    // FPR ≈ (fill rate)^k where k is number of hash functions
    const double fpr = std::pow(fillRate, static_cast<double>(m_numHashes));
    
    // Clamp result to valid range
    return Clamp(fpr, 0.0, 1.0);
}


}