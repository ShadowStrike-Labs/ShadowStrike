// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
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
 * - BatchAdd()/BatchQuery() are thread-safe
 *
 * Performance:
 * - Add: O(k) where k = number of hash functions
 * - MightContain: O(k) with early termination on first zero bit
 * - BatchAdd: O(n*k) with cache-optimized access patterns
 * - Memory: Configurable from 1MB to 64MB bit array
 *
 * Algorithm:
 * - Uses enhanced double hashing: h(i) = h1(x) + i*h2(x) + i^2
 * - h1 = FNV-1a hash, h2 = MurmurHash3 finalizer
 * - Optimal parameters calculated using theoretical formulas
 *
 * Security Hardening:
 * - All arithmetic operations checked for overflow
 * - Bounds validation on all array accesses
 * - Input validation with defensive defaults
 * - Memory zeroing on clear for security
 *
 * ============================================================================
 */

#include "WhiteListStore.hpp"
#include "WhiteListFormat.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <climits>
#include <type_traits>
#include <bit>

// Platform-specific intrinsics for SIMD and popcount
#if defined(_MSC_VER)
    #include <intrin.h>
    #include <immintrin.h>
#elif defined(__GNUC__) || defined(__clang__)
    #include <x86intrin.h>
#endif

namespace ShadowStrike::Whitelist {

// ============================================================================
// COMPILE-TIME CONSTANTS (Internal)
// ============================================================================

namespace {

/// @brief FNV-1a offset basis constant
constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;

/// @brief FNV-1a prime constant
constexpr uint64_t FNV_PRIME = 1099511628211ULL;

/// @brief MurmurHash3 constant 1
constexpr uint64_t MURMUR_C1 = 0xff51afd7ed558ccdULL;

/// @brief MurmurHash3 constant 2
constexpr uint64_t MURMUR_C2 = 0xc4ceb9fe1a85ec53ULL;

/// @brief Cache line size for alignment
constexpr size_t CACHE_LINE_SIZE = 64;

/// @brief Maximum allocation size (128MB safety limit)
constexpr size_t MAX_ALLOC_BYTES = 128ULL * 1024 * 1024;

/// @brief Prefetch distance for batch operations
constexpr size_t PREFETCH_DISTANCE = 8;

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Safely multiply two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only modified on success)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] constexpr bool SafeMul(T a, T b, T& result) noexcept {
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
 * @brief Safely add two sizes with overflow check
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only modified on success)
 * @return True if addition succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] constexpr bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_unsigned_v<T>, "SafeAdd requires unsigned type");
    if (a > std::numeric_limits<T>::max() - b) {
        return false;  // Would overflow
    }
    result = a + b;
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
 * @brief Clamp floating point value with NaN/Inf handling
 * @param value Value to clamp (may be NaN or Inf)
 * @param minVal Minimum allowed value
 * @param maxVal Maximum allowed value
 * @return Clamped value (NaN/Inf mapped to minVal)
 */
[[nodiscard]] inline double ClampDouble(double value, double minVal, double maxVal) noexcept {
    // Handle NaN and Inf - map to minimum value for safety
    if (!std::isfinite(value)) {
        return minVal;
    }
    return (value < minVal) ? minVal : ((value > maxVal) ? maxVal : value);
}

/**
 * @brief Population count (number of set bits) for 64-bit integer
 * @param value Input value
 * @return Number of bits set to 1
 * @note Uses compiler intrinsics when available for optimal performance
 */
[[nodiscard]] inline uint32_t PopCount64(uint64_t value) noexcept {
#if defined(__cpp_lib_bitops) && __cpp_lib_bitops >= 201907L
    // C++20 standard library popcount
    return static_cast<uint32_t>(std::popcount(value));
#elif defined(_MSC_VER) && defined(_M_X64)
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

/**
 * @brief Prefetch memory location for future read
 * @param ptr Pointer to prefetch
 */
inline void PrefetchRead(const void* ptr) noexcept {
#if defined(_MSC_VER)
    _mm_prefetch(static_cast<const char*>(ptr), _MM_HINT_T0);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(ptr, 0, 3);  // Read access, high temporal locality
#endif
}

/**
 * @brief Prefetch memory location for future write
 * @param ptr Pointer to prefetch
 */
inline void PrefetchWrite(void* ptr) noexcept {
#if defined(_MSC_VER)
    _mm_prefetch(static_cast<const char*>(ptr), _MM_HINT_T0);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin_prefetch(ptr, 1, 3);  // Write access, high temporal locality
#endif
}

/**
 * @brief Validate that a pointer and size represent a valid memory region
 * @param ptr Pointer to validate
 * @param size Size in bytes
 * @return True if valid, false otherwise
 */
[[nodiscard]] inline bool ValidateMemoryRegion(const void* ptr, size_t size) noexcept {
    if (!ptr) return false;
    if (size == 0) return false;
    if (size > MAX_ALLOC_BYTES) return false;
    
    // Check for pointer alignment (should be at least 8-byte aligned for uint64_t)
    if (reinterpret_cast<uintptr_t>(ptr) % alignof(uint64_t) != 0) {
        return false;
    }
    
    return true;
}

/**
 * @brief Secure memory zeroing that won't be optimized away
 * @param ptr Pointer to memory
 * @param size Size in bytes
 */
inline void SecureZero(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, size);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    // Memory barrier to prevent reordering
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

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
    , m_targetFPR(ClampDouble(falsePositiveRate, MIN_BLOOM_FPR, MAX_BLOOM_FPR))
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
    
    // Calculate required data size and validate memory region
    const size_t wordCount = (bitCount + 63ULL) / 64ULL;
    const size_t requiredBytes = wordCount * sizeof(uint64_t);
    if (!ValidateMemoryRegion(data, requiredBytes)) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Initialize: invalid memory region (size=%zu, alignment issue or exceeds limit)", requiredBytes);
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
    std::vector<std::atomic<uint64_t>> empty;
    m_bits.swap(empty);
    
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
        // Uses MAX_ALLOC_BYTES from anonymous namespace (128MB limit)
        const size_t allocBytes = wordCount * sizeof(std::atomic<uint64_t>);
        if (allocBytes > MAX_ALLOC_BYTES) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::InitializeForBuild: allocation %zu bytes exceeds limit",
                allocBytes);
            return false;
        }
        
        // Clear and allocate bit array
        std::vector<std::atomic<uint64_t>> newBits(wordCount);

        
        // Zero all bits explicitly (resize should zero-init, but be explicit for security)
        for (size_t i = 0; i < wordCount; ++i) {
            newBits[i].store(0, std::memory_order_relaxed);
        }
        m_bits.swap(newBits);
        
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
     * ENHANCED DOUBLE HASHING SCHEME FOR BLOOM FILTER
     * ========================================================================
     *
     * Uses enhanced double hashing: h(i) = h1(x) + i * h2(x) + i^2
     * This provides better distribution than simple double hashing and
     * eliminates clustering issues at higher seed values.
     *
     * h1 = FNV-1a hash (excellent distribution, fast)
     * h2 = MurmurHash3 finalizer (strong avalanche effect)
     *
     * The quadratic term (i^2) breaks up linear patterns that could
     * cause hash collisions to cluster.
     *
     * ========================================================================
     */
    
    // FNV-1a as h1 - process all 8 bytes
    uint64_t h1 = FNV_OFFSET_BASIS;
    
    // Unrolled loop for performance (8 bytes)
    h1 ^= (value & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 8) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 16) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 24) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 32) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 40) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 48) & 0xFFULL);
    h1 *= FNV_PRIME;
    h1 ^= ((value >> 56) & 0xFFULL);
    h1 *= FNV_PRIME;
    
    // MurmurHash3 64-bit finalizer as h2
    // Provides excellent avalanche effect - single bit change affects all output bits
    uint64_t h2 = value;
    h2 ^= h2 >> 33;
    h2 *= MURMUR_C1;
    h2 ^= h2 >> 33;
    h2 *= MURMUR_C2;
    h2 ^= h2 >> 33;
    
    // Enhanced double hashing with quadratic probing
    // h(i) = h1 + i * h2 + i^2
    // Note: seed is guaranteed to be < MAX_BLOOM_HASHES (16) so i^2 is at most 225
    const uint64_t i = static_cast<uint64_t>(seed);
    const uint64_t iSquared = i * i;  // Safe: max value is 225
    
    return h1 + (i * h2) + iSquared;
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
     * Optimization: Pre-compute all bit positions before touching memory
     * to improve cache utilization.
     *
     * ========================================================================
     */
    
    // Cannot modify memory-mapped bloom filter
    if (m_isMemoryMapped) [[unlikely]] {
        return;
    }
    
    // Validate state - fast path for common case
    if (m_bits.empty() || m_bitCount == 0 || m_numHashes == 0) [[unlikely]] {
        return;
    }
    
    const size_t wordCount = m_bits.size();
    const size_t bitCountLocal = m_bitCount;  // Cache for tight loop
    const size_t numHashesLocal = m_numHashes;
    
    // Pre-compute all hash positions for better cache behavior
    // Stack allocation for small arrays (max 16 hashes)
    struct BitPosition {
        size_t wordIndex;
        uint64_t mask;
    };
    
    BitPosition positions[MAX_BLOOM_HASHES];
    
    for (size_t i = 0; i < numHashesLocal; ++i) {
        const uint64_t h = Hash(hash, i);
        const size_t bitIndex = static_cast<size_t>(h % bitCountLocal);
        positions[i].wordIndex = bitIndex / 64ULL;
        positions[i].mask = 1ULL << (bitIndex % 64ULL);
    }
    
    // Now apply all bits - potentially better cache behavior
    for (size_t i = 0; i < numHashesLocal; ++i) {
        const size_t wordIndex = positions[i].wordIndex;
        
        // Bounds check (should never fail with correct m_bitCount)
        if (wordIndex >= wordCount) [[unlikely]] {
            continue;
        }
        
        // Atomic OR - relaxed ordering is sufficient for bloom filter
        m_bits[wordIndex].fetch_or(positions[i].mask, std::memory_order_relaxed);
    }
    
    m_elementsAdded.fetch_add(1, std::memory_order_relaxed);
}

bool BloomFilter::MightContain(uint64_t hash) const noexcept {
    /*
     * ========================================================================
     * NANOSECOND-LEVEL BLOOM FILTER LOOKUP (OPTIMIZED)
     * ========================================================================
     *
     * Optimized for minimal latency:
     * - Early termination on first zero bit (most common case for negative)
     * - Prefetching for better cache behavior
     * - Minimal branching in hot path
     * - Direct memory access for memory-mapped case
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
        // Direct memory access to atomic storage for read-only operation
        // This is safe because we only read, and atomic<T> has same layout as T
        bits = reinterpret_cast<const uint64_t*>(m_bits.data());
        wordCount = m_bits.size();
    }
    
    // If not initialized, return true (conservative - assume might contain)
    if (!bits || m_bitCount == 0 || m_numHashes == 0) [[unlikely]] {
        return true;
    }
    
    const size_t bitCountLocal = m_bitCount;
    const size_t numHashesLocal = m_numHashes;
    
    // Prefetch first likely word
    const uint64_t firstH = Hash(hash, 0);
    const size_t firstWordIdx = static_cast<size_t>((firstH % bitCountLocal) / 64ULL);
    if (firstWordIdx < wordCount) {
        PrefetchRead(&bits[firstWordIdx]);
    }
    
    // Check all hash positions with early termination
    for (size_t i = 0; i < numHashesLocal; ++i) {
        const uint64_t h = Hash(hash, i);
        const size_t bitIndex = static_cast<size_t>(h % bitCountLocal);
        const size_t wordIndex = bitIndex / 64ULL;
        const size_t bitOffset = bitIndex % 64ULL;
        
        // Bounds check
        if (wordIndex >= wordCount) [[unlikely]] {
            // Corrupt state - return conservative result
            return true;
        }
        
        // Prefetch next word for better pipelining
        if (i + 1 < numHashesLocal) {
            const uint64_t nextH = Hash(hash, i + 1);
            const size_t nextWordIdx = static_cast<size_t>((nextH % bitCountLocal) / 64ULL);
            if (nextWordIdx < wordCount) {
                PrefetchRead(&bits[nextWordIdx]);
            }
        }
        
        const uint64_t mask = 1ULL << bitOffset;
        const uint64_t word = bits[wordIndex];
        
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
    
    if (m_bits.empty()) {
        return;
    }
    
    // Zero all bits using atomic stores for thread-safety
    // Note: We use relaxed ordering for performance since we issue a release fence below
    for (auto& word : m_bits) {
        word.store(0, std::memory_order_relaxed);
    }
    
    // Memory barrier to ensure all atomic writes are visible before any subsequent reads
    // This prevents reordering and ensures visibility across threads
    std::atomic_thread_fence(std::memory_order_release);
    
    m_elementsAdded.store(0, std::memory_order_relaxed);
    
    SS_LOG_DEBUG(L"Whitelist", L"BloomFilter cleared: %zu bits", m_bitCount);
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
        uint64_t byteCount = 0;
        if (!SafeMul(static_cast<uint64_t>(m_bits.size()), 
                     static_cast<uint64_t>(sizeof(uint64_t)), 
                     byteCount)) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: size overflow");
            return false;
        }
        
        // Sanity check against maximum allowed size
        if (byteCount > MAX_BLOOM_BITS / 8) {
            SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: size %llu exceeds max", byteCount);
            return false;
        }
        
        // Pre-allocate to avoid multiple reallocations
        data.clear();
        data.reserve(static_cast<size_t>(byteCount));
        data.resize(static_cast<size_t>(byteCount));
        
        // Copy atomic values with memory barrier for consistency
        std::atomic_thread_fence(std::memory_order_acquire);
        
        uint8_t* dest = data.data();
        for (size_t i = 0; i < m_bits.size(); ++i) {
            const uint64_t value = m_bits[i].load(std::memory_order_relaxed);
            std::memcpy(dest + i * sizeof(uint64_t), &value, sizeof(uint64_t));
        }
        
        SS_LOG_DEBUG(L"Whitelist", L"BloomFilter serialized: %zu bytes", data.size());
        return true;
        
    } catch (const std::bad_alloc& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize: allocation failed - %S", e.what());
        data.clear();
        return false;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"BloomFilter::Serialize failed: %S", e.what());
        data.clear();
        return false;
    }
}

double BloomFilter::EstimatedFillRate() const noexcept {
    if (m_bitCount == 0) {
        return 0.0;
    }
    
    // Acquire fence to ensure we see consistent state from concurrent Add() operations
    // This is important for accurate fill rate calculation during concurrent access
    std::atomic_thread_fence(std::memory_order_acquire);
    
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
    
    // Count set bits using population count with SIMD-friendly loop
    uint64_t setBits = 0;
    
    // Process in batches of 4 for better instruction pipelining
    const size_t batchCount = wordCount / 4;
    size_t i = 0;
    
    for (size_t batch = 0; batch < batchCount; ++batch) {
        uint64_t w0, w1, w2, w3;
        if (m_isMemoryMapped) {
            w0 = bits[i];
            w1 = bits[i + 1];
            w2 = bits[i + 2];
            w3 = bits[i + 3];
        } else {
            w0 = m_bits[i].load(std::memory_order_relaxed);
            w1 = m_bits[i + 1].load(std::memory_order_relaxed);
            w2 = m_bits[i + 2].load(std::memory_order_relaxed);
            w3 = m_bits[i + 3].load(std::memory_order_relaxed);
        }
        setBits += PopCount64(w0) + PopCount64(w1) + PopCount64(w2) + PopCount64(w3);
        i += 4;
    }
    
    // Handle remaining words
    for (; i < wordCount; ++i) {
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
    
    // Edge case handling
    if (fillRate <= 0.0) {
        return 0.0;  // Empty filter has 0% FPR
    }
    if (fillRate >= 1.0) {
        return 1.0;  // Full filter has 100% FPR
    }
    if (m_numHashes == 0) {
        return 1.0;  // Invalid state
    }
    
    // FPR ≈ (fill rate)^k where k is number of hash functions
    // Using std::pow is safe here since fillRate is in (0, 1) and k > 0
    const double fpr = std::pow(fillRate, static_cast<double>(m_numHashes));
    
    // Clamp result to valid range (handles any floating point edge cases)
    return Clamp(fpr, 0.0, 1.0);
}

// ============================================================================
// BATCH OPERATIONS (Enterprise Feature)
// ============================================================================

/**
 * @brief Add multiple elements efficiently
 * @param hashes Span of hash values to add
 * @return Number of elements successfully added
 * @note Thread-safe, uses cache-optimized access patterns
 */
size_t BloomFilter::BatchAdd(std::span<const uint64_t> hashes) noexcept {
    if (m_isMemoryMapped || m_bits.empty() || m_bitCount == 0 || m_numHashes == 0) {
        return 0;
    }
    
    if (hashes.empty()) {
        return 0;
    }
    
    const size_t count = hashes.size();
    const size_t wordCount = m_bits.size();
    const size_t bitCountLocal = m_bitCount;
    const size_t numHashesLocal = m_numHashes;
    
    // Process with prefetching
    for (size_t idx = 0; idx < count; ++idx) {
        // Prefetch next hash's first bit position
        if (idx + PREFETCH_DISTANCE < count) {
            const uint64_t prefetchHash = Hash(hashes[idx + PREFETCH_DISTANCE], 0);
            const size_t prefetchWord = static_cast<size_t>((prefetchHash % bitCountLocal) / 64ULL);
            if (prefetchWord < wordCount) {
                PrefetchWrite(&m_bits[prefetchWord]);
            }
        }
        
        const uint64_t hash = hashes[idx];
        
        // Set bits for each hash function
        for (size_t i = 0; i < numHashesLocal; ++i) {
            const uint64_t h = Hash(hash, i);
            const size_t bitIndex = static_cast<size_t>(h % bitCountLocal);
            const size_t wordIndex = bitIndex / 64ULL;
            
            if (wordIndex < wordCount) {
                const uint64_t mask = 1ULL << (bitIndex % 64ULL);
                m_bits[wordIndex].fetch_or(mask, std::memory_order_relaxed);
            }
        }
    }
    
    m_elementsAdded.fetch_add(count, std::memory_order_relaxed);
    return count;
}

/**
 * @brief Query multiple elements efficiently
 * @param hashes Span of hash values to query
 * @param results Output span for results (true = might contain, false = definitely not)
 * @return Number of elements that might be contained (positive results)
 * @note Thread-safe, uses prefetching for better cache behavior
 */
size_t BloomFilter::BatchQuery(
    std::span<const uint64_t> hashes,
    std::span<bool> results
) const noexcept {
    if (hashes.size() != results.size()) {
        return 0;
    }
    
    // Get pointer to bit array
    const uint64_t* bits = nullptr;
    size_t wordCount = 0;
    
    if (m_isMemoryMapped) {
        bits = m_mappedBits;
        wordCount = (m_bitCount + 63ULL) / 64ULL;
    } else if (!m_bits.empty()) {
        bits = reinterpret_cast<const uint64_t*>(m_bits.data());
        wordCount = m_bits.size();
    }
    
    // Uninitialized filter - all results are conservative true
    if (!bits || m_bitCount == 0 || m_numHashes == 0) {
        std::fill(results.begin(), results.end(), true);
        return hashes.size();
    }
    
    const size_t count = hashes.size();
    const size_t bitCountLocal = m_bitCount;
    const size_t numHashesLocal = m_numHashes;
    
    size_t positiveCount = 0;
    
    for (size_t idx = 0; idx < count; ++idx) {
        // Prefetch ahead
        if (idx + PREFETCH_DISTANCE < count) {
            const uint64_t prefetchHash = Hash(hashes[idx + PREFETCH_DISTANCE], 0);
            const size_t prefetchWord = static_cast<size_t>((prefetchHash % bitCountLocal) / 64ULL);
            if (prefetchWord < wordCount) {
                PrefetchRead(&bits[prefetchWord]);
            }
        }
        
        const uint64_t hash = hashes[idx];
        bool mightContain = true;
        
        // Check all hash positions with early termination
        for (size_t i = 0; i < numHashesLocal && mightContain; ++i) {
            const uint64_t h = Hash(hash, i);
            const size_t bitIndex = static_cast<size_t>(h % bitCountLocal);
            const size_t wordIndex = bitIndex / 64ULL;
            
            if (wordIndex >= wordCount) {
                continue;  // Treat as might contain for safety
            }
            
            const uint64_t mask = 1ULL << (bitIndex % 64ULL);
            const uint64_t word = bits[wordIndex];
            
            if ((word & mask) == 0) {
                mightContain = false;
            }
        }
        
        results[idx] = mightContain;
        if (mightContain) {
            ++positiveCount;
        }
    }
    
    return positiveCount;
}

/**
 * @brief Get detailed statistics about the bloom filter
 * @return Statistics structure with all metrics
 */
BloomFilterStats BloomFilter::GetDetailedStats() const noexcept {
    BloomFilterStats stats{};
    
    stats.bitCount = m_bitCount;
    stats.hashFunctions = m_numHashes;
    stats.expectedElements = m_expectedElements;
    stats.elementsAdded = m_elementsAdded.load(std::memory_order_relaxed);
    stats.targetFPR = m_targetFPR;
    stats.isMemoryMapped = m_isMemoryMapped;
    stats.isReady = IsReady();
    
    // Calculate memory usage
    if (m_isMemoryMapped) {
        stats.memoryBytes = 0;  // Memory is external
        stats.allocatedBytes = 0;
    } else {
        stats.memoryBytes = m_bits.size() * sizeof(std::atomic<uint64_t>);
        stats.allocatedBytes = m_bits.capacity() * sizeof(std::atomic<uint64_t>);
    }
    
    // Compute fill rate and estimated FPR
    stats.fillRate = EstimatedFillRate();
    stats.estimatedFPR = EstimatedFalsePositiveRate();
    
    // Compute load factor (elements added vs expected)
    if (m_expectedElements > 0) {
        stats.loadFactor = static_cast<double>(stats.elementsAdded) / 
                          static_cast<double>(m_expectedElements);
    } else {
        stats.loadFactor = 0.0;
    }
    
    return stats;
}

} // namespace ShadowStrike::Whitelist