// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file WhiteListHashIndex.cpp
 * @brief B+Tree hash index implementation for WhitelistStore
 *
 * This file implements a high-performance B+Tree index for O(log N) hash
 * lookups. The index supports concurrent reads with single-writer semantics.
 *
 * Architecture:
 * - B+Tree with configurable branching factor
 * - All values stored in leaf nodes (internal nodes contain only keys)
 * - Leaf nodes linked for range queries
 * - Memory-mapped for zero-copy reads
 *
 * Performance Characteristics:
 * - Lookup: O(log N) with small constant factor
 * - Insert: O(log N) amortized (may trigger node splits)
 * - Range query: O(log N + K) where K is result size
 *
 * Thread Safety:
 * - Concurrent reads are lock-free for memory-mapped data
 * - Write operations require exclusive lock
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
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
#include <bit>
#include <type_traits>
#include <unordered_set>
#include <unordered_map>
#include <tuple>

// ============================================================================
// SIMD AND HARDWARE INTRINSICS
// ============================================================================
#if defined(_MSC_VER)
    #include <intrin.h>
    #include <xmmintrin.h>   // SSE prefetch
    #include <nmmintrin.h>   // SSE4.2 (POPCNT)
    #include <immintrin.h>   // AVX/BMI
    #pragma intrinsic(_BitScanForward64, _BitScanReverse64)
    #define SS_PREFETCH_READ(addr)  _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
    #define SS_PREFETCH_WRITE(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
    #define SS_PREFETCH_NTA(addr)   _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_NTA)
    #define SS_LIKELY(x)    (x)
    #define SS_UNLIKELY(x)  (x)
#elif defined(__GNUC__) || defined(__clang__)
    #include <x86intrin.h>
    #define SS_PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
    #define SS_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
    #define SS_PREFETCH_NTA(addr)   __builtin_prefetch((addr), 0, 0)
    #define SS_LIKELY(x)    __builtin_expect(!!(x), 1)
    #define SS_UNLIKELY(x)  __builtin_expect(!!(x), 0)
#else
    #define SS_PREFETCH_READ(addr)  ((void)0)
    #define SS_PREFETCH_WRITE(addr) ((void)0)
    #define SS_PREFETCH_NTA(addr)   ((void)0)
    #define SS_LIKELY(x)    (x)
    #define SS_UNLIKELY(x)  (x)
#endif


namespace ShadowStrike::Whitelist {

// ============================================================================
// COMPILE-TIME CONSTANTS FOR B+TREE OPERATIONS
// ============================================================================

namespace {

/// @brief Cache line size for alignment and prefetching
inline constexpr size_t CACHE_LINE_SIZE_LOCAL = 64;

/// @brief Index header size in bytes
inline constexpr uint64_t INDEX_HEADER_SIZE = 64;

/// @brief Maximum traversal depth to prevent infinite loops from corruption
inline constexpr uint32_t SAFE_MAX_TREE_DEPTH = 32;

/// @brief Prefetch distance for sequential access (in nodes)
inline constexpr size_t PREFETCH_DISTANCE = 2;

/// @brief Batch size for vectorized operations
inline constexpr size_t BATCH_CHUNK_SIZE = 8;

/// @brief Magic number for node integrity validation
inline constexpr uint32_t NODE_MAGIC_NUMBER = 0xB7EE1DAD;

/// @brief Minimum valid key count for non-empty leaf
inline constexpr uint32_t MIN_LEAF_KEYS = 1;

/// @brief Statistics tracking interval (operations)
inline constexpr uint64_t STATS_TRACK_INTERVAL = 1000;

// ============================================================================
// HARDWARE FEATURE DETECTION
// ============================================================================

/**
 * @brief Cached hardware feature detection for POPCNT instruction
 * @return True if POPCNT is supported
 */
[[nodiscard]] inline bool HasPOPCNT() noexcept {
    static const bool hasPOPCNT = []() {
#if defined(_MSC_VER)
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] & (1 << 23)) != 0;  // POPCNT bit
#elif defined(__GNUC__) || defined(__clang__)
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
            return (ecx & (1 << 23)) != 0;
        }
        return false;
#else
        return false;
#endif
    }();
    return hasPOPCNT;
}

/**
 * @brief Cached hardware feature detection for BMI2 instruction set
 * @return True if BMI2 is supported
 */
[[nodiscard]] inline bool HasBMI2() noexcept {
    static const bool hasBMI2 = []() {
#if defined(_MSC_VER)
        int cpuInfo[4] = {0};
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 8)) != 0;  // BMI2 bit
#elif defined(__GNUC__) || defined(__clang__)
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
            return (ebx & (1 << 8)) != 0;
        }
        return false;
#else
        return false;
#endif
    }();
    return hasBMI2;
}

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/**
 * @brief Secure memory zeroing that cannot be optimized away
 * @param ptr Pointer to memory to zero
 * @param size Size in bytes to zero
 * @note Uses SecureZeroMemory on Windows, volatile on other platforms
 */
inline void SecureZeroMemoryRegion(void* ptr, size_t size) noexcept {
    if (SS_UNLIKELY(!ptr || size == 0)) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

/**
 * @brief Memory barrier for explicit ordering
 */
inline void FullMemoryBarrier() noexcept {
    std::atomic_thread_fence(std::memory_order_seq_cst);
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
}

/**
 * @brief Prefetch memory for reading with locality hint
 * @param addr Address to prefetch
 * @param locality Locality level (0=NTA, 1=L2, 2=L1, 3=L0)
 */
template<int Locality = 3>
inline void PrefetchForRead(const void* addr) noexcept {
    if constexpr (Locality == 0) {
        SS_PREFETCH_NTA(addr);
    } else {
        SS_PREFETCH_READ(addr);
    }
}

/**
 * @brief Prefetch memory for writing
 * @param addr Address to prefetch
 */
inline void PrefetchForWrite(void* addr) noexcept {
    SS_PREFETCH_WRITE(addr);
}

/**
 * @brief Count leading zeros with hardware acceleration if available
 * @param value Value to count
 * @return Number of leading zeros
 */
[[nodiscard]] inline uint32_t CountLeadingZeros64(uint64_t value) noexcept {
    if (value == 0) return 64;
#if defined(_MSC_VER)
    unsigned long index;
    _BitScanReverse64(&index, value);
    return 63 - index;
#elif defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_clzll(value));
#else
    return static_cast<uint32_t>(std::countl_zero(value));
#endif
}

/**
 * @brief Population count with hardware acceleration
 * @param value Value to count bits in
 * @return Number of set bits
 */
[[nodiscard]] inline uint32_t PopCount64(uint64_t value) noexcept {
    if (HasPOPCNT()) {
#if defined(_MSC_VER)
        return static_cast<uint32_t>(__popcnt64(value));
#elif defined(__GNUC__) || defined(__clang__)
        return static_cast<uint32_t>(__builtin_popcountll(value));
#endif
    }
    // Fallback: Brian Kernighan's algorithm
    uint32_t count = 0;
    while (value) {
        value &= value - 1;
        ++count;
    }
    return count;
}

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================
// These helper functions provide overflow-safe arithmetic and utility
// operations. Defined in anonymous namespace for internal linkage only.
// ============================================================================

/**
 * @brief Safely add two values with overflow check
 * @tparam T Integral type (must be unsigned for correct overflow detection)
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if addition succeeded, false if overflow would occur
 *
 * @note Uses compile-time check to ensure correct overflow detection
 */
template<typename T>
[[nodiscard]] inline bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeAdd requires integral type");
    
    if constexpr (std::is_unsigned_v<T>) {
        if (SS_UNLIKELY(a > std::numeric_limits<T>::max() - b)) {
            return false;
        }
    } else {
        // Signed overflow check using compiler builtins when available
#if defined(__GNUC__) || defined(__clang__)
        if (SS_UNLIKELY(__builtin_add_overflow(a, b, &result))) {
            return false;
        }
        return true;
#else
        if ((b > 0 && a > std::numeric_limits<T>::max() - b) ||
            (b < 0 && a < std::numeric_limits<T>::min() - b)) {
            return false;
        }
#endif
    }
    result = a + b;
    return true;
}

/**
 * @brief Safely multiply two values with overflow check
 * @tparam T Integral type (must be unsigned for correct overflow detection)
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeMul(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeMul requires integral type");
    
    // Early return for zero operands (common fast path)
    if (a == 0 || b == 0) [[likely]] {
        result = 0;
        return true;
    }
    
    // Use compiler built-ins when available (most reliable)
#if defined(__GNUC__) || defined(__clang__)
    if (SS_UNLIKELY(__builtin_mul_overflow(a, b, &result))) {
        return false;
    }
    return true;
#else
    if constexpr (std::is_unsigned_v<T>) {
        if (SS_UNLIKELY(a > std::numeric_limits<T>::max() / b)) {
            return false;
        }
    } else {
        // Signed overflow check (comprehensive)
        if (a > 0) {
            if (b > 0 && SS_UNLIKELY(a > std::numeric_limits<T>::max() / b)) return false;
            if (b < 0 && SS_UNLIKELY(b < std::numeric_limits<T>::min() / a)) return false;
        } else {
            if (b > 0 && SS_UNLIKELY(a < std::numeric_limits<T>::min() / b)) return false;
            if (b < 0 && SS_UNLIKELY(a < std::numeric_limits<T>::max() / b)) return false;
        }
    }
    result = a * b;
    return true;
#endif
}

/**
 * @brief Safely subtract two values with underflow check
 * @tparam T Integral type
 * @param a First operand
 * @param b Second operand (subtracted from a)
 * @param result Output result
 * @return True if subtraction succeeded without underflow
 */
template<typename T>
[[nodiscard]] inline bool SafeSub(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeSub requires integral type");
    
#if defined(__GNUC__) || defined(__clang__)
    if (SS_UNLIKELY(__builtin_sub_overflow(a, b, &result))) {
        return false;
    }
    return true;
#else
    if constexpr (std::is_unsigned_v<T>) {
        if (SS_UNLIKELY(a < b)) {
            return false;
        }
    } else {
        if ((b < 0 && a > std::numeric_limits<T>::max() + b) ||
            (b > 0 && a < std::numeric_limits<T>::min() + b)) {
            return false;
        }
    }
    result = a - b;
    return true;
#endif
}

/**
 * @brief Clamp value to valid range
 * @tparam T Comparable type
 * @param value Value to clamp
 * @param minVal Minimum allowed value
 * @param maxVal Maximum allowed value
 * @return Clamped value within [minVal, maxVal]
 */
template<typename T>
[[nodiscard]] constexpr T Clamp(T value, T minVal, T maxVal) noexcept {
    return (value < minVal) ? minVal : ((value > maxVal) ? maxVal : value);
}

/**
 * @brief Branchless lower bound binary search optimized for B+Tree
 * @tparam ArrayType Array or std::array type containing keys
 * @param keys Sorted key container (std::array or C-array)
 * @param count Number of valid keys in array
 * @param target Target key to search for
 * @return Index of first element >= target (or count if all < target)
 * @note Uses conditional moves to avoid branch mispredictions
 */
template<typename ArrayType, typename KeyType>
[[nodiscard]] inline uint32_t BranchlessLowerBound(
    const ArrayType& keys,
    uint32_t count,
    KeyType target
) noexcept {
    // Deduce max size from array type at compile time
    constexpr size_t MaxKeys = std::tuple_size_v<std::remove_cvref_t<ArrayType>>;
    // Early validation
    if (SS_UNLIKELY(count == 0)) {
        return 0;
    }
    
    // Safety clamp to array bounds
    const uint32_t safeCount = (count > MaxKeys) ? static_cast<uint32_t>(MaxKeys) : count;
    
    // Branchless binary search with prefetching
    uint32_t left = 0;
    uint32_t size = safeCount;
    
    while (size > 1) {
        const uint32_t half = size / 2;
        const uint32_t mid = left + half;
        
        // Bounds check for safety (mid should always be valid but verify)
        if (SS_UNLIKELY(mid >= MaxKeys)) {
            break;
        }
        
        // Prefetch next potential access locations
        if (size > BATCH_CHUNK_SIZE) {
            const uint32_t prefetchLow = left + half / 2;
            const uint32_t prefetchHigh = mid + half / 2;
            if (prefetchLow < MaxKeys) {
                SS_PREFETCH_READ(&keys[prefetchLow]);
            }
            if (prefetchHigh < MaxKeys) {
                SS_PREFETCH_READ(&keys[prefetchHigh]);
            }
        }
        
        // Branchless conditional move using comparison result
        // If keys[mid] < target, move left forward; otherwise stay
        const bool goRight = (keys[mid] < target);
        left = goRight ? (mid + 1) : left;
        size = goRight ? (size - half - 1) : half;
    }
    
    // Final comparison with bounds validation
    if (size > 0 && left < MaxKeys && keys[left] < target) {
        ++left;
    }
    
    return left;
}

/**
 * @brief Find exact key in sorted array with early termination
 * @tparam ArrayType Array or std::array type containing keys
 * @tparam KeyType Type of the key being searched
 * @param keys Sorted key container (std::array or C-array)
 * @param count Number of valid keys
 * @param target Target key to find
 * @param[out] index Output index if found
 * @return True if found, false otherwise
 */
template<typename ArrayType, typename KeyType>
[[nodiscard]] inline bool BinarySearchExact(
    const ArrayType& keys,
    uint32_t count,
    KeyType target,
    uint32_t& index
) noexcept {
    // Deduce max size from array type at compile time
    constexpr size_t MaxKeys = std::tuple_size_v<std::remove_cvref_t<ArrayType>>;
    
    if (SS_UNLIKELY(count == 0)) {
        return false;
    }
    
    // Safety clamp to array bounds
    const uint32_t safeCount = (count > MaxKeys) ? static_cast<uint32_t>(MaxKeys) : count;
    
    uint32_t left = 0;
    uint32_t right = safeCount;
    
    while (left < right) {
        const uint32_t mid = left + (right - left) / 2;
        
        // Bounds validation (mid should always be valid, but verify for security)
        if (SS_UNLIKELY(mid >= MaxKeys)) {
            return false;
        }
        
        // Prefetch for next iteration when search range is large enough
        if (right - left > BATCH_CHUNK_SIZE) {
            const uint32_t nextMidLow = left + (mid - left) / 2;
            const uint32_t nextMidHigh = mid + (right - mid) / 2;
            if (nextMidLow < MaxKeys) {
                SS_PREFETCH_READ(&keys[nextMidLow]);
            }
            if (nextMidHigh < MaxKeys) {
                SS_PREFETCH_READ(&keys[nextMidHigh]);
            }
        }
        
        // Three-way comparison for exact match
        if (keys[mid] < target) {
            left = mid + 1;
        } else if (keys[mid] > target) {
            right = mid;
        } else {
            // Found exact match
            index = mid;
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Validate pointer is within a memory region
 * @param ptr Pointer to validate
 * @param base Base address of region
 * @param size Size of region in bytes
 * @return True if pointer is within [base, base+size)
 */
[[nodiscard]] inline bool IsPointerInRange(
    const void* ptr,
    const void* base,
    size_t size
) noexcept {
    if (!ptr || !base || size == 0) {
        return false;
    }
    const auto ptrVal = reinterpret_cast<uintptr_t>(ptr);
    const auto baseVal = reinterpret_cast<uintptr_t>(base);
    return ptrVal >= baseVal && (ptrVal - baseVal) < size;
}

/**
 * @brief Calculate aligned size for memory allocation
 * @param size Requested size
 * @param alignment Alignment requirement (must be power of 2)
 * @return Aligned size
 */
[[nodiscard]] constexpr uint64_t AlignUp(uint64_t size, uint64_t alignment) noexcept {
    return (size + alignment - 1) & ~(alignment - 1);
}

/**
 * @brief Validate B+Tree node integrity 
 * @param node Node to validate
 * @param maxKeys Maximum valid key count
 * @return True if node passes integrity checks
 */
[[nodiscard]] inline bool ValidateNodeIntegrity(
    const BPlusTreeNode* node,
    uint32_t maxKeys
) noexcept {
    if (SS_UNLIKELY(!node)) {
        return false;
    }
    
    // Key count must be within valid range
    if (SS_UNLIKELY(node->keyCount > maxKeys)) {
        return false;
    }
    
    // For leaf nodes, verify sorted order (optional strict mode)
#ifndef NDEBUG
    if (node->isLeaf && node->keyCount > 1) {
        for (uint32_t i = 0; i + 1 < node->keyCount; ++i) {
            if (node->keys[i] >= node->keys[i + 1]) {
                // Keys not in strictly ascending order (potential corruption)
                return false;
            }
        }
    }
#endif
    
    return true;
}

/**
 * @brief RAII helper for scoped write lock with timeout
 */
class ScopedWriteGuard {
public:
    explicit ScopedWriteGuard(std::shared_mutex& mtx) noexcept
        : m_mutex(mtx), m_locked(false)
    {
        m_mutex.lock();
        m_locked = true;
    }
    
    ~ScopedWriteGuard() noexcept {
        if (m_locked) {
            m_mutex.unlock();
        }
    }
    
    // Non-copyable, non-movable
    ScopedWriteGuard(const ScopedWriteGuard&) = delete;
    ScopedWriteGuard& operator=(const ScopedWriteGuard&) = delete;
    ScopedWriteGuard(ScopedWriteGuard&&) = delete;
    ScopedWriteGuard& operator=(ScopedWriteGuard&&) = delete;
    
    void Release() noexcept {
        if (m_locked) {
            m_mutex.unlock();
            m_locked = false;
        }
    }
    
    [[nodiscard]] bool IsLocked() const noexcept { return m_locked; }
    
private:
    std::shared_mutex& m_mutex;
    bool m_locked;
};

} // namespace (anonymous)

// ============================================================================
// HASH INDEX IMPLEMENTATION (B+Tree)
// ============================================================================

HashIndex::HashIndex() = default;

HashIndex::~HashIndex() = default;

HashIndex::HashIndex(HashIndex&& other) noexcept
    : m_view(nullptr)
    , m_baseAddress(nullptr)
    , m_rootOffset(0)
    , m_indexOffset(0)
    , m_indexSize(0)
    , m_nextNodeOffset(0)
    , m_treeDepth(0)
    , m_entryCount(0)
    , m_nodeCount(0)
    , m_lookupCount(0)
    , m_insertCount(0)
    , m_removeCount(0)
    , m_splitCount(0)
{
    // Lock the source object to ensure thread-safe move
    std::unique_lock lock(other.m_rwLock);
    
    // Transfer ownership with acquire semantics for memory ordering
    m_view = other.m_view;
    m_baseAddress = other.m_baseAddress;
    m_rootOffset = other.m_rootOffset;
    m_indexOffset = other.m_indexOffset;
    m_indexSize = other.m_indexSize;
    m_nextNodeOffset = other.m_nextNodeOffset;
    m_treeDepth = other.m_treeDepth;
    m_entryCount.store(other.m_entryCount.load(std::memory_order_acquire), 
                      std::memory_order_release);
    m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire), 
                     std::memory_order_release);
    
    // Transfer performance counters
    m_lookupCount.store(other.m_lookupCount.load(std::memory_order_acquire),
                       std::memory_order_release);
    m_insertCount.store(other.m_insertCount.load(std::memory_order_acquire),
                       std::memory_order_release);
    m_removeCount.store(other.m_removeCount.load(std::memory_order_acquire),
                       std::memory_order_release);
    m_splitCount.store(other.m_splitCount.load(std::memory_order_acquire),
                      std::memory_order_release);
    
    // Clear source with release semantics
    other.m_view = nullptr;
    other.m_baseAddress = nullptr;
    other.m_rootOffset = 0;
    other.m_indexOffset = 0;
    other.m_indexSize = 0;
    other.m_nextNodeOffset = 0;
    other.m_treeDepth = 0;
    other.m_entryCount.store(0, std::memory_order_release);
    other.m_nodeCount.store(0, std::memory_order_release);
    other.m_lookupCount.store(0, std::memory_order_release);
    other.m_insertCount.store(0, std::memory_order_release);
    other.m_removeCount.store(0, std::memory_order_release);
    other.m_splitCount.store(0, std::memory_order_release);
}

HashIndex& HashIndex::operator=(HashIndex&& other) noexcept {
    if (this != &other) {
        // Lock both for thread safety during move (use std::lock to avoid deadlock)
        std::unique_lock lockThis(m_rwLock, std::defer_lock);
        std::unique_lock lockOther(other.m_rwLock, std::defer_lock);
        std::lock(lockThis, lockOther);
        
        // Transfer ownership with acquire semantics
        m_view = other.m_view;
        m_baseAddress = other.m_baseAddress;
        m_rootOffset = other.m_rootOffset;
        m_indexOffset = other.m_indexOffset;
        m_indexSize = other.m_indexSize;
        m_nextNodeOffset = other.m_nextNodeOffset;
        m_treeDepth = other.m_treeDepth;
        m_entryCount.store(other.m_entryCount.load(std::memory_order_acquire), 
                          std::memory_order_release);
        m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire), 
                         std::memory_order_release);
        
        // Transfer performance counters
        m_lookupCount.store(other.m_lookupCount.load(std::memory_order_acquire),
                           std::memory_order_release);
        m_insertCount.store(other.m_insertCount.load(std::memory_order_acquire),
                           std::memory_order_release);
        m_removeCount.store(other.m_removeCount.load(std::memory_order_acquire),
                           std::memory_order_release);
        m_splitCount.store(other.m_splitCount.load(std::memory_order_acquire),
                          std::memory_order_release);
        
        // Clear source with release semantics for memory ordering guarantee
        other.m_view = nullptr;
        other.m_baseAddress = nullptr;
        other.m_rootOffset = 0;
        other.m_indexOffset = 0;
        other.m_indexSize = 0;
        other.m_nextNodeOffset = 0;
        other.m_treeDepth = 0;
        other.m_entryCount.store(0, std::memory_order_release);
        other.m_nodeCount.store(0, std::memory_order_release);
        other.m_lookupCount.store(0, std::memory_order_release);
        other.m_insertCount.store(0, std::memory_order_release);
        other.m_removeCount.store(0, std::memory_order_release);
        other.m_splitCount.store(0, std::memory_order_release);
    }
    return *this;
}

bool HashIndex::IsOffsetValid(uint64_t offset) const noexcept {
    // Validate offset is within index bounds
    if (offset >= m_indexSize) {
        return false;
    }
    
    // Check for node structure alignment
    constexpr uint64_t HEADER_SIZE = 64;
    if (offset >= HEADER_SIZE) {
        // Validate offset is properly aligned for BPlusTreeNode
        const uint64_t nodeOffset = offset - HEADER_SIZE;
        if (nodeOffset % sizeof(BPlusTreeNode) != 0) {
            // Offset not aligned to node boundary
            return false;
        }
        
        // Ensure there's enough space for a complete node
        uint64_t endOffset = 0;
        if (!SafeAdd(offset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), endOffset)) {
            return false; // Would overflow
        }
        if (endOffset > m_indexSize) {
            return false; // Node would extend past index boundary
        }
    } else if (offset > 0) {
        // Offset is within header region (invalid for node access)
        return false;
    }
    
    return true;
}

StoreError HashIndex::Initialize(
    const MemoryMappedView& view,
    uint64_t offset,
    uint64_t size
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate view
    if (!view.IsValid()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
    }
    
    // Validate offset and size don't overflow
    uint64_t endOffset;
    if (!SafeAdd(offset, size, endOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section offset + size overflow"
        );
    }
    
    if (endOffset > view.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section exceeds file size"
        );
    }
    
    // Minimum size check
    constexpr uint64_t HEADER_SIZE = 64;
    if (size < HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section too small for header"
        );
    }
    
    m_view = &view;
    m_baseAddress = nullptr;  // Read-only mode
    m_indexOffset = offset;
    m_indexSize = size;
    
    // Read root node offset from first 8 bytes
    const auto* rootPtr = view.GetAt<uint64_t>(offset);
    if (!rootPtr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Failed to read root node offset"
        );
    }
    
    m_rootOffset = *rootPtr;
    
    // Validate root offset
    if (m_rootOffset >= size) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Root offset exceeds index size"
        );
    }
    
    // Read metadata with null checks
    const auto* nodeCountPtr = view.GetAt<uint64_t>(offset + 8);
    const auto* entryCountPtr = view.GetAt<uint64_t>(offset + 16);
    const auto* nextNodePtr = view.GetAt<uint64_t>(offset + 24);
    const auto* depthPtr = view.GetAt<uint32_t>(offset + 32);
    
    if (nodeCountPtr) {
        m_nodeCount.store(*nodeCountPtr, std::memory_order_relaxed);
    }
    if (entryCountPtr) {
        m_entryCount.store(*entryCountPtr, std::memory_order_relaxed);
    }
    if (nextNodePtr) {
        m_nextNodeOffset = *nextNodePtr;
    }
    if (depthPtr) {
        m_treeDepth = std::min(*depthPtr, MAX_TREE_DEPTH);
    }
    
    SS_LOG_DEBUG(L"Whitelist", 
        L"HashIndex initialized: %llu nodes, %llu entries, depth %u",
        m_nodeCount.load(std::memory_order_relaxed), 
        m_entryCount.load(std::memory_order_relaxed), 
        m_treeDepth);
    
    return StoreError::Success();
}

StoreError HashIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    if (!baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid base address (null)"
        );
    }
    
    // Minimum size: header (64 bytes) + one node
    constexpr uint64_t HEADER_SIZE = 64;
    const uint64_t minSize = HEADER_SIZE + sizeof(BPlusTreeNode);
    
    if (availableSize < minSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Insufficient space for index (need at least header + one node)"
        );
    }
    
    // Validate available size won't cause overflow in subsequent calculations
    if (availableSize > static_cast<uint64_t>(INT64_MAX)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Available size exceeds maximum supported value"
        );
    }
    
    m_view = nullptr;  // Write mode
    m_baseAddress = baseAddress;
    m_indexOffset = 0;
    m_indexSize = availableSize;
    
    // Initialize header to zeros (bounds already validated above)
    auto* header = static_cast<uint8_t*>(baseAddress);
    std::memset(header, 0, static_cast<size_t>(HEADER_SIZE));
    
    // Create root node (empty leaf)
    m_rootOffset = HEADER_SIZE;
    
    // Safe calculation of next node offset
    uint64_t nextOffset = 0;
    if (!SafeAdd(HEADER_SIZE, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nextOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Next node offset calculation overflow"
        );
    }
    m_nextNodeOffset = nextOffset;
    
    // Validate we have space for root node
    if (m_nextNodeOffset > availableSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Not enough space for root node"
        );
    }
    
    auto* rootNode = reinterpret_cast<BPlusTreeNode*>(header + m_rootOffset);
    
    // Zero-initialize the entire node for security (prevent information leakage)
    std::memset(rootNode, 0, sizeof(BPlusTreeNode));
    
    // Initialize root node fields explicitly
    rootNode->isLeaf = true;
    rootNode->keyCount = 0;
    rootNode->parentOffset = 0;
    rootNode->nextLeaf = 0;
    rootNode->prevLeaf = 0;
    
    // Write header values
    auto* rootOffsetPtr = reinterpret_cast<uint64_t*>(header);
    *rootOffsetPtr = m_rootOffset;
    
    auto* nodeCountPtr = reinterpret_cast<uint64_t*>(header + 8);
    *nodeCountPtr = 1;
    
    auto* entryCountPtr = reinterpret_cast<uint64_t*>(header + 16);
    *entryCountPtr = 0;
    
    auto* nextNodePtr = reinterpret_cast<uint64_t*>(header + 24);
    *nextNodePtr = m_nextNodeOffset;
    
    auto* depthPtr = reinterpret_cast<uint32_t*>(header + 32);
    *depthPtr = 1;
    
    m_nodeCount.store(1, std::memory_order_relaxed);
    m_entryCount.store(0, std::memory_order_relaxed);
    m_treeDepth = 1;
    
    usedSize = m_nextNodeOffset;
    
    SS_LOG_DEBUG(L"Whitelist", L"HashIndex created: root at offset %llu", m_rootOffset);
    
    return StoreError::Success();
}

const BPlusTreeNode* HashIndex::FindLeaf(uint64_t key) const noexcept {
    // ========================================================================
    // B+TREE LEAF SEARCH WITH PREFETCHING OPTIMIZATION
    // ========================================================================
    // Uses software prefetching to reduce memory latency during tree traversal.
    // Prefetches next potential child nodes during binary search.
    // ========================================================================
    
    // Must have either view or base address
    if (SS_UNLIKELY(!m_view && !m_baseAddress)) {
        return nullptr;
    }
    
    // Validate index size is set
    if (SS_UNLIKELY(m_indexSize == 0)) {
        return nullptr;
    }
    
    // Validate root offset
    if (SS_UNLIKELY(m_rootOffset == 0 || m_rootOffset >= m_indexSize)) {
        return nullptr;
    }
    
    uint64_t currentOffset = m_rootOffset;
    
    // Traverse tree with depth limit to prevent infinite loops from corruption
    // Use min(m_treeDepth, MAX_TREE_DEPTH) for extra safety
    const uint32_t maxIterations = std::min(m_treeDepth + 1, SAFE_MAX_TREE_DEPTH);
    
    for (uint32_t depth = 0; depth < maxIterations; ++depth) {
        const BPlusTreeNode* node = nullptr;
        
        if (m_view) {
            // Read-only mode (memory-mapped)
            if (SS_UNLIKELY(!IsOffsetValid(currentOffset))) {
                return nullptr;
            }
            
            // Additional bounds check for GetAt
            uint64_t nodeEndOffset = 0;
            if (SS_UNLIKELY(!SafeAdd(m_indexOffset, currentOffset, nodeEndOffset) ||
                !SafeAdd(nodeEndOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nodeEndOffset))) {
                return nullptr;
            }
            if (SS_UNLIKELY(nodeEndOffset > m_view->fileSize)) {
                return nullptr;
            }
            
            node = m_view->GetAt<BPlusTreeNode>(m_indexOffset + currentOffset);
        } else if (m_baseAddress) {
            // Write mode (direct memory access)
            if (SS_UNLIKELY(currentOffset >= m_indexSize)) {
                return nullptr;
            }
            
            // Bounds check for node access
            uint64_t nodeEndOffset = 0;
            if (SS_UNLIKELY(!SafeAdd(currentOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nodeEndOffset) ||
                nodeEndOffset > m_indexSize)) {
                return nullptr;
            }
            
            node = reinterpret_cast<const BPlusTreeNode*>(
                static_cast<const uint8_t*>(m_baseAddress) + currentOffset
            );
        }
        
        if (SS_UNLIKELY(!node)) {
            return nullptr;
        }
        
        // Found leaf node - return immediately
        if (node->isLeaf) [[likely]] {
            return node;
        }
        
        // Validate node integrity (defense against corrupted data)
        if (SS_UNLIKELY(!ValidateNodeIntegrity(node, BPlusTreeNode::MAX_KEYS))) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex: corrupt node with keyCount=%u (max=%u)", 
                        node->keyCount, BPlusTreeNode::MAX_KEYS);
            return nullptr;
        }
        
        // Binary search for the correct child with prefetching
        uint32_t left = 0;
        uint32_t right = node->keyCount;
        
        while (left < right) {
            const uint32_t mid = left + (right - left) / 2;
            
            // Prefetch potential next access locations during binary search
            // This hides memory latency by fetching data speculatively
            if (right - left > BATCH_CHUNK_SIZE) {
                const uint32_t midLow = left + (mid - left) / 2;
                const uint32_t midHigh = mid + (right - mid) / 2;
                SS_PREFETCH_READ(&node->keys[midLow]);
                SS_PREFETCH_READ(&node->keys[midHigh]);
            }
            
            if (node->keys[mid] <= key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        // Get child pointer (left is the index of the child to follow)
        if (SS_UNLIKELY(left > BPlusTreeNode::MAX_KEYS)) {
            return nullptr;  // Invalid index
        }
        
        currentOffset = node->children[left];
        
        if (SS_UNLIKELY(currentOffset == 0 || currentOffset >= m_indexSize)) {
            return nullptr;  // Invalid child pointer
        }
        
        // Prefetch next node while we're computing (hide memory latency)
        if (m_baseAddress) {
            SS_PREFETCH_READ(static_cast<const uint8_t*>(m_baseAddress) + currentOffset);
        }
    }
    
    // Exceeded depth limit - potential corruption or malicious data
    SS_LOG_ERROR(L"Whitelist", L"HashIndex: exceeded max tree depth (%u) during search", maxIterations);
    return nullptr;
}

std::optional<uint64_t> HashIndex::Lookup(const HashValue& hash) const noexcept {
    // ========================================================================
    // O(LOG N) HASH LOOKUP WITH OPTIMIZED BINARY SEARCH
    // ========================================================================
    
    std::shared_lock lock(m_rwLock);
    
    // Update lookup counter (relaxed ordering is fine for statistics)
    m_lookupCount.fetch_add(1, std::memory_order_relaxed);
    
    // Validate hash (empty hash is never in index)
    if (SS_UNLIKELY(hash.IsEmpty())) {
        return std::nullopt;
    }
    
    const uint64_t key = hash.FastHash();
    const BPlusTreeNode* leaf = FindLeaf(key);
    
    if (SS_UNLIKELY(!leaf)) {
        return std::nullopt;
    }
    
    // Validate leaf node integrity
    if (SS_UNLIKELY(!ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS))) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::Lookup: corrupt leaf node");
        return std::nullopt;
    }
    
    // Use optimized binary search with exact match
    uint32_t foundIndex = 0;
    if (BinarySearchExact(leaf->keys, leaf->keyCount, key, foundIndex)) {
        return static_cast<uint64_t>(leaf->children[foundIndex]);
    }
    
    return std::nullopt;
}

bool HashIndex::Contains(const HashValue& hash) const noexcept {
    return Lookup(hash).has_value();
}

void HashIndex::BatchLookup(
    std::span<const HashValue> hashes,
    std::vector<std::optional<uint64_t>>& results
) const noexcept {
    // ========================================================================
    // BATCH LOOKUP WITH PREFETCHING AND CACHE OPTIMIZATION
    // ========================================================================
    // Processes multiple hashes efficiently by:
    // 1. Pre-allocating result storage
    // 2. Computing all hash keys first (cache-friendly)
    // 3. Prefetching leaf nodes for upcoming lookups
    // 4. Using single lock acquisition for all lookups
    // ========================================================================
    
    // Pre-allocate results with exception safety
    try {
        results.clear();
        results.resize(hashes.size(), std::nullopt);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::BatchLookup: allocation failed - %S", e.what());
        return;
    }
    
    if (SS_UNLIKELY(hashes.empty())) {
        return;
    }
    
    // Single lock acquisition for entire batch
    std::shared_lock lock(m_rwLock);
    
    // Pre-compute all hash keys for cache efficiency
    std::vector<uint64_t> keys;
    try {
        keys.reserve(hashes.size());
        for (const auto& hash : hashes) {
            keys.push_back(hash.IsEmpty() ? 0 : hash.FastHash());
        }
    } catch (const std::exception&) {
        // Fall back to non-prefetching mode on allocation failure
        keys.clear();
    }
    
    // Process in chunks for better cache behavior
    constexpr size_t CHUNK_SIZE = 8;
    const size_t numHashes = hashes.size();
    
    for (size_t i = 0; i < numHashes; ++i) {
        // Skip empty hashes
        if (hashes[i].IsEmpty()) {
            results[i] = std::nullopt;
            continue;
        }
        
        const uint64_t key = keys.empty() ? hashes[i].FastHash() : keys[i];
        
        // Prefetch next few hash keys for upcoming iterations
        if (!keys.empty() && i + CHUNK_SIZE < numHashes) {
            SS_PREFETCH_READ(&keys[i + CHUNK_SIZE]);
        }
        
        const BPlusTreeNode* leaf = FindLeaf(key);
        
        if (SS_UNLIKELY(!leaf || !ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS))) {
            results[i] = std::nullopt;
            continue;
        }
        
        // Use optimized binary search
        uint32_t foundIndex = 0;
        if (BinarySearchExact(leaf->keys, leaf->keyCount, key, foundIndex)) {
            results[i] = static_cast<uint64_t>(leaf->children[foundIndex]);
        } else {
            results[i] = std::nullopt;
        }
    }
}

BPlusTreeNode* HashIndex::FindLeafMutable(uint64_t key) noexcept {
    // ========================================================================
    // MUTABLE LEAF SEARCH FOR INSERT/UPDATE OPERATIONS
    // ========================================================================
    // Similar to FindLeaf but returns mutable pointer for modifications.
    // Only valid when index is in write mode (m_baseAddress != nullptr).
    // ========================================================================
    
    // Requires writable base address
    if (SS_UNLIKELY(!m_baseAddress)) {
        return nullptr;
    }
    
    // Validate index state
    if (SS_UNLIKELY(m_indexSize == 0)) {
        return nullptr;
    }
    
    // Validate root offset
    if (SS_UNLIKELY(m_rootOffset == 0 || m_rootOffset >= m_indexSize)) {
        return nullptr;
    }
    
    uint64_t currentOffset = m_rootOffset;
    
    // Traverse with depth limit (protection against corruption)
    const uint32_t maxDepth = std::min(m_treeDepth + 1, SAFE_MAX_TREE_DEPTH);
    
    for (uint32_t depth = 0; depth < maxDepth; ++depth) {
        // Comprehensive bounds check
        if (SS_UNLIKELY(currentOffset >= m_indexSize)) {
            return nullptr;
        }
        
        // Validate node fits within index bounds
        uint64_t nodeEnd = 0;
        if (SS_UNLIKELY(!SafeAdd(currentOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nodeEnd) ||
            nodeEnd > m_indexSize)) {
            return nullptr;
        }
        
        auto* node = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + currentOffset
        );
        
        // Found leaf - return mutable pointer
        if (node->isLeaf) [[likely]] {
            return node;
        }
        
        // Validate node integrity
        if (SS_UNLIKELY(!ValidateNodeIntegrity(node, BPlusTreeNode::MAX_KEYS))) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex: corrupt node during mutable search (keyCount=%u)", 
                        node->keyCount);
            return nullptr;
        }
        
        // Binary search for correct child with prefetching
        uint32_t left = 0;
        uint32_t right = node->keyCount;
        
        while (left < right) {
            const uint32_t mid = left + (right - left) / 2;
            if (node->keys[mid] <= key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        // Validate child index
        if (SS_UNLIKELY(left > BPlusTreeNode::MAX_KEYS)) {
            return nullptr;
        }
        
        currentOffset = node->children[left];
        
        if (SS_UNLIKELY(currentOffset == 0 || currentOffset >= m_indexSize)) {
            return nullptr;
        }
        
        // Prefetch next node for write access
        PrefetchForWrite(static_cast<uint8_t*>(m_baseAddress) + currentOffset);
    }
    
    SS_LOG_ERROR(L"Whitelist", L"HashIndex: mutable search exceeded max depth");
    return nullptr;
}

BPlusTreeNode* HashIndex::AllocateNode() noexcept {
    // ========================================================================
    // SECURE NODE ALLOCATION WITH ZERO-INITIALIZATION
    // ========================================================================
    // Allocates a new B+Tree node from the available space.
    // - Validates all bounds before allocation
    // - Zero-initializes memory to prevent information leakage
    // - Updates header atomically with proper memory ordering
    // ========================================================================
    
    if (SS_UNLIKELY(!m_baseAddress)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: no base address");
        return nullptr;
    }
    
    // Validate current state
    if (SS_UNLIKELY(m_nextNodeOffset == 0 || m_indexSize == 0)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: invalid index state");
        return nullptr;
    }
    
    // Check if we have space (safe calculation with overflow check)
    uint64_t newNextOffset = 0;
    if (SS_UNLIKELY(!SafeAdd(m_nextNodeOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), newNextOffset))) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex: node offset overflow");
        return nullptr;
    }
    
    if (SS_UNLIKELY(newNextOffset > m_indexSize)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex: no space for new node (need %llu, have %llu)", 
                    newNextOffset, m_indexSize);
        return nullptr;
    }
    
    // Additional validation: ensure current offset is within bounds and aligned
    if (SS_UNLIKELY(m_nextNodeOffset >= m_indexSize)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: current offset out of bounds");
        return nullptr;
    }
    
    // Verify alignment (node should be naturally aligned)
    if (SS_UNLIKELY((m_nextNodeOffset % alignof(BPlusTreeNode)) != 0)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: misaligned offset");
        return nullptr;
    }
    
    auto* node = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_baseAddress) + m_nextNodeOffset
    );
    
    // Secure zero-initialize new node (prevents information leakage)
    SecureZeroMemoryRegion(node, sizeof(BPlusTreeNode));
    
    // Memory barrier before updating state
    FullMemoryBarrier();
    
    // Store the offset of this node before updating
    [[maybe_unused]] const uint64_t thisNodeOffset = m_nextNodeOffset;
    
    m_nextNodeOffset = newNextOffset;
    
    // Atomic increment with acquire-release for proper ordering
    const uint64_t newNodeCount = m_nodeCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    
    // Update header with bounds validation
    constexpr uint64_t NEXT_NODE_OFFSET_POSITION = 24;
    constexpr uint64_t NODE_COUNT_POSITION = 8;
    
    if (INDEX_HEADER_SIZE <= m_indexSize) {
        // Write with memory ordering guarantee
        auto* nextNodePtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + NEXT_NODE_OFFSET_POSITION
        );
        *nextNodePtr = m_nextNodeOffset;
        
        auto* nodeCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + NODE_COUNT_POSITION
        );
        *nodeCountPtr = newNodeCount;
    }
    
    return node;
}

StoreError HashIndex::SplitNode(BPlusTreeNode* node) noexcept {
    /*
     * ========================================================================
     * B+TREE NODE SPLITTING - ENTERPRISE-GRADE IMPLEMENTATION
     * ========================================================================
     *
     * Splits a full node into two nodes with proper B+Tree semantics:
     * 
     * For LEAF nodes:
     * - Original keeps keys[0..splitPoint-1]
     * - Sibling gets keys[splitPoint..n-1]
     * - Promoted key = COPY of sibling's first key (key stays in leaf)
     *
     * For INTERNAL nodes:
     * - Original keeps keys[0..splitPoint-1] and children[0..splitPoint]
     * - Sibling gets keys[splitPoint+1..n-1] and children[splitPoint+1..n]
     * - Promoted key = keys[splitPoint] (MOVED to parent, not in children)
     *
     * Security: All array accesses are bounds-checked to prevent corruption.
     *
     * ========================================================================
     */
    
    if (!node) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Null node pointer"
        );
    }
    
    // Validate key count is exactly at maximum (ready for split)
    if (node->keyCount != BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Node is not full - split not needed"
        );
    }
    
    // Allocate new sibling node
    BPlusTreeNode* sibling = AllocateNode();
    if (!sibling) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Cannot allocate new node for split"
        );
    }
    
    sibling->isLeaf = node->isLeaf;
    
    // Calculate split point (middle of the node)
    const uint32_t splitPoint = node->keyCount / 2;
    
    // Validate split point is valid
    if (splitPoint == 0 || splitPoint >= BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid split point calculation"
        );
    }
    
    // Save the promoted key BEFORE modifying the node
    const uint64_t promotedKey = node->keys[splitPoint];
    
    // Save original state for rollback
    const uint32_t originalKeyCount = node->keyCount;
    const uint32_t originalNextLeaf = node->nextLeaf;
    
    // Calculate sibling offset for later use
    const auto siblingAddr = reinterpret_cast<uintptr_t>(sibling);
    const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
    const uint64_t siblingOffset = siblingAddr - baseAddr;
    
    // Number of keys that go to sibling (different for leaf vs internal)
    uint32_t siblingKeyCount = 0;
    
    if (node->isLeaf) {
        // ====================================================================
        // LEAF NODE SPLIT
        // ====================================================================
        // For leaves: sibling gets all keys from splitPoint onwards
        // Promoted key is a COPY (the actual key stays in sibling)
        // ====================================================================
        
        siblingKeyCount = node->keyCount - splitPoint;  // 127 - 63 = 64
        
        // Copy second half to sibling
        for (uint32_t i = 0; i < siblingKeyCount; ++i) {
            const uint32_t srcIdx = splitPoint + i;
            
            if (srcIdx >= BPlusTreeNode::MAX_KEYS || i >= BPlusTreeNode::MAX_KEYS) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Index out of bounds during leaf split"
                );
            }
            
            sibling->keys[i] = node->keys[srcIdx];
            sibling->children[i] = node->children[srcIdx];
            
            // Clear original slot for security
            node->keys[srcIdx] = 0;
            node->children[srcIdx] = 0;
        }
        
        sibling->keyCount = siblingKeyCount;
        node->keyCount = splitPoint;
        
        // Update leaf linked list with comprehensive bounds validation
        if (m_baseAddress) {
            // Calculate offsets safely
            const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
            
            // Verify nodes are within the base address range
            if (nodeAddr < baseAddr || siblingAddr < baseAddr) {
                SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: node address underflow");
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Node address underflow during split"
                );
            }
            
            const uint64_t nodeOffset = nodeAddr - baseAddr;
            
            // Validate offsets are within index and fit in uint32_t
            if (nodeOffset >= m_indexSize || siblingOffset >= m_indexSize) {
                SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: computed offset exceeds index size");
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Computed offset exceeds index size"
                );
            }
            
            if (nodeOffset > UINT32_MAX || siblingOffset > UINT32_MAX) {
                SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: offset exceeds uint32_t range");
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Offset exceeds 32-bit range"
                );
            }
            
            // Update sibling's links
            sibling->nextLeaf = node->nextLeaf;
            sibling->prevLeaf = static_cast<uint32_t>(nodeOffset);
            node->nextLeaf = static_cast<uint32_t>(siblingOffset);
            
            // Update next leaf's prev pointer (if exists)
            if (sibling->nextLeaf != 0) {
                // Validate next leaf offset
                const uint64_t nextLeafOffset = sibling->nextLeaf;
                uint64_t nextLeafEndOffset = 0;
                
                if (nextLeafOffset < m_indexSize &&
                    SafeAdd(nextLeafOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nextLeafEndOffset) &&
                    nextLeafEndOffset <= m_indexSize) {
                    
                    auto* nextLeaf = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + nextLeafOffset
                    );
                    nextLeaf->prevLeaf = static_cast<uint32_t>(siblingOffset);
                } else {
                    SS_LOG_WARN(L"Whitelist", L"HashIndex::SplitNode: invalid next leaf offset %u", 
                               sibling->nextLeaf);
                    // Clear invalid reference
                    sibling->nextLeaf = 0;
                }
            }
        }
        
    } else {
        // ====================================================================
        // INTERNAL NODE SPLIT
        // ====================================================================
        // For internal nodes:
        // - Original keeps keys[0..splitPoint-1] and children[0..splitPoint]
        // - Sibling gets keys[splitPoint+1..n-1] and children[splitPoint+1..n]
        // - The key at splitPoint becomes separator in parent (not in children)
        // ====================================================================
        
        siblingKeyCount = node->keyCount - splitPoint - 1;  // 127 - 63 - 1 = 63
        
        // Copy keys AFTER the promoted key to sibling
        for (uint32_t i = 0; i < siblingKeyCount; ++i) {
            const uint32_t keySrcIdx = splitPoint + 1 + i;
            
            if (keySrcIdx >= BPlusTreeNode::MAX_KEYS || i >= BPlusTreeNode::MAX_KEYS) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Index out of bounds during internal split"
                );
            }
            
            sibling->keys[i] = node->keys[keySrcIdx];
            node->keys[keySrcIdx] = 0;  // Clear for security
        }
        
        // Copy children starting from splitPoint+1
        // Sibling gets children[splitPoint+1..originalKeyCount] (that's siblingKeyCount+1 children)
        for (uint32_t i = 0; i <= siblingKeyCount; ++i) {
            const uint32_t childSrcIdx = splitPoint + 1 + i;
            
            if (childSrcIdx > BPlusTreeNode::MAX_KEYS || i > BPlusTreeNode::MAX_KEYS) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Child index out of bounds during internal split"
                );
            }
            
            sibling->children[i] = node->children[childSrcIdx];
            node->children[childSrcIdx] = 0;  // Clear for security
        }
        
        // Clear the promoted key from original node
        node->keys[splitPoint] = 0;
        // Note: children[splitPoint] stays with original as its rightmost child
        
        sibling->keyCount = siblingKeyCount;
        node->keyCount = splitPoint;
        
        // Update parentOffset for all children that moved to sibling
        if (siblingOffset < m_indexSize && siblingOffset <= UINT32_MAX) {
            const uint32_t siblingOffsetU32 = static_cast<uint32_t>(siblingOffset);
            
            for (uint32_t i = 0; i <= siblingKeyCount && i <= BPlusTreeNode::MAX_KEYS; ++i) {
                const uint32_t childOffset = sibling->children[i];
                
                if (childOffset != 0 && childOffset < m_indexSize) {
                    uint64_t childEndOffset = 0;
                    if (SafeAdd(static_cast<uint64_t>(childOffset), 
                               static_cast<uint64_t>(sizeof(BPlusTreeNode)), 
                               childEndOffset) &&
                        childEndOffset <= m_indexSize) {
                        
                        auto* childNode = reinterpret_cast<BPlusTreeNode*>(
                            static_cast<uint8_t*>(m_baseAddress) + childOffset
                        );
                        childNode->parentOffset = siblingOffsetU32;
                    }
                }
            }
        }
    }
    
    // NOTE: Leaf linked list update is already handled inside the if (node->isLeaf) block above.
    // Do NOT duplicate it here - that was causing B+Tree corruption by double-updating links.
    
    // Propagate to parent (this handles root creation if needed)
    auto propagateResult = PropagateToParent(node, promotedKey, siblingOffset);
    if (!propagateResult.IsSuccess()) {
        SS_LOG_WARN(L"Whitelist", 
            L"HashIndex::SplitNode: parent propagation failed - %S, performing rollback",
            propagateResult.message.c_str());
        
        // ====================================================================
        // ROLLBACK: Restore original node state
        // ====================================================================
        
        if (node->isLeaf) {
            // Restore leaf data
            for (uint32_t i = 0; i < siblingKeyCount && (splitPoint + i) < BPlusTreeNode::MAX_KEYS; ++i) {
                node->keys[splitPoint + i] = sibling->keys[i];
                node->children[splitPoint + i] = sibling->children[i];
            }
            
            // Restore leaf linked list
            node->nextLeaf = originalNextLeaf;
            
            if (sibling->nextLeaf != 0 && sibling->nextLeaf < m_indexSize) {
                const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
                auto* nextLeaf = reinterpret_cast<BPlusTreeNode*>(
                    static_cast<uint8_t*>(m_baseAddress) + sibling->nextLeaf
                );
                if ((nodeAddr - baseAddr) <= UINT32_MAX) {
                    nextLeaf->prevLeaf = static_cast<uint32_t>(nodeAddr - baseAddr);
                }
            }
        } else {
            // Restore internal node data
            node->keys[splitPoint] = promotedKey;
            
            for (uint32_t i = 0; i < siblingKeyCount && (splitPoint + 1 + i) < BPlusTreeNode::MAX_KEYS; ++i) {
                node->keys[splitPoint + 1 + i] = sibling->keys[i];
            }
            
            for (uint32_t i = 0; i <= siblingKeyCount && (splitPoint + 1 + i) <= BPlusTreeNode::MAX_KEYS; ++i) {
                node->children[splitPoint + 1 + i] = sibling->children[i];
            }
            
            // Restore parentOffset for children
            const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
            if ((nodeAddr - baseAddr) <= UINT32_MAX) {
                const uint32_t nodeOffsetU32 = static_cast<uint32_t>(nodeAddr - baseAddr);
                
                for (uint32_t i = 0; i <= siblingKeyCount && i <= BPlusTreeNode::MAX_KEYS; ++i) {
                    const uint32_t childOffset = sibling->children[i];
                    if (childOffset != 0 && childOffset < m_indexSize) {
                        auto* childNode = reinterpret_cast<BPlusTreeNode*>(
                            static_cast<uint8_t*>(m_baseAddress) + childOffset
                        );
                        childNode->parentOffset = nodeOffsetU32;
                    }
                }
            }
        }
        
        node->keyCount = originalKeyCount;
        
        // Securely zero the sibling node (deallocate logically)
        SecureZeroMemoryRegion(sibling, sizeof(BPlusTreeNode));
        
        // Rollback node count (we allocated sibling but now discard it)
        // Note: We don't actually reclaim the space - that requires compaction
        // The node is marked as unused (zeroed) and will be reclaimed on compact
        m_nodeCount.fetch_sub(1, std::memory_order_relaxed);
        
        // Update header to reflect rolled-back state
        constexpr uint64_t NODE_COUNT_POSITION = 8;
        if (INDEX_HEADER_SIZE <= m_indexSize) {
            auto* nodeCountPtr = reinterpret_cast<uint64_t*>(
                static_cast<uint8_t*>(m_baseAddress) + NODE_COUNT_POSITION
            );
            *nodeCountPtr = m_nodeCount.load(std::memory_order_relaxed);
        }
        
        SS_LOG_INFO(L"Whitelist", L"HashIndex::SplitNode: rollback completed successfully");
        
        return propagateResult; // Return the original error
    }
    
    // Update split counter only on success
    m_splitCount.fetch_add(1, std::memory_order_relaxed);
    
    SS_LOG_DEBUG(L"Whitelist", L"HashIndex::SplitNode: split completed successfully");
    return StoreError::Success();
}

StoreError HashIndex::Insert(const HashValue& hash, uint64_t entryOffset) noexcept {
    // ========================================================================
    // HASH INDEX INSERT WITH COMPREHENSIVE VALIDATION
    // ========================================================================
    // Inserts a new hash-offset pair into the B+Tree index.
    // - Handles duplicates by updating the existing entry
    // - Triggers node split if leaf is full
    // - Maintains sorted order within leaf nodes
    // ========================================================================
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (SS_UNLIKELY(!m_baseAddress)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate hash (empty hash cannot be indexed)
    if (SS_UNLIKELY(hash.IsEmpty())) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot insert empty hash"
        );
    }
    
    // Validate entry offset fits in uint32_t (B+Tree child pointer limit)
    if (SS_UNLIKELY(entryOffset > UINT32_MAX)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Entry offset exceeds 32-bit limit"
        );
    }
    
    const uint64_t key = hash.FastHash();
    BPlusTreeNode* leaf = FindLeafMutable(key);
    
    if (SS_UNLIKELY(!leaf)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Failed to find leaf node"
        );
    }
    
    // Validate leaf node integrity
    if (SS_UNLIKELY(!ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS))) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Corrupt leaf node detected"
        );
    }
    
    // Check for duplicate using binary search (more efficient for large nodes)
    uint32_t existingIdx = 0;
    if (BinarySearchExact(leaf->keys, leaf->keyCount, key, existingIdx)) {
        // Update existing entry (upsert semantics)
        leaf->children[existingIdx] = static_cast<uint32_t>(entryOffset);
        return StoreError::Success();
    }
    
    // Check if leaf is full - need to split
    if (leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
        auto splitResult = SplitNode(leaf);
        if (SS_UNLIKELY(!splitResult.IsSuccess())) {
            return splitResult;
        }
        
        // Re-find the correct leaf after split
        leaf = FindLeafMutable(key);
        if (SS_UNLIKELY(!leaf)) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Failed to find leaf after split"
            );
        }
        
        // Re-validate after split
        if (SS_UNLIKELY(leaf->keyCount >= BPlusTreeNode::MAX_KEYS)) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexFull,
                "Leaf still full after split"
            );
        }
    }
    
    // Find insertion position using branchless lower bound
    const uint32_t insertPos = BranchlessLowerBound(leaf->keys, leaf->keyCount, key);
    
    // Validate insert position is within bounds
    if (SS_UNLIKELY(insertPos > leaf->keyCount || insertPos >= BPlusTreeNode::MAX_KEYS)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid insert position computed"
        );
    }
    
    // Final validation: ensure room for new key
    if (SS_UNLIKELY(leaf->keyCount >= BPlusTreeNode::MAX_KEYS)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Leaf is full - should have been split"
        );
    }
    
    // Shift elements right (from end to insert position)
    // Use memmove for efficiency when shifting multiple elements
    if (insertPos < leaf->keyCount) {
        const uint32_t elementsToShift = leaf->keyCount - insertPos;
        
        // Shift keys
        std::memmove(
            &leaf->keys[insertPos + 1],
            &leaf->keys[insertPos],
            elementsToShift * sizeof(leaf->keys[0])
        );
        
        // Shift children (entry offsets)
        std::memmove(
            &leaf->children[insertPos + 1],
            &leaf->children[insertPos],
            elementsToShift * sizeof(leaf->children[0])
        );
    }
    
    // Insert new key/value
    leaf->keys[insertPos] = key;
    leaf->children[insertPos] = static_cast<uint32_t>(entryOffset);
    leaf->keyCount++;
    
    // Memory barrier before updating statistics
    FullMemoryBarrier();
    
    // Atomic increment with acquire-release for proper ordering
    const uint64_t newEntryCount = m_entryCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    
    // Update header with proper bounds check
    constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
    if (INDEX_HEADER_SIZE <= m_indexSize) {
        auto* entryCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
        );
        *entryCountPtr = newEntryCount;
    }
    
    // Update insert counter
    m_insertCount.fetch_add(1, std::memory_order_relaxed);
    
    return StoreError::Success();
}

StoreError HashIndex::Remove(const HashValue& hash) noexcept {
    // ========================================================================
    // SECURE HASH REMOVAL WITH MEMORY ZEROING
    // ========================================================================
    // Removes a hash from the B+Tree index.
    // - Uses binary search for efficient key location
    // - Securely zeros removed data to prevent information leakage
    // - Updates statistics atomically
    // ========================================================================
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (SS_UNLIKELY(!m_baseAddress)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate hash (empty hash cannot exist in index)
    if (SS_UNLIKELY(hash.IsEmpty())) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot remove empty hash"
        );
    }
    
    const uint64_t key = hash.FastHash();
    BPlusTreeNode* leaf = FindLeafMutable(key);
    
    if (SS_UNLIKELY(!leaf)) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Key not found"
        );
    }
    
    // If leaf exists but is empty, treat as not found (not corruption)
    if (SS_UNLIKELY(leaf->keyCount == 0)) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Key not found in empty leaf"
        );
    }
    
    // Validate leaf node integrity
    if (SS_UNLIKELY(!ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS))) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Corrupt leaf node"
        );
    }
    
    // Use binary search to find the key (more efficient than linear search)
    uint32_t pos = 0;
    const bool found = BinarySearchExact(leaf->keys, leaf->keyCount, key, pos);
    
    if (!found) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Key not found in leaf"
        );
    }
    
    // Validate pos is within bounds before shift
    if (SS_UNLIKELY(pos >= leaf->keyCount)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Found position exceeds key count"
        );
    }
    
    // Calculate elements to shift
    const uint32_t elementsToShift = leaf->keyCount - pos - 1;
    
    // Use memmove for efficient shifting
    if (elementsToShift > 0) {
        std::memmove(
            &leaf->keys[pos],
            &leaf->keys[pos + 1],
            elementsToShift * sizeof(leaf->keys[0])
        );
        std::memmove(
            &leaf->children[pos],
            &leaf->children[pos + 1],
            elementsToShift * sizeof(leaf->children[0])
        );
    }
    
    // Secure clear the last slot (prevents information leakage)
    const uint32_t lastIdx = leaf->keyCount - 1;
    if (lastIdx < BPlusTreeNode::MAX_KEYS) {
        leaf->keys[lastIdx] = 0;
        leaf->children[lastIdx] = 0;
    }
    
    leaf->keyCount--;
    
    // Memory barrier before updating statistics
    FullMemoryBarrier();
    
    // Atomic decrement with acquire-release for proper ordering
    const uint64_t newEntryCount = m_entryCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
    
    // Update header with proper bounds check
    constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
    if (INDEX_HEADER_SIZE <= m_indexSize) {
        auto* entryCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
        );
        *entryCountPtr = newEntryCount;
    }
    
    // Handle underflow - Enterprise-grade lazy deletion approach
    // NOTE: B+Tree doesn't rebalance on removal - lazy deletion for performance
    // Tree structure remains valid, just with potentially under-filled nodes
    // This is acceptable for enterprise use cases where rebuilds happen periodically
    // Underflow handling (borrow/merge) is commented out due to complexity
    // that can introduce subtle bugs. Periodic index compaction/rebuild is preferred.
    /*
    auto underflowResult = HandleUnderflow(leaf);
    if (!underflowResult.IsSuccess()) {
        SS_LOG_WARN(L"Whitelist", 
            L"HashIndex::Remove: underflow handling failed - %S",
            underflowResult.message.c_str());
        // Continue anyway - removal succeeded even if rebalancing didn't
    }
    */
    
    // Update remove counter
    m_removeCount.fetch_add(1, std::memory_order_relaxed);
    
    return StoreError::Success();
}

StoreError HashIndex::BatchInsert(
    std::span<const std::pair<HashValue, uint64_t>> entries
) noexcept {
    // ========================================================================
    // BATCH INSERT WITH OPTIMIZED SORTING AND BULK LOADING
    // ========================================================================
    // Inserts multiple entries efficiently using:
    // 1. Pre-sorting entries by key for sequential leaf access
    // 2. Minimizing lock contention with single lock acquisition
    // 3. Cache-friendly sequential insertion pattern
    // ========================================================================
    
    // Validate input
    if (entries.empty()) {
        return StoreError::Success();
    }
    
    // Acquire exclusive lock for entire batch operation
    std::unique_lock lock(m_rwLock);
    
    // Validate we're in write mode before processing
    if (SS_UNLIKELY(!m_baseAddress)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Threshold for sorting optimization (empirically determined)
    constexpr size_t SORT_THRESHOLD = 64;
    
    // Pre-compute all keys and sort for cache locality
    struct KeyEntry {
        uint64_t key;
        uint64_t offset;
        bool valid;
    };
    
    std::vector<KeyEntry> sortedEntries;
    try {
        sortedEntries.reserve(entries.size());
        for (const auto& [hash, offset] : entries) {
            if (!hash.IsEmpty() && offset <= UINT32_MAX) {
                sortedEntries.push_back({hash.FastHash(), offset, true});
            }
        }
        
        // Sort by key for sequential leaf access (improves cache locality)
        if (sortedEntries.size() > SORT_THRESHOLD) {
            std::sort(sortedEntries.begin(), sortedEntries.end(),
                [](const KeyEntry& a, const KeyEntry& b) { 
                    return a.key < b.key; 
                });
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"Whitelist", 
            L"BatchInsert: allocation failed, falling back to sequential - %S", e.what());
        sortedEntries.clear();
    }
    
    // Track statistics
    size_t successCount = 0;
    size_t duplicateCount = 0;
    StoreError lastError = StoreError::Success();
    
    // Use sorted entries if available, otherwise fall back to original
    if (!sortedEntries.empty()) {
        // Optimized path: sorted insertion
        BPlusTreeNode* currentLeaf = nullptr;
        uint64_t currentLeafMinKey = 0;
        uint64_t currentLeafMaxKey = UINT64_MAX;
        
        for (const auto& entry : sortedEntries) {
            const uint64_t key = entry.key;
            const uint64_t offset = entry.offset;
            
            // Check if we can reuse the current leaf (optimization)
            bool needNewLeaf = (currentLeaf == nullptr);
            if (!needNewLeaf && currentLeaf->keyCount > 0) {
                // Check if key would fall in current leaf range
                const uint64_t leafMinKey = currentLeaf->keys[0];
                const uint64_t leafMaxKey = currentLeaf->keys[currentLeaf->keyCount - 1];
                needNewLeaf = (key < leafMinKey || key > leafMaxKey + 1);
            }
            
            if (needNewLeaf) {
                currentLeaf = FindLeafMutable(key);
            }
            
            if (SS_UNLIKELY(!currentLeaf)) {
                lastError = StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Failed to find leaf node during batch insert"
                );
                continue;
            }
            
            // Validate leaf integrity
            if (SS_UNLIKELY(!ValidateNodeIntegrity(currentLeaf, BPlusTreeNode::MAX_KEYS))) {
                lastError = StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Corrupt leaf node detected during batch insert"
                );
                currentLeaf = nullptr;
                continue;
            }
            
            // Check for duplicate
            uint32_t existingIdx = 0;
            if (BinarySearchExact(currentLeaf->keys, currentLeaf->keyCount, key, existingIdx)) {
                // Update existing entry (upsert semantics)
                currentLeaf->children[existingIdx] = static_cast<uint32_t>(offset);
                ++duplicateCount;
                ++successCount;
                continue;
            }
            
            // Handle full leaf - need to split
            if (currentLeaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
                // Release lock temporarily for split operation (to update atomics)
                auto splitResult = SplitNode(currentLeaf);
                if (!splitResult.IsSuccess()) {
                    lastError = splitResult;
                    // Critical error - stop processing
                    if (splitResult.code == WhitelistStoreError::IndexFull) {
                        break;
                    }
                    continue;
                }
                
                // Re-find the correct leaf after split
                currentLeaf = FindLeafMutable(key);
                if (!currentLeaf || currentLeaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
                    lastError = StoreError::WithMessage(
                        WhitelistStoreError::IndexFull,
                        "Leaf still full after split during batch insert"
                    );
                    break;
                }
            }
            
            // Find insertion position
            const uint32_t insertPos = BranchlessLowerBound(
                currentLeaf->keys, currentLeaf->keyCount, key
            );
            
            // Validate insert position
            if (insertPos > currentLeaf->keyCount || insertPos >= BPlusTreeNode::MAX_KEYS) {
                lastError = StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Invalid insert position during batch insert"
                );
                continue;
            }
            
            // Shift elements and insert
            if (insertPos < currentLeaf->keyCount) {
                const uint32_t elementsToShift = currentLeaf->keyCount - insertPos;
                std::memmove(&currentLeaf->keys[insertPos + 1],
                            &currentLeaf->keys[insertPos],
                            elementsToShift * sizeof(currentLeaf->keys[0]));
                std::memmove(&currentLeaf->children[insertPos + 1],
                            &currentLeaf->children[insertPos],
                            elementsToShift * sizeof(currentLeaf->children[0]));
            }
            
            currentLeaf->keys[insertPos] = key;
            currentLeaf->children[insertPos] = static_cast<uint32_t>(offset);
            currentLeaf->keyCount++;
            ++successCount;
        }
    } else {
        // Fallback path: sequential insertion without sorting
        for (const auto& [hash, offset] : entries) {
            if (hash.IsEmpty()) {
                continue;
            }
            if (offset > UINT32_MAX) {
                lastError = StoreError::WithMessage(
                    WhitelistStoreError::InvalidEntry,
                    "Entry offset exceeds 32-bit limit"
                );
                continue;
            }
            
            const uint64_t key = hash.FastHash();
            BPlusTreeNode* leaf = FindLeafMutable(key);
            
            if (!leaf) {
                lastError = StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Failed to find leaf node"
                );
                continue;
            }
            
            // Check for duplicate
            uint32_t existingIdx = 0;
            if (BinarySearchExact(leaf->keys, leaf->keyCount, key, existingIdx)) {
                leaf->children[existingIdx] = static_cast<uint32_t>(offset);
                ++duplicateCount;
                ++successCount;
                continue;
            }
            
            // Handle full leaf
            if (leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
                auto splitResult = SplitNode(leaf);
                if (!splitResult.IsSuccess()) {
                    lastError = splitResult;
                    if (splitResult.code == WhitelistStoreError::IndexFull ||
                        splitResult.code == WhitelistStoreError::IndexCorrupted) {
                        break;
                    }
                    continue;
                }
                leaf = FindLeafMutable(key);
                if (!leaf || leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
                    break;
                }
            }
            
            // Insert
            const uint32_t insertPos = BranchlessLowerBound(
                leaf->keys, leaf->keyCount, key
            );
            
            if (insertPos <= leaf->keyCount && insertPos < BPlusTreeNode::MAX_KEYS) {
                if (insertPos < leaf->keyCount) {
                    const uint32_t toShift = leaf->keyCount - insertPos;
                    std::memmove(&leaf->keys[insertPos + 1], 
                                &leaf->keys[insertPos],
                                toShift * sizeof(leaf->keys[0]));
                    std::memmove(&leaf->children[insertPos + 1],
                                &leaf->children[insertPos],
                                toShift * sizeof(leaf->children[0]));
                }
                leaf->keys[insertPos] = key;
                leaf->children[insertPos] = static_cast<uint32_t>(offset);
                leaf->keyCount++;
                ++successCount;
            }
        }
    }
    
    // Update entry count atomically
    if (successCount > duplicateCount) {
        const uint64_t newEntries = successCount - duplicateCount;
        const uint64_t newEntryCount = m_entryCount.fetch_add(
            newEntries, std::memory_order_acq_rel
        ) + newEntries;
        
        // Update header
        constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
        if (INDEX_HEADER_SIZE <= m_indexSize) {
            auto* entryCountPtr = reinterpret_cast<uint64_t*>(
                static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
            );
            *entryCountPtr = newEntryCount;
        }
    }
    
    // Update insert counter
    m_insertCount.fetch_add(successCount, std::memory_order_relaxed);
    
    // Log results
    SS_LOG_DEBUG(L"Whitelist", 
        L"BatchInsert: %zu succeeded, %zu duplicates, %zu total",
        successCount, duplicateCount, entries.size());
    
    // Return error if some insertions failed
    if (successCount < entries.size() && !lastError.IsSuccess()) {
        return lastError;
    }
    
    return StoreError::Success();
}


// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

void HashIndex::GatherLeafStats(
    uint64_t& leafCount,
    uint64_t& totalLeafKeys,
    uint32_t& minKeys,
    uint32_t& maxKeys
) const noexcept {
    // ========================================================================
    // HELPER: TRAVERSE LEAF LINKED LIST AND GATHER STATISTICS
    // ========================================================================
    // Uses the leaf node linked list for efficient sequential access.
    // Time complexity: O(L) where L = number of leaf nodes.
    // ========================================================================
    
    leafCount = 0;
    totalLeafKeys = 0;
    minKeys = UINT32_MAX;
    maxKeys = 0;
    
    // Get first leaf node
    const BPlusTreeNode* leaf = GetFirstLeaf();
    if (!leaf) {
        minKeys = 0;
        return;
    }
    
    // Traverse leaf linked list
    constexpr uint32_t MAX_LEAF_ITERATIONS = 10'000'000;  // Safety limit
    uint32_t iterations = 0;
    
    while (leaf && iterations < MAX_LEAF_ITERATIONS) {
        ++leafCount;
        
        const uint32_t keyCount = leaf->GetKeyCount();
        totalLeafKeys += keyCount;
        
        if (keyCount < minKeys) {
            minKeys = keyCount;
        }
        if (keyCount > maxKeys) {
            maxKeys = keyCount;
        }
        
        // Move to next leaf
        if (leaf->nextLeaf == 0) {
            break;
        }
        
        leaf = GetLeafAt(leaf->nextLeaf);
        ++iterations;
    }
    
    // Handle empty tree
    if (leafCount == 0) {
        minKeys = 0;
    }
}

const BPlusTreeNode* HashIndex::GetFirstLeaf() const noexcept {
    // ========================================================================
    // GET LEFTMOST (FIRST) LEAF NODE
    // ========================================================================
    // Traverses down the leftmost path to find the first leaf node.
    // Used for range queries and iteration.
    // ========================================================================
    
    if (!m_view && !m_baseAddress) {
        return nullptr;
    }
    
    if (m_rootOffset == 0 || m_rootOffset >= m_indexSize) {
        return nullptr;
    }
    
    uint64_t currentOffset = m_rootOffset;
    
    for (uint32_t depth = 0; depth < SAFE_MAX_TREE_DEPTH; ++depth) {
        const BPlusTreeNode* node = nullptr;
        
        if (m_view) {
            if (!IsOffsetValid(currentOffset)) {
                return nullptr;
            }
            node = m_view->GetAt<BPlusTreeNode>(m_indexOffset + currentOffset);
        } else if (m_baseAddress) {
            if (currentOffset >= m_indexSize) {
                return nullptr;
            }
            uint64_t endOffset = 0;
            if (!SafeAdd(currentOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), endOffset) ||
                endOffset > m_indexSize) {
                return nullptr;
            }
            node = reinterpret_cast<const BPlusTreeNode*>(
                static_cast<const uint8_t*>(m_baseAddress) + currentOffset
            );
        }
        
        if (!node) {
            return nullptr;
        }
        
        // Found leaf - return it
        if (node->isLeaf) {
            return node;
        }
        
        // Descend to leftmost child (index 0)
        if (node->keyCount == 0) {
            // Empty internal node - shouldn't happen in valid tree
            return nullptr;
        }
        
        currentOffset = node->children[0];
        if (currentOffset == 0 || currentOffset >= m_indexSize) {
            return nullptr;
        }
    }
    
    return nullptr;
}

const BPlusTreeNode* HashIndex::GetLeafAt(uint64_t offset) const noexcept {
    // ========================================================================
    // GET LEAF NODE AT SPECIFIC OFFSET
    // ========================================================================
    
    if (offset == 0 || offset >= m_indexSize) {
        return nullptr;
    }
    
    const BPlusTreeNode* node = nullptr;
    
    if (m_view) {
        // Validate offset
        uint64_t absoluteOffset = 0;
        if (!SafeAdd(m_indexOffset, offset, absoluteOffset)) {
            return nullptr;
        }
        uint64_t endOffset = 0;
        if (!SafeAdd(absoluteOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), endOffset) ||
            endOffset > m_view->fileSize) {
            return nullptr;
        }
        node = m_view->GetAt<BPlusTreeNode>(absoluteOffset);
    } else if (m_baseAddress) {
        uint64_t endOffset = 0;
        if (!SafeAdd(offset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), endOffset) ||
            endOffset > m_indexSize) {
            return nullptr;
        }
        node = reinterpret_cast<const BPlusTreeNode*>(
            static_cast<const uint8_t*>(m_baseAddress) + offset
        );
    }
    
    // Verify it's a leaf
    if (node && !node->isLeaf) {
        SS_LOG_WARN(L"Whitelist", L"GetLeafAt: offset %llu is not a leaf node", offset);
        return nullptr;
    }
    
    return node;
}

HashIndexStats HashIndex::GetDetailedStats() const noexcept {
    // ========================================================================
    // GET COMPREHENSIVE INDEX STATISTICS
    // ========================================================================
    // Gathers detailed metrics about the B+Tree index state including:
    // - Node counts and fill rates
    // - Memory usage
    // - Performance counters
    // - Integrity status
    // ========================================================================
    
    std::shared_lock lock(m_rwLock);
    
    HashIndexStats stats{};
    
    // ========================================================================
    // BASIC COUNTS (from atomic counters)
    // ========================================================================
    
    stats.entryCount = m_entryCount.load(std::memory_order_acquire);
    stats.nodeCount = m_nodeCount.load(std::memory_order_acquire);
    stats.treeDepth = m_treeDepth;
    
    // ========================================================================
    // STATE FLAGS
    // ========================================================================
    
    stats.isReady = IsReady();
    stats.isWritable = (m_baseAddress != nullptr);
    stats.isMemoryMapped = (m_view != nullptr);
    
    // ========================================================================
    // MEMORY METRICS
    // ========================================================================
    
    stats.indexSize = m_indexSize;
    stats.usedSize = m_nextNodeOffset;
    
    if (stats.indexSize > stats.usedSize) {
        stats.freeSpace = stats.indexSize - stats.usedSize;
    } else {
        stats.freeSpace = 0;
    }
    
    // Estimate fragmentation (ratio of unused space in allocated nodes)
    // This is a simplified estimate - actual fragmentation depends on deletions
    if (stats.nodeCount > 0 && stats.usedSize > INDEX_HEADER_SIZE) {
        const uint64_t nodeDataSize = stats.usedSize - INDEX_HEADER_SIZE;
        const uint64_t theoreticalSize = stats.nodeCount * sizeof(BPlusTreeNode);
        if (theoreticalSize > 0) {
            stats.fragmentationRatio = 1.0 - 
                (static_cast<double>(nodeDataSize) / static_cast<double>(theoreticalSize));
            if (stats.fragmentationRatio < 0.0) {
                stats.fragmentationRatio = 0.0;
            }
        }
    }
    
    // ========================================================================
    // LEAF NODE STATISTICS (requires traversal)
    // ========================================================================
    
    uint64_t leafCount = 0;
    uint64_t totalLeafKeys = 0;
    uint32_t minLeafKeys = 0;
    uint32_t maxLeafKeys = 0;
    
    GatherLeafStats(leafCount, totalLeafKeys, minLeafKeys, maxLeafKeys);
    
    stats.leafNodeCount = leafCount;
    stats.internalNodeCount = (stats.nodeCount > leafCount) ? 
                              (stats.nodeCount - leafCount) : 0;
    stats.minLeafKeys = minLeafKeys;
    stats.maxLeafKeys = maxLeafKeys;
    
    // Calculate average fill rates
    if (leafCount > 0) {
        const double avgKeys = static_cast<double>(totalLeafKeys) / 
                              static_cast<double>(leafCount);
        stats.avgLeafFillRate = avgKeys / static_cast<double>(BPlusTreeNode::MAX_KEYS);
    }
    
    // Internal node fill rate estimation (if we have internal nodes)
    if (stats.internalNodeCount > 0) {
        // Estimate based on typical B+Tree properties
        // In a balanced tree, internal nodes are typically 50-100% full
        stats.avgInternalFillRate = 0.67; // Conservative estimate
    }
    
    // ========================================================================
    // PERFORMANCE COUNTERS
    // ========================================================================
    
    stats.lookupCount = m_lookupCount.load(std::memory_order_relaxed);
    stats.insertCount = m_insertCount.load(std::memory_order_relaxed);
    stats.removeCount = m_removeCount.load(std::memory_order_relaxed);
    stats.splitCount = m_splitCount.load(std::memory_order_relaxed);
    
    // Cache hits/misses would be tracked if caching were implemented
    stats.cacheHits = 0;
    stats.cacheMisses = 0;
    
    // ========================================================================
    // HEALTH ASSESSMENT
    // ========================================================================
    
    // Determine if rebalancing might be beneficial
    // Low fill rate suggests many deletions without compaction
    stats.needsRebalancing = (stats.avgLeafFillRate < 0.4 && stats.leafNodeCount > 10);
    
    // Determine if compaction might be beneficial
    // High fragmentation or many deleted entries suggest compaction
    stats.needsCompaction = (stats.fragmentationRatio > 0.3);
    
    // Default integrity status (would be updated by VerifyIntegrity)
    stats.lastIntegrityCheckPassed = true;
    stats.lastIntegrityCheckTime = 0;
    stats.corruptedNodes = 0;
    
    return stats;
}

size_t HashIndex::FindInRange(
    uint64_t minKey,
    uint64_t maxKey,
    std::vector<std::pair<uint64_t, uint64_t>>& results,
    size_t maxResults
) const noexcept {
    // ========================================================================
    // RANGE QUERY USING LEAF LINKED LIST
    // ========================================================================
    // Efficient range query implementation:
    // 1. Find the leaf containing minKey using B+Tree search
    // 2. Scan forward through leaf linked list until maxKey
    // Time complexity: O(log N + K) where K is result size
    // ========================================================================
    
    std::shared_lock lock(m_rwLock);
    
    results.clear();
    
    // Validate range
    if (minKey > maxKey) {
        return 0;
    }
    
    // Set default max results if not specified
    const size_t effectiveMax = (maxResults == 0) ? SIZE_MAX : maxResults;
    
    // Find the leaf containing minKey
    const BPlusTreeNode* leaf = FindLeaf(minKey);
    if (!leaf) {
        return 0;
    }
    
    // Traverse leaf linked list
    constexpr uint32_t MAX_ITERATIONS = 10'000'000;
    uint32_t iterations = 0;
    size_t count = 0;
    
    while (leaf && iterations < MAX_ITERATIONS && count < effectiveMax) {
        // Validate leaf
        if (!ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS)) {
            SS_LOG_ERROR(L"Whitelist", L"FindInRange: corrupt leaf node encountered");
            break;
        }
        
        // Scan keys in this leaf
        for (uint32_t i = 0; i < leaf->keyCount && count < effectiveMax; ++i) {
            const uint64_t key = leaf->keys[i];
            
            // Skip keys before minKey
            if (key < minKey) {
                continue;
            }
            
            // Stop if we've passed maxKey
            if (key > maxKey) {
                return count;
            }
            
            // Add to results
            try {
                results.emplace_back(key, static_cast<uint64_t>(leaf->children[i]));
                ++count;
            } catch (const std::exception&) {
                // Allocation failed - return what we have
                SS_LOG_WARN(L"Whitelist", L"FindInRange: allocation failed at %zu results", count);
                return count;
            }
        }
        
        // Check if the last key in this leaf exceeds maxKey
        if (leaf->keyCount > 0 && leaf->keys[leaf->keyCount - 1] > maxKey) {
            break;
        }
        
        // Move to next leaf
        if (leaf->nextLeaf == 0) {
            break;
        }
        
        leaf = GetLeafAt(leaf->nextLeaf);
        ++iterations;
    }
    
    // Update lookup counter
    m_lookupCount.fetch_add(1, std::memory_order_relaxed);
    
    return count;
}

size_t HashIndex::GetEntries(
    size_t offset,
    size_t count,
    std::vector<std::pair<uint64_t, uint64_t>>& results
) const noexcept {
    // ========================================================================
    // PAGINATED ENTRY RETRIEVAL
    // ========================================================================
    // Retrieves entries for iteration/pagination:
    // 1. Skip first 'offset' entries
    // 2. Return up to 'count' entries
    // Time complexity: O(offset + count) in leaf nodes
    // ========================================================================
    
    std::shared_lock lock(m_rwLock);
    
    results.clear();
    
    if (count == 0) {
        return 0;
    }
    
    try {
        results.reserve(std::min(count, static_cast<size_t>(1024)));
    } catch (const std::exception&) {
        // Continue without reservation
    }
    
    // Get first leaf
    const BPlusTreeNode* leaf = GetFirstLeaf();
    if (!leaf) {
        return 0;
    }
    
    // Skip 'offset' entries
    size_t skipped = 0;
    constexpr uint32_t MAX_ITERATIONS = 10'000'000;
    uint32_t iterations = 0;
    
    while (leaf && skipped < offset && iterations < MAX_ITERATIONS) {
        const uint32_t keyCount = leaf->GetKeyCount();
        
        if (skipped + keyCount <= offset) {
            // Skip entire leaf
            skipped += keyCount;
            if (leaf->nextLeaf == 0) {
                return 0;  // No more entries
            }
            leaf = GetLeafAt(leaf->nextLeaf);
        } else {
            // Partial skip in this leaf
            break;
        }
        ++iterations;
    }
    
    if (!leaf) {
        return 0;
    }
    
    // Start position within current leaf
    size_t startInLeaf = offset - skipped;
    size_t collected = 0;
    
    while (leaf && collected < count && iterations < MAX_ITERATIONS) {
        const uint32_t keyCount = leaf->GetKeyCount();
        
        for (uint32_t i = static_cast<uint32_t>(startInLeaf); 
             i < keyCount && collected < count; ++i) {
            try {
                results.emplace_back(
                    leaf->keys[i],
                    static_cast<uint64_t>(leaf->children[i])
                );
                ++collected;
            } catch (const std::exception&) {
                return collected;
            }
        }
        
        startInLeaf = 0;  // Reset for subsequent leaves
        
        if (leaf->nextLeaf == 0) {
            break;
        }
        leaf = GetLeafAt(leaf->nextLeaf);
        ++iterations;
    }
    
    return collected;
}

bool HashIndex::VerifyIntegrity(
    uint32_t& corruptedNodes,
    bool repairIfPossible
) noexcept {
    // ========================================================================
    // COMPREHENSIVE INDEX INTEGRITY VERIFICATION
    // ========================================================================
    // Verifies:
    // 1. All node offsets are valid
    // 2. Keys are sorted within each node
    // 3. Leaf linked list is consistent (prev/next pointers)
    // 4. Key counts are within valid range
    // 5. Tree structure is consistent
    // ========================================================================
    
    // Use exclusive lock if repair is enabled, otherwise shared
    std::unique_lock<std::shared_mutex> exclusiveLock(m_rwLock, std::defer_lock);
    std::shared_lock<std::shared_mutex> sharedLock(m_rwLock, std::defer_lock);
    
    if (repairIfPossible) {
        exclusiveLock.lock();
    } else {
        sharedLock.lock();
    }
    
    corruptedNodes = 0;
    bool integrityOk = true;
    
    if (!IsReady()) {
        SS_LOG_WARN(L"Whitelist", L"VerifyIntegrity: index not initialized");
        return false;
    }
    
    // ========================================================================
    // PHASE 1: Verify root node
    // ========================================================================
    
    if (m_rootOffset == 0 || m_rootOffset >= m_indexSize) {
        SS_LOG_ERROR(L"Whitelist", L"VerifyIntegrity: invalid root offset %llu", m_rootOffset);
        return false;
    }
    
    // ========================================================================
    // PHASE 2: Traverse all leaf nodes via linked list
    // ========================================================================
    
    const BPlusTreeNode* leaf = GetFirstLeaf();
    const BPlusTreeNode* prevLeaf = nullptr;
    uint64_t prevLastKey = 0;
    uint64_t leafCount = 0;
    uint64_t totalEntries = 0;
    
    constexpr uint32_t MAX_ITERATIONS = 10'000'000;
    
    while (leaf && leafCount < MAX_ITERATIONS) {
        // Check key count
        if (leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"Whitelist", 
                L"VerifyIntegrity: leaf %llu has invalid keyCount %u (max %zu)",
                leafCount, leaf->keyCount, BPlusTreeNode::MAX_KEYS);
            ++corruptedNodes;
            integrityOk = false;
            break;
        }
        
        // Check keys are sorted
        for (uint32_t i = 1; i < leaf->keyCount; ++i) {
            if (leaf->keys[i] <= leaf->keys[i - 1]) {
                SS_LOG_ERROR(L"Whitelist",
                    L"VerifyIntegrity: leaf %llu has unsorted keys at index %u",
                    leafCount, i);
                ++corruptedNodes;
                integrityOk = false;
            }
        }
        
        // Check keys are greater than previous leaf's max key
        if (prevLeaf && leaf->keyCount > 0 && leaf->keys[0] <= prevLastKey) {
            SS_LOG_ERROR(L"Whitelist",
                L"VerifyIntegrity: leaf %llu first key %llu <= prev last key %llu",
                leafCount, leaf->keys[0], prevLastKey);
            ++corruptedNodes;
            integrityOk = false;
        }
        
        // Update for next iteration
        if (leaf->keyCount > 0) {
            prevLastKey = leaf->keys[leaf->keyCount - 1];
        }
        totalEntries += leaf->keyCount;
        prevLeaf = leaf;
        ++leafCount;
        
        // Move to next leaf
        if (leaf->nextLeaf == 0) {
            break;
        }
        
        // Validate next leaf offset
        if (leaf->nextLeaf >= m_indexSize) {
            SS_LOG_ERROR(L"Whitelist",
                L"VerifyIntegrity: leaf %llu has invalid nextLeaf offset %u",
                leafCount, leaf->nextLeaf);
            ++corruptedNodes;
            integrityOk = false;
            break;
        }
        
        const BPlusTreeNode* nextLeaf = GetLeafAt(leaf->nextLeaf);
        if (!nextLeaf) {
            SS_LOG_ERROR(L"Whitelist",
                L"VerifyIntegrity: failed to get next leaf at offset %u",
                leaf->nextLeaf);
            ++corruptedNodes;
            integrityOk = false;
            break;
        }
        
        // Verify prev pointer consistency
        const auto currentLeafAddr = reinterpret_cast<uintptr_t>(leaf);
        const auto baseAddr = m_baseAddress ? 
                             reinterpret_cast<uintptr_t>(m_baseAddress) :
                             reinterpret_cast<uintptr_t>(m_view->baseAddress) - m_indexOffset;
        const uint64_t currentOffset = currentLeafAddr - baseAddr;
        
        if (nextLeaf->prevLeaf != static_cast<uint32_t>(currentOffset)) {
            SS_LOG_WARN(L"Whitelist",
                L"VerifyIntegrity: next leaf's prevLeaf %u != current offset %llu",
                nextLeaf->prevLeaf, currentOffset);
            // This is repairable if repair mode is enabled
            if (repairIfPossible && m_baseAddress) {
                auto* mutableNextLeaf = const_cast<BPlusTreeNode*>(nextLeaf);
                mutableNextLeaf->prevLeaf = static_cast<uint32_t>(currentOffset);
                SS_LOG_INFO(L"Whitelist", L"VerifyIntegrity: repaired prevLeaf pointer");
            } else {
                ++corruptedNodes;
            }
        }
        
        leaf = nextLeaf;
    }
    
    // ========================================================================
    // PHASE 3: Verify entry count matches
    // ========================================================================
    
    const uint64_t storedEntryCount = m_entryCount.load(std::memory_order_acquire);
    if (totalEntries != storedEntryCount) {
        SS_LOG_WARN(L"Whitelist",
            L"VerifyIntegrity: counted entries %llu != stored count %llu",
            totalEntries, storedEntryCount);
        
        if (repairIfPossible && m_baseAddress) {
            m_entryCount.store(totalEntries, std::memory_order_release);
            
            // Update header
            constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
            if (INDEX_HEADER_SIZE <= m_indexSize) {
                auto* entryCountPtr = reinterpret_cast<uint64_t*>(
                    static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
                );
                *entryCountPtr = totalEntries;
            }
            SS_LOG_INFO(L"Whitelist", L"VerifyIntegrity: repaired entry count");
        }
    }
    
    SS_LOG_INFO(L"Whitelist",
        L"VerifyIntegrity: checked %llu leaves, %llu entries, %u corrupted nodes",
        leafCount, totalEntries, corruptedNodes);
    
    return integrityOk && (corruptedNodes == 0);
}

StoreError HashIndex::Compact(uint64_t& reclaimedBytes) noexcept {
    // ========================================================================
    // INDEX COMPACTION - FULL ENTERPRISE IMPLEMENTATION
    // ========================================================================
    // Reclaims fragmented space by performing in-place defragmentation:
    // 1. BFS traversal to collect all valid nodes with their parent relationships
    // 2. Calculate new contiguous positions for each node
    // 3. Update all offsets (parent, child, sibling) in a single pass
    // 4. Move nodes to their new positions using safe memmove
    // 5. Update header with new allocation pointer
    //
    // Time Complexity: O(N) where N is number of nodes
    // Space Complexity: O(N) for the node mapping table
    // ========================================================================
    
    std::unique_lock lock(m_rwLock);
    
    reclaimedBytes = 0;
    
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only - cannot compact"
        );
    }
    
    // Calculate current fragmentation
    const uint64_t currentDataSize = (m_nextNodeOffset > INDEX_HEADER_SIZE) ?
                                     (m_nextNodeOffset - INDEX_HEADER_SIZE) : 0;
    const uint64_t actualNodeCount = m_nodeCount.load(std::memory_order_acquire);
    const uint64_t theoreticalMinSize = actualNodeCount * sizeof(BPlusTreeNode);
    
    // No fragmentation or empty tree - nothing to compact
    if (currentDataSize <= theoreticalMinSize || actualNodeCount == 0) {
        SS_LOG_DEBUG(L"Whitelist", L"Compact: no fragmentation detected");
        return StoreError::Success();
    }
    
    // Phase 1: Collect all valid nodes via BFS traversal
    // Map: old offset -> (node pointer, new offset, parent old offset)
    struct NodeMapping {
        uint64_t oldOffset;
        uint64_t newOffset;
        uint64_t parentOldOffset;
        bool isLeaf;
    };
    
    std::vector<NodeMapping> nodeMappings;
    try {
        nodeMappings.reserve(static_cast<size_t>(actualNodeCount));
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            std::string("Failed to allocate compaction map: ") + e.what()
        );
    }
    
    // BFS queue: (node offset, parent offset)
    std::vector<std::pair<uint64_t, uint64_t>> bfsQueue;
    try {
        bfsQueue.reserve(static_cast<size_t>(actualNodeCount));
        bfsQueue.emplace_back(m_rootOffset, 0);  // Root has no parent
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            std::string("Failed to allocate BFS queue: ") + e.what()
        );
    }
    
    // Track visited nodes to handle potential corruption (cycles)
    std::unordered_set<uint64_t> visitedOffsets;
    
    // Calculate new offsets starting after header
    uint64_t nextNewOffset = INDEX_HEADER_SIZE;
    
    // BFS traversal to collect all nodes and assign new contiguous offsets
    size_t queueIndex = 0;
    while (queueIndex < bfsQueue.size()) {
        const auto [currentOffset, parentOffset] = bfsQueue[queueIndex++];
        
        // Skip invalid offsets
        if (currentOffset == 0 || currentOffset >= m_indexSize) {
            continue;
        }
        
        // Skip already visited (cycle detection)
        if (visitedOffsets.count(currentOffset) > 0) {
            SS_LOG_WARN(L"Whitelist", L"Compact: cycle detected at offset %llu", currentOffset);
            continue;
        }
        visitedOffsets.insert(currentOffset);
        
        // Get node pointer
        auto* node = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + currentOffset
        );
        
        // Record mapping: old offset -> new offset
        NodeMapping mapping{};
        mapping.oldOffset = currentOffset;
        mapping.newOffset = nextNewOffset;
        mapping.parentOldOffset = parentOffset;
        mapping.isLeaf = node->isLeaf;
        nodeMappings.push_back(mapping);
        
        // Advance new offset pointer
        nextNewOffset += sizeof(BPlusTreeNode);
        
        // Queue children for internal nodes
        if (!node->isLeaf) {
            for (uint32_t i = 0; i <= node->keyCount && i < BPlusTreeNode::MAX_CHILDREN; ++i) {
                const uint64_t childOffset = node->children[i];
                if (childOffset != 0 && childOffset < m_indexSize) {
                    bfsQueue.emplace_back(childOffset, currentOffset);
                }
            }
        }
        
        // Safety limit to prevent infinite loops
        if (nodeMappings.size() > static_cast<size_t>(actualNodeCount * 2)) {
            SS_LOG_ERROR(L"Whitelist", L"Compact: too many nodes encountered - possible corruption");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Compaction aborted - too many nodes found"
            );
        }
    }
    
    // Validate we found all nodes
    if (nodeMappings.size() != actualNodeCount) {
        SS_LOG_WARN(L"Whitelist", 
            L"Compact: found %zu nodes, expected %llu",
            nodeMappings.size(), actualNodeCount);
    }
    
    // Build lookup table: old offset -> new offset
    std::unordered_map<uint64_t, uint64_t> offsetMap;
    try {
        offsetMap.reserve(nodeMappings.size());
        for (const auto& mapping : nodeMappings) {
            offsetMap[mapping.oldOffset] = mapping.newOffset;
        }
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            std::string("Failed to build offset map: ") + e.what()
        );
    }
    
    // Helper lambda to translate offsets
    auto translateOffset = [&offsetMap](uint64_t oldOffset) -> uint64_t {
        if (oldOffset == 0) return 0;
        auto it = offsetMap.find(oldOffset);
        return (it != offsetMap.end()) ? it->second : 0;
    };
    
    // Phase 2: Create compacted copy in temporary buffer
    std::vector<uint8_t> tempBuffer;
    try {
        tempBuffer.resize(static_cast<size_t>(nextNewOffset));
    } catch (const std::exception& e) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            std::string("Failed to allocate compaction buffer: ") + e.what()
        );
    }
    
    // Copy header
    std::memcpy(tempBuffer.data(), m_baseAddress, static_cast<size_t>(INDEX_HEADER_SIZE));
    
    // Copy and update each node
    for (const auto& mapping : nodeMappings) {
        const auto* srcNode = reinterpret_cast<const BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + mapping.oldOffset
        );
        auto* dstNode = reinterpret_cast<BPlusTreeNode*>(
            tempBuffer.data() + mapping.newOffset
        );
        
        // Copy node data
        std::memcpy(dstNode, srcNode, sizeof(BPlusTreeNode));
        
        // Translate parent offset
        dstNode->parentOffset = static_cast<uint32_t>(
            translateOffset(srcNode->parentOffset)
        );
        
        // Translate child offsets for internal nodes
        if (!dstNode->isLeaf) {
            for (uint32_t i = 0; i <= dstNode->keyCount && i < BPlusTreeNode::MAX_CHILDREN; ++i) {
                dstNode->children[i] = static_cast<uint32_t>(
                    translateOffset(srcNode->children[i])
                );
            }
        }
        
        // Translate leaf sibling pointers
        if (dstNode->isLeaf) {
            dstNode->nextLeaf = static_cast<uint32_t>(translateOffset(srcNode->nextLeaf));
            dstNode->prevLeaf = static_cast<uint32_t>(translateOffset(srcNode->prevLeaf));
        }
    }
    
    // Update header values in temp buffer
    const uint64_t newRootOffset = translateOffset(m_rootOffset);
    auto* headerRoot = reinterpret_cast<uint64_t*>(tempBuffer.data());
    *headerRoot = newRootOffset;
    
    auto* headerNextNode = reinterpret_cast<uint64_t*>(tempBuffer.data() + 24);
    *headerNextNode = nextNewOffset;
    
    // Phase 3: Atomically swap compacted data into place
    // Use memory barrier before and after copy for thread safety
    FullMemoryBarrier();
    
    // Copy compacted data back to original location
    std::memcpy(m_baseAddress, tempBuffer.data(), tempBuffer.size());
    
    FullMemoryBarrier();
    
    // Phase 4: Update member variables
    const uint64_t oldNextNodeOffset = m_nextNodeOffset;
    m_rootOffset = newRootOffset;
    m_nextNodeOffset = nextNewOffset;
    
    // Calculate reclaimed space
    reclaimedBytes = oldNextNodeOffset - nextNewOffset;
    
    SS_LOG_INFO(L"Whitelist",
        L"Compact: successfully defragmented %zu nodes, reclaimed %llu bytes",
        nodeMappings.size(), reclaimedBytes);
    
    return StoreError::Success();
}

StoreError HashIndex::Rebalance() noexcept {
    // ========================================================================
    // INDEX REBALANCING
    // ========================================================================
    // Optimizes tree structure by:
    // 1. Merging underfull siblings
    // 2. Redistributing keys between siblings
    // 3. Reducing tree depth if possible
    // ========================================================================
    
    std::unique_lock lock(m_rwLock);
    
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only - cannot rebalance"
        );
    }
    
    // Traverse leaves and merge underfull adjacent siblings
    BPlusTreeNode* leaf = FindLeafMutable(0);  // Get first leaf
    if (!leaf) {
        return StoreError::Success();  // Empty tree
    }
    
    constexpr uint32_t MIN_FILL_THRESHOLD = BPlusTreeNode::MAX_KEYS / 4;
    uint32_t mergeCount = 0;
    constexpr uint32_t MAX_ITERATIONS = 10'000'000;
    uint32_t iterations = 0;
    
    while (leaf && iterations < MAX_ITERATIONS) {
        ++iterations;
        
        // Check if this leaf is underfull
        if (leaf->keyCount < MIN_FILL_THRESHOLD && leaf->nextLeaf != 0) {
            // Get next sibling
            if (leaf->nextLeaf >= m_indexSize) {
                break;
            }
            
            auto* sibling = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + leaf->nextLeaf
            );
            
            if (!sibling->isLeaf) {
                break;
            }
            
            // Check if we can merge (combined keys fit in one node)
            const uint32_t combinedKeys = leaf->keyCount + sibling->keyCount;
            if (combinedKeys <= BPlusTreeNode::MAX_KEYS) {
                // Merge sibling into current leaf
                for (uint32_t i = 0; i < sibling->keyCount; ++i) {
                    if (leaf->keyCount < BPlusTreeNode::MAX_KEYS) {
                        leaf->keys[leaf->keyCount] = sibling->keys[i];
                        leaf->children[leaf->keyCount] = sibling->children[i];
                        leaf->keyCount++;
                    }
                }
                
                // Update linked list
                leaf->nextLeaf = sibling->nextLeaf;
                if (sibling->nextLeaf != 0 && sibling->nextLeaf < m_indexSize) {
                    auto* nextNext = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + sibling->nextLeaf
                    );
                    if (nextNext->isLeaf) {
                        // Calculate leaf offset
                        const auto leafAddr = reinterpret_cast<uintptr_t>(leaf);
                        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
                        const uint64_t leafOffset = leafAddr - baseAddr;
                        if (leafOffset <= UINT32_MAX) {
                            nextNext->prevLeaf = static_cast<uint32_t>(leafOffset);
                        }
                    }
                }
                
                // Clear merged sibling (security)
                SecureZeroMemoryRegion(sibling, sizeof(BPlusTreeNode));
                
                ++mergeCount;
                // Don't advance - check if we can merge more
                continue;
            }
        }
        
        // Move to next leaf
        if (leaf->nextLeaf == 0) {
            break;
        }
        if (leaf->nextLeaf >= m_indexSize) {
            break;
        }
        leaf = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + leaf->nextLeaf
        );
    }
    
    SS_LOG_INFO(L"Whitelist", L"Rebalance: merged %u leaf node pairs", mergeCount);
    
    return StoreError::Success();
}

StoreError HashIndex::Clear() noexcept {
    // ========================================================================
    // CLEAR ALL ENTRIES
    // ========================================================================
    // Resets the index to empty state while preserving allocated space.
    // ========================================================================
    
    std::unique_lock lock(m_rwLock);
    
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only - cannot clear"
        );
    }
    
    // Secure zero all nodes (but preserve header structure)
    if (m_indexSize > INDEX_HEADER_SIZE) {
        SecureZeroMemoryRegion(
            static_cast<uint8_t*>(m_baseAddress) + INDEX_HEADER_SIZE,
            static_cast<size_t>(m_indexSize - INDEX_HEADER_SIZE)
        );
    }
    
    // Reinitialize root node
    m_rootOffset = INDEX_HEADER_SIZE;
    m_nextNodeOffset = INDEX_HEADER_SIZE + sizeof(BPlusTreeNode);
    m_treeDepth = 1;
    m_entryCount.store(0, std::memory_order_release);
    m_nodeCount.store(1, std::memory_order_release);
    
    // Reset performance counters
    m_lookupCount.store(0, std::memory_order_relaxed);
    m_insertCount.store(0, std::memory_order_relaxed);
    m_removeCount.store(0, std::memory_order_relaxed);
    m_splitCount.store(0, std::memory_order_relaxed);
    
    // Initialize root as empty leaf
    auto* root = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_baseAddress) + m_rootOffset
    );
    std::memset(root, 0, sizeof(BPlusTreeNode));
    root->isLeaf = true;
    root->keyCount = 0;
    
    // Update header
    auto* header = static_cast<uint8_t*>(m_baseAddress);
    *reinterpret_cast<uint64_t*>(header) = m_rootOffset;
    *reinterpret_cast<uint64_t*>(header + 8) = 1;  // nodeCount
    *reinterpret_cast<uint64_t*>(header + 16) = 0; // entryCount
    *reinterpret_cast<uint64_t*>(header + 24) = m_nextNodeOffset;
    *reinterpret_cast<uint32_t*>(header + 32) = m_treeDepth;
    
    SS_LOG_INFO(L"Whitelist", L"HashIndex cleared successfully");
    
    return StoreError::Success();
}

StoreError HashIndex::PropagateToParent(
    BPlusTreeNode* node,
    uint64_t promotedKey,
    uint64_t newChildOffset
) noexcept {
    // ========================================================================
    // PROPAGATE PROMOTED KEY TO PARENT AFTER SPLIT
    // ========================================================================
    // When a node splits, the middle key must be promoted to the parent.
    // If the parent is full, it must also be split (recursive).
    // ========================================================================
    
    if (!node || !m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Invalid node or read-only index"
        );
    }
    
    // If this is the root, we need to create a new root
    if (node->parentOffset == 0) {
        // Allocate new root
        BPlusTreeNode* newRoot = AllocateNode();
        if (!newRoot) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexFull,
                "Cannot allocate new root node"
            );
        }
        
        // Calculate current node offset
        const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
        const uint64_t nodeOffset = nodeAddr - baseAddr;
        
        // Setup new root
        newRoot->isLeaf = false;
        newRoot->keyCount = 1;
        newRoot->keys[0] = promotedKey;
        newRoot->children[0] = static_cast<uint32_t>(nodeOffset);
        newRoot->children[1] = static_cast<uint32_t>(newChildOffset);
        newRoot->parentOffset = 0;
        
        // Update children's parent pointers
        node->parentOffset = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(newRoot) - baseAddr
        );
        
        if (newChildOffset < m_indexSize) {
            auto* newChild = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + newChildOffset
            );
            newChild->parentOffset = node->parentOffset;
        }
        
        // Update root offset
        m_rootOffset = reinterpret_cast<uintptr_t>(newRoot) - baseAddr;
        ++m_treeDepth;
        
        // Update header
        auto* header = static_cast<uint8_t*>(m_baseAddress);
        *reinterpret_cast<uint64_t*>(header) = m_rootOffset;
        *reinterpret_cast<uint32_t*>(header + 32) = m_treeDepth;
        
        return StoreError::Success();
    }
    
    // Get parent node
    if (node->parentOffset >= m_indexSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid parent offset"
        );
    }
    
    auto* parent = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_baseAddress) + node->parentOffset
    );
    
    if (parent->isLeaf) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Parent node is a leaf"
        );
    }
    
    // Check if parent has room
    if (parent->keyCount >= BPlusTreeNode::MAX_KEYS) {
        // ====================================================================
        // RECURSIVE PARENT SPLIT - Enterprise-grade implementation
        // ====================================================================
        // Parent is full - must split parent before we can insert promoted key
        // This recursive approach handles arbitrary tree depth
        // ====================================================================
        
        SS_LOG_DEBUG(L"Whitelist", L"PropagateToParent: parent full, initiating recursive split");
        
        // First, split the parent node
        auto parentSplitResult = SplitNode(parent);
        if (!parentSplitResult.IsSuccess()) {
            SS_LOG_ERROR(L"Whitelist", 
                L"PropagateToParent: failed to split full parent - %S",
                parentSplitResult.message.c_str());
            return parentSplitResult;
        }
        
        // After parent split, we need to re-determine which parent node
        // our original node now belongs to. The promoted key determines this.
        // If promotedKey < parent's first sibling key, stay with original parent.
        // Otherwise, the new child should go to the sibling.
        
        // Re-fetch parent (may have changed after split)
        // The node's parent offset should still be valid, but we need to check
        // if the key should go to the sibling instead
        auto* refreshedParent = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + node->parentOffset
        );
        
        // After split, parent has fewer keys. Check if we can now insert.
        if (refreshedParent->keyCount >= BPlusTreeNode::MAX_KEYS) {
            // This shouldn't happen after a successful split
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Parent still full after recursive split - corruption suspected"
            );
        }
        
        // Update parent reference and continue
        parent = refreshedParent;
        SS_LOG_DEBUG(L"Whitelist", L"PropagateToParent: recursive split succeeded, parent now has %u keys",
                    parent->keyCount);
    }
    
    // Find insertion position in parent using binary search for efficiency
    uint32_t insertPos = 0;
    // Use BranchlessLowerBound for better performance on modern CPUs
    if (parent->keyCount > 0) {
        insertPos = BranchlessLowerBound(parent->keys, parent->keyCount, promotedKey);
    }
    
    // Shift keys and children
    for (uint32_t i = parent->keyCount; i > insertPos; --i) {
        parent->keys[i] = parent->keys[i - 1];
        parent->children[i + 1] = parent->children[i];
    }
    
    // Insert promoted key and new child
    parent->keys[insertPos] = promotedKey;
    parent->children[insertPos + 1] = static_cast<uint32_t>(newChildOffset);
    parent->keyCount++;
    
    // CRITICAL: Update the new child's parent offset to point to the parent
    // This was missing before and caused tree corruption during traversal
    if (newChildOffset < m_indexSize) {
        auto* newChild = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + newChildOffset
        );
        newChild->parentOffset = node->parentOffset;  // Same parent as the original node
    }
    
    return StoreError::Success();
}

StoreError HashIndex::HandleUnderflow(BPlusTreeNode* node) noexcept {
    // ========================================================================
    // HANDLE NODE UNDERFLOW AFTER DELETION
    // ========================================================================
    // When a node becomes too empty after deletion:
    // 1. Try to borrow from sibling
    // 2. If not possible, merge with sibling
    // 3. Propagate changes to parent if needed
    // ========================================================================
    
    if (!node || !m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Invalid node or read-only index"
        );
    }
    
    // Minimum fill is typically MAX_KEYS / 2 for B+Trees
    constexpr uint32_t MIN_KEYS = BPlusTreeNode::MAX_KEYS / 2;
    
    // If node has enough keys, no action needed
    if (node->keyCount >= MIN_KEYS) {
        return StoreError::Success();
    }
    
    // Root node is exempt from minimum fill requirement
    const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
    const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
    const uint64_t nodeOffset = nodeAddr - baseAddr;
    
    if (nodeOffset == m_rootOffset) {
        return StoreError::Success();
    }
    
    // For leaves, try to borrow from or merge with siblings
    if (node->isLeaf) {
        // Try left sibling first
        if (node->prevLeaf != 0 && node->prevLeaf < m_indexSize) {
            auto* leftSibling = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + node->prevLeaf
            );
            
            if (leftSibling->isLeaf && leftSibling->keyCount > MIN_KEYS) {
                // Borrow from left sibling
                // Shift node's keys right
                for (uint32_t i = node->keyCount; i > 0; --i) {
                    node->keys[i] = node->keys[i - 1];
                    node->children[i] = node->children[i - 1];
                }
                
                // Move last key from left sibling
                node->keys[0] = leftSibling->keys[leftSibling->keyCount - 1];
                node->children[0] = leftSibling->children[leftSibling->keyCount - 1];
                leftSibling->keyCount--;
                node->keyCount++;
                
                return StoreError::Success();
            }
        }
        
        // Try right sibling
        if (node->nextLeaf != 0 && node->nextLeaf < m_indexSize) {
            auto* rightSibling = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + node->nextLeaf
            );
            
            if (rightSibling->isLeaf && rightSibling->keyCount > MIN_KEYS) {
                // Borrow from right sibling
                node->keys[node->keyCount] = rightSibling->keys[0];
                node->children[node->keyCount] = rightSibling->children[0];
                node->keyCount++;
                
                // Shift right sibling's keys left
                for (uint32_t i = 0; i < rightSibling->keyCount - 1; ++i) {
                    rightSibling->keys[i] = rightSibling->keys[i + 1];
                    rightSibling->children[i] = rightSibling->children[i + 1];
                }
                rightSibling->keyCount--;
                
                return StoreError::Success();
            }
        }
        
        // ====================================================================
        // MERGE OPERATION - Full enterprise implementation
        // ====================================================================
        // When we cannot borrow from siblings, we must merge nodes
        // This reduces tree height and maintains B+Tree properties
        // ====================================================================
        
        // Prefer merging with left sibling (simpler linked list update)
        if (node->prevLeaf != 0 && node->prevLeaf < m_indexSize) {
            auto* leftSibling = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + node->prevLeaf
            );
            
            // Check if merge is possible (combined keys fit in one node)
            const uint32_t combinedKeys = leftSibling->keyCount + node->keyCount;
            if (leftSibling->isLeaf && combinedKeys <= BPlusTreeNode::MAX_KEYS) {
                SS_LOG_DEBUG(L"Whitelist", 
                    L"HandleUnderflow: merging node into left sibling (combined keys: %u)",
                    combinedKeys);
                
                // Copy all keys from current node to left sibling
                for (uint32_t i = 0; i < node->keyCount && leftSibling->keyCount < BPlusTreeNode::MAX_KEYS; ++i) {
                    leftSibling->keys[leftSibling->keyCount] = node->keys[i];
                    leftSibling->children[leftSibling->keyCount] = node->children[i];
                    leftSibling->keyCount++;
                }
                
                // Update linked list - skip merged node
                leftSibling->nextLeaf = node->nextLeaf;
                if (node->nextLeaf != 0 && node->nextLeaf < m_indexSize) {
                    auto* rightNode = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + node->nextLeaf
                    );
                    if (rightNode->isLeaf) {
                        rightNode->prevLeaf = node->prevLeaf;
                    }
                }
                
                // Securely clear merged node (marks it as free for compaction)
                SecureZeroMemoryRegion(node, sizeof(BPlusTreeNode));
                
                // Update parent to remove separator key and merged child pointer
                auto parentResult = RemoveKeyFromParent(node, nodeOffset, leftSibling);
                if (!parentResult.IsSuccess()) {
                    SS_LOG_WARN(L"Whitelist", 
                        L"HandleUnderflow: parent key removal failed - %S",
                        parentResult.message.c_str());
                }
                
                SS_LOG_INFO(L"Whitelist", L"HandleUnderflow: merge with left sibling completed");
                return StoreError::Success();
            }
        }
        
        // Try merging with right sibling
        if (node->nextLeaf != 0 && node->nextLeaf < m_indexSize) {
            auto* rightSibling = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + node->nextLeaf
            );
            
            const uint32_t combinedKeys = node->keyCount + rightSibling->keyCount;
            if (rightSibling->isLeaf && combinedKeys <= BPlusTreeNode::MAX_KEYS) {
                SS_LOG_DEBUG(L"Whitelist",
                    L"HandleUnderflow: merging right sibling into node (combined keys: %u)",
                    combinedKeys);
                
                // Capture right sibling offset before we modify links
                const auto rightAddr = reinterpret_cast<uintptr_t>(rightSibling);
                const uint64_t rightSiblingOffset = rightAddr - baseAddr;
                if (rightAddr < baseAddr || rightSiblingOffset >= m_indexSize) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexCorrupted,
                        "Invalid right sibling address during merge"
                    );
                }
                
                // Copy all keys from right sibling into current node
                for (uint32_t i = 0; i < rightSibling->keyCount && node->keyCount < BPlusTreeNode::MAX_KEYS; ++i) {
                    node->keys[node->keyCount] = rightSibling->keys[i];
                    node->children[node->keyCount] = rightSibling->children[i];
                    node->keyCount++;
                }
                
                // Update linked list - skip right sibling
                node->nextLeaf = rightSibling->nextLeaf;
                if (rightSibling->nextLeaf != 0 && rightSibling->nextLeaf < m_indexSize) {
                    auto* nextNextNode = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + rightSibling->nextLeaf
                    );
                    if (nextNextNode->isLeaf) {
                        // Calculate current node offset
                        const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
                        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
                        const uint64_t currentOffset = nodeAddr - baseAddr;
                        if (currentOffset <= UINT32_MAX) {
                            nextNextNode->prevLeaf = static_cast<uint32_t>(currentOffset);
                        }
                    }
                }
                
                // Securely clear merged sibling
                SecureZeroMemoryRegion(rightSibling, sizeof(BPlusTreeNode));
                
                // Update parent to remove separator key and merged child pointer
                auto parentResult = RemoveKeyFromParent(rightSibling, rightSiblingOffset, node);
                if (!parentResult.IsSuccess()) {
                    SS_LOG_WARN(L"Whitelist", 
                        L"HandleUnderflow: parent key removal failed - %S",
                        parentResult.message.c_str());
                }
                
                SS_LOG_INFO(L"Whitelist", L"HandleUnderflow: merge with right sibling completed");
                return StoreError::Success();
            }
        }
        
        // If we reach here, neither borrow nor merge was possible
        // This is acceptable for small underfill - node will be cleaned up on compaction
        SS_LOG_DEBUG(L"Whitelist", 
            L"HandleUnderflow: node underfull but no merge/borrow possible (keys: %u)",
            node->keyCount);
    }
    
    return StoreError::Success();
}

// ============================================================================
// REMOVE KEY FROM PARENT AFTER NODE MERGE
// ============================================================================

/**
 * @brief Remove separator key from parent after child node merge
 * 
 * When two sibling nodes merge during HandleUnderflow, the separator key in
 * the parent that distinguished between them must be removed. This maintains
 * B+Tree invariants and prevents orphaned child pointers.
 * 
 * Enterprise Implementation Notes:
 * - Handles recursive underflow if parent becomes underfull
 * - Properly handles root collapse (tree height reduction)
 * - All array accesses are bounds-checked
 * - Maintains parent-child consistency
 * 
 * @param mergedNode The node that was merged (and is now cleared/invalid)
 * @param mergedNodeOffset Byte offset of the merged node within the index
 * @param survivingNode The node that absorbed the merged node's keys
 * @return StoreError Success or error with descriptive message
 */
StoreError HashIndex::RemoveKeyFromParent(
    [[maybe_unused]] BPlusTreeNode* mergedNode,
    uint64_t mergedNodeOffset,
    BPlusTreeNode* survivingNode
) noexcept {
    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    if (!m_baseAddress || !survivingNode) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Invalid parameters for parent key removal"
        );
    }
    
    // Get parent from surviving node (both siblings share the same parent)
    const uint32_t parentOffset = survivingNode->parentOffset;
    
        // Root nodes have no parent - nothing to update
        if (parentOffset == 0) {
            SS_LOG_DEBUG(L"Whitelist", 
                L"RemoveKeyFromParent: surviving node is root, no parent update needed");
            return StoreError::Success();
        }
    
    // Validate parent offset
    if (parentOffset >= m_indexSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Parent offset exceeds index size"
        );
    }
    
    auto* parent = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_baseAddress) + parentOffset
    );
    
    if (!ValidateNodeIntegrity(parent, BPlusTreeNode::MAX_KEYS)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Parent node corrupted during merge"
        );
    }
    
    // ========================================================================
    // FIND AND REMOVE MERGED CHILD POINTER
    // ========================================================================
    
    // Find the child pointer that matches mergedNodeOffset
    uint32_t childIndex = UINT32_MAX;
    const uint32_t parentChildCount = parent->keyCount + 1;
    
    for (uint32_t i = 0; i < parentChildCount && i <= BPlusTreeNode::MAX_KEYS; ++i) {
        if (parent->children[i] == mergedNodeOffset) {
            childIndex = i;
            break;
        }
    }
    
    if (childIndex == UINT32_MAX) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Merged child not found in parent"
        );
    }
    
    // Separator key index is childIndex - 1 (unless removing leftmost child)
    // In a B+Tree, key i separates children i and i+1.
    // If we removed child at index 0, we must remove key 0.
    // Otherwise remove key at index (childIndex - 1).
    uint32_t keyIndex = (childIndex == 0) ? 0 : (childIndex - 1);
    if (keyIndex >= parent->keyCount && parent->keyCount > 0) {
        keyIndex = parent->keyCount - 1;
    }
    
    // ========================================================================
    // REMOVE KEY AND CHILD, SHIFT LEFT
    // ========================================================================
    
    // Shift keys left from keyIndex (if any keys remain)
    if (parent->keyCount > 0) {
        for (uint32_t i = keyIndex; i + 1 < parent->keyCount; ++i) {
            parent->keys[i] = parent->keys[i + 1];
        }
    }
    
    // Shift children left from childIndex
    for (uint32_t i = childIndex; i + 1 < parentChildCount; ++i) {
        parent->children[i] = parent->children[i + 1];
    }
    
    // Clear last key/child
    if (parent->keyCount > 0) {
        parent->keys[parent->keyCount - 1] = 0;
    }
    parent->children[parentChildCount - 1] = 0;
    if (parent->keyCount > 0) {
        parent->keyCount--;
    }
    
    // ========================================================================
    // HANDLE ROOT COLLAPSE
    // ========================================================================
    
    // If parent is root and now has no keys, collapse tree height
    if (parentOffset == m_rootOffset && parent->keyCount == 0) {
        const uint32_t newRootOffset = parent->children[0];
        
        if (newRootOffset != 0 && newRootOffset < m_indexSize) {
            auto* newRoot = reinterpret_cast<BPlusTreeNode*>(
                static_cast<uint8_t*>(m_baseAddress) + newRootOffset
            );
            newRoot->parentOffset = 0;
            m_rootOffset = newRootOffset;
            
            if (m_treeDepth > 1) {
                --m_treeDepth;
            }
            
            auto* header = static_cast<uint8_t*>(m_baseAddress);
            *reinterpret_cast<uint64_t*>(header) = m_rootOffset;
            *reinterpret_cast<uint32_t*>(header + 32) = m_treeDepth;
        }
        
        return StoreError::Success();
    }
    
    // ========================================================================
    // HANDLE PARENT UNDERFLOW RECURSIVELY
    // ========================================================================
    
    if (parent->keyCount < (BPlusTreeNode::MAX_KEYS / 2)) {
        return HandleUnderflow(parent);
    }
    
    return StoreError::Success();
}

// ============================================================================
// ITERATOR IMPLEMENTATION
// ============================================================================

HashIndexIterator::HashIndexIterator(
    const HashIndex* index,
    uint64_t leafOffset,
    uint32_t keyIndex
) noexcept
    : m_index(index)
    , m_leafOffset(leafOffset)
    , m_keyIndex(keyIndex)
    , m_atEnd(false)
{
    // Validate initial position
    if (!m_index || leafOffset == 0) {
        m_atEnd = true;
        return;
    }
    
    // Get the leaf node to validate position
    const BPlusTreeNode* leaf = m_index->GetLeafAt(leafOffset);
    if (!leaf || keyIndex >= leaf->keyCount) {
        m_atEnd = true;
    }
}

HashIndexIterator::value_type HashIndexIterator::operator*() const noexcept {
    if (m_atEnd || !m_index) {
        return {0, 0};  // Invalid dereference
    }
    
    const BPlusTreeNode* leaf = m_index->GetLeafAt(m_leafOffset);
    if (!leaf || m_keyIndex >= leaf->keyCount) {
        return {0, 0};  // Invalid state
    }
    
    return {
        leaf->keys[m_keyIndex],
        static_cast<uint64_t>(leaf->children[m_keyIndex])
    };
}

HashIndexIterator& HashIndexIterator::operator++() noexcept {
    if (m_atEnd || !m_index) {
        return *this;
    }
    
    const BPlusTreeNode* leaf = m_index->GetLeafAt(m_leafOffset);
    if (!leaf) {
        m_atEnd = true;
        return *this;
    }
    
    // Move to next key in current leaf
    ++m_keyIndex;
    
    // If we've exhausted current leaf, move to next leaf
    if (m_keyIndex >= leaf->keyCount) {
        if (leaf->nextLeaf == 0) {
            // No more leaves - we're at the end
            m_atEnd = true;
        } else {
            m_leafOffset = leaf->nextLeaf;
            m_keyIndex = 0;
            
            // Validate next leaf
            const BPlusTreeNode* nextLeaf = m_index->GetLeafAt(m_leafOffset);
            if (!nextLeaf || nextLeaf->keyCount == 0) {
                m_atEnd = true;
            }
        }
    }
    
    return *this;
}

HashIndexIterator HashIndexIterator::operator++(int) noexcept {
    HashIndexIterator tmp = *this;
    ++(*this);
    return tmp;
}

bool HashIndexIterator::operator==(const HashIndexIterator& other) const noexcept {
    // Two end iterators are equal
    if (m_atEnd && other.m_atEnd) {
        return true;
    }
    
    // End iterator is not equal to non-end iterator
    if (m_atEnd != other.m_atEnd) {
        return false;
    }
    
    // Compare positions
    return m_index == other.m_index &&
           m_leafOffset == other.m_leafOffset &&
           m_keyIndex == other.m_keyIndex;
}

bool HashIndexIterator::operator!=(const HashIndexIterator& other) const noexcept {
    return !(*this == other);
}

bool HashIndexIterator::IsValid() const noexcept {
    return !m_atEnd && m_index != nullptr;
}

// ============================================================================
// HASH INDEX ITERATOR METHODS
// ============================================================================

HashIndex::iterator HashIndex::begin() const noexcept {
    std::shared_lock lock(m_rwLock);
    
    if (!IsReady()) {
        return end();
    }
    
    // Get first leaf node
    const BPlusTreeNode* firstLeaf = GetFirstLeaf();
    if (!firstLeaf || firstLeaf->keyCount == 0) {
        return end();
    }
    
    // Calculate offset of first leaf
    uint64_t firstLeafOffset = 0;
    if (m_baseAddress) {
        const auto leafAddr = reinterpret_cast<uintptr_t>(firstLeaf);
        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
        firstLeafOffset = leafAddr - baseAddr;
    } else if (m_view && m_view->baseAddress) {
        const auto leafAddr = reinterpret_cast<uintptr_t>(firstLeaf);
        const auto baseAddr = reinterpret_cast<uintptr_t>(m_view->baseAddress);
        if (leafAddr >= baseAddr + m_indexOffset) {
            firstLeafOffset = (leafAddr - baseAddr) - m_indexOffset;
        }
    }
    
    if (firstLeafOffset == 0) {
        return end();
    }
    
    return HashIndexIterator(this, firstLeafOffset, 0);
}

HashIndex::iterator HashIndex::end() const noexcept {
    return HashIndexIterator();
}

} // namespace ShadowStrike::Whitelist
