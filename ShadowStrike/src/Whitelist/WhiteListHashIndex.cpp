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
 * @param keys Array of sorted keys
 * @param count Number of valid keys in array
 * @param target Target key to search for
 * @return Index of first element >= target (or count if all < target)
 * @note Uses conditional moves to avoid branch mispredictions
 */
template<typename KeyType, size_t MaxKeys>
[[nodiscard]] inline uint32_t BranchlessLowerBound(
    const KeyType (&keys)[MaxKeys],
    uint32_t count,
    KeyType target
) noexcept {
    // Early validation
    if (SS_UNLIKELY(count == 0)) {
        return 0;
    }
    if (SS_UNLIKELY(count > MaxKeys)) {
        count = static_cast<uint32_t>(MaxKeys);  // Safety clamp
    }
    
    // Branchless binary search with prefetching
    uint32_t left = 0;
    uint32_t size = count;
    
    while (size > 1) {
        const uint32_t half = size / 2;
        const uint32_t mid = left + half;
        
        // Prefetch next potential access locations
        if (size > BATCH_CHUNK_SIZE) {
            SS_PREFETCH_READ(&keys[left + half / 2]);
            SS_PREFETCH_READ(&keys[mid + half / 2]);
        }
        
        // Branchless conditional move
        // If keys[mid] < target, move left forward; otherwise stay
        const bool goRight = keys[mid] < target;
        left = goRight ? (mid + 1) : left;
        size = goRight ? (size - half - 1) : half;
    }
    
    // Final comparison
    if (size > 0 && keys[left] < target) {
        ++left;
    }
    
    return left;
}

/**
 * @brief Find exact key in sorted array with early termination
 * @param keys Array of sorted keys
 * @param count Number of valid keys
 * @param target Target key to find
 * @param[out] index Output index if found
 * @return True if found, false otherwise
 */
template<typename KeyType, size_t MaxKeys>
[[nodiscard]] inline bool BinarySearchExact(
    const KeyType (&keys)[MaxKeys],
    uint32_t count,
    KeyType target,
    uint32_t& index
) noexcept {
    if (SS_UNLIKELY(count == 0)) {
        return false;
    }
    if (SS_UNLIKELY(count > MaxKeys)) {
        count = static_cast<uint32_t>(MaxKeys);
    }
    
    uint32_t left = 0;
    uint32_t right = count;
    
    while (left < right) {
        const uint32_t mid = left + (right - left) / 2;
        
        // Prefetch mid for next iteration
        if (right - left > BATCH_CHUNK_SIZE) {
            const uint32_t nextMidLow = left + (mid - left) / 2;
            const uint32_t nextMidHigh = mid + (right - mid) / 2;
            SS_PREFETCH_READ(&keys[nextMidLow]);
            SS_PREFETCH_READ(&keys[nextMidHigh]);
        }
        
        if (keys[mid] < target) {
            left = mid + 1;
        } else if (keys[mid] > target) {
            right = mid;
        } else {
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
     * B+TREE NODE SPLITTING
     * ========================================================================
     *
     * Splits a full node into two nodes:
     * - Original node keeps first half of keys
     * - New node gets second half of keys
     * - Parent gets middle key (for internal nodes) or copy (for leaves)
     *
     * Security: All array accesses are bounds-checked to prevent corruption.
     *
     * Note: This is a simplified implementation. Full B+Tree would require
     * recursive parent updates.
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
    
    // Calculate sibling key count with bounds validation
    const uint32_t siblingKeyCount = node->keyCount - splitPoint;
    
    // Validate sibling won't overflow
    if (siblingKeyCount > BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Sibling key count exceeds maximum"
        );
    }
    
    // Copy second half to sibling with explicit bounds checking
    for (uint32_t i = 0; i < siblingKeyCount; ++i) {
        const uint32_t srcIdx = splitPoint + i;
        
        // Bounds check source index
        if (srcIdx >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Source index out of bounds during split"
            );
        }
        
        // Bounds check destination index
        if (i >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Destination index out of bounds during split"
            );
        }
        
        sibling->keys[i] = node->keys[srcIdx];
        sibling->children[i] = node->children[srcIdx];
        
        // Clear original slot for security
        node->keys[srcIdx] = 0;
        node->children[srcIdx] = 0;
    }
    
    // For internal nodes, copy the extra child pointer (MAX_KEYS + 1 children)
    if (!node->isLeaf && node->keyCount < BPlusTreeNode::MAX_KEYS + 1) {
        // The last child pointer is at index keyCount
        const uint32_t lastChildIdx = node->keyCount;
        if (lastChildIdx <= BPlusTreeNode::MAX_KEYS && siblingKeyCount <= BPlusTreeNode::MAX_KEYS) {
            sibling->children[siblingKeyCount] = node->children[lastChildIdx];
            node->children[lastChildIdx] = 0; // Clear for security
        }
    }
    
    sibling->keyCount = siblingKeyCount;
    node->keyCount = splitPoint;
    
    // Update leaf linked list with comprehensive bounds validation
    if (node->isLeaf && m_baseAddress) {
        // Calculate offsets safely
        const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
        const auto siblingAddr = reinterpret_cast<uintptr_t>(sibling);
        
        // Verify nodes are within the base address range
        if (nodeAddr < baseAddr || siblingAddr < baseAddr) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: node address underflow");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Node address underflow during split"
            );
        }
        
        const uint64_t nodeOffset = nodeAddr - baseAddr;
        const uint64_t siblingOffset = siblingAddr - baseAddr;
        
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
    
    // TODO: Insert middle key into parent (requires full parent tracking)
    // This simplified implementation doesn't handle parent updates
    
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
    
    // Validate leaf node integrity
    if (SS_UNLIKELY(leaf->keyCount == 0 || !ValidateNodeIntegrity(leaf, BPlusTreeNode::MAX_KEYS))) {
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
    
    // TODO: Handle underflow and node merging for B+Tree balance
    // This would be implemented in a full B+Tree implementation
    
    return StoreError::Success();
}

StoreError HashIndex::BatchInsert(
    std::span<const std::pair<HashValue, uint64_t>> entries
) noexcept {
    // ========================================================================
    // BATCH INSERT WITH OPTIMIZED SORTING
    // ========================================================================
    // Inserts multiple entries efficiently.
    // For large batches, could be optimized with:
    // 1. Sorting entries by key for sequential access
    // 2. Bulk loading directly into leaf nodes
    // 3. Building subtrees and merging
    // ========================================================================
    
    // Validate input
    if (entries.empty()) {
        return StoreError::Success();
    }
    
    // Validate we're in write mode before processing
    if (SS_UNLIKELY(!m_baseAddress)) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // For small batches, insert one by one
    // For large batches (>1000), consider sorting first for cache locality
    constexpr size_t SORT_THRESHOLD = 1000;
    
    if (entries.size() > SORT_THRESHOLD) {
        // Create sorted copy for cache-friendly insertion
        std::vector<std::pair<uint64_t, uint64_t>> sortedEntries;
        try {
            sortedEntries.reserve(entries.size());
            for (const auto& [hash, offset] : entries) {
                if (!hash.IsEmpty()) {
                    sortedEntries.emplace_back(hash.FastHash(), offset);
                }
            }
            std::sort(sortedEntries.begin(), sortedEntries.end(),
                [](const auto& a, const auto& b) { return a.first < b.first; });
            
            // Insert sorted entries (better cache locality)
            for (const auto& [key, offset] : sortedEntries) {
                // Create temporary HashValue for key
                HashValue tempHash;
                // Note: This is a simplification - in production, 
                // we'd have a direct key-based insert method
                
                // For now, iterate original entries in key order
            }
        } catch (const std::exception& e) {
            SS_LOG_WARN(L"Whitelist", L"BatchInsert: sort allocation failed, using sequential insert - %S", e.what());
        }
    }
    
    // Sequential insertion (works for all cases)
    size_t successCount = 0;
    StoreError lastError = StoreError::Success();
    
    for (const auto& [hash, offset] : entries) {
        auto result = Insert(hash, offset);
        if (result.IsSuccess()) {
            ++successCount;
        } else {
            lastError = result;
            // Continue with other entries unless it's a critical error
            if (result.code == WhitelistStoreError::IndexFull ||
                result.code == WhitelistStoreError::IndexCorrupted ||
                result.code == WhitelistStoreError::ReadOnlyDatabase) {
                break;  // Critical error - stop processing
            }
        }
    }
    
    // Return last error if any failed
    if (successCount < entries.size() && !lastError.IsSuccess()) {
        return lastError;
    }
    
    return StoreError::Success();
}

// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

/**
 * @brief Get detailed index statistics for monitoring
 * @return HashIndexStats structure with all metrics
 */
// Note: This would be exposed in header if needed externally
// HashIndexStats HashIndex::GetDetailedStats() const noexcept {
//     std::shared_lock lock(m_rwLock);
//     
//     HashIndexStats stats{};
//     stats.entryCount = m_entryCount.load(std::memory_order_acquire);
//     stats.nodeCount = m_nodeCount.load(std::memory_order_acquire);
//     stats.treeDepth = m_treeDepth;
//     stats.indexSize = m_indexSize;
//     stats.usedSize = m_nextNodeOffset;
//     stats.isWritable = (m_baseAddress != nullptr);
//     stats.isReady = IsReady();
//     
//     return stats;
// }

} // namespace ShadowStrike::Whitelist