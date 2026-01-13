/**
 * @file WhiteListPatternIndex.cpp
 * @brief Compressed Trie path index implementation for WhitelistStore
 *
 * This file implements a memory-efficient compressed trie for path-based
 * whitelisting with support for multiple match modes (exact, prefix, suffix,
 * glob, regex).
 *
 * Architecture:
 * - Compressed trie with path segment storage
 * - Up to 4 children per node (hash-based selection)
 * - Memory-mapped for zero-copy reads
 * - Supports case-insensitive Windows paths
 *
 * Performance Characteristics:
 * - Exact match: O(k) where k is path length
 * - Prefix match: O(k) for finding first match
 * - Pattern match: O(k * m) where m is pattern complexity
 *
 * Thread Safety:
 * - Concurrent reads supported
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
#include <type_traits>
#include <bit>
#include <atomic>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <regex>

// ============================================================================
// PLATFORM-SPECIFIC SIMD AND INTRINSICS
// ============================================================================
#if defined(_MSC_VER)
    #include <intrin.h>
    #include <immintrin.h>
    #include <nmmintrin.h>  // SSE4.2 for CRC32
    
    // Cache prefetch macros for memory access optimization
    #define SS_PREFETCH_READ(addr)      _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
    #define SS_PREFETCH_WRITE(addr)     _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
    #define SS_PREFETCH_NTA(addr)       _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_NTA)
    #define SS_PREFETCH_READ_L2(addr)   _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T1)
    
    // Memory barrier intrinsics
    #define SS_MEMORY_FENCE()           _mm_mfence()
    #define SS_STORE_FENCE()            _mm_sfence()
    #define SS_LOAD_FENCE()             _mm_lfence()
    
    // Compiler memory barrier
    #define SS_COMPILER_BARRIER()       _ReadWriteBarrier()
    
#elif defined(__GNUC__) || defined(__clang__)
    #include <x86intrin.h>
    #include <cpuid.h>
    
    #define SS_PREFETCH_READ(addr)      __builtin_prefetch(addr, 0, 3)
    #define SS_PREFETCH_WRITE(addr)     __builtin_prefetch(addr, 1, 3)
    #define SS_PREFETCH_NTA(addr)       __builtin_prefetch(addr, 0, 0)
    #define SS_PREFETCH_READ_L2(addr)   __builtin_prefetch(addr, 0, 2)
    
    #define SS_MEMORY_FENCE()           __sync_synchronize()
    #define SS_STORE_FENCE()            __sync_synchronize()
    #define SS_LOAD_FENCE()             __sync_synchronize()
    
    #define SS_COMPILER_BARRIER()       asm volatile("" ::: "memory")
#else
    // Fallback: no-op prefetch for unsupported platforms
    #define SS_PREFETCH_READ(addr)      ((void)0)
    #define SS_PREFETCH_WRITE(addr)     ((void)0)
    #define SS_PREFETCH_NTA(addr)       ((void)0)
    #define SS_PREFETCH_READ_L2(addr)   ((void)0)
    
    #define SS_MEMORY_FENCE()           std::atomic_thread_fence(std::memory_order_seq_cst)
    #define SS_STORE_FENCE()            std::atomic_thread_fence(std::memory_order_release)
    #define SS_LOAD_FENCE()             std::atomic_thread_fence(std::memory_order_acquire)
    
    #define SS_COMPILER_BARRIER()       std::atomic_signal_fence(std::memory_order_seq_cst)
#endif



namespace ShadowStrike::Whitelist {

// ============================================================================
// COMPILE-TIME CONSTANTS FOR PATH INDEX
// ============================================================================
namespace {

/// @brief Cache line size for memory alignment optimization
constexpr size_t CACHE_LINE_SIZE_LOCAL = 64;

/// @brief Path index header size (must match CreateNew allocation)
constexpr uint64_t PATH_INDEX_HEADER_SIZE = 64;

/// @brief Maximum safe trie traversal depth to prevent infinite loops
constexpr size_t SAFE_MAX_TRIE_DEPTH = 512;

/// @brief Maximum Windows path length (UNC paths)
constexpr size_t MAX_WINDOWS_PATH_LENGTH = 32767;

/// @brief Prefetch distance for trie node traversal
constexpr size_t TRIE_PREFETCH_DISTANCE = 2;

/// @brief Batch processing chunk size for optimal cache utilization
constexpr size_t BATCH_CHUNK_SIZE = 8;

/// @brief FNV-1a hash constants for segment hashing
constexpr uint32_t FNV1A_OFFSET_BASIS = 2166136261u;
constexpr uint32_t FNV1A_PRIME = 16777619u;

// ============================================================================
// HARDWARE FEATURE DETECTION
// ============================================================================

/**
 * @brief Detect POPCNT instruction support at runtime
 * @return True if POPCNT is available
 */
[[nodiscard]] inline bool HasPOPCNT() noexcept {
#if defined(_MSC_VER)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 23)) != 0; // POPCNT bit
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 23)) != 0;
    }
    return false;
#else
    return false;
#endif
}

/**
 * @brief Detect BMI2 instruction support (PEXT/PDEP)
 * @return True if BMI2 is available
 */
[[nodiscard]] inline bool HasBMI2() noexcept {
#if defined(_MSC_VER)
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 8)) != 0; // BMI2 bit
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & (1 << 8)) != 0;
    }
    return false;
#else
    return false;
#endif
}

/**
 * @brief Detect SSE4.2 support (CRC32 instruction)
 * @return True if SSE4.2 is available
 */
[[nodiscard]] inline bool HasSSE42() noexcept {
#if defined(_MSC_VER)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 20)) != 0; // SSE4.2 bit
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 20)) != 0;
    }
    return false;
#else
    return false;
#endif
}

// ============================================================================
// SECURE MEMORY OPERATIONS
// ============================================================================

/**
 * @brief Securely zero memory region (not optimized away by compiler)
 * @param ptr Pointer to memory region
 * @param size Size in bytes
 */
inline void SecureZeroMemoryRegion(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;
    
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    SS_COMPILER_BARRIER();
#endif
}

/**
 * @brief Full memory barrier for safe multi-threaded access
 */
inline void FullMemoryBarrier() noexcept {
    SS_MEMORY_FENCE();
}

/**
 * @brief Align value up to cache line boundary
 * @param value Value to align
 * @return Aligned value
 */
[[nodiscard]] constexpr uint64_t AlignToCacheLine(uint64_t value) noexcept {
    return (value + CACHE_LINE_SIZE_LOCAL - 1) & ~(CACHE_LINE_SIZE_LOCAL - 1);
}

// ============================================================================
// BIT MANIPULATION UTILITIES
// ============================================================================

/**
 * @brief Count leading zeros (CLZ) with hardware acceleration
 * @param value Input value (must be non-zero)
 * @return Number of leading zero bits
 */
[[nodiscard]] inline uint32_t CountLeadingZeros32(uint32_t value) noexcept {
    if (value == 0) return 32;
#if defined(_MSC_VER)
    unsigned long index = 0;
    _BitScanReverse(&index, value);
    return 31 - index;
#elif defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_clz(value));
#else
    // Fallback software implementation
    uint32_t n = 0;
    if ((value & 0xFFFF0000) == 0) { n += 16; value <<= 16; }
    if ((value & 0xFF000000) == 0) { n += 8; value <<= 8; }
    if ((value & 0xF0000000) == 0) { n += 4; value <<= 4; }
    if ((value & 0xC0000000) == 0) { n += 2; value <<= 2; }
    if ((value & 0x80000000) == 0) { n += 1; }
    return n;
#endif
}

/**
 * @brief Count population (number of set bits) with hardware acceleration
 * @param value Input value
 * @return Number of set bits
 */
[[nodiscard]] inline uint32_t PopCount32(uint32_t value) noexcept {
#if defined(_MSC_VER)
    return static_cast<uint32_t>(__popcnt(value));
#elif defined(__GNUC__) || defined(__clang__)
    return static_cast<uint32_t>(__builtin_popcount(value));
#else
    // Fallback software implementation
    value = value - ((value >> 1) & 0x55555555);
    value = (value & 0x33333333) + ((value >> 2) & 0x33333333);
    return ((value + (value >> 4) & 0x0F0F0F0F) * 0x01010101) >> 24;
#endif
}

} // anonymous namespace (constants and hardware detection)

// ============================================================================
// PATH INDEX IMPLEMENTATION (Compressed Trie)
// ============================================================================

/**
 * @brief Compressed Trie Node for path indexing
 * 
 * This is a memory-efficient trie node that supports:
 * - Up to 4 children (indexed by path component hash)
 * - Path compression (stores common prefixes)
 * - Multiple match modes per node
 * 
 * Memory layout (64 bytes per node, packed):
 * - 1 byte: node flags
 * - 1 byte: match mode
 * - 1 byte: segment length
 * - 1 byte: reserved1
 * - 4 bytes: child count
 * - 8 bytes: entry offset
 * - 16 bytes: child offsets (4 x uint32_t)
 * - 32 bytes: compressed path segment
 */
#pragma pack(push, 1)
struct PathTrieNode {
    static constexpr size_t MAX_CHILDREN = 4;
    static constexpr size_t MAX_SEGMENT_LENGTH = 32;
    
    /// @brief Node flags
    uint8_t flags{0};
    
    /// @brief Match mode for this node
    PathMatchMode matchMode{PathMatchMode::Exact};
    
    /// @brief Length of compressed segment
    uint8_t segmentLength{0};
    
    /// @brief Reserved for alignment and future use
    uint8_t reserved1{0};
    
    /// @brief Number of valid children
    uint32_t childCount{0};
    
    /// @brief Entry offset (0 if not terminal)
    uint64_t entryOffset{0};
    
    /// @brief Child node offsets (0 if no child)
    uint32_t children[MAX_CHILDREN]{0, 0, 0, 0};
    
    /// @brief Compressed path segment (UTF-8 encoded, null-terminated if < max)
    char segment[MAX_SEGMENT_LENGTH]{};
    
    /// @brief Check if this node is a terminal (has an entry)
    [[nodiscard]] bool IsTerminal() const noexcept {
        return (flags & 0x01) != 0;
    }
    
    /// @brief Set terminal flag
    void SetTerminal(bool terminal) noexcept {
        if (terminal) {
            flags |= 0x01;
        } else {
            flags &= ~0x01;
        }
    }
    
    /// @brief Check if node has any children
    [[nodiscard]] bool HasChildren() const noexcept {
        return childCount > 0;
    }
    
    /// @brief Get segment as string_view
    [[nodiscard]] std::string_view GetSegment() const noexcept {
        return std::string_view(segment, std::min<size_t>(segmentLength, MAX_SEGMENT_LENGTH));
    }
};
#pragma pack(pop)

static_assert(sizeof(PathTrieNode) == 64, "PathTrieNode must be 64 bytes");

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================
// These helper functions provide overflow-safe arithmetic and utility
// operations. Defined in anonymous namespace for internal linkage only.
// ============================================================================

namespace {

// ============================================================================
// ENHANCED SAFE ARITHMETIC WITH COMPILER BUILTINS
// ============================================================================

/**
 * @brief Safely add two values with overflow check using compiler builtins
 * @tparam T Integral type (must be unsigned for correct overflow detection)
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if addition succeeded, false if overflow would occur
 * 
 * Uses compiler intrinsics for optimal codegen (single instruction on modern CPUs)
 */
template<typename T>
[[nodiscard]] inline bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeAdd requires integral type");
    
#if defined(_MSC_VER) && defined(_M_X64)
    // MSVC x64: Use intrinsics for unsigned types
    if constexpr (std::is_same_v<T, uint64_t>) {
        unsigned char carry = _addcarry_u64(0, a, b, &result);
        return carry == 0;
    } else if constexpr (std::is_same_v<T, uint32_t>) {
        unsigned char carry = _addcarry_u32(0, a, b, &result);
        return carry == 0;
    } else
#elif defined(__GNUC__) || defined(__clang__)
    // GCC/Clang: Use __builtin_add_overflow for all types
    return !__builtin_add_overflow(a, b, &result);
#endif
    {
        // Fallback for other types/compilers
        if constexpr (std::is_unsigned_v<T>) {
            if (a > std::numeric_limits<T>::max() - b) {
                return false;
            }
        } else {
            if ((b > 0 && a > std::numeric_limits<T>::max() - b) ||
                (b < 0 && a < std::numeric_limits<T>::min() - b)) {
                return false;
            }
        }
        result = a + b;
        return true;
    }
}

/**
 * @brief Safely subtract two values with underflow check
 * @tparam T Integral type
 * @param a Minuend
 * @param b Subtrahend
 * @param result Output result (only valid if function returns true)
 * @return True if subtraction succeeded, false if underflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeSub(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeSub requires integral type");
    
#if defined(__GNUC__) || defined(__clang__)
    return !__builtin_sub_overflow(a, b, &result);
#else
    if constexpr (std::is_unsigned_v<T>) {
        if (a < b) {
            return false; // Underflow
        }
    } else {
        if ((b > 0 && a < std::numeric_limits<T>::min() + b) ||
            (b < 0 && a > std::numeric_limits<T>::max() + b)) {
            return false;
        }
    }
    result = a - b;
    return true;
#endif
}

/**
 * @brief Safely multiply two values with overflow check using compiler builtins
 * @tparam T Integral type
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeMul(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeMul requires integral type");
    
    // Fast path for zero operands
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    
#if defined(__GNUC__) || defined(__clang__)
    // GCC/Clang: Use __builtin_mul_overflow
    return !__builtin_mul_overflow(a, b, &result);
#elif defined(_MSC_VER) && defined(_M_X64)
    // MSVC x64: Use _umul128 for 64-bit unsigned
    if constexpr (std::is_same_v<T, uint64_t>) {
        uint64_t high = 0;
        result = _umul128(a, b, &high);
        return high == 0;
    } else
#endif
    {
        // Fallback implementation
        if constexpr (std::is_unsigned_v<T>) {
            if (a > std::numeric_limits<T>::max() / b) {
                return false;
            }
        } else {
            if (a > 0) {
                if (b > 0 && a > std::numeric_limits<T>::max() / b) return false;
                if (b < 0 && b < std::numeric_limits<T>::min() / a) return false;
            } else if (a < 0) {
                if (b > 0 && a < std::numeric_limits<T>::min() / b) return false;
                if (b < 0 && a != 0 && b < std::numeric_limits<T>::max() / a) return false;
            }
        }
        result = a * b;
        return true;
    }
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

// ============================================================================
// TRIE NODE VALIDATION HELPERS
// ============================================================================

/**
 * @brief Validate node offset is within bounds
 * @param offset Node offset to validate
 * @param indexSize Total index size
 * @return True if offset is valid for a PathTrieNode
 */
[[nodiscard]] inline bool IsValidNodeOffset(uint64_t offset, uint64_t indexSize) noexcept {
    if (offset == 0) return false;
    if (offset >= indexSize) return false;
    
    uint64_t endOffset = 0;
    if (!SafeAdd(offset, static_cast<uint64_t>(sizeof(PathTrieNode)), endOffset)) {
        return false;
    }
    return endOffset <= indexSize;
}

/**
 * @brief Validate PathTrieNode integrity for corruption detection
 * @param node Pointer to node
 * @param indexSize Total index size for child offset validation
 * @return True if node passes integrity checks
 */
[[nodiscard]] inline bool ValidateNodeIntegrity(
    const PathTrieNode* node,
    uint64_t indexSize
) noexcept {
    if (!node) return false;
    
    // Check segment length is within bounds
    if (node->segmentLength > PathTrieNode::MAX_SEGMENT_LENGTH) {
        return false;
    }
    
    // Check child count is reasonable
    if (node->childCount > PathTrieNode::MAX_CHILDREN) {
        return false;
    }
    
    // Validate match mode is in valid range
    if (static_cast<uint8_t>(node->matchMode) > static_cast<uint8_t>(PathMatchMode::Regex)) {
        return false;
    }
    
    // Check reserved field is zero (indicates uninitialized or corrupted node)
    // Note: This check can be disabled if reserved field is repurposed
    // if (node->reserved1 != 0) return false;
    
    // Validate child offsets are within bounds
    uint32_t actualChildCount = 0;
    for (size_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
        const uint32_t childOff = node->children[i];
        if (childOff != 0) {
            if (!IsValidNodeOffset(static_cast<uint64_t>(childOff), indexSize)) {
                return false;
            }
            ++actualChildCount;
        }
    }
    
    // Verify child count matches actual non-zero children
    if (actualChildCount != node->childCount) {
        return false;
    }
    
    return true;
}

/**
 * @brief Check if pointer is within memory region (for safe dereferencing)
 * @param ptr Pointer to check
 * @param base Base address of region
 * @param size Size of region in bytes
 * @param objSize Size of object being accessed
 * @return True if pointer is safely within bounds
 */
[[nodiscard]] inline bool IsPointerInRange(
    const void* ptr,
    const void* base,
    uint64_t size,
    size_t objSize
) noexcept {
    if (!ptr || !base || size == 0 || objSize == 0) return false;
    
    const auto ptrAddr = reinterpret_cast<uintptr_t>(ptr);
    const auto baseAddr = reinterpret_cast<uintptr_t>(base);
    
    // Check pointer is >= base
    if (ptrAddr < baseAddr) return false;
    
    // Check object fits within region
    const uint64_t offset = ptrAddr - baseAddr;
    uint64_t endOffset = 0;
    if (!SafeAdd(offset, static_cast<uint64_t>(objSize), endOffset)) {
        return false;
    }
    
    return endOffset <= size;
}

// ============================================================================
// OPTIMIZED HASH FUNCTION WITH SSE4.2 CRC32
// ============================================================================

/**
 * @brief Calculate FNV-1a hash for segment (optimized with hardware CRC32 when available)
 * @param segment Path segment to hash
 * @return Hash value modulo MAX_CHILDREN (0-3)
 */
[[nodiscard]] inline uint32_t SegmentHashOptimized(std::string_view segment) noexcept {
    if (segment.empty()) {
        return 0;
    }
    
    uint32_t hash = 0;
    
#if defined(_MSC_VER) && defined(__SSE4_2__)
    // Use hardware CRC32 if available
    if (HasSSE42()) {
        hash = 0xFFFFFFFF;
        for (char c : segment) {
            hash = _mm_crc32_u8(hash, static_cast<unsigned char>(c));
        }
        return hash % PathTrieNode::MAX_CHILDREN;
    }
#endif
    
    // FNV-1a fallback (still very fast)
    hash = FNV1A_OFFSET_BASIS;
    for (char c : segment) {
        hash ^= static_cast<uint8_t>(c);
        hash *= FNV1A_PRIME;
    }
    
    return hash % PathTrieNode::MAX_CHILDREN;
}

/**
 * @brief Convert wide string path to normalized UTF-8 for trie storage
 * @param path Input path (wide string)
 * @param output Output buffer for UTF-8
 * @return True if conversion succeeded
 * 
 * Security: Validates path length, handles UTF-8 encoding carefully,
 * normalizes separators for consistent matching.
 */
[[nodiscard]] bool NormalizePath(std::wstring_view path, std::string& output) noexcept {
    try {
        output.clear();
        
        // Validate input length to prevent excessive allocation
        constexpr size_t MAX_PATH_INPUT = 32767; // Windows MAX_PATH limit
        if (path.empty() || path.length() > MAX_PATH_INPUT) {
            return path.empty() ? true : false; // Empty is valid, too long is invalid
        }
        
        // Reserve with overflow protection
        // Worst case UTF-8 expansion is 3x for BMP characters
        const size_t maxSize = path.length() * 3;
        if (maxSize < path.length()) { // Overflow check
            return false;
        }
        output.reserve(maxSize);
        
        for (wchar_t wc : path) {
            // Convert to lowercase for case-insensitive matching (Windows paths)
            // Only ASCII letters need conversion for basic path normalization
            wchar_t lower = (wc >= L'A' && wc <= L'Z') ? (wc + 32) : wc;
            
            // Normalize path separators (Windows to Unix style)
            if (lower == L'\\') {
                lower = L'/';
            }
            
            // UTF-8 encoding with explicit bounds checking
            if (lower < 0x80) {
                // Single byte (ASCII)
                output.push_back(static_cast<char>(lower));
            } else if (lower < 0x800) {
                // Two bytes
                output.push_back(static_cast<char>(0xC0 | ((lower >> 6) & 0x1F)));
                output.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
            } else {
                // Three bytes (BMP only - wchar_t on Windows is UCS-2)
                output.push_back(static_cast<char>(0xE0 | ((lower >> 12) & 0x0F)));
                output.push_back(static_cast<char>(0x80 | ((lower >> 6) & 0x3F)));
                output.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
            }
        }
        
        // Remove trailing slashes (iterate safely)
        while (!output.empty() && output.back() == '/') {
            output.pop_back();
        }
        
        return true;
    } catch (const std::bad_alloc&) {
        // Memory allocation failed - clear output for safety
        output.clear();
        return false;
    } catch (...) {
        output.clear();
        return false;
    }
}

/**
 * @brief Calculate hash for child index selection (wrapper for optimized version)
 * @param segment Path segment
 * @return Index 0-3 for child selection
 */
[[nodiscard]] inline uint32_t SegmentHash(std::string_view segment) noexcept {
    return SegmentHashOptimized(segment);
}

/**
 * @brief Find common prefix length between two strings (SIMD-optimized)
 * @param a First string
 * @param b Second string
 * @return Length of common prefix
 * 
 * Uses SIMD comparison for longer strings when available
 */
[[nodiscard]] size_t CommonPrefixLength(std::string_view a, std::string_view b) noexcept {
    const size_t len = std::min(a.length(), b.length());
    
    // For very short strings, use simple loop
    if (len < 16) {
        for (size_t i = 0; i < len; ++i) {
            if (a[i] != b[i]) {
                return i;
            }
        }
        return len;
    }
    
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    // Process 8 bytes at a time using XOR for mismatch detection
    const char* pa = a.data();
    const char* pb = b.data();
    size_t i = 0;
    
    // Process 8-byte chunks
    while (i + 8 <= len) {
        uint64_t va, vb;
        std::memcpy(&va, pa + i, 8);
        std::memcpy(&vb, pb + i, 8);
        
        if (va != vb) {
            // Find first differing byte using XOR and trailing zeros
            uint64_t diff = va ^ vb;
#if defined(_MSC_VER)
            unsigned long idx;
            _BitScanForward64(&idx, diff);
            return i + (idx / 8);
#else
            return i + (__builtin_ctzll(diff) / 8);
#endif
        }
        i += 8;
    }
    
    // Handle remaining bytes
    for (; i < len; ++i) {
        if (pa[i] != pb[i]) {
            return i;
        }
    }
    
    return len;
#else
    // Fallback simple implementation
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    return len;
#endif
}

// ============================================================================
// RAII HELPERS FOR SCOPED OPERATIONS
// ============================================================================

/**
 * @brief RAII guard for scoped memory fence operations
 */
class ScopedMemoryFence {
public:
    ScopedMemoryFence() noexcept { SS_LOAD_FENCE(); }
    ~ScopedMemoryFence() noexcept { SS_STORE_FENCE(); }
    
    ScopedMemoryFence(const ScopedMemoryFence&) = delete;
    ScopedMemoryFence& operator=(const ScopedMemoryFence&) = delete;
};

} // anonymous namespace

PathIndex::PathIndex() = default;

PathIndex::~PathIndex() = default;

PathIndex::PathIndex(PathIndex&& other) noexcept
    : m_view(nullptr)
    , m_baseAddress(nullptr)
    , m_rootOffset(0)
    , m_indexOffset(0)
    , m_indexSize(0)
    , m_pathCount(0)
    , m_nodeCount(0)
{
    // Lock source for thread-safe move
    std::unique_lock lock(other.m_rwLock);
    
    m_view = other.m_view;
    m_baseAddress = other.m_baseAddress;
    m_rootOffset = other.m_rootOffset;
    m_indexOffset = other.m_indexOffset;
    m_indexSize = other.m_indexSize;
    m_pathCount.store(other.m_pathCount.load(std::memory_order_acquire),
                      std::memory_order_release);
    m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire),
                      std::memory_order_release);
    
    // Clear source
    other.m_view = nullptr;
    other.m_baseAddress = nullptr;
    other.m_rootOffset = 0;
    other.m_indexOffset = 0;
    other.m_indexSize = 0;
    other.m_pathCount.store(0, std::memory_order_release);
    other.m_nodeCount.store(0, std::memory_order_release);
}

PathIndex& PathIndex::operator=(PathIndex&& other) noexcept {
    if (this != &other) {
        // Lock both for thread-safe move (use std::lock to avoid deadlock)
        std::unique_lock lockThis(m_rwLock, std::defer_lock);
        std::unique_lock lockOther(other.m_rwLock, std::defer_lock);
        std::lock(lockThis, lockOther);
        
        m_view = other.m_view;
        m_baseAddress = other.m_baseAddress;
        m_rootOffset = other.m_rootOffset;
        m_indexOffset = other.m_indexOffset;
        m_indexSize = other.m_indexSize;
        m_pathCount.store(other.m_pathCount.load(std::memory_order_acquire),
                          std::memory_order_release);
        m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire),
                          std::memory_order_release);
        
        // Clear source
        other.m_view = nullptr;
        other.m_baseAddress = nullptr;
        other.m_rootOffset = 0;
        other.m_indexOffset = 0;
        other.m_indexSize = 0;
        other.m_pathCount.store(0, std::memory_order_release);
        other.m_nodeCount.store(0, std::memory_order_release);
    }
    return *this;
}

StoreError PathIndex::Initialize(
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
    
    // Validate offset and size with overflow protection
    uint64_t endOffset = 0;
    if (!SafeAdd(offset, size, endOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Path index section overflow"
        );
    }
    
    // Validate against file size
    if (endOffset > view.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Path index section exceeds file size"
        );
    }
    
    m_view = &view;
    m_baseAddress = nullptr; // Read-only mode
    m_indexOffset = offset;
    m_indexSize = size;
    
    // Read root offset with bounds validation
    constexpr uint64_t MIN_HEADER_SIZE = 24; // root + pathCount + nodeCount
    if (size < MIN_HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Path index section too small for header"
        );
    }
    
    const auto* rootPtr = view.GetAt<uint64_t>(offset);
    if (rootPtr) {
        m_rootOffset = *rootPtr;
        // Validate root offset is within section bounds
        if (m_rootOffset != 0) {
            // Root must be within section and have room for at least one node
            if (m_rootOffset >= size || m_rootOffset + sizeof(PathTrieNode) > size) {
                SS_LOG_WARN(L"Whitelist", L"PathIndex: invalid root offset %llu (size=%llu)", 
                           m_rootOffset, size);
                m_rootOffset = 0;
            }
        }
    } else {
        m_rootOffset = 0;
    }
    
    const auto* pathCountPtr = view.GetAt<uint64_t>(offset + 8);
    const auto* nodeCountPtr = view.GetAt<uint64_t>(offset + 16);
    
    if (pathCountPtr) {
        m_pathCount.store(*pathCountPtr, std::memory_order_release);
    } else {
        m_pathCount.store(0, std::memory_order_release);
    }
    if (nodeCountPtr) {
        m_nodeCount.store(*nodeCountPtr, std::memory_order_release);
    } else {
        m_nodeCount.store(0, std::memory_order_release);
    }
    
    SS_LOG_DEBUG(L"Whitelist",
        L"PathIndex initialized: %llu paths, %llu nodes",
        m_pathCount.load(std::memory_order_relaxed),
        m_nodeCount.load(std::memory_order_relaxed));
    
    return StoreError::Success();
}

StoreError PathIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate base address
    if (!baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid base address (null)"
        );
    }
    
    // Validate minimum size requirement
    constexpr uint64_t HEADER_SIZE = 64;
    if (availableSize < HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Insufficient space for path index header"
        );
    }
    
    // Validate available size is reasonable
    if (availableSize > static_cast<uint64_t>(INT64_MAX)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Available size exceeds maximum supported value"
        );
    }
    
    // Clear any existing state
    m_view = nullptr; // Write mode
    m_baseAddress = baseAddress;
    m_indexOffset = 0;
    m_indexSize = availableSize;
    
    // Initialize header with zero-fill for security (prevent info leakage)
    auto* header = static_cast<uint8_t*>(baseAddress);
    std::memset(header, 0, static_cast<size_t>(HEADER_SIZE));
    
    // Initialize root offset to after header (will be set on first insert)
    m_rootOffset = HEADER_SIZE;
    
    // Initialize counters with proper memory ordering
    m_pathCount.store(0, std::memory_order_release);
    m_nodeCount.store(0, std::memory_order_release);
    
    // Set output used size
    usedSize = HEADER_SIZE;
    
    SS_LOG_DEBUG(L"Whitelist", L"PathIndex created: header size %llu, available %llu",
                HEADER_SIZE, availableSize);
    
    return StoreError::Success();
}

std::vector<uint64_t> PathIndex::Lookup(
    std::wstring_view path,
    PathMatchMode mode
) const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE PATH TRIE LOOKUP WITH PREFETCHING
     * ========================================================================
     *
     * Implements compressed trie lookup with support for multiple match modes:
     * - Exact: Path must match exactly
     * - Prefix: Path must start with pattern
     * - Suffix: Path must end with pattern
     * - Glob: Pattern uses wildcards (* and ?)
     * - Regex: Full regex matching (expensive, use sparingly)
     *
     * Performance Optimizations:
     * - Cache prefetching for next trie node during traversal
     * - Validated node integrity checks for corruption detection
     * - Early exit paths for common cases
     *
     * Security Note: Returns empty vector on any error (conservative).
     * Unknown paths should NOT be whitelisted.
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_rwLock);
    
    std::vector<uint64_t> results;
    
    // Validate input - empty paths never match
    if (path.empty()) {
        return results;
    }
    
    // Validate path length against Windows MAX_PATH limit
    if (path.length() > MAX_WINDOWS_PATH_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: path exceeds max length (%zu)", path.length());
        return results;
    }
    
    // Validate state - ensure index is initialized
    if (!m_view && !m_baseAddress) {
        return results; // Not initialized
    }
    
    // Fast path: empty index returns immediately
    const uint64_t pathCount = m_pathCount.load(std::memory_order_acquire);
    if (pathCount == 0) {
        return results;
    }
    
    // Normalize path for lookup (lowercase, forward slashes)
    std::string normalizedPath;
    if (!NormalizePath(path, normalizedPath)) {
        SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: path normalization failed");
        return results;
    }
    
    if (normalizedPath.empty()) {
        return results;
    }
    
    try {
        // Reserve reasonable space for results (cap to prevent excessive allocation)
        constexpr size_t MAX_RESULTS = 1024;
        results.reserve(std::min<size_t>(16, MAX_RESULTS));
        
        // Get pointer to trie data with validation
        const uint8_t* base = nullptr;
        uint64_t baseSize = 0;
        
        if (m_view) {
            // Validate view bounds with overflow protection
            uint64_t effectiveBase = 0;
            if (!SafeAdd(reinterpret_cast<uint64_t>(m_view->baseAddress), m_indexOffset, effectiveBase)) {
                return results; // Overflow - return empty (security)
            }
            base = static_cast<const uint8_t*>(m_view->baseAddress) + m_indexOffset;
            baseSize = m_indexSize;
        } else if (m_baseAddress) {
            base = static_cast<const uint8_t*>(m_baseAddress) + m_indexOffset;
            baseSize = m_indexSize;
        }
        
        if (!base || baseSize == 0) {
            return results;
        }
        
        // Validate root offset before starting traversal
        if (!IsValidNodeOffset(m_rootOffset, baseSize)) {
            return results;
        }
        
        // Prefetch root node for cache efficiency
        SS_PREFETCH_READ(base + m_rootOffset);
        
        // Start at root node
        uint64_t currentOffset = m_rootOffset;
        std::string_view remaining(normalizedPath);
        
        // Traverse trie with depth limit to prevent infinite loops
        size_t depth = 0;
        
        while (!remaining.empty() && depth < SAFE_MAX_TRIE_DEPTH) {
            // Validate node offset
            if (!IsValidNodeOffset(currentOffset, baseSize)) {
                SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: invalid node offset at depth %zu", depth);
                break;
            }
            
            const auto* node = reinterpret_cast<const PathTrieNode*>(base + currentOffset);
            
            // Validate node integrity for corruption detection
            if (!ValidateNodeIntegrity(node, baseSize)) {
                SS_LOG_ERROR(L"Whitelist", L"PathIndex::Lookup: corrupted node at offset %llu", currentOffset);
                break;
            }
            
            // Check node segment
            std::string_view nodeSegment = node->GetSegment();
            
            if (!nodeSegment.empty()) {
                // Check if remaining path starts with node segment
                if (remaining.length() < nodeSegment.length() ||
                    remaining.substr(0, nodeSegment.length()) != nodeSegment) {
                    // Mismatch - check for prefix match mode
                    if (mode == PathMatchMode::Prefix && node->IsTerminal()) {
                        // This node might match as a prefix
                        const size_t commonLen = CommonPrefixLength(remaining, nodeSegment);
                        if (commonLen > 0 && commonLen == remaining.length()) {
                            results.push_back(node->entryOffset);
                        }
                    }
                    break; // No match in this branch
                }
                
                // Consume matched segment
                remaining = remaining.substr(nodeSegment.length());
            }
            
            // Check for terminal match
            if (remaining.empty() && node->IsTerminal()) {
                // Exact match found
                if (mode == PathMatchMode::Exact || 
                    mode == PathMatchMode::Prefix ||
                    node->matchMode == mode) {
                    results.push_back(node->entryOffset);
                }
            }
            
            // For prefix mode, also collect all terminal nodes along the path
            if (mode == PathMatchMode::Prefix && node->IsTerminal() && !remaining.empty()) {
                results.push_back(node->entryOffset);
            }
            
            // Try to continue to children
            if (remaining.empty() || !node->HasChildren()) {
                break;
            }
            
            // Find next segment (split by '/')
            const size_t nextSep = remaining.find('/');
            std::string_view nextSegment;
            
            if (nextSep != std::string_view::npos) {
                nextSegment = remaining.substr(0, nextSep + 1);
            } else {
                nextSegment = remaining;
            }
            
            // Calculate child index using optimized hash
            const uint32_t childIdx = SegmentHash(nextSegment);
            
            // Bounds check child index (should always pass due to modulo)
            if (childIdx >= PathTrieNode::MAX_CHILDREN) {
                break;
            }
            
            uint32_t childOffset = node->children[childIdx];
            
            // Prefetch next node if we have a direct hit
            if (childOffset != 0 && IsValidNodeOffset(childOffset, baseSize)) {
                SS_PREFETCH_READ(base + childOffset);
            }
            
            if (childOffset == 0) {
                // No child in this slot - try linear search through all children
                bool found = false;
                
                // Prefetch all potential children for cache efficiency
                for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
                    if (node->children[i] != 0 && IsValidNodeOffset(node->children[i], baseSize)) {
                        SS_PREFETCH_READ_L2(base + node->children[i]);
                    }
                }
                
                for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN && !found; ++i) {
                    const uint32_t childOff = node->children[i];
                    
                    // Skip empty slots
                    if (childOff == 0) {
                        continue;
                    }
                    
                    // Validate child offset
                    if (!IsValidNodeOffset(static_cast<uint64_t>(childOff), baseSize)) {
                        SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: invalid child offset %u", childOff);
                        continue;
                    }
                    
                    const auto* childNode = reinterpret_cast<const PathTrieNode*>(base + childOff);
                    std::string_view childSeg = childNode->GetSegment();
                    
                    // Check if remaining path starts with child segment
                    if (!childSeg.empty() && remaining.length() >= childSeg.length() &&
                        remaining.substr(0, childSeg.length()) == childSeg) {
                        currentOffset = childOff;
                        found = true;
                    }
                }
                
                if (!found) {
                    break; // No matching child
                }
            } else {
                // Validate direct child offset
                if (!IsValidNodeOffset(static_cast<uint64_t>(childOffset), baseSize)) {
                    SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: invalid direct child %u", childOffset);
                    break;
                }
                currentOffset = childOffset;
            }
            
            ++depth;
            
            // Cap results to prevent excessive memory usage
            if (results.size() >= MAX_RESULTS) {
                SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: max results reached");
                break;
            }
        }
        
        // For suffix mode, we need a different approach (scan all paths)
        // This is expensive but necessary for correct suffix matching
        if (mode == PathMatchMode::Suffix && results.empty()) {
            // Perform BFS to find all terminal nodes with matching suffix
            std::queue<uint64_t> bfsQueue;
            std::unordered_set<uint64_t> visited;
            
            bfsQueue.push(m_rootOffset);
            visited.insert(m_rootOffset);
            
            constexpr size_t MAX_SUFFIX_ITERATIONS = 100'000;
            size_t iterations = 0;
            
            while (!bfsQueue.empty() && iterations < MAX_SUFFIX_ITERATIONS && results.size() < MAX_RESULTS) {
                const uint64_t offset = bfsQueue.front();
                bfsQueue.pop();
                ++iterations;
                
                if (!IsValidNodeOffset(offset, baseSize)) {
                    continue;
                }
                
                const auto* node = reinterpret_cast<const PathTrieNode*>(base + offset);
                if (!ValidateNodeIntegrity(node, baseSize)) {
                    continue;
                }
                
                // Check if this terminal node's path ends with our search suffix
                if (node->IsTerminal()) {
                    std::string_view nodeSeg = node->GetSegment();
                    // Check if segment ends with normalized path
                    if (nodeSeg.length() >= normalizedPath.length()) {
                        if (nodeSeg.substr(nodeSeg.length() - normalizedPath.length()) == normalizedPath) {
                            results.push_back(node->entryOffset);
                        }
                    }
                }
                
                // Add children to queue
                for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
                    const uint32_t childOff = node->children[i];
                    if (childOff != 0 && visited.find(childOff) == visited.end()) {
                        if (IsValidNodeOffset(childOff, baseSize)) {
                            bfsQueue.push(childOff);
                            visited.insert(childOff);
                        }
                    }
                }
            }
        }
        
        // For glob mode, implement wildcard matching
        if (mode == PathMatchMode::Glob && results.empty()) {
            // Glob patterns: * matches any sequence, ? matches single char
            // BFS through trie with pattern matching
            
            // Lambda for glob pattern matching
            auto globMatch = [](std::string_view pattern, std::string_view text) -> bool {
                size_t pi = 0, ti = 0;
                size_t starIdx = std::string_view::npos;
                size_t matchIdx = 0;
                
                while (ti < text.length()) {
                    if (pi < pattern.length() && 
                        (pattern[pi] == '?' || pattern[pi] == text[ti])) {
                        ++pi;
                        ++ti;
                    } else if (pi < pattern.length() && pattern[pi] == '*') {
                        starIdx = pi;
                        matchIdx = ti;
                        ++pi;
                    } else if (starIdx != std::string_view::npos) {
                        pi = starIdx + 1;
                        ++matchIdx;
                        ti = matchIdx;
                    } else {
                        return false;
                    }
                }
                
                while (pi < pattern.length() && pattern[pi] == '*') {
                    ++pi;
                }
                
                return pi == pattern.length();
            };
            
            // BFS to find matching paths
            std::queue<std::pair<uint64_t, std::string>> bfsQueue; // (offset, accumulated_path)
            std::unordered_set<uint64_t> visited;
            
            bfsQueue.push({m_rootOffset, ""});
            visited.insert(m_rootOffset);
            
            constexpr size_t MAX_GLOB_ITERATIONS = 100'000;
            size_t iterations = 0;
            
            while (!bfsQueue.empty() && iterations < MAX_GLOB_ITERATIONS && results.size() < MAX_RESULTS) {
                auto [offset, accPath] = bfsQueue.front();
                bfsQueue.pop();
                ++iterations;
                
                if (!IsValidNodeOffset(offset, baseSize)) {
                    continue;
                }
                
                const auto* node = reinterpret_cast<const PathTrieNode*>(base + offset);
                if (!ValidateNodeIntegrity(node, baseSize)) {
                    continue;
                }
                
                // Build accumulated path
                std::string_view nodeSeg = node->GetSegment();
                std::string currentPath = accPath + std::string(nodeSeg);
                
                // Check if this terminal node matches glob pattern
                if (node->IsTerminal()) {
                    if (globMatch(normalizedPath, currentPath)) {
                        results.push_back(node->entryOffset);
                    }
                }
                
                // Add children to queue
                for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
                    const uint32_t childOff = node->children[i];
                    if (childOff != 0 && visited.find(childOff) == visited.end()) {
                        if (IsValidNodeOffset(childOff, baseSize)) {
                            bfsQueue.push({childOff, currentPath});
                            visited.insert(childOff);
                        }
                    }
                }
            }
        }
        
        // For regex mode, use std::regex for full pattern matching
        // Note: This is expensive - use sparingly
        if (mode == PathMatchMode::Regex && results.empty()) {
            try {
                // Compile regex pattern with case-insensitive flag for Windows paths
                std::regex pattern(normalizedPath, 
                    std::regex_constants::ECMAScript | 
                    std::regex_constants::icase |
                    std::regex_constants::optimize);
                
                // BFS to find matching paths
                std::queue<std::pair<uint64_t, std::string>> bfsQueue;
                std::unordered_set<uint64_t> visited;
                
                bfsQueue.push({m_rootOffset, ""});
                visited.insert(m_rootOffset);
                
                constexpr size_t MAX_REGEX_ITERATIONS = 50'000; // Lower limit for expensive regex
                size_t iterations = 0;
                
                while (!bfsQueue.empty() && iterations < MAX_REGEX_ITERATIONS && results.size() < MAX_RESULTS) {
                    auto [offset, accPath] = bfsQueue.front();
                    bfsQueue.pop();
                    ++iterations;
                    
                    if (!IsValidNodeOffset(offset, baseSize)) {
                        continue;
                    }
                    
                    const auto* node = reinterpret_cast<const PathTrieNode*>(base + offset);
                    if (!ValidateNodeIntegrity(node, baseSize)) {
                        continue;
                    }
                    
                    // Build accumulated path
                    std::string_view nodeSeg = node->GetSegment();
                    std::string currentPath = accPath + std::string(nodeSeg);
                    
                    // Check if this terminal node matches regex pattern
                    if (node->IsTerminal()) {
                        if (std::regex_match(currentPath, pattern)) {
                            results.push_back(node->entryOffset);
                        }
                    }
                    
                    // Add children to queue
                    for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
                        const uint32_t childOff = node->children[i];
                        if (childOff != 0 && visited.find(childOff) == visited.end()) {
                            if (IsValidNodeOffset(childOff, baseSize)) {
                                bfsQueue.push({childOff, currentPath});
                                visited.insert(childOff);
                            }
                        }
                    }
                }
            } catch (const std::regex_error& e) {
                SS_LOG_ERROR(L"Whitelist", L"PathIndex::Lookup: invalid regex pattern: %S", e.what());
                // Return empty results for invalid regex
            }
        }
        
        // Remove duplicates if any (sort + unique for O(n log n))
        if (results.size() > 1) {
            std::sort(results.begin(), results.end());
            results.erase(std::unique(results.begin(), results.end()), results.end());
        }
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Lookup exception: %S", e.what());
        results.clear();
    }
    
    // Update performance counters
    m_lookupCount.fetch_add(1, std::memory_order_relaxed);
    if (!results.empty()) {
        m_lookupHits.fetch_add(1, std::memory_order_relaxed);
    }
    
    return results;
}

bool PathIndex::Contains(
    std::wstring_view path,
    PathMatchMode mode
) const noexcept {
    // Validate input
    if (path.empty()) {
        return false;
    }
    
    auto results = Lookup(path, mode);
    return !results.empty();
}

StoreError PathIndex::Insert(
    std::wstring_view path,
    PathMatchMode mode,
    uint64_t entryOffset
) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE PATH TRIE INSERT
     * ========================================================================
     *
     * Inserts a path pattern into the compressed trie. Handles:
     * - Path normalization and UTF-8 encoding
     * - Node allocation and splitting
     * - Prefix compression
     * - Collision handling
     *
     * Thread-safety: Protected by unique_lock
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate input
    if (path.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot insert empty path"
        );
    }
    
    // Validate path length
    constexpr size_t MAX_PATH_LENGTH = 32767;
    if (path.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Path exceeds maximum length"
        );
    }
    
    // Normalize path
    std::string normalizedPath;
    if (!NormalizePath(path, normalizedPath)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Path normalization failed"
        );
    }
    
    if (normalizedPath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Normalized path is empty"
        );
    }
    
    // Get writable base with validation
    if (m_indexOffset > 0) {
        // Ensure offset doesn't cause pointer arithmetic overflow
        uint64_t testOffset = 0;
        if (!SafeAdd(reinterpret_cast<uint64_t>(m_baseAddress), m_indexOffset, testOffset)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Index offset causes pointer overflow"
            );
        }
    }
    auto* base = static_cast<uint8_t*>(m_baseAddress) + m_indexOffset;
    
    // Calculate space needed with overflow protection
    const uint64_t nodeSize = sizeof(PathTrieNode);
    const uint64_t currentNodeCount = m_nodeCount.load(std::memory_order_acquire);
    
    // Validate current node count is reasonable
    constexpr uint64_t MAX_NODE_COUNT = UINT32_MAX;
    if (currentNodeCount > MAX_NODE_COUNT) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Node count exceeds maximum"
        );
    }
    
    // Calculate next node offset with overflow protection
    constexpr uint64_t HEADER_SIZE = 64;
    uint64_t totalNodeSpace = 0;
    if (!SafeMul(currentNodeCount, nodeSize, totalNodeSpace)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Node space calculation overflow"
        );
    }
    
    uint64_t nextNodeOffset = 0;
    if (!SafeAdd(HEADER_SIZE, totalNodeSpace, nextNodeOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Next node offset overflow"
        );
    }
    
    // Check space for at least one new node
    uint64_t requiredSpace = 0;
    if (!SafeAdd(nextNodeOffset, nodeSize, requiredSpace)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Required space calculation overflow"
        );
    }
    
    if (requiredSpace > m_indexSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Path index is full"
        );
    }
    
    // Navigate to insertion point
    uint64_t currentOffset = m_rootOffset;
    std::string_view remaining(normalizedPath);
    
    // Allocate root node if needed
    if (currentNodeCount == 0) {
        // Create root node - use secure zero initialization
        auto* root = reinterpret_cast<PathTrieNode*>(base + HEADER_SIZE);
        SecureZeroMemoryRegion(root, sizeof(PathTrieNode));
        
        // Store path segment (truncate if necessary)
        const size_t segLen = std::min(remaining.length(), PathTrieNode::MAX_SEGMENT_LENGTH);
        std::memcpy(root->segment, remaining.data(), segLen);
        root->segmentLength = static_cast<uint8_t>(segLen);
        root->matchMode = mode;
        root->entryOffset = entryOffset;
        root->SetTerminal(true);
        
        // Memory fence before updating shared state
        SS_STORE_FENCE();
        
        // Update counters
        m_rootOffset = HEADER_SIZE;
        m_nodeCount.store(1, std::memory_order_release);
        m_pathCount.fetch_add(1, std::memory_order_release);
        m_insertCount.fetch_add(1, std::memory_order_relaxed);
        
        // Update header with proper ordering
        auto* headerRoot = reinterpret_cast<uint64_t*>(base);
        *headerRoot = m_rootOffset;
        
        auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
        *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
        
        auto* headerNodeCount = reinterpret_cast<uint64_t*>(base + 16);
        *headerNodeCount = m_nodeCount.load(std::memory_order_relaxed);
        
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex: created root node for path");
        return StoreError::Success();
    }
    
    // Traverse trie to find insertion point with prefetching
    size_t depth = 0;
    
    // Prefetch root node
    SS_PREFETCH_WRITE(base + currentOffset);
    
    while (depth < SAFE_MAX_TRIE_DEPTH) {
        // Validate node offset
        if (!IsValidNodeOffset(currentOffset, m_indexSize)) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Node offset out of bounds during insert traversal"
            );
        }
        
        auto* node = reinterpret_cast<PathTrieNode*>(base + currentOffset);
        std::string_view nodeSegment = node->GetSegment();
        
        // Find common prefix using optimized comparison
        const size_t commonLen = CommonPrefixLength(remaining, nodeSegment);
        
        if (commonLen == 0 && !nodeSegment.empty()) {
            // No common prefix - need to find/create sibling
            const uint32_t childIdx = SegmentHash(remaining);
            
            if (childIdx < PathTrieNode::MAX_CHILDREN && node->children[childIdx] == 0) {
                // Calculate new node offset with overflow protection
                const uint64_t curNodeCount = m_nodeCount.load(std::memory_order_acquire);
                uint64_t newNodeSpace = 0;
                if (!SafeMul(curNodeCount, nodeSize, newNodeSpace)) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexFull,
                        "Node space calculation overflow during insert"
                    );
                }
                
                uint64_t newNodeOffset = 0;
                if (!SafeAdd(PATH_INDEX_HEADER_SIZE, newNodeSpace, newNodeOffset)) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexFull,
                        "New node offset calculation overflow"
                    );
                }
                
                // Validate space for new node
                uint64_t newNodeEndOffset = 0;
                if (!SafeAdd(newNodeOffset, nodeSize, newNodeEndOffset) || newNodeEndOffset > m_indexSize) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexFull,
                        "Path index is full - cannot allocate new child"
                    );
                }
                
                // Validate new node offset fits in uint32_t for children array
                if (newNodeOffset > UINT32_MAX) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexFull,
                        "Node offset exceeds uint32_t range"
                    );
                }
                
                // Allocate and initialize new node securely
                auto* newNode = reinterpret_cast<PathTrieNode*>(base + newNodeOffset);
                SecureZeroMemoryRegion(newNode, sizeof(PathTrieNode));
                
                const size_t segLen = std::min(remaining.length(), PathTrieNode::MAX_SEGMENT_LENGTH);
                std::memcpy(newNode->segment, remaining.data(), segLen);
                newNode->segmentLength = static_cast<uint8_t>(segLen);
                newNode->matchMode = mode;
                newNode->entryOffset = entryOffset;
                newNode->SetTerminal(true);
                
                // Memory fence before linking to parent
                SS_STORE_FENCE();
                
                // Link to parent atomically
                node->children[childIdx] = static_cast<uint32_t>(newNodeOffset);
                node->childCount++;
                
                m_nodeCount.fetch_add(1, std::memory_order_release);
                m_pathCount.fetch_add(1, std::memory_order_release);
                m_insertCount.fetch_add(1, std::memory_order_relaxed);
                
                // Update header counts
                auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
                *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
                
                auto* headerNodeCount = reinterpret_cast<uint64_t*>(base + 16);
                *headerNodeCount = m_nodeCount.load(std::memory_order_relaxed);
                
                return StoreError::Success();
            }
            
            // Child slot occupied - try to traverse
            if (node->children[childIdx] != 0) {
                // Prefetch next node
                SS_PREFETCH_WRITE(base + node->children[childIdx]);
                currentOffset = node->children[childIdx];
                ++depth;
                continue;
            }
        }
        
        if (commonLen == nodeSegment.length() && commonLen == remaining.length()) {
            // Exact match - update existing node
            if (node->IsTerminal()) {
                // Already exists
                return StoreError::WithMessage(
                    WhitelistStoreError::DuplicateEntry,
                    "Path already exists in index"
                );
            }
            
            // Make this node terminal
            node->SetTerminal(true);
            node->entryOffset = entryOffset;
            node->matchMode = mode;
            
            m_pathCount.fetch_add(1, std::memory_order_release);
            m_insertCount.fetch_add(1, std::memory_order_relaxed);
            
            auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
            *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
            
            return StoreError::Success();
        }
        
        if (commonLen == nodeSegment.length()) {
            // Node segment is prefix of remaining - continue down
            remaining = remaining.substr(commonLen);
            
            // Skip separator if present
            if (!remaining.empty() && remaining[0] == '/') {
                remaining = remaining.substr(1);
            }
            
            if (remaining.empty()) {
                // This node should be terminal
                if (node->IsTerminal()) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::DuplicateEntry,
                        "Path already exists"
                    );
                }
                
                node->SetTerminal(true);
                node->entryOffset = entryOffset;
                node->matchMode = mode;
                
                m_pathCount.fetch_add(1, std::memory_order_release);
                m_insertCount.fetch_add(1, std::memory_order_relaxed);
                return StoreError::Success();
            }
            
            // Find child to continue
            uint32_t childIdx = SegmentHash(remaining);
            
            if (childIdx < PathTrieNode::MAX_CHILDREN && node->children[childIdx] != 0) {
                // Validate child offset before traversing
                const uint64_t childOff = node->children[childIdx];
                uint64_t childEndOff = 0;
                if (!SafeAdd(childOff, nodeSize, childEndOff) || childEndOff > m_indexSize) {
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexCorrupted,
                        "Child node offset invalid during traversal"
                    );
                }
                currentOffset = childOff;
                ++depth;
                continue;
            }
            
            // Allocate new child with overflow protection
            const uint64_t curNodeCount = m_nodeCount.load(std::memory_order_acquire);
            uint64_t newNodeSpace = 0;
            if (!SafeMul(curNodeCount, nodeSize, newNodeSpace)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node space calculation overflow"
                );
            }
            
            uint64_t newNodeOffset = 0;
            if (!SafeAdd(HEADER_SIZE, newNodeSpace, newNodeOffset)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "New node offset overflow"
                );
            }
            
            // Validate space and uint32_t range
            uint64_t newNodeEndOffset = 0;
            if (!SafeAdd(newNodeOffset, nodeSize, newNodeEndOffset) || newNodeEndOffset > m_indexSize) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Path index full - cannot allocate child"
                );
            }
            
            if (newNodeOffset > UINT32_MAX) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node offset exceeds uint32_t range"
                );
            }
            
            auto* newNode = reinterpret_cast<PathTrieNode*>(base + newNodeOffset);
            SecureZeroMemoryRegion(newNode, sizeof(PathTrieNode));
            
            const size_t segLen = std::min(remaining.length(), PathTrieNode::MAX_SEGMENT_LENGTH);
            std::memcpy(newNode->segment, remaining.data(), segLen);
            newNode->segmentLength = static_cast<uint8_t>(segLen);
            newNode->matchMode = mode;
            newNode->entryOffset = entryOffset;
            newNode->SetTerminal(true);
            
            // Memory fence before linking
            SS_STORE_FENCE();
            
            if (childIdx < PathTrieNode::MAX_CHILDREN) {
                node->children[childIdx] = static_cast<uint32_t>(newNodeOffset);
                node->childCount++;
            }
            
            m_nodeCount.fetch_add(1, std::memory_order_release);
            m_pathCount.fetch_add(1, std::memory_order_release);
            m_insertCount.fetch_add(1, std::memory_order_relaxed);
            
            auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
            *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
            
            auto* headerNodeCount = reinterpret_cast<uint64_t*>(base + 16);
            *headerNodeCount = m_nodeCount.load(std::memory_order_relaxed);
            
            return StoreError::Success();
        }
        
        // ====================================================================
        // ENTERPRISE-GRADE NODE SPLIT IMPLEMENTATION
        // ====================================================================
        // 
        // Scenario: commonLen < nodeSegment.length()
        // We need to split the current node into two nodes:
        //   1. A new internal node containing the common prefix
        //   2. The original node (modified) containing the remaining suffix
        //   3. A new leaf node for the path being inserted
        //
        // Example: Existing node has "program_files", inserting "program_data"
        //   Common prefix: "program_" (commonLen = 8)
        //   Node becomes: "program_" (internal)
        //     -> Child 0: "files" (original content, terminal if it was)
        //     -> Child 1: "data" (new insertion, terminal)
        //
        // This maintains proper trie structure with path compression.
        // ====================================================================
        
        {
            // Calculate offsets for two new nodes with overflow protection
            const uint64_t curNodeCount = m_nodeCount.load(std::memory_order_acquire);
            
            // We need space for two new nodes: suffix node + new path node
            uint64_t newNode1Offset = 0;  // Suffix node (remaining of original segment)
            uint64_t newNode2Offset = 0;  // New path node
            
            uint64_t curNodeSpace = 0;
            if (!SafeMul(curNodeCount, nodeSize, curNodeSpace)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node space overflow in split"
                );
            }
            
            if (!SafeAdd(HEADER_SIZE, curNodeSpace, newNode1Offset)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node1 offset overflow in split"
                );
            }
            
            if (!SafeAdd(newNode1Offset, nodeSize, newNode2Offset)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node2 offset overflow in split"
                );
            }
            
            // Validate we have space for both new nodes
            uint64_t totalRequired = 0;
            if (!SafeAdd(newNode2Offset, nodeSize, totalRequired) || totalRequired > m_indexSize) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Insufficient space for node split"
                );
            }
            
            // Validate offsets fit in uint32_t
            if (newNode1Offset > UINT32_MAX || newNode2Offset > UINT32_MAX) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Node offset exceeds uint32_t range in split"
                );
            }
            
            // Save original node state before modification
            const bool originalWasTerminal = node->IsTerminal();
            const uint64_t originalEntryOffset = node->entryOffset;
            const PathMatchMode originalMatchMode = node->matchMode;
            const uint32_t originalChildCount = node->childCount;
            uint32_t originalChildren[PathTrieNode::MAX_CHILDREN];
            std::memcpy(originalChildren, node->children, sizeof(originalChildren));
            
            // Calculate segments
            // Original segment suffix (part after common prefix)
            std::string_view suffixSegment = nodeSegment.substr(commonLen);
            // New path suffix (part after common prefix)  
            std::string_view newPathSegment = remaining.substr(commonLen);
            
            // Allocate suffix node (contains rest of original segment)
            auto* suffixNode = reinterpret_cast<PathTrieNode*>(base + newNode1Offset);
            SecureZeroMemoryRegion(suffixNode, sizeof(PathTrieNode));
            
            // Copy suffix segment
            const size_t suffixLen = std::min(suffixSegment.length(), PathTrieNode::MAX_SEGMENT_LENGTH);
            std::memcpy(suffixNode->segment, suffixSegment.data(), suffixLen);
            suffixNode->segmentLength = static_cast<uint8_t>(suffixLen);
            
            // Transfer original node's terminal state and children to suffix node
            if (originalWasTerminal) {
                suffixNode->SetTerminal(true);
                suffixNode->entryOffset = originalEntryOffset;
                suffixNode->matchMode = originalMatchMode;
            }
            
            // Transfer original children to suffix node
            std::memcpy(suffixNode->children, originalChildren, sizeof(originalChildren));
            suffixNode->childCount = originalChildCount;
            
            // Allocate new path node (contains new insertion)
            auto* newPathNode = reinterpret_cast<PathTrieNode*>(base + newNode2Offset);
            SecureZeroMemoryRegion(newPathNode, sizeof(PathTrieNode));
            
            // Copy new path segment
            const size_t newPathLen = std::min(newPathSegment.length(), PathTrieNode::MAX_SEGMENT_LENGTH);
            std::memcpy(newPathNode->segment, newPathSegment.data(), newPathLen);
            newPathNode->segmentLength = static_cast<uint8_t>(newPathLen);
            newPathNode->SetTerminal(true);
            newPathNode->entryOffset = entryOffset;
            newPathNode->matchMode = mode;
            
            // Modify current node to become the internal node with common prefix
            // This reuses the original node's position in the trie
            
            // Update segment to common prefix only
            const size_t commonPrefixLen = std::min(commonLen, PathTrieNode::MAX_SEGMENT_LENGTH);
            // Clear segment first for security
            SecureZeroMemoryRegion(node->segment, PathTrieNode::MAX_SEGMENT_LENGTH);
            std::memcpy(node->segment, nodeSegment.data(), commonPrefixLen);
            node->segmentLength = static_cast<uint8_t>(commonPrefixLen);
            
            // Current node is no longer terminal (it's now an internal node)
            node->SetTerminal(false);
            node->entryOffset = 0;
            
            // Clear all children of current node
            SecureZeroMemoryRegion(node->children, sizeof(node->children));
            node->childCount = 0;
            
            // Link suffix node and new path node as children
            // Calculate child indices using hash of first char of each suffix
            const uint32_t suffixChildIdx = suffixSegment.empty() ? 0 : SegmentHash(suffixSegment);
            const uint32_t newPathChildIdx = newPathSegment.empty() ? 0 : SegmentHash(newPathSegment);
            
            // Handle collision: if both hash to same index, use linear probing
            if (suffixChildIdx == newPathChildIdx) {
                // Place suffix at hashed index
                node->children[suffixChildIdx] = static_cast<uint32_t>(newNode1Offset);
                node->childCount++;
                
                // Find next available slot for new path
                for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
                    const uint32_t probeIdx = (suffixChildIdx + i + 1) % PathTrieNode::MAX_CHILDREN;
                    if (node->children[probeIdx] == 0) {
                        node->children[probeIdx] = static_cast<uint32_t>(newNode2Offset);
                        node->childCount++;
                        break;
                    }
                }
            } else {
                // No collision - direct placement
                node->children[suffixChildIdx] = static_cast<uint32_t>(newNode1Offset);
                node->children[newPathChildIdx] = static_cast<uint32_t>(newNode2Offset);
                node->childCount = 2;
            }
            
            // Memory fence to ensure all writes are visible
            SS_STORE_FENCE();
            
            // Update counters - we added 2 new nodes
            m_nodeCount.fetch_add(2, std::memory_order_release);
            m_pathCount.fetch_add(1, std::memory_order_release);
            m_insertCount.fetch_add(1, std::memory_order_relaxed);
            
            // Update header
            auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
            *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
            
            auto* headerNodeCount = reinterpret_cast<uint64_t*>(base + 16);
            *headerNodeCount = m_nodeCount.load(std::memory_order_relaxed);
            
            SS_LOG_DEBUG(L"Whitelist", 
                L"PathIndex: node split at depth %zu, common prefix len %zu",
                depth, commonLen);
            
            return StoreError::Success();
        }
        
        // All paths should be handled by node split above
        // If we reach here, it's an unexpected state
        ++depth;
    }
    
    return StoreError::WithMessage(
        WhitelistStoreError::IndexFull,
        "Failed to insert path - max depth or no slot available"
    );
}

StoreError PathIndex::Remove(
    std::wstring_view path,
    PathMatchMode mode
) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE PATH TRIE REMOVE WITH SECURE DELETION
     * ========================================================================
     *
     * Removes a path pattern from the trie. The node is marked as non-terminal
     * rather than physically deleted (lazy deletion for performance).
     *
     * Security Features:
     * - Node validation before modification
     * - Secure memory clearing of sensitive data
     * - Atomic counter updates with underflow protection
     *
     * Physical cleanup happens during compaction.
     *
     * Thread-safety: Protected by unique_lock
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate input
    if (path.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot remove empty path"
        );
    }
    
    // Validate path length
    if (path.length() > MAX_WINDOWS_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Path exceeds maximum length"
        );
    }
    
    // Fast path: empty index
    const uint64_t currentPathCount = m_pathCount.load(std::memory_order_acquire);
    if (currentPathCount == 0) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Index is empty"
        );
    }
    
    // Normalize path
    std::string normalizedPath;
    if (!NormalizePath(path, normalizedPath)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Path normalization failed"
        );
    }
    
    if (normalizedPath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Normalized path is empty"
        );
    }
    
    // Get writable base with validation
    if (m_indexOffset > 0) {
        uint64_t testOffset = 0;
        if (!SafeAdd(reinterpret_cast<uint64_t>(m_baseAddress), m_indexOffset, testOffset)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Index offset causes pointer overflow"
            );
        }
    }
    auto* base = static_cast<uint8_t*>(m_baseAddress) + m_indexOffset;
    
    // Validate root offset
    if (!IsValidNodeOffset(m_rootOffset, m_indexSize)) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Root offset invalid - index may be corrupted or empty"
        );
    }
    
    // Navigate to the node with prefetching
    uint64_t currentOffset = m_rootOffset;
    std::string_view remaining(normalizedPath);
    const uint64_t nodeSize = sizeof(PathTrieNode);
    
    // Prefetch root node
    SS_PREFETCH_WRITE(base + currentOffset);
    
    size_t depth = 0;
    
    while (depth < SAFE_MAX_TRIE_DEPTH) {
        // Validate node offset
        if (!IsValidNodeOffset(currentOffset, m_indexSize)) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Node offset out of bounds during remove"
            );
        }
        
        auto* node = reinterpret_cast<PathTrieNode*>(base + currentOffset);
        
        // Validate node integrity
        if (!ValidateNodeIntegrity(node, m_indexSize)) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Corrupted node detected during remove"
            );
        }
        
        std::string_view nodeSegment = node->GetSegment();
        
        // Check if segments match
        if (!nodeSegment.empty()) {
            if (remaining.length() < nodeSegment.length() ||
                remaining.substr(0, nodeSegment.length()) != nodeSegment) {
                // Mismatch - path not found
                return StoreError::WithMessage(
                    WhitelistStoreError::EntryNotFound,
                    "Path not found in index"
                );
            }
            
            remaining = remaining.substr(nodeSegment.length());
        }
        
        // Check if this is the target node
        if (remaining.empty()) {
            if (node->IsTerminal() && node->matchMode == mode) {
                // Found it - mark as non-terminal (lazy delete)
                node->SetTerminal(false);
                
                // Securely clear the entry offset to prevent information leakage
                node->entryOffset = 0;
                
                // Memory fence to ensure visibility
                SS_STORE_FENCE();
                
                // Atomic decrement with proper ordering and underflow protection
                const uint64_t previousCount = m_pathCount.fetch_sub(1, std::memory_order_acq_rel);
                
                // Safety check: ensure we didn't underflow
                // Note: fetch_sub returns the PREVIOUS value, so if previousCount was 0,
                // we have underflowed (counter wrapped to UINT64_MAX)
                if (previousCount == 0) {
                    // Critical: Counter underflow indicates data corruption or race condition
                    // Restore count to maintain consistency and report error
                    m_pathCount.fetch_add(1, std::memory_order_relaxed);
                    
                    SS_LOG_ERROR(L"Whitelist", 
                        L"PathIndex::Remove: CRITICAL - path count underflow prevented, "
                        L"possible index corruption or concurrent modification");
                    
                    // Use IndexCorrupted as this indicates a serious state inconsistency
                    // that should trigger integrity verification
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexCorrupted,
                        "Counter underflow detected - index state inconsistent"
                    );
                }
                
                // Update remove counter
                m_removeCount.fetch_add(1, std::memory_order_relaxed);
                
                // Update header with current count
                auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
                *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
                
                SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Remove: path removed (lazy delete)");
                return StoreError::Success();
            }
            
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path exists but not as terminal with matching mode"
            );
        }
        
        // Skip separator if present
        if (!remaining.empty() && remaining[0] == '/') {
            remaining = remaining.substr(1);
        }
        
        if (remaining.empty()) {
            // Check current node
            if (node->IsTerminal() && node->matchMode == mode) {
                node->SetTerminal(false);
                node->entryOffset = 0;
                
                // Memory fence for visibility
                SS_STORE_FENCE();
                
                // Atomic decrement with underflow protection
                const uint64_t previousCount = m_pathCount.fetch_sub(1, std::memory_order_acq_rel);
                
                // Check for underflow - previousCount was the value BEFORE subtraction
                if (previousCount == 0) {
                    // Critical: Counter underflow indicates corruption
                    m_pathCount.fetch_add(1, std::memory_order_relaxed);
                    
                    SS_LOG_ERROR(L"Whitelist", 
                        L"PathIndex::Remove: CRITICAL - path count underflow in separator check, "
                        L"possible index corruption");
                    
                    return StoreError::WithMessage(
                        WhitelistStoreError::IndexCorrupted,
                        "Counter underflow detected in terminal check - index state inconsistent"
                    );
                }
                
                // Update remove counter
                m_removeCount.fetch_add(1, std::memory_order_relaxed);
                
                // Update header
                auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
                *headerPathCount = m_pathCount.load(std::memory_order_relaxed);
                
                SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Remove: path removed (terminal check path)");
                return StoreError::Success();
            }
            
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path not found"
            );
        }
        
        // Navigate to child
        if (!node->HasChildren()) {
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path not found - no children"
            );
        }
        
        const uint32_t childIdx = SegmentHash(remaining);
        
        // Try direct child first with validation and prefetching
        if (childIdx < PathTrieNode::MAX_CHILDREN && node->children[childIdx] != 0) {
            const uint64_t childOff = node->children[childIdx];
            if (!IsValidNodeOffset(childOff, m_indexSize)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexCorrupted,
                    "Child offset invalid during remove traversal"
                );
            }
            // Prefetch next node
            SS_PREFETCH_WRITE(base + childOff);
            currentOffset = childOff;
            ++depth;
            continue;
        }
        
        // Linear search children with validation
        bool found = false;
        
        // Prefetch all potential children
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            if (node->children[i] != 0 && IsValidNodeOffset(node->children[i], m_indexSize)) {
                SS_PREFETCH_READ_L2(base + node->children[i]);
            }
        }
        
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN && !found; ++i) {
            const uint32_t childOff = node->children[i];
            if (childOff == 0) {
                continue;
            }
            
            // Validate child offset
            if (!IsValidNodeOffset(static_cast<uint64_t>(childOff), m_indexSize)) {
                SS_LOG_WARN(L"Whitelist", L"PathIndex::Remove: skipping invalid child offset %u", childOff);
                continue;
            }
            
            const auto* childNode = reinterpret_cast<const PathTrieNode*>(base + childOff);
            std::string_view childSeg = childNode->GetSegment();
            
            if (!childSeg.empty() && remaining.length() >= childSeg.length() &&
                remaining.substr(0, childSeg.length()) == childSeg) {
                currentOffset = childOff;
                found = true;
            }
        }
        
        if (!found) {
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path not found - no matching child"
            );
        }
        
        ++depth;
    }
    
    return StoreError::WithMessage(
        WhitelistStoreError::EntryNotFound,
        "Path not found - max depth exceeded"
    );
}

// ============================================================================
// CLEAR IMPLEMENTATION
// ============================================================================

StoreError PathIndex::Clear() noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE TRIE CLEAR WITH SECURE MEMORY ZEROING
     * ========================================================================
     *
     * Clears all paths from the index by:
     * 1. Securely zeroing all node data
     * 2. Resetting counters and root offset
     * 3. Updating header metadata
     *
     * Security: Uses SecureZeroMemory to prevent data leakage
     *
     * Thread-safety: Protected by unique_lock
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only - cannot clear"
        );
    }
    
    // Get base pointer with validation
    if (m_indexOffset > 0) {
        uint64_t testOffset = 0;
        if (!SafeAdd(reinterpret_cast<uint64_t>(m_baseAddress), m_indexOffset, testOffset)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidSection,
                "Index offset causes pointer overflow"
            );
        }
    }
    
    auto* base = static_cast<uint8_t*>(m_baseAddress) + m_indexOffset;
    
    // Calculate total used space
    const uint64_t nodeCount = m_nodeCount.load(std::memory_order_acquire);
    constexpr uint64_t HEADER_SIZE = 64;
    const uint64_t nodeSize = sizeof(PathTrieNode);
    
    uint64_t totalUsedSpace = 0;
    if (!SafeMul(nodeCount, nodeSize, totalUsedSpace)) {
        totalUsedSpace = m_indexSize; // Fallback: clear entire index
    }
    
    uint64_t clearSize = 0;
    if (!SafeAdd(HEADER_SIZE, totalUsedSpace, clearSize)) {
        clearSize = m_indexSize;
    }
    
    // Clamp to actual index size
    if (clearSize > m_indexSize) {
        clearSize = m_indexSize;
    }
    
    // Securely zero all data (prevent information leakage)
    SecureZeroMemoryRegion(base, static_cast<size_t>(clearSize));
    
    // Memory fence to ensure zeroing is visible
    SS_STORE_FENCE();
    
    // Reset state
    m_rootOffset = HEADER_SIZE;
    m_pathCount.store(0, std::memory_order_release);
    m_nodeCount.store(0, std::memory_order_release);
    
    // Update header (redundant but explicit)
    auto* headerRoot = reinterpret_cast<uint64_t*>(base);
    *headerRoot = 0;
    
    auto* headerPathCount = reinterpret_cast<uint64_t*>(base + 8);
    *headerPathCount = 0;
    
    auto* headerNodeCount = reinterpret_cast<uint64_t*>(base + 16);
    *headerNodeCount = 0;
    
    SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Clear: index cleared securely");
    
    return StoreError::Success();
}

// ============================================================================
// COMPACT IMPLEMENTATION
// ============================================================================

StoreError PathIndex::Compact() noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE TRIE COMPACTION WITH DEFRAGMENTATION
     * ========================================================================
     *
     * Rebuilds the trie to:
     * 1. Remove lazy-deleted nodes (non-terminal with no terminal descendants)
     * 2. Merge single-child paths (path compression)
     * 3. Reorder nodes for better cache locality
     * 4. Reclaim fragmented space
     *
     * Algorithm:
     * 1. BFS traversal to identify all live nodes
     * 2. Allocate temporary buffer for new trie
     * 3. Copy live nodes with new offsets
     * 4. Update all child pointers
     * 5. Copy back to original location
     *
     * Thread-safety: Protected by unique_lock (exclusive access required)
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only - cannot compact"
        );
    }
    
    const uint64_t currentPathCount = m_pathCount.load(std::memory_order_acquire);
    const uint64_t currentNodeCount = m_nodeCount.load(std::memory_order_acquire);
    
    // Fast path: empty or minimal index doesn't need compaction
    if (currentNodeCount <= 1) {
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Compact: nothing to compact");
        return StoreError::Success();
    }
    
    // Get base pointer
    auto* base = static_cast<uint8_t*>(m_baseAddress) + m_indexOffset;
    constexpr uint64_t HEADER_SIZE = 64;
    const uint64_t nodeSize = sizeof(PathTrieNode);
    
    // Validate root offset
    if (!IsValidNodeOffset(m_rootOffset, m_indexSize)) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid root offset - cannot compact"
        );
    }
    
    // Structure to track node mappings during compaction
    struct NodeMapping {
        uint64_t oldOffset{0};
        uint64_t newOffset{0};
        bool isLive{false};
        bool hasTerminalDescendant{false};
    };
    
    // Collect all reachable nodes using BFS
    std::vector<NodeMapping> nodeMappings;
    std::unordered_set<uint64_t> visitedOffsets;
    std::queue<uint64_t> bfsQueue;
    
    try {
        nodeMappings.reserve(static_cast<size_t>(currentNodeCount));
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate memory for compaction"
        );
    }
    
    // Start BFS from root
    bfsQueue.push(m_rootOffset);
    visitedOffsets.insert(m_rootOffset);
    
    // First pass: identify all reachable nodes
    size_t processedNodes = 0;
    constexpr size_t MAX_NODES_TO_PROCESS = 10'000'000; // Safety limit
    
    while (!bfsQueue.empty() && processedNodes < MAX_NODES_TO_PROCESS) {
        const uint64_t currentOffset = bfsQueue.front();
        bfsQueue.pop();
        ++processedNodes;
        
        // Validate node offset
        if (!IsValidNodeOffset(currentOffset, m_indexSize)) {
            SS_LOG_WARN(L"Whitelist", L"PathIndex::Compact: skipping invalid offset %llu", currentOffset);
            continue;
        }
        
        const auto* node = reinterpret_cast<const PathTrieNode*>(base + currentOffset);
        
        // Validate node integrity
        if (!ValidateNodeIntegrity(node, m_indexSize)) {
            SS_LOG_WARN(L"Whitelist", L"PathIndex::Compact: skipping corrupted node at %llu", currentOffset);
            continue;
        }
        
        // Record this node
        NodeMapping mapping;
        mapping.oldOffset = currentOffset;
        mapping.isLive = node->IsTerminal(); // Initially live if terminal
        nodeMappings.push_back(mapping);
        
        // Add children to queue
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            const uint32_t childOff = node->children[i];
            if (childOff != 0 && visitedOffsets.find(childOff) == visitedOffsets.end()) {
                if (IsValidNodeOffset(childOff, m_indexSize)) {
                    bfsQueue.push(childOff);
                    visitedOffsets.insert(childOff);
                }
            }
        }
    }
    
    if (nodeMappings.empty()) {
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Compact: no nodes to compact");
        return StoreError::Success();
    }
    
    // Second pass: mark nodes with terminal descendants as live
    // Process in reverse (children before parents due to BFS order)
    std::unordered_map<uint64_t, size_t> offsetToIndex;
    for (size_t i = 0; i < nodeMappings.size(); ++i) {
        offsetToIndex[nodeMappings[i].oldOffset] = i;
    }
    
    // Mark terminal descendants
    for (auto it = nodeMappings.rbegin(); it != nodeMappings.rend(); ++it) {
        const auto* node = reinterpret_cast<const PathTrieNode*>(base + it->oldOffset);
        
        // Check if any child has terminal descendants
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            const uint32_t childOff = node->children[i];
            if (childOff != 0) {
                auto childIt = offsetToIndex.find(childOff);
                if (childIt != offsetToIndex.end()) {
                    const auto& childMapping = nodeMappings[childIt->second];
                    if (childMapping.isLive || childMapping.hasTerminalDescendant) {
                        it->hasTerminalDescendant = true;
                        break;
                    }
                }
            }
        }
        
        // Node is live if terminal or has terminal descendants
        if (it->hasTerminalDescendant) {
            it->isLive = true;
        }
    }
    
    // Count live nodes and calculate new offsets
    uint64_t newNodeCount = 0;
    uint64_t nextOffset = HEADER_SIZE;
    
    for (auto& mapping : nodeMappings) {
        if (mapping.isLive) {
            mapping.newOffset = nextOffset;
            
            uint64_t newNextOffset = 0;
            if (!SafeAdd(nextOffset, nodeSize, newNextOffset)) {
                return StoreError::WithMessage(
                    WhitelistStoreError::IndexFull,
                    "Offset overflow during compaction"
                );
            }
            nextOffset = newNextOffset;
            ++newNodeCount;
        }
    }
    
    // Check if compaction is beneficial
    if (newNodeCount == currentNodeCount) {
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Compact: no dead nodes to remove");
        return StoreError::Success();
    }
    
    // Allocate temporary buffer for new trie
    const uint64_t newTrieSize = nextOffset;
    std::vector<uint8_t> tempBuffer;
    
    try {
        tempBuffer.resize(static_cast<size_t>(newTrieSize), 0);
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate temporary buffer for compaction"
        );
    }
    
    // Build offset translation map
    std::unordered_map<uint64_t, uint64_t> oldToNewOffset;
    for (const auto& mapping : nodeMappings) {
        if (mapping.isLive) {
            oldToNewOffset[mapping.oldOffset] = mapping.newOffset;
        }
    }
    
    // Copy live nodes to temporary buffer with updated offsets
    for (const auto& mapping : nodeMappings) {
        if (!mapping.isLive) {
            continue;
        }
        
        const auto* oldNode = reinterpret_cast<const PathTrieNode*>(base + mapping.oldOffset);
        auto* newNode = reinterpret_cast<PathTrieNode*>(tempBuffer.data() + mapping.newOffset);
        
        // Copy node data
        std::memcpy(newNode, oldNode, sizeof(PathTrieNode));
        
        // Update child offsets
        uint32_t newChildCount = 0;
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            const uint32_t oldChildOff = oldNode->children[i];
            if (oldChildOff != 0) {
                auto it = oldToNewOffset.find(oldChildOff);
                if (it != oldToNewOffset.end()) {
                    // Child is live - update offset
                    if (it->second <= UINT32_MAX) {
                        newNode->children[i] = static_cast<uint32_t>(it->second);
                        ++newChildCount;
                    } else {
                        newNode->children[i] = 0;
                    }
                } else {
                    // Child was removed
                    newNode->children[i] = 0;
                }
            }
        }
        newNode->childCount = newChildCount;
    }
    
    // Write header to temporary buffer
    auto* headerRoot = reinterpret_cast<uint64_t*>(tempBuffer.data());
    auto rootIt = oldToNewOffset.find(m_rootOffset);
    if (rootIt != oldToNewOffset.end()) {
        *headerRoot = rootIt->second;
    } else {
        *headerRoot = HEADER_SIZE; // Default to first node after header
    }
    
    auto* headerPathCount = reinterpret_cast<uint64_t*>(tempBuffer.data() + 8);
    *headerPathCount = currentPathCount;
    
    auto* headerNodeCount = reinterpret_cast<uint64_t*>(tempBuffer.data() + 16);
    *headerNodeCount = newNodeCount;
    
    // Memory fence before copying back
    SS_STORE_FENCE();
    
    // Securely clear original data first
    SecureZeroMemoryRegion(base, static_cast<size_t>(m_indexSize));
    
    // Copy compacted trie back to original location
    std::memcpy(base, tempBuffer.data(), static_cast<size_t>(newTrieSize));
    
    // Update state
    m_rootOffset = *headerRoot;
    m_nodeCount.store(newNodeCount, std::memory_order_release);
    
    // Final memory fence
    SS_STORE_FENCE();
    
    SS_LOG_INFO(L"Whitelist", 
        L"PathIndex::Compact: compacted from %llu to %llu nodes (%.1f%% reduction)",
        currentNodeCount, newNodeCount,
        100.0 * (1.0 - static_cast<double>(newNodeCount) / static_cast<double>(currentNodeCount)));
    
    return StoreError::Success();
}

// ============================================================================
// GET DETAILED STATS IMPLEMENTATION
// ============================================================================

PathIndexStats PathIndex::GetDetailedStats() const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE STATISTICS COLLECTION
     * ========================================================================
     *
     * Collects comprehensive statistics by traversing the trie:
     * - Node counts (total, terminal, internal)
     * - Structural metrics (depth, children, segments)
     * - Memory metrics (usage, fragmentation)
     * - Match mode distribution
     * - Performance counters
     *
     * Thread-safety: Uses shared_lock for concurrent reads
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_rwLock);
    
    PathIndexStats stats;
    
    // Basic state
    stats.pathCount = m_pathCount.load(std::memory_order_acquire);
    stats.nodeCount = m_nodeCount.load(std::memory_order_acquire);
    stats.indexSize = m_indexSize;
    stats.isReady = IsReady();
    stats.isWritable = (m_baseAddress != nullptr);
    
    // Performance counters
    stats.lookupCount = m_lookupCount.load(std::memory_order_relaxed);
    stats.lookupHits = m_lookupHits.load(std::memory_order_relaxed);
    stats.insertCount = m_insertCount.load(std::memory_order_relaxed);
    stats.removeCount = m_removeCount.load(std::memory_order_relaxed);
    stats.lookupMisses = stats.lookupCount - stats.lookupHits;
    
    // Early return if not initialized
    if (!stats.isReady || stats.nodeCount == 0) {
        return stats;
    }
    
    // Get base pointer for traversal
    const uint8_t* base = nullptr;
    if (m_view) {
        base = static_cast<const uint8_t*>(m_view->baseAddress) + m_indexOffset;
    } else if (m_baseAddress) {
        base = static_cast<const uint8_t*>(m_baseAddress) + m_indexOffset;
    }
    
    if (!base) {
        return stats;
    }
    
    // Validate root offset
    if (!IsValidNodeOffset(m_rootOffset, m_indexSize)) {
        stats.lastIntegrityCheckPassed = false;
        return stats;
    }
    
    // BFS traversal to collect detailed statistics
    std::queue<std::pair<uint64_t, uint32_t>> bfsQueue; // (offset, depth)
    std::unordered_set<uint64_t> visited;
    
    bfsQueue.push({m_rootOffset, 0});
    visited.insert(m_rootOffset);
    
    uint64_t totalChildCount = 0;
    uint64_t totalSegmentLength = 0;
    uint64_t totalDepth = 0;
    uint64_t terminalCount = 0;
    constexpr size_t MAX_ITERATIONS = 10'000'000;
    size_t iterations = 0;
    
    while (!bfsQueue.empty() && iterations < MAX_ITERATIONS) {
        auto [currentOffset, depth] = bfsQueue.front();
        bfsQueue.pop();
        ++iterations;
        
        // Validate node offset
        if (!IsValidNodeOffset(currentOffset, m_indexSize)) {
            ++stats.corruptedNodes;
            continue;
        }
        
        const auto* node = reinterpret_cast<const PathTrieNode*>(base + currentOffset);
        
        // Validate node integrity
        if (!ValidateNodeIntegrity(node, m_indexSize)) {
            ++stats.corruptedNodes;
            continue;
        }
        
        // Update max depth
        if (depth > stats.maxDepth) {
            stats.maxDepth = depth;
        }
        
        // Count terminal vs internal
        if (node->IsTerminal()) {
            ++stats.terminalNodes;
            ++terminalCount;
            totalDepth += depth;
            
            // Count by match mode
            switch (node->matchMode) {
                case PathMatchMode::Exact:   ++stats.exactMatchPaths; break;
                case PathMatchMode::Prefix:  ++stats.prefixMatchPaths; break;
                case PathMatchMode::Suffix:  ++stats.suffixMatchPaths; break;
                case PathMatchMode::Glob:    ++stats.globMatchPaths; break;
                case PathMatchMode::Regex:   ++stats.regexMatchPaths; break;
                default: break;
            }
        } else {
            ++stats.internalNodes;
        }
        
        // Segment statistics
        totalSegmentLength += node->segmentLength;
        if (node->segmentLength > stats.longestSegment) {
            stats.longestSegment = node->segmentLength;
        }
        
        // Child statistics
        totalChildCount += node->childCount;
        stats.emptyChildSlots += (PathTrieNode::MAX_CHILDREN - node->childCount);
        
        // Count deleted nodes (non-terminal with no children)
        if (!node->IsTerminal() && !node->HasChildren()) {
            ++stats.deletedNodes;
        }
        
        // Add children to queue
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            const uint32_t childOff = node->children[i];
            if (childOff != 0 && visited.find(childOff) == visited.end()) {
                if (IsValidNodeOffset(childOff, m_indexSize)) {
                    bfsQueue.push({childOff, depth + 1});
                    visited.insert(childOff);
                }
            }
        }
    }
    
    // Calculate derived metrics
    const uint64_t actualNodeCount = visited.size();
    
    if (actualNodeCount > 0) {
        stats.avgChildCount = static_cast<double>(totalChildCount) / static_cast<double>(actualNodeCount);
        stats.avgSegmentLength = static_cast<double>(totalSegmentLength) / static_cast<double>(actualNodeCount);
    }
    
    if (terminalCount > 0) {
        stats.avgDepth = static_cast<uint32_t>(totalDepth / terminalCount);
    }
    
    // Memory metrics
    constexpr uint64_t HEADER_SIZE = 64;
    const uint64_t nodeSize = sizeof(PathTrieNode);
    
    uint64_t usedNodeSpace = 0;
    if (!SafeMul(actualNodeCount, nodeSize, usedNodeSpace)) {
        usedNodeSpace = m_indexSize;
    }
    
    uint64_t usedSpace = 0;
    if (!SafeAdd(HEADER_SIZE, usedNodeSpace, usedSpace)) {
        usedSpace = m_indexSize;
    }
    
    stats.usedSize = usedSpace;
    stats.freeSpace = (usedSpace < m_indexSize) ? (m_indexSize - usedSpace) : 0;
    
    // Fragmentation ratio (deleted nodes / total nodes)
    if (actualNodeCount > 0) {
        stats.fragmentationRatio = static_cast<double>(stats.deletedNodes) / static_cast<double>(actualNodeCount);
    }
    
    // Determine if compaction is needed (>10% deleted nodes)
    stats.needsCompaction = (stats.fragmentationRatio > 0.10);
    
    // Check for orphaned nodes (allocated but not reachable)
    stats.orphanedNodes = static_cast<uint32_t>(
        stats.nodeCount > actualNodeCount ? (stats.nodeCount - actualNodeCount) : 0
    );
    
    // Integrity status
    stats.lastIntegrityCheckPassed = (stats.corruptedNodes == 0 && stats.orphanedNodes == 0);
    stats.lastIntegrityCheckTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    
    return stats;
}

// ============================================================================
// VERIFY INTEGRITY IMPLEMENTATION
// ============================================================================

PathIndexIntegrityResult PathIndex::VerifyIntegrity() const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE TRIE INTEGRITY VERIFICATION
     * ========================================================================
     *
     * Performs comprehensive integrity checks:
     * 1. Node offset validation (within bounds)
     * 2. Node structure validation (field ranges)
     * 3. Child pointer validation (no invalid offsets)
     * 4. Cycle detection (no loops in trie)
     * 5. Orphan detection (unreachable nodes)
     * 6. Counter consistency (path count vs terminal nodes)
     *
     * Thread-safety: Uses shared_lock for concurrent verification
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_rwLock);
    
    PathIndexIntegrityResult result;
    result.isValid = true;
    
    // Early return for uninitialized index
    if (!m_view && !m_baseAddress) {
        result.errorDetails = "Index not initialized";
        return result;
    }
    
    const uint64_t nodeCount = m_nodeCount.load(std::memory_order_acquire);
    const uint64_t pathCount = m_pathCount.load(std::memory_order_acquire);
    
    // Empty index is valid
    if (nodeCount == 0) {
        result.isValid = (pathCount == 0);
        if (!result.isValid) {
            result.errorDetails = "Path count non-zero but node count is zero";
        }
        return result;
    }
    
    // Get base pointer
    const uint8_t* base = nullptr;
    if (m_view) {
        base = static_cast<const uint8_t*>(m_view->baseAddress) + m_indexOffset;
    } else if (m_baseAddress) {
        base = static_cast<const uint8_t*>(m_baseAddress) + m_indexOffset;
    }
    
    if (!base) {
        result.isValid = false;
        result.errorDetails = "Invalid base pointer";
        return result;
    }
    
    // Validate root offset
    if (!IsValidNodeOffset(m_rootOffset, m_indexSize)) {
        result.isValid = false;
        result.errorDetails = "Invalid root offset: " + std::to_string(m_rootOffset);
        return result;
    }
    
    // BFS traversal for integrity verification
    std::queue<uint64_t> bfsQueue;
    std::unordered_set<uint64_t> visited;
    uint64_t terminalCount = 0;
    
    bfsQueue.push(m_rootOffset);
    visited.insert(m_rootOffset);
    
    constexpr size_t MAX_ITERATIONS = 10'000'000;
    size_t iterations = 0;
    
    while (!bfsQueue.empty() && iterations < MAX_ITERATIONS) {
        const uint64_t currentOffset = bfsQueue.front();
        bfsQueue.pop();
        ++iterations;
        ++result.nodesChecked;
        
        // Validate node offset (redundant but explicit)
        if (!IsValidNodeOffset(currentOffset, m_indexSize)) {
            ++result.invalidOffsets;
            result.isValid = false;
            continue;
        }
        
        const auto* node = reinterpret_cast<const PathTrieNode*>(base + currentOffset);
        
        // Validate node integrity
        if (!ValidateNodeIntegrity(node, m_indexSize)) {
            ++result.corruptedNodes;
            result.isValid = false;
            
            // Log specific corruption details
            if (node->segmentLength > PathTrieNode::MAX_SEGMENT_LENGTH) {
                result.errorDetails += "Node at " + std::to_string(currentOffset) + 
                    " has invalid segment length: " + std::to_string(node->segmentLength) + "; ";
            }
            if (node->childCount > PathTrieNode::MAX_CHILDREN) {
                result.errorDetails += "Node at " + std::to_string(currentOffset) + 
                    " has invalid child count: " + std::to_string(node->childCount) + "; ";
            }
            continue;
        }
        
        // Count terminals
        if (node->IsTerminal()) {
            ++terminalCount;
        }
        
        // Validate and traverse children
        for (uint32_t i = 0; i < PathTrieNode::MAX_CHILDREN; ++i) {
            const uint32_t childOff = node->children[i];
            if (childOff == 0) {
                continue;
            }
            
            // Check for invalid offset
            if (!IsValidNodeOffset(childOff, m_indexSize)) {
                ++result.invalidOffsets;
                result.isValid = false;
                result.errorDetails += "Invalid child offset " + std::to_string(childOff) + 
                    " at node " + std::to_string(currentOffset) + "; ";
                continue;
            }
            
            // Check for cycle
            if (visited.find(childOff) != visited.end()) {
                ++result.cycleDetected;
                result.isValid = false;
                result.errorDetails += "Cycle detected at offset " + std::to_string(childOff) + "; ";
                continue;
            }
            
            bfsQueue.push(childOff);
            visited.insert(childOff);
        }
    }
    
    // Check for orphaned nodes (allocated but not reachable)
    if (visited.size() < nodeCount) {
        result.orphanedNodes = static_cast<uint32_t>(nodeCount - visited.size());
        // Orphaned nodes are a warning, not necessarily invalid
        // They can occur after lazy deletion before compaction
    }
    
    // Verify path count matches terminal count
    if (terminalCount != pathCount) {
        result.isValid = false;
        result.errorDetails += "Path count mismatch: stored=" + std::to_string(pathCount) + 
            ", actual terminals=" + std::to_string(terminalCount) + "; ";
    }
    
    // Check for iteration limit exceeded
    if (iterations >= MAX_ITERATIONS) {
        result.isValid = false;
        result.errorDetails += "Max iteration limit exceeded - possible corruption; ";
    }
    
    // Final status message
    if (result.isValid && result.errorDetails.empty()) {
        result.errorDetails = "All integrity checks passed";
    }
    
    return result;
}

} // namespace ShadowStrike::Whitelist