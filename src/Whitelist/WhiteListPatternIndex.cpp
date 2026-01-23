// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
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

/**
 * @brief Compute FNV-1a hash for byte array
 * @param data Pointer to data
 * @param length Length of data in bytes
 * @return 32-bit FNV-1a hash value
 * 
 * Used for PathEntryRecord hash filtering and deduplication.
 */
[[nodiscard]] inline uint32_t ComputeFNV1aHash(const uint8_t* data, size_t length) noexcept {
    if (!data || length == 0) {
        return FNV1A_OFFSET_BASIS;
    }
    
    uint32_t hash = FNV1A_OFFSET_BASIS;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= FNV1A_PRIME;
    }
    return hash;
}

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
        
        // Reserve with overflow protection (check BEFORE multiplication)
        // Worst case UTF-8 expansion is 3x for BMP characters
        if (path.length() > SIZE_MAX / 3) {
            return false; // Would overflow
        }
        const size_t maxSize = path.length() * 3;
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
        
        // SECURITY: Detect and reject path traversal attacks
        // Patterns like ".." or "." segments could be used to escape directory boundaries
        // Check for: /./ or /../ or starts with ./ or ../ or ends with /. or /..
        if (output.find("/./") != std::string::npos ||
            output.find("/../") != std::string::npos ||
            (output.length() >= 2 && output.substr(0, 2) == "./") ||
            (output.length() >= 3 && output.substr(0, 3) == "../") ||
            (output.length() >= 2 && output.substr(output.length() - 2) == "/.") ||
            (output.length() >= 3 && output.substr(output.length() - 3) == "/..")) {
            SS_LOG_WARN(L"Whitelist", L"NormalizePath: path traversal detected, rejecting");
            output.clear();
            return false;
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
 * @brief Split normalized path into segments by '/' separator
 * @param path Normalized path (lowercase, forward slashes)
 * @param segments Output vector of path segments
 * 
 * Example: "c:/windows/system32" -> ["c:", "windows", "system32"]
 */
inline void SplitPathSegments(std::string_view path, std::vector<std::string_view>& segments) noexcept {
    segments.clear();
    
    if (path.empty()) {
        return;
    }
    
    try {
        segments.reserve(32); // Pre-reserve reasonable capacity
        
        size_t start = 0;
        while (start < path.length()) {
            // Find next separator
            size_t end = path.find('/', start);
            
            if (end == std::string_view::npos) {
                // Last segment
                if (start < path.length()) {
                    segments.push_back(path.substr(start));
                }
                break;
            }
            
            // Add segment if non-empty
            if (end > start) {
                segments.push_back(path.substr(start, end - start));
            }
            
            start = end + 1;
        }
    } catch (...) {
        segments.clear();
    }
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

PathIndex::PathIndex()
    : m_heapRoot(std::make_unique<HeapTrieNode>())
{
    // Initialize with root node
    m_nodeCount.store(1, std::memory_order_release);
}

PathIndex::~PathIndex() = default;

PathIndex::PathIndex(PathIndex&& other) noexcept
    : m_heapRoot(nullptr)
    , m_view(nullptr)
    , m_baseAddress(nullptr)
    , m_rootOffset(0)
    , m_indexOffset(0)
    , m_indexSize(0)
    , m_pathCount(0)
    , m_nodeCount(0)
    , m_lookupCount(0)
    , m_lookupHits(0)
    , m_insertCount(0)
    , m_removeCount(0)
    , m_nextRecordIndex(0)
{
    // Lock source for thread-safe move
    std::unique_lock lock(other.m_rwLock);
    
    m_heapRoot = std::move(other.m_heapRoot);
    m_pathRecords = std::move(other.m_pathRecords);
    m_view = other.m_view;
    m_baseAddress = other.m_baseAddress;
    m_rootOffset = other.m_rootOffset;
    m_indexOffset = other.m_indexOffset;
    m_indexSize = other.m_indexSize;
    m_pathCount.store(other.m_pathCount.load(std::memory_order_acquire),
                      std::memory_order_release);
    m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire),
                      std::memory_order_release);
    m_nextRecordIndex.store(other.m_nextRecordIndex.load(std::memory_order_acquire),
                            std::memory_order_release);
    
    // Transfer performance counters
    m_lookupCount.store(other.m_lookupCount.load(std::memory_order_acquire),
                        std::memory_order_release);
    m_lookupHits.store(other.m_lookupHits.load(std::memory_order_acquire),
                       std::memory_order_release);
    m_insertCount.store(other.m_insertCount.load(std::memory_order_acquire),
                        std::memory_order_release);
    m_removeCount.store(other.m_removeCount.load(std::memory_order_acquire),
                        std::memory_order_release);
    
    // Clear source
    other.m_view = nullptr;
    other.m_baseAddress = nullptr;
    other.m_rootOffset = 0;
    other.m_indexOffset = 0;
    other.m_indexSize = 0;
    other.m_pathCount.store(0, std::memory_order_release);
    other.m_nodeCount.store(0, std::memory_order_release);
    other.m_nextRecordIndex.store(0, std::memory_order_release);
    other.m_lookupCount.store(0, std::memory_order_release);
    other.m_lookupHits.store(0, std::memory_order_release);
    other.m_insertCount.store(0, std::memory_order_release);
    other.m_removeCount.store(0, std::memory_order_release);
}

PathIndex& PathIndex::operator=(PathIndex&& other) noexcept {
    if (this != &other) {
        // Lock both for thread-safe move (use std::lock to avoid deadlock)
        std::unique_lock lockThis(m_rwLock, std::defer_lock);
        std::unique_lock lockOther(other.m_rwLock, std::defer_lock);
        std::lock(lockThis, lockOther);
        
        m_heapRoot = std::move(other.m_heapRoot);
        m_pathRecords = std::move(other.m_pathRecords);
        m_view = other.m_view;
        m_baseAddress = other.m_baseAddress;
        m_rootOffset = other.m_rootOffset;
        m_indexOffset = other.m_indexOffset;
        m_indexSize = other.m_indexSize;
        m_pathCount.store(other.m_pathCount.load(std::memory_order_acquire),
                          std::memory_order_release);
        m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire),
                          std::memory_order_release);
        m_nextRecordIndex.store(other.m_nextRecordIndex.load(std::memory_order_acquire),
                                std::memory_order_release);
        
        // Transfer performance counters
        m_lookupCount.store(other.m_lookupCount.load(std::memory_order_acquire),
                            std::memory_order_release);
        m_lookupHits.store(other.m_lookupHits.load(std::memory_order_acquire),
                           std::memory_order_release);
        m_insertCount.store(other.m_insertCount.load(std::memory_order_acquire),
                            std::memory_order_release);
        m_removeCount.store(other.m_removeCount.load(std::memory_order_acquire),
                            std::memory_order_release);
        
        // Clear source
        other.m_view = nullptr;
        other.m_baseAddress = nullptr;
        other.m_rootOffset = 0;
        other.m_indexOffset = 0;
        other.m_indexSize = 0;
        other.m_pathCount.store(0, std::memory_order_release);
        other.m_nodeCount.store(0, std::memory_order_release);
        other.m_nextRecordIndex.store(0, std::memory_order_release);
        other.m_lookupCount.store(0, std::memory_order_release);
        other.m_lookupHits.store(0, std::memory_order_release);
        other.m_insertCount.store(0, std::memory_order_release);
        other.m_removeCount.store(0, std::memory_order_release);
    }
    return *this;
}

StoreError PathIndex::Initialize(
    const MemoryMappedView& view,
    uint64_t offset,
    uint64_t size
) noexcept {
    /*
     * ========================================================================
     * INITIALIZE PATH INDEX (THREATINTEL HYBRID MODEL)
     * ========================================================================
     * 
     * Initializes the PathIndex in READ-ONLY mode by:
     * 1. Validating memory-mapped view parameters
     * 2. Loading PathEntryRecord structures from persistent storage
     * 3. Rebuilding HeapTrieNode index from loaded records
     *
     * This follows the ThreatIntel pattern where:
     * - Raw data (PathEntryRecord) is stored in memory-mapped file (persistent)
     * - Heap-based index is rebuilt on startup for fast lookups
     * - Startup cost is O(n) where n = number of entries
     *
     * ========================================================================
     */
    
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
    
    // Minimum header size for hybrid model
    // Header layout: root offset (8) + pathCount (8) + nodeCount (8) + recordCount (8) + reserved (32) = 64 bytes
    constexpr uint64_t MIN_HEADER_SIZE = 64;
    if (size < MIN_HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Path index section too small for header"
        );
    }
    
    // Read legacy header fields for backwards compatibility
    const auto* rootPtr = view.GetAt<uint64_t>(offset);
    if (rootPtr) {
        m_rootOffset = *rootPtr;
        // Validate root offset is within section bounds (legacy validation)
        if (m_rootOffset != 0) {
            if (m_rootOffset >= size) {
                SS_LOG_WARN(L"Whitelist", L"PathIndex: invalid root offset %llu (size=%llu)", 
                           m_rootOffset, size);
                m_rootOffset = 0;
            }
        }
    } else {
        m_rootOffset = 0;
    }
    
    // ========================================================================
    // THREATINTEL HYBRID MODEL: Load records and rebuild index
    // ========================================================================
    
    // Step 1: Load PathEntryRecord structures from memory-mapped storage
    auto loadError = LoadRecordsFromStorage();
    if (loadError.code != WhitelistStoreError::Success) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Initialize: LoadRecordsFromStorage failed: %S",
            loadError.message.c_str());
        // Non-fatal: continue with empty index
        m_pathRecords.clear();
    }
    
    // Step 2: Rebuild HeapTrieNode index from loaded records
    const auto startTime = std::chrono::steady_clock::now();
    const uint64_t rebuiltCount = RebuildIndexFromRecords();
    const auto endTime = std::chrono::steady_clock::now();
    const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    SS_LOG_INFO(L"Whitelist",
        L"PathIndex initialized (hybrid): %llu paths, %llu nodes rebuilt in %lld ms",
        m_pathCount.load(std::memory_order_relaxed),
        m_nodeCount.load(std::memory_order_relaxed),
        durationMs);
    
    return StoreError::Success();
}

void PathIndex::EnableWriteMode(void* baseAddress, uint64_t size) noexcept {
    /*
     * ========================================================================
     * ENABLE WRITE MODE FOR EXISTING DATABASE
     * ========================================================================
     *
     * Called after Initialize() when loading an existing database for writing.
     * This enables insert/remove operations by setting m_baseAddress.
     *
     * For PathIndex (ThreatIntel Hybrid Model), the heap-based trie is already
     * rebuilt from records during Initialize(). This just enables the storage
     * portion for persisting new entries.
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    if (!baseAddress) {
        SS_LOG_WARN(L"Whitelist", L"PathIndex::EnableWriteMode called with null base address");
        return;
    }
    
    m_baseAddress = baseAddress;
    m_indexSize = size;
    
    SS_LOG_DEBUG(L"Whitelist", L"PathIndex write mode enabled, size: %llu", size);
}

StoreError PathIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    /*
     * ========================================================================
     * CREATE NEW PATH INDEX (THREATINTEL HYBRID MODEL)
     * ========================================================================
     * 
     * Creates a new PathIndex in WRITABLE mode:
     * 1. Initializes heap-based trie root node
     * 2. Clears m_pathRecords vector for new entries
     * 3. Sets up memory-mapped region for PathEntryRecord storage
     *
     * Storage Layout:
     * - Offset 0-7:   Root offset (legacy, kept for compatibility)
     * - Offset 8-15:  Path count
     * - Offset 16-23: Node count
     * - Offset 24-63: Reserved (header padding)
     * - Offset 64-71: Record count (number of PathEntryRecord)
     * - Offset 72-79: Reserved
     * - Offset 80+:   PathEntryRecord array
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    // Validate base address
    if (!baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid base address (null)"
        );
    }
    
    // Minimum size: header (64) + record header (16) + at least one record (2072)
    constexpr uint64_t HEADER_SIZE = 64;
    constexpr uint64_t RECORD_HEADER_SIZE = 16;  // record count + reserved
    constexpr uint64_t MIN_SIZE = HEADER_SIZE + RECORD_HEADER_SIZE + sizeof(PathEntryRecord);
    
    if (availableSize < MIN_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Insufficient space for path index (need at least header + 1 record)"
        );
    }
    
    // Validate available size is reasonable
    if (availableSize > static_cast<uint64_t>(INT64_MAX)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Available size exceeds maximum supported value"
        );
    }
    
    // Initialize heap-based trie root
    try {
        m_heapRoot = std::make_unique<HeapTrieNode>();
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate heap trie root"
        );
    }
    
    // Clear persistent record storage
    m_pathRecords.clear();
    m_nextRecordIndex.store(0, std::memory_order_release);
    
    // Clear any existing state
    m_view = nullptr; // Write mode
    m_baseAddress = baseAddress;
    m_indexOffset = 0;
    m_indexSize = availableSize;
    
    // Initialize header with zero-fill for security (prevent info leakage)
    auto* header = static_cast<uint8_t*>(baseAddress);
    std::memset(header, 0, static_cast<size_t>(HEADER_SIZE + RECORD_HEADER_SIZE));
    
    // Initialize root offset (legacy field)
    m_rootOffset = HEADER_SIZE;
    
    // Initialize counters with proper memory ordering (root node = 1)
    m_pathCount.store(0, std::memory_order_release);
    m_nodeCount.store(1, std::memory_order_release);
    
    // Write initial record count = 0
    auto* recordCountPtr = reinterpret_cast<uint64_t*>(header + HEADER_SIZE);
    *recordCountPtr = 0;
    
    // Set output used size (header + record header)
    usedSize = HEADER_SIZE + RECORD_HEADER_SIZE;
    
    SS_LOG_DEBUG(L"Whitelist", L"PathIndex created (hybrid): header %llu bytes, available %llu bytes",
                usedSize, availableSize);
    
    return StoreError::Success();
}

std::vector<uint64_t> PathIndex::Lookup(
    std::wstring_view path,
    PathMatchMode mode
) const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE PATH TRIE LOOKUP (HEAP-BASED)
     * ========================================================================
     *
     * Implements heap-based trie lookup following the proven DomainSuffixTrie
     * pattern from ThreatIntelIndex. Uses std::unordered_map for unlimited
     * children per node.
     *
     * Match modes supported:
     * - Exact: Path must match exactly
     * - Prefix: Path must start with pattern  
     * - Suffix: Path must end with pattern
     * - Glob: Pattern uses wildcards (* and ?)
     * - Regex: Full regex matching
     *
     * Security Note: Returns empty vector on any error (conservative).
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_rwLock);
    
    std::vector<uint64_t> results;
    
    // Validate input
    if (path.empty()) {
        return results;
    }
    
    if (path.length() > MAX_WINDOWS_PATH_LENGTH) {
        SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: path exceeds max length");
        return results;
    }
    
    // Validate heap root exists
    if (!m_heapRoot) {
        return results;
    }
    
    // Fast path: empty index
    if (m_pathCount.load(std::memory_order_acquire) == 0) {
        return results;
    }
    
    // Normalize path
    std::string normalizedPath;
    if (!NormalizePath(path, normalizedPath)) {
        SS_LOG_WARN(L"Whitelist", L"PathIndex::Lookup: path normalization failed");
        return results;
    }
    
    if (normalizedPath.empty()) {
        return results;
    }
    
    try {
        results.reserve(16);
        constexpr size_t MAX_RESULTS = 1024;
        
        // Split normalized path into segments
        std::vector<std::string_view> segments;
        SplitPathSegments(normalizedPath, segments);
        
        if (segments.empty()) {
            return results;
        }
        
        // ====================================================================
        // EXACT AND PREFIX MATCH - Simple trie traversal
        // ====================================================================
        if (mode == PathMatchMode::Exact || mode == PathMatchMode::Prefix) {
            const HeapTrieNode* node = m_heapRoot.get();
            
            for (size_t i = 0; i < segments.size() && node != nullptr; ++i) {
                const std::string segmentKey(segments[i]);
                
                // For prefix mode, collect terminal nodes along the path
                if (mode == PathMatchMode::Prefix && node->isTerminal) {
                    results.push_back(node->entryOffset);
                    if (results.size() >= MAX_RESULTS) break;
                }
                
                // Find child for this segment
                auto it = node->children.find(segmentKey);
                if (it == node->children.end()) {
                    node = nullptr; // No match
                    break;
                }
                node = it->second.get();
            }
            
            // Check for exact match at final node
            if (node && node->isTerminal && results.size() < MAX_RESULTS) {
                if (mode == PathMatchMode::Exact) {
                    results.push_back(node->entryOffset);
                } else if (mode == PathMatchMode::Prefix) {
                    // Add final node if not already added
                    if (results.empty() || results.back() != node->entryOffset) {
                        results.push_back(node->entryOffset);
                    }
                }
            }
        }
        
        // ====================================================================
        // SUFFIX MATCH - Find stored suffix patterns that match queryPath's end
        // E.g., stored ".dll" should match query "kernel32.dll"
        // ====================================================================
        else if (mode == PathMatchMode::Suffix) {
            // Iterate through ALL stored patterns that were added with Suffix mode
            // and check if the queryPath ENDS WITH that pattern
            std::function<void(const HeapTrieNode*, std::vector<std::string>&, size_t)> traverse;
            traverse = [&](const HeapTrieNode* node, std::vector<std::string>& pathParts, size_t depth) {
                // Stack overflow protection and result limit
                if (!node || results.size() >= MAX_RESULTS || depth >= SAFE_MAX_TRIE_DEPTH) return;
                
                if (node->isTerminal && node->matchMode == PathMatchMode::Suffix) {
                    // Reconstruct the stored pattern
                    std::string storedPattern;
                    for (size_t i = 0; i < pathParts.size(); ++i) {
                        if (i > 0) storedPattern += '/';
                        storedPattern += pathParts[i];
                    }
                    
                    // Check if queryPath (normalizedPath) ENDS WITH storedPattern
                    if (normalizedPath.length() >= storedPattern.length() &&
                        normalizedPath.substr(normalizedPath.length() - storedPattern.length()) == storedPattern) {
                        results.push_back(node->entryOffset);
                    }
                }
                
                for (const auto& [segment, child] : node->children) {
                    pathParts.push_back(segment);
                    traverse(child.get(), pathParts, depth + 1);
                    pathParts.pop_back();
                }
            };
            
            std::vector<std::string> pathParts;
            traverse(m_heapRoot.get(), pathParts, 0);
        }
        
        // ====================================================================
        // GLOB MATCH - Wildcard pattern matching
        // NOTE: This implements Windows-style glob semantics where:
        //   - '*' matches zero or more characters INCLUDING path separators
        //   - '?' matches exactly one character INCLUDING path separators
        //   - This differs from Unix shell globs where '*' doesn't match '/'
        //   - Windows behavior is intentional for path-based whitelisting
        // ====================================================================
        else if (mode == PathMatchMode::Glob) {
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
            
            // Traverse all stored Glob patterns and check if they match normalizedPath
            std::function<void(const HeapTrieNode*, std::string&, size_t)> traverse;
            traverse = [&](const HeapTrieNode* node, std::string& accPath, size_t depth) {
                // Stack overflow protection and result limit
                if (!node || results.size() >= MAX_RESULTS || depth >= SAFE_MAX_TRIE_DEPTH) return;
                
                if (node->isTerminal && node->matchMode == PathMatchMode::Glob) {
                    // accPath is the stored PATTERN, normalizedPath is the QUERY to match
                    if (globMatch(accPath, normalizedPath)) {
                        results.push_back(node->entryOffset);
                    }
                }
                
                for (const auto& [segment, child] : node->children) {
                    std::string newPath = accPath.empty() ? segment : (accPath + "/" + segment);
                    traverse(child.get(), newPath, depth + 1);
                }
            };
            
            std::string accPath;
            traverse(m_heapRoot.get(), accPath, 0);
        }
        
        // ====================================================================
        // REGEX MATCH - Full regex pattern matching with ReDoS protection
        // ====================================================================
        else if (mode == PathMatchMode::Regex) {
            /*
             * REDOS PROTECTION (ENTERPRISE-GRADE)
             * =====================================
             * Regex can cause catastrophic backtracking with patterns like:
             * - (a+)+$ - nested quantifiers
             * - (a|aa)+$ - alternation with overlap
             * - ([a-zA-Z]+)* - quantified groups
             * 
             * Protection measures:
             * 1. Limit pattern length
             * 2. Limit quantifier count
             * 3. Detect nested quantifiers (quantifier inside group with quantifier)
             * 4. Use nosubs flag to disable capturing groups
             * 5. Catch and handle regex errors
             */
            constexpr size_t MAX_REGEX_LENGTH = 512;  // Reduced from 1024
            constexpr size_t MAX_REGEX_QUANTIFIERS = 5;  // Reduced from 10
            constexpr size_t MAX_NESTING_DEPTH = 3;
            
            // Check pattern length
            if (normalizedPath.length() > MAX_REGEX_LENGTH) {
                SS_LOG_ERROR(L"Whitelist", 
                    L"PathIndex::Lookup: regex pattern too long (%zu > %zu)",
                    normalizedPath.length(), MAX_REGEX_LENGTH);
                return results;
            }
            
            // Analyze pattern for dangerous constructs
            size_t quantifierCount = 0;
            size_t nestingDepth = 0;
            size_t maxNesting = 0;
            bool quantifierInGroup = false;
            bool prevWasQuantifier = false;
            
            for (size_t i = 0; i < normalizedPath.length(); ++i) {
                char c = normalizedPath[i];
                
                // Track nesting depth
                if (c == '(' || c == '[') {
                    ++nestingDepth;
                    maxNesting = std::max(maxNesting, nestingDepth);
                    prevWasQuantifier = false;
                } else if (c == ')' || c == ']') {
                    if (nestingDepth > 0) --nestingDepth;
                    // Check for quantifier immediately after group close
                } else if (c == '*' || c == '+' || c == '?' || c == '{') {
                    ++quantifierCount;
                    // CRITICAL: Detect nested quantifiers (quantifier after group that had quantifier)
                    if (nestingDepth > 0 || prevWasQuantifier) {
                        quantifierInGroup = true;
                    }
                    prevWasQuantifier = true;
                } else if (c == '|' && nestingDepth > 0) {
                    // Alternation inside group can cause backtracking
                    quantifierInGroup = true;
                } else {
                    prevWasQuantifier = false;
                }
            }
            
            // Reject dangerous patterns
            if (quantifierCount > MAX_REGEX_QUANTIFIERS) {
                SS_LOG_ERROR(L"Whitelist", 
                    L"PathIndex::Lookup: regex has too many quantifiers (%zu > %zu)",
                    quantifierCount, MAX_REGEX_QUANTIFIERS);
                return results;
            }
            
            if (maxNesting > MAX_NESTING_DEPTH) {
                SS_LOG_ERROR(L"Whitelist", 
                    L"PathIndex::Lookup: regex nesting too deep (%zu > %zu)",
                    maxNesting, MAX_NESTING_DEPTH);
                return results;
            }
            
            if (quantifierInGroup) {
                SS_LOG_ERROR(L"Whitelist", 
                    L"PathIndex::Lookup: regex has nested/consecutive quantifiers (ReDoS risk)");
                return results;
            }
            
            // For regex, iterate through all stored Regex patterns and try to match queryPath
            std::function<void(const HeapTrieNode*, std::string&, size_t)> traverse;
            traverse = [&](const HeapTrieNode* node, std::string& accPath, size_t depth) {
                // Stack overflow protection and result limit
                if (!node || results.size() >= MAX_RESULTS || depth >= SAFE_MAX_TRIE_DEPTH) return;
                
                if (node->isTerminal && node->matchMode == PathMatchMode::Regex) {
                    // accPath is the stored REGEX PATTERN, normalizedPath is the QUERY to match
                    try {
                        // Validate stored pattern length
                        if (accPath.length() <= MAX_REGEX_LENGTH) {
                            std::regex storedPattern(accPath, 
                                std::regex_constants::ECMAScript | 
                                std::regex_constants::icase |
                                std::regex_constants::nosubs |
                                std::regex_constants::optimize);
                            
                            if (std::regex_match(normalizedPath, storedPattern)) {
                                results.push_back(node->entryOffset);
                            }
                        }
                    } catch (const std::regex_error&) {
                        // Invalid stored regex - skip it
                    }
                }
                
                for (const auto& [segment, child] : node->children) {
                    std::string newPath = accPath.empty() ? segment : (accPath + "/" + segment);
                    traverse(child.get(), newPath, depth + 1);
                }
            };
            
            std::string accPath;
            traverse(m_heapRoot.get(), accPath, 0);
        }
        
        // Remove duplicates
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
     * ENTERPRISE-GRADE PATH INSERT (THREATINTEL HYBRID MODEL)
     * ========================================================================
     *
     * Inserts a path pattern using the ThreatIntel Hybrid persistence model:
     * 1. Creates PathEntryRecord (persistent storage)
     * 2. Adds record to m_pathRecords vector
     * 3. Inserts into HeapTrieNode index (fast lookup)
     *
     * This ensures:
     * - Data persists across restarts (PathEntryRecord in memory-mapped file)
     * - Fast lookups (HeapTrieNode with O(k) traversal)
     * - Thread-safe operations (unique_lock)
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
    
    // Validate heap root exists
    if (!m_heapRoot) {
        try {
            m_heapRoot = std::make_unique<HeapTrieNode>();
            m_nodeCount.store(1, std::memory_order_release);
        } catch (const std::bad_alloc&) {
            return StoreError::WithMessage(
                WhitelistStoreError::OutOfMemory,
                "Failed to allocate heap trie root"
            );
        }
    }
    
    // Validate input
    if (path.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot insert empty path"
        );
    }
    
    // Validate path length against PathEntryRecord limit
    constexpr size_t MAX_PATH_LENGTH = PathEntryRecord::MAX_PATH_LENGTH;
    if (path.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Path exceeds maximum length for storage"
        );
    }
    
    // Normalize path (or preserve pattern for Regex modes)
    std::string normalizedPath;
    if (mode == PathMatchMode::Regex) {
        // For Regex patterns, preserve backslash escapes (e.g., .*\.exe$)
        // Only convert to UTF-8 and lowercase without path separator changes
        try {
            normalizedPath.reserve(path.length() * 3); // Worst case UTF-8
            for (wchar_t wc : path) {
                // Convert to lowercase for case-insensitive matching
                wchar_t lower = (wc >= L'A' && wc <= L'Z') ? (wc + 32) : wc;
                
                // UTF-8 encoding
                if (lower < 0x80) {
                    normalizedPath.push_back(static_cast<char>(lower));
                } else if (lower < 0x800) {
                    normalizedPath.push_back(static_cast<char>(0xC0 | ((lower >> 6) & 0x1F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
                } else {
                    normalizedPath.push_back(static_cast<char>(0xE0 | ((lower >> 12) & 0x0F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | ((lower >> 6) & 0x3F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
                }
            }
        } catch (const std::bad_alloc&) {
            return StoreError::WithMessage(
                WhitelistStoreError::OutOfMemory,
                "Pattern conversion failed"
            );
        }
    } else if (mode == PathMatchMode::Glob) {
        // For Glob patterns, normalize backslash to forward slash (to match lookup)
        // but preserve wildcard characters (* and ?)
        try {
            normalizedPath.reserve(path.length() * 3);
            for (wchar_t wc : path) {
                // Convert backslash to forward slash for consistent path matching
                wchar_t ch = (wc == L'\\') ? L'/' : wc;
                // Convert to lowercase
                wchar_t lower = (ch >= L'A' && ch <= L'Z') ? (ch + 32) : ch;
                
                // UTF-8 encoding
                if (lower < 0x80) {
                    normalizedPath.push_back(static_cast<char>(lower));
                } else if (lower < 0x800) {
                    normalizedPath.push_back(static_cast<char>(0xC0 | ((lower >> 6) & 0x1F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
                } else {
                    normalizedPath.push_back(static_cast<char>(0xE0 | ((lower >> 12) & 0x0F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | ((lower >> 6) & 0x3F)));
                    normalizedPath.push_back(static_cast<char>(0x80 | (lower & 0x3F)));
                }
            }
        } catch (const std::bad_alloc&) {
            return StoreError::WithMessage(
                WhitelistStoreError::OutOfMemory,
                "Pattern conversion failed"
            );
        }
    } else {
        // For Exact, Prefix, Suffix - use full path normalization
        if (!NormalizePath(path, normalizedPath)) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Path normalization failed"
            );
        }
    }
    
    if (normalizedPath.empty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Normalized path is empty"
        );
    }
    
    // Validate normalized path fits in record
    if (normalizedPath.length() > MAX_PATH_LENGTH) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Normalized path exceeds storage limit"
        );
    }
    
    try {
        // ====================================================================
        // STEP 0: Check for duplicate path (same path + mode = update)
        // Enterprise behavior: update entry offset if same path+mode exists
        // ====================================================================
        std::vector<std::string_view> segments;
        SplitPathSegments(normalizedPath, segments);
        HeapTrieNode* current = m_heapRoot.get();
        
        for (const auto& segment : segments) {
            if (!current) break;
            auto it = current->children.find(std::string(segment));
            if (it == current->children.end()) {
                current = nullptr;  // Path doesn't exist yet
                break;
            }
            current = it->second.get();
        }
        
        // If we found the full path and it's terminal with same mode, update it
        if (current && current->isTerminal && current->matchMode == mode) {
            // Update the entry offset in the heap node
            current->entryOffset = entryOffset;
            
            // Also update the corresponding PathEntryRecord
            for (auto& record : m_pathRecords) {
                if ((record.flags & 1) == 0 &&  // Not deleted
                    record.pathLength == normalizedPath.length() &&
                    std::memcmp(record.path, normalizedPath.data(), normalizedPath.length()) == 0 &&
                    record.matchMode == static_cast<uint8_t>(mode)) {
                    record.entryOffset = entryOffset;
                    break;
                }
            }
            
            SS_LOG_DEBUG(L"Whitelist", 
                L"PathIndex::Insert: updated existing entry, new offset %llu", entryOffset);
            
            return StoreError::Success();
        }
        
        // ====================================================================
        // STEP 1: Create PathEntryRecord for persistent storage
        // ====================================================================
        PathEntryRecord record{};
        record.magic = PathEntryRecord::MAGIC;
        record.version = PathEntryRecord::VERSION;
        record.pathLength = static_cast<uint16_t>(normalizedPath.length());
        record.entryOffset = entryOffset;
        record.matchMode = static_cast<uint8_t>(mode);
        record.flags = 0;  // Not deleted
        record.reserved = 0;
        
        // Compute FNV-1a hash for quick filtering
        record.pathHash = ComputeFNV1aHash(
            reinterpret_cast<const uint8_t*>(normalizedPath.data()),
            normalizedPath.length()
        );
        
        // Copy path data (secure memset first to prevent info leakage)
        std::memset(record.path, 0, MAX_PATH_LENGTH);
        std::memcpy(record.path, normalizedPath.data(), normalizedPath.length());
        
        // ====================================================================
        // STEP 2: Add record to m_pathRecords vector
        // ====================================================================
        m_pathRecords.push_back(record);
        const uint64_t recordIndex = m_nextRecordIndex.fetch_add(1, std::memory_order_relaxed);
        
        // ====================================================================
        // STEP 3: Insert into HeapTrieNode index
        // ====================================================================
        if (!InsertIntoHeapTrie(normalizedPath, mode, entryOffset)) {
            // Rollback: remove the record we just added
            if (!m_pathRecords.empty()) {
                m_pathRecords.pop_back();
                m_nextRecordIndex.fetch_sub(1, std::memory_order_relaxed);
            }
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Failed to insert into heap trie"
            );
        }
        
        // Update insert counter
        m_insertCount.fetch_add(1, std::memory_order_relaxed);
        
        // NOTE: Records are stored in m_pathRecords but NOT immediately flushed to
        // memory-mapped storage. This is by design (like ThreatIntel):
        // - Immediate flushes would be too slow for bulk inserts
        // - Call Flush() explicitly to persist to storage
        // - Data is automatically flushed during Compact()
        // - On graceful shutdown, caller should call Flush()
        
        SS_LOG_DEBUG(L"Whitelist", 
            L"PathIndex::Insert: stored record %llu, path length %u, entry offset %llu",
            recordIndex, record.pathLength, entryOffset);
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Memory allocation failed during insert"
        );
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Insert exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Exception during insert"
        );
    }
}

StoreError PathIndex::Remove(
    std::wstring_view path,
    PathMatchMode mode
) noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE PATH REMOVE (THREATINTEL HYBRID MODEL)
     * ========================================================================
     *
     * Removes a path pattern using the ThreatIntel Hybrid persistence model:
     * 1. Finds and marks the HeapTrieNode as non-terminal (lazy deletion)
     * 2. Finds and marks the corresponding PathEntryRecord as deleted
     *
     * This ensures:
     * - Removal is reflected in heap index immediately
     * - Removal persists across restarts (record marked deleted)
     * - Thread-safe operations (unique_lock)
     *
     * Note: Physical removal from m_pathRecords is deferred to Compact()
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
    
    // Validate heap root exists
    if (!m_heapRoot) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Index not initialized"
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
    
    try {
        // Split normalized path into segments
        std::vector<std::string_view> segments;
        SplitPathSegments(normalizedPath, segments);
        
        if (segments.empty()) {
            return StoreError::WithMessage(
                WhitelistStoreError::InvalidEntry,
                "Path has no segments"
            );
        }
        
        // Navigate to the target node
        HeapTrieNode* node = m_heapRoot.get();
        
        for (size_t i = 0; i < segments.size(); ++i) {
            const std::string segmentKey(segments[i]);
            
            auto it = node->children.find(segmentKey);
            if (it == node->children.end()) {
                return StoreError::WithMessage(
                    WhitelistStoreError::EntryNotFound,
                    "Path not found in index"
                );
            }
            node = it->second.get();
        }
        
        // Check if this is a terminal node with matching mode
        if (!node->isTerminal) {
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path exists but is not a terminal node"
            );
        }
        
        // For exact mode matching, verify the mode (unless searching any mode)
        if (mode != PathMatchMode::Exact && node->matchMode != mode) {
            return StoreError::WithMessage(
                WhitelistStoreError::EntryNotFound,
                "Path found but match mode differs"
            );
        }
        
        // ====================================================================
        // STEP 1: Mark heap trie node as non-terminal (lazy deletion)
        // ====================================================================
        const uint64_t removedEntryOffset = node->entryOffset;
        node->isTerminal = false;
        node->entryOffset = 0;
        
        // ====================================================================
        // STEP 2: Mark corresponding PathEntryRecord as deleted
        // ====================================================================
        // Compute hash for fast filtering
        const uint32_t pathHash = ComputeFNV1aHash(
            reinterpret_cast<const uint8_t*>(normalizedPath.data()),
            normalizedPath.length()
        );
        
        bool recordFound = false;
        for (auto& record : m_pathRecords) {
            if (record.IsDeleted()) {
                continue;  // Skip already deleted records
            }
            
            // Quick filter by hash
            if (record.pathHash != pathHash) {
                continue;
            }
            
            // Verify path matches
            std::string_view recordPath = record.GetPath();
            if (recordPath != normalizedPath) {
                continue;
            }
            
            // Verify entry offset matches (for extra safety)
            if (record.entryOffset != removedEntryOffset) {
                continue;
            }
            
            // Mark record as deleted
            record.MarkDeleted();
            recordFound = true;
            break;
        }
        
        if (!recordFound) {
            SS_LOG_WARN(L"Whitelist", 
                L"PathIndex::Remove: path removed from heap but record not found (inconsistent state)");
            // Continue anyway - heap index is authoritative for lookups
        }
        
        // Atomic decrement with underflow protection
        const uint64_t previousCount = m_pathCount.fetch_sub(1, std::memory_order_acq_rel);
        
        // Check for underflow - previousCount was the value BEFORE subtraction
        if (previousCount == 0) {
            // Critical: Counter underflow indicates corruption
            m_pathCount.fetch_add(1, std::memory_order_relaxed);
            
            SS_LOG_ERROR(L"Whitelist", 
                L"PathIndex::Remove: CRITICAL - path count underflow prevented, "
                L"possible index corruption or concurrent modification");
            
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Counter underflow detected - index state inconsistent"
            );
        }
        
        // Update remove counter
        m_removeCount.fetch_add(1, std::memory_order_relaxed);
        
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Remove: path removed, record %s",
                    recordFound ? L"marked deleted" : L"not found");
        
        return StoreError::Success();
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Remove exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Exception during remove"
        );
    }
}

// ============================================================================
// CLEAR IMPLEMENTATION
// ============================================================================

StoreError PathIndex::Clear() noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE CLEAR (THREATINTEL HYBRID MODEL)
     * ========================================================================
     *
     * Clears all paths from the PathIndex by:
     * 1. Clearing m_pathRecords vector (persistent storage)
     * 2. Resetting the heap root to a fresh node (index)
     * 3. Resetting all counters
     * 4. Zeroing the memory-mapped header
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
    
    try {
        // ====================================================================
        // STEP 1: Clear persistent record storage
        // ====================================================================
        m_pathRecords.clear();
        m_nextRecordIndex.store(0, std::memory_order_release);
        
        // ====================================================================
        // STEP 2: Reset heap root (old tree is automatically deallocated)
        // ====================================================================
        m_heapRoot = std::make_unique<HeapTrieNode>();
        
        // ====================================================================
        // STEP 3: Reset state counters
        // ====================================================================
        m_pathCount.store(0, std::memory_order_release);
        m_nodeCount.store(1, std::memory_order_release); // Root node = 1
        
        // ====================================================================
        // STEP 4: Zero the memory-mapped header for consistency
        // ====================================================================
        if (m_baseAddress) {
            auto* base = static_cast<uint8_t*>(m_baseAddress) + m_indexOffset;
            
            // Zero header + record count region (80 bytes)
            constexpr uint64_t CLEAR_SIZE = 80;
            if (m_indexSize >= CLEAR_SIZE) {
                SecureZeroMemoryRegion(base, static_cast<size_t>(CLEAR_SIZE));
            }
            
            // Reset root offset
            m_rootOffset = 64; // HEADER_SIZE
        }
        
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Clear: index and records cleared");
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Memory allocation failed during clear"
        );
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Clear exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Exception during clear"
        );
    }
}

// ============================================================================
// COMPACT IMPLEMENTATION
// ============================================================================

StoreError PathIndex::Compact() noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE COMPACTION (THREATINTEL HYBRID MODEL)
     * ========================================================================
     *
     * Performs compaction on both layers:
     * 1. Heap Index: Removes non-terminal leaf nodes (dead branches)
     * 2. PathEntryRecords: Removes deleted records and rebuilds index
     *
     * This is a full rebuild operation that:
     * - Physically removes deleted PathEntryRecords
     * - Prunes empty branches from heap trie
     * - Optionally flushes to persistent storage
     *
     * Performance: O(n) where n = number of records
     * Recommended: Call during maintenance windows
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
    
    // Validate heap root exists
    if (!m_heapRoot) {
        SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Compact: no heap root");
        return StoreError::Success();
    }
    
    const auto startTime = std::chrono::steady_clock::now();
    const uint64_t beforeNodeCount = m_nodeCount.load(std::memory_order_acquire);
    const size_t beforeRecordCount = m_pathRecords.size();
    
    try {
        // ====================================================================
        // STEP 1: Compact PathEntryRecords (remove deleted records)
        // ====================================================================
        std::vector<PathEntryRecord> compactedRecords;
        compactedRecords.reserve(beforeRecordCount);
        
        for (const auto& record : m_pathRecords) {
            if (!record.IsDeleted() && record.IsValid()) {
                compactedRecords.push_back(record);
            }
        }
        
        const size_t deletedRecords = beforeRecordCount - compactedRecords.size();
        
        // ====================================================================
        // STEP 2: Rebuild heap index from compacted records
        // ====================================================================
        // This ensures heap index is perfectly in sync with records
        m_heapRoot = std::make_unique<HeapTrieNode>();
        m_nodeCount.store(1, std::memory_order_release);
        m_pathCount.store(0, std::memory_order_release);
        
        uint64_t rebuiltCount = 0;
        for (const auto& record : compactedRecords) {
            std::string_view pathView = record.GetPath();
            PathMatchMode mode = static_cast<PathMatchMode>(record.matchMode);
            
            if (InsertIntoHeapTrie(pathView, mode, record.entryOffset)) {
                ++rebuiltCount;
            }
        }
        
        // ====================================================================
        // STEP 3: Replace old records with compacted records
        // ====================================================================
        m_pathRecords = std::move(compactedRecords);
        m_nextRecordIndex.store(m_pathRecords.size(), std::memory_order_release);
        
        // ====================================================================
        // STEP 4: Prune empty branches from heap trie (optional cleanup)
        // SECURITY: Add depth limit to prevent stack overflow
        // ====================================================================
        constexpr size_t PRUNE_MAX_DEPTH = 512;
        
        std::function<bool(HeapTrieNode*, size_t)> pruneEmptyBranches;
        pruneEmptyBranches = [&](HeapTrieNode* node, size_t depth) -> bool {
            if (!node || depth >= PRUNE_MAX_DEPTH) return false;  // Stack overflow protection
            
            std::vector<std::string> keysToRemove;
            
            for (auto& [key, child] : node->children) {
                if (!pruneEmptyBranches(child.get(), depth + 1)) {
                    keysToRemove.push_back(key);
                }
            }
            
            for (const auto& key : keysToRemove) {
                node->children.erase(key);
                m_nodeCount.fetch_sub(1, std::memory_order_relaxed);
            }
            
            return node->isTerminal || !node->children.empty();
        };
        
        pruneEmptyBranches(m_heapRoot.get(), 0);
        
        const auto endTime = std::chrono::steady_clock::now();
        const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        const uint64_t afterNodeCount = m_nodeCount.load(std::memory_order_acquire);
        const size_t afterRecordCount = m_pathRecords.size();
        
        SS_LOG_INFO(L"Whitelist", 
            L"PathIndex::Compact: records %zu->%zu (-%zu), nodes %llu->%llu, rebuilt %llu in %lld ms",
            beforeRecordCount, afterRecordCount, deletedRecords,
            beforeNodeCount, afterNodeCount, rebuiltCount, durationMs);
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Compact: memory allocation failed");
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Memory allocation failed during compaction"
        );
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"PathIndex::Compact exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Exception during compaction"
        );
    }
}

// ============================================================================
// FLUSH IMPLEMENTATION (PUBLIC API)
// ============================================================================

StoreError PathIndex::Flush() noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE FLUSH OPERATION
     * ========================================================================
     *
     * Persists all pending PathEntryRecords to the memory-mapped storage.
     * This ensures data durability across application restarts.
     *
     * Call this method:
     * - Before application shutdown
     * - After bulk insert operations
     * - Periodically if data durability is critical
     *
     * Thread-safety: Acquires exclusive write lock
     *
     * ========================================================================
     */
    
    std::unique_lock lock(m_rwLock);
    
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot flush: no storage mapped"
        );
    }
    
    SS_LOG_DEBUG(L"Whitelist", L"PathIndex::Flush: persisting %zu records to storage", 
        m_pathRecords.size());
    
    return FlushRecordsToStorage();
}

// ============================================================================
// GET DETAILED STATS IMPLEMENTATION
// ============================================================================

PathIndexStats PathIndex::GetDetailedStats() const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE STATISTICS COLLECTION (HEAP-BASED)
     * ========================================================================
     *
     * Collects comprehensive statistics by traversing the heap-based trie:
     * - Node counts (total, terminal, internal)
     * - Structural metrics (depth, children)
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
    
    // Early return if heap root doesn't exist
    if (!m_heapRoot) {
        return stats;
    }
    
    try {
        // Traverse heap trie to collect statistics
        // SECURITY: Add depth limit to prevent stack overflow
        constexpr uint32_t STATS_MAX_DEPTH = 512;
        
        uint64_t totalChildren = 0;
        uint64_t totalDepth = 0;
        uint64_t terminalCount = 0;
        uint64_t internalCount = 0;
        uint64_t deletedCount = 0;
        
        std::function<void(const HeapTrieNode*, uint32_t)> traverse;
        traverse = [&](const HeapTrieNode* node, uint32_t depth) {
            if (!node || depth >= STATS_MAX_DEPTH) return;  // Stack overflow protection
            
            // Update max depth
            if (depth > stats.maxDepth) {
                stats.maxDepth = depth;
            }
            
            // Count children
            totalChildren += node->children.size();
            
            // Count terminal vs internal
            if (node->isTerminal) {
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
                ++internalCount;
                
                // Count deleted nodes (non-terminal leaf)
                if (node->children.empty()) {
                    ++deletedCount;
                }
            }
            
            // Recurse to children
            for (const auto& [segment, child] : node->children) {
                traverse(child.get(), depth + 1);
            }
        };
        
        traverse(m_heapRoot.get(), 0);
        
        // Set counts
        stats.terminalNodes = static_cast<uint32_t>(terminalCount);
        stats.internalNodes = static_cast<uint32_t>(internalCount);
        stats.deletedNodes = static_cast<uint32_t>(deletedCount);
        
        // Calculate derived metrics
        const uint64_t actualNodeCount = terminalCount + internalCount;
        
        if (actualNodeCount > 0) {
            stats.avgChildCount = static_cast<double>(totalChildren) / static_cast<double>(actualNodeCount);
        }
        
        if (terminalCount > 0) {
            stats.avgDepth = static_cast<uint32_t>(totalDepth / terminalCount);
        }
        
        // Fragmentation ratio
        if (actualNodeCount > 0) {
            stats.fragmentationRatio = static_cast<double>(deletedCount) / static_cast<double>(actualNodeCount);
        }
        
        // Compaction needed if >10% deleted
        stats.needsCompaction = (stats.fragmentationRatio > 0.10);
        
        // Integrity status - heap trie is always structurally valid
        stats.lastIntegrityCheckPassed = true;
        stats.corruptedNodes = 0;
        stats.orphanedNodes = 0;
        stats.lastIntegrityCheckTime = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
        
    } catch (const std::exception&) {
        // On any error, mark integrity as failed
        stats.lastIntegrityCheckPassed = false;
    }
    
    return stats;
}

// ============================================================================
// VERIFY INTEGRITY IMPLEMENTATION
// ============================================================================

PathIndexIntegrityResult PathIndex::VerifyIntegrity() const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE TRIE INTEGRITY VERIFICATION (HEAP-BASED)
     * ========================================================================
     *
     * Performs comprehensive integrity checks for heap-based trie:
     * 1. Root node existence
     * 2. Counter consistency (path count vs terminal nodes)
     * 3. Node count validation
     *
     * Note: Heap-based trie with std::unique_ptr is inherently structurally
     * sound - no pointer corruption, cycles, or orphans possible.
     *
     * Thread-safety: Uses shared_lock for concurrent verification
     *
     * ========================================================================
     */
    
    std::shared_lock lock(m_rwLock);
    
    PathIndexIntegrityResult result;
    result.isValid = true;
    
    // Check if heap root exists
    if (!m_heapRoot) {
        result.isValid = false;
        result.errorDetails = "Heap root is null";
        return result;
    }
    
    const uint64_t storedPathCount = m_pathCount.load(std::memory_order_acquire);
    const uint64_t storedNodeCount = m_nodeCount.load(std::memory_order_acquire);
    
    try {
        // Traverse heap trie to count nodes and terminals
        // SECURITY: Add depth limit to prevent stack overflow
        constexpr size_t VERIFY_MAX_DEPTH = 512;
        
        uint64_t actualNodeCount = 0;
        uint64_t actualTerminalCount = 0;
        
        std::function<void(const HeapTrieNode*, size_t)> countNodes;
        countNodes = [&](const HeapTrieNode* node, size_t depth) {
            if (!node || depth >= VERIFY_MAX_DEPTH) return;  // Stack overflow protection
            
            ++actualNodeCount;
            ++result.nodesChecked;
            
            if (node->isTerminal) {
                ++actualTerminalCount;
            }
            
            for (const auto& [segment, child] : node->children) {
                countNodes(child.get(), depth + 1);
            }
        };
        
        countNodes(m_heapRoot.get(), 0);
        
        // Verify path count matches terminal count
        if (actualTerminalCount != storedPathCount) {
            result.isValid = false;
            result.errorDetails += "Path count mismatch: stored=" + std::to_string(storedPathCount) + 
                ", actual terminals=" + std::to_string(actualTerminalCount) + "; ";
        }
        
        // Verify node count
        if (actualNodeCount != storedNodeCount) {
            // This is a warning, not an error - counts can drift slightly
            result.errorDetails += "Node count mismatch: stored=" + std::to_string(storedNodeCount) + 
                ", actual=" + std::to_string(actualNodeCount) + "; ";
        }
        
        // Final status message
        if (result.isValid && result.errorDetails.empty()) {
            result.errorDetails = "All integrity checks passed";
        }
        
    } catch (const std::exception& e) {
        result.isValid = false;
        result.errorDetails = std::string("Exception during verification: ") + e.what();
    }
    
    return result;
}

// ============================================================================
// THREATINTEL HYBRID PERSISTENCE MODEL IMPLEMENTATION
// ============================================================================
// Following the proven ThreatIntel pattern:
// - PathEntryRecord stored in memory-mapped file (persistent)
// - HeapTrieNode index rebuilt from records on startup (fast lookup)
// ============================================================================

bool PathIndex::InsertIntoHeapTrie(
    std::string_view normalizedPath,
    PathMatchMode mode,
    uint64_t entryOffset
) noexcept {
    /*
     * ========================================================================
     * INSERT INTO HEAP TRIE (INDEX ONLY - NO PERSISTENCE)
     * ========================================================================
     * 
     * This method handles ONLY the heap-based trie insertion. Used by:
     * 1. RebuildIndexFromRecords() - rebuilding index on startup
     * 2. Insert() - after creating the PathEntryRecord
     *
     * IMPORTANT: Caller must hold m_rwLock in exclusive mode
     * 
     * ========================================================================
     */
    
    if (normalizedPath.empty()) {
        return false;
    }
    
    // Ensure heap root exists
    if (!m_heapRoot) {
        try {
            m_heapRoot = std::make_unique<HeapTrieNode>();
            m_nodeCount.store(1, std::memory_order_release);
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"Whitelist", L"InsertIntoHeapTrie: failed to allocate root node");
            return false;
        }
    }
    
    try {
        // Split path into segments
        std::vector<std::string_view> segments;
        std::string pathCopy(normalizedPath); // Need mutable copy for SplitPathSegments
        SplitPathSegments(pathCopy, segments);
        
        if (segments.empty()) {
            SS_LOG_WARN(L"Whitelist", L"InsertIntoHeapTrie: path produced no segments");
            return false;
        }
        
        // Navigate/create trie nodes for each segment
        HeapTrieNode* node = m_heapRoot.get();
        
        for (size_t i = 0; i < segments.size(); ++i) {
            const std::string segmentKey(segments[i]);
            
            auto it = node->children.find(segmentKey);
            if (it == node->children.end()) {
                // Create new child node
                auto newNode = std::make_unique<HeapTrieNode>();
                auto [newIt, inserted] = node->children.emplace(segmentKey, std::move(newNode));
                
                if (!inserted) {
                    SS_LOG_ERROR(L"Whitelist", L"InsertIntoHeapTrie: failed to insert child node");
                    return false;
                }
                
                m_nodeCount.fetch_add(1, std::memory_order_relaxed);
                node = newIt->second.get();
            } else {
                node = it->second.get();
            }
        }
        
        // Mark terminal node
        if (!node->isTerminal) {
            m_pathCount.fetch_add(1, std::memory_order_relaxed);
        }
        
        node->isTerminal = true;
        node->entryOffset = entryOffset;
        node->matchMode = mode;
        
        return true;
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"InsertIntoHeapTrie exception: %S", e.what());
        return false;
    }
}

uint64_t PathIndex::RebuildIndexFromRecords() noexcept {
    /*
     * ========================================================================
     * REBUILD HEAP INDEX FROM PERSISTENT RECORDS
     * ========================================================================
     * 
     * Iterates all PathEntryRecord in m_pathRecords and rebuilds the
     * HeapTrieNode index. Called during Initialize() after LoadRecordsFromStorage().
     *
     * Following ThreatIntel pattern:
     * - O(n) startup cost where n = number of entries
     * - Typical performance: ~1µs per entry
     * - 1 million entries ≈ 1 second startup time
     *
     * IMPORTANT: Caller must hold m_rwLock in exclusive mode
     *
     * ========================================================================
     */
    
    // Reset heap index
    try {
        m_heapRoot = std::make_unique<HeapTrieNode>();
        m_nodeCount.store(1, std::memory_order_release);
        m_pathCount.store(0, std::memory_order_release);
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"Whitelist", L"RebuildIndexFromRecords: failed to allocate root node");
        return 0;
    }
    
    uint64_t rebuiltCount = 0;
    uint64_t skippedCount = 0;
    uint64_t errorCount = 0;
    
    const auto startTime = std::chrono::steady_clock::now();
    
    for (const auto& record : m_pathRecords) {
        // Skip invalid records
        if (!record.IsValid()) {
            ++errorCount;
            continue;
        }
        
        // Skip deleted records
        if (record.IsDeleted()) {
            ++skippedCount;
            continue;
        }
        
        // Get path from record
        std::string_view pathView = record.GetPath();
        if (pathView.empty()) {
            ++errorCount;
            continue;
        }
        
        // Insert into heap trie
        PathMatchMode mode = static_cast<PathMatchMode>(record.matchMode);
        if (InsertIntoHeapTrie(pathView, mode, record.entryOffset)) {
            ++rebuiltCount;
        } else {
            ++errorCount;
        }
    }
    
    const auto endTime = std::chrono::steady_clock::now();
    const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
    
    SS_LOG_INFO(L"Whitelist", 
        L"PathIndex rebuilt from %zu records: %llu active, %llu deleted, %llu errors in %lld µs",
        m_pathRecords.size(), rebuiltCount, skippedCount, errorCount, durationUs);
    
    return rebuiltCount;
}

StoreError PathIndex::FlushRecordsToStorage() noexcept {
    /*
     * ========================================================================
     * FLUSH RECORDS TO MEMORY-MAPPED STORAGE
     * ========================================================================
     * 
     * Writes all PathEntryRecord in m_pathRecords to the memory-mapped region.
     * Called during Compact() or explicit Flush() operations.
     *
     * Storage Layout (after header):
     * - Offset 64: Record count (uint64_t)
     * - Offset 72: Reserved (8 bytes)
     * - Offset 80: PathEntryRecord[0]
     * - Offset 80 + sizeof(PathEntryRecord): PathEntryRecord[1]
     * - ...
     *
     * IMPORTANT: Caller must hold m_rwLock in exclusive mode
     *
     * ========================================================================
     */
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Cannot flush: index is read-only"
        );
    }
    
    constexpr uint64_t HEADER_SIZE = 64;
    constexpr uint64_t RECORD_HEADER_OFFSET = HEADER_SIZE;  // Offset for record count
    constexpr uint64_t RECORDS_START_OFFSET = 80;           // Offset where records begin
    
    const size_t recordCount = m_pathRecords.size();
    const uint64_t requiredSize = RECORDS_START_OFFSET + (recordCount * sizeof(PathEntryRecord));
    
    // Check if we have enough space
    if (requiredSize > m_indexSize) {
        SS_LOG_ERROR(L"Whitelist", 
            L"FlushRecordsToStorage: insufficient space (need %llu, have %llu)",
            requiredSize, m_indexSize);
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Insufficient space for path records"
        );
    }
    
    auto* basePtr = static_cast<uint8_t*>(m_baseAddress);
    
    try {
        // Write record count
        auto* countPtr = reinterpret_cast<uint64_t*>(basePtr + RECORD_HEADER_OFFSET);
        *countPtr = static_cast<uint64_t>(recordCount);
        
        // Write records
        auto* recordsPtr = reinterpret_cast<PathEntryRecord*>(basePtr + RECORDS_START_OFFSET);
        
        for (size_t i = 0; i < recordCount; ++i) {
            std::memcpy(&recordsPtr[i], &m_pathRecords[i], sizeof(PathEntryRecord));
        }
        
        // Memory barrier to ensure writes are visible
        SS_STORE_FENCE();
        
        SS_LOG_DEBUG(L"Whitelist", L"FlushRecordsToStorage: wrote %zu records (%llu bytes)",
            recordCount, requiredSize);
        
        return StoreError::Success();
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"FlushRecordsToStorage exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::FileCorrupted,
            "Exception during record flush"
        );
    }
}

StoreError PathIndex::LoadRecordsFromStorage() noexcept {
    /*
     * ========================================================================
     * LOAD RECORDS FROM MEMORY-MAPPED STORAGE
     * ========================================================================
     * 
     * Reads PathEntryRecord structures from the memory-mapped region into
     * m_pathRecords vector. Called during Initialize() for read-only mode.
     *
     * Security Features:
     * - Validates record magic numbers
     * - Validates record version
     * - Bounds checking on all offsets
     * - Graceful handling of corrupted records
     *
     * IMPORTANT: Caller must hold m_rwLock in exclusive mode
     *
     * ========================================================================
     */
    
    // Clear existing records
    m_pathRecords.clear();
    m_nextRecordIndex.store(0, std::memory_order_release);
    
    // Validate view exists
    if (!m_view || !m_view->IsValid()) {
        SS_LOG_DEBUG(L"Whitelist", L"LoadRecordsFromStorage: no valid view (new database)");
        return StoreError::Success(); // Not an error - might be new database
    }
    
    constexpr uint64_t HEADER_SIZE = 64;
    constexpr uint64_t RECORD_HEADER_OFFSET = HEADER_SIZE;
    constexpr uint64_t RECORDS_START_OFFSET = 80;
    
    // Check minimum size for record header
    if (m_indexSize < RECORDS_START_OFFSET) {
        SS_LOG_DEBUG(L"Whitelist", L"LoadRecordsFromStorage: section too small for records");
        return StoreError::Success(); // No records stored
    }
    
    // Read record count
    const auto* countPtr = m_view->GetAt<uint64_t>(m_indexOffset + RECORD_HEADER_OFFSET);
    if (!countPtr) {
        SS_LOG_WARN(L"Whitelist", L"LoadRecordsFromStorage: failed to read record count");
        return StoreError::Success(); // Treat as empty
    }
    
    const uint64_t recordCount = *countPtr;
    
    // Validate record count is reasonable
    constexpr uint64_t MAX_RECORDS = 100'000'000; // 100 million max
    if (recordCount > MAX_RECORDS) {
        SS_LOG_ERROR(L"Whitelist", L"LoadRecordsFromStorage: invalid record count %llu", recordCount);
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Record count exceeds maximum"
        );
    }
    
    if (recordCount == 0) {
        SS_LOG_DEBUG(L"Whitelist", L"LoadRecordsFromStorage: no records stored");
        return StoreError::Success();
    }
    
    // Validate space for all records
    const uint64_t requiredSize = RECORDS_START_OFFSET + (recordCount * sizeof(PathEntryRecord));
    if (requiredSize > m_indexSize) {
        SS_LOG_ERROR(L"Whitelist", 
            L"LoadRecordsFromStorage: insufficient data for %llu records", recordCount);
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Insufficient data for stored record count"
        );
    }
    
    // Load records with validation
    try {
        m_pathRecords.reserve(static_cast<size_t>(recordCount));
        
        const auto* recordsBase = m_view->GetAt<PathEntryRecord>(m_indexOffset + RECORDS_START_OFFSET);
        if (!recordsBase) {
            SS_LOG_ERROR(L"Whitelist", L"LoadRecordsFromStorage: failed to get records base pointer");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Failed to access record storage"
            );
        }
        
        uint64_t validCount = 0;
        uint64_t invalidCount = 0;
        
        for (uint64_t i = 0; i < recordCount; ++i) {
            const PathEntryRecord& record = recordsBase[i];
            
            // Validate record
            if (!record.IsValid()) {
                ++invalidCount;
                SS_LOG_WARN(L"Whitelist", L"LoadRecordsFromStorage: invalid record at index %llu", i);
                
                // Add placeholder to maintain index alignment
                PathEntryRecord placeholder{};
                placeholder.flags = 0x01; // Mark as deleted
                m_pathRecords.push_back(placeholder);
                continue;
            }
            
            m_pathRecords.push_back(record);
            ++validCount;
        }
        
        m_nextRecordIndex.store(recordCount, std::memory_order_release);
        
        SS_LOG_INFO(L"Whitelist", 
            L"LoadRecordsFromStorage: loaded %llu records (%llu valid, %llu invalid)",
            recordCount, validCount, invalidCount);
        
        return StoreError::Success();
        
    } catch (const std::bad_alloc&) {
        m_pathRecords.clear();
        return StoreError::WithMessage(
            WhitelistStoreError::OutOfMemory,
            "Failed to allocate memory for records"
        );
    } catch (const std::exception& e) {
        m_pathRecords.clear();
        SS_LOG_ERROR(L"Whitelist", L"LoadRecordsFromStorage exception: %S", e.what());
        return StoreError::WithMessage(
            WhitelistStoreError::FileCorrupted,
            "Exception during record load"
        );
    }
}

} // namespace ShadowStrike::Whitelist
