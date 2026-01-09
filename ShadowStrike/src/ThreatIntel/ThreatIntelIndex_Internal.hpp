/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Internal Implementation Header
 * ============================================================================
 *
 * Copyright (c) 2024 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This header contains the complete definition of ThreatIntelIndex::Impl
 * and all internal data structures. It is included ONLY by the modular
 * .cpp files (Core, Lookups, Modifications, etc.) to allow them to access
 * m_impl members without exposing implementation details in the public API.
 *
 * WARNING: This is an INTERNAL header - DO NOT include in any public headers!
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelIndex.hpp"
#include "ThreatIntelIndex_DataStructures.hpp"
#include "ThreatIntelIndex_Trees.hpp"
#include "ThreatIntelIndex_URLMatcher.hpp"
#include "ThreatIntelIndex_LRU.hpp"
#include "ThreatIntelDatabase.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <numeric>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// Windows-specific includes for SIMD and performance
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <intrin.h>
#include <immintrin.h>  // SIMD intrinsics (AVX2, SSE4)

// ============================================================================
// PERFORMANCE MACROS
// ============================================================================

// Prefetch hint macro
#ifdef _MSC_VER
#define PREFETCH_READ(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
#define PREFETCH_WRITE(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T1)
#else
#define PREFETCH_READ(addr) __builtin_prefetch(addr, 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch(addr, 1, 3)
#endif

// Branch prediction hints
#ifdef __GNUC__
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

// Compiler barrier
#ifdef _MSC_VER
#define COMPILER_BARRIER() _ReadWriteBarrier()
#else
#define COMPILER_BARRIER() asm volatile("" ::: "memory")
#endif

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// INTERNAL HELPER FUNCTIONS - Shared across all modular .cpp files
// ============================================================================

/**
 * @brief Get cached performance counter frequency (thread-safe, lazily initialized)
 * 
 * Uses static local variable for thread-safe lazy initialization (C++11 magic statics).
 * QueryPerformanceFrequency is guaranteed to succeed on Windows XP and later.
 * 
 * @return Performance counter frequency in counts per second
 */
[[nodiscard]] inline LONGLONG GetCachedPerformanceFrequency() noexcept {
    static const LONGLONG frequency = []() {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);  // Cannot fail on Windows XP+
        return freq.QuadPart;
    }();
    return frequency;
}

/**
 * @brief Get high-resolution timestamp in nanoseconds
 * 
 * Uses Windows QueryPerformanceCounter for nanosecond-level precision.
 * Handles potential overflow for very large counter values.
 * 
 * @return Current timestamp in nanoseconds, or 0 on failure
 */
[[nodiscard]] inline uint64_t GetNanoseconds() noexcept {
    LARGE_INTEGER counter;
    if (UNLIKELY(!QueryPerformanceCounter(&counter))) {
        return 0;  // Counter unavailable - should never happen on modern Windows
    }

    // Get cached frequency (guaranteed non-zero)
    const LONGLONG frequency = GetCachedPerformanceFrequency();

    // Convert to nanoseconds with overflow protection
    constexpr uint64_t NANOSECONDS_PER_SECOND = 1000000000ULL;
    constexpr uint64_t MAX_SAFE_COUNTER = UINT64_MAX / NANOSECONDS_PER_SECOND;

    if (static_cast<uint64_t>(counter.QuadPart) <= MAX_SAFE_COUNTER) {
        // Safe to multiply directly
        return (static_cast<uint64_t>(counter.QuadPart) * NANOSECONDS_PER_SECOND)
            / static_cast<uint64_t>(frequency);
    }
    else {
        // Use safer calculation for large counter values
        const uint64_t seconds = static_cast<uint64_t>(counter.QuadPart)
            / static_cast<uint64_t>(frequency);
        const uint64_t remainder = static_cast<uint64_t>(counter.QuadPart)
            % static_cast<uint64_t>(frequency);

        return (seconds * NANOSECONDS_PER_SECOND) +
            (remainder * NANOSECONDS_PER_SECOND / static_cast<uint64_t>(frequency));
    }
}

/**
 * @brief Calculate FNV-1a hash for string
 * 
 * Fast, high-quality hash function suitable for hash tables and bloom filters.
 * Uses 64-bit FNV-1a algorithm with official offset basis and prime.
 * 
 * @param str String to hash
 * @return 64-bit hash value
 */
[[nodiscard]] inline uint64_t HashString(std::string_view str) noexcept {
    uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
    for (char c : str) {
        hash ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
        hash *= 1099511628211ULL;  // FNV prime
    }
    return hash;
}

/**
 * @brief Normalize domain name (lowercase, trim whitespace)
 * 
 * Uses locale-independent character handling for security.
 * 
 * @param domain Domain name to normalize
 * @return Normalized domain string
 */
[[nodiscard]] inline std::string NormalizeDomain(std::string_view domain) noexcept {
    std::string result;
    result.reserve(domain.size());

    // Skip leading whitespace (locale-independent)
    size_t start = 0;
    while (start < domain.size()) {
        const char c = domain[start];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\v' && c != '\f') {
            break;
        }
        ++start;
    }

    // Convert to lowercase and remove trailing whitespace
    for (size_t i = start; i < domain.size(); ++i) {
        const char c = domain[i];
        // Check for whitespace (locale-independent)
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
            break;
        }
        // Lowercase conversion (ASCII only, safe for domains)
        if (c >= 'A' && c <= 'Z') {
            result.push_back(static_cast<char>(c + ('a' - 'A')));
        }
        else {
            result.push_back(c);
        }
    }

    return result;
}

// ============================================================================
// THREATINTELINDEX::IMPL - COMPLETE INTERNAL IMPLEMENTATION
// ============================================================================

/**
 * @brief Internal implementation class (Pimpl pattern)
 * 
 * Contains all index data structures and internal state.
 * This complete definition allows modular .cpp files to access
 * m_impl members while maintaining ABI stability in the public API.
 */
class ThreatIntelIndex::Impl {
public:
    Impl() = default;
    ~Impl() = default;
    
    // Non-copyable, non-movable
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;
    
    // =========================================================================
    // INDEX INSTANCES
    // =========================================================================
    
    /// IPv4 address index (Radix Tree - 4-level hierarchical)
    std::unique_ptr<IPv4RadixTree> ipv4Index;
    
    /// IPv6 address index (Patricia Trie - 128-bit optimized)
    std::unique_ptr<IPv6PatriciaTrie> ipv6Index;
    
    /// Domain name index (Suffix Trie + Hash Table)
    std::unique_ptr<DomainSuffixTrie> domainIndex;
    
    /// URL pattern index (Aho-Corasick automaton)
    std::unique_ptr<URLPatternMatcher> urlIndex;
    
    /// Email address index (Hash Table)
    std::unique_ptr<EmailHashTable> emailIndex;
    
    /// Generic IOC index (B+Tree for miscellaneous types)
    std::unique_ptr<GenericBPlusTree> genericIndex;
    
    /// Hash indexes per algorithm (MD5, SHA1, SHA256, etc.)
    /// Array index corresponds to HashAlgorithm enum value
    std::array<std::unique_ptr<HashBPlusTree>, 11> hashIndexes;
    
    /// Bloom filters per index type for fast negative lookups
    std::unordered_map<IOCType, std::unique_ptr<IndexBloomFilter>> bloomFilters;
    
    // =========================================================================
    // MEMORY-MAPPED VIEW
    // =========================================================================
    
    /// Pointer to memory-mapped database view (NOT owned)
    const MemoryMappedView* view{nullptr};
    
    /// Pointer to database header (NOT owned, lives in memory-mapped region)
    const ThreatIntelDatabaseHeader* header{nullptr};
    
    // =========================================================================
    // STATISTICS
    // =========================================================================
    
    /// Thread-safe statistics counters
    mutable IndexStatistics stats{};
    
    // =========================================================================
    // CONFIGURATION
    // =========================================================================
    
    /// Index build configuration options
    IndexBuildOptions buildOptions{};
};

} // namespace ThreatIntel
} // namespace ShadowStrike
