/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Internal Implementation Header
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
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
