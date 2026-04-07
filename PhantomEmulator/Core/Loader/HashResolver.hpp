/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * HashResolver.hpp — API hash-based import resolver for shellcode analysis
 *
 * Resolves hashed API imports used by shellcode, packers, and malware loaders.
 * Supports the hash algorithms most commonly encountered in real-world malware:
 * ROR13 (Metasploit/Cobalt Strike), CRC32 (APT32/OceanLotus), DJB2, FNV-1a,
 * SDBM, Jenkins OAAT, SuperFastHash, MurmurHash OAAT, and wide-char variants.
 *
 * Pre-computes hash lookup tables from ExportResolver's module database so that
 * runtime resolution is a single O(1) hash-map lookup per query.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "ExportResolver.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Phantom {

// ============================================================================
// HashAlgorithm — Supported API hashing algorithms
// ============================================================================

enum class HashAlgorithm : uint8_t {
    ROR13,       // Metasploit/Cobalt Strike block_api standard
    CRC32,       // APT32/OceanLotus — CRC32 of function name only
    DJB2,        // Dan Bernstein hash — common lightweight variant
    FNV1a,       // Fowler-Noll-Vo 1a (32-bit)
    SDBM,        // SDBM hash (some packers)
    SuperFast,   // Paul Hsieh's SuperFastHash
    MurmurOAAT,  // MurmurHash one-at-a-time variant
    JenkinsOAAT, // Jenkins one-at-a-time
    ROR13Wide,   // ROR13 on wide strings (some APTs)
    CRC32Full,   // CRC32 of "module.dll!FunctionName" combined
    Unknown,
};

// ============================================================================
// HashResolution — Result of resolving a hashed import
// ============================================================================

struct HashResolution {
    GuestAddress  address      = 0;
    std::string   moduleName;
    std::string   functionName;
    HashAlgorithm algorithm    = HashAlgorithm::Unknown;
    uint32_t      hash         = 0;
};

// ============================================================================
// HashResolver — Pre-computed hash-to-export lookup engine
// ============================================================================
//
// Usage:
//   1. Load PE modules into ExportResolver
//   2. Construct HashResolver
//   3. Call BuildFromExports() to pre-compute all hash tables
//   4. Use ResolveByHash() / BatchResolve() during shellcode analysis
//
// Not thread-safe during BuildFromExports(). After build completes,
// all Resolve/Detect methods are safe for concurrent read access.

class HashResolver {
public:
    HashResolver() noexcept;

    // Build hash tables from ExportResolver's module database.
    // Must be called AFTER all modules are registered with ExportResolver.
    void BuildFromExports(const ExportResolver& exports) noexcept;

    // Resolve a hash value. Tries all known algorithms if algo==Unknown.
    [[nodiscard]] std::optional<HashResolution> ResolveByHash(
        uint32_t hash, HashAlgorithm algo = HashAlgorithm::Unknown) const noexcept;

    // Resolve with a specific algorithm only.
    [[nodiscard]] std::optional<HashResolution> ResolveByHashExact(
        uint32_t hash, HashAlgorithm algo) const noexcept;

    // Auto-detect which algorithm a set of hashes uses.
    // Returns the algorithm that resolves the most hashes (>= minMatches).
    [[nodiscard]] HashAlgorithm DetectAlgorithm(
        const uint32_t* hashes, uint32_t count,
        uint32_t minMatches = 2) const noexcept;

    // Batch resolve (for shellcode analysis — resolve multiple hashes at once).
    [[nodiscard]] std::vector<HashResolution> BatchResolve(
        const uint32_t* hashes, uint32_t count,
        HashAlgorithm algo = HashAlgorithm::Unknown) const noexcept;

    // Statistics
    [[nodiscard]] uint32_t GetTotalHashes() const noexcept;
    [[nodiscard]] uint32_t GetModuleCount() const noexcept;

    // Clear all pre-computed tables.
    void Reset() noexcept;

private:
    // Compact storage: indices into m_moduleNames / m_functionNames
    struct HashEntry {
        GuestAddress address    = 0;
        uint16_t     moduleIndex   = 0;
        uint16_t     nameIndex     = 0;
    };

    // Interned string pools
    std::vector<std::string> m_moduleNames;
    std::vector<std::string> m_functionNames;

    // Per-algorithm hash → entry maps
    static constexpr uint32_t kAlgoCount =
        static_cast<uint32_t>(HashAlgorithm::Unknown);
    std::array<std::unordered_map<uint32_t, HashEntry>, kAlgoCount> m_tables;

    // Tracked module count for statistics
    uint32_t m_moduleCount = 0;

    // Insert a resolved export into all hash tables for all algorithms
    void InsertExport(uint16_t moduleIdx, uint16_t nameIdx,
                      std::string_view moduleName, std::string_view funcName,
                      GuestAddress address) noexcept;
};

} // namespace Phantom
