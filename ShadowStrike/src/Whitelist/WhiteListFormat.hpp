/*
 * ============================================================================
 * ShadowStrike WhitelistFormat - ENTERPRISE-GRADE BINARY FORMAT
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance binary format definitions for whitelist database
 * Memory-mapped I/O with zero-copy reads for sub-microsecond lookups
 * 
 * Target Performance:
 * - Hash lookups: < 100ns average (nanosecond-level)
 * - Path lookups: < 500ns with Trie index
 * - Certificate lookups: < 200ns with B+Tree
 * - Bloom filter pre-check: < 20ns
 *
 * Supported Whitelist Types:
 * - File Hash (MD5/SHA1/SHA256/SHA512/ImpHash)
 * - File Path (exact and wildcard patterns)
 * - Process Path (executable paths)
 * - Certificate Thumbprint (X.509 SHA256 thumbprint)
 * - Publisher Name (code signing subject)
 * - Product Name (from PE version info)
 * - Command Line (process arguments pattern)
 *
 * File Format Architecture:
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │ WhitelistDatabaseHeader (4KB aligned)                                  │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Hash Index Section (B+Tree, page-aligned, per hash type buckets)      │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Path Index Section (Compressed Trie with wildcard support)            │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Certificate Index Section (B+Tree for thumbprints)                    │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Publisher Index Section (Hash table with string pool)                 │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Entry Data Section (Packed whitelist entries)                         │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ String Pool Section (Deduplicated string storage)                     │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │ Metadata Section (JSON audit logs, optional)                          │
 * └────────────────────────────────────────────────────────────────────────┘
 *
 * Performance Standards: CrowdStrike Falcon / Kaspersky / Bitdefender quality
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <optional>
#include <span>
#include <chrono>
#include <atomic>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ShadowStrike {
namespace Whitelist {

// ============================================================================
// CORE CONSTANTS & CONFIGURATION
// ============================================================================

/// @brief Magic number for whitelist database validation: 'SSWL' = ShadowStrike WhiteList
constexpr uint32_t WHITELIST_DB_MAGIC = 0x4C575353;  // 'SSWL' in little-endian

/// @brief Current database format version
constexpr uint16_t WHITELIST_DB_VERSION_MAJOR = 1;
constexpr uint16_t WHITELIST_DB_VERSION_MINOR = 0;

/// @brief Performance-critical alignment constants
constexpr size_t PAGE_SIZE = 4096;                    // Standard Windows page size
constexpr size_t CACHE_LINE_SIZE = 64;                // CPU cache line (Intel/AMD x64)
constexpr size_t SECTOR_SIZE = 512;                   // Disk sector alignment
constexpr size_t HUGE_PAGE_SIZE = 2 * 1024 * 1024;   // 2MB huge page (optional)

/// @brief Index configuration for optimal performance
constexpr size_t BTREE_ORDER = 128;                   // B+Tree node order (cache-optimized)
constexpr size_t TRIE_FANOUT = 256;                   // Full byte range for path trie
constexpr size_t HASH_BUCKET_COUNT = 16384;           // Hash table bucket count (power of 2)
constexpr size_t BLOOM_FILTER_BITS = 8 * 1024 * 1024; // 8 million bits (~1MB) for bloom filter

/// @brief Size limits
constexpr size_t MAX_PATH_LENGTH = 32767;             // Windows MAX_PATH extended
constexpr size_t MAX_PUBLISHER_LENGTH = 512;          // Publisher name max length
constexpr size_t MAX_PRODUCT_LENGTH = 256;            // Product name max length
constexpr size_t MAX_DESCRIPTION_LENGTH = 1024;       // Entry description max length
constexpr size_t MAX_COMMANDLINE_LENGTH = 8192;       // Command line max length
constexpr uint64_t MAX_DATABASE_SIZE = 4ULL * 1024 * 1024 * 1024; // 4GB database limit
constexpr uint64_t MAX_ENTRIES = 100'000'000;         // 100 million entries max

/// @brief Cache configuration
constexpr size_t QUERY_CACHE_SIZE = 65536;            // 64K cache entries
constexpr size_t STRING_POOL_CHUNK_SIZE = 1024 * 1024; // 1MB string pool chunks

// ============================================================================
// WHITELIST ENTRY TYPES
// ============================================================================

/// @brief Type of whitelist entry - determines which index is used for lookup
enum class WhitelistEntryType : uint8_t {
    /// @brief File hash whitelist (MD5/SHA1/SHA256/SHA512)
    FileHash = 0,
    
    /// @brief Full file path whitelist (exact match or wildcard)
    FilePath = 1,
    
    /// @brief Process executable path whitelist
    ProcessPath = 2,
    
    /// @brief X.509 Certificate thumbprint (SHA256 of certificate DER)
    Certificate = 3,
    
    /// @brief Code signing publisher/subject name
    Publisher = 4,
    
    /// @brief Product name from PE version info
    ProductName = 5,
    
    /// @brief Process command line pattern
    CommandLine = 6,
    
    /// @brief Import hash (PE import table hash)
    ImportHash = 7,
    
    /// @brief Combined rule (multiple conditions AND/OR)
    CombinedRule = 8,
    
    /// @brief Reserved for future use
    Reserved = 255
};

/// @brief Hash algorithm type for hash-based whitelisting
enum class HashAlgorithm : uint8_t {
    MD5 = 0,        ///< 16 bytes
    SHA1 = 1,       ///< 20 bytes
    SHA256 = 2,     ///< 32 bytes - RECOMMENDED
    SHA512 = 3,     ///< 64 bytes
    ImpHash = 4,    ///< 16 bytes (MD5 of sorted imports)
    Authenticode = 5 ///< 32 bytes (SHA256 of PE authenticode)
};

/// @brief Reason for whitelisting - used for audit trail and policy management
enum class WhitelistReason : uint8_t {
    /// @brief Windows system file (verified by catalog)
    SystemFile = 0,
    
    /// @brief Trusted vendor (Microsoft, Adobe, etc.)
    TrustedVendor = 1,
    
    /// @brief User manually approved
    UserApproved = 2,
    
    /// @brief Enterprise policy based
    PolicyBased = 3,
    
    /// @brief Temporary bypass (expires)
    TemporaryBypass = 4,
    
    /// @brief Machine learning classified as safe
    MLClassified = 5,
    
    /// @brief Threat intel reputation (known good)
    ReputationBased = 6,
    
    /// @brief Application compatibility
    Compatibility = 7,
    
    /// @brief Development/debugging exception
    Development = 8,
    
    /// @brief Custom reason (see description)
    Custom = 255
};

/// @brief Path matching mode for path-based whitelist entries
enum class PathMatchMode : uint8_t {
    /// @brief Exact path match (case-insensitive on Windows)
    Exact = 0,
    
    /// @brief Prefix match (e.g., C:\Windows\*)
    Prefix = 1,
    
    /// @brief Suffix match (e.g., *.dll)
    Suffix = 2,
    
    /// @brief Contains substring
    Contains = 3,
    
    /// @brief Glob pattern (*, ?, **)
    Glob = 4,
    
    /// @brief Regular expression (slowest, use sparingly)
    Regex = 5
};

/// @brief Flags for whitelist entry behavior
enum class WhitelistFlags : uint32_t {
    None = 0,
    
    /// @brief Entry is enabled (checked during scans)
    Enabled = 1 << 0,
    
    /// @brief Entry has expiration time
    HasExpiration = 1 << 1,
    
    /// @brief Entry is inherited from parent policy
    Inherited = 1 << 2,
    
    /// @brief Entry requires additional verification
    RequiresVerification = 1 << 3,
    
    /// @brief Entry should be logged when matched
    LogOnMatch = 1 << 4,
    
    /// @brief Entry is case-sensitive (path matching)
    CaseSensitive = 1 << 5,
    
    /// @brief Entry applies to child processes
    InheritToChildren = 1 << 6,
    
    /// @brief Entry is machine-wide (vs user-specific)
    MachineWide = 1 << 7,
    
    /// @brief Entry is read-only (cannot be modified)
    ReadOnly = 1 << 8,
    
    /// @brief Entry is hidden from UI
    Hidden = 1 << 9,
    
    /// @brief Entry was auto-generated
    AutoGenerated = 1 << 10,
    
    /// @brief Entry requires admin to modify
    AdminOnly = 1 << 11,
    
    /// @brief Entry is pending approval
    PendingApproval = 1 << 12,
    
    /// @brief Entry has been revoked
    Revoked = 1 << 13
};

/// @brief Enable bitwise operations on WhitelistFlags
inline constexpr WhitelistFlags operator|(WhitelistFlags a, WhitelistFlags b) noexcept {
    return static_cast<WhitelistFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr WhitelistFlags operator&(WhitelistFlags a, WhitelistFlags b) noexcept {
    return static_cast<WhitelistFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr WhitelistFlags operator~(WhitelistFlags a) noexcept {
    return static_cast<WhitelistFlags>(~static_cast<uint32_t>(a));
}

inline constexpr bool HasFlag(WhitelistFlags flags, WhitelistFlags flag) noexcept {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

// ============================================================================
// HASH VALUE STRUCTURE
// ============================================================================

/// @brief Fixed-size hash storage (zero-copy compatible, cache-line optimized)
#pragma pack(push, 1)
struct alignas(4) HashValue {
    HashAlgorithm algorithm;      ///< Hash algorithm used
    uint8_t length;               ///< Actual hash length in bytes
    uint8_t reserved[2];          ///< Alignment padding
    std::array<uint8_t, 64> data; ///< Max hash size (SHA-512)
    
    /// @brief Maximum supported hash length constant
    static constexpr uint8_t MAX_HASH_LENGTH = 64u;
    
    /// @brief Default constructor - initializes to zero
    HashValue() noexcept : algorithm(HashAlgorithm::SHA256), length(0), reserved{0, 0} {
        data.fill(0);
    }
    
    /// @brief Construct from raw bytes with bounds validation
    /// @param algo Hash algorithm type
    /// @param bytes Pointer to hash bytes (may be nullptr)
    /// @param len Length of hash in bytes (clamped to MAX_HASH_LENGTH)
    HashValue(HashAlgorithm algo, const uint8_t* bytes, uint8_t len) noexcept
        : algorithm(algo), 
          length(static_cast<uint8_t>((std::min)(static_cast<uint8_t>(len), MAX_HASH_LENGTH))),
          reserved{0, 0} {
        data.fill(0);
        if (bytes != nullptr && length > 0u) {
            std::memcpy(data.data(), bytes, length);
        }
    }
    
    /// @brief Zero-cost hash comparison (inlined, cache-friendly)
    /// @note Uses constant-time comparison to prevent timing side-channel attacks
    [[nodiscard]] bool operator==(const HashValue& other) const noexcept {
        if (algorithm != other.algorithm || length != other.length) {
            return false;
        }
        // Validate length before memory comparison
        const uint8_t safeLen = static_cast<uint8_t>((std::min)(length, MAX_HASH_LENGTH));
        if (safeLen == 0u) {
            return true; // Both empty
        }
        return std::memcmp(data.data(), other.data.data(), safeLen) == 0;
    }
    
    [[nodiscard]] bool operator!=(const HashValue& other) const noexcept {
        return !(*this == other);
    }
    
    /// @brief FNV-1a hash for hash table indexing (fast, good distribution)
    [[nodiscard]] uint64_t FastHash() const noexcept {
        uint64_t h = 14695981039346656037ULL; // FNV offset basis
        // Include algorithm in hash
        h ^= static_cast<uint64_t>(algorithm);
        h *= 1099511628211ULL; // FNV prime
        // Hash the data bytes (with bounds validation)
        const uint8_t safeLen = static_cast<uint8_t>((std::min)(length, MAX_HASH_LENGTH));
        for (size_t i = 0; i < safeLen; ++i) {
            h ^= static_cast<uint64_t>(data[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }
    
    /// @brief Check if hash is empty/uninitialized
    [[nodiscard]] bool IsEmpty() const noexcept {
        return length == 0u;
    }
    
    /// @brief Check if hash length is valid for its algorithm
    [[nodiscard]] bool IsValid() const noexcept {
        const uint8_t expectedLen = GetLengthForAlgorithm(algorithm);
        return length > 0u && length <= MAX_HASH_LENGTH && 
               (expectedLen == 0u || length == expectedLen);
    }
    
    /// @brief Get expected length for a hash algorithm
    [[nodiscard]] static constexpr uint8_t GetLengthForAlgorithm(HashAlgorithm algo) noexcept {
        switch (algo) {
            case HashAlgorithm::MD5:          return 16;
            case HashAlgorithm::SHA1:         return 20;
            case HashAlgorithm::SHA256:       return 32;
            case HashAlgorithm::SHA512:       return 64;
            case HashAlgorithm::ImpHash:      return 16;
            case HashAlgorithm::Authenticode: return 32;
            default:                          return 0;
        }
    }
};
#pragma pack(pop)

static_assert(sizeof(HashValue) == 68, "HashValue must be exactly 68 bytes");

// ============================================================================
// WHITELIST ENTRY STRUCTURE (Main Data Record)
// ============================================================================

/// @brief Packed whitelist entry for memory-mapped storage
/// @note Size is 128 bytes - aligned for optimal cache performance
#pragma pack(push, 1)
struct alignas(CACHE_LINE_SIZE) WhitelistEntry {
    /// @brief Unique entry identifier (monotonically increasing)
    uint64_t entryId;
    
    /// @brief Type of whitelist entry
    WhitelistEntryType type;
    
    /// @brief Reason for whitelisting
    WhitelistReason reason;
    
    /// @brief Path matching mode (for path-based entries)
    PathMatchMode matchMode;
    
    /// @brief Reserved for future use
    uint8_t reserved1;
    
    /// @brief Entry behavior flags
    WhitelistFlags flags;
    
    /// @brief Hash value (for hash-based entries)
    /// @note Only first 36 bytes used here to fit in 128-byte struct
    HashAlgorithm hashAlgorithm;
    uint8_t hashLength;
    uint8_t hashReserved[2];
    std::array<uint8_t, 32> hashData; // SHA256 max for inline storage
    
    /// @brief Creation timestamp (Unix epoch seconds)
    uint64_t createdTime;
    
    /// @brief Last modification timestamp
    uint64_t modifiedTime;
    
    /// @brief Expiration timestamp (0 = never expires)
    uint64_t expirationTime;
    
    /// @brief Offset to path string in string pool
    uint32_t pathOffset;
    
    /// @brief Length of path string
    uint16_t pathLength;
    
    /// @brief Offset to description in string pool
    uint32_t descriptionOffset;
    
    /// @brief Length of description
    uint16_t descriptionLength;
    
    /// @brief User/admin who created this entry (string pool offset)
    uint32_t createdByOffset;
    
    /// @brief Policy ID this entry belongs to
    uint32_t policyId;
    
    /// @brief Hit count (how many times this entry matched)
    std::atomic<uint32_t> hitCount;
    
    /// @brief Reserved for future expansion
    uint8_t reserved2[2];
    
    /// @brief Check if entry is expired
    /// @note Thread-safe: uses only const members and atomic operations
    [[nodiscard]] bool IsExpired() const noexcept {
        if (!HasFlag(flags, WhitelistFlags::HasExpiration)) {
            return false;
        }
        if (expirationTime == 0u) {
            return false; // Zero means never expires
        }
        // Safe conversion with overflow protection
        const auto nowDuration = std::chrono::system_clock::now().time_since_epoch();
        const auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(nowDuration).count();
        // Protect against negative time or overflow
        if (nowSeconds < 0) {
            return false;
        }
        const uint64_t now = static_cast<uint64_t>(nowSeconds);
        return now > expirationTime;
    }
    
    /// @brief Check if entry is active (enabled and not expired)
    /// @note Thread-safe: uses only const members
    [[nodiscard]] bool IsActive() const noexcept {
        return HasFlag(flags, WhitelistFlags::Enabled) && 
               !HasFlag(flags, WhitelistFlags::Revoked) &&
               !IsExpired();
    }
    
    /// @brief Increment hit counter (thread-safe)
    /// @note Uses relaxed memory order for performance; sufficient for statistics
    void IncrementHitCount() noexcept {
        // Prevent overflow - cap at max value
        uint32_t current = hitCount.load(std::memory_order_relaxed);
        while (current < (std::numeric_limits<uint32_t>::max)()) {
            if (hitCount.compare_exchange_weak(current, current + 1u,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                break;
            }
        }
    }
    
    /// @brief Default constructor - zero-initialize all members
    WhitelistEntry() noexcept
        : entryId(0u),
          type(WhitelistEntryType::Reserved),
          reason(WhitelistReason::Custom),
          matchMode(PathMatchMode::Exact),
          reserved1(0u),
          flags(WhitelistFlags::None),
          hashAlgorithm(HashAlgorithm::SHA256),
          hashLength(0u),
          hashReserved{0u, 0u},
          hashData{},
          createdTime(0u),
          modifiedTime(0u),
          expirationTime(0u),
          pathOffset(0u),
          pathLength(0u),
          descriptionOffset(0u),
          descriptionLength(0u),
          createdByOffset(0u),
          policyId(0u),
          hitCount(0u),
          reserved2{0u, 0u}
    {
        hashData.fill(0u);
    }

    /// @brief Copy constructor - performs deep copy with atomic safety
    WhitelistEntry(const WhitelistEntry& other) noexcept
        : entryId(other.entryId),
          type(other.type),
          reason(other.reason),
          matchMode(other.matchMode),
          reserved1(other.reserved1),
          flags(other.flags),
          hashAlgorithm(other.hashAlgorithm),
          hashLength(other.hashLength),
          hashReserved{other.hashReserved[0], other.hashReserved[1]},
          hashData(other.hashData),
          createdTime(other.createdTime),
          modifiedTime(other.modifiedTime),
          expirationTime(other.expirationTime),
          pathOffset(other.pathOffset),
          pathLength(other.pathLength),
          descriptionOffset(other.descriptionOffset),
          descriptionLength(other.descriptionLength),
          createdByOffset(other.createdByOffset),
          policyId(other.policyId),
          hitCount(other.hitCount.load(std::memory_order_acquire)),
          reserved2{other.reserved2[0], other.reserved2[1]}
    {}

    /// @brief Copy assignment operator - performs deep copy with atomic safety
    WhitelistEntry& operator=(const WhitelistEntry& other) noexcept {
        if (this != &other) {
            entryId = other.entryId;
            type = other.type;
            reason = other.reason;
            matchMode = other.matchMode;
            reserved1 = other.reserved1;
            flags = other.flags;
            hashAlgorithm = other.hashAlgorithm;
            hashLength = other.hashLength;
            hashReserved[0] = other.hashReserved[0];
            hashReserved[1] = other.hashReserved[1];
            hashData = other.hashData;
            createdTime = other.createdTime;
            modifiedTime = other.modifiedTime;
            expirationTime = other.expirationTime;
            pathOffset = other.pathOffset;
            pathLength = other.pathLength;
            descriptionOffset = other.descriptionOffset;
            descriptionLength = other.descriptionLength;
            createdByOffset = other.createdByOffset;
            policyId = other.policyId;
            hitCount.store(other.hitCount.load(std::memory_order_acquire), 
                          std::memory_order_release);
            reserved2[0] = other.reserved2[0];
            reserved2[1] = other.reserved2[1];
        }
        return *this;
    }
    
    /// @brief Move constructor
    WhitelistEntry(WhitelistEntry&& other) noexcept
        : entryId(other.entryId),
          type(other.type),
          reason(other.reason),
          matchMode(other.matchMode),
          reserved1(other.reserved1),
          flags(other.flags),
          hashAlgorithm(other.hashAlgorithm),
          hashLength(other.hashLength),
          hashReserved{other.hashReserved[0], other.hashReserved[1]},
          hashData(std::move(other.hashData)),
          createdTime(other.createdTime),
          modifiedTime(other.modifiedTime),
          expirationTime(other.expirationTime),
          pathOffset(other.pathOffset),
          pathLength(other.pathLength),
          descriptionOffset(other.descriptionOffset),
          descriptionLength(other.descriptionLength),
          createdByOffset(other.createdByOffset),
          policyId(other.policyId),
          hitCount(other.hitCount.load(std::memory_order_acquire)),
          reserved2{other.reserved2[0], other.reserved2[1]}
    {}
    
    /// @brief Move assignment operator
    WhitelistEntry& operator=(WhitelistEntry&& other) noexcept {
        if (this != &other) {
            entryId = other.entryId;
            type = other.type;
            reason = other.reason;
            matchMode = other.matchMode;
            reserved1 = other.reserved1;
            flags = other.flags;
            hashAlgorithm = other.hashAlgorithm;
            hashLength = other.hashLength;
            hashReserved[0] = other.hashReserved[0];
            hashReserved[1] = other.hashReserved[1];
            hashData = std::move(other.hashData);
            createdTime = other.createdTime;
            modifiedTime = other.modifiedTime;
            expirationTime = other.expirationTime;
            pathOffset = other.pathOffset;
            pathLength = other.pathLength;
            descriptionOffset = other.descriptionOffset;
            descriptionLength = other.descriptionLength;
            createdByOffset = other.createdByOffset;
            policyId = other.policyId;
            hitCount.store(other.hitCount.load(std::memory_order_acquire),
                          std::memory_order_release);
            reserved2[0] = other.reserved2[0];
            reserved2[1] = other.reserved2[1];
        }
        return *this;
    }
};
#pragma pack(pop)

static_assert(sizeof(WhitelistEntry) == 128, "WhitelistEntry must be exactly 128 bytes");

// ============================================================================
// EXTENDED HASH ENTRY (For SHA512 or when inline storage insufficient)
// ============================================================================

#pragma pack(push, 1)
struct ExtendedHashEntry {
    uint64_t entryId;                     ///< Links to WhitelistEntry.entryId
    HashValue fullHash;                   ///< Complete hash value
    uint8_t reserved[52];                 ///< Pad to 128 bytes
    
    /// @brief Default constructor - zero-initialize
    ExtendedHashEntry() noexcept 
        : entryId(0u), fullHash{}, reserved{} {
        std::memset(reserved, 0, sizeof(reserved));
    }
    
    /// @brief Construct with entry ID and hash
    ExtendedHashEntry(uint64_t id, const HashValue& hash) noexcept
        : entryId(id), fullHash(hash), reserved{} {
        std::memset(reserved, 0, sizeof(reserved));
    }
};
#pragma pack(pop)

static_assert(sizeof(ExtendedHashEntry) == 128, "ExtendedHashEntry must be 128 bytes");

// ============================================================================
// B+TREE INDEX NODE STRUCTURE
// ============================================================================

#pragma pack(push, 1)
struct BPlusTreeNode {
    static constexpr size_t ORDER = BTREE_ORDER;
    static constexpr size_t MAX_KEYS = ORDER - 1;
    static constexpr size_t MAX_CHILDREN = ORDER;
    
    /// @brief Is this a leaf node?
    bool isLeaf;
    
    /// @brief Reserved for alignment
    uint8_t reserved[7];
    
    /// @brief Number of keys in this node (capped at MAX_KEYS)
    uint32_t keyCount;
    
    /// @brief Offset to parent node (0 = root)
    uint32_t parentOffset;
    
    /// @brief Keys: FastHash values for comparison
    std::array<uint64_t, MAX_KEYS> keys;
    
    /// @brief Children/Values:
    /// - Internal nodes: offsets to child nodes
    /// - Leaf nodes: offsets to WhitelistEntry
    std::array<uint32_t, MAX_CHILDREN> children;
    
    /// @brief Next leaf in linked list (for range scans)
    uint32_t nextLeaf;
    
    /// @brief Previous leaf in linked list
    uint32_t prevLeaf;
    
    /// @brief Default constructor - zero-initialize
    BPlusTreeNode() noexcept
        : isLeaf(true),
          reserved{0, 0, 0, 0, 0, 0, 0},
          keyCount(0u),
          parentOffset(0u),
          keys{},
          children{},
          nextLeaf(0u),
          prevLeaf(0u) {
        keys.fill(0u);
        children.fill(0u);
    }
    
    /// @brief Get valid key count (bounds-checked)
    [[nodiscard]] uint32_t GetKeyCount() const noexcept {
        return (std::min)(keyCount, static_cast<uint32_t>(MAX_KEYS));
    }
    
    /// @brief Get valid child count (bounds-checked)
    [[nodiscard]] uint32_t GetChildCount() const noexcept {
        return (std::min)(static_cast<uint32_t>(keyCount + 1u), static_cast<uint32_t>(MAX_CHILDREN));
    }
};
#pragma pack(pop)

static_assert(sizeof(BPlusTreeNode) <= PAGE_SIZE, "BPlusTreeNode must fit in one page");

// ============================================================================
// BLOOM FILTER SECTION HEADER
// ============================================================================

#pragma pack(push, 1)
struct BloomFilterHeader {
    uint32_t magic;                       ///< 0x424C4F4D = 'BLOM'
    uint32_t version;                     ///< Version 1
    uint64_t bitCount;                    ///< Number of bits in filter
    uint32_t hashFunctions;               ///< Number of hash functions
    uint32_t reserved;
    uint64_t elementCount;                ///< Estimated elements added
    double falsePositiveRate;             ///< Target false positive rate
    uint64_t dataOffset;                  ///< Offset to bit array
    uint64_t dataSize;                    ///< Size of bit array in bytes
    
    /// @brief Magic constant for bloom filter validation
    static constexpr uint32_t BLOOM_MAGIC = 0x424C4F4Du; // 'BLOM'
    
    /// @brief Default constructor - zero-initialize
    BloomFilterHeader() noexcept
        : magic(BLOOM_MAGIC),
          version(1u),
          bitCount(0u),
          hashFunctions(0u),
          reserved(0u),
          elementCount(0u),
          falsePositiveRate(0.0),
          dataOffset(0u),
          dataSize(0u)
    {}
    
    /// @brief Check if header is valid
    [[nodiscard]] bool IsValid() const noexcept {
        return magic == BLOOM_MAGIC && 
               version == 1u && 
               hashFunctions > 0u && 
               hashFunctions <= 32u &&  // Reasonable limit
               bitCount > 0u &&
               dataSize > 0u;
    }
};
#pragma pack(pop)

static_assert(sizeof(BloomFilterHeader) == 56, "BloomFilterHeader must be 56 bytes");

// ============================================================================
// DATABASE HEADER (First 4KB of database file)
// ============================================================================

#pragma pack(push, 1)
struct WhitelistDatabaseHeader {
    // ========================================================================
    // IDENTIFICATION (48 bytes)
    // ========================================================================
    
    /// @brief Magic number: WHITELIST_DB_MAGIC
    uint32_t magic;
    
    /// @brief Major version
    uint16_t versionMajor;
    
    /// @brief Minor version
    uint16_t versionMinor;
    
    /// @brief Database UUID for tracking and sync
    std::array<uint8_t, 16> databaseUuid;
    
    /// @brief Creation timestamp (Unix epoch)
    uint64_t creationTime;
    
    /// @brief Last update timestamp
    uint64_t lastUpdateTime;
    
    /// @brief Incremental build number
    uint64_t buildNumber;
    
    // ========================================================================
    // SECTION OFFSETS (All 4KB page-aligned) (160 bytes)
    // ========================================================================
    
    /// @brief Hash index section (B+Tree for hash lookups)
    uint64_t hashIndexOffset;
    uint64_t hashIndexSize;
    
    /// @brief Path index section (Trie for path matching)
    uint64_t pathIndexOffset;
    uint64_t pathIndexSize;
    
    /// @brief Certificate index section
    uint64_t certIndexOffset;
    uint64_t certIndexSize;
    
    /// @brief Publisher index section
    uint64_t publisherIndexOffset;
    uint64_t publisherIndexSize;
    
    /// @brief Entry data section
    uint64_t entryDataOffset;
    uint64_t entryDataSize;
    
    /// @brief Extended hash entries section
    uint64_t extendedHashOffset;
    uint64_t extendedHashSize;
    
    /// @brief String pool section
    uint64_t stringPoolOffset;
    uint64_t stringPoolSize;
    
    /// @brief Bloom filter section
    uint64_t bloomFilterOffset;
    uint64_t bloomFilterSize;
    
    /// @brief Metadata/audit section
    uint64_t metadataOffset;
    uint64_t metadataSize;
    
    /// @brief Path Trie bloom filter (for fast negative)
    uint64_t pathBloomOffset;
    uint64_t pathBloomSize;
    
    // ========================================================================
    // STATISTICS (64 bytes)
    // ========================================================================
    
    /// @brief Total entries by type
    uint64_t totalHashEntries;
    uint64_t totalPathEntries;
    uint64_t totalCertEntries;
    uint64_t totalPublisherEntries;
    uint64_t totalOtherEntries;
    
    /// @brief Lifetime statistics
    uint64_t totalLookups;
    uint64_t totalHits;
    uint64_t totalMisses;
    
    // ========================================================================
    // PERFORMANCE HINTS (32 bytes)
    // ========================================================================
    
    /// @brief Recommended cache size in MB
    uint32_t recommendedCacheSize;
    
    /// @brief Bloom filter expected elements
    uint32_t bloomExpectedElements;
    
    /// @brief Bloom filter target false positive rate (scaled by 1M)
    uint32_t bloomFalsePositiveRate;
    
    /// @brief Compression flags
    uint32_t compressionFlags;
    
    /// @brief Index optimization level (0-3)
    uint8_t indexOptLevel;
    
    /// @brief Reserved
    uint8_t reserved1[15];
    
    // ========================================================================
    // INTEGRITY (64 bytes)
    // ========================================================================
    
    /// @brief SHA-256 checksum of entire database (excluding this field)
    std::array<uint8_t, 32> sha256Checksum;
    
    /// @brief CRC32 of header (for quick validation)
    uint32_t headerCrc32;
    
    /// @brief Reserved
    uint8_t reserved2[28];
    
    // ========================================================================
    // RESERVED FOR FUTURE (Pad to exactly 4096 bytes)
    // ========================================================================
    
    std::array<uint8_t, 3728> reserved;
};
#pragma pack(pop)

static_assert(sizeof(WhitelistDatabaseHeader) == 4096, 
    "WhitelistDatabaseHeader must be exactly 4KB (4096 bytes)");

// ============================================================================
// ERROR HANDLING
// ============================================================================

/// @brief Error codes for whitelist operations
enum class WhitelistStoreError : uint32_t {
    Success = 0,
    
    // File errors
    FileNotFound = 1,
    FileAccessDenied = 2,
    FileLocked = 3,
    FileCorrupted = 4,
    
    // Format errors
    InvalidMagic = 10,
    InvalidVersion = 11,
    InvalidHeader = 12,
    InvalidChecksum = 13,
    InvalidSection = 14,
    
    // Memory errors
    OutOfMemory = 20,
    MappingFailed = 21,
    AddressSpaceExhausted = 22,
    
    // Data errors
    EntryNotFound = 30,
    DuplicateEntry = 31,
    InvalidEntry = 32,
    EntryExpired = 33,
    EntryRevoked = 34,
    
    // Index errors
    IndexCorrupted = 40,
    IndexFull = 41,
    IndexRebuildRequired = 42,
    
    // Operation errors
    ReadOnlyDatabase = 50,
    OperationTimeout = 51,
    OperationCancelled = 52,
    ConcurrentModification = 53,
    
    // Limit errors
    DatabaseTooLarge = 60,
    TooManyEntries = 61,
    PathTooLong = 62,
    StringTooLong = 63,
    
    // Unknown
    Unknown = 0xFFFFFFFF
};

/// @brief Detailed error information with Win32 error code
struct StoreError {
    WhitelistStoreError code{WhitelistStoreError::Success};
    DWORD win32Error{0};
    std::string message;
    
    /// @brief Check if operation succeeded
    [[nodiscard]] bool IsSuccess() const noexcept {
        return code == WhitelistStoreError::Success;
    }
    
    /// @brief Implicit bool conversion for if-checks
    [[nodiscard]] explicit operator bool() const noexcept {
        return IsSuccess();
    }
    
    /// @brief Factory for success result
    [[nodiscard]] static StoreError Success() noexcept {
        return StoreError{WhitelistStoreError::Success, 0, {}};
    }
    
    /// @brief Factory for Win32 error
    [[nodiscard]] static StoreError FromWin32(WhitelistStoreError code, DWORD win32Err) noexcept {
        StoreError err;
        err.code = code;
        err.win32Error = win32Err;
        return err;
    }
    
    /// @brief Factory with message
    [[nodiscard]] static StoreError WithMessage(WhitelistStoreError code, std::string msg) noexcept {
        StoreError err;
        err.code = code;
        err.win32Error = 0;
        err.message = std::move(msg);
        return err;
    }
    
    /// @brief Clear error state
    void Clear() noexcept {
        code = WhitelistStoreError::Success;
        win32Error = 0;
        message.clear();
    }
};

// ============================================================================
// MEMORY-MAPPED VIEW STRUCTURE
// ============================================================================

/// @brief Memory-mapped file view handle
struct MemoryMappedView {
    HANDLE fileHandle{INVALID_HANDLE_VALUE};
    HANDLE mappingHandle{INVALID_HANDLE_VALUE};
    void* baseAddress{nullptr};
    uint64_t fileSize{0};
    bool readOnly{true};
    
    /// @brief Check if view is valid and usable
    [[nodiscard]] bool IsValid() const noexcept {
        return baseAddress != nullptr && fileHandle != INVALID_HANDLE_VALUE;
    }
    
    /// @brief Get typed pointer at offset with bounds checking
    /// @tparam T Type to cast to (must be trivially copyable)
    /// @param offset Byte offset from base address
    /// @return Pointer to T or nullptr if bounds check fails
    template<typename T>
    [[nodiscard]] const T* GetAt(uint64_t offset) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        // Check for overflow and bounds
        if (offset > fileSize || sizeof(T) > fileSize - offset) {
            return nullptr;
        }
        if (baseAddress == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(
            static_cast<const uint8_t*>(baseAddress) + offset
        );
    }
    
    /// @brief Get mutable typed pointer at offset
    /// @tparam T Type to cast to (must be trivially copyable)
    /// @param offset Byte offset from base address
    /// @return Pointer to T or nullptr if read-only or bounds check fails
    template<typename T>
    [[nodiscard]] T* GetAtMutable(uint64_t offset) noexcept {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        if (readOnly) {
            return nullptr;
        }
        // Check for overflow and bounds
        if (offset > fileSize || sizeof(T) > fileSize - offset) {
            return nullptr;
        }
        if (baseAddress == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<T*>(
            static_cast<uint8_t*>(baseAddress) + offset
        );
    }
    
    /// @brief Get span of bytes at offset with bounds checking
    /// @param offset Byte offset from base address
    /// @param length Number of bytes to include in span
    /// @return Span of bytes or empty span if bounds check fails
    [[nodiscard]] std::span<const uint8_t> GetSpan(uint64_t offset, size_t length) const noexcept {
        // Check for overflow and bounds
        if (baseAddress == nullptr || offset > fileSize) {
            return {};
        }
        // Check if length would overflow or exceed bounds
        if (length > fileSize - offset) {
            return {};
        }
        return std::span<const uint8_t>(
            static_cast<const uint8_t*>(baseAddress) + offset, length
        );
    }
    
    /// @brief Get string view at offset with bounds checking
    /// @param offset Byte offset from base address
    /// @param length Number of characters in string
    /// @return String view or empty string_view if bounds check fails
    [[nodiscard]] std::string_view GetString(uint64_t offset, size_t length) const noexcept {
        // Check for overflow and bounds
        if (baseAddress == nullptr || offset > fileSize) {
            return {};
        }
        // Check if length would overflow or exceed bounds
        if (length > fileSize - offset) {
            return {};
        }
        return std::string_view(
            reinterpret_cast<const char*>(static_cast<const uint8_t*>(baseAddress) + offset),
            length
        );
    }
    
    /// @brief Get wide string view at offset with bounds checking
    /// @param offset Byte offset from base address
    /// @param charCount Number of wide characters in string
    /// @return Wide string view or empty wstring_view if bounds check fails
    [[nodiscard]] std::wstring_view GetWideString(uint64_t offset, size_t charCount) const noexcept {
        const size_t byteLen = charCount * sizeof(wchar_t);
        // Check for overflow in byte calculation
        if (charCount > 0u && byteLen / sizeof(wchar_t) != charCount) {
            return {}; // Overflow in size calculation
        }
        // Check for overflow and bounds
        if (baseAddress == nullptr || offset > fileSize) {
            return {};
        }
        if (byteLen > fileSize - offset) {
            return {};
        }
        return std::wstring_view(
            reinterpret_cast<const wchar_t*>(static_cast<const uint8_t*>(baseAddress) + offset),
            charCount
        );
    }
};

// ============================================================================
// QUERY OPTIONS
// ============================================================================

/// @brief Options for whitelist lookup operations
struct QueryOptions {
    /// @brief Maximum time to spend on lookup (milliseconds)
    uint32_t timeoutMs{1000};
    
    /// @brief Use query result cache
    bool useCache{true};
    
    /// @brief Check bloom filter first
    bool useBloomFilter{true};
    
    /// @brief Include expired entries in results
    bool includeExpired{false};
    
    /// @brief Include disabled entries in results
    bool includeDisabled{false};
    
    /// @brief Log this lookup
    bool logLookup{false};
    
    /// @brief Case-sensitive path matching
    bool caseSensitive{false};
};

// ============================================================================
// LOOKUP RESULT
// ============================================================================

/// @brief Result of a whitelist lookup operation
struct LookupResult {
    /// @brief Was the item found in whitelist?
    bool found{false};
    
    /// @brief Entry ID if found
    uint64_t entryId{0};
    
    /// @brief Entry type
    WhitelistEntryType type{WhitelistEntryType::Reserved};
    
    /// @brief Reason for whitelisting
    WhitelistReason reason{WhitelistReason::Custom};
    
    /// @brief Entry flags
    WhitelistFlags flags{WhitelistFlags::None};
    
    /// @brief Lookup time in nanoseconds
    uint64_t lookupTimeNs{0};
    
    /// @brief Was bloom filter used?
    bool bloomFilterChecked{false};
    
    /// @brief Was cache used?
    bool cacheHit{false};
    
    /// @brief Description (if requested)
    std::string description;
    
    /// @brief Policy ID
    uint32_t policyId{0};
    
    /// @brief Expiration time (0 = never)
    uint64_t expirationTime{0};
};

// ============================================================================
// STATISTICS
// ============================================================================

/// @brief Whitelist store statistics
struct WhitelistStatistics {
    // Entry counts
    uint64_t totalEntries{0};
    uint64_t hashEntries{0};
    uint64_t pathEntries{0};
    uint64_t certEntries{0};
    uint64_t publisherEntries{0};
    uint64_t activeEntries{0};
    uint64_t expiredEntries{0};
    
    // Lookup performance
    uint64_t totalLookups{0};
    uint64_t cacheHits{0};
    uint64_t cacheMisses{0};
    uint64_t bloomFilterHits{0};      // Bloom said "might exist"
    uint64_t bloomFilterRejects{0};   // Bloom said "definitely not"
    uint64_t indexLookups{0};
    uint64_t totalHits{0};
    uint64_t totalMisses{0};
    
    // Timing (nanoseconds)
    uint64_t avgLookupTimeNs{0};
    uint64_t minLookupTimeNs{0};
    uint64_t maxLookupTimeNs{0};
    uint64_t p99LookupTimeNs{0};     // 99th percentile
    
    // Memory
    uint64_t databaseSizeBytes{0};
    uint64_t mappedSizeBytes{0};
    uint64_t cacheMemoryBytes{0};
    uint64_t indexMemoryBytes{0};
    
    /// @brief Calculate cache hit rate (0.0 - 1.0)
    /// @return Cache hit rate or 0.0 if no lookups performed
    [[nodiscard]] double CacheHitRate() const noexcept {
        // Safe arithmetic: check for potential overflow before addition
        if (cacheHits > (std::numeric_limits<uint64_t>::max)() - cacheMisses) {
            return 0.0; // Overflow protection
        }
        const uint64_t total = cacheHits + cacheMisses;
        if (total == 0u) {
            return 0.0;
        }
        return static_cast<double>(cacheHits) / static_cast<double>(total);
    }
    
    /// @brief Calculate bloom filter effectiveness (rejection rate)
    /// @return Bloom filter rejection rate (0.0 - 1.0) or 0.0 if no checks performed
    [[nodiscard]] double BloomFilterEffectiveness() const noexcept {
        // Safe arithmetic: check for potential overflow before addition
        if (bloomFilterHits > (std::numeric_limits<uint64_t>::max)() - bloomFilterRejects) {
            return 0.0; // Overflow protection
        }
        const uint64_t total = bloomFilterHits + bloomFilterRejects;
        if (total == 0u) {
            return 0.0;
        }
        return static_cast<double>(bloomFilterRejects) / static_cast<double>(total);
    }
    
    /// @brief Reset all statistics to zero
    void Reset() noexcept {
        totalEntries = 0u;
        hashEntries = 0u;
        pathEntries = 0u;
        certEntries = 0u;
        publisherEntries = 0u;
        activeEntries = 0u;
        expiredEntries = 0u;
        totalLookups = 0u;
        cacheHits = 0u;
        cacheMisses = 0u;
        bloomFilterHits = 0u;
        bloomFilterRejects = 0u;
        indexLookups = 0u;
        totalHits = 0u;
        totalMisses = 0u;
        avgLookupTimeNs = 0u;
        minLookupTimeNs = 0u;
        maxLookupTimeNs = 0u;
        p99LookupTimeNs = 0u;
        databaseSizeBytes = 0u;
        mappedSizeBytes = 0u;
        cacheMemoryBytes = 0u;
        indexMemoryBytes = 0u;
    }
};

// ============================================================================
// UTILITY FUNCTIONS FORWARD DECLARATIONS
// ============================================================================

namespace Format {

/// @brief Validate database header integrity
[[nodiscard]] bool ValidateHeader(const WhitelistDatabaseHeader* header) noexcept;

/// @brief Compute CRC32 of header
[[nodiscard]] uint32_t ComputeHeaderCRC32(const WhitelistDatabaseHeader* header) noexcept;

/// @brief Compute SHA256 checksum of database
[[nodiscard]] bool ComputeDatabaseChecksum(
    const MemoryMappedView& view,
    std::array<uint8_t, 32>& outChecksum
) noexcept;

/// @brief Verify database integrity
[[nodiscard]] bool VerifyIntegrity(
    const MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Align offset to page boundary
[[nodiscard]] constexpr uint64_t AlignToPage(uint64_t offset) noexcept {
    return (offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

/// @brief Align offset to cache line
[[nodiscard]] constexpr size_t AlignToCacheLine(size_t offset) noexcept {
    return (offset + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);
}

/// @brief Get hash algorithm name
[[nodiscard]] const char* HashAlgorithmToString(HashAlgorithm algo) noexcept;

/// @brief Get entry type name
[[nodiscard]] const char* EntryTypeToString(WhitelistEntryType type) noexcept;

/// @brief Get reason name
[[nodiscard]] const char* ReasonToString(WhitelistReason reason) noexcept;

/// @brief Parse hash string to HashValue
[[nodiscard]] std::optional<HashValue> ParseHashString(
    const std::string& hashStr,
    HashAlgorithm algo
) noexcept;

/// @brief Format hash value to hex string
[[nodiscard]] std::string FormatHashString(const HashValue& hash);

/// @brief Calculate optimal cache size based on database size
[[nodiscard]] uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept;

/// @brief Normalize path for comparison (lowercase on Windows, forward slashes)
[[nodiscard]] std::wstring NormalizePath(std::wstring_view path);

/// @brief Check if path matches pattern
[[nodiscard]] bool PathMatchesPattern(
    std::wstring_view path,
    std::wstring_view pattern,
    PathMatchMode mode,
    bool caseSensitive = false
) noexcept;

} // namespace Format

namespace MemoryMapping {

/// @brief Open memory-mapped view of database file
[[nodiscard]] bool OpenView(
    const std::wstring& path,
    bool readOnly,
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Create new database file with header
[[nodiscard]] bool CreateDatabase(
    const std::wstring& path,
    uint64_t initialSize,
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Close memory-mapped view
void CloseView(MemoryMappedView& view) noexcept;

/// @brief Flush changes to disk
[[nodiscard]] bool FlushView(
    MemoryMappedView& view,
    StoreError& error
) noexcept;

/// @brief Extend database file size
[[nodiscard]] bool ExtendDatabase(
    MemoryMappedView& view,
    uint64_t newSize,
    StoreError& error
) noexcept;

} // namespace MemoryMapping

} // namespace Whitelist
} // namespace ShadowStrike
