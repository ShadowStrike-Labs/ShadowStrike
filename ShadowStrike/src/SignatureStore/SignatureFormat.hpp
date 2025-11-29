/*
 * ============================================================================
 * ShadowStrike SignatureFormat - ENTERPRISE-GRADE BINARY FORMAT
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-high performance binary format definitions for signature database
 * Designed for memory-mapped I/O with zero-copy reads
 * Target: < 1?s hash lookups, < 10ms pattern scans on 10MB files
 *
 * File Format Architecture:
 * ???????????????????????????????????????????????????????????????
 * ? FileHeader (4KB aligned)                                    ?
 * ???????????????????????????????????????????????????????????????
 * ? Hash Index Section (B+Tree, page-aligned)                  ?
 * ???????????????????????????????????????????????????????????????
 * ? Pattern Index Section (Optimized trie, cache-line aligned) ?
 * ???????????????????????????????????????????????????????????????
 * ? YARA Rules Section (Compiled bytecode)                     ?
 * ???????????????????????????????????????????????????????????????
 * ? Metadata Section (Compressed JSON)                         ?
 * ???????????????????????????????????????????????????????????????
 *
 * Performance Standards: CrowdStrike/Sophos enterprise quality
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <optional>
#include <span>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// CORE CONSTANTS & CONFIGURATION
// ============================================================================

// Magic numbers for format validation
constexpr uint32_t SIGNATURE_DB_MAGIC = 0x53535344;      // 'SSSD' = ShadowStrike Signature Database
constexpr uint16_t SIGNATURE_DB_VERSION_MAJOR = 1;
constexpr uint16_t SIGNATURE_DB_VERSION_MINOR = 0;

// Performance-critical alignment constants
constexpr size_t PAGE_SIZE = 4096;                        // Standard Windows page size
constexpr size_t CACHE_LINE_SIZE = 64;                    // CPU cache line (Intel/AMD)
constexpr size_t SECTOR_SIZE = 512;                       // Disk sector alignment

// Index configuration for optimal performance
constexpr size_t BTREE_ORDER = 128;                       // B+Tree node order (cache-optimized)
constexpr size_t PATTERN_TRIE_FANOUT = 256;              // Full byte range for pattern matching
constexpr size_t HASH_BUCKET_SIZE = 1024;                // Hash table bucket size

// Size limits
constexpr size_t MAX_SIGNATURE_NAME_LEN = 256;
constexpr size_t MAX_PATTERN_LENGTH = 8192;              // Max single pattern size
constexpr size_t MAX_YARA_RULE_SIZE = 1024 * 1024;       // 1MB per YARA rule
constexpr uint64_t MAX_DATABASE_SIZE = 16ULL * 1024 * 1024 * 1024; // 16GB database limit

// ============================================================================
// HASH TYPES & STRUCTURES
// ============================================================================

// Hash type enumeration
enum class HashType : uint8_t {
    MD5 = 0,
    SHA1 = 1,
    SHA256 = 2,
    SHA512 = 3,
    IMPHASH = 4,        // PE Import Hash
    SSDEEP = 5,         // Fuzzy hash
    TLSH = 6            // Trend Micro Locality Sensitive Hash
};

// Fixed-size hash storage (zero-copy compatible)
#pragma pack(push, 1)
struct HashValue {
    HashType type;
    uint8_t length;                                       // Actual hash length in bytes
    uint8_t reserved[2];                                  // Alignment padding
    std::array<uint8_t, 64> data;                        // Max hash size (SHA-512)

    // Zero-cost hash comparison (inlined, cache-friendly)
    [[nodiscard]] bool operator==(const HashValue& other) const noexcept {
        return type == other.type && 
               length == other.length && 
               std::memcmp(data.data(), other.data.data(), length) == 0;
    }

    [[nodiscard]] uint64_t FastHash() const noexcept {
        // FNV-1a hash for hash table indexing (ironically)
        uint64_t h = 14695981039346656037ULL;
        for (size_t i = 0; i < length; ++i) {
            h ^= data[i];
            h *= 1099511628211ULL;
        }
        return h;
    }
};
#pragma pack(pop)

static_assert(sizeof(HashValue) == 68, "HashValue must be 68 bytes for alignment");

// ============================================================================
// PATTERN STRUCTURES
// ============================================================================

// Pattern matching mode
enum class PatternMode : uint8_t {
    Exact = 0,          // Exact byte sequence match
    Wildcard = 1,       // With '?' wildcards
    Regex = 2,          // Regex pattern (slowest)
    ByteMask = 3        // Byte + mask pairs
};

// Pattern entry (memory-mapped structure)
#pragma pack(push, 1)
struct PatternEntry {
    PatternMode mode;
    uint8_t reserved[3];                                  // Alignment
    uint32_t patternLength;                               // Pattern data length
    uint32_t nameOffset;                                  // Offset to name string
    uint32_t dataOffset;                                  // Offset to pattern data
    uint32_t threatLevel;                                 // 0-100 severity score
    uint64_t signatureId;                                 // Unique signature ID
    uint64_t flags;                                       // Additional metadata flags

    // Performance hint: pattern entropy (higher = better for quick rejection)
    float entropy;

    // Statistics for optimization
    uint32_t hitCount;                                    // Detection count (heatmap)
    uint32_t lastUpdateTime;                              // Unix timestamp
};
#pragma pack(pop)

static_assert(sizeof(PatternEntry) == 48, "PatternEntry must be 48 bytes");

// ============================================================================
// YARA RULE STRUCTURES
// ============================================================================

// YARA rule metadata
#pragma pack(push, 1)
struct YaraRuleEntry {
    uint64_t ruleId;                                      // Unique rule identifier
    uint32_t nameOffset;                                  // Offset to rule name
    uint32_t sourceOffset;                                // Offset to YARA source code
    uint32_t compiledOffset;                              // Offset to compiled bytecode
    uint32_t compiledSize;                                // Compiled bytecode size
    uint32_t threatLevel;                                 // Severity: 0-100
    uint32_t flags;                                       // Compilation flags
    uint64_t lastModified;                                // Unix timestamp
    uint32_t dependencies;                                // Bitmask of rule dependencies
    uint32_t reserved;                                    // Future use
};
#pragma pack(pop)

static_assert(sizeof(YaraRuleEntry) == 48, "YaraRuleEntry must be 48 bytes");

// ============================================================================
// B+TREE INDEX STRUCTURES (for hash lookups)
// ============================================================================

#pragma pack(push, 1)
struct BPlusTreeNode {
    static constexpr size_t ORDER = BTREE_ORDER;
    static constexpr size_t MAX_KEYS = ORDER - 1;
    static constexpr size_t MAX_CHILDREN = ORDER;

    bool isLeaf;
    uint8_t reserved[7];                                  // Alignment to 8 bytes
    uint32_t keyCount;                                    // Number of keys in this node
    uint32_t parentOffset;                                // Offset to parent node (0 = root)
    
    // Keys: hash fast-hash values for quick comparison
    std::array<uint64_t, MAX_KEYS> keys;
    
    // Values/Children: 
    // - Internal nodes: offsets to child nodes
    // - Leaf nodes: offsets to signature data
    std::array<uint32_t, MAX_CHILDREN> children;
    
    // Leaf node linked list for sequential scans
    uint32_t nextLeaf;                                    // Next leaf in sequence
    uint32_t prevLeaf;                                    // Previous leaf in sequence
};
#pragma pack(pop)

// Ensure node fits in cache-friendly size (multiple cache lines)
static_assert(sizeof(BPlusTreeNode) <= PAGE_SIZE, "BPlusTreeNode too large");

// ============================================================================
// FILE HEADER (First 4KB of database)
// ============================================================================
//SignatureDatabaseHeader
#pragma pack(push,1)
struct SignatureDatabaseHeader {
    // Magic & version
    uint32_t magic;                                       // SIGNATURE_DB_MAGIC
    uint16_t versionMajor;
    uint16_t versionMinor;
    
    // Database identification
    std::array<uint8_t, 16> databaseUuid;                // UUID for database tracking
    uint64_t creationTime;                                // Unix timestamp
    uint64_t lastUpdateTime;                              // Unix timestamp
    uint64_t buildNumber;                                 // Incremental build ID
    
    // Section offsets (all 4KB aligned)
    uint64_t hashIndexOffset;                             // B+Tree root for hash index
    uint64_t hashIndexSize;
    uint64_t patternIndexOffset;                          // Pattern trie root
    uint64_t patternIndexSize;
    uint64_t yaraRulesOffset;                             // YARA rules section
    uint64_t yaraRulesSize;
    uint64_t metadataOffset;                              // JSON metadata
    uint64_t metadataSize;
    uint64_t stringPoolOffset;                            // String pool (names, etc.)
    uint64_t stringPoolSize;
    
    // Statistics
    uint64_t totalHashes;                                 // Total hash signatures
    uint64_t totalPatterns;                               // Total byte patterns
    uint64_t totalYaraRules;                              // Total YARA rules
    uint64_t totalDetections;                             // Lifetime detection count
    
    // Performance hints
    uint32_t recommendedCacheSize;                        // Suggested cache size in MB
    uint32_t compressionFlags;                            // Compression algorithms used
    
    // Integrity
    std::array<uint8_t, 32> sha256Checksum;              // SHA-256 of entire database
    
    // Reserved for future extensions
    std::array<uint8_t, 3840> reserved;                   // Pad to 4KB
};

#pragma pack(pop)

static_assert(sizeof(SignatureDatabaseHeader) == 4040,
    "Header must be exactly 4KB");

// ============================================================================
// AHO-CORASICK TRIE BINARY SERIALIZATION FORMAT
// ============================================================================


#pragma pack(push,1)

// Binary representation of a single Trie node on disk
struct TrieNodeBinary {
    // Header (16 bytes)
    uint32_t magic;                      // 0x54524945 = 'TRIE' for validation
    uint16_t version;                    // Version 1
    uint16_t reserved;                   // Alignment padding

    // Node structure (256 + 4 + 4 + 4 + 4 + 4 = 280 bytes)
    std::array<uint32_t, 256> childOffsets;  // Child node disk offsets (or 0 if null)
    uint32_t failureLinkOffset;          // Failure link disk offset (0 = root/self)
    uint32_t outputCount;                // Number of pattern IDs in outputs
    uint32_t outputOffset;               // Disk offset to output pattern IDs (if > 0)
    uint32_t depth;                      // Node depth in trie (0 = root)
    uint32_t reserved2;                  // Future use

    // Total: 16 + 280 + 20 = 316 bytes (will be padded to 320 for alignment)
};

#pragma pack(pop)

static_assert(sizeof(TrieNodeBinary) == 1052, "TrieNodeBinary must be exactly 316 bytes");

// ============================================================================
// TRIE INDEX STRUCTURE (Header of entire trie section)
// ============================================================================

#pragma pack(push, 1)

struct TrieIndexHeader {
    uint32_t magic;                      // 0x54524945 = 'TRIE'
    uint32_t version;                    // 1
    uint64_t totalNodes;                 // Total number of nodes in trie
    uint64_t totalPatterns;              // Total unique patterns indexed
    uint64_t rootNodeOffset;             // Offset to root TrieNodeBinary
    uint64_t outputPoolOffset;           // Offset to start of pattern ID pool
    uint64_t outputPoolSize;             // Total bytes in output pool
    uint32_t maxNodeDepth;               // Maximum depth reached in trie
    uint32_t flags;                      // Bit flags: 0x01 = Aho-Corasick optimized
    uint64_t checksumCRC64;              // CRC64 of entire trie section (for integrity)
    uint64_t reserved[4];                // Future use (32 bytes total)
};

#pragma pack(pop)

static_assert(sizeof(TrieIndexHeader) == 96, "TrieIndexHeader must be exactly 96 bytes");


// ============================================================================
// DETECTION RESULT STRUCTURES
// ============================================================================

// Detection severity levels
enum class ThreatLevel : uint8_t {
    Info = 0,           // Informational
    Low = 25,           // Low threat
    Medium = 50,        // Medium threat
    High = 75,          // High threat
    Critical = 100      // Critical threat
};

// Detection result
struct DetectionResult {
    uint64_t signatureId;                                 // Matched signature ID
    std::string signatureName;                            // Human-readable name
    ThreatLevel threatLevel;                              // Severity
    uint64_t fileOffset;                                  // Where in file (for patterns)
    std::string description;                              // Threat description
    std::vector<std::string> tags;                        // Metadata tags
    uint64_t matchTimestamp;                              // Detection time (us precision)
    
    // Performance metrics
    uint64_t matchTimeNanoseconds;                        // Time to match (profiling)
};

// ============================================================================
// MEMORY-MAPPED FILE HANDLE
// ============================================================================

struct MemoryMappedView {
    HANDLE fileHandle{INVALID_HANDLE_VALUE};
    HANDLE mappingHandle{INVALID_HANDLE_VALUE};
    void* baseAddress{nullptr};
    uint64_t fileSize{0};
    bool readOnly{true};
    
    [[nodiscard]] bool IsValid() const noexcept {
        return baseAddress != nullptr && fileHandle != INVALID_HANDLE_VALUE;
    }
    
    template<typename T>
    [[nodiscard]] const T* GetAt(uint64_t offset) const noexcept {
        if (offset + sizeof(T) > fileSize) return nullptr;
        return reinterpret_cast<const T*>(
            static_cast<const uint8_t*>(baseAddress) + offset
        );
    }
    
    template<typename T>
    [[nodiscard]] T* GetAtMutable(uint64_t offset) noexcept {
        if (readOnly || offset + sizeof(T) > fileSize) return nullptr;
        return reinterpret_cast<T*>(
            static_cast<uint8_t*>(baseAddress) + offset
        );
    }
    
    [[nodiscard]] std::span<const uint8_t> GetSpan(uint64_t offset, size_t length) const noexcept {
        if (offset + length > fileSize) return {};
        return std::span<const uint8_t>(
            static_cast<const uint8_t*>(baseAddress) + offset, length
        );
    }
};

// ============================================================================
// ERROR HANDLING
// ============================================================================

enum class SignatureStoreError : uint32_t {
    Success = 0,
    FileNotFound,
    InvalidFormat,
    CorruptedDatabase,
    VersionMismatch,
    AccessDenied,
    OutOfMemory,
    InvalidSignature,
    DuplicateEntry,
    IndexCorrupted,
    MappingFailed,
    ChecksumMismatch,
    TooLarge,
    Unknown = 0xFFFFFFFF
};

struct StoreError {
    SignatureStoreError code{SignatureStoreError::Success};
    DWORD win32Error{0};
    std::string message;
    
    [[nodiscard]] bool IsSuccess() const noexcept {
        return code == SignatureStoreError::Success;
    }
    
    [[nodiscard]] explicit operator bool() const noexcept {
        return IsSuccess();
    }
};

// ============================================================================
// QUERY & SEARCH OPTIONS
// ============================================================================

struct QueryOptions {
    bool exactMatch{true};                                // Exact or fuzzy matching
    uint32_t maxResults{1000};                            // Maximum results to return
    uint32_t timeoutMilliseconds{5000};                   // Query timeout
    bool enableCache{true};                               // Use query result cache
    ThreatLevel minThreatLevel{ThreatLevel::Info};       // Filter by severity
};

// ============================================================================
// STATISTICS & MONITORING
// ============================================================================

struct StoreStatistics {
    uint64_t totalQueries{0};
    uint64_t cacheHits{0};
    uint64_t cacheMisses{0};
    uint64_t totalDetections{0};
    uint64_t averageQueryTimeMicroseconds{0};
    uint64_t peakMemoryUsageBytes{0};
    uint64_t databaseSizeBytes{0};
    
    [[nodiscard]] double CacheHitRate() const noexcept {
        uint64_t total = cacheHits + cacheMisses;
        return total > 0 ? (static_cast<double>(cacheHits) / total) : 0.0;
    }
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace Format {

// Validate database header integrity
[[nodiscard]] bool ValidateHeader(const SignatureDatabaseHeader* header) noexcept;

// Calculate optimal cache size based on database size
[[nodiscard]] uint32_t CalculateOptimalCacheSize(uint64_t dbSizeBytes) noexcept;

// Align offset to page boundary
[[nodiscard]] constexpr uint64_t AlignToPage(uint64_t offset) noexcept {
    return (offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

// Align offset to cache line
[[nodiscard]] constexpr size_t AlignToCacheLine(size_t offset) noexcept {
    return (offset + CACHE_LINE_SIZE - 1) & ~(CACHE_LINE_SIZE - 1);
}

// Convert hash type to string
[[nodiscard]] const char* HashTypeToString(HashType type) noexcept;

// Parse hash string to HashValue
[[nodiscard]] std::optional<HashValue> ParseHashString(
    const std::string& hashStr, HashType type) noexcept;

// Format hash value as hex string
[[nodiscard]] std::string FormatHashString(const HashValue& hash);

} // namespace Format
namespace MemoryMapping {

    // Open memory-mapped view
    [[nodiscard]] bool OpenView(
        const std::wstring& path,
        bool readOnly,
        MemoryMappedView& view,
        StoreError& error
    ) noexcept;

    // Close memory-mapped view
    void CloseView(MemoryMappedView& view) noexcept;

    // Flush view to disk
    [[nodiscard]] bool FlushView(
        MemoryMappedView& view,
        StoreError& error
    ) noexcept;

} // namespace MemoryMapping

} // namespace SignatureStore
} // namespace ShadowStrike
