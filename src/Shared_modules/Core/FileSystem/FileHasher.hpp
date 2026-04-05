/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike Core FileSystem - FILE HASHER (The Fingerprinter)
 * ============================================================================
 *
 * @file FileHasher.hpp
 * @brief Enterprise-grade high-performance multi-algorithm hashing engine.
 *
 * Chief orchestrator for all file fingerprinting in the ShadowStrike NGAV
 * platform. Computes cryptographic and fuzzy hashes in a TRUE single-pass
 * architecture, enabling sub-millisecond threat identification against
 * nation-state APTs.
 *
 * Key Capabilities:
 * =================
 * 1. CRYPTOGRAPHIC HASHES (single-pass via streaming BCrypt hashers)
 *    - MD5 (legacy compatibility / IOC matching)
 *    - SHA-1 (legacy compatibility)
 *    - SHA-256 (primary identification)
 *    - SHA-512
 *    - SHA-3 256/512 (Keccak, Win10 1903+)
 *
 * 2. FUZZY / SIMILARITY HASHES
 *    - CTPH (context-triggered piecewise hashing via FuzzyHasher)
 *    - TLSH (locality-sensitive hashing via libtlsh)
 *    - imphash (PE import table hash via PEParser)
 *    - authentihash (PE authenticode hash via PEParser)
 *
 * 3. PARTIAL HASHING
 *    - Header hash (first 4KB)
 *    - PE section hashes (via PEParser)
 *    - Rich header hash
 *
 * 4. PERFORMANCE
 *    - TRUE single-pass multi-hash (one file read, N hashers)
 *    - Hardware acceleration detection (AES-NI, SHA-NI)
 *    - Parallel batch hashing via ThreadPool
 *    - Memory-mapped files for large binaries
 *    - LRU cache with TTL and file-modification invalidation
 *
 * Integration Points:
 * ===================
 * - ScanEngine: Primary hash provider for the 9-stage scan pipeline
 * - HashStore: Sub-microsecond known-malware hash lookups
 * - ThreatIntel: IOC hash matching across 5-tier cache
 * - FileReputation: Hybrid reputation engine queries
 * - FilterConnection: Kernel minifilter scan request servicing
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see HashStore.hpp for hash database
 * @see ThreatIntelLookup.hpp for IOC matching
 * @see FileReputation.hpp for reputation lookup
 * @see PEParser.hpp for PE binary analysis
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CacheManager.hpp"
#include "../../Utils/ThreadPool.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <future>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class FileHasherImpl;

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileHasherConstants {

    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 1;
    constexpr uint32_t VERSION_PATCH = 0;

    // Hash digest sizes (bytes)
    constexpr size_t MD5_SIZE      = 16;
    constexpr size_t SHA1_SIZE     = 20;
    constexpr size_t SHA256_SIZE   = 32;
    constexpr size_t SHA512_SIZE   = 64;
    constexpr size_t SHA3_256_SIZE = 32;
    constexpr size_t SHA3_512_SIZE = 64;

    // I/O tuning
    constexpr size_t DEFAULT_BUFFER_SIZE      = 64 * 1024;           // 64 KB per read
    constexpr size_t LARGE_FILE_THRESHOLD     = 100 * 1024 * 1024;   // 100 MB → mmap
    constexpr size_t HEADER_HASH_SIZE         = 4096;                // 4 KB

    // Security caps
    constexpr uint64_t MAX_HASH_FILE_SIZE     = 4ULL * 1024 * 1024 * 1024;  // 4 GB
    constexpr size_t   MAX_HEADER_READ_SIZE   = 16 * 1024 * 1024;           // 16 MB

    // Cache
    constexpr size_t   DEFAULT_CACHE_SIZE     = 100000;
    constexpr uint32_t DEFAULT_CACHE_TTL_HOURS = 24;

}  // namespace FileHasherConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum HashAlgorithm
 * @brief Bitmask of supported hash algorithms.
 */
enum class HashAlgorithm : uint16_t {
    None = 0,

    // Cryptographic
    MD5        = 0x0001,
    SHA1       = 0x0002,
    SHA256     = 0x0004,
    SHA512     = 0x0008,
    SHA3_256   = 0x0010,
    SHA3_512   = 0x0020,

    // Fuzzy / similarity
    FUZZY       = 0x0100,
    TLSH        = 0x0200,
    IMPHASH     = 0x0400,
    AUTHENTIHASH = 0x0800,

    // Composite presets
    All        = 0x0FFF,
    AllCrypto  = MD5 | SHA1 | SHA256 | SHA512 | SHA3_256 | SHA3_512,
    AllFuzzy   = FUZZY | TLSH | IMPHASH | AUTHENTIHASH,
    Standard   = MD5 | SHA1 | SHA256,
    Modern     = SHA256 | SHA3_256 | FUZZY
};

// Bitwise operators (defined once — NOT duplicated in .cpp)
[[nodiscard]] constexpr HashAlgorithm operator|(HashAlgorithm a, HashAlgorithm b) noexcept {
    return static_cast<HashAlgorithm>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}
[[nodiscard]] constexpr HashAlgorithm operator&(HashAlgorithm a, HashAlgorithm b) noexcept {
    return static_cast<HashAlgorithm>(static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}
[[nodiscard]] constexpr HashAlgorithm operator^(HashAlgorithm a, HashAlgorithm b) noexcept {
    return static_cast<HashAlgorithm>(static_cast<uint16_t>(a) ^ static_cast<uint16_t>(b));
}
[[nodiscard]] constexpr HashAlgorithm operator~(HashAlgorithm a) noexcept {
    return static_cast<HashAlgorithm>(~static_cast<uint16_t>(a));
}
[[nodiscard]] constexpr bool HasFlag(HashAlgorithm value, HashAlgorithm flag) noexcept {
    return (static_cast<uint16_t>(value) & static_cast<uint16_t>(flag)) != 0;
}

/**
 * @enum HashFormat
 * @brief Output format for hash strings.
 */
enum class HashFormat : uint8_t {
    Hex      = 0,
    HexUpper = 1,
    Base64   = 2,
    Raw      = 3
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct HashResult
 * @brief Single hash computation result.
 */
struct alignas(32) HashResult {
    HashAlgorithm algorithm{ HashAlgorithm::None };
    std::vector<uint8_t> hash;
    std::string hashHex;
    bool valid{ false };
    std::string errorMessage;
};

/**
 * @struct FileHashes
 * @brief Complete file hash collection — returned by ComputeAll().
 */
struct FileHashes {
    // Cryptographic digests (raw bytes)
    std::array<uint8_t, FileHasherConstants::MD5_SIZE>      md5{};
    std::array<uint8_t, FileHasherConstants::SHA1_SIZE>     sha1{};
    std::array<uint8_t, FileHasherConstants::SHA256_SIZE>   sha256{};
    std::array<uint8_t, FileHasherConstants::SHA512_SIZE>   sha512{};
    std::array<uint8_t, FileHasherConstants::SHA3_256_SIZE> sha3_256{};
    std::array<uint8_t, FileHasherConstants::SHA3_512_SIZE> sha3_512{};

    // Hex string representations
    std::string md5Hex;
    std::string sha1Hex;
    std::string sha256Hex;
    std::string sha512Hex;
    std::string sha3_256Hex;
    std::string sha3_512Hex;

    // Fuzzy / similarity hashes
    std::string fuzzyHash;
    std::string tlsh;
    std::string imphash;
    std::string authentihash;

    // Metadata
    uint64_t fileSize{ 0 };
    std::wstring filePath;
    std::chrono::system_clock::time_point computedTime;
    std::chrono::milliseconds computeDuration{ 0 };

    // Per-algorithm validity flags
    bool hasMD5{ false };
    bool hasSHA1{ false };
    bool hasSHA256{ false };
    bool hasSHA512{ false };
    bool hasSHA3_256{ false };
    bool hasSHA3_512{ false };
    bool hasFuzzyHash{ false };
    bool hasTLSH{ false };
    bool hasImpHash{ false };
    bool hasAuthentihash{ false };

    // Error tracking
    bool hasErrors{ false };
    std::vector<std::string> errors;

    // Convenience helpers
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @struct PartialHashes
 * @brief Partial / header / section hashes.
 */
struct PartialHashes {
    std::string headerSHA256;
    std::unordered_map<std::string, std::string> sectionHashes;
    std::string richHeaderHash;
    std::unordered_map<std::string, std::string> resourceHashes;
};

/**
 * @struct HashComparison
 * @brief Result of comparing two FileHashes collections.
 */
struct HashComparison {
    // Per-algorithm exact match flags
    bool md5Match{ false };
    bool sha1Match{ false };
    bool sha256Match{ false };
    bool sha512Match{ false };
    bool sha3_256Match{ false };
    bool sha3_512Match{ false };

    // Similarity metrics
    double fuzzySimilarity{ 0.0 };   // 0.0–100.0 (higher = more similar)
    uint32_t tlshDistance{ UINT32_MAX };  // lower = more similar

    [[nodiscard]] bool IsMatch() const noexcept;
    [[nodiscard]] bool IsSimilar() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @struct FileHasherConfig
 * @brief Configuration for the FileHasher engine.
 */
struct FileHasherConfig {
    // Algorithm selection
    HashAlgorithm defaultAlgorithms{ HashAlgorithm::Standard };
    bool computeFuzzyHashes{ true };
    bool computePEHashes{ true };

    // I/O performance
    size_t   bufferSize{ FileHasherConstants::DEFAULT_BUFFER_SIZE };
    uint64_t largeFileThreshold{ FileHasherConstants::LARGE_FILE_THRESHOLD };
    bool     useMemoryMapping{ true };
    bool     useHardwareAcceleration{ true };
    uint32_t workerThreads{ 4 };

    // Caching
    bool     enableCache{ true };
    size_t   maxCacheSize{ FileHasherConstants::DEFAULT_CACHE_SIZE };
    uint32_t cacheTTLHours{ FileHasherConstants::DEFAULT_CACHE_TTL_HOURS };

    // Factory presets
    [[nodiscard]] static FileHasherConfig CreateDefault() noexcept;
    [[nodiscard]] static FileHasherConfig CreateHighPerformance() noexcept;
    [[nodiscard]] static FileHasherConfig CreateComprehensive() noexcept;
    [[nodiscard]] static FileHasherConfig CreateMinimal() noexcept;
};

/**
 * @struct FileHasherStatistics
 * @brief Public statistics snapshot (copyable — no atomics).
 *
 * Returned by GetStatistics(); the internal implementation uses
 * atomic counters and snapshots into this struct.
 */
struct FileHasherStatistics {
    uint64_t filesHashed{ 0 };
    uint64_t bytesProcessed{ 0 };
    uint64_t cacheHits{ 0 };
    uint64_t cacheMisses{ 0 };

    uint64_t md5Computed{ 0 };
    uint64_t sha1Computed{ 0 };
    uint64_t sha256Computed{ 0 };
    uint64_t sha512Computed{ 0 };
    uint64_t fuzzyHashComputed{ 0 };
    uint64_t tlshComputed{ 0 };
    uint64_t imphashComputed{ 0 };

    uint64_t averageTimeUs{ 0 };
    uint64_t maxTimeUs{ 0 };
    uint64_t hardwareAccelUsed{ 0 };
    uint64_t memoryMappedFiles{ 0 };

    std::chrono::steady_clock::time_point startTime;
};

/**
 * @struct VersionInfo
 * @brief FileHasher build / dependency version information.
 */
struct VersionInfo {
    std::string hasherVersion;
    std::string fuzzyHasherVersion;
    std::string tlshVersion;
    std::chrono::system_clock::time_point lastUpdate;
};

/**
 * @struct HardwareInfo
 * @brief CPU hardware acceleration capabilities.
 */
struct HardwareInfo {
    bool hasAESNI{ false };
    bool hasSHANI{ false };
    bool useHardwareAccel{ false };
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

using HashCallback     = std::function<void(const FileHashes& hashes)>;
using ProgressCallback = std::function<void(uint64_t bytesProcessed, uint64_t totalBytes)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileHasher
 * @brief Enterprise-grade file hashing engine (Meyers' Singleton, PIMPL).
 *
 * Thread Safety: All public methods are thread-safe.
 */
class FileHasher {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static FileHasher& Instance();

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize(const FileHasherConfig& config);
    bool Initialize();
    void Shutdown() noexcept;

    [[nodiscard]] bool IsInitialized() const noexcept;
    void UpdateConfig(const FileHasherConfig& config);
    [[nodiscard]] FileHasherConfig GetConfig() const;

    // ========================================================================
    // COMPLETE HASH COMPUTATION
    // ========================================================================

    [[nodiscard]] FileHashes ComputeAll(
        const std::wstring& filePath,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    [[nodiscard]] FileHashes ComputeAll(
        std::span<const uint8_t> buffer,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    [[nodiscard]] std::future<FileHashes> ComputeAllAsync(
        const std::wstring& filePath,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    void ComputeAllAsync(
        const std::wstring& filePath,
        HashCallback callback,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    [[nodiscard]] std::vector<FileHashes> ComputeBatch(
        const std::vector<std::wstring>& filePaths,
        HashAlgorithm algorithms = HashAlgorithm::Standard,
        ProgressCallback progressCallback = nullptr);

    // ========================================================================
    // INDIVIDUAL HASH ALGORITHMS — file path
    // ========================================================================

    [[nodiscard]] std::string ComputeMD5(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeSHA1(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeSHA256(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeSHA512(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeSHA3_256(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeSHA3_512(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeFuzzyHash(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeTLSH(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeImpHash(const std::wstring& filePath);
    [[nodiscard]] std::string ComputeAuthentihash(const std::wstring& filePath);

    // ========================================================================
    // INDIVIDUAL HASH ALGORITHMS — buffer
    // ========================================================================

    [[nodiscard]] std::string ComputeMD5(std::span<const uint8_t> buffer);
    [[nodiscard]] std::string ComputeSHA256(std::span<const uint8_t> buffer);

    // ========================================================================
    // PARTIAL HASHING
    // ========================================================================

    [[nodiscard]] std::string ComputeHeaderHash(
        const std::wstring& filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256,
        size_t headerSize = FileHasherConstants::HEADER_HASH_SIZE);

    [[nodiscard]] std::unordered_map<std::string, std::string> ComputeSectionHashes(
        const std::wstring& filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256);

    [[nodiscard]] PartialHashes ComputePartialHashes(const std::wstring& filePath);

    // ========================================================================
    // HASH COMPARISON
    // ========================================================================

    [[nodiscard]] HashComparison Compare(
        const FileHashes& hashes1,
        const FileHashes& hashes2) const;

    [[nodiscard]] double CompareFuzzyHash(
        std::string_view hash1,
        std::string_view hash2) const noexcept;

    [[nodiscard]] uint32_t ComputeTLSHDistance(
        std::string_view tlsh1,
        std::string_view tlsh2) const noexcept;

    [[nodiscard]] bool MatchesAny(
        const FileHashes& hashes,
        const std::vector<FileHashes>& candidates) const;

    [[nodiscard]] std::optional<size_t> FindBestMatch(
        const FileHashes& hashes,
        const std::vector<FileHashes>& candidates,
        double minSimilarity = 50.0) const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::optional<FileHashes> GetCached(const std::wstring& filePath) const;
    void ClearCache() noexcept;
    void InvalidateCache(const std::wstring& filePath);
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterHashCallback(HashCallback callback);
    bool UnregisterHashCallback(uint64_t callbackId);

    [[nodiscard]] uint64_t RegisterProgressCallback(ProgressCallback callback);
    bool UnregisterProgressCallback(uint64_t callbackId);

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] std::string ToHexString(
        std::span<const uint8_t> hash,
        HashFormat format = HashFormat::Hex) const;

    [[nodiscard]] std::vector<uint8_t> FromHexString(std::string_view hexString) const;

    [[nodiscard]] bool ValidateHashFormat(
        std::string_view hash,
        HashAlgorithm algorithm) const;

    // ========================================================================
    // HARDWARE & DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool HasHardwareAcceleration() const noexcept;
    [[nodiscard]] std::vector<std::string> GetHardwareFeatures() const;

    [[nodiscard]] FileHasherStatistics GetStatistics() const;
    void ResetStatistics() noexcept;

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] VersionInfo  GetVersionInfo() const;
    [[nodiscard]] HardwareInfo GetHardwareInfo() const;

private:
    FileHasher();
    ~FileHasher();

    FileHasher(const FileHasher&) = delete;
    FileHasher& operator=(const FileHasher&) = delete;

    std::unique_ptr<FileHasherImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
