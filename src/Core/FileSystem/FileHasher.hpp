/**
 * ============================================================================
 * ShadowStrike Core FileSystem - FILE HASHER (The Fingerprinter)
 * ============================================================================
 *
 * @file FileHasher.hpp
 * @brief Enterprise-grade high-performance multi-algorithm hashing engine.
 *
 * This module provides comprehensive file hashing capabilities with multiple
 * algorithms computed in a single pass for maximum performance, supporting
 * both cryptographic and fuzzy hashing for malware analysis.
 *
 * Key Capabilities:
 * =================
 * 1. CRYPTOGRAPHIC HASHES
 *    - MD5 (legacy compatibility)
 *    - SHA-1 (legacy compatibility)
 *    - SHA-256 (primary)
 *    - SHA-512
 *    - SHA-3 (256/512)
 *
 * 2. FUZZY HASHES
 *    - CTPH fuzzy (context-triggered piecewise)
 *    - TLSH (locality-sensitive)
 *    - imphash (import hash)
 *    - authentihash (PE hash)
 *
 * 3. PARTIAL HASHING
 *    - Header hash (first 4KB)
 *    - Section hashes
 *    - Stream hashes
 *
 * 4. PERFORMANCE
 *    - Single-pass multi-hash
 *    - Hardware acceleration (AES-NI, SHA-NI)
 *    - Async/parallel hashing
 *    - Memory-mapped files
 *
 * Hashing Architecture:
 * =====================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         FileHasher                                  │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ CryptoEngine │  │ FuzzyEngine  │  │    StreamProcessor       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - MD5        │  │ - CTPH fuzzy     │  │ - Chunked reading        │  │
 *   │  │ - SHA-1/256  │  │ - TLSH       │  │ - Memory mapping         │  │
 *   │  │ - SHA-3      │  │ - imphash    │  │ - Async I/O              │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ HWAccelerator│  │ AsyncManager │  │    HashCache             │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - AES-NI     │  │ - Thread pool│  │ - LRU cache              │  │
 *   │  │ - SHA-NI     │  │ - Futures    │  │ - Invalidation           │  │
 *   │  │ - ARM crypto │  │ - Callbacks  │  │ - Persistence            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - HashStore: Hash database lookup
 * - FileReputation: Reputation queries
 * - ThreatIntel: IOC matching
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see HashStore.hpp for hash database
 * @see FileReputation.hpp for reputation lookup
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/HashUtils.hpp"          // Core hash algorithms
#include "../../Utils/FileUtils.hpp"          // File reading, memory mapping
#include "../../Utils/CacheManager.hpp"       // Hash caching
#include "../../Utils/ThreadPool.hpp"         // Async hashing

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
class FileHasherImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileHasherConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Hash sizes
    constexpr size_t MD5_SIZE = 16;
    constexpr size_t SHA1_SIZE = 20;
    constexpr size_t SHA256_SIZE = 32;
    constexpr size_t SHA512_SIZE = 64;
    constexpr size_t SHA3_256_SIZE = 32;
    constexpr size_t SHA3_512_SIZE = 64;

    // Performance
    constexpr size_t DEFAULT_BUFFER_SIZE = 64 * 1024;      // 64KB
    constexpr size_t LARGE_FILE_THRESHOLD = 100 * 1024 * 1024;  // 100MB
    constexpr size_t HEADER_HASH_SIZE = 4096;              // 4KB

    // Cache
    constexpr size_t DEFAULT_CACHE_SIZE = 100000;
    constexpr uint32_t DEFAULT_CACHE_TTL_HOURS = 24;

}  // namespace FileHasherConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum HashAlgorithm
 * @brief Supported hash algorithms.
 */
enum class HashAlgorithm : uint16_t {
    None = 0,

    // Cryptographic
    MD5 = 0x0001,
    SHA1 = 0x0002,
    SHA256 = 0x0004,
    SHA512 = 0x0008,
    SHA3_256 = 0x0010,
    SHA3_512 = 0x0020,

    // Fuzzy
    FUZZY = 0x0100,
    TLSH = 0x0200,
    IMPHASH = 0x0400,
    AUTHENTIHASH = 0x0800,

    // Composite
    All = 0x0FFF,
    AllCrypto = MD5 | SHA1 | SHA256 | SHA512 | SHA3_256 | SHA3_512,
    AllFuzzy = FUZZY | TLSH | IMPHASH | AUTHENTIHASH,
    Standard = MD5 | SHA1 | SHA256,
    Modern = SHA256 | SHA3_256 | FUZZY
};

// Enable bitwise operations
inline HashAlgorithm operator|(HashAlgorithm a, HashAlgorithm b) {
    return static_cast<HashAlgorithm>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}
inline HashAlgorithm operator&(HashAlgorithm a, HashAlgorithm b) {
    return static_cast<HashAlgorithm>(static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}
inline bool HasFlag(HashAlgorithm value, HashAlgorithm flag) {
    return (static_cast<uint16_t>(value) & static_cast<uint16_t>(flag)) != 0;
}

/**
 * @enum HashFormat
 * @brief Output format for hash strings.
 */
enum class HashFormat : uint8_t {
    Hex = 0,                       // Lowercase hexadecimal
    HexUpper = 1,                  // Uppercase hexadecimal
    Base64 = 2,                    // Base64 encoded
    Raw = 3                        // Raw bytes
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
 * @brief Complete file hash collection.
 */
struct alignas(256) FileHashes {
    // Cryptographic hashes
    std::array<uint8_t, FileHasherConstants::MD5_SIZE> md5{ 0 };
    std::array<uint8_t, FileHasherConstants::SHA1_SIZE> sha1{ 0 };
    std::array<uint8_t, FileHasherConstants::SHA256_SIZE> sha256{ 0 };
    std::array<uint8_t, FileHasherConstants::SHA512_SIZE> sha512{ 0 };
    std::array<uint8_t, FileHasherConstants::SHA3_256_SIZE> sha3_256{ 0 };
    std::array<uint8_t, FileHasherConstants::SHA3_512_SIZE> sha3_512{ 0 };

    // String representations
    std::string md5Hex;
    std::string sha1Hex;
    std::string sha256Hex;
    std::string sha512Hex;
    std::string sha3_256Hex;
    std::string sha3_512Hex;

    // Fuzzy hashes
    std::string fuzzyHash;
    std::string tlsh;
    std::string imphash;
    std::string authentihash;

    // Metadata
    uint64_t fileSize{ 0 };
    std::wstring filePath;
    std::chrono::system_clock::time_point computedTime;
    std::chrono::milliseconds computeDuration{ 0 };

    // Validity flags
    bool hasMD5{ false };
    bool hasSHA1{ false };
    bool hasSHA256{ false };
    bool hasSHA512{ false };
    bool hasSHA3{ false };
    bool hasFuzzyHash{ false };
    bool hasTLSH{ false };
    bool hasImpHash{ false };
    bool hasAuthentihash{ false };

    // Error handling
    bool hasErrors{ false };
    std::vector<std::string> errors;
};

/**
 * @struct PartialHashes
 * @brief Partial/header hashes.
 */
struct alignas(64) PartialHashes {
    // Header hash (first 4KB)
    std::string headerSHA256;

    // Section hashes (for PE files)
    std::unordered_map<std::string, std::string> sectionHashes;

    // Rich header hash
    std::string richHeaderHash;

    // Resource hashes
    std::unordered_map<std::string, std::string> resourceHashes;
};

/**
 * @struct HashComparison
 * @brief Result of hash comparison.
 */
struct alignas(32) HashComparison {
    bool areIdentical{ false };
    double fuzzySimilarity{ 0.0 };        // 0-100%
    double tlshDistance{ 0.0 };            // Lower = more similar
    bool sameFamily{ false };              // Based on fuzzy hash
};

/**
 * @struct FileHasherConfig
 * @brief Configuration for file hasher.
 */
struct alignas(64) FileHasherConfig {
    // Default algorithms
    HashAlgorithm defaultAlgorithms{ HashAlgorithm::Standard };

    // Performance
    size_t bufferSize{ FileHasherConstants::DEFAULT_BUFFER_SIZE };
    bool useMemoryMapping{ true };
    bool useHardwareAcceleration{ true };
    uint32_t workerThreads{ 4 };

    // Caching
    bool enableCache{ true };
    size_t maxCacheSize{ FileHasherConstants::DEFAULT_CACHE_SIZE };
    uint32_t cacheTTLHours{ FileHasherConstants::DEFAULT_CACHE_TTL_HOURS };

    // Factory methods
    static FileHasherConfig CreateDefault() noexcept;
    static FileHasherConfig CreateHighPerformance() noexcept;
    static FileHasherConfig CreateComprehensive() noexcept;
};

/**
 * @struct FileHasherStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) FileHasherStatistics {
    std::atomic<uint64_t> filesHashed{ 0 };
    std::atomic<uint64_t> bytesProcessed{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };

    std::atomic<uint64_t> md5Computed{ 0 };
    std::atomic<uint64_t> sha1Computed{ 0 };
    std::atomic<uint64_t> sha256Computed{ 0 };
    std::atomic<uint64_t> fuzzyHashComputed{ 0 };

    std::atomic<uint64_t> averageTimeUs{ 0 };
    std::atomic<uint64_t> maxTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for async hash completion.
 */
using HashCallback = std::function<void(const FileHashes& hashes)>;

/**
 * @brief Callback for progress updates.
 */
using HashProgressCallback = std::function<void(uint64_t bytesProcessed, uint64_t totalBytes)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileHasher
 * @brief Enterprise-grade file hashing engine.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& hasher = FileHasher::Instance();
 * 
 * // Compute all standard hashes
 * auto hashes = hasher.ComputeAll(L"suspicious.exe");
 * LOG_INFO << "SHA256: " << hashes.sha256Hex;
 * LOG_INFO << "fuzzyHash: " << hashes.fuzzyHash;
 * 
 * // Async hashing
 * hasher.ComputeAllAsync(L"large_file.bin", [](const FileHashes& h) {
 *     // Handle result
 * });
 * 
 * // Compare files using fuzzy hash
 * auto comparison = hasher.Compare(file1Hashes, file2Hashes);
 * if (comparison.fuzzySimilarity > 80.0) {
 *     LOG_INFO << "Files are similar variants";
 * }
 * 
 * // Single hash computation
 * auto sha256 = hasher.ComputeSHA256(filePath);
 * @endcode
 */
class FileHasher {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static FileHasher& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the hasher.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FileHasherConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // COMPLETE HASH COMPUTATION
    // ========================================================================

    /**
     * @brief Computes all configured hashes.
     * @param filePath Path to file.
     * @param algorithms Algorithms to compute.
     * @return Complete hash collection.
     */
    [[nodiscard]] FileHashes ComputeAll(
        const std::wstring& filePath,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    /**
     * @brief Computes hashes from buffer.
     * @param buffer Data buffer.
     * @param algorithms Algorithms to compute.
     * @return Complete hash collection.
     */
    [[nodiscard]] FileHashes ComputeAll(
        std::span<const uint8_t> buffer,
        HashAlgorithm algorithms = HashAlgorithm::Standard);

    /**
     * @brief Async hash computation.
     * @param filePath Path to file.
     * @return Future with hash results.
     */
    [[nodiscard]] std::future<FileHashes> ComputeAllAsync(const std::wstring& filePath);

    /**
     * @brief Async hash computation with callback.
     * @param filePath Path to file.
     * @param callback Result callback.
     */
    void ComputeAllAsync(const std::wstring& filePath, HashCallback callback);

    /**
     * @brief Batch hash computation.
     * @param filePaths Vector of paths.
     * @return Vector of hash collections.
     */
    [[nodiscard]] std::vector<FileHashes> ComputeBatch(const std::vector<std::wstring>& filePaths);

    // ========================================================================
    // INDIVIDUAL HASH COMPUTATION
    // ========================================================================

    /**
     * @brief Computes MD5 hash.
     * @param filePath Path to file.
     * @return MD5 hash as hex string.
     */
    [[nodiscard]] std::string ComputeMD5(const std::wstring& filePath);

    /**
     * @brief Computes SHA-1 hash.
     * @param filePath Path to file.
     * @return SHA-1 hash as hex string.
     */
    [[nodiscard]] std::string ComputeSHA1(const std::wstring& filePath);

    /**
     * @brief Computes SHA-256 hash.
     * @param filePath Path to file.
     * @return SHA-256 hash as hex string.
     */
    [[nodiscard]] std::string ComputeSHA256(const std::wstring& filePath);

    /**
     * @brief Computes SHA-512 hash.
     * @param filePath Path to file.
     * @return SHA-512 hash as hex string.
     */
    [[nodiscard]] std::string ComputeSHA512(const std::wstring& filePath);

    /**
     * @brief Computes CTPH fuzzy hash.
     * @param filePath Path to file.
     * @return Fuzzy hash string.
     */
    [[nodiscard]] std::string ComputeFuzzyHash(const std::wstring& filePath);

    /**
     * @brief Computes TLSH fuzzy hash.
     * @param filePath Path to file.
     * @return TLSH hash string.
     */
    [[nodiscard]] std::string ComputeTLSH(const std::wstring& filePath);

    /**
     * @brief Computes import hash (PE files).
     * @param filePath Path to PE file.
     * @return Import hash as hex string.
     */
    [[nodiscard]] std::string ComputeImpHash(const std::wstring& filePath);

    /**
     * @brief Computes authentihash (PE files).
     * @param filePath Path to PE file.
     * @return Authentihash as hex string.
     */
    [[nodiscard]] std::string ComputeAuthentihash(const std::wstring& filePath);

    // ========================================================================
    // BUFFER HASHING
    // ========================================================================

    /**
     * @brief Computes hash from buffer.
     * @param buffer Data buffer.
     * @param algorithm Algorithm to use.
     * @return Hash result.
     */
    [[nodiscard]] HashResult ComputeBuffer(
        std::span<const uint8_t> buffer,
        HashAlgorithm algorithm);

    /**
     * @brief Computes SHA-256 from buffer.
     * @param buffer Data buffer.
     * @return SHA-256 as hex string.
     */
    [[nodiscard]] std::string ComputeSHA256Buffer(std::span<const uint8_t> buffer);

    // ========================================================================
    // PARTIAL HASHING
    // ========================================================================

    /**
     * @brief Computes header hash.
     * @param filePath Path to file.
     * @param headerSize Size of header to hash.
     * @return Header SHA-256 hash.
     */
    [[nodiscard]] std::string ComputeHeaderHash(
        const std::wstring& filePath,
        size_t headerSize = FileHasherConstants::HEADER_HASH_SIZE);

    /**
     * @brief Computes PE section hashes.
     * @param filePath Path to PE file.
     * @return Map of section name to SHA-256.
     */
    [[nodiscard]] std::unordered_map<std::string, std::string> ComputeSectionHashes(
        const std::wstring& filePath);

    /**
     * @brief Gets all partial hashes.
     * @param filePath Path to file.
     * @return Partial hash collection.
     */
    [[nodiscard]] PartialHashes ComputePartialHashes(const std::wstring& filePath);

    // ========================================================================
    // HASH COMPARISON
    // ========================================================================

    /**
     * @brief Compares two hash collections.
     * @param hashes1 First hash collection.
     * @param hashes2 Second hash collection.
     * @return Comparison result.
     */
    [[nodiscard]] HashComparison Compare(const FileHashes& hashes1, const FileHashes& hashes2) const;

    /**
     * @brief Compares fuzzy hashes.
     * @param hash1 First fuzzy hash.
     * @param hash2 Second fuzzy hash.
     * @return Similarity percentage (0-100).
     */
    [[nodiscard]] double CompareFuzzyHash(std::string_view hash1, std::string_view hash2) const;

    /**
     * @brief Computes TLSH distance.
     * @param tlsh1 First TLSH hash.
     * @param tlsh2 Second TLSH hash.
     * @return Distance (lower = more similar).
     */
    [[nodiscard]] double ComputeTLSHDistance(std::string_view tlsh1, std::string_view tlsh2) const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets cached hash if available.
     * @param filePath Path to file.
     * @return Cached hashes, or nullopt.
     */
    [[nodiscard]] std::optional<FileHashes> GetCached(const std::wstring& filePath) const;

    /**
     * @brief Clears hash cache.
     */
    void ClearCache() noexcept;

    /**
     * @brief Invalidates cache for file.
     * @param filePath Path to file.
     */
    void InvalidateCache(const std::wstring& filePath);

    /**
     * @brief Gets cache size.
     * @return Number of cached entries.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Converts hash bytes to hex string.
     * @param hash Hash bytes.
     * @param format Output format.
     * @return Formatted hash string.
     */
    [[nodiscard]] std::string ToHexString(
        std::span<const uint8_t> hash,
        HashFormat format = HashFormat::Hex) const;

    /**
     * @brief Parses hex string to bytes.
     * @param hexString Hex string.
     * @return Hash bytes.
     */
    [[nodiscard]] std::vector<uint8_t> FromHexString(std::string_view hexString) const;

    /**
     * @brief Validates hash format.
     * @param hash Hash string.
     * @param algorithm Expected algorithm.
     * @return True if valid format.
     */
    [[nodiscard]] bool ValidateHashFormat(std::string_view hash, HashAlgorithm algorithm) const;

    // ========================================================================
    // HARDWARE CAPABILITIES
    // ========================================================================

    /**
     * @brief Checks for hardware acceleration support.
     * @return True if available.
     */
    [[nodiscard]] bool HasHardwareAcceleration() const noexcept;

    /**
     * @brief Gets supported hardware features.
     * @return Vector of feature names.
     */
    [[nodiscard]] std::vector<std::string> GetHardwareFeatures() const;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileHasherStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

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
