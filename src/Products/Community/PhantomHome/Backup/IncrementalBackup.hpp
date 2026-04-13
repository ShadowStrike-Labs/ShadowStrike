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
 * ShadowStrike NGAV - INCREMENTAL BACKUP MODULE
 * ============================================================================
 *
 * @file IncrementalBackup.hpp
 * @brief Enterprise-grade incremental backup with block-level deduplication,
 *        content-defined chunking, and advanced compression.
 *
 * Provides efficient incremental backup capabilities using rolling hash
 * algorithms for content-defined chunking and intelligent deduplication.
 *
 * INCREMENTAL CAPABILITIES:
 * =========================
 *
 * 1. CHUNKING STRATEGIES
 *    - Fixed-size blocks
 *    - Content-defined chunking (CDC)
 *    - Rolling hash (Rabin-Karp)
 *    - Buzhash algorithm
 *    - FastCDC algorithm
 *
 * 2. DEDUPLICATION
 *    - Block-level dedup
 *    - Inline dedup
 *    - Post-process dedup
 *    - Cross-backup dedup
 *    - Sliding window dedup
 *
 * 3. COMPRESSION
 *    - LZ4 (fast)
 *    - ZSTD (balanced)
 *    - LZMA/XZ (high compression)
 *    - Brotli
 *    - Per-block compression
 *
 * 4. CHANGE DETECTION
 *    - Archive bit tracking
 *    - USN journal monitoring
 *    - File system timestamps
 *    - Content hashing
 *    - Metadata comparison
 *
 * 5. DELTA ENCODING
 *    - Binary delta
 *    - Block-level delta
 *    - Rsync-style delta
 *    - XDelta3 integration
 *
 * @note Uses optimized SIMD implementations for hashing.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../HashStore/HashStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Backup {
    class IncrementalBackupImpl;
}

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IncrementalConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default minimum chunk size
    inline constexpr size_t MIN_CHUNK_SIZE = 2 * 1024;           // 2KB
    
    /// @brief Default average chunk size
    inline constexpr size_t AVG_CHUNK_SIZE = 64 * 1024;          // 64KB
    
    /// @brief Default maximum chunk size
    inline constexpr size_t MAX_CHUNK_SIZE = 1024 * 1024;        // 1MB
    
    /// @brief Default block size for fixed chunking
    inline constexpr size_t DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024; // 4MB
    
    /// @brief Hash table size for dedup
    inline constexpr size_t DEDUP_HASH_TABLE_SIZE = 1 << 20;      // 1M entries
    
    /// @brief Rabin fingerprint polynomial
    inline constexpr uint64_t RABIN_POLYNOMIAL = 0x3DA3358B4DC173;
    
    /// @brief Rolling hash window size
    inline constexpr size_t ROLLING_WINDOW_SIZE = 64;

}  // namespace IncrementalConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Chunking algorithm
 */
enum class ChunkingAlgorithm : uint8_t {
    Fixed           = 0,    ///< Fixed-size blocks
    RabinKarp       = 1,    ///< Rabin-Karp rolling hash
    Buzhash         = 2,    ///< Buzhash algorithm
    FastCDC         = 3,    ///< FastCDC algorithm
    Gear            = 4     ///< Gear-based CDC
};

/**
 * @brief Compression algorithm
 */
enum class CompressionAlgorithm : uint8_t {
    None            = 0,
    LZ4             = 1,    ///< LZ4 (fast)
    LZ4HC           = 2,    ///< LZ4 High Compression
    ZSTD            = 3,    ///< Zstandard (balanced)
    LZMA            = 4,    ///< LZMA/XZ (high)
    Brotli          = 5     ///< Brotli
};

/**
 * @brief Hash algorithm for chunks
 */
enum class ChunkHashAlgorithm : uint8_t {
    XXHash64        = 0,    ///< xxHash64 (fast)
    XXHash128       = 1,    ///< xxHash128
    SHA256          = 2,    ///< SHA-256
    BLAKE3          = 3,    ///< BLAKE3
    CityHash        = 4     ///< CityHash
};

/**
 * @brief Change type
 */
enum class ChangeType : uint8_t {
    None            = 0,
    Added           = 1,    ///< New file
    Modified        = 2,    ///< File changed
    Deleted         = 3,    ///< File deleted
    Renamed         = 4,    ///< File renamed
    Metadata        = 5     ///< Metadata only change
};

/**
 * @brief Sync status
 */
enum class SyncStatus : uint8_t {
    Pending         = 0,
    Scanning        = 1,
    Chunking        = 2,
    Deduplicating   = 3,
    Compressing     = 4,
    Writing         = 5,
    Completed       = 6,
    Failed          = 7,
    Cancelled       = 8
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Ready           = 2,
    Processing      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Chunk descriptor
 */
struct ChunkDescriptor {
    /// @brief Chunk hash
    std::array<uint8_t, 32> hash;
    
    /// @brief Offset in source file
    uint64_t offset = 0;
    
    /// @brief Original size
    uint32_t originalSize = 0;
    
    /// @brief Compressed size
    uint32_t compressedSize = 0;
    
    /// @brief Compression algorithm used
    CompressionAlgorithm compression = CompressionAlgorithm::None;
    
    /// @brief Is deduplicated (exists elsewhere)
    bool isDeduplicated = false;
    
    /// @brief Reference count
    uint32_t refCount = 1;
    
    /// @brief Storage offset in vault
    uint64_t storageOffset = 0;
    
    [[nodiscard]] std::string GetHashHex() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File change record
 */
struct FileChangeRecord {
    /// @brief File path
    fs::path path;
    
    /// @brief Change type
    ChangeType changeType = ChangeType::None;
    
    /// @brief Old path (for renames)
    fs::path oldPath;
    
    /// @brief File size
    uint64_t size = 0;
    
    /// @brief Previous size
    uint64_t previousSize = 0;
    
    /// @brief Modified time
    SystemTimePoint modifiedTime;
    
    /// @brief Previous modified time
    SystemTimePoint previousModifiedTime;
    
    /// @brief Content hash
    std::string contentHash;
    
    /// @brief Previous content hash
    std::string previousContentHash;
    
    /// @brief Changed chunks
    std::vector<ChunkDescriptor> changedChunks;
    
    /// @brief Bytes changed
    uint64_t bytesChanged = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Dedup index entry
 */
struct DedupIndexEntry {
    /// @brief Chunk hash
    std::array<uint8_t, 32> hash;
    
    /// @brief Storage location
    uint64_t storageOffset = 0;
    
    /// @brief Size
    uint32_t size = 0;
    
    /// @brief Reference count
    uint32_t refCount = 0;
    
    /// @brief Last accessed
    SystemTimePoint lastAccessed;
};

/**
 * @brief Sync result
 */
struct SyncResult {
    /// @brief Sync ID
    std::string syncId;
    
    /// @brief Status
    SyncStatus status = SyncStatus::Completed;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Duration
    std::chrono::seconds duration{0};
    
    /// @brief Files scanned
    uint64_t filesScanned = 0;
    
    /// @brief Files changed
    uint64_t filesChanged = 0;
    
    /// @brief Bytes scanned
    uint64_t bytesScanned = 0;
    
    /// @brief Bytes changed
    uint64_t bytesChanged = 0;
    
    /// @brief Bytes after dedup
    uint64_t bytesAfterDedup = 0;
    
    /// @brief Bytes stored (after compression)
    uint64_t bytesStored = 0;
    
    /// @brief Chunks created
    uint64_t chunksCreated = 0;
    
    /// @brief Chunks deduplicated
    uint64_t chunksDeduplicated = 0;
    
    /// @brief Dedup ratio
    double dedupRatio = 1.0;
    
    /// @brief Compression ratio
    double compressionRatio = 1.0;
    
    /// @brief Change records
    std::vector<FileChangeRecord> changes;
    
    /// @brief Errors
    std::vector<std::string> errors;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sync progress
 */
struct SyncProgress {
    /// @brief Sync ID
    std::string syncId;
    
    /// @brief Status
    SyncStatus status = SyncStatus::Pending;
    
    /// @brief Current phase
    std::string phase;
    
    /// @brief Current file
    fs::path currentFile;
    
    /// @brief Percent complete
    int percentComplete = 0;
    
    /// @brief Files processed
    uint64_t filesProcessed = 0;
    
    /// @brief Total files
    uint64_t totalFiles = 0;
    
    /// @brief Bytes processed
    uint64_t bytesProcessed = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Processing rate (bytes/sec)
    uint64_t processingRate = 0;
    
    /// @brief Estimated time remaining
    uint32_t estimatedTimeRemaining = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Chunking options
 */
struct ChunkingOptions {
    /// @brief Algorithm
    ChunkingAlgorithm algorithm = ChunkingAlgorithm::FastCDC;
    
    /// @brief Minimum chunk size
    size_t minChunkSize = IncrementalConstants::MIN_CHUNK_SIZE;
    
    /// @brief Average chunk size
    size_t avgChunkSize = IncrementalConstants::AVG_CHUNK_SIZE;
    
    /// @brief Maximum chunk size
    size_t maxChunkSize = IncrementalConstants::MAX_CHUNK_SIZE;
    
    /// @brief Hash algorithm
    ChunkHashAlgorithm hashAlgorithm = ChunkHashAlgorithm::XXHash64;
    
    /// @brief Normalization level (for CDC)
    int normalizationLevel = 2;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct IncrementalStatistics {
    std::atomic<uint64_t> totalSyncs{0};
    std::atomic<uint64_t> successfulSyncs{0};
    std::atomic<uint64_t> failedSyncs{0};
    std::atomic<uint64_t> totalBytesProcessed{0};
    std::atomic<uint64_t> totalBytesStored{0};
    std::atomic<uint64_t> totalChunksCreated{0};
    std::atomic<uint64_t> totalChunksDeduplicated{0};
    std::atomic<uint64_t> bytesSavedByDedup{0};
    std::atomic<uint64_t> bytesSavedByCompression{0};
    std::atomic<uint64_t> uniqueChunks{0};
    std::atomic<uint64_t> duplicateChunks{0};
    std::array<std::atomic<uint64_t>, 8> byCompression{};
    TimePoint startTime = Clock::now();

    IncrementalStatistics() noexcept = default;

    /// Atomics are non-copyable; explicit snapshot copy loads each counter.
    IncrementalStatistics(const IncrementalStatistics& o) noexcept
        : totalSyncs(o.totalSyncs.load(std::memory_order_relaxed))
        , successfulSyncs(o.successfulSyncs.load(std::memory_order_relaxed))
        , failedSyncs(o.failedSyncs.load(std::memory_order_relaxed))
        , totalBytesProcessed(o.totalBytesProcessed.load(std::memory_order_relaxed))
        , totalBytesStored(o.totalBytesStored.load(std::memory_order_relaxed))
        , totalChunksCreated(o.totalChunksCreated.load(std::memory_order_relaxed))
        , totalChunksDeduplicated(o.totalChunksDeduplicated.load(std::memory_order_relaxed))
        , bytesSavedByDedup(o.bytesSavedByDedup.load(std::memory_order_relaxed))
        , bytesSavedByCompression(o.bytesSavedByCompression.load(std::memory_order_relaxed))
        , uniqueChunks(o.uniqueChunks.load(std::memory_order_relaxed))
        , duplicateChunks(o.duplicateChunks.load(std::memory_order_relaxed))
        , startTime(o.startTime)
    {
        for (size_t i = 0; i < byCompression.size(); ++i) {
            byCompression[i].store(
                o.byCompression[i].load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
    }

    IncrementalStatistics& operator=(const IncrementalStatistics& o) noexcept {
        if (this != &o) {
            totalSyncs.store(o.totalSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            successfulSyncs.store(o.successfulSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            failedSyncs.store(o.failedSyncs.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalBytesProcessed.store(o.totalBytesProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalBytesStored.store(o.totalBytesStored.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalChunksCreated.store(o.totalChunksCreated.load(std::memory_order_relaxed), std::memory_order_relaxed);
            totalChunksDeduplicated.store(o.totalChunksDeduplicated.load(std::memory_order_relaxed), std::memory_order_relaxed);
            bytesSavedByDedup.store(o.bytesSavedByDedup.load(std::memory_order_relaxed), std::memory_order_relaxed);
            bytesSavedByCompression.store(o.bytesSavedByCompression.load(std::memory_order_relaxed), std::memory_order_relaxed);
            uniqueChunks.store(o.uniqueChunks.load(std::memory_order_relaxed), std::memory_order_relaxed);
            duplicateChunks.store(o.duplicateChunks.load(std::memory_order_relaxed), std::memory_order_relaxed);
            startTime = o.startTime;
            for (size_t i = 0; i < byCompression.size(); ++i) {
                byCompression[i].store(
                    o.byCompression[i].load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
            }
        }
        return *this;
    }
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct IncrementalConfiguration {
    /// @brief Enable incremental backup
    bool enabled = true;
    
    /// @brief Chunking options
    ChunkingOptions chunkingOptions;
    
    /// @brief Compression algorithm
    CompressionAlgorithm compression = CompressionAlgorithm::ZSTD;
    
    /// @brief Compression level (0-9)
    int compressionLevel = 3;
    
    /// @brief Enable deduplication
    bool enableDedup = true;
    
    /// @brief Dedup index path
    fs::path dedupIndexPath;
    
    /// @brief Use USN journal for change detection
    bool useUSNJournal = true;
    
    /// @brief Use archive bit
    bool useArchiveBit = true;
    
    /// @brief Thread count for processing
    size_t threadCount = 4;
    
    /// @brief Buffer size
    size_t bufferSize = 16 * 1024 * 1024;  // 16MB
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback = std::function<void(const SyncProgress&)>;
using CompletionCallback = std::function<void(const SyncResult&)>;
using ChunkCallback = std::function<void(const ChunkDescriptor&)>;
using ChangeCallback = std::function<void(const FileChangeRecord&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// INCREMENTAL BACKUP CLASS
// ============================================================================

/**
 * @class IncrementalBackup
 * @brief Enterprise incremental backup engine
 */
class IncrementalBackup final {
public:
    [[nodiscard]] static IncrementalBackup& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    IncrementalBackup(const IncrementalBackup&) = delete;
    IncrementalBackup& operator=(const IncrementalBackup&) = delete;
    IncrementalBackup(IncrementalBackup&&) = delete;
    IncrementalBackup& operator=(IncrementalBackup&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const IncrementalConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const IncrementalConfiguration& config);
    [[nodiscard]] IncrementalConfiguration GetConfiguration() const;

    // ========================================================================
    // SYNC OPERATIONS
    // ========================================================================
    
    /// @brief Sync source to vault
    [[nodiscard]] bool Sync(const std::wstring& source, const std::wstring& vault);
    
    /// @brief Sync with options
    [[nodiscard]] std::string StartSync(
        const fs::path& source,
        const fs::path& vault,
        const ChunkingOptions& options = {});
    
    /// @brief Cancel sync
    [[nodiscard]] bool CancelSync(const std::string& syncId);
    
    /// @brief Pause sync
    [[nodiscard]] bool PauseSync(const std::string& syncId);
    
    /// @brief Resume sync
    [[nodiscard]] bool ResumeSync(const std::string& syncId);
    
    /// @brief Get sync progress
    [[nodiscard]] std::optional<SyncProgress> GetProgress(const std::string& syncId);
    
    /// @brief Get sync result
    [[nodiscard]] std::optional<SyncResult> GetResult(const std::string& syncId);

    // ========================================================================
    // CHANGE DETECTION
    // ========================================================================
    
    /// @brief Scan for changes
    [[nodiscard]] std::vector<FileChangeRecord> ScanForChanges(
        const fs::path& source,
        const fs::path& baselinePath = {});
    
    /// @brief Get USN journal changes
    [[nodiscard]] std::vector<FileChangeRecord> GetUSNChanges(
        const std::wstring& volumePath,
        uint64_t fromUSN = 0);
    
    /// @brief Compare files
    [[nodiscard]] FileChangeRecord CompareFiles(
        const fs::path& oldFile,
        const fs::path& newFile);

    // ========================================================================
    // CHUNKING
    // ========================================================================
    
    /// @brief Chunk file
    [[nodiscard]] std::vector<ChunkDescriptor> ChunkFile(
        const fs::path& filePath,
        const ChunkingOptions& options = {});
    
    /// @brief Chunk data buffer
    [[nodiscard]] std::vector<ChunkDescriptor> ChunkData(
        std::span<const uint8_t> data,
        const ChunkingOptions& options = {});
    
    /// @brief Set chunking algorithm
    void SetChunkingAlgorithm(ChunkingAlgorithm algorithm);

    // ========================================================================
    // DEDUPLICATION
    // ========================================================================
    
    /// @brief Check if chunk exists
    [[nodiscard]] bool ChunkExists(const std::array<uint8_t, 32>& hash);
    
    /// @brief Add chunk to dedup index
    [[nodiscard]] bool AddChunkToIndex(const ChunkDescriptor& chunk);
    
    /// @brief Get chunk from index
    [[nodiscard]] std::optional<DedupIndexEntry> GetChunkFromIndex(
        const std::array<uint8_t, 32>& hash);
    
    /// @brief Get dedup ratio
    [[nodiscard]] double GetDedupRatio() const noexcept;
    
    /// @brief Compact dedup index
    [[nodiscard]] bool CompactIndex();

    // ========================================================================
    // COMPRESSION
    // ========================================================================
    
    /// @brief Compress chunk
    [[nodiscard]] std::vector<uint8_t> CompressChunk(
        std::span<const uint8_t> data,
        CompressionAlgorithm algorithm = CompressionAlgorithm::ZSTD);
    
    /// @brief Decompress chunk
    [[nodiscard]] std::vector<uint8_t> DecompressChunk(
        std::span<const uint8_t> data,
        CompressionAlgorithm algorithm,
        size_t originalSize);
    
    /// @brief Set compression algorithm
    void SetCompressionAlgorithm(CompressionAlgorithm algorithm);
    
    /// @brief Set compression level
    void SetCompressionLevel(int level);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterChunkCallback(ChunkCallback callback);
    void RegisterChangeCallback(ChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] IncrementalStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    IncrementalBackup();
    ~IncrementalBackup();
    
    std::unique_ptr<IncrementalBackupImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetChunkingAlgorithmName(ChunkingAlgorithm algorithm) noexcept;
[[nodiscard]] std::string_view GetCompressionAlgorithmName(CompressionAlgorithm algorithm) noexcept;
[[nodiscard]] std::string_view GetChunkHashAlgorithmName(ChunkHashAlgorithm algorithm) noexcept;
[[nodiscard]] std::string_view GetChangeTypeName(ChangeType type) noexcept;
[[nodiscard]] std::string_view GetSyncStatusName(SyncStatus status) noexcept;

/// @brief Calculate Rabin fingerprint
[[nodiscard]] uint64_t RabinFingerprint(std::span<const uint8_t> data);

/// @brief Calculate content hash
[[nodiscard]] std::array<uint8_t, 32> CalculateChunkHash(
    std::span<const uint8_t> data,
    ChunkHashAlgorithm algorithm = ChunkHashAlgorithm::XXHash64);

/// @brief Find chunk boundaries using CDC
[[nodiscard]] std::vector<size_t> FindChunkBoundaries(
    std::span<const uint8_t> data,
    const ChunkingOptions& options);

}  // namespace Backup
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_INCREMENTAL_SYNC(src, vault) \
    ::ShadowStrike::Backup::IncrementalBackup::Instance().Sync(src, vault)

#define SS_INCREMENTAL_CHUNK(file) \
    ::ShadowStrike::Backup::IncrementalBackup::Instance().ChunkFile(file)

#define SS_INCREMENTAL_CHANGES(src) \
    ::ShadowStrike::Backup::IncrementalBackup::Instance().ScanForChanges(src)
