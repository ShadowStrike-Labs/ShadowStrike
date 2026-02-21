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
 * ShadowStrike NGAV - DELTA UPDATER MODULE
 * ============================================================================
 *
 * @file DeltaUpdater.hpp
 * @brief Enterprise-grade binary delta patching for efficient updates with
 *        multiple algorithms, integrity verification, and rollback support.
 *
 * Provides comprehensive delta update capabilities enabling minimal bandwidth
 * usage through intelligent binary differencing and patching.
 *
 * DELTA CAPABILITIES:
 * ===================
 *
 * 1. PATCHING ALGORITHMS
 *    - BSDiff/BSPatch
 *    - Courgette (Chrome)
 *    - VCDIFF (RFC 3284)
 *    - XDelta3
 *    - Custom binary diff
 *
 * 2. DATABASE PATCHING
 *    - SQLite session extension
 *    - LMDB delta sync
 *    - Custom DB formats
 *    - Schema migration
 *
 * 3. INTEGRITY
 *    - Pre-patch validation
 *    - Post-patch verification
 *    - Checksum comparison
 *    - Size verification
 *
 * 4. OPTIMIZATION
 *    - Memory-mapped I/O
 *    - Streaming patches
 *    - Parallel processing
 *    - Compression support
 *
 * 5. RECOVERY
 *    - Atomic operations
 *    - Rollback support
 *    - Partial patch recovery
 *    - Corruption detection
 *
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
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
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class DeltaUpdaterImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DeltaConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum patch size (MB)
    inline constexpr size_t MAX_PATCH_SIZE_MB = 256;
    
    /// @brief Maximum file size (GB)
    inline constexpr size_t MAX_FILE_SIZE_GB = 4;
    
    /// @brief Patch header magic
    inline constexpr uint32_t PATCH_MAGIC = 0x53534450;  // "SSDP"
    
    /// @brief Buffer size for streaming
    inline constexpr size_t STREAM_BUFFER_SIZE = 4 * 1024 * 1024;  // 4 MB

}  // namespace DeltaConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Patching algorithm
 */
enum class PatchAlgorithm : uint8_t {
    Auto            = 0,    ///< Auto-detect from header
    BSDiff          = 1,    ///< BSDiff algorithm
    Courgette       = 2,    ///< Courgette (Chrome)
    VCDIFF          = 3,    ///< RFC 3284 VCDIFF
    XDelta3         = 4,    ///< XDelta3
    Custom          = 5     ///< ShadowStrike custom
};

/**
 * @brief Patch operation
 */
enum class PatchOperation : uint8_t {
    Add             = 0,    ///< Add bytes
    Copy            = 1,    ///< Copy from source
    Run             = 2,    ///< Run-length encoding
    Insert          = 3     ///< Insert new data
};

/**
 * @brief Patch state
 */
enum class PatchState : uint8_t {
    NotStarted      = 0,
    Validating      = 1,
    Patching        = 2,
    Verifying       = 3,
    Completed       = 4,
    Failed          = 5
};

/**
 * @brief Module status
 */
enum class DeltaUpdaterStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Patching        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Patch header
 */
struct PatchHeader {
    /// @brief Magic number
    uint32_t magic = DeltaConstants::PATCH_MAGIC;
    
    /// @brief Version
    uint16_t version = 1;
    
    /// @brief Algorithm
    PatchAlgorithm algorithm = PatchAlgorithm::BSDiff;
    
    /// @brief Flags
    uint8_t flags = 0;
    
    /// @brief Source size
    uint64_t sourceSize = 0;
    
    /// @brief Target size
    uint64_t targetSize = 0;
    
    /// @brief Patch data size
    uint64_t patchSize = 0;
    
    /// @brief Source checksum (SHA-256)
    std::array<uint8_t, 32> sourceChecksum{};
    
    /// @brief Target checksum (SHA-256)
    std::array<uint8_t, 32> targetChecksum{};
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Patch info
 */
struct PatchInfo {
    /// @brief Patch file path
    fs::path patchPath;
    
    /// @brief Header
    PatchHeader header;
    
    /// @brief Source file
    fs::path sourceFile;
    
    /// @brief Target file (output)
    fs::path targetFile;
    
    /// @brief Compression ratio
    double compressionRatio = 0.0;
    
    /// @brief Estimated memory usage (bytes)
    uint64_t estimatedMemory = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Patch progress
 */
struct PatchProgress {
    /// @brief State
    PatchState state = PatchState::NotStarted;
    
    /// @brief Progress (0-100)
    uint8_t progressPercent = 0;
    
    /// @brief Bytes processed
    uint64_t bytesProcessed = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Current operation
    std::string currentOperation;
    
    /// @brief Speed (bytes/sec)
    uint64_t speedBps = 0;
    
    /// @brief ETA (seconds)
    uint32_t etaSeconds = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Patch result
 */
struct PatchResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Source file
    fs::path sourceFile;
    
    /// @brief Output file
    fs::path outputFile;
    
    /// @brief Algorithm used
    PatchAlgorithm algorithmUsed = PatchAlgorithm::Auto;
    
    /// @brief Bytes saved
    uint64_t bytesSaved = 0;
    
    /// @brief Duration (milliseconds)
    uint32_t durationMs = 0;
    
    /// @brief Output verified
    bool outputVerified = false;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DeltaStatistics {
    std::atomic<uint64_t> patchesApplied{0};
    std::atomic<uint64_t> patchesFailed{0};
    std::atomic<uint64_t> bytesProcessed{0};
    std::atomic<uint64_t> bytesSaved{0};
    std::atomic<uint64_t> totalDurationMs{0};
    std::array<std::atomic<uint64_t>, 8> byAlgorithm{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DeltaUpdaterConfiguration {
    /// @brief Enable delta updates
    bool enabled = true;
    
    /// @brief Preferred algorithm
    PatchAlgorithm preferredAlgorithm = PatchAlgorithm::BSDiff;
    
    /// @brief Max patch size (MB)
    size_t maxPatchSizeMB = DeltaConstants::MAX_PATCH_SIZE_MB;
    
    /// @brief Max file size (GB)
    size_t maxFileSizeGB = DeltaConstants::MAX_FILE_SIZE_GB;
    
    /// @brief Use memory mapping
    bool useMemoryMapping = true;
    
    /// @brief Verify output
    bool verifyOutput = true;
    
    /// @brief Stream buffer size
    size_t streamBufferSize = DeltaConstants::STREAM_BUFFER_SIZE;
    
    /// @brief Temp directory
    fs::path tempDirectory;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PatchProgressCallback = std::function<void(const PatchProgress&)>;
using PatchCompletionCallback = std::function<void(const PatchResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// DELTA UPDATER CLASS
// ============================================================================

/**
 * @class DeltaUpdater
 * @brief Enterprise delta patching
 */
class DeltaUpdater final {
public:
    [[nodiscard]] static DeltaUpdater& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    DeltaUpdater(const DeltaUpdater&) = delete;
    DeltaUpdater& operator=(const DeltaUpdater&) = delete;
    DeltaUpdater(DeltaUpdater&&) = delete;
    DeltaUpdater& operator=(DeltaUpdater&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DeltaUpdaterConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] DeltaUpdaterStatus GetStatus() const noexcept;

    // ========================================================================
    // PATCH OPERATIONS
    // ========================================================================
    
    /// @brief Apply patch from file
    [[nodiscard]] bool ApplyPatch(
        const std::wstring& originalPath,
        const std::vector<uint8_t>& patchData);
    
    /// @brief Apply patch file
    [[nodiscard]] PatchResult ApplyPatchFile(
        const fs::path& sourcePath,
        const fs::path& patchPath,
        const fs::path& outputPath);
    
    /// @brief Apply patch from memory
    [[nodiscard]] PatchResult ApplyPatchMemory(
        std::span<const uint8_t> sourceData,
        std::span<const uint8_t> patchData);
    
    /// @brief Create patch (for testing/development)
    [[nodiscard]] bool CreatePatch(
        const fs::path& oldFile,
        const fs::path& newFile,
        const fs::path& patchFile,
        PatchAlgorithm algorithm = PatchAlgorithm::BSDiff);

    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    /// @brief Validate patch file
    [[nodiscard]] bool ValidatePatch(const fs::path& patchPath);
    
    /// @brief Validate patch data
    [[nodiscard]] bool ValidatePatch(std::span<const uint8_t> patchData);
    
    /// @brief Get patch info
    [[nodiscard]] std::optional<PatchInfo> GetPatchInfo(const fs::path& patchPath);
    
    /// @brief Verify source file matches patch requirements
    [[nodiscard]] bool VerifySource(
        const fs::path& sourcePath,
        const PatchHeader& header);

    // ========================================================================
    // PROGRESS
    // ========================================================================
    
    /// @brief Get current progress
    [[nodiscard]] PatchProgress GetProgress() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(PatchProgressCallback callback);
    void RegisterCompletionCallback(PatchCompletionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DeltaStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DeltaUpdater();
    ~DeltaUpdater();
    
    std::unique_ptr<DeltaUpdaterImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAlgorithmName(PatchAlgorithm algorithm) noexcept;
[[nodiscard]] std::string_view GetPatchStateName(PatchState state) noexcept;

/// @brief Detect algorithm from patch header
[[nodiscard]] PatchAlgorithm DetectAlgorithm(std::span<const uint8_t> patchData);

/// @brief Calculate estimated patch size
[[nodiscard]] uint64_t EstimatePatchSize(uint64_t sourceSize, uint64_t targetSize);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_APPLY_DELTA_PATCH(original, patch) \
    ::ShadowStrike::Update::DeltaUpdater::Instance().ApplyPatch(original, patch)
