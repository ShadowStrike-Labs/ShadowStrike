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
 * ShadowStrike NGAV - PACKER UNPACKER MODULE
 * ============================================================================
 *
 * @file PackerUnpacker.hpp
 * @brief Enterprise-grade automated unpacking of protected, packed, and
 *        obfuscated executables with static and dynamic analysis capabilities.
 *
 * Provides comprehensive unpacking support for common and custom packers,
 * including import reconstruction and memory dump analysis.
 *
 * @note Thread-safe singleton design (Meyers' singleton).
 * @note PackerType enum is defined in EmulationEngine.hpp to avoid duplication.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
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
#include <set>
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

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CompressionUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

// PackerType is authoritatively defined in EmulationEngine.hpp.
// Forward-declare here so consumers do not need the heavyweight header.
namespace ShadowStrike::Core::Engine {
    enum class PackerType : uint16_t;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace UnpackerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// Maximum unpacking layers
    inline constexpr uint32_t MAX_UNPACKING_LAYERS = 10;

    /// Maximum emulation instructions
    inline constexpr uint64_t MAX_EMULATION_INSTRUCTIONS = 10'000'000;

    /// Maximum unpacked size (256 MB)
    inline constexpr size_t MAX_UNPACKED_SIZE = 256ULL * 1024 * 1024;

    /// Maximum input file size for detection/unpacking (512 MB)
    inline constexpr size_t MAX_INPUT_FILE_SIZE = 512ULL * 1024 * 1024;

    /// Default unpacking timeout (seconds)
    inline constexpr uint32_t DEFAULT_TIMEOUT_SECONDS = 60;

    /// Maximum PE section count (hardened against crafted headers)
    inline constexpr uint32_t MAX_SECTIONS = 96;

    /// Maximum archive nesting depth
    inline constexpr uint32_t MAX_ARCHIVE_DEPTH = 8;

}  // namespace UnpackerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/// Unpacking method
enum class UnpackMethod : uint8_t {
    Static  = 0,
    Dynamic = 1,
    Hybrid  = 2,
    Plugin  = 3,
    Memory  = 4
};

/// Unpacking result status
enum class UnpackStatus : uint8_t {
    Success              = 0,
    PartialSuccess       = 1,
    NotPacked            = 2,
    UnsupportedPacker    = 3,
    CorruptedInput       = 4,
    OEPNotFound          = 5,
    EmulationFailed      = 6,
    Timeout              = 7,
    OutputTooLarge       = 8,
    ImportRecoveryFailed = 9,
    AntiDebugDetected    = 10,
    VirtualizedCode      = 11,
    Error                = 12
};

/// OEP detection method
enum class OEPDetectionMethod : uint8_t {
    PatternMatch        = 0,
    MemoryWrite         = 1,
    ExecutionBreakpoint = 2,
    StackFrame          = 3,
    Heuristic           = 4
};

/// Module lifecycle status
enum class UnpackerStatus : uint8_t {
    Uninitialized = 0,
    Initializing  = 1,
    Running       = 2,
    Unpacking     = 3,
    Error         = 4,
    Stopping      = 5,
    Stopped       = 6
};

// ============================================================================
// ERROR TYPE
// ============================================================================

/// Error detail for unpacker operations.
struct UnpackError {
    DWORD        win32Code = ERROR_SUCCESS;
    std::wstring message;
    std::wstring context;

    [[nodiscard]] bool HasError() const noexcept { return win32Code != ERROR_SUCCESS; }
    void Clear() noexcept { win32Code = ERROR_SUCCESS; message.clear(); context.clear(); }
};

// ============================================================================
// STRUCTURES
// ============================================================================

/// Packer detection result
struct PackerDetectionResult {
    PackerType    packerType{};
    std::string   packerName;
    std::string   version;
    float         confidence    = 0.0f;
    bool          isPacked      = false;
    bool          isEncrypted   = false;
    bool          isVirtualized = false;
    uint32_t      estimatedLayers = 0;
    std::string   entryPointSection;
    std::vector<std::pair<std::string, float>> sectionEntropies;

    /// Path of the analysed file (set by file-based detection)
    fs::path      filePath;
    /// Human-readable detection method label
    std::wstring  detectionMethod;
    /// Additional informational strings
    std::vector<std::wstring> additionalInfo;
};

/// PE section info
struct SectionInfo {
    std::string name;
    uint32_t virtualAddress  = 0;
    uint32_t virtualSize     = 0;
    uint32_t rawDataSize     = 0;
    uint32_t rawDataOffset   = 0;
    uint32_t characteristics = 0;
    float    entropy         = 0.0f;
    bool     isExecutable    = false;
    bool     isWritable      = false;
};

/// Import entry
struct ImportEntry {
    std::string dllName;
    std::string functionName;
    uint16_t    ordinal         = 0;
    uint64_t    iatAddress      = 0;
    uint64_t    resolvedAddress = 0;
    bool        byOrdinal       = false;
};

/// A single reconstructed import descriptor (per DLL).
struct ReconstructedImportDescriptor {
    std::string dllName;
    std::vector<ImportEntry> functions;
};

/// Reconstructed import table after unpacking.
struct ReconstructedImports {
    uint64_t iatRVA = 0;
    std::vector<ReconstructedImportDescriptor> importDescriptors;
    uint32_t totalFunctions = 0;
    bool     reconstructedSuccessfully = false;
};

/// Options for import reconstruction.
struct ImportReconstructionOptions {
    bool resolveByOrdinal  = true;
    bool resolveByAddress  = true;
    bool allowPartial      = true;
};

/// Unpacked PE info
struct UnpackedPEInfo {
    uint64_t originalEntryPoint = 0;
    uint64_t newEntryPoint      = 0;
    uint64_t imageBase          = 0;
    uint32_t sizeOfImage        = 0;
    std::vector<SectionInfo> sections;
    std::vector<ImportEntry> imports;
    OEPDetectionMethod oepMethod = OEPDetectionMethod::Heuristic;
    bool hasValidImports = false;
    bool hasValidPE      = false;
};

/// Unpacking result
struct UnpackResult {
    UnpackStatus  status = UnpackStatus::Error;
    std::vector<uint8_t> unpackedData;
    UnpackedPEInfo peInfo;
    PackerDetectionResult packerInfo;
    UnpackMethod  methodUsed       = UnpackMethod::Static;
    uint32_t      layersUnpacked   = 0;
    size_t        originalSize     = 0;
    size_t        unpackedSize     = 0;
    float         compressionRatio = 0.0f;
    uint64_t      instructionsEmulated = 0;
    uint32_t      processingTimeMs     = 0;
    std::string   errorMessage;
    std::vector<std::string> warnings;

    [[nodiscard]] bool IsSuccess() const noexcept {
        return status == UnpackStatus::Success || status == UnpackStatus::PartialSuccess;
    }
};

/// Unpacking options
struct UnpackOptions {
    UnpackMethod preferredMethod = UnpackMethod::Hybrid;
    uint32_t maxLayers        = UnpackerConstants::MAX_UNPACKING_LAYERS;
    uint64_t maxInstructions  = UnpackerConstants::MAX_EMULATION_INSTRUCTIONS;
    uint32_t timeoutSeconds   = UnpackerConstants::DEFAULT_TIMEOUT_SECONDS;
    bool     reconstructImports    = true;
    bool     fixPEHeaders          = true;
    bool     extractOverlay        = false;
    bool     dumpAllLayers         = false;
    bool     antiAntiDebug         = true;
    bool     enableStaticUnpacking  = true;
    bool     enableDynamicUnpacking = true;

    [[nodiscard]] uint32_t MaxEmulationTimeMs() const noexcept {
        return timeoutSeconds * 1000u;
    }
    [[nodiscard]] bool IsValid() const noexcept {
        return maxLayers > 0 && maxLayers <= UnpackerConstants::MAX_UNPACKING_LAYERS;
    }
};

/// Configuration
struct PackerUnpackerConfiguration {
    bool enabled = true;
    UnpackOptions defaultOptions;
    uint32_t maxConcurrentUnpacks = 4;
    bool     enableCache          = true;
    uint32_t cacheTtlSeconds      = 3600;
    uint32_t workerThreads        = 2;
    fs::path scriptsPath;

    [[nodiscard]] bool IsValid() const noexcept {
        return workerThreads > 0 && maxConcurrentUnpacks > 0;
    }
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using UnpackProgressCallback = std::function<void(uint32_t layer, const std::string& status)>;
using UnpackCompleteCallback = std::function<void(const UnpackResult& result)>;
using UnpackerErrorCallback  = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PACKER UNPACKER CLASS
// ============================================================================

/**
 * @class PackerUnpacker
 * @brief Enterprise-grade packer detection and unpacking engine.
 *
 * Meyers' singleton.  All public methods are thread-safe.
 */
class PackerUnpacker final {
public:
    // ========================================================================
    // STATISTICS
    // ========================================================================

    struct Statistics {
        std::atomic<uint64_t> totalUnpackAttempts{0};
        std::atomic<uint64_t> successfulUnpacks{0};
        std::atomic<uint64_t> failedUnpacks{0};
        std::atomic<uint64_t> packersDetected{0};
        std::atomic<uint64_t> staticUnpacks{0};
        std::atomic<uint64_t> dynamicUnpacks{0};
        std::atomic<uint64_t> oepsFound{0};
        std::atomic<uint64_t> importsReconstructed{0};

        void Reset() noexcept;
    };

    // ========================================================================
    // SINGLETON
    // ========================================================================

    [[nodiscard]] static PackerUnpacker& Instance() noexcept;

    PackerUnpacker(const PackerUnpacker&)            = delete;
    PackerUnpacker& operator=(const PackerUnpacker&) = delete;
    PackerUnpacker(PackerUnpacker&&)                 = delete;
    PackerUnpacker& operator=(PackerUnpacker&&)      = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(UnpackError* err = nullptr) noexcept;
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // PACKER DETECTION
    // ========================================================================

    [[nodiscard]] PackerDetectionResult DetectPacker(const fs::path& filePath) noexcept;
    [[nodiscard]] PackerDetectionResult DetectPacker(std::span<const uint8_t> data) noexcept;

    // ========================================================================
    // UNPACKING
    // ========================================================================

    [[nodiscard]] UnpackResult UnpackFile(const fs::path& filePath,
                                          const UnpackOptions& options = {}) noexcept;
    [[nodiscard]] UnpackResult StaticUnpack(std::span<const uint8_t> data,
                                            PackerType type) noexcept;
    [[nodiscard]] UnpackResult DynamicUnpack(std::span<const uint8_t> data,
                                             const UnpackOptions& options = {}) noexcept;

    // ========================================================================
    // OEP DETECTION
    // ========================================================================

    [[nodiscard]] std::optional<uint64_t> FindOEP(std::span<const uint8_t> data) noexcept;

    // ========================================================================
    // IMPORT RECONSTRUCTION
    // ========================================================================

    [[nodiscard]] std::optional<ReconstructedImports> ReconstructImports(
        std::span<const uint8_t> unpackedData,
        const ImportReconstructionOptions& options = {}) noexcept;

    // ========================================================================
    // PE RECONSTRUCTION
    // ========================================================================

    [[nodiscard]] std::optional<std::vector<uint8_t>> FixPEHeaders(
        std::span<const uint8_t> data,
        uint64_t newEntryPoint,
        const ReconstructedImports* imports = nullptr) noexcept;

    // ========================================================================
    // ARCHIVE / SELF-EXTRACTOR
    // ========================================================================

    [[nodiscard]] std::vector<fs::path> ExtractArchive(
        const fs::path& archivePath,
        uint32_t maxDepth = UnpackerConstants::MAX_ARCHIVE_DEPTH) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const Statistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    [[nodiscard]] std::vector<std::string> GetSupportedPackers() const;
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PackerUnpacker() noexcept;
    ~PackerUnpacker();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] float CalculateSectionEntropy(std::span<const uint8_t> data) noexcept;
[[nodiscard]] bool  IsHighEntropySection(float entropy) noexcept;

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

#define SS_IS_PACKED(path) \
    ::ShadowStrike::Core::Engine::PackerUnpacker::Instance().DetectPacker(path).isPacked

#define SS_UNPACK_FILE(path) \
    ::ShadowStrike::Core::Engine::PackerUnpacker::Instance().UnpackFile(path)
