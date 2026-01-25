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
 * UNPACKING CAPABILITIES:
 * =======================
 *
 * 1. STATIC UNPACKING
 *    - UPX unpacking
 *    - ASPack unpacking
 *    - FSG unpacking
 *    - PECompact unpacking
 *    - MPRESS unpacking
 *    - Custom packer scripts
 *
 * 2. DYNAMIC UNPACKING
 *    - Emulation-based unpacking
 *    - OEP (Original Entry Point) detection
 *    - Multi-layer unpacking
 *    - Self-extracting archives
 *    - VM-protected code
 *
 * 3. IMPORT RECONSTRUCTION
 *    - IAT rebuilding
 *    - Import name resolution
 *    - Ordinal-to-name mapping
 *    - API redirection detection
 *
 * 4. MEMORY DUMP ANALYSIS
 *    - Section dump
 *    - Full PE reconstruction
 *    - Overlay extraction
 *    - Resource extraction
 *
 * 5. PACKER DETECTION
 *    - Signature-based detection
 *    - Heuristic detection
 *    - Entropy analysis
 *    - Section characteristics
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
#include <set>
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

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CompressionUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class PackerUnpackerImpl;
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

    /// @brief Maximum unpacking layers
    inline constexpr uint32_t MAX_UNPACKING_LAYERS = 10;
    
    /// @brief Maximum emulation instructions
    inline constexpr uint64_t MAX_EMULATION_INSTRUCTIONS = 10000000;
    
    /// @brief Maximum unpacked size (256 MB)
    inline constexpr size_t MAX_UNPACKED_SIZE = 256 * 1024 * 1024;
    
    /// @brief Unpacking timeout (seconds)
    inline constexpr uint32_t DEFAULT_TIMEOUT_SECONDS = 60;
    
    /// @brief Maximum section count
    inline constexpr uint32_t MAX_SECTIONS = 96;

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

/**
 * @brief Known packer types
 */
enum class PackerType : uint8_t {
    Unknown         = 0,
    UPX             = 1,
    ASPack          = 2,
    FSG             = 3,
    PECompact       = 4,
    MPRESS          = 5,
    NSPack          = 6,
    PEtite          = 7,
    Armadillo       = 8,
    Themida         = 9,
    VMProtect       = 10,
    Enigma          = 11,
    ExeCryptor      = 12,
    PELock          = 13,
    ASProtect       = 14,
    SafeEngine      = 15,
    Custom          = 16,
    SelfExtractor   = 17,
    DotNetObfuscator= 18,
    Confuser        = 19,
    SmartAssembly   = 20
};

/**
 * @brief Unpacking method
 */
enum class UnpackMethod : uint8_t {
    Static          = 0,    ///< Pattern-based static unpacking
    Dynamic         = 1,    ///< Emulation-based dynamic unpacking
    Hybrid          = 2,    ///< Combined approach
    Plugin          = 3,    ///< External unpacker plugin
    Memory          = 4     ///< Live memory dump (for running processes)
};

/**
 * @brief Unpacking result status
 */
enum class UnpackStatus : uint8_t {
    Success             = 0,
    PartialSuccess      = 1,    ///< Some layers unpacked
    UnsupportedPacker   = 2,
    CorruptedInput      = 3,
    EmulationFailed     = 4,
    Timeout             = 5,
    OutputTooLarge      = 6,
    ImportRecoveryFailed= 7,
    AntiDebugDetected   = 8,
    VirtualizedCode     = 9,
    Error               = 10
};

/**
 * @brief OEP detection method
 */
enum class OEPDetectionMethod : uint8_t {
    PatternMatch        = 0,    ///< Known OEP patterns
    MemoryWrite         = 1,    ///< Detect write to code section
    ExecutionBreakpoint = 2,    ///< Break on execution of original code
    StackFrame          = 3,    ///< Stack analysis
    Heuristic           = 4     ///< Combined heuristics
};

/**
 * @brief Detector status
 */
enum class UnpackerStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Unpacking       = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Packer detection result
 */
struct PackerDetectionResult {
    /// @brief Detected packer type
    PackerType packerType = PackerType::Unknown;
    
    /// @brief Packer name
    std::string packerName;
    
    /// @brief Packer version (if detectable)
    std::string version;
    
    /// @brief Detection confidence (0.0 - 1.0)
    float confidence = 0.0f;
    
    /// @brief Is packed
    bool isPacked = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is virtualized (VM protection)
    bool isVirtualized = false;
    
    /// @brief Estimated layers
    uint32_t estimatedLayers = 0;
    
    /// @brief Entry point section
    std::string entryPointSection;
    
    /// @brief Suspicious section entropy
    std::vector<std::pair<std::string, float>> sectionEntropies;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief PE section info
 */
struct SectionInfo {
    /// @brief Section name
    std::string name;
    
    /// @brief Virtual address
    uint32_t virtualAddress = 0;
    
    /// @brief Virtual size
    uint32_t virtualSize = 0;
    
    /// @brief Raw data size
    uint32_t rawDataSize = 0;
    
    /// @brief Raw data offset
    uint32_t rawDataOffset = 0;
    
    /// @brief Characteristics
    uint32_t characteristics = 0;
    
    /// @brief Entropy
    float entropy = 0.0f;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is writable
    bool isWritable = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Import entry
 */
struct ImportEntry {
    /// @brief DLL name
    std::string dllName;
    
    /// @brief Function name
    std::string functionName;
    
    /// @brief Ordinal (if by ordinal)
    uint16_t ordinal = 0;
    
    /// @brief IAT address
    uint64_t iatAddress = 0;
    
    /// @brief Resolved address
    uint64_t resolvedAddress = 0;
    
    /// @brief Is by ordinal
    bool byOrdinal = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Unpacked PE info
 */
struct UnpackedPEInfo {
    /// @brief Original Entry Point (OEP)
    uint64_t originalEntryPoint = 0;
    
    /// @brief Image base
    uint64_t imageBase = 0;
    
    /// @brief Size of image
    uint32_t sizeOfImage = 0;
    
    /// @brief Sections
    std::vector<SectionInfo> sections;
    
    /// @brief Reconstructed imports
    std::vector<ImportEntry> imports;
    
    /// @brief OEP detection method used
    OEPDetectionMethod oepMethod = OEPDetectionMethod::Heuristic;
    
    /// @brief Has reconstructed imports
    bool hasValidImports = false;
    
    /// @brief Has valid PE structure
    bool hasValidPE = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Unpacking result
 */
struct UnpackResult {
    /// @brief Status
    UnpackStatus status = UnpackStatus::Error;
    
    /// @brief Unpacked data
    std::vector<uint8_t> unpackedData;
    
    /// @brief PE information
    UnpackedPEInfo peInfo;
    
    /// @brief Packer detection
    PackerDetectionResult packerInfo;
    
    /// @brief Unpacking method used
    UnpackMethod methodUsed = UnpackMethod::Static;
    
    /// @brief Layers unpacked
    uint32_t layersUnpacked = 0;
    
    /// @brief Original size
    size_t originalSize = 0;
    
    /// @brief Unpacked size
    size_t unpackedSize = 0;
    
    /// @brief Compression ratio
    float compressionRatio = 0.0f;
    
    /// @brief Instructions emulated
    uint64_t instructionsEmulated = 0;
    
    /// @brief Processing time (milliseconds)
    uint32_t processingTimeMs = 0;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Warnings
    std::vector<std::string> warnings;
    
    [[nodiscard]] bool IsSuccess() const noexcept { return status == UnpackStatus::Success || status == UnpackStatus::PartialSuccess; }
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Unpacking options
 */
struct UnpackOptions {
    /// @brief Preferred method
    UnpackMethod preferredMethod = UnpackMethod::Hybrid;
    
    /// @brief Maximum layers
    uint32_t maxLayers = UnpackerConstants::MAX_UNPACKING_LAYERS;
    
    /// @brief Maximum emulation instructions
    uint64_t maxInstructions = UnpackerConstants::MAX_EMULATION_INSTRUCTIONS;
    
    /// @brief Timeout (seconds)
    uint32_t timeoutSeconds = UnpackerConstants::DEFAULT_TIMEOUT_SECONDS;
    
    /// @brief Reconstruct imports
    bool reconstructImports = true;
    
    /// @brief Fix PE headers
    bool fixPEHeaders = true;
    
    /// @brief Extract overlay
    bool extractOverlay = false;
    
    /// @brief Dump all layers
    bool dumpAllLayers = false;
    
    /// @brief Anti-anti-debug
    bool antiAntiDebug = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct UnpackerStatistics {
    std::atomic<uint64_t> totalAttempts{0};
    std::atomic<uint64_t> successfulUnpacks{0};
    std::atomic<uint64_t> partialUnpacks{0};
    std::atomic<uint64_t> failedUnpacks{0};
    std::atomic<uint64_t> staticUnpacks{0};
    std::atomic<uint64_t> dynamicUnpacks{0};
    std::atomic<uint64_t> hybridUnpacks{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> importReconstructions{0};
    std::atomic<uint64_t> totalInstructionsEmulated{0};
    std::array<std::atomic<uint64_t>, 32> byPackerType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PackerUnpackerConfiguration {
    /// @brief Enable unpacker
    bool enabled = true;
    
    /// @brief Default options
    UnpackOptions defaultOptions;
    
    /// @brief Maximum concurrent unpacks
    uint32_t maxConcurrentUnpacks = 4;
    
    /// @brief Cache unpacked results
    bool enableCache = true;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTtlSeconds = 3600;
    
    /// @brief Worker threads
    uint32_t workerThreads = 2;
    
    /// @brief Custom packer scripts path
    fs::path scriptsPath;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using UnpackProgressCallback = std::function<void(uint32_t layer, const std::string& status)>;
using UnpackCompleteCallback = std::function<void(const UnpackResult& result)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PACKER UNPACKER CLASS
// ============================================================================

/**
 * @class PackerUnpacker
 * @brief Enterprise packer unpacking
 */
class PackerUnpacker final {
public:
    [[nodiscard]] static PackerUnpacker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PackerUnpacker(const PackerUnpacker&) = delete;
    PackerUnpacker& operator=(const PackerUnpacker&) = delete;
    PackerUnpacker(PackerUnpacker&&) = delete;
    PackerUnpacker& operator=(PackerUnpacker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PackerUnpackerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] UnpackerStatus GetStatus() const noexcept;

    // ========================================================================
    // PACKER DETECTION
    // ========================================================================
    
    /// @brief Detect packer in file
    [[nodiscard]] PackerDetectionResult DetectPacker(const fs::path& filePath);
    
    /// @brief Detect packer in buffer
    [[nodiscard]] PackerDetectionResult DetectPacker(std::span<const uint8_t> data);
    
    /// @brief Is file packed
    [[nodiscard]] bool IsPacked(const fs::path& filePath);
    
    /// @brief Is buffer packed
    [[nodiscard]] bool IsPacked(std::span<const uint8_t> data);

    // ========================================================================
    // UNPACKING
    // ========================================================================
    
    /// @brief Unpack file
    [[nodiscard]] UnpackResult UnpackFile(const fs::path& filePath, const UnpackOptions& options = {});
    
    /// @brief Unpack buffer (legacy interface)
    [[nodiscard]] bool Unpack(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
    
    /// @brief Unpack buffer with full result
    [[nodiscard]] UnpackResult UnpackBuffer(std::span<const uint8_t> input, const UnpackOptions& options = {});
    
    /// @brief Async unpack
    void UnpackAsync(const fs::path& filePath, UnpackCompleteCallback callback, const UnpackOptions& options = {});

    // ========================================================================
    // STATIC UNPACKING
    // ========================================================================
    
    /// @brief Static unpack UPX
    [[nodiscard]] UnpackResult UnpackUPX(std::span<const uint8_t> data);
    
    /// @brief Static unpack ASPack
    [[nodiscard]] UnpackResult UnpackASPack(std::span<const uint8_t> data);
    
    /// @brief Static unpack MPRESS
    [[nodiscard]] UnpackResult UnpackMPRESS(std::span<const uint8_t> data);
    
    /// @brief Static unpack by detected type
    [[nodiscard]] UnpackResult StaticUnpack(std::span<const uint8_t> data, PackerType type);

    // ========================================================================
    // DYNAMIC UNPACKING
    // ========================================================================
    
    /// @brief Dynamic unpack using emulation
    [[nodiscard]] UnpackResult DynamicUnpack(std::span<const uint8_t> data, const UnpackOptions& options = {});
    
    /// @brief Find Original Entry Point
    [[nodiscard]] std::optional<uint64_t> FindOEP(std::span<const uint8_t> data);

    // ========================================================================
    // IMPORT RECONSTRUCTION
    // ========================================================================
    
    /// @brief Reconstruct imports
    [[nodiscard]] std::vector<ImportEntry> ReconstructImports(
        std::span<const uint8_t> unpackedData,
        uint64_t imageBase);
    
    /// @brief Rebuild IAT
    [[nodiscard]] bool RebuildIAT(
        std::vector<uint8_t>& peData,
        const std::vector<ImportEntry>& imports);

    // ========================================================================
    // PE RECONSTRUCTION
    // ========================================================================
    
    /// @brief Fix PE headers
    [[nodiscard]] bool FixPEHeaders(std::vector<uint8_t>& peData, uint64_t oep);
    
    /// @brief Realign sections
    [[nodiscard]] bool RealignSections(std::vector<uint8_t>& peData);
    
    /// @brief Extract overlay
    [[nodiscard]] std::vector<uint8_t> ExtractOverlay(std::span<const uint8_t> data);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(UnpackProgressCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // CACHE
    // ========================================================================
    
    /// @brief Get cached result
    [[nodiscard]] std::optional<UnpackResult> GetCachedResult(const std::string& hash) const;
    
    /// @brief Clear cache
    void ClearCache();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] UnpackerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] std::vector<std::string> GetSupportedPackers() const;
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PackerUnpacker();
    ~PackerUnpacker();
    
    std::unique_ptr<PackerUnpackerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPackerTypeName(PackerType type) noexcept;
[[nodiscard]] std::string_view GetUnpackMethodName(UnpackMethod method) noexcept;
[[nodiscard]] std::string_view GetUnpackStatusName(UnpackStatus status) noexcept;
[[nodiscard]] std::string_view GetOEPDetectionMethodName(OEPDetectionMethod method) noexcept;

/// @brief Calculate section entropy
[[nodiscard]] float CalculateSectionEntropy(std::span<const uint8_t> data);

/// @brief Is high entropy section
[[nodiscard]] bool IsHighEntropySection(float entropy);

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IS_PACKED(path) \
    ::ShadowStrike::Core::Engine::PackerUnpacker::Instance().IsPacked(path)

#define SS_UNPACK(input, output) \
    ::ShadowStrike::Core::Engine::PackerUnpacker::Instance().Unpack(input, output)
