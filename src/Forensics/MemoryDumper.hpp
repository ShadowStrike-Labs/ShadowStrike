/**
 * ============================================================================
 * ShadowStrike Forensics - MEMORY ANALYSIS AND DUMP ENGINE
 * ============================================================================
 *
 * @file MemoryDumper.hpp
 * @brief Enterprise-grade process and system memory acquisition system for
 *        forensic analysis, malware investigation, and incident response.
 *
 * This module provides comprehensive memory dump capabilities including process
 * dumps, full system memory acquisition, and advanced memory analysis features.
 *
 * MEMORY DUMP CAPABILITIES:
 * =========================
 *
 * 1. PROCESS MEMORY DUMPS
 *    - MiniDump (minimal info)
 *    - Full memory dump
 *    - Custom dump types
 *    - Exception dumps
 *    - Triage dumps
 *
 * 2. SYSTEM MEMORY
 *    - Full RAM acquisition
 *    - Kernel memory dump
 *    - Pagefile analysis
 *    - Hibernation file analysis
 *    - Crash dump analysis
 *
 * 3. MEMORY ANALYSIS
 *    - String extraction (ASCII/UTF-16)
 *    - Pattern scanning
 *    - Executable extraction
 *    - PE detection in memory
 *    - Injection detection
 *
 * 4. DUMP FORMATS
 *    - Windows MiniDump (.dmp)
 *    - Full dump (.dmp)
 *    - Raw memory (.raw)
 *    - ELF core dump
 *    - Custom ShadowStrike format
 *
 * 5. ADVANCED FEATURES
 *    - VAD tree walking
 *    - Memory region classification
 *    - Heap analysis
 *    - Stack analysis
 *    - Module enumeration
 *
 * 6. INTEGRITY FEATURES
 *    - SHA-256 hashing
 *    - Chain of custody
 *    - Timestamp preservation
 *    - Acquisition metadata
 *
 * @note Uses DbgHelp API for MiniDump functionality.
 * @note Full RAM dump requires kernel driver or WinPMEM.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST
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
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>

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
#  include <DbgHelp.h>
#  include <TlHelp32.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/MemoryUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class MemoryDumperImpl;
    class EvidenceCollector;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MemoryDumpConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum dump file size (for single file)
    inline constexpr uint64_t MAX_DUMP_SIZE = 16ULL * 1024 * 1024 * 1024;  // 16GB
    
    /// @brief Maximum strings to extract
    inline constexpr size_t MAX_EXTRACTED_STRINGS = 1000000;
    
    /// @brief Minimum string length for extraction
    inline constexpr size_t MIN_STRING_LENGTH = 4;
    
    /// @brief Maximum string length for extraction
    inline constexpr size_t MAX_STRING_LENGTH = 4096;
    
    /// @brief Maximum concurrent dumps
    inline constexpr size_t MAX_CONCURRENT_DUMPS = 5;
    
    /// @brief Memory region scan batch size
    inline constexpr size_t REGION_SCAN_BATCH_SIZE = 64 * 1024;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Process dump timeout (milliseconds)
    inline constexpr uint32_t PROCESS_DUMP_TIMEOUT_MS = 120000;  // 2 minutes
    
    /// @brief Full memory dump timeout (milliseconds)
    inline constexpr uint32_t FULL_DUMP_TIMEOUT_MS = 600000;  // 10 minutes
    
    /// @brief String extraction timeout (milliseconds)
    inline constexpr uint32_t STRING_EXTRACTION_TIMEOUT_MS = 300000;  // 5 minutes

    // ========================================================================
    // HASHING
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;

    // ========================================================================
    // PATTERNS
    // ========================================================================
    
    /// @brief MZ header magic
    inline constexpr uint16_t MZ_MAGIC = 0x5A4D;
    
    /// @brief PE signature
    inline constexpr uint32_t PE_SIGNATURE = 0x00004550;

}  // namespace MemoryDumpConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Dump type
 */
enum class DumpType : uint32_t {
    MiniDumpNormal              = 0x00000000,   ///< Basic info only
    MiniDumpWithDataSegs        = 0x00000001,   ///< Include data segments
    MiniDumpWithFullMemory      = 0x00000002,   ///< Full process memory
    MiniDumpWithHandleData      = 0x00000004,   ///< Include handle data
    MiniDumpFilterMemory        = 0x00000008,   ///< Filter memory
    MiniDumpScanMemory          = 0x00000010,   ///< Scan for executables
    MiniDumpWithUnloadedModules = 0x00000020,   ///< Include unloaded modules
    MiniDumpWithIndirectlyRefMem= 0x00000040,   ///< Include indirectly referenced memory
    MiniDumpFilterModulePaths   = 0x00000080,   ///< Filter module paths
    MiniDumpWithProcessThreadData=0x00000100,   ///< Include thread data
    MiniDumpWithPrivateReadWrite= 0x00000200,   ///< Include private RW memory
    MiniDumpWithoutOptionalData = 0x00000400,   ///< Without optional data
    MiniDumpWithFullMemoryInfo  = 0x00000800,   ///< Full memory info
    MiniDumpWithThreadInfo      = 0x00001000,   ///< Thread info
    MiniDumpWithCodeSegs        = 0x00002000,   ///< Code segments
    MiniDumpWithoutAuxState     = 0x00004000,   ///< Without auxiliary state
    MiniDumpWithFullAuxState    = 0x00008000,   ///< Full auxiliary state
    MiniDumpWithPrivateWriteCopy= 0x00010000,   ///< Private write copy
    MiniDumpIgnoreInaccessibleMem=0x00020000,   ///< Ignore inaccessible memory
    MiniDumpWithTokenInfo       = 0x00040000,   ///< Include token info
    MiniDumpWithModuleHeaders   = 0x00080000,   ///< Include module headers
    MiniDumpFilterTriage        = 0x00100000,   ///< Triage dump
    MiniDumpWithAvxXStateContext= 0x00200000,   ///< AVX state
    MiniDumpWithIptTrace        = 0x00400000,   ///< Intel PT trace
    MiniDumpScanInaccessibleMem = 0x00800000,   ///< Scan inaccessible memory
    
    /// @brief Standard forensic dump (recommended)
    ForensicStandard            = MiniDumpWithFullMemory | MiniDumpWithHandleData |
                                  MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData |
                                  MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo |
                                  MiniDumpWithTokenInfo | MiniDumpWithModuleHeaders,
    
    /// @brief Quick triage dump
    Triage                      = MiniDumpFilterTriage | MiniDumpScanMemory
};

inline constexpr DumpType operator|(DumpType a, DumpType b) noexcept {
    return static_cast<DumpType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Memory region type
 */
enum class MemoryRegionType : uint8_t {
    Unknown         = 0,
    Image           = 1,    ///< Mapped image (DLL/EXE)
    Mapped          = 2,    ///< Memory-mapped file
    Private         = 3,    ///< Private memory
    Stack           = 4,    ///< Thread stack
    Heap            = 5,    ///< Heap memory
    PEB             = 6,    ///< Process Environment Block
    TEB             = 7,    ///< Thread Environment Block
    Shared          = 8,    ///< Shared memory
    Guard           = 9,    ///< Guard page
    Reserved        = 10    ///< Reserved memory
};

/**
 * @brief Memory protection flags
 */
enum class MemoryProtection : uint32_t {
    NoAccess            = 0x00000001,
    ReadOnly            = 0x00000002,
    ReadWrite           = 0x00000004,
    WriteCopy           = 0x00000008,
    Execute             = 0x00000010,
    ExecuteRead         = 0x00000020,
    ExecuteReadWrite    = 0x00000040,
    ExecuteWriteCopy    = 0x00000080,
    Guard               = 0x00000100,
    NoCache             = 0x00000200,
    WriteCombine        = 0x00000400
};

/**
 * @brief Dump format
 */
enum class DumpFormat : uint8_t {
    WindowsMiniDump = 0,    ///< Windows .dmp format
    RawMemory       = 1,    ///< Raw memory dump
    ShadowStrike    = 2,    ///< Custom encrypted format
    ELFCore         = 3,    ///< ELF core dump
    Volatility      = 4     ///< Volatility-compatible
};

/**
 * @brief Dump status
 */
enum class DumpStatus : uint8_t {
    NotStarted  = 0,
    InProgress  = 1,
    Completed   = 2,
    Failed      = 3,
    Cancelled   = 4,
    Partial     = 5
};

/**
 * @brief String type
 */
enum class StringType : uint8_t {
    ASCII   = 0,
    UTF16LE = 1,
    UTF16BE = 2,
    UTF8    = 3
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Memory region information
 */
struct MemoryRegion {
    /// @brief Base address
    uint64_t baseAddress = 0;
    
    /// @brief Allocation base
    uint64_t allocationBase = 0;
    
    /// @brief Region size
    uint64_t regionSize = 0;
    
    /// @brief Protection flags
    MemoryProtection protection = MemoryProtection::NoAccess;
    
    /// @brief State (committed, reserved, free)
    uint32_t state = 0;
    
    /// @brief Region type
    MemoryRegionType type = MemoryRegionType::Unknown;
    
    /// @brief Mapped file path (if any)
    std::wstring mappedFilePath;
    
    /// @brief Contains executable code
    bool isExecutable = false;
    
    /// @brief Contains writable data
    bool isWritable = false;
    
    /// @brief Is private memory
    bool isPrivate = false;
    
    /// @brief Contains PE header
    bool containsPE = false;
    
    /**
     * @brief Format as string
     */
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Extracted string
 */
struct ExtractedString {
    /// @brief String value
    std::string value;
    
    /// @brief Original address
    uint64_t address = 0;
    
    /// @brief String type
    StringType type = StringType::ASCII;
    
    /// @brief Source region type
    MemoryRegionType regionType = MemoryRegionType::Unknown;
    
    /// @brief Is potentially interesting (API, URL, path, etc.)
    bool isInteresting = false;
    
    /// @brief Category (URL, IP, path, API, etc.)
    std::string category;
};

/**
 * @brief Module information
 */
struct ModuleInfo {
    /// @brief Module base address
    uint64_t baseAddress = 0;
    
    /// @brief Module size
    uint64_t size = 0;
    
    /// @brief Module name
    std::wstring name;
    
    /// @brief Full path
    std::wstring path;
    
    /// @brief Module hash
    Hash256 hash{};
    
    /// @brief Entry point
    uint64_t entryPoint = 0;
    
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /// @brief Version info
    std::wstring version;
    
    /// @brief File description
    std::wstring description;
};

/**
 * @brief Thread information for dump
 */
struct ThreadDumpInfo {
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Start address
    uint64_t startAddress = 0;
    
    /// @brief Stack base
    uint64_t stackBase = 0;
    
    /// @brief Stack limit
    uint64_t stackLimit = 0;
    
    /// @brief TEB address
    uint64_t tebAddress = 0;
    
    /// @brief Current instruction pointer
    uint64_t instructionPointer = 0;
    
    /// @brief Thread state
    uint32_t state = 0;
    
    /// @brief Wait reason
    uint32_t waitReason = 0;
    
    /// @brief Priority
    int32_t priority = 0;
};

/**
 * @brief Dump metadata
 */
struct DumpMetadata {
    /// @brief Dump ID
    std::string dumpId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Dump type
    DumpType dumpType = DumpType::ForensicStandard;
    
    /// @brief Dump format
    DumpFormat format = DumpFormat::WindowsMiniDump;
    
    /// @brief Output path
    std::wstring outputPath;
    
    /// @brief Dump size (bytes)
    uint64_t dumpSize = 0;
    
    /// @brief Creation timestamp
    SystemTimePoint timestamp;
    
    /// @brief Hostname
    std::wstring hostname;
    
    /// @brief Examiner
    std::string examiner;
    
    /// @brief Incident ID
    std::string incidentId;
    
    /// @brief Dump hash
    Hash256 hash{};
    
    /// @brief Status
    DumpStatus status = DumpStatus::NotStarted;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Memory regions captured
    uint32_t regionsCaptured = 0;
    
    /// @brief Total memory size
    uint64_t totalMemorySize = 0;
    
    /// @brief Modules captured
    std::vector<ModuleInfo> modules;
    
    /// @brief Threads captured
    std::vector<ThreadDumpInfo> threads;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Dump options
 */
struct DumpOptions {
    /// @brief Dump type flags
    DumpType type = DumpType::ForensicStandard;
    
    /// @brief Output format
    DumpFormat format = DumpFormat::WindowsMiniDump;
    
    /// @brief Include module list
    bool includeModuleList = true;
    
    /// @brief Include thread info
    bool includeThreadInfo = true;
    
    /// @brief Extract strings after dump
    bool extractStrings = false;
    
    /// @brief Calculate hash
    bool calculateHash = true;
    
    /// @brief Compress output
    bool compress = false;
    
    /// @brief Encrypt output
    bool encrypt = false;
    
    /// @brief Encryption password
    std::string password;
    
    /// @brief Incident ID for linking
    std::string incidentId;
    
    /// @brief Examiner name
    std::string examiner;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = MemoryDumpConstants::PROCESS_DUMP_TIMEOUT_MS;
    
    /**
     * @brief Create quick dump options
     */
    static DumpOptions Quick();
    
    /**
     * @brief Create full dump options
     */
    static DumpOptions Full();
    
    /**
     * @brief Create forensic dump options
     */
    static DumpOptions Forensic();
};

/**
 * @brief String extraction options
 */
struct StringExtractionOptions {
    /// @brief Minimum string length
    size_t minLength = MemoryDumpConstants::MIN_STRING_LENGTH;
    
    /// @brief Maximum string length
    size_t maxLength = MemoryDumpConstants::MAX_STRING_LENGTH;
    
    /// @brief Extract ASCII strings
    bool extractASCII = true;
    
    /// @brief Extract UTF-16 strings
    bool extractUTF16 = true;
    
    /// @brief Filter printable only
    bool printableOnly = true;
    
    /// @brief Categorize strings
    bool categorize = true;
    
    /// @brief Maximum strings to extract
    size_t maxStrings = MemoryDumpConstants::MAX_EXTRACTED_STRINGS;
    
    /// @brief Region types to scan
    std::vector<MemoryRegionType> regionTypes;
    
    /// @brief Custom patterns to match
    std::vector<std::string> patterns;
};

/**
 * @brief Dump configuration
 */
struct MemoryDumperConfiguration {
    /// @brief Default dump options
    DumpOptions defaultOptions;
    
    /// @brief Output directory
    std::wstring outputDirectory;
    
    /// @brief Maximum concurrent dumps
    uint32_t maxConcurrentDumps = MemoryDumpConstants::MAX_CONCURRENT_DUMPS;
    
    /// @brief Enable verbose logging
    bool verboseLogging = false;
    
    /// @brief Auto-collect on detection
    bool autoCollect = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Dump statistics
 */
struct MemoryDumperStatistics {
    /// @brief Total dumps created
    std::atomic<uint64_t> totalDumps{0};
    
    /// @brief Successful dumps
    std::atomic<uint64_t> successfulDumps{0};
    
    /// @brief Failed dumps
    std::atomic<uint64_t> failedDumps{0};
    
    /// @brief Total bytes dumped
    std::atomic<uint64_t> totalBytesDumped{0};
    
    /// @brief Strings extracted
    std::atomic<uint64_t> stringsExtracted{0};
    
    /// @brief Active dumps
    std::atomic<uint32_t> activeDumps{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Dump progress callback
using DumpProgressCallback = std::function<void(uint8_t percentage, 
                                                const std::wstring& currentRegion)>;

/// @brief String extraction callback
using StringCallback = std::function<void(const ExtractedString&)>;

/// @brief Dump completion callback
using DumpCompletionCallback = std::function<void(const DumpMetadata&)>;

// ============================================================================
// MEMORY DUMPER ENGINE CLASS
// ============================================================================

/**
 * @class MemoryDumper
 * @brief Enterprise-grade memory dump and analysis engine
 *
 * Provides comprehensive process memory dump capabilities with
 * forensic integrity features and advanced analysis.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& dumper = MemoryDumper::Instance();
 *     
 *     // Create full process dump
 *     if (dumper.DumpProcess(pid, L"C:\\Evidence\\dump.dmp")) {
 *         // Dump created successfully
 *     }
 *     
 *     // Create mini dump
 *     dumper.CreateMiniDump(pid, L"C:\\Evidence\\mini.dmp");
 * @endcode
 */
class MemoryDumper final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static MemoryDumper& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    MemoryDumper(const MemoryDumper&) = delete;
    MemoryDumper& operator=(const MemoryDumper&) = delete;
    MemoryDumper(MemoryDumper&&) = delete;
    MemoryDumper& operator=(MemoryDumper&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize memory dumper
     */
    [[nodiscard]] bool Initialize(const MemoryDumperConfiguration& config = {});
    
    /**
     * @brief Shutdown memory dumper
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const MemoryDumperConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] MemoryDumperConfiguration GetConfiguration() const;
    
    // ========================================================================
    // PRIMARY DUMP METHODS
    // ========================================================================
    
    /**
     * @brief Create a full memory dump of a running process
     */
    [[nodiscard]] bool DumpProcess(uint32_t pid, const std::wstring& outputPath);
    
    /**
     * @brief Dump with options
     */
    [[nodiscard]] DumpMetadata DumpProcess(uint32_t pid, std::wstring_view outputPath,
                                           const DumpOptions& options);
    
    /**
     * @brief Create a lightweight minidump
     */
    [[nodiscard]] bool CreateMiniDump(uint32_t pid, const std::wstring& outputPath);
    
    /**
     * @brief Create minidump with custom flags
     */
    [[nodiscard]] DumpMetadata CreateMiniDump(uint32_t pid, std::wstring_view outputPath,
                                              DumpType type);
    
    /**
     * @brief Asynchronous dump
     */
    [[nodiscard]] std::string StartAsyncDump(uint32_t pid, std::wstring_view outputPath,
                                             const DumpOptions& options = {});
    
    /**
     * @brief Cancel async dump
     */
    [[nodiscard]] bool CancelDump(const std::string& dumpId);
    
    /**
     * @brief Get dump status
     */
    [[nodiscard]] std::optional<DumpMetadata> GetDumpStatus(const std::string& dumpId) const;
    
    /**
     * @brief Wait for dump to complete
     */
    [[nodiscard]] DumpStatus WaitForDump(const std::string& dumpId, uint32_t timeoutMs = 0);
    
    // ========================================================================
    // FULL SYSTEM MEMORY
    // ========================================================================
    
    /**
     * @brief Dump full system RAM (requires driver)
     */
    [[nodiscard]] bool DumpSystemMemory(std::wstring_view outputPath);
    
    /**
     * @brief Check if full memory dump is available
     */
    [[nodiscard]] bool IsFullDumpAvailable() const;
    
    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================
    
    /**
     * @brief Get process memory regions
     */
    [[nodiscard]] std::vector<MemoryRegion> GetMemoryRegions(uint32_t pid);
    
    /**
     * @brief Read memory region
     */
    [[nodiscard]] std::vector<uint8_t> ReadMemoryRegion(uint32_t pid, 
                                                        uint64_t baseAddress,
                                                        size_t size);
    
    /**
     * @brief Scan for PE headers in memory
     */
    [[nodiscard]] std::vector<uint64_t> ScanForPEHeaders(uint32_t pid);
    
    /**
     * @brief Extract PE from memory
     */
    [[nodiscard]] std::vector<uint8_t> ExtractPEFromMemory(uint32_t pid, 
                                                           uint64_t baseAddress);
    
    /**
     * @brief Get loaded modules
     */
    [[nodiscard]] std::vector<ModuleInfo> GetLoadedModules(uint32_t pid);
    
    /**
     * @brief Get thread information
     */
    [[nodiscard]] std::vector<ThreadDumpInfo> GetThreadInfo(uint32_t pid);
    
    // ========================================================================
    // STRING EXTRACTION
    // ========================================================================
    
    /**
     * @brief Extract strings from process memory
     */
    [[nodiscard]] std::vector<ExtractedString> ExtractStrings(uint32_t pid,
                                                               const StringExtractionOptions& options = {});
    
    /**
     * @brief Extract strings from dump file
     */
    [[nodiscard]] std::vector<ExtractedString> ExtractStringsFromDump(
        std::wstring_view dumpPath, const StringExtractionOptions& options = {});
    
    /**
     * @brief Stream strings (for large dumps)
     */
    void StreamStrings(uint32_t pid, StringCallback callback,
                       const StringExtractionOptions& options = {});
    
    // ========================================================================
    // DUMP FILE OPERATIONS
    // ========================================================================
    
    /**
     * @brief Load dump metadata
     */
    [[nodiscard]] std::optional<DumpMetadata> LoadDumpMetadata(std::wstring_view dumpPath);
    
    /**
     * @brief Verify dump integrity
     */
    [[nodiscard]] bool VerifyDumpIntegrity(std::wstring_view dumpPath);
    
    /**
     * @brief Convert dump format
     */
    [[nodiscard]] bool ConvertDump(std::wstring_view inputPath, std::wstring_view outputPath,
                                   DumpFormat targetFormat);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set progress callback
     */
    void SetProgressCallback(DumpProgressCallback callback);
    
    /**
     * @brief Set completion callback
     */
    void SetCompletionCallback(DumpCompletionCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] MemoryDumperStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    MemoryDumper();
    ~MemoryDumper();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<MemoryDumperImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get dump type name
 */
[[nodiscard]] std::string GetDumpTypeName(DumpType type);

/**
 * @brief Get memory region type name
 */
[[nodiscard]] std::string_view GetMemoryRegionTypeName(MemoryRegionType type) noexcept;

/**
 * @brief Get memory protection name
 */
[[nodiscard]] std::string GetMemoryProtectionName(MemoryProtection protection);

/**
 * @brief Get dump format name
 */
[[nodiscard]] std::string_view GetDumpFormatName(DumpFormat format) noexcept;

/**
 * @brief Get dump format extension
 */
[[nodiscard]] std::wstring_view GetDumpFormatExtension(DumpFormat format) noexcept;

/**
 * @brief Get dump status name
 */
[[nodiscard]] std::string_view GetDumpStatusName(DumpStatus status) noexcept;

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Create process dump
 */
#define SS_DUMP_PROCESS(pid, path) \
    ::ShadowStrike::Forensics::MemoryDumper::Instance().DumpProcess((pid), (path))

/**
 * @brief Create mini dump
 */
#define SS_MINI_DUMP(pid, path) \
    ::ShadowStrike::Forensics::MemoryDumper::Instance().CreateMiniDump((pid), (path))
