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
 * ShadowStrike Forensics - ARTIFACT EXTRACTION ENGINE
 * ============================================================================
 *
 * @file ArtifactExtractor.hpp
 * @brief Enterprise-grade Windows forensic artifact extraction system for
 *        post-infection analysis and incident reconstruction.
 *
 * This module provides comprehensive extraction and parsing of Windows
 * forensic artifacts to support malware analysis and incident investigation.
 *
 * ARTIFACT EXTRACTION CAPABILITIES:
 * ==================================
 *
 * 1. FILE SYSTEM ARTIFACTS
 *    - MFT (Master File Table) parsing
 *    - $USN Journal analysis
 *    - $LogFile parsing
 *    - Deleted file recovery
 *    - Alternate Data Streams
 *
 * 2. EXECUTION ARTIFACTS
 *    - Prefetch files (.pf)
 *    - Shimcache (Application Compatibility)
 *    - Amcache.hve parsing
 *    - SRUM (System Resource Usage)
 *    - BAM/DAM databases
 *
 * 3. PERSISTENCE ARTIFACTS
 *    - Registry Run keys
 *    - Scheduled tasks
 *    - Services
 *    - WMI subscriptions
 *    - Startup folders
 *
 * 4. USER ACTIVITY ARTIFACTS
 *    - Jump Lists
 *    - LNK files
 *    - Recent Documents
 *    - Shellbags
 *    - UserAssist
 *
 * 5. BROWSER ARTIFACTS
 *    - Chrome history/cache/downloads
 *    - Firefox history/cache
 *    - Edge/IE history
 *    - Saved credentials
 *    - Cookies
 *
 * 6. NETWORK ARTIFACTS
 *    - DNS cache
 *    - ARP cache
 *    - Network connections
 *    - Wi-Fi profiles
 *    - Firewall logs
 *
 * 7. LOG ARTIFACTS
 *    - Windows Event Logs
 *    - PowerShell logs
 *    - Sysmon logs
 *    - Application logs
 *    - Antivirus logs
 *
 * @note Requires elevated privileges for many operations.
 * @note Some artifacts require raw disk access.
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
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class ArtifactExtractorImpl;
    class EvidenceCollector;
    class TimelineAnalyzer;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ArtifactConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum artifacts per extraction
    inline constexpr size_t MAX_ARTIFACTS = 100000;
    
    /// @brief Maximum MFT records to parse
    inline constexpr size_t MAX_MFT_RECORDS = 10000000;
    
    /// @brief Maximum prefetch files
    inline constexpr size_t MAX_PREFETCH_FILES = 1024;
    
    /// @brief Maximum browser history entries
    inline constexpr size_t MAX_BROWSER_ENTRIES = 100000;
    
    /// @brief Maximum recovered file size
    inline constexpr uint64_t MAX_RECOVERED_FILE_SIZE = 100 * 1024 * 1024;  // 100MB

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Extraction timeout (milliseconds)
    inline constexpr uint32_t EXTRACTION_TIMEOUT_MS = 600000;  // 10 minutes
    
    /// @brief MFT parsing timeout (milliseconds)
    inline constexpr uint32_t MFT_TIMEOUT_MS = 300000;  // 5 minutes

    // ========================================================================
    // FILE SIGNATURES
    // ========================================================================
    
    /// @brief MFT FILE signature
    inline constexpr uint32_t MFT_FILE_SIGNATURE = 0x454C4946;  // "FILE"
    
    /// @brief Prefetch signature
    inline constexpr uint32_t PREFETCH_SIGNATURE_V30 = 0x1A;
    
    /// @brief LNK signature
    inline constexpr uint32_t LNK_SIGNATURE = 0x4C;

}  // namespace ArtifactConstants

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
 * @brief Artifact type
 */
enum class ArtifactType : uint32_t {
    Unknown             = 0x00000000,
    
    // File System
    MFTRecord           = 0x00000001,
    USNJournalEntry     = 0x00000002,
    DeletedFile         = 0x00000004,
    AlternateDataStream = 0x00000008,
    
    // Execution
    PrefetchFile        = 0x00000010,
    ShimcacheEntry      = 0x00000020,
    AmcacheEntry        = 0x00000040,
    SRUMEntry           = 0x00000080,
    BAMEntry            = 0x00000100,
    
    // Persistence
    RunKey              = 0x00000200,
    ScheduledTask       = 0x00000400,
    Service             = 0x00000800,
    WMISubscription     = 0x00001000,
    StartupItem         = 0x00002000,
    
    // User Activity
    JumpList            = 0x00004000,
    LNKFile             = 0x00008000,
    RecentDocument      = 0x00010000,
    Shellbag            = 0x00020000,
    UserAssist          = 0x00040000,
    
    // Browser
    BrowserHistory      = 0x00080000,
    BrowserDownload     = 0x00100000,
    BrowserCache        = 0x00200000,
    BrowserCookie       = 0x00400000,
    BrowserCredential   = 0x00800000,
    
    // Network
    DNSCache            = 0x01000000,
    ARPCache            = 0x02000000,
    NetworkConnection   = 0x04000000,
    
    // Logs
    EventLog            = 0x08000000,
    PowerShellLog       = 0x10000000,
    SysmonLog           = 0x20000000,
    
    // All types
    All                 = 0xFFFFFFFF
};

inline constexpr ArtifactType operator|(ArtifactType a, ArtifactType b) noexcept {
    return static_cast<ArtifactType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ArtifactType operator&(ArtifactType a, ArtifactType b) noexcept {
    return static_cast<ArtifactType>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Browser type
 */
enum class BrowserType : uint8_t {
    Unknown     = 0,
    Chrome      = 1,
    Firefox     = 2,
    Edge        = 3,
    IE          = 4,
    Opera       = 5,
    Brave       = 6,
    Vivaldi     = 7,
    Safari      = 8
};

/**
 * @brief MFT record flags
 */
enum class MFTRecordFlags : uint16_t {
    InUse       = 0x0001,
    Directory   = 0x0002,
    Unknown4    = 0x0004,
    Unknown8    = 0x0008
};

/**
 * @brief Extraction mode
 */
enum class ExtractionMode : uint8_t {
    Quick       = 0,    ///< Fast, common artifacts only
    Standard    = 1,    ///< Standard forensic collection
    Deep        = 2,    ///< Deep analysis including deleted
    Custom      = 3     ///< Custom artifact selection
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
 * @brief Base artifact structure
 */
struct BaseArtifact {
    /// @brief Artifact ID
    std::string artifactId;
    
    /// @brief Artifact type
    ArtifactType type = ArtifactType::Unknown;
    
    /// @brief Source path
    std::wstring sourcePath;
    
    /// @brief Collection timestamp
    SystemTimePoint collectionTime;
    
    /// @brief Artifact timestamp (from artifact itself)
    SystemTimePoint artifactTime;
    
    /// @brief Associated user SID
    std::wstring userSID;
    
    /// @brief Associated user name
    std::wstring userName;
    
    /// @brief Is artifact complete
    bool isComplete = true;
    
    /// @brief Raw data (if collected)
    std::vector<uint8_t> rawData;
    
    /// @brief Additional metadata
    std::unordered_map<std::string, std::string> metadata;
    
    /**
     * @brief Virtual destructor
     */
    virtual ~BaseArtifact() = default;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] virtual std::string ToJson() const;
};

/**
 * @brief MFT record
 */
struct MFTRecord : BaseArtifact {
    /// @brief Record number
    uint64_t recordNumber = 0;
    
    /// @brief Sequence number
    uint16_t sequenceNumber = 0;
    
    /// @brief Flags
    MFTRecordFlags flags = MFTRecordFlags::InUse;
    
    /// @brief File name
    std::wstring fileName;
    
    /// @brief Parent directory record number
    uint64_t parentRecordNumber = 0;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Allocated size
    uint64_t allocatedSize = 0;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Modification time
    SystemTimePoint modificationTime;
    
    /// @brief MFT modification time
    SystemTimePoint mftModificationTime;
    
    /// @brief Access time
    SystemTimePoint accessTime;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Is deleted
    bool isDeleted = false;
    
    /// @brief Has resident data
    bool hasResidentData = false;
    
    /// @brief Resident data
    std::vector<uint8_t> residentData;
    
    /// @brief Data runs (for non-resident)
    std::vector<std::pair<uint64_t, uint64_t>> dataRuns;
    
    /// @brief Alternate data streams
    std::vector<std::pair<std::wstring, uint64_t>> alternateStreams;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Prefetch file
 */
struct PrefetchEntry : BaseArtifact {
    /// @brief Executable name
    std::wstring executableName;
    
    /// @brief Executable path
    std::wstring executablePath;
    
    /// @brief Hash (part of filename)
    uint32_t prefetchHash = 0;
    
    /// @brief Run count
    uint32_t runCount = 0;
    
    /// @brief Last run times (up to 8)
    std::vector<SystemTimePoint> lastRunTimes;
    
    /// @brief Volume information
    std::vector<std::wstring> volumes;
    
    /// @brief Loaded files
    std::vector<std::wstring> loadedFiles;
    
    /// @brief Loaded directories
    std::vector<std::wstring> loadedDirectories;
    
    /// @brief Prefetch version
    uint32_t version = 0;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Shimcache entry
 */
struct ShimcacheEntry : BaseArtifact {
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Last modification time
    SystemTimePoint lastModifiedTime;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Execution flag
    bool executed = false;
    
    /// @brief Cache index
    uint32_t cacheIndex = 0;
    
    /// @brief Control set
    uint32_t controlSet = 1;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Amcache entry
 */
struct AmcacheEntry : BaseArtifact {
    /// @brief File path
    std::wstring filePath;
    
    /// @brief File SHA-1 hash
    std::string sha1Hash;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Product name
    std::wstring productName;
    
    /// @brief Company name
    std::wstring companyName;
    
    /// @brief File version
    std::wstring fileVersion;
    
    /// @brief Description
    std::wstring description;
    
    /// @brief Link timestamp
    SystemTimePoint linkTimestamp;
    
    /// @brief Last write time
    SystemTimePoint lastWriteTime;
    
    /// @brief Is PE file
    bool isPE = false;
    
    /// @brief Original filename
    std::wstring originalFileName;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Browser history entry
 */
struct BrowserHistoryEntry : BaseArtifact {
    /// @brief Browser type
    BrowserType browser = BrowserType::Unknown;
    
    /// @brief URL
    std::string url;
    
    /// @brief Title
    std::wstring title;
    
    /// @brief Visit time
    SystemTimePoint visitTime;
    
    /// @brief Visit count
    uint32_t visitCount = 0;
    
    /// @brief Is typed URL
    bool isTyped = false;
    
    /// @brief Referrer URL
    std::string referrerUrl;
    
    /// @brief Profile name
    std::wstring profile;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief LNK file (shortcut)
 */
struct LNKFileEntry : BaseArtifact {
    /// @brief LNK file path
    std::wstring lnkPath;
    
    /// @brief Target path
    std::wstring targetPath;
    
    /// @brief Working directory
    std::wstring workingDirectory;
    
    /// @brief Arguments
    std::wstring arguments;
    
    /// @brief Target creation time
    SystemTimePoint targetCreationTime;
    
    /// @brief Target modification time
    SystemTimePoint targetModificationTime;
    
    /// @brief Target access time
    SystemTimePoint targetAccessTime;
    
    /// @brief Target file size
    uint64_t targetFileSize = 0;
    
    /// @brief Machine identifier
    std::string machineId;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief Volume serial number
    uint32_t volumeSerialNumber = 0;
    
    /// @brief Has network location
    bool hasNetworkLocation = false;
    
    /// @brief Network share path
    std::wstring networkPath;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Jump list entry
 */
struct JumpListEntry : BaseArtifact {
    /// @brief Application ID
    std::wstring appId;
    
    /// @brief Target path
    std::wstring targetPath;
    
    /// @brief Entry type (recent/pinned)
    std::string entryType;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Modification time
    SystemTimePoint modificationTime;
    
    /// @brief Access time
    SystemTimePoint accessTime;
    
    /// @brief Arguments
    std::wstring arguments;
    
    /// @brief Working directory
    std::wstring workingDirectory;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief UserAssist entry
 */
struct UserAssistEntry : BaseArtifact {
    /// @brief ROT13 decoded name
    std::wstring name;
    
    /// @brief Run count
    uint32_t runCount = 0;
    
    /// @brief Focus count
    uint32_t focusCount = 0;
    
    /// @brief Focus time (100ns)
    uint64_t focusTime = 0;
    
    /// @brief Last execution time
    SystemTimePoint lastExecutionTime;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief GUID
    std::string guid;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Shellbag entry
 */
struct ShellbagEntry : BaseArtifact {
    /// @brief Path
    std::wstring path;
    
    /// @brief Slot modified time
    SystemTimePoint slotModifiedTime;
    
    /// @brief First explored time
    SystemTimePoint firstExploredTime;
    
    /// @brief Last explored time
    SystemTimePoint lastExploredTime;
    
    /// @brief Item type
    std::string itemType;
    
    /// @brief Registry path
    std::wstring registryPath;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Scheduled task entry
 */
struct ScheduledTaskEntry : BaseArtifact {
    /// @brief Task name
    std::wstring taskName;
    
    /// @brief Task path
    std::wstring taskPath;
    
    /// @brief Action (command)
    std::wstring action;
    
    /// @brief Arguments
    std::wstring arguments;
    
    /// @brief Author
    std::wstring author;
    
    /// @brief Description
    std::wstring description;
    
    /// @brief Registration time
    SystemTimePoint registrationTime;
    
    /// @brief Last run time
    SystemTimePoint lastRunTime;
    
    /// @brief Next run time
    SystemTimePoint nextRunTime;
    
    /// @brief Trigger type
    std::string triggerType;
    
    /// @brief Is enabled
    bool isEnabled = false;
    
    /// @brief Run level
    std::string runLevel;
    
    [[nodiscard]] std::string ToJson() const override;
};

/**
 * @brief Extraction configuration
 */
struct ExtractionConfiguration {
    /// @brief Extraction mode
    ExtractionMode mode = ExtractionMode::Standard;
    
    /// @brief Artifact types to extract
    ArtifactType artifactTypes = ArtifactType::All;
    
    /// @brief Output directory
    std::wstring outputDirectory;
    
    /// @brief Include raw data
    bool includeRawData = false;
    
    /// @brief Parse deleted files
    bool parseDeletedFiles = true;
    
    /// @brief Time range start
    std::optional<SystemTimePoint> timeRangeStart;
    
    /// @brief Time range end
    std::optional<SystemTimePoint> timeRangeEnd;
    
    /// @brief Target users (empty = all)
    std::vector<std::wstring> targetUsers;
    
    /// @brief Browsers to parse
    std::vector<BrowserType> browsers;
    
    /// @brief Maximum artifacts per type
    size_t maxArtifactsPerType = ArtifactConstants::MAX_ARTIFACTS;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = ArtifactConstants::EXTRACTION_TIMEOUT_MS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Extraction statistics
 */
struct ExtractionStatistics {
    /// @brief Total extractions
    std::atomic<uint64_t> totalExtractions{0};
    
    /// @brief Total artifacts extracted
    std::atomic<uint64_t> totalArtifacts{0};
    
    /// @brief MFT records parsed
    std::atomic<uint64_t> mftRecordsParsed{0};
    
    /// @brief Prefetch files parsed
    std::atomic<uint64_t> prefetchFilesParsed{0};
    
    /// @brief Deleted files found
    std::atomic<uint64_t> deletedFilesFound{0};
    
    /// @brief Files recovered
    std::atomic<uint64_t> filesRecovered{0};
    
    /// @brief Browser entries found
    std::atomic<uint64_t> browserEntriesFound{0};
    
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

/// @brief Artifact callback
using ArtifactCallback = std::function<void(const BaseArtifact&)>;

/// @brief Progress callback
using ExtractionProgressCallback = std::function<void(ArtifactType currentType,
                                                      uint32_t percentage,
                                                      const std::wstring& currentItem)>;

// ============================================================================
// ARTIFACT EXTRACTOR ENGINE CLASS
// ============================================================================

/**
 * @class ArtifactExtractor
 * @brief Enterprise-grade Windows artifact extraction engine
 *
 * Provides comprehensive extraction and parsing of Windows forensic
 * artifacts for incident investigation and malware analysis.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& extractor = ArtifactExtractor::Instance();
 *     
 *     // Extract all artifacts
 *     extractor.ExtractAll(L"C:\\Evidence");
 *     
 *     // Recover deleted file
 *     std::vector<uint8_t> data;
 *     if (extractor.RecoverFile(L"malware.exe", data)) {
 *         // File recovered
 *     }
 * @endcode
 */
class ArtifactExtractor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static ArtifactExtractor& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    ArtifactExtractor(const ArtifactExtractor&) = delete;
    ArtifactExtractor& operator=(const ArtifactExtractor&) = delete;
    ArtifactExtractor(ArtifactExtractor&&) = delete;
    ArtifactExtractor& operator=(ArtifactExtractor&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize artifact extractor
     */
    [[nodiscard]] bool Initialize(const ExtractionConfiguration& config = {});
    
    /**
     * @brief Shutdown artifact extractor
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
    // COMPREHENSIVE EXTRACTION
    // ========================================================================
    
    /**
     * @brief Perform a comprehensive artifact sweep
     */
    void ExtractAll(const std::wstring& outputDir);
    
    /**
     * @brief Extract with configuration
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ExtractAll(
        const ExtractionConfiguration& config);
    
    /**
     * @brief Extract specific artifact types
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ExtractTypes(
        ArtifactType types, std::wstring_view outputDir = L"");
    
    // ========================================================================
    // FILE SYSTEM ARTIFACTS
    // ========================================================================
    
    /**
     * @brief Parse MFT
     */
    [[nodiscard]] std::vector<MFTRecord> ParseMFT(wchar_t driveLetter = L'C');
    
    /**
     * @brief Get deleted files from MFT
     */
    [[nodiscard]] std::vector<MFTRecord> GetDeletedFiles(wchar_t driveLetter = L'C');
    
    /**
     * @brief Recover a deleted file from MFT (if possible)
     */
    [[nodiscard]] bool RecoverFile(const std::wstring& fileName, std::vector<uint8_t>& outData);
    
    /**
     * @brief Recover file by MFT record number
     */
    [[nodiscard]] bool RecoverFileByMFT(uint64_t recordNumber, std::vector<uint8_t>& outData,
                                        wchar_t driveLetter = L'C');
    
    /**
     * @brief Parse USN Journal
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseUSNJournal(
        wchar_t driveLetter = L'C');
    
    /**
     * @brief Get alternate data streams
     */
    [[nodiscard]] std::vector<std::pair<std::wstring, std::wstring>> GetAlternateDataStreams(
        std::wstring_view path);
    
    // ========================================================================
    // EXECUTION ARTIFACTS
    // ========================================================================
    
    /**
     * @brief Parse prefetch files
     */
    [[nodiscard]] std::vector<PrefetchEntry> ParsePrefetch();
    
    /**
     * @brief Parse Shimcache
     */
    [[nodiscard]] std::vector<ShimcacheEntry> ParseShimcache();
    
    /**
     * @brief Parse Amcache
     */
    [[nodiscard]] std::vector<AmcacheEntry> ParseAmcache();
    
    /**
     * @brief Parse SRUM database
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseSRUM();
    
    /**
     * @brief Parse BAM/DAM
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseBAM();
    
    // ========================================================================
    // USER ACTIVITY ARTIFACTS
    // ========================================================================
    
    /**
     * @brief Parse Jump Lists
     */
    [[nodiscard]] std::vector<JumpListEntry> ParseJumpLists(std::wstring_view userProfile = L"");
    
    /**
     * @brief Parse LNK files
     */
    [[nodiscard]] std::vector<LNKFileEntry> ParseLNKFiles(std::wstring_view directory = L"");
    
    /**
     * @brief Parse UserAssist
     */
    [[nodiscard]] std::vector<UserAssistEntry> ParseUserAssist(std::wstring_view userSID = L"");
    
    /**
     * @brief Parse Shellbags
     */
    [[nodiscard]] std::vector<ShellbagEntry> ParseShellbags(std::wstring_view userSID = L"");
    
    // ========================================================================
    // BROWSER ARTIFACTS
    // ========================================================================
    
    /**
     * @brief Parse browser history
     */
    [[nodiscard]] std::vector<BrowserHistoryEntry> ParseBrowserHistory(
        BrowserType browser = BrowserType::Unknown);
    
    /**
     * @brief Parse all browser histories
     */
    [[nodiscard]] std::vector<BrowserHistoryEntry> ParseAllBrowserHistories();
    
    /**
     * @brief Parse browser downloads
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseBrowserDownloads(
        BrowserType browser = BrowserType::Unknown);
    
    // ========================================================================
    // PERSISTENCE ARTIFACTS
    // ========================================================================
    
    /**
     * @brief Parse scheduled tasks
     */
    [[nodiscard]] std::vector<ScheduledTaskEntry> ParseScheduledTasks();
    
    /**
     * @brief Parse Run keys
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseRunKeys();
    
    /**
     * @brief Parse services
     */
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ParseServices();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set artifact callback
     */
    void SetArtifactCallback(ArtifactCallback callback);
    
    /**
     * @brief Set progress callback
     */
    void SetProgressCallback(ExtractionProgressCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] ExtractionStatistics GetStatistics() const;
    
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
    
    ArtifactExtractor();
    ~ArtifactExtractor();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<ArtifactExtractorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get artifact type name
 */
[[nodiscard]] std::string_view GetArtifactTypeName(ArtifactType type) noexcept;

/**
 * @brief Get browser type name
 */
[[nodiscard]] std::string_view GetBrowserTypeName(BrowserType type) noexcept;

/**
 * @brief Get extraction mode name
 */
[[nodiscard]] std::string_view GetExtractionModeName(ExtractionMode mode) noexcept;

/**
 * @brief Decode ROT13 (for UserAssist)
 */
[[nodiscard]] std::wstring DecodeROT13(std::wstring_view encoded);

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Extract all artifacts
 */
#define SS_EXTRACT_ARTIFACTS(outputDir) \
    ::ShadowStrike::Forensics::ArtifactExtractor::Instance().ExtractAll(outputDir)

/**
 * @brief Recover deleted file
 */
#define SS_RECOVER_FILE(fileName, outData) \
    ::ShadowStrike::Forensics::ArtifactExtractor::Instance().RecoverFile((fileName), (outData))
