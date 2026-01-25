/**
 * ============================================================================
 * ShadowStrike Forensics - DIGITAL EVIDENCE COLLECTION ENGINE
 * ============================================================================
 *
 * @file EvidenceCollector.hpp
 * @brief Enterprise-grade digital evidence collection and preservation system
 *        for forensic analysis, incident response, and legal proceedings.
 *
 * This module provides comprehensive evidence collection capabilities following
 * forensic best practices and legal requirements for chain of custody.
 *
 * COLLECTION CAPABILITIES:
 * ========================
 *
 * 1. FILE EVIDENCE
 *    - Malware sample acquisition
 *    - Related file collection
 *    - Deleted file recovery
 *    - Alternate data streams
 *    - File metadata extraction
 *
 * 2. PROCESS EVIDENCE
 *    - Memory dump collection
 *    - Process metadata
 *    - Command line arguments
 *    - Environment variables
 *    - Loaded modules
 *
 * 3. SYSTEM STATE
 *    - Running processes snapshot
 *    - Network connections
 *    - Registry state
 *    - Service status
 *    - Scheduled tasks
 *
 * 4. NETWORK EVIDENCE
 *    - Active connections
 *    - DNS cache
 *    - ARP cache
 *    - Routing tables
 *    - Firewall rules
 *
 * 5. LOG COLLECTION
 *    - Windows Event Logs
 *    - Application logs
 *    - Security logs
 *    - PowerShell logs
 *    - Sysmon logs
 *
 * 6. ARTIFACT COLLECTION
 *    - Browser artifacts
 *    - Prefetch files
 *    - Jump lists
 *    - Recent documents
 *    - Shimcache/Amcache
 *
 * CHAIN OF CUSTODY:
 * =================
 * - SHA-256 hashing of all evidence
 * - Timestamping with trusted TSA
 * - Digital signing of containers
 * - Tamper-evident sealing
 * - Collection audit logging
 *
 * CONTAINER FORMATS:
 * ==================
 * - ShadowStrike Forensic Container (.sfc)
 * - Encrypted ZIP archives
 * - Virtual Hard Disk (VHD/VHDX)
 * - Raw forensic images
 *
 * @note Follows NIST SP 800-86 guidelines.
 * @note ACPO/SWGDE compliant evidence handling.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST, ACPO, SWGDE
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
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <future>
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
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/CompressionUtils.hpp"
#include "../Security/CryptoManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class EvidenceCollectorImpl;
    class ArtifactExtractor;
    class MemoryDumper;
    class IncidentRecorder;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace EvidenceConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum evidence items per collection
    inline constexpr size_t MAX_EVIDENCE_ITEMS = 10000;
    
    /// @brief Maximum file size for individual evidence
    inline constexpr size_t MAX_FILE_SIZE = 2ULL * 1024 * 1024 * 1024;  // 2GB
    
    /// @brief Maximum total collection size
    inline constexpr size_t MAX_COLLECTION_SIZE = 50ULL * 1024 * 1024 * 1024;  // 50GB
    
    /// @brief Maximum concurrent collections
    inline constexpr size_t MAX_CONCURRENT_COLLECTIONS = 5;
    
    /// @brief Maximum container password length
    inline constexpr size_t MAX_PASSWORD_LENGTH = 256;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Collection timeout (milliseconds)
    inline constexpr uint32_t COLLECTION_TIMEOUT_MS = 300000;  // 5 minutes
    
    /// @brief File acquisition timeout (milliseconds)
    inline constexpr uint32_t FILE_TIMEOUT_MS = 60000;  // 1 minute
    
    /// @brief Memory dump timeout (milliseconds)
    inline constexpr uint32_t MEMORY_DUMP_TIMEOUT_MS = 120000;  // 2 minutes

    // ========================================================================
    // HASHING
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;
    inline constexpr size_t MD5_SIZE = 16;

    // ========================================================================
    // CONTAINER
    // ========================================================================
    
    /// @brief SFC container magic
    inline constexpr uint32_t SFC_MAGIC = 0x53464321;  // "SFC!"
    
    /// @brief SFC container version
    inline constexpr uint32_t SFC_VERSION = 1;

}  // namespace EvidenceConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;
using Hash128 = std::array<uint8_t, 16>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Evidence type
 */
enum class EvidenceType : uint8_t {
    Unknown             = 0,
    MalwareFile         = 1,    ///< Suspicious/malicious file
    ProcessDump         = 2,    ///< Process memory dump
    SystemMemory        = 3,    ///< Full system memory
    RegistryHive        = 4,    ///< Registry hive export
    EventLog            = 5,    ///< Windows Event Log
    NetworkCapture      = 6,    ///< Network packet capture
    FileSystemArtifact  = 7,    ///< MFT, prefetch, etc.
    BrowserArtifact     = 8,    ///< Browser history, cache
    ConfigurationFile   = 9,    ///< System/app config
    LogFile             = 10,   ///< Application log
    Screenshot          = 11,   ///< Screen capture
    SystemState         = 12,   ///< Process list, connections
    Metadata            = 13,   ///< Collection metadata
    Custom              = 255   ///< User-defined
};

/**
 * @brief Evidence category
 */
enum class EvidenceCategory : uint8_t {
    Uncategorized       = 0,
    Malware             = 1,
    SystemState         = 2,
    UserActivity        = 3,
    NetworkActivity     = 4,
    VolatileData        = 5,
    PersistentData      = 6,
    Logs                = 7,
    Artifacts           = 8
};

/**
 * @brief Collection mode
 */
enum class CollectionMode : uint8_t {
    Quick           = 0,    ///< Fast, essential evidence only
    Standard        = 1,    ///< Standard forensic collection
    Comprehensive   = 2,    ///< Full forensic acquisition
    IncidentResponse= 3,    ///< IR-focused collection
    Malware         = 4,    ///< Malware analysis focused
    Custom          = 5     ///< Custom collection profile
};

/**
 * @brief Container format
 */
enum class ContainerFormat : uint8_t {
    SFC         = 0,    ///< ShadowStrike Forensic Container
    EncryptedZip= 1,    ///< AES-256 encrypted ZIP
    VHD         = 2,    ///< Virtual Hard Disk
    VHDX        = 3,    ///< VHDX format
    Raw         = 4,    ///< Raw directory structure
    E01         = 5     ///< EnCase format
};

/**
 * @brief Collection status
 */
enum class CollectionStatus : uint8_t {
    NotStarted      = 0,
    InProgress      = 1,
    Paused          = 2,
    Completed       = 3,
    Failed          = 4,
    Cancelled       = 5,
    PartialSuccess  = 6
};

/**
 * @brief Evidence integrity status
 */
enum class IntegrityStatus : uint8_t {
    Unknown     = 0,
    Verified    = 1,
    Modified    = 2,
    Corrupted   = 3,
    Missing     = 4
};

/**
 * @brief Collection flags
 */
enum class CollectionFlags : uint32_t {
    None                    = 0x00000000,
    IncludeProcessDumps     = 0x00000001,
    IncludeRelatedFiles     = 0x00000002,
    IncludeRegistryKeys     = 0x00000004,
    IncludeEventLogs        = 0x00000008,
    IncludeNetworkState     = 0x00000010,
    IncludeSystemState      = 0x00000020,
    IncludeBrowserArtifacts = 0x00000040,
    IncludePrefetch         = 0x00000080,
    RecoverDeletedFiles     = 0x00000100,
    CollectAlternateStreams = 0x00000200,
    HashAllFiles            = 0x00000400,
    SignContainer           = 0x00000800,
    EncryptContainer        = 0x00001000,
    CompressData            = 0x00002000,
    
    Quick                   = IncludeProcessDumps | HashAllFiles,
    Standard                = Quick | IncludeRelatedFiles | IncludeRegistryKeys | 
                              IncludeEventLogs | CompressData,
    Comprehensive           = Standard | IncludeNetworkState | IncludeSystemState | 
                              IncludeBrowserArtifacts | IncludePrefetch | 
                              RecoverDeletedFiles | CollectAlternateStreams | 
                              SignContainer | EncryptContainer
};

inline constexpr CollectionFlags operator|(CollectionFlags a, CollectionFlags b) noexcept {
    return static_cast<CollectionFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr CollectionFlags operator&(CollectionFlags a, CollectionFlags b) noexcept {
    return static_cast<CollectionFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

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
 * @brief Evidence item metadata
 */
struct EvidenceItem {
    /// @brief Unique item ID
    std::string itemId;
    
    /// @brief Evidence type
    EvidenceType type = EvidenceType::Unknown;
    
    /// @brief Category
    EvidenceCategory category = EvidenceCategory::Uncategorized;
    
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Stored path in container
    std::wstring storedPath;
    
    /// @brief Original file name
    std::wstring originalName;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief SHA-256 hash
    Hash256 sha256Hash{};
    
    /// @brief MD5 hash (for compatibility)
    Hash128 md5Hash{};
    
    /// @brief File creation time
    SystemTimePoint creationTime;
    
    /// @brief File modification time
    SystemTimePoint modificationTime;
    
    /// @brief File access time
    SystemTimePoint accessTime;
    
    /// @brief Collection time
    SystemTimePoint collectionTime;
    
    /// @brief Source PID (if process-related)
    uint32_t sourcePID = 0;
    
    /// @brief Related incident ID
    std::string incidentId;
    
    /// @brief Description
    std::string description;
    
    /// @brief Custom tags
    std::vector<std::string> tags;
    
    /// @brief Additional metadata
    std::unordered_map<std::string, std::string> metadata;
    
    /// @brief Integrity status
    IntegrityStatus integrity = IntegrityStatus::Unknown;
    
    /// @brief Is compressed
    bool isCompressed = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
    
    /**
     * @brief Get hash as hex string
     */
    [[nodiscard]] std::string GetSHA256Hex() const;
    
    /**
     * @brief Get hash as hex string
     */
    [[nodiscard]] std::string GetMD5Hex() const;
};

/**
 * @brief System state snapshot
 */
struct SystemStateSnapshot {
    /// @brief Snapshot timestamp
    SystemTimePoint timestamp;
    
    /// @brief Running processes
    struct ProcessInfo {
        uint32_t pid;
        uint32_t ppid;
        std::wstring name;
        std::wstring path;
        std::wstring commandLine;
        std::wstring user;
        uint64_t memoryUsage;
        SystemTimePoint startTime;
    };
    std::vector<ProcessInfo> processes;
    
    /// @brief Network connections
    struct ConnectionInfo {
        std::string localAddress;
        uint16_t localPort;
        std::string remoteAddress;
        uint16_t remotePort;
        std::string protocol;
        std::string state;
        uint32_t owningPid;
    };
    std::vector<ConnectionInfo> connections;
    
    /// @brief Loaded drivers
    struct DriverInfo {
        std::wstring name;
        std::wstring path;
        void* baseAddress;
        size_t size;
    };
    std::vector<DriverInfo> drivers;
    
    /// @brief Services
    struct ServiceInfo {
        std::wstring name;
        std::wstring displayName;
        std::wstring path;
        uint32_t state;
        uint32_t startType;
    };
    std::vector<ServiceInfo> services;
    
    /// @brief Scheduled tasks
    struct TaskInfo {
        std::wstring name;
        std::wstring path;
        std::wstring action;
        std::wstring trigger;
    };
    std::vector<TaskInfo> scheduledTasks;
    
    /// @brief DNS cache
    std::vector<std::pair<std::wstring, std::string>> dnsCache;
    
    /// @brief ARP cache
    std::vector<std::tuple<std::string, std::string, std::string>> arpCache;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Evidence container metadata
 */
struct ContainerMetadata {
    /// @brief Container ID
    std::string containerId;
    
    /// @brief Container format
    ContainerFormat format = ContainerFormat::SFC;
    
    /// @brief Creation timestamp
    SystemTimePoint createdAt;
    
    /// @brief Creator information
    std::string createdBy;
    
    /// @brief Hostname
    std::wstring hostname;
    
    /// @brief Machine GUID
    std::string machineGuid;
    
    /// @brief Collection mode
    CollectionMode mode = CollectionMode::Standard;
    
    /// @brief Total items
    uint32_t totalItems = 0;
    
    /// @brief Total size (bytes)
    uint64_t totalSize = 0;
    
    /// @brief Incident ID
    std::string incidentId;
    
    /// @brief Case number
    std::string caseNumber;
    
    /// @brief Examiner name
    std::string examinerName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief Container hash
    Hash256 containerHash{};
    
    /// @brief Signature (if signed)
    std::vector<uint8_t> signature;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Chain of custody entry
 */
struct ChainOfCustodyEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Action performed
    std::string action;
    
    /// @brief Person/system performing action
    std::string actor;
    
    /// @brief Description
    std::string description;
    
    /// @brief Location
    std::string location;
    
    /// @brief Hash before action
    Hash256 hashBefore{};
    
    /// @brief Hash after action
    Hash256 hashAfter{};
    
    /// @brief Digital signature
    std::vector<uint8_t> signature;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Collection profile
 */
struct CollectionProfile {
    /// @brief Profile name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Collection flags
    CollectionFlags flags = CollectionFlags::Standard;
    
    /// @brief Container format
    ContainerFormat containerFormat = ContainerFormat::SFC;
    
    /// @brief File patterns to include
    std::vector<std::wstring> includePatterns;
    
    /// @brief File patterns to exclude
    std::vector<std::wstring> excludePatterns;
    
    /// @brief Registry keys to collect
    std::vector<std::wstring> registryKeys;
    
    /// @brief Event log names
    std::vector<std::wstring> eventLogs;
    
    /// @brief Maximum file size
    uint64_t maxFileSize = EvidenceConstants::MAX_FILE_SIZE;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = EvidenceConstants::COLLECTION_TIMEOUT_MS;
    
    /**
     * @brief Create from mode
     */
    static CollectionProfile FromMode(CollectionMode mode);
};

/**
 * @brief Collection configuration
 */
struct CollectionConfiguration {
    /// @brief Default collection mode
    CollectionMode defaultMode = CollectionMode::Standard;
    
    /// @brief Default container format
    ContainerFormat containerFormat = ContainerFormat::SFC;
    
    /// @brief Output directory
    std::wstring outputDirectory;
    
    /// @brief Enable compression
    bool enableCompression = true;
    
    /// @brief Enable encryption
    bool enableEncryption = true;
    
    /// @brief Default password (if encryption enabled)
    std::string defaultPassword;
    
    /// @brief Sign containers
    bool signContainers = true;
    
    /// @brief Signing certificate thumbprint
    std::vector<uint8_t> signingCertThumbprint;
    
    /// @brief TSA URL for timestamping
    std::string tsaUrl;
    
    /// @brief Maximum concurrent collections
    uint32_t maxConcurrentCollections = EvidenceConstants::MAX_CONCURRENT_COLLECTIONS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Collection progress
 */
struct CollectionProgress {
    /// @brief Collection ID
    std::string collectionId;
    
    /// @brief Status
    CollectionStatus status = CollectionStatus::NotStarted;
    
    /// @brief Progress percentage (0-100)
    uint8_t percentage = 0;
    
    /// @brief Current phase
    std::string currentPhase;
    
    /// @brief Current item being collected
    std::wstring currentItem;
    
    /// @brief Items collected
    uint32_t itemsCollected = 0;
    
    /// @brief Items failed
    uint32_t itemsFailed = 0;
    
    /// @brief Total items to collect
    uint32_t totalItems = 0;
    
    /// @brief Bytes collected
    uint64_t bytesCollected = 0;
    
    /// @brief Start time
    TimePoint startTime;
    
    /// @brief Estimated completion time
    TimePoint estimatedCompletion;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
};

/**
 * @brief Collection statistics
 */
struct CollectionStatistics {
    /// @brief Total collections
    std::atomic<uint64_t> totalCollections{0};
    
    /// @brief Successful collections
    std::atomic<uint64_t> successfulCollections{0};
    
    /// @brief Failed collections
    std::atomic<uint64_t> failedCollections{0};
    
    /// @brief Total evidence items
    std::atomic<uint64_t> totalEvidenceItems{0};
    
    /// @brief Total bytes collected
    std::atomic<uint64_t> totalBytesCollected{0};
    
    /// @brief Total containers created
    std::atomic<uint64_t> totalContainers{0};
    
    /// @brief Active collections
    std::atomic<uint32_t> activeCollections{0};
    
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

/// @brief Collection progress callback
using ProgressCallback = std::function<void(const CollectionProgress&)>;

/// @brief Evidence item callback
using EvidenceCallback = std::function<void(const EvidenceItem&)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& error, const std::wstring& item)>;

/// @brief Collection completion callback
using CompletionCallback = std::function<void(const std::string& collectionId, 
                                              CollectionStatus status,
                                              const std::wstring& containerPath)>;

// ============================================================================
// EVIDENCE COLLECTOR ENGINE CLASS
// ============================================================================

/**
 * @class EvidenceCollector
 * @brief Enterprise-grade digital evidence collection engine
 *
 * Provides comprehensive evidence collection with chain of custody,
 * integrity verification, and secure container creation.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& collector = EvidenceCollector::Instance();
 *     
 *     // Collect evidence for a detection
 *     if (collector.CollectEvidence(pid, filePath)) {
 *         // Export to encrypted container
 *         auto containerPath = collector.ExportEvidence(incidentId);
 *     }
 * @endcode
 */
class EvidenceCollector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static EvidenceCollector& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    EvidenceCollector(const EvidenceCollector&) = delete;
    EvidenceCollector& operator=(const EvidenceCollector&) = delete;
    EvidenceCollector(EvidenceCollector&&) = delete;
    EvidenceCollector& operator=(EvidenceCollector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize evidence collector
     */
    [[nodiscard]] bool Initialize(const CollectionConfiguration& config = {});
    
    /**
     * @brief Shutdown evidence collector
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
    [[nodiscard]] bool SetConfiguration(const CollectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] CollectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set collection profile
     */
    void SetProfile(const CollectionProfile& profile);
    
    /**
     * @brief Get collection profile
     */
    [[nodiscard]] CollectionProfile GetProfile() const;
    
    // ========================================================================
    // PRIMARY COLLECTION METHODS
    // ========================================================================
    
    /**
     * @brief Collect all artifacts related to a specific detection
     */
    [[nodiscard]] bool CollectEvidence(uint32_t pid, const std::wstring& filePath);
    
    /**
     * @brief Collect with incident ID
     */
    [[nodiscard]] std::string CollectEvidence(uint32_t pid, std::wstring_view filePath,
                                              std::string_view incidentId,
                                              CollectionMode mode = CollectionMode::Standard);
    
    /**
     * @brief Start asynchronous collection
     */
    [[nodiscard]] std::string StartCollection(uint32_t pid, std::wstring_view filePath,
                                              std::string_view incidentId,
                                              const CollectionProfile& profile = {});
    
    /**
     * @brief Cancel ongoing collection
     */
    [[nodiscard]] bool CancelCollection(const std::string& collectionId);
    
    /**
     * @brief Get collection progress
     */
    [[nodiscard]] std::optional<CollectionProgress> GetProgress(
        const std::string& collectionId) const;
    
    /**
     * @brief Wait for collection to complete
     */
    [[nodiscard]] CollectionStatus WaitForCollection(const std::string& collectionId,
                                                     uint32_t timeoutMs = 0);
    
    // ========================================================================
    // EVIDENCE ITEM COLLECTION
    // ========================================================================
    
    /**
     * @brief Collect file as evidence
     */
    [[nodiscard]] std::optional<EvidenceItem> CollectFile(std::wstring_view filePath,
                                                          EvidenceType type = EvidenceType::MalwareFile);
    
    /**
     * @brief Collect process dump
     */
    [[nodiscard]] std::optional<EvidenceItem> CollectProcessDump(uint32_t pid,
                                                                  bool fullDump = false);
    
    /**
     * @brief Collect registry key
     */
    [[nodiscard]] std::optional<EvidenceItem> CollectRegistryKey(std::wstring_view keyPath);
    
    /**
     * @brief Collect event log
     */
    [[nodiscard]] std::optional<EvidenceItem> CollectEventLog(std::wstring_view logName,
                                                               uint32_t maxRecords = 0);
    
    /**
     * @brief Collect system state snapshot
     */
    [[nodiscard]] std::optional<SystemStateSnapshot> CollectSystemState();
    
    /**
     * @brief Add custom evidence item
     */
    [[nodiscard]] bool AddEvidence(const std::string& collectionId,
                                   const EvidenceItem& item,
                                   std::span<const uint8_t> data);
    
    // ========================================================================
    // CONTAINER EXPORT
    // ========================================================================
    
    /**
     * @brief Pack the evidence into an encrypted ShadowStrike Forensic Container
     */
    [[nodiscard]] std::wstring ExportEvidence(const std::string& incidentId);
    
    /**
     * @brief Export with options
     */
    [[nodiscard]] std::wstring ExportEvidence(const std::string& incidentId,
                                              ContainerFormat format,
                                              std::string_view password = "",
                                              std::wstring_view outputPath = L"");
    
    /**
     * @brief Create container from collection
     */
    [[nodiscard]] std::wstring CreateContainer(const std::string& collectionId,
                                               const ContainerMetadata& metadata,
                                               std::string_view password = "");
    
    /**
     * @brief Open existing container
     */
    [[nodiscard]] std::optional<ContainerMetadata> OpenContainer(std::wstring_view containerPath,
                                                                  std::string_view password = "");
    
    /**
     * @brief Extract item from container
     */
    [[nodiscard]] std::vector<uint8_t> ExtractItem(std::wstring_view containerPath,
                                                   const std::string& itemId,
                                                   std::string_view password = "");
    
    /**
     * @brief List items in container
     */
    [[nodiscard]] std::vector<EvidenceItem> ListContainerItems(std::wstring_view containerPath,
                                                                std::string_view password = "");
    
    // ========================================================================
    // CHAIN OF CUSTODY
    // ========================================================================
    
    /**
     * @brief Add chain of custody entry
     */
    [[nodiscard]] bool AddChainOfCustody(const std::string& collectionId,
                                         const ChainOfCustodyEntry& entry);
    
    /**
     * @brief Get chain of custody
     */
    [[nodiscard]] std::vector<ChainOfCustodyEntry> GetChainOfCustody(
        const std::string& collectionId) const;
    
    /**
     * @brief Verify chain of custody
     */
    [[nodiscard]] bool VerifyChainOfCustody(const std::string& collectionId) const;
    
    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verify evidence item integrity
     */
    [[nodiscard]] IntegrityStatus VerifyItemIntegrity(const EvidenceItem& item) const;
    
    /**
     * @brief Verify container integrity
     */
    [[nodiscard]] bool VerifyContainerIntegrity(std::wstring_view containerPath,
                                                std::string_view password = "");
    
    /**
     * @brief Verify all items in collection
     */
    [[nodiscard]] std::vector<std::pair<std::string, IntegrityStatus>> 
        VerifyCollectionIntegrity(const std::string& collectionId) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set progress callback
     */
    void SetProgressCallback(ProgressCallback callback);
    
    /**
     * @brief Set evidence callback
     */
    void SetEvidenceCallback(EvidenceCallback callback);
    
    /**
     * @brief Set error callback
     */
    void SetErrorCallback(ErrorCallback callback);
    
    /**
     * @brief Set completion callback
     */
    void SetCompletionCallback(CompletionCallback callback);
    
    // ========================================================================
    // COLLECTION MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Get all collections
     */
    [[nodiscard]] std::vector<std::string> GetCollections() const;
    
    /**
     * @brief Get active collections
     */
    [[nodiscard]] std::vector<std::string> GetActiveCollections() const;
    
    /**
     * @brief Get collection metadata
     */
    [[nodiscard]] std::optional<ContainerMetadata> GetCollectionMetadata(
        const std::string& collectionId) const;
    
    /**
     * @brief Delete collection
     */
    [[nodiscard]] bool DeleteCollection(const std::string& collectionId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] CollectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport(const std::string& collectionId) const;
    
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
    
    EvidenceCollector();
    ~EvidenceCollector();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<EvidenceCollectorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get evidence type name
 */
[[nodiscard]] std::string_view GetEvidenceTypeName(EvidenceType type) noexcept;

/**
 * @brief Get evidence category name
 */
[[nodiscard]] std::string_view GetEvidenceCategoryName(EvidenceCategory category) noexcept;

/**
 * @brief Get collection mode name
 */
[[nodiscard]] std::string_view GetCollectionModeName(CollectionMode mode) noexcept;

/**
 * @brief Get container format name
 */
[[nodiscard]] std::string_view GetContainerFormatName(ContainerFormat format) noexcept;

/**
 * @brief Get collection status name
 */
[[nodiscard]] std::string_view GetCollectionStatusName(CollectionStatus status) noexcept;

/**
 * @brief Get container extension
 */
[[nodiscard]] std::wstring_view GetContainerExtension(ContainerFormat format) noexcept;

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Collect evidence for detection
 */
#define SS_COLLECT_EVIDENCE(pid, path) \
    ::ShadowStrike::Forensics::EvidenceCollector::Instance().CollectEvidence((pid), (path))

/**
 * @brief Export evidence container
 */
#define SS_EXPORT_EVIDENCE(incidentId) \
    ::ShadowStrike::Forensics::EvidenceCollector::Instance().ExportEvidence(incidentId)
