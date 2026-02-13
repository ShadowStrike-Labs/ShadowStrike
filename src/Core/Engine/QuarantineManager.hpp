/**
 * ============================================================================
 * ShadowStrike Core Engine - QUARANTINE MANAGER (The Jailer)
 * ============================================================================
 *
 * @file QuarantineManager.hpp
 * @brief Enterprise-grade threat isolation and remediation engine.
 *
 * QuarantineManager orchestrates the complex multi-step process of safely
 * isolating malicious files from a live production system. It handles all
 * edge cases including locked files, active processes, system files, and
 * provides rollback capabilities for false positive remediation.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Threat Isolation**
 *    - Safe file quarantine with encryption
 *    - Process termination before isolation
 *    - Handle locked/in-use files
 *    - Alternate data stream handling
 *    - Directory quarantine support
 *
 * 2. **Remediation**
 *    - Registry cleanup
 *    - Service removal
 *    - Scheduled task removal
 *    - Startup entry cleanup
 *    - Browser extension cleanup
 *    - Shell extension cleanup
 *
 * 3. **Recovery**
 *    - Full file restoration
 *    - Partial restoration
 *    - Original location restoration
 *    - Custom location restoration
 *    - Integrity verification
 *
 * 4. **Rollback**
 *    - System state rollback
 *    - Registry rollback
 *    - Service restoration
 *    - File version rollback
 *
 * 5. **Forensics**
 *    - Evidence preservation
 *    - Metadata collection
 *    - Chain of custody tracking
 *    - Sample submission
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 *   ┌────────────────────────────────────────────────────────────────────────┐
 *   │                           Threat Sources                               │
 *   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
 *   │  │ ScanEngine │  │  Threat    │  │  RealTime  │  │   Manual   │       │
 *   │  │            │  │  Detector  │  │ Protection │  │   Report   │       │
 *   │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘       │
 *   │        │               │               │               │              │
 *   └────────┴───────────────┴───────────────┴───────────────┴──────────────┘
 *                                    │
 *                                    ▼
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          QUARANTINE MANAGER                                  │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                         Request Handler                                 │ │
 * │  │  - Validate request                                                     │ │
 * │  │  - Check permissions                                                    │ │
 * │  │  - Resolve file paths                                                   │ │
 * │  │  - Check whitelist                                                      │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                    │                                        │
 * │                                    ▼                                        │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                      Pre-Quarantine Analysis                           │ │
 * │  │  - Identify locking processes                                          │ │
 * │  │  - Check file type and size                                            │ │
 * │  │  - Detect system/critical files                                        │ │
 * │  │  - Check available storage                                             │ │
 * │  │  - Collect metadata                                                    │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                    │                                        │
 * │                                    ▼                                        │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                      Process Neutralization                            │ │
 * │  │  - Terminate processes gracefully                                      │ │
 * │  │  - Force terminate if needed                                           │ │
 * │  │  - Close handles                                                       │ │
 * │  │  - Wait for release                                                    │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                    │                                        │
 * │                                    ▼                                        │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                         File Isolation                                 │ │
 * │  │  - Read file content                                                   │ │
 * │  │  - Calculate hashes                                                    │ │
 * │  │  - Encrypt file (AES-256-GCM)                                          │ │
 * │  │  - Store in quarantine vault                                           │ │
 * │  │  - Delete original (secure wipe)                                       │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                    │                                        │
 * │                                    ▼                                        │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                      Artifact Remediation                              │ │
 * │  │  - Registry entries                                                    │ │
 * │  │  - Services                                                            │ │
 * │  │  - Scheduled tasks                                                     │ │
 * │  │  - Startup entries                                                     │ │
 * │  │  - Related files                                                       │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                    │                                        │
 * │                                    ▼                                        │
 * │  ┌────────────────────────────────────────────────────────────────────────┐ │
 * │  │                      Database & Notification                           │ │
 * │  │  - Store in QuarantineDB                                               │ │
 * │  │  - Generate audit log                                                  │ │
 * │  │  - Notify callbacks                                                    │ │
 * │  │  - Update statistics                                                   │ │
 * │  └────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *                                    │
 *                                    ▼
 *   ┌────────────────────────────────────────────────────────────────────────┐
 *   │                         Storage Layer                                   │
 *   │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐           │
 *   │  │  QuarantineDB  │  │  Quarantine    │  │   Forensics    │           │
 *   │  │   (Metadata)   │  │   Vault (AES)  │  │    Archive     │           │
 *   │  └────────────────┘  └────────────────┘  └────────────────┘           │
 *   └────────────────────────────────────────────────────────────────────────┘
 *
 * =============================================================================
 * QUARANTINE WORKFLOW
 * =============================================================================
 *
 * 1. **Request** → Quarantine requested for file
 * 2. **Validate** → Check permissions, whitelist, file existence
 * 3. **Analyze** → Identify locks, collect metadata
 * 4. **Neutralize** → Kill processes holding file
 * 5. **Isolate** → Encrypt and move to vault
 * 6. **Remediate** → Clean up artifacts
 * 7. **Record** → Store metadata, generate logs
 * 8. **Notify** → Callbacks, UI update
 *
 * =============================================================================
 * ENCRYPTION SCHEME
 * =============================================================================
 *
 * - **Algorithm**: AES-256-GCM
 * - **Key Derivation**: Per-quarantine unique key from master key
 * - **IV**: Random 12 bytes per file
 * - **Tag**: 16-byte authentication tag
 * - **Format**: [IV][Encrypted Data][Auth Tag]
 *
 * =============================================================================
 * FILE FORMAT IN VAULT
 * =============================================================================
 *
 * ```
 * ┌──────────────────────────────────────────┐
 * │          Quarantine File Format          │
 * ├──────────────────────────────────────────┤
 * │ Magic: "SSQF" (4 bytes)                  │
 * │ Version: uint16_t                        │
 * │ Flags: uint16_t                          │
 * │ Original Size: uint64_t                  │
 * │ Original Path Length: uint32_t           │
 * │ Original Path: UTF-16 string             │
 * │ Threat Name Length: uint32_t             │
 * │ Threat Name: UTF-16 string               │
 * │ SHA256: 32 bytes                         │
 * │ Quarantine Time: uint64_t                │
 * │ IV: 12 bytes                             │
 * │ Encrypted Data: variable                 │
 * │ Auth Tag: 16 bytes                       │
 * └──────────────────────────────────────────┘
 * ```
 *
 * @note Thread-safe for all public methods
 * @note Supports concurrent quarantine operations
 *
 * @see QuarantineDB for metadata storage
 * @see Utils::CryptoUtils for encryption
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File operations
#include "../../Utils/CryptoUtils.hpp"        // AES-256-GCM encryption
#include "../../Utils/HashUtils.hpp"          // Hash calculation
#include "../../Utils/ProcessUtils.hpp"       // Process termination
#include "../../Utils/RegistryUtils.hpp"      // Registry cleanup
#include "../../Database/QuarantineDB.hpp"    // Metadata storage

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace Database {
        class QuarantineDB;
    }
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class QuarantineManager;
struct QuarantineEntry;
struct QuarantineResult;
struct RemediationAction;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace QuarantineConstants {
    // -------------------------------------------------------------------------
    // File Format
    // -------------------------------------------------------------------------
    
    /// @brief Quarantine file magic number
    constexpr uint32_t QUARANTINE_MAGIC = 0x46515353;  // "SSQF"
    
    /// @brief Current quarantine format version
    constexpr uint16_t QUARANTINE_VERSION = 2;
    
    /// @brief Minimum file size for compression
    constexpr uint64_t COMPRESSION_THRESHOLD = 4096;
    
    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------
    
    /// @brief AES key size (256 bits)
    constexpr size_t AES_KEY_SIZE = 32;
    
    /// @brief GCM IV size
    constexpr size_t GCM_IV_SIZE = 12;
    
    /// @brief GCM auth tag size
    constexpr size_t GCM_TAG_SIZE = 16;
    
    // -------------------------------------------------------------------------
    // Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum file size for quarantine
    constexpr uint64_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024;  // 4 GB
    
    /// @brief Maximum quarantine entries
    constexpr size_t MAX_QUARANTINE_ENTRIES = 1000000;
    
    /// @brief Maximum concurrent quarantine operations
    constexpr size_t MAX_CONCURRENT_OPS = 16;
    
    /// @brief Process termination timeout (ms)
    constexpr uint32_t PROCESS_KILL_TIMEOUT_MS = 10000;
    
    /// @brief File lock wait timeout (ms)
    constexpr uint32_t FILE_LOCK_TIMEOUT_MS = 30000;
    
    // -------------------------------------------------------------------------
    // Retention
    // -------------------------------------------------------------------------
    
    /// @brief Default retention period (days)
    constexpr uint32_t DEFAULT_RETENTION_DAYS = 30;
    
    /// @brief Maximum retention period (days)
    constexpr uint32_t MAX_RETENTION_DAYS = 365;
    
    // -------------------------------------------------------------------------
    // Paths
    // -------------------------------------------------------------------------
    
    /// @brief Default quarantine folder name
    constexpr wchar_t DEFAULT_VAULT_FOLDER[] = L"Quarantine";
    
    /// @brief Quarantine file extension
    constexpr wchar_t QUARANTINE_EXTENSION[] = L".ssqf";
    
    /// @brief Forensics archive folder
    constexpr wchar_t FORENSICS_FOLDER[] = L"Forensics";
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Quarantine operation status.
 */
enum class QuarantineStatus : uint8_t {
    /// @brief Operation succeeded
    Success = 0,
    
    /// @brief File not found
    FileNotFound = 1,
    
    /// @brief Access denied
    AccessDenied = 2,
    
    /// @brief File is in use
    FileInUse = 3,
    
    /// @brief File too large
    FileTooLarge = 4,
    
    /// @brief System file protected
    SystemFileProtected = 5,
    
    /// @brief Whitelist match
    WhitelistMatch = 6,
    
    /// @brief Encryption failed
    EncryptionFailed = 7,
    
    /// @brief Storage full
    StorageFull = 8,
    
    /// @brief Database error
    DatabaseError = 9,
    
    /// @brief Process kill failed
    ProcessKillFailed = 10,
    
    /// @brief Already quarantined
    AlreadyQuarantined = 11,
    
    /// @brief Entry not found
    EntryNotFound = 12,
    
    /// @brief Decryption failed
    DecryptionFailed = 13,
    
    /// @brief Integrity check failed
    IntegrityFailed = 14,
    
    /// @brief Reboot required
    RebootRequired = 15,
    
    /// @brief Operation cancelled
    Cancelled = 16,
    
    /// @brief Timeout
    Timeout = 17,
    
    /// @brief Unknown error
    UnknownError = 255
};

/**
 * @brief Quarantine entry state.
 */
enum class QuarantineState : uint8_t {
    /// @brief Active (in quarantine)
    Active = 0,
    
    /// @brief Restored to original location
    Restored = 1,
    
    /// @brief Permanently deleted
    Deleted = 2,
    
    /// @brief Pending (scheduled for quarantine)
    Pending = 3,
    
    /// @brief Failed to quarantine
    Failed = 4,
    
    /// @brief Submitted for analysis
    Submitted = 5,
    
    /// @brief Awaiting reboot
    PendingReboot = 6
};

/**
 * @brief Type of quarantined item.
 */
enum class QuarantineItemType : uint8_t {
    /// @brief Unknown type
    Unknown = 0,
    
    /// @brief Regular file
    File = 1,
    
    /// @brief Directory
    Directory = 2,
    
    /// @brief Registry key
    RegistryKey = 3,
    
    /// @brief Registry value
    RegistryValue = 4,
    
    /// @brief Service
    Service = 5,
    
    /// @brief Scheduled task
    ScheduledTask = 6,
    
    /// @brief Browser extension
    BrowserExtension = 7,
    
    /// @brief Memory region
    Memory = 8,
    
    /// @brief Process
    Process = 9
};

/**
 * @brief Remediation action type.
 */
enum class RemediationType : uint8_t {
    /// @brief No action
    None = 0,
    
    /// @brief Delete file
    DeleteFile = 1,
    
    /// @brief Delete registry key
    DeleteRegistryKey = 2,
    
    /// @brief Delete registry value
    DeleteRegistryValue = 3,
    
    /// @brief Stop and delete service
    DeleteService = 4,
    
    /// @brief Delete scheduled task
    DeleteScheduledTask = 5,
    
    /// @brief Remove startup entry
    RemoveStartupEntry = 6,
    
    /// @brief Remove browser extension
    RemoveBrowserExtension = 7,
    
    /// @brief Terminate process
    TerminateProcess = 8,
    
    /// @brief Restore file
    RestoreFile = 9,
    
    /// @brief Restore registry
    RestoreRegistry = 10,
    
    /// @brief Clean directory
    CleanDirectory = 11,
    
    /// @brief Reset browser settings
    ResetBrowserSettings = 12,
    
    /// @brief Repair system file
    RepairSystemFile = 13
};

/**
 * @brief Threat severity for prioritization.
 */
enum class QuarantinePriority : uint8_t {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
    Emergency = 4
};

/**
 * @brief Quarantine file flags.
 */
enum class QuarantineFlags : uint16_t {
    None = 0x0000,
    Compressed = 0x0001,
    Encrypted = 0x0002,
    HasMetadata = 0x0004,
    HasADS = 0x0008,           // Alternate Data Streams
    SystemFile = 0x0010,
    HiddenFile = 0x0020,
    ReadOnly = 0x0040,
    Executable = 0x0080,
    Script = 0x0100,
    Archive = 0x0200,
    NetworkFile = 0x0400,
    RebootRequired = 0x0800
};

inline QuarantineFlags operator|(QuarantineFlags a, QuarantineFlags b) {
    return static_cast<QuarantineFlags>(
        static_cast<uint16_t>(a) | static_cast<uint16_t>(b)
    );
}

inline QuarantineFlags operator&(QuarantineFlags a, QuarantineFlags b) {
    return static_cast<QuarantineFlags>(
        static_cast<uint16_t>(a) & static_cast<uint16_t>(b)
    );
}

/**
 * @brief Get string representation of QuarantineStatus.
 */
[[nodiscard]] constexpr const char* QuarantineStatusToString(QuarantineStatus status) noexcept;

/**
 * @brief Get string representation of QuarantineState.
 */
[[nodiscard]] constexpr const char* QuarantineStateToString(QuarantineState state) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief File metadata collected before quarantine.
 */
struct FileMetadata {
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief File name only
    std::wstring fileName;
    
    /// @brief File extension
    std::wstring extension;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Last modification time
    std::chrono::system_clock::time_point modificationTime{};
    
    /// @brief Last access time
    std::chrono::system_clock::time_point accessTime{};
    
    /// @brief File attributes
    uint32_t attributes = 0;
    
    /// @brief Is read-only
    bool isReadOnly = false;
    
    /// @brief Is hidden
    bool isHidden = false;
    
    /// @brief Is system file
    bool isSystem = false;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Has Alternate Data Streams
    bool hasADS = false;
    
    /// @brief ADS names
    std::vector<std::wstring> adsNames;
    
    /// @brief File owner SID
    std::wstring ownerSid;
    
    /// @brief File owner name
    std::wstring ownerName;
    
    /// @brief Security descriptor
    std::vector<uint8_t> securityDescriptor;
};

/**
 * @brief Hash information for quarantined file.
 */
struct QuarantineHashes {
    /// @brief MD5 hash (hex string)
    std::string md5;
    
    /// @brief SHA1 hash (hex string)
    std::string sha1;
    
    /// @brief SHA256 hash (hex string)
    std::string sha256;
    
    /// @brief CTPH fuzzy hash
    std::string fuzzyHash;
    
    /// @brief TLSH locality hash
    std::string tlsh;
    
    /// @brief Import hash (PE files)
    std::string impHash;
};

/**
 * @brief Process information for locking process.
 */
struct LockingProcess {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Is system process
    bool isSystemProcess = false;
    
    /// @brief Can be terminated
    bool canTerminate = true;
    
    /// @brief Handle type
    std::string handleType;
    
    /// @brief Was terminated
    bool wasTerminated = false;
};

/**
 * @brief Remediation action details.
 */
struct RemediationAction {
    /// @brief Action type
    RemediationType type = RemediationType::None;
    
    /// @brief Target path/key/name
    std::wstring target;
    
    /// @brief Additional target (e.g., value name for registry)
    std::wstring additionalTarget;
    
    /// @brief Was action successful
    bool success = false;
    
    /// @brief Error message if failed
    std::wstring errorMessage;
    
    /// @brief Original value (for rollback)
    std::vector<uint8_t> originalValue;
    
    /// @brief Timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Requires reboot
    bool requiresReboot = false;
};

/**
 * @brief Complete quarantine entry.
 */
struct QuarantineEntry {
    // -------------------------------------------------------------------------
    // Identification
    // -------------------------------------------------------------------------
    
    /// @brief Unique entry ID
    uint64_t entryId = 0;
    
    /// @brief Quarantine file path (in vault)
    std::wstring quarantinePath;
    
    /// @brief Entry state
    QuarantineState state = QuarantineState::Active;
    
    /// @brief Item type
    QuarantineItemType itemType = QuarantineItemType::File;
    
    /// @brief Flags
    QuarantineFlags flags = QuarantineFlags::None;
    
    // -------------------------------------------------------------------------
    // Original File Info
    // -------------------------------------------------------------------------
    
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Original file name
    std::wstring fileName;
    
    /// @brief Original file size
    uint64_t originalSize = 0;
    
    /// @brief File metadata
    FileMetadata metadata;
    
    /// @brief File hashes
    QuarantineHashes hashes;
    
    // -------------------------------------------------------------------------
    // Threat Information
    // -------------------------------------------------------------------------
    
    /// @brief Threat name
    std::wstring threatName;
    
    /// @brief Threat family
    std::wstring threatFamily;
    
    /// @brief Threat category
    std::wstring threatCategory;
    
    /// @brief Detection source
    std::wstring detectionSource;
    
    /// @brief Threat score
    double threatScore = 0.0;
    
    /// @brief Priority
    QuarantinePriority priority = QuarantinePriority::Normal;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    // -------------------------------------------------------------------------
    // Detection Context
    // -------------------------------------------------------------------------
    
    /// @brief Process ID during detection
    uint32_t detectionProcessId = 0;
    
    /// @brief Process name during detection
    std::wstring detectionProcessName;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Machine name
    std::wstring machineName;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    // -------------------------------------------------------------------------
    // Timestamps
    // -------------------------------------------------------------------------
    
    /// @brief Detection time
    std::chrono::system_clock::time_point detectionTime{};
    
    /// @brief Quarantine time
    std::chrono::system_clock::time_point quarantineTime{};
    
    /// @brief Restore time (if restored)
    std::chrono::system_clock::time_point restoreTime{};
    
    /// @brief Deletion time (if deleted)
    std::chrono::system_clock::time_point deletionTime{};
    
    /// @brief Expiration time
    std::chrono::system_clock::time_point expirationTime{};
    
    // -------------------------------------------------------------------------
    // Remediation
    // -------------------------------------------------------------------------
    
    /// @brief Remediation actions taken
    std::vector<RemediationAction> remediationActions;
    
    /// @brief Processes that were terminated
    std::vector<LockingProcess> terminatedProcesses;
    
    /// @brief Reboot required
    bool rebootRequired = false;
    
    // -------------------------------------------------------------------------
    // Forensics
    // -------------------------------------------------------------------------
    
    /// @brief Evidence preserved
    bool evidencePreserved = false;
    
    /// @brief Forensics archive path
    std::wstring forensicsPath;
    
    /// @brief Sample submitted
    bool sampleSubmitted = false;
    
    /// @brief Submission ID
    std::string submissionId;
    
    // -------------------------------------------------------------------------
    // Notes
    // -------------------------------------------------------------------------
    
    /// @brief User notes
    std::wstring userNotes;
    
    /// @brief Auto-generated notes
    std::wstring autoNotes;
    
    /**
     * @brief Get entry age.
     */
    [[nodiscard]] std::chrono::hours GetAge() const noexcept {
        return std::chrono::duration_cast<std::chrono::hours>(
            std::chrono::system_clock::now() - quarantineTime
        );
    }
    
    /**
     * @brief Check if entry is expired.
     */
    [[nodiscard]] bool IsExpired() const noexcept {
        return std::chrono::system_clock::now() > expirationTime;
    }
};

/**
 * @brief Result of quarantine operation.
 */
struct QuarantineResult {
    /// @brief Operation status
    QuarantineStatus status = QuarantineStatus::UnknownError;
    
    /// @brief Entry ID (if successful)
    uint64_t entryId = 0;
    
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Quarantine path
    std::wstring quarantinePath;
    
    /// @brief Result message
    std::wstring message;
    
    /// @brief Error code (if failed)
    uint32_t errorCode = 0;
    
    /// @brief Reboot required
    bool rebootRequired = false;
    
    /// @brief Processes terminated
    std::vector<LockingProcess> processesTerminated;
    
    /// @brief Remediation actions
    std::vector<RemediationAction> remediationActions;
    
    /// @brief Operation duration
    std::chrono::milliseconds duration{};
    
    /**
     * @brief Check if operation succeeded.
     */
    [[nodiscard]] bool IsSuccess() const noexcept {
        return status == QuarantineStatus::Success;
    }
};

/**
 * @brief Result of restore operation.
 */
struct RestoreResult {
    /// @brief Operation status
    QuarantineStatus status = QuarantineStatus::UnknownError;
    
    /// @brief Entry ID
    uint64_t entryId = 0;
    
    /// @brief Restored path
    std::wstring restoredPath;
    
    /// @brief Result message
    std::wstring message;
    
    /// @brief Integrity verified
    bool integrityVerified = false;
    
    /// @brief File hash after restore
    std::string restoredHash;
    
    /**
     * @brief Check if operation succeeded.
     */
    [[nodiscard]] bool IsSuccess() const noexcept {
        return status == QuarantineStatus::Success;
    }
};

/**
 * @brief Quarantine request.
 */
struct QuarantineRequest {
    /// @brief File path to quarantine
    std::wstring filePath;
    
    /// @brief Threat name
    std::wstring threatName;
    
    /// @brief Threat family
    std::wstring threatFamily;
    
    /// @brief Detection source
    std::wstring detectionSource;
    
    /// @brief Related process ID
    uint32_t relatedProcessId = 0;
    
    /// @brief Threat score
    double threatScore = 0.0;
    
    /// @brief Priority
    QuarantinePriority priority = QuarantinePriority::Normal;
    
    /// @brief Auto-remediate artifacts
    bool autoRemediate = true;
    
    /// @brief Preserve evidence
    bool preserveEvidence = false;
    
    /// @brief Submit sample
    bool submitSample = false;
    
    /// @brief Force quarantine (skip some checks)
    bool force = false;
    
    /// @brief Related paths to remediate
    std::vector<std::wstring> relatedPaths;
    
    /// @brief Related registry keys
    std::vector<std::wstring> relatedRegistryKeys;
    
    /// @brief MITRE techniques
    std::vector<std::string> mitreTechniques;
    
    /// @brief User notes
    std::wstring userNotes;
};

/**
 * @brief Restore request.
 */
struct RestoreRequest {
    /// @brief Entry ID to restore
    uint64_t entryId = 0;
    
    /// @brief Custom restore path (empty = original)
    std::wstring customPath;
    
    /// @brief Verify integrity
    bool verifyIntegrity = true;
    
    /// @brief Override existing file
    bool overrideExisting = false;
    
    /// @brief Restore metadata
    bool restoreMetadata = true;
    
    /// @brief Reason for restore
    std::wstring restoreReason;
};

/**
 * @brief Quarantine query parameters.
 */
struct QuarantineQuery {
    /// @brief Filter by state
    std::optional<QuarantineState> state;
    
    /// @brief Filter by threat name (pattern)
    std::optional<std::wstring> threatNamePattern;
    
    /// @brief Filter by hash
    std::optional<std::string> hash;
    
    /// @brief Filter by original path (pattern)
    std::optional<std::wstring> pathPattern;
    
    /// @brief Filter by minimum threat score
    std::optional<double> minThreatScore;
    
    /// @brief Filter by priority
    std::optional<QuarantinePriority> minPriority;
    
    /// @brief Filter by date range
    std::optional<std::chrono::system_clock::time_point> startTime;
    std::optional<std::chrono::system_clock::time_point> endTime;
    
    /// @brief Sort field
    std::string sortField = "quarantineTime";
    
    /// @brief Sort descending
    bool sortDescending = true;
    
    /// @brief Maximum results
    size_t maxResults = 1000;
    
    /// @brief Offset for pagination
    size_t offset = 0;
};

/**
 * @brief Configuration for quarantine manager.
 */
struct QuarantineManagerConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable quarantine
    bool enabled = true;
    
    /// @brief Quarantine vault path
    std::wstring vaultPath;
    
    /// @brief Maximum vault size (bytes, 0 = unlimited)
    uint64_t maxVaultSize = 0;
    
    /// @brief Maximum file size
    uint64_t maxFileSize = QuarantineConstants::MAX_FILE_SIZE;
    
    // -------------------------------------------------------------------------
    // Retention Settings
    // -------------------------------------------------------------------------
    
    /// @brief Default retention (days)
    uint32_t defaultRetentionDays = QuarantineConstants::DEFAULT_RETENTION_DAYS;
    
    /// @brief Auto-delete expired
    bool autoDeleteExpired = true;
    
    /// @brief Cleanup interval (hours)
    uint32_t cleanupIntervalHours = 24;
    
    // -------------------------------------------------------------------------
    // Process Handling
    // -------------------------------------------------------------------------
    
    /// @brief Auto-terminate locking processes
    bool autoTerminateProcesses = true;
    
    /// @brief Process kill timeout (ms)
    uint32_t processKillTimeoutMs = QuarantineConstants::PROCESS_KILL_TIMEOUT_MS;
    
    /// @brief Allow killing system processes
    bool allowKillSystemProcesses = false;
    
    // -------------------------------------------------------------------------
    // Remediation Settings
    // -------------------------------------------------------------------------
    
    /// @brief Auto-remediate artifacts
    bool autoRemediate = true;
    
    /// @brief Clean registry entries
    bool cleanRegistry = true;
    
    /// @brief Clean services
    bool cleanServices = true;
    
    /// @brief Clean scheduled tasks
    bool cleanScheduledTasks = true;
    
    /// @brief Clean startup entries
    bool cleanStartupEntries = true;
    
    // -------------------------------------------------------------------------
    // Security Settings
    // -------------------------------------------------------------------------
    
    /// @brief Encrypt quarantined files
    bool encryptFiles = true;
    
    /// @brief Compress files before encryption
    bool compressFiles = true;
    
    /// @brief Secure wipe original
    bool secureWipeOriginal = false;
    
    /// @brief Verify integrity on restore
    bool verifyIntegrityOnRestore = true;
    
    // -------------------------------------------------------------------------
    // Forensics Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable forensics preservation
    bool enableForensics = false;
    
    /// @brief Forensics archive path
    std::wstring forensicsPath;
    
    /// @brief Enable sample submission
    bool enableSampleSubmission = false;
    
    /// @brief Sample submission URL
    std::string submissionUrl;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static QuarantineManagerConfig CreateDefault() noexcept {
        return QuarantineManagerConfig{};
    }
    
    /**
     * @brief Create secure configuration.
     */
    [[nodiscard]] static QuarantineManagerConfig CreateSecure() noexcept {
        QuarantineManagerConfig config;
        config.encryptFiles = true;
        config.secureWipeOriginal = true;
        config.verifyIntegrityOnRestore = true;
        config.autoTerminateProcesses = true;
        return config;
    }
    
    /**
     * @brief Create forensics configuration.
     */
    [[nodiscard]] static QuarantineManagerConfig CreateForensics() noexcept {
        QuarantineManagerConfig config;
        config.enableForensics = true;
        config.enableSampleSubmission = true;
        config.secureWipeOriginal = false;  // Preserve evidence
        return config;
    }
};

/**
 * @brief Statistics for quarantine manager.
 */
struct QuarantineManagerStats {
    /// @brief Total files quarantined
    std::atomic<uint64_t> totalQuarantined{ 0 };
    
    /// @brief Total files restored
    std::atomic<uint64_t> totalRestored{ 0 };
    
    /// @brief Total files deleted
    std::atomic<uint64_t> totalDeleted{ 0 };
    
    /// @brief Current active entries
    std::atomic<size_t> activeEntries{ 0 };
    
    /// @brief Current vault size (bytes)
    std::atomic<uint64_t> currentVaultSize{ 0 };
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{ 0 };
    
    /// @brief Remediation actions performed
    std::atomic<uint64_t> remediationActions{ 0 };
    
    /// @brief Quarantine failures
    std::atomic<uint64_t> quarantineFailures{ 0 };
    
    /// @brief Restore failures
    std::atomic<uint64_t> restoreFailures{ 0 };
    
    /// @brief Files submitted
    std::atomic<uint64_t> samplesSubmitted{ 0 };
    
    /// @brief Expired entries auto-deleted
    std::atomic<uint64_t> expiredDeleted{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalQuarantined.store(0, std::memory_order_relaxed);
        totalRestored.store(0, std::memory_order_relaxed);
        totalDeleted.store(0, std::memory_order_relaxed);
        activeEntries.store(0, std::memory_order_relaxed);
        currentVaultSize.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        remediationActions.store(0, std::memory_order_relaxed);
        quarantineFailures.store(0, std::memory_order_relaxed);
        restoreFailures.store(0, std::memory_order_relaxed);
        samplesSubmitted.store(0, std::memory_order_relaxed);
        expiredDeleted.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using QuarantineCallback = std::function<void(const QuarantineResult&)>;
using RestoreCallback = std::function<void(const RestoreResult&)>;
using RemediationCallback = std::function<void(const RemediationAction&)>;
using ProgressCallback = std::function<void(double progress, const std::wstring& status)>;

// ============================================================================
// MAIN QUARANTINE MANAGER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade threat isolation and remediation engine.
 *
 * Orchestrates the complete process of safely isolating malicious files
 * from a live production system, including process termination, file
 * encryption, artifact cleanup, and recovery capabilities.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& manager = QuarantineManager::Instance();
 * 
 * // Initialize
 * QuarantineManagerConfig config = QuarantineManagerConfig::CreateDefault();
 * config.vaultPath = L"C:\\ProgramData\\ShadowStrike\\Quarantine";
 * manager.Initialize(threadPool, config);
 * 
 * // Quarantine a threat
 * QuarantineRequest request;
 * request.filePath = L"C:\\malware.exe";
 * request.threatName = L"Trojan:Win32/Emotet";
 * request.relatedProcessId = 1234;
 * request.autoRemediate = true;
 * 
 * QuarantineResult result = manager.QuarantineFile(request);
 * if (result.IsSuccess()) {
 *     LOG_INFO(L"Quarantined: {} (ID: {})", 
 *              result.originalPath, result.entryId);
 * }
 * 
 * // Restore if false positive
 * RestoreRequest restore;
 * restore.entryId = result.entryId;
 * restore.restoreReason = L"False positive confirmed by analyst";
 * 
 * RestoreResult restoreResult = manager.RestoreFile(restore);
 * 
 * // Query quarantine
 * QuarantineQuery query;
 * query.state = QuarantineState::Active;
 * query.minThreatScore = 70.0;
 * 
 * auto entries = manager.QueryEntries(query);
 * 
 * manager.Shutdown();
 * @endcode
 */
class QuarantineManager {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global QuarantineManager instance.
     */
    [[nodiscard]] static QuarantineManager& Instance();

    // Non-copyable, non-movable
    QuarantineManager(const QuarantineManager&) = delete;
    QuarantineManager& operator=(const QuarantineManager&) = delete;
    QuarantineManager(QuarantineManager&&) = delete;
    QuarantineManager& operator=(QuarantineManager&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the manager.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const QuarantineManagerConfig& config
    );

    /**
     * @brief Shutdown the manager.
     */
    void Shutdown();

    /**
     * @brief Check if manager is initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const QuarantineManagerConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] QuarantineManagerConfig GetConfig() const;

    // =========================================================================
    // Quarantine Operations
    // =========================================================================

    /**
     * @brief Quarantine a file synchronously.
     * @param request Quarantine request.
     * @return Quarantine result.
     */
    [[nodiscard]] QuarantineResult QuarantineFile(const QuarantineRequest& request);

    /**
     * @brief Quarantine a file (simplified).
     * @param filePath Path to file.
     * @param threatName Threat name.
     * @param relatedPid Related process ID.
     * @return Quarantine result.
     */
    [[nodiscard]] QuarantineResult QuarantineFile(
        const std::wstring& filePath,
        const std::wstring& threatName,
        uint32_t relatedPid = 0
    );

    /**
     * @brief Quarantine a file asynchronously.
     * @param request Quarantine request.
     * @param callback Completion callback.
     * @return Future for result.
     */
    [[nodiscard]] std::future<QuarantineResult> QuarantineFileAsync(
        const QuarantineRequest& request,
        QuarantineCallback callback = nullptr
    );

    /**
     * @brief Quarantine multiple files.
     * @param requests Vector of requests.
     * @return Vector of results.
     */
    [[nodiscard]] std::vector<QuarantineResult> QuarantineFiles(
        const std::vector<QuarantineRequest>& requests
    );

    // =========================================================================
    // Restore Operations
    // =========================================================================

    /**
     * @brief Restore a quarantined file.
     * @param request Restore request.
     * @return Restore result.
     */
    [[nodiscard]] RestoreResult RestoreFile(const RestoreRequest& request);

    /**
     * @brief Restore a file (simplified).
     * @param entryId Entry ID.
     * @param restorePath Optional custom path.
     * @return Restore result.
     */
    [[nodiscard]] RestoreResult RestoreFile(
        uint64_t entryId,
        const std::wstring& restorePath = L""
    );

    /**
     * @brief Restore a file asynchronously.
     * @param request Restore request.
     * @param callback Completion callback.
     * @return Future for result.
     */
    [[nodiscard]] std::future<RestoreResult> RestoreFileAsync(
        const RestoreRequest& request,
        RestoreCallback callback = nullptr
    );

    // =========================================================================
    // Delete Operations
    // =========================================================================

    /**
     * @brief Permanently delete a quarantined file.
     * @param entryId Entry ID.
     * @param secureWipe Secure wipe the data.
     * @return true if deleted successfully.
     */
    bool DeleteFile(uint64_t entryId, bool secureWipe = false);

    /**
     * @brief Delete multiple entries.
     * @param entryIds Vector of entry IDs.
     * @return Number of entries deleted.
     */
    size_t DeleteFiles(const std::vector<uint64_t>& entryIds);

    /**
     * @brief Delete all expired entries.
     * @return Number of entries deleted.
     */
    size_t DeleteExpiredEntries();

    /**
     * @brief Delete all entries.
     * @return Number of entries deleted.
     */
    size_t DeleteAllEntries();

    // =========================================================================
    // Query Operations
    // =========================================================================

    /**
     * @brief Get entry by ID.
     * @param entryId Entry ID.
     * @return Entry or nullopt if not found.
     */
    [[nodiscard]] std::optional<QuarantineEntry> GetEntry(uint64_t entryId) const;

    /**
     * @brief Get entry by hash.
     * @param hash SHA256 hash.
     * @return Entry or nullopt if not found.
     */
    [[nodiscard]] std::optional<QuarantineEntry> GetEntryByHash(
        const std::string& hash
    ) const;

    /**
     * @brief Query entries.
     * @param query Query parameters.
     * @return Vector of matching entries.
     */
    [[nodiscard]] std::vector<QuarantineEntry> QueryEntries(
        const QuarantineQuery& query
    ) const;

    /**
     * @brief Get all active entries.
     * @return Vector of active entries.
     */
    [[nodiscard]] std::vector<QuarantineEntry> GetActiveEntries() const;

    /**
     * @brief Get entry count.
     * @param state Optional state filter.
     * @return Number of entries.
     */
    [[nodiscard]] size_t GetEntryCount(
        std::optional<QuarantineState> state = std::nullopt
    ) const;

    /**
     * @brief Check if file is quarantined.
     * @param hash SHA256 hash.
     * @return true if quarantined.
     */
    [[nodiscard]] bool IsQuarantined(const std::string& hash) const;

    // =========================================================================
    // Process Management
    // =========================================================================

    /**
     * @brief Terminate processes locking a file.
     * @param filePath File path.
     * @return Vector of terminated processes.
     */
    std::vector<LockingProcess> TerminateLockingProcesses(
        const std::wstring& filePath
    );

    /**
     * @brief Get processes locking a file.
     * @param filePath File path.
     * @return Vector of locking processes.
     */
    [[nodiscard]] std::vector<LockingProcess> GetLockingProcesses(
        const std::wstring& filePath
    ) const;

    // =========================================================================
    // Remediation
    // =========================================================================

    /**
     * @brief Remediate threat artifacts.
     * @param entryId Entry ID.
     * @return Vector of remediation actions.
     */
    std::vector<RemediationAction> RemediateArtifacts(uint64_t entryId);

    /**
     * @brief Rollback remediation actions.
     * @param entryId Entry ID.
     * @return true if rollback succeeded.
     */
    bool RollbackRemediation(uint64_t entryId);

    /**
     * @brief Add remediation action.
     * @param entryId Entry ID.
     * @param action Remediation action.
     * @return true if added successfully.
     */
    bool AddRemediationAction(uint64_t entryId, const RemediationAction& action);

    // =========================================================================
    // Forensics
    // =========================================================================

    /**
     * @brief Extract quarantined file for analysis.
     * @param entryId Entry ID.
     * @param destPath Destination path.
     * @return true if extracted successfully.
     */
    bool ExtractForAnalysis(uint64_t entryId, const std::wstring& destPath);

    /**
     * @brief Submit sample for analysis.
     * @param entryId Entry ID.
     * @return Submission ID or empty on failure.
     */
    std::string SubmitSample(uint64_t entryId);

    /**
     * @brief Preserve evidence.
     * @param entryId Entry ID.
     * @return Forensics archive path.
     */
    std::wstring PreserveEvidence(uint64_t entryId);

    // =========================================================================
    // Export/Import
    // =========================================================================

    /**
     * @brief Export quarantine database.
     * @param filePath Export file path.
     * @return true if exported successfully.
     */
    bool ExportDatabase(const std::wstring& filePath) const;

    /**
     * @brief Import quarantine database.
     * @param filePath Import file path.
     * @return Number of entries imported.
     */
    size_t ImportDatabase(const std::wstring& filePath);

    // =========================================================================
    // Maintenance
    // =========================================================================

    /**
     * @brief Run maintenance tasks.
     */
    void RunMaintenance();

    /**
     * @brief Verify vault integrity.
     * @return Number of corrupted entries.
     */
    size_t VerifyVaultIntegrity();

    /**
     * @brief Compact vault (remove deleted entries).
     * @return Bytes reclaimed.
     */
    uint64_t CompactVault();

    /**
     * @brief Get vault path.
     */
    [[nodiscard]] std::wstring GetVaultPath() const;

    /**
     * @brief Get vault size.
     */
    [[nodiscard]] uint64_t GetVaultSize() const;

    /**
     * @brief Get available vault space.
     */
    [[nodiscard]] uint64_t GetAvailableSpace() const;

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register quarantine callback.
     */
    [[nodiscard]] uint64_t RegisterQuarantineCallback(QuarantineCallback callback);

    /**
     * @brief Unregister quarantine callback.
     */
    bool UnregisterQuarantineCallback(uint64_t callbackId);

    /**
     * @brief Register restore callback.
     */
    [[nodiscard]] uint64_t RegisterRestoreCallback(RestoreCallback callback);

    /**
     * @brief Unregister restore callback.
     */
    bool UnregisterRestoreCallback(uint64_t callbackId);

    /**
     * @brief Register remediation callback.
     */
    [[nodiscard]] uint64_t RegisterRemediationCallback(RemediationCallback callback);

    /**
     * @brief Unregister remediation callback.
     */
    bool UnregisterRemediationCallback(uint64_t callbackId);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] QuarantineManagerStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set quarantine database.
     */
    void SetQuarantineDB(Database::QuarantineDB* db);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    QuarantineManager();
    ~QuarantineManager();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Collect file metadata.
     */
    FileMetadata CollectMetadata(const std::wstring& filePath);

    /**
     * @brief Calculate file hashes.
     */
    QuarantineHashes CalculateHashes(const std::wstring& filePath);

    /**
     * @brief Encrypt file content.
     */
    std::vector<uint8_t> EncryptContent(
        std::span<const uint8_t> data,
        std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    );

    /**
     * @brief Decrypt file content.
     */
    std::vector<uint8_t> DecryptContent(
        std::span<const uint8_t> data,
        const std::array<uint8_t, QuarantineConstants::GCM_IV_SIZE>& iv
    );

    /**
     * @brief Write quarantine file.
     */
    bool WriteQuarantineFile(
        const std::wstring& destPath,
        const QuarantineEntry& entry,
        std::span<const uint8_t> content
    );

    /**
     * @brief Read quarantine file.
     */
    std::optional<std::vector<uint8_t>> ReadQuarantineFile(
        const std::wstring& sourcePath,
        QuarantineEntry& entry
    );

    /**
     * @brief Secure wipe file.
     */
    bool SecureWipeFile(const std::wstring& filePath);

    /**
     * @brief Generate unique quarantine path.
     */
    std::wstring GenerateQuarantinePath(const std::wstring& originalPath);

    /**
     * @brief Check if file is system-critical.
     */
    bool IsSystemCriticalFile(const std::wstring& filePath);

    /**
     * @brief Invoke quarantine callbacks.
     */
    void InvokeQuarantineCallbacks(const QuarantineResult& result);

    /**
     * @brief Invoke restore callbacks.
     */
    void InvokeRestoreCallbacks(const RestoreResult& result);

    /**
     * @brief Invoke remediation callbacks.
     */
    void InvokeRemediationCallbacks(const RemediationAction& action);

    /**
     * @brief Cleanup expired entries (background).
     */
    void CleanupExpiredEntries();

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if file path is valid for quarantine.
 */
[[nodiscard]] bool IsValidQuarantinePath(const std::wstring& path) noexcept;

/**
 * @brief Get file size safely.
 */
[[nodiscard]] uint64_t GetFileSizeSafe(const std::wstring& path) noexcept;

/**
 * @brief Generate quarantine file name.
 */
[[nodiscard]] std::wstring GenerateQuarantineFileName(
    const std::string& hash,
    const std::wstring& originalExtension
) noexcept;

/**
 * @brief Check if process can be terminated.
 */
[[nodiscard]] bool CanTerminateProcess(uint32_t processId) noexcept;

/**
 * @brief Get process image path.
 */
[[nodiscard]] std::wstring GetProcessImagePath(uint32_t processId) noexcept;

/**
 * @brief Check if file is locked.
 */
[[nodiscard]] bool IsFileLocked(const std::wstring& path) noexcept;

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
