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
 * ShadowStrike Security - FILE PROTECTION ENGINE
 * ============================================================================
 *
 * @file FileProtection.hpp
 * @brief Enterprise-grade file protection system for securing ShadowStrike
 *        installation files, databases, and configuration from tampering.
 *
 * This module implements comprehensive file protection mechanisms to prevent
 * malware from deleting, modifying, or corrupting critical antivirus files.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. DIRECTORY LOCKDOWN
 *    - Installation directory protection
 *    - Signature database protection
 *    - Configuration directory protection
 *    - Quarantine directory protection
 *    - Log directory protection
 *
 * 2. FILE OPERATION FILTERING
 *    - Delete operation blocking
 *    - Rename operation blocking
 *    - Write operation control
 *    - Attribute change blocking
 *    - Permission change blocking
 *
 * 3. MINIFILTER INTEGRATION
 *    - Kernel-mode file filtering
 *    - Pre-operation callbacks
 *    - Post-operation callbacks
 *    - Stream context management
 *    - File context tracking
 *
 * 4. SIGNATURE VALIDATION
 *    - Authenticode verification
 *    - Catalog signature checking
 *    - Publisher validation
 *    - Certificate chain verification
 *    - ShadowStrike-signed file detection
 *
 * 5. INTEGRITY MONITORING
 *    - Hash-based integrity verification
 *    - Change detection and alerting
 *    - Real-time modification tracking
 *    - Baseline management
 *    - Automatic repair capability
 *
 * 6. ACCESS CONTROL
 *    - DACL enforcement
 *    - ACE manipulation protection
 *    - Ownership protection
 *    - Inheritance control
 *    - Mandatory integrity labels
 *
 * 7. BACKUP AND RECOVERY
 *    - Automatic backup creation
 *    - Version tracking
 *    - Rollback capability
 *    - Shadow copy integration
 *    - Restore point creation
 *
 * 8. RANSOMWARE PROTECTION
 *    - Encryption detection
 *    - Mass modification detection
 *    - Extension change monitoring
 *    - Entropy analysis
 *    - Honeypot file monitoring
 *
 * PROTECTED FILE CATEGORIES:
 * ==========================
 * - Executables: ShadowStrike*.exe, *.dll
 * - Databases: *.db, *.mmf (memory-mapped files)
 * - Signatures: signatures.*, patterns.*, rules.*
 * - Configuration: *.conf, *.xml, *.json
 * - Logs: *.log (optional write-only mode)
 * - Quarantine: quarantine\*
 *
 * @note Full protection requires kernel minifilter driver.
 * @note User-mode protection available with reduced capability.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
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
#include <bitset>
#include <filesystem>
#include <regex>

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
#  include <Aclapi.h>
#  include <Sddl.h>
#  include <wintrust.h>
#  include <softpub.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/CertUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../HashStore/HashStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class FileProtectionImpl;
    class TamperProtection;
    class SelfDefense;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace FileProtectionConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum protected paths
    inline constexpr size_t MAX_PROTECTED_PATHS = 500;
    
    /// @brief Maximum protected patterns
    inline constexpr size_t MAX_PROTECTED_PATTERNS = 100;
    
    /// @brief Maximum file size for hashing (100 MB)
    inline constexpr size_t MAX_FILE_SIZE_FOR_HASH = 100 * 1024 * 1024;
    
    /// @brief Maximum path length
    inline constexpr size_t MAX_PATH_LENGTH = 32767;
    
    /// @brief Maximum backup versions per file
    inline constexpr size_t MAX_BACKUP_VERSIONS = 5;
    
    /// @brief Maximum blocked operations log entries
    inline constexpr size_t MAX_BLOCKED_OPERATIONS_LOG = 1000;

    // ========================================================================
    // INTERVALS
    // ========================================================================
    
    /// @brief Integrity check interval (milliseconds)
    inline constexpr uint32_t INTEGRITY_CHECK_INTERVAL_MS = 60000;
    
    /// @brief Ransomware detection window (milliseconds)
    inline constexpr uint32_t RANSOMWARE_DETECTION_WINDOW_MS = 5000;
    
    /// @brief Minimum interval between file change alerts
    inline constexpr uint32_t CHANGE_ALERT_INTERVAL_MS = 1000;

    // ========================================================================
    // RANSOMWARE DETECTION
    // ========================================================================
    
    /// @brief Modifications threshold for ransomware detection
    inline constexpr uint32_t RANSOMWARE_MODIFICATION_THRESHOLD = 10;
    
    /// @brief Entropy threshold for encryption detection
    inline constexpr double ENCRYPTION_ENTROPY_THRESHOLD = 7.5;
    
    /// @brief Maximum file extensions to track for ransomware
    inline constexpr size_t MAX_EXTENSION_TRACKING = 1000;

    // ========================================================================
    // HASH SIZES
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;
    inline constexpr size_t SHA512_SIZE = 64;

    // ========================================================================
    // DEFAULT PROTECTED EXTENSIONS
    // ========================================================================
    
    inline constexpr std::array<std::wstring_view, 15> PROTECTED_EXTENSIONS = {
        L".exe", L".dll", L".sys", L".db", L".mmf",
        L".sig", L".yar", L".yara", L".rule", L".conf",
        L".xml", L".json", L".pem", L".cer", L".crt"
    };

}  // namespace FileProtectionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Milliseconds = std::chrono::milliseconds;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief File protection mode
 */
enum class FileProtectionMode : uint8_t {
    Disabled    = 0,    ///< No protection
    Monitor     = 1,    ///< Monitor and log only
    Protect     = 2,    ///< Monitor and block
    Strict      = 3     ///< Strict enforcement
};

/**
 * @brief File operation type
 */
enum class FileOperation : uint32_t {
    None            = 0x00000000,
    Read            = 0x00000001,
    Write           = 0x00000002,
    Delete          = 0x00000004,
    Rename          = 0x00000008,
    Create          = 0x00000010,
    SetAttributes   = 0x00000020,
    SetSecurity     = 0x00000040,
    SetOwner        = 0x00000080,
    Execute         = 0x00000100,
    OpenDirectory   = 0x00000200,
    QueryInfo       = 0x00000400,
    SetInfo         = 0x00000800,
    
    AllWrite        = Write | Delete | Rename | Create | SetAttributes | SetSecurity | SetOwner,
    AllRead         = Read | QueryInfo | OpenDirectory,
    All             = 0xFFFFFFFF
};

inline constexpr FileOperation operator|(FileOperation a, FileOperation b) noexcept {
    return static_cast<FileOperation>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr FileOperation operator&(FileOperation a, FileOperation b) noexcept {
    return static_cast<FileOperation>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief File protection type
 */
enum class ProtectionType : uint8_t {
    None            = 0,
    ReadOnly        = 1,    ///< Allow reads, block writes
    NoDelete        = 2,    ///< Allow writes, block delete
    NoModify        = 3,    ///< Block all modifications
    Full            = 4,    ///< Full protection (ShadowStrike signed only)
    WriteOnly       = 5,    ///< For logs - append only
    Custom          = 6     ///< Custom operation mask
};

/**
 * @brief Integrity status
 */
enum class IntegrityStatus : uint8_t {
    Unknown     = 0,
    Valid       = 1,
    Modified    = 2,
    Missing     = 3,
    Corrupted   = 4,
    New         = 5,
    Restored    = 6
};

/**
 * @brief Signature status
 */
enum class SignatureStatus : uint8_t {
    Unknown         = 0,
    Valid           = 1,
    Invalid         = 2,
    Unsigned        = 3,
    Expired         = 4,
    Revoked         = 5,
    Untrusted       = 6,
    ShadowStrike    = 7     ///< Valid ShadowStrike signature
};

/**
 * @brief File operation decision
 */
enum class OperationDecision : uint8_t {
    Allow       = 0,
    Block       = 1,
    AllowLogged = 2,    ///< Allow but log
    Defer       = 3     ///< Defer to other filters
};

/**
 * @brief Protection event type
 */
enum class ProtectionEventType : uint32_t {
    None                    = 0x00000000,
    OperationBlocked        = 0x00000001,
    OperationAllowed        = 0x00000002,
    IntegrityViolation      = 0x00000004,
    SignatureViolation      = 0x00000008,
    UnauthorizedAccess      = 0x00000010,
    FileCreated             = 0x00000020,
    FileDeleted             = 0x00000040,
    FileModified            = 0x00000080,
    FileRenamed             = 0x00000100,
    RansomwareDetected      = 0x00000200,
    MassModification        = 0x00000400,
    BackupCreated           = 0x00000800,
    FileRestored            = 0x00001000,
    
    All                     = 0xFFFFFFFF
};

inline constexpr ProtectionEventType operator|(ProtectionEventType a, ProtectionEventType b) noexcept {
    return static_cast<ProtectionEventType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Protection response
 */
enum class ProtectionResponse : uint32_t {
    None            = 0x00000000,
    Log             = 0x00000001,
    Alert           = 0x00000002,
    Block           = 0x00000004,
    Backup          = 0x00000008,
    Restore         = 0x00000010,
    Quarantine      = 0x00000020,
    TerminateSource = 0x00000040,
    Escalate        = 0x00000080,
    
    Passive         = Log | Alert,
    Active          = Log | Alert | Block | Backup,
    Aggressive      = Log | Alert | Block | Backup | TerminateSource
};

inline constexpr ProtectionResponse operator|(ProtectionResponse a, ProtectionResponse b) noexcept {
    return static_cast<ProtectionResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
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
 * @brief File protection configuration
 */
struct FileProtectionConfiguration {
    /// @brief Protection mode
    FileProtectionMode mode = FileProtectionMode::Protect;
    
    /// @brief Enable kernel-mode filtering (requires driver)
    bool enableKernelFiltering = true;
    
    /// @brief Enable signature validation
    bool enableSignatureValidation = true;
    
    /// @brief Require ShadowStrike signature for modifications
    bool requireShadowStrikeSignature = true;
    
    /// @brief Enable integrity monitoring
    bool enableIntegrityMonitoring = true;
    
    /// @brief Integrity check interval (milliseconds)
    uint32_t integrityCheckIntervalMs = FileProtectionConstants::INTEGRITY_CHECK_INTERVAL_MS;
    
    /// @brief Enable automatic backup
    bool enableAutoBackup = true;
    
    /// @brief Maximum backup versions
    uint32_t maxBackupVersions = FileProtectionConstants::MAX_BACKUP_VERSIONS;
    
    /// @brief Enable ransomware protection
    bool enableRansomwareProtection = true;
    
    /// @brief Enable real-time monitoring
    bool enableRealTimeMonitoring = true;
    
    /// @brief Default protection response
    ProtectionResponse defaultResponse = ProtectionResponse::Active;
    
    /// @brief Protected directories
    std::vector<std::wstring> protectedDirectories;
    
    /// @brief Protected file patterns (wildcards)
    std::vector<std::wstring> protectedPatterns;
    
    /// @brief Whitelisted processes that can modify protected files
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /// @brief Send telemetry
    bool sendTelemetry = true;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Create from protection mode
     */
    static FileProtectionConfiguration FromMode(FileProtectionMode mode);
};

/**
 * @brief Protected file information
 */
struct ProtectedFile {
    /// @brief File identifier
    std::string id;
    
    /// @brief Full path
    std::wstring path;
    
    /// @brief Normalized path (lowercase, no trailing slash)
    std::wstring normalizedPath;
    
    /// @brief Protection type
    ProtectionType type = ProtectionType::Full;
    
    /// @brief Blocked operations mask
    FileOperation blockedOperations = FileOperation::AllWrite;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Expected hash (SHA-256)
    Hash256 expectedHash{};
    
    /// @brief Current hash
    Hash256 currentHash{};
    
    /// @brief Integrity status
    IntegrityStatus integrity = IntegrityStatus::Unknown;
    
    /// @brief Signature status
    SignatureStatus signature = SignatureStatus::Unknown;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /// @brief Is ShadowStrike component
    bool isShadowStrikeFile = false;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Include subdirectories
    bool includeSubdirectories = false;
    
    /// @brief Last modified time
    std::chrono::system_clock::time_point lastModified;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief Last verified timestamp
    TimePoint lastVerified;
    
    /// @brief Blocked operation count
    std::atomic<uint64_t> blockedOperations_{0};
    
    /// @brief Backup path (if backed up)
    std::wstring backupPath;
    
    /// @brief Last backup time
    TimePoint lastBackupTime;
};

/**
 * @brief Protected directory information
 */
struct ProtectedDirectory {
    /// @brief Directory identifier
    std::string id;
    
    /// @brief Full path
    std::wstring path;
    
    /// @brief Protection type
    ProtectionType type = ProtectionType::Full;
    
    /// @brief Blocked operations
    FileOperation blockedOperations = FileOperation::AllWrite;
    
    /// @brief Include subdirectories
    bool includeSubdirectories = true;
    
    /// @brief File patterns to protect (within directory)
    std::vector<std::wstring> protectedPatterns;
    
    /// @brief File patterns to exclude
    std::vector<std::wstring> excludedPatterns;
    
    /// @brief Protection timestamp
    TimePoint protectedSince;
    
    /// @brief File count
    size_t fileCount = 0;
    
    /// @brief Blocked operation count
    std::atomic<uint64_t> blockedOperations_{0};
};

/**
 * @brief File operation request
 */
struct FileOperationRequest {
    /// @brief Operation type
    FileOperation operation = FileOperation::None;
    
    /// @brief Full file path
    std::wstring filePath;
    
    /// @brief Target path (for rename/move)
    std::wstring targetPath;
    
    /// @brief Requesting process ID
    uint32_t processId = 0;
    
    /// @brief Requesting thread ID
    uint32_t threadId = 0;
    
    /// @brief Requesting process name
    std::wstring processName;
    
    /// @brief Requesting process path
    std::wstring processPath;
    
    /// @brief Requested access rights
    uint32_t desiredAccess = 0;
    
    /// @brief Request timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Is requesting process elevated
    bool isElevated = false;
    
    /// @brief Is requesting process system
    bool isSystem = false;
    
    /// @brief Is requesting process whitelisted
    bool isWhitelisted = false;
    
    /// @brief Has valid ShadowStrike signature
    bool hasShadowStrikeSignature = false;
};

/**
 * @brief Operation decision result
 */
struct OperationDecisionResult {
    /// @brief Decision
    OperationDecision decision = OperationDecision::Allow;
    
    /// @brief Reason for decision
    std::string reason;
    
    /// @brief Should log this decision
    bool shouldLog = false;
    
    /// @brief Should alert on this decision
    bool shouldAlert = false;
    
    /// @brief Should create backup before operation
    bool shouldBackup = false;
};

/**
 * @brief File protection event
 */
struct FileProtectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event type
    ProtectionEventType type = ProtectionEventType::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Affected file path
    std::wstring filePath;
    
    /// @brief Target path (for rename)
    std::wstring targetPath;
    
    /// @brief File operation
    FileOperation operation = FileOperation::None;
    
    /// @brief Operation decision
    OperationDecision decision = OperationDecision::Allow;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Source process path
    std::wstring sourceProcessPath;
    
    /// @brief Response taken
    ProtectionResponse responseTaken = ProtectionResponse::None;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Was backed up
    bool wasBackedUp = false;
    
    /// @brief Was restored
    bool wasRestored = false;
    
    /// @brief Event description
    std::string description;
    
    /// @brief Previous hash (for modifications)
    Hash256 previousHash{};
    
    /// @brief New hash (for modifications)
    Hash256 newHash{};
    
    /// @brief Additional context
    std::unordered_map<std::string, std::string> context;
    
    /**
     * @brief Get event summary
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File backup information
 */
struct FileBackup {
    /// @brief Backup ID
    std::string id;
    
    /// @brief Original file path
    std::wstring originalPath;
    
    /// @brief Backup file path
    std::wstring backupPath;
    
    /// @brief Original file hash
    Hash256 originalHash{};
    
    /// @brief Backup file hash
    Hash256 backupHash{};
    
    /// @brief Original file size
    uint64_t originalSize = 0;
    
    /// @brief Backup timestamp
    TimePoint backupTime = Clock::now();
    
    /// @brief Backup version number
    uint32_t versionNumber = 0;
    
    /// @brief Backup reason
    std::string reason;
    
    /// @brief Is compressed
    bool isCompressed = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
};

/**
 * @brief Ransomware detection info
 */
struct RansomwareDetection {
    /// @brief Detection timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Suspected process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Number of modifications in window
    uint32_t modificationCount = 0;
    
    /// @brief Affected files
    std::vector<std::wstring> affectedFiles;
    
    /// @brief Changed extensions
    std::vector<std::wstring> changedExtensions;
    
    /// @brief Average entropy of modified files
    double averageEntropy = 0.0;
    
    /// @brief Detection confidence (0-100)
    uint32_t confidence = 0;
    
    /// @brief Response taken
    ProtectionResponse responseTaken = ProtectionResponse::None;
};

/**
 * @brief File protection statistics
 */
struct FileProtectionStatistics {
    /// @brief Total protected files
    std::atomic<uint64_t> totalProtectedFiles{0};
    
    /// @brief Total protected directories
    std::atomic<uint64_t> totalProtectedDirectories{0};
    
    /// @brief Total operations processed
    std::atomic<uint64_t> totalOperations{0};
    
    /// @brief Total operations blocked
    std::atomic<uint64_t> totalBlocked{0};
    
    /// @brief Total integrity checks
    std::atomic<uint64_t> totalIntegrityChecks{0};
    
    /// @brief Integrity violations
    std::atomic<uint64_t> integrityViolations{0};
    
    /// @brief Signature violations
    std::atomic<uint64_t> signatureViolations{0};
    
    /// @brief Ransomware detections
    std::atomic<uint64_t> ransomwareDetections{0};
    
    /// @brief Backups created
    std::atomic<uint64_t> backupsCreated{0};
    
    /// @brief Files restored
    std::atomic<uint64_t> filesRestored{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last event time
    TimePoint lastEventTime;
    
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

/// @brief Callback for protection events
using FileProtectionEventCallback = std::function<void(const FileProtectionEvent&)>;

/// @brief Callback for operation decisions (can override)
using OperationDecisionCallback = std::function<std::optional<OperationDecisionResult>(
    const FileOperationRequest&)>;

/// @brief Callback for ransomware detection
using RansomwareCallback = std::function<void(const RansomwareDetection&)>;

/// @brief Callback for integrity violations
using IntegrityCallback = std::function<void(const ProtectedFile&)>;

// ============================================================================
// FILE PROTECTION ENGINE CLASS
// ============================================================================

/**
 * @class FileProtection
 * @brief Enterprise-grade file protection engine
 *
 * Provides comprehensive file protection including directory lockdown,
 * signature validation, integrity monitoring, and ransomware protection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& fileProtection = FileProtection::Instance();
 *     
 *     FileProtectionConfiguration config;
 *     config.mode = FileProtectionMode::Protect;
 *     config.enableRansomwareProtection = true;
 *     
 *     if (!fileProtection.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize file protection");
 *     }
 *     
 *     // Protect installation directory
 *     fileProtection.ProtectDirectory(L"C:\\Program Files\\ShadowStrike");
 *     
 *     // Protect specific file
 *     fileProtection.ProtectFile(L"C:\\Program Files\\ShadowStrike\\signatures.db");
 *     
 *     // Check if operation is allowed
 *     bool allowed = fileProtection.IsOperationAllowed(path, desiredAccess);
 * @endcode
 */
class FileProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static FileProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    FileProtection(const FileProtection&) = delete;
    FileProtection& operator=(const FileProtection&) = delete;
    FileProtection(FileProtection&&) = delete;
    FileProtection& operator=(FileProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize file protection
     */
    [[nodiscard]] bool Initialize(const FileProtectionConfiguration& config = {});
    
    /**
     * @brief Initialize with protection mode
     */
    [[nodiscard]] bool Initialize(FileProtectionMode mode);
    
    /**
     * @brief Shutdown file protection
     */
    void Shutdown(std::string_view authorizationToken);
    
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
    [[nodiscard]] bool SetConfiguration(const FileProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] FileProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection mode
     */
    void SetProtectionMode(FileProtectionMode mode);
    
    /**
     * @brief Get protection mode
     */
    [[nodiscard]] FileProtectionMode GetProtectionMode() const noexcept;
    
    // ========================================================================
    // DIRECTORY PROTECTION
    // ========================================================================
    
    /**
     * @brief Register directory for protection
     */
    void ProtectDirectory(const std::wstring& path);
    
    /**
     * @brief Protect directory with options
     */
    [[nodiscard]] bool ProtectDirectory(std::wstring_view path, ProtectionType type,
                                        bool includeSubdirs = true);
    
    /**
     * @brief Unprotect directory
     */
    [[nodiscard]] bool UnprotectDirectory(std::wstring_view path, 
                                          std::string_view authorizationToken);
    
    /**
     * @brief Check if directory is protected
     */
    [[nodiscard]] bool IsDirectoryProtected(std::wstring_view path) const;
    
    /**
     * @brief Get protected directory info
     */
    [[nodiscard]] std::optional<ProtectedDirectory> GetProtectedDirectory(
        std::wstring_view path) const;
    
    /**
     * @brief Get all protected directories
     */
    [[nodiscard]] std::vector<ProtectedDirectory> GetAllProtectedDirectories() const;
    
    /**
     * @brief Protect ShadowStrike installation
     */
    [[nodiscard]] bool ProtectInstallationDirectory();
    
    // ========================================================================
    // FILE PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect file
     */
    [[nodiscard]] bool ProtectFile(std::wstring_view path, 
                                   ProtectionType type = ProtectionType::Full);
    
    /**
     * @brief Unprotect file
     */
    [[nodiscard]] bool UnprotectFile(std::wstring_view path, 
                                     std::string_view authorizationToken);
    
    /**
     * @brief Check if file is protected
     */
    [[nodiscard]] bool IsFileProtected(std::wstring_view path) const;
    
    /**
     * @brief Get protected file info
     */
    [[nodiscard]] std::optional<ProtectedFile> GetProtectedFile(std::wstring_view path) const;
    
    /**
     * @brief Get all protected files
     */
    [[nodiscard]] std::vector<ProtectedFile> GetAllProtectedFiles() const;
    
    /**
     * @brief Add file pattern to protection
     */
    [[nodiscard]] bool ProtectPattern(std::wstring_view pattern, 
                                      ProtectionType type = ProtectionType::Full);
    
    /**
     * @brief Remove file pattern from protection
     */
    [[nodiscard]] bool UnprotectPattern(std::wstring_view pattern,
                                        std::string_view authorizationToken);
    
    // ========================================================================
    // OPERATION FILTERING
    // ========================================================================
    
    /**
     * @brief Check if operation is allowed on path
     */
    [[nodiscard]] bool IsOperationAllowed(const std::wstring& path, uint32_t desiredAccess);
    
    /**
     * @brief Filter file operation request
     */
    [[nodiscard]] OperationDecisionResult FilterOperation(const FileOperationRequest& request);
    
    /**
     * @brief Set custom decision callback
     */
    void SetDecisionCallback(OperationDecisionCallback callback);
    
    /**
     * @brief Clear custom decision callback
     */
    void ClearDecisionCallback();
    
    // ========================================================================
    // SIGNATURE VALIDATION
    // ========================================================================
    
    /**
     * @brief Verify file signature
     */
    [[nodiscard]] SignatureStatus VerifyFileSignature(std::wstring_view path);
    
    /**
     * @brief Check if file has ShadowStrike signature
     */
    [[nodiscard]] bool HasShadowStrikeSignature(std::wstring_view path);
    
    /**
     * @brief Get file signer name
     */
    [[nodiscard]] std::wstring GetFileSigner(std::wstring_view path);
    
    /**
     * @brief Verify file against catalog
     */
    [[nodiscard]] bool VerifyFileCatalog(std::wstring_view path);
    
    // ========================================================================
    // INTEGRITY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Verify file integrity
     */
    [[nodiscard]] IntegrityStatus VerifyFileIntegrity(std::wstring_view path);
    
    /**
     * @brief Verify all protected files
     */
    [[nodiscard]] std::vector<std::pair<std::wstring, IntegrityStatus>> VerifyAllIntegrity();
    
    /**
     * @brief Update file baseline
     */
    [[nodiscard]] bool UpdateFileBaseline(std::wstring_view path, 
                                          std::string_view authorizationToken);
    
    /**
     * @brief Force integrity check
     */
    void ForceIntegrityCheck();
    
    /**
     * @brief Compute file hash
     */
    [[nodiscard]] Hash256 ComputeFileHash(std::wstring_view path);
    
    // ========================================================================
    // BACKUP AND RESTORE
    // ========================================================================
    
    /**
     * @brief Create file backup
     */
    [[nodiscard]] bool CreateBackup(std::wstring_view path);
    
    /**
     * @brief Restore file from backup
     */
    [[nodiscard]] bool RestoreFromBackup(std::wstring_view path, uint32_t version = 0);
    
    /**
     * @brief Get available backups for file
     */
    [[nodiscard]] std::vector<FileBackup> GetAvailableBackups(std::wstring_view path) const;
    
    /**
     * @brief Delete old backups
     */
    void CleanupOldBackups();
    
    /**
     * @brief Get backup storage path
     */
    [[nodiscard]] std::wstring GetBackupStoragePath() const;
    
    /**
     * @brief Set backup storage path
     */
    [[nodiscard]] bool SetBackupStoragePath(std::wstring_view path);
    
    // ========================================================================
    // RANSOMWARE PROTECTION
    // ========================================================================
    
    /**
     * @brief Enable ransomware protection
     */
    [[nodiscard]] bool EnableRansomwareProtection();
    
    /**
     * @brief Disable ransomware protection
     */
    void DisableRansomwareProtection(std::string_view authorizationToken);
    
    /**
     * @brief Check if ransomware protection is enabled
     */
    [[nodiscard]] bool IsRansomwareProtectionEnabled() const;
    
    /**
     * @brief Get ransomware detections
     */
    [[nodiscard]] std::vector<RansomwareDetection> GetRansomwareDetections() const;
    
    /**
     * @brief Set ransomware callback
     */
    void SetRansomwareCallback(RansomwareCallback callback);
    
    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add process to whitelist
     */
    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName,
                                      std::string_view authorizationToken);
    
    /**
     * @brief Remove process from whitelist
     */
    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view processName,
                                           std::string_view authorizationToken);
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;
    
    /**
     * @brief Check if process ID is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    
    /**
     * @brief Get all whitelisted processes
     */
    [[nodiscard]] std::vector<std::wstring> GetWhitelistedProcesses() const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register event callback
     */
    [[nodiscard]] uint64_t RegisterEventCallback(FileProtectionEventCallback callback);
    
    /**
     * @brief Unregister event callback
     */
    void UnregisterEventCallback(uint64_t callbackId);
    
    /**
     * @brief Register integrity callback
     */
    [[nodiscard]] uint64_t RegisterIntegrityCallback(IntegrityCallback callback);
    
    /**
     * @brief Unregister integrity callback
     */
    void UnregisterIntegrityCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] FileProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get event history
     */
    [[nodiscard]] std::vector<FileProtectionEvent> GetEventHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear event history
     */
    void ClearEventHistory(std::string_view authorizationToken);
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test protection mechanisms
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Normalize file path
     */
    [[nodiscard]] static std::wstring NormalizePath(std::wstring_view path);
    
    /**
     * @brief Check if path matches pattern
     */
    [[nodiscard]] static bool MatchesPattern(std::wstring_view path, std::wstring_view pattern);
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    FileProtection();
    ~FileProtection();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<FileProtectionImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get protection mode name
 */
[[nodiscard]] std::string_view GetProtectionModeName(FileProtectionMode mode) noexcept;

/**
 * @brief Get file operation name
 */
[[nodiscard]] std::string_view GetFileOperationName(FileOperation operation) noexcept;

/**
 * @brief Get protection type name
 */
[[nodiscard]] std::string_view GetProtectionTypeName(ProtectionType type) noexcept;

/**
 * @brief Get integrity status name
 */
[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept;

/**
 * @brief Get signature status name
 */
[[nodiscard]] std::string_view GetSignatureStatusName(SignatureStatus status) noexcept;

/**
 * @brief Format file operation for display
 */
[[nodiscard]] std::string FormatFileOperation(FileOperation operation);

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class FileProtectionGuard
 * @brief RAII wrapper for temporary file protection
 */
class FileProtectionGuard final {
public:
    explicit FileProtectionGuard(std::wstring_view path, 
                                 ProtectionType type = ProtectionType::Full);
    ~FileProtectionGuard();
    
    FileProtectionGuard(const FileProtectionGuard&) = delete;
    FileProtectionGuard& operator=(const FileProtectionGuard&) = delete;
    
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }

private:
    std::wstring m_path;
    bool m_protected = false;
    std::string m_authToken;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Protect ShadowStrike installation
 */
#define SS_PROTECT_INSTALLATION() \
    ::ShadowStrike::Security::FileProtection::Instance().ProtectInstallationDirectory()

/**
 * @brief Check if file operation is allowed
 */
#define SS_IS_FILE_OP_ALLOWED(path, access) \
    ::ShadowStrike::Security::FileProtection::Instance().IsOperationAllowed((path), (access))
