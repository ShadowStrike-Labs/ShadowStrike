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
 * ShadowStrike Real-Time - FILE INTEGRITY MONITOR (The Surveyor)
 * ============================================================================
 *
 * @file FileIntegrityMonitor.hpp
 * @brief Enterprise-grade file integrity monitoring and protection.
 *
 * This module provides continuous monitoring of critical system files,
 * application binaries, and configuration files for unauthorized changes.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **Baseline Management**
 *    - Cryptographic hash baselines (SHA-256, SHA-512)
 *    - Attribute baselines (size, timestamps, permissions)
 *    - Digital signature verification
 *    - Version tracking
 *
 * 2. **Real-Time Monitoring**
 *    - File change detection via kernel callbacks
 *    - Directory change notification
 *    - Attribute modification detection
 *    - Rename/move tracking
 *
 * 3. **Integrity Verification**
 *    - On-demand verification
 *    - Scheduled verification
 *    - Boot-time verification
 *    - Continuous verification mode
 *
 * 4. **Automatic Remediation**
 *    - Restore from known-good copy
 *    - WFP (Windows File Protection) integration
 *    - Backup management
 *    - Rollback capabilities
 *
 * 5. **Compliance Support**
 *    - PCI-DSS FIM requirements
 *    - HIPAA audit trail
 *    - SOX compliance logging
 *    - Custom compliance policies
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                          KERNEL MODE                                         │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    Minifilter Driver                                 │   │
 * │  │                                                                       │   │
 * │  │  - IRP_MJ_WRITE monitoring                                           │   │
 * │  │  - IRP_MJ_SET_INFORMATION (rename, delete)                          │   │
 * │  │  - IRP_MJ_SET_SECURITY (permission changes)                         │   │
 * │  │                                                                       │   │
 * │  └────────────────────────────────────┬──────────────────────────────────┘   │
 * │                                       │                                      │
 * └───────────────────────────────────────┼──────────────────────────────────────┘
 *                                         │
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │ Change Notifications
 * ════════════════════════════════════════╪══════════════════════════════════════
 *                                         │
 * ┌───────────────────────────────────────┼──────────────────────────────────────┐
 * │                                       ▼                                      │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                    FileIntegrityMonitor                              │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────────────────────────────────────────────────┐    │   │
 * │  │  │                   Baseline Database                          │    │   │
 * │  │  │  - File path → Hash mapping                                  │    │   │
 * │  │  │  - Attribute snapshots                                       │    │   │
 * │  │  │  - Digital signature info                                    │    │   │
 * │  │  │  - Version history                                           │    │   │
 * │  │  └─────────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                       │   │
 * │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │   │
 * │  │  │  Change    │  │  Integrity │  │ Signature  │  │ Compliance │    │   │
 * │  │  │  Detector  │  │  Verifier  │  │  Checker   │  │  Reporter  │    │   │
 * │  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │   │
 * │  │        │               │               │               │           │   │
 * │  │        └───────────────┼───────────────┴───────────────┘           │   │
 * │  │                        │                                            │   │
 * │  │  ┌─────────────────────▼───────────────────────────────────────┐   │   │
 * │  │  │                   Remediation Engine                         │   │   │
 * │  │  │  - Restore from backup                                       │   │   │
 * │  │  │  - SFC (System File Checker) integration                    │   │   │
 * │  │  │  - Custom restore procedures                                 │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────────────────────────────────────────────────┐   │   │
 * │  │  │                   Monitoring Rules                           │   │   │
 * │  │  │  - Critical system files                                     │   │   │
 * │  │  │  - Application binaries                                      │   │   │
 * │  │  │  - Configuration files                                       │   │   │
 * │  │  │  - Custom watch paths                                        │   │   │
 * │  │  └─────────────────────────────────────────────────────────────┘   │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │                           USER MODE                                          │
 * └──────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * MONITORED FILE CATEGORIES
 * =============================================================================
 *
 * | Category              | Examples                                          |
 * |-----------------------|---------------------------------------------------|
 * | System DLLs           | kernel32.dll, ntdll.dll, user32.dll              |
 * | System Executables    | csrss.exe, lsass.exe, services.exe               |
 * | Boot Files            | bootmgr, winload.exe, BCD                        |
 * | Security Components   | MsMpEng.exe, defender DLLs                       |
 * | Configuration Files   | hosts, registry hives                            |
 * | Drivers               | *.sys files in System32\drivers                  |
 * | Application Binaries  | Custom monitored applications                    |
 *
 * =============================================================================
 * CHANGE TYPES DETECTED
 * =============================================================================
 *
 * | Change Type          | Detection Method                                   |
 * |----------------------|----------------------------------------------------|
 * | Content Modified     | Hash comparison                                    |
 * | File Replaced        | Hash + inode tracking                              |
 * | File Renamed         | Directory change notification                      |
 * | File Deleted         | Directory change notification                      |
 * | Permissions Changed  | ACL comparison                                     |
 * | Owner Changed        | Security descriptor comparison                     |
 * | Timestamp Modified   | Attribute comparison                               |
 * | Alternate Streams    | ADS enumeration                                    |
 *
 * =============================================================================
 * COMPLIANCE MAPPING
 * =============================================================================
 *
 * | Standard    | Requirement                        | Coverage                |
 * |-------------|------------------------------------|--------------------------
 * | PCI-DSS 11.5| FIM for critical system files      | Full                    |
 * | HIPAA       | Audit controls, integrity controls | Full                    |
 * | SOX         | IT general controls               | Full                    |
 * | NIST 800-53 | SI-7 (Software integrity)          | Full                    |
 * | CIS Controls| Control 3 (Data Protection)        | Full                    |
 *
 * =============================================================================
 * MITRE ATT&CK COVERAGE
 * =============================================================================
 *
 * | Technique | Description                          | Detection Method         |
 * |-----------|--------------------------------------|--------------------------|
 * | T1565     | Data Manipulation                    | Hash verification        |
 * | T1070     | Indicator Removal                    | Delete detection         |
 * | T1036     | Masquerading                         | Rename tracking          |
 * | T1222     | File Permissions Modification        | ACL monitoring           |
 * | T1553     | Subvert Trust Controls               | Signature verification   |
 * | T1574     | Hijack Execution Flow               | DLL modification detect  |
 *
 * @note Thread-safe for all public methods
 * @note Requires kernel driver for real-time monitoring
 *
 * @see FileSystemFilter for file access monitoring
 * @see Backup::FileBackupManager for backup management
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/FileUtils.hpp"             // File operations
#include "../Utils/HashUtils.hpp"             // Hash computation
#include "../HashStore/HashStore.hpp"         // Baseline storage
#include "../Whitelist/WhiteListStore.hpp"    // Excluded paths

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
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
    namespace HashStore {
        class HashStore;
    }
    namespace Database {
        class DatabaseManager;
    }
    namespace Backup {
        class FileBackupManager;
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class FileIntegrityMonitor;
struct FileBaseline;
struct FileChangeEvent;
struct IntegrityViolation;
struct MonitoringRule;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace FIMConstants {
    // -------------------------------------------------------------------------
    // Monitoring Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum monitored files
    constexpr size_t MAX_MONITORED_FILES = 100000;
    
    /// @brief Maximum monitored directories
    constexpr size_t MAX_MONITORED_DIRECTORIES = 10000;
    
    /// @brief Maximum baseline history per file
    constexpr size_t MAX_BASELINE_HISTORY = 100;
    
    /// @brief Maximum pending changes in queue
    constexpr size_t MAX_PENDING_CHANGES = 10000;
    
    // -------------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------------
    
    /// @brief Default verification interval (seconds)
    constexpr uint32_t DEFAULT_VERIFY_INTERVAL_SEC = 3600;  // 1 hour
    
    /// @brief Critical file verification interval (seconds)
    constexpr uint32_t CRITICAL_VERIFY_INTERVAL_SEC = 300;  // 5 minutes
    
    /// @brief Maximum file size for full hash (10 MB)
    constexpr size_t MAX_FULL_HASH_SIZE = 10 * 1024 * 1024;
    
    // -------------------------------------------------------------------------
    // Change Detection
    // -------------------------------------------------------------------------
    
    /// @brief Change detection debounce time (ms)
    constexpr uint32_t CHANGE_DEBOUNCE_MS = 1000;
    
    /// @brief Maximum changes per second before throttling
    constexpr size_t MAX_CHANGES_PER_SECOND = 100;
    
    // -------------------------------------------------------------------------
    // Risk Scores
    // -------------------------------------------------------------------------
    
    /// @brief System DLL modification score
    constexpr double SYSTEM_DLL_MODIFICATION_SCORE = 95.0;
    
    /// @brief Boot file modification score
    constexpr double BOOT_FILE_MODIFICATION_SCORE = 98.0;
    
    /// @brief Security component modification score
    constexpr double SECURITY_COMPONENT_SCORE = 90.0;
    
    /// @brief Configuration file modification score
    constexpr double CONFIG_FILE_MODIFICATION_SCORE = 70.0;
    
    /// @brief Permission change score
    constexpr double PERMISSION_CHANGE_SCORE = 50.0;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief File category for monitoring priority.
 */
enum class FileCategory : uint8_t {
    /// @brief Unknown category
    Unknown = 0,
    
    /// @brief System DLL
    SystemDLL = 1,
    
    /// @brief System executable
    SystemExecutable = 2,
    
    /// @brief Boot file
    BootFile = 3,
    
    /// @brief Driver file
    Driver = 4,
    
    /// @brief Security component
    SecurityComponent = 5,
    
    /// @brief Configuration file
    ConfigurationFile = 6,
    
    /// @brief Registry hive
    RegistryHive = 7,
    
    /// @brief Application binary
    ApplicationBinary = 8,
    
    /// @brief Application configuration
    ApplicationConfig = 9,
    
    /// @brief Log file
    LogFile = 10,
    
    /// @brief User data
    UserData = 11,
    
    /// @brief Temporary file
    Temporary = 12,
    
    /// @brief Custom monitored
    Custom = 13
};

/**
 * @brief Change type detected.
 */
enum class FileChangeType : uint16_t {
    /// @brief No change
    None = 0,
    
    /// @brief File created
    Created = 1,
    
    /// @brief File deleted
    Deleted = 2,
    
    /// @brief File modified (content)
    Modified = 3,
    
    /// @brief File renamed
    Renamed = 4,
    
    /// @brief File moved
    Moved = 5,
    
    /// @brief File replaced (deleted + created)
    Replaced = 6,
    
    /// @brief Permissions changed
    PermissionsChanged = 7,
    
    /// @brief Owner changed
    OwnerChanged = 8,
    
    /// @brief Timestamps modified
    TimestampsChanged = 9,
    
    /// @brief Attributes changed
    AttributesChanged = 10,
    
    /// @brief Alternate data stream added
    ADSAdded = 11,
    
    /// @brief Alternate data stream removed
    ADSRemoved = 12,
    
    /// @brief Alternate data stream modified
    ADSModified = 13,
    
    /// @brief Signature invalidated
    SignatureInvalidated = 14
};

/**
 * @brief Verification status.
 */
enum class VerificationStatus : uint8_t {
    /// @brief Not verified
    NotVerified = 0,
    
    /// @brief Integrity verified (matches baseline)
    Verified = 1,
    
    /// @brief Integrity violation
    Violated = 2,
    
    /// @brief File not found
    NotFound = 3,
    
    /// @brief Access denied
    AccessDenied = 4,
    
    /// @brief Verification error
    Error = 5,
    
    /// @brief No baseline exists
    NoBaseline = 6,
    
    /// @brief Pending verification
    Pending = 7
};

/**
 * @brief Monitoring mode.
 */
enum class MonitoringMode : uint8_t {
    /// @brief Disabled
    Disabled = 0,
    
    /// @brief Real-time monitoring
    RealTime = 1,
    
    /// @brief Scheduled monitoring
    Scheduled = 2,
    
    /// @brief On-demand only
    OnDemand = 3,
    
    /// @brief Continuous (aggressive)
    Continuous = 4
};

/**
 * @brief Remediation action.
 */
enum class FIMAction : uint8_t {
    /// @brief Log only
    LogOnly = 0,
    
    /// @brief Alert
    Alert = 1,
    
    /// @brief Restore from backup
    Restore = 2,
    
    /// @brief Block access
    BlockAccess = 3,
    
    /// @brief Quarantine
    Quarantine = 4,
    
    /// @brief Custom action
    Custom = 5
};

/**
 * @brief Hash algorithm for baselines.
 */
enum class HashAlgorithm : uint8_t {
    /// @brief SHA-256
    SHA256 = 0,
    
    /// @brief SHA-512
    SHA512 = 1,
    
    /// @brief SHA-1 (legacy)
    SHA1 = 2,
    
    /// @brief MD5 (legacy, not recommended)
    MD5 = 3,
    
    /// @brief BLAKE2b
    BLAKE2b = 4,
    
    /// @brief BLAKE3
    BLAKE3 = 5
};

/**
 * @brief Get string for FileChangeType.
 */
[[nodiscard]] constexpr const char* FileChangeTypeToString(FileChangeType type) noexcept;

/**
 * @brief Get string for FileCategory.
 */
[[nodiscard]] constexpr const char* FileCategoryToString(FileCategory category) noexcept;

/**
 * @brief Get MITRE technique for change type.
 */
[[nodiscard]] constexpr const char* FileChangeToMitre(FileChangeType type) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief File attributes for baseline.
 */
struct FileAttributes {
    /// @brief File size
    uint64_t size = 0;
    
    /// @brief Creation time
    std::chrono::system_clock::time_point creationTime{};
    
    /// @brief Last modification time
    std::chrono::system_clock::time_point modificationTime{};
    
    /// @brief Last access time
    std::chrono::system_clock::time_point accessTime{};
    
    /// @brief File attributes (FILE_ATTRIBUTE_*)
    uint32_t attributes = 0;
    
    /// @brief Is read-only
    bool isReadOnly = false;
    
    /// @brief Is hidden
    bool isHidden = false;
    
    /// @brief Is system file
    bool isSystem = false;
    
    /// @brief Is archive
    bool isArchive = false;
    
    /// @brief Is compressed
    bool isCompressed = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is sparse file
    bool isSparse = false;
    
    /// @brief Has alternate data streams
    bool hasADS = false;
    
    /// @brief Number of alternate data streams
    uint32_t adsCount = 0;
};

/**
 * @brief Security descriptor information.
 */
struct FileSecurityInfo {
    /// @brief Owner SID (string form)
    std::wstring ownerSid;
    
    /// @brief Owner name
    std::wstring ownerName;
    
    /// @brief Group SID
    std::wstring groupSid;
    
    /// @brief Group name
    std::wstring groupName;
    
    /// @brief DACL present
    bool hasDACL = false;
    
    /// @brief SACL present
    bool hasSACL = false;
    
    /// @brief ACL hash (for change detection)
    std::string aclHash;
    
    /// @brief Inheritance enabled
    bool inheritanceEnabled = true;
};

/**
 * @brief Digital signature information.
 */
struct FileSignatureInfo {
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief Signature valid
    bool signatureValid = false;
    
    /// @brief Is catalog signed
    bool isCatalogSigned = false;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /// @brief Signer timestamp
    std::chrono::system_clock::time_point signerTimestamp{};
    
    /// @brief Certificate issuer
    std::wstring issuer;
    
    /// @brief Certificate serial
    std::string serialNumber;
    
    /// @brief Certificate thumbprint
    std::string thumbprint;
    
    /// @brief Is Microsoft signed
    bool isMicrosoftSigned = false;
    
    /// @brief Is OS component
    bool isOSComponent = false;
};

/**
 * @brief File baseline (known-good state).
 */
struct FileBaseline {
    /// @brief File path
    std::wstring path;
    
    /// @brief Normalized path (lowercase, no trailing slash)
    std::wstring normalizedPath;
    
    /// @brief File category
    FileCategory category = FileCategory::Unknown;
    
    /// @brief Primary hash (SHA-256)
    std::string hashSHA256;
    
    /// @brief Secondary hash (optional)
    std::string hashSHA512;
    
    /// @brief File attributes
    FileAttributes attributes;
    
    /// @brief Security information
    FileSecurityInfo security;
    
    /// @brief Signature information
    FileSignatureInfo signature;
    
    /// @brief PE version info (if applicable)
    std::wstring fileVersion;
    std::wstring productVersion;
    std::wstring companyName;
    std::wstring productName;
    
    /// @brief Baseline creation time
    std::chrono::system_clock::time_point baselineTime{};
    
    /// @brief Last verification time
    std::chrono::system_clock::time_point lastVerification{};
    
    /// @brief Verification status
    VerificationStatus status = VerificationStatus::NotVerified;
    
    /// @brief Is critical file
    bool isCritical = false;
    
    /// @brief Auto-restore enabled
    bool autoRestore = false;
    
    /// @brief Backup path (if exists)
    std::wstring backupPath;
    
    /// @brief Version number
    uint32_t version = 1;
    
    /// @brief Notes
    std::wstring notes;
};

/**
 * @brief File change event.
 */
struct FileChangeEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Change type
    FileChangeType changeType = FileChangeType::None;
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief New path (for rename/move)
    std::wstring newPath;
    
    /// @brief File category
    FileCategory category = FileCategory::Unknown;
    
    /// @brief Process ID that made the change
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Old hash (before change)
    std::string oldHash;
    
    /// @brief New hash (after change)
    std::string newHash;
    
    /// @brief Old size
    uint64_t oldSize = 0;
    
    /// @brief New size
    uint64_t newSize = 0;
    
    /// @brief Old attributes
    FileAttributes oldAttributes;
    
    /// @brief New attributes
    FileAttributes newAttributes;
    
    /// @brief Risk score
    double riskScore = 0.0;
    
    /// @brief Action taken
    FIMAction actionTaken = FIMAction::LogOnly;
    
    /// @brief Was restored
    bool wasRestored = false;
    
    /// @brief MITRE technique
    std::string mitreTechnique;
    
    /// @brief Additional context
    std::map<std::string, std::wstring> context;
};

/**
 * @brief Integrity violation record.
 */
struct IntegrityViolation {
    /// @brief Violation ID
    uint64_t violationId = 0;
    
    /// @brief Detection timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief File category
    FileCategory category = FileCategory::Unknown;
    
    /// @brief Violation type (change type)
    FileChangeType violationType = FileChangeType::None;
    
    /// @brief Expected hash
    std::string expectedHash;
    
    /// @brief Actual hash
    std::string actualHash;
    
    /// @brief Baseline reference
    std::shared_ptr<FileBaseline> baseline;
    
    /// @brief Current state
    FileAttributes currentAttributes;
    
    /// @brief Process that caused violation
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief User
    std::wstring userName;
    
    /// @brief Severity (0-100)
    double severity = 0.0;
    
    /// @brief Was remediated
    bool wasRemediated = false;
    
    /// @brief Remediation action
    FIMAction remediationAction = FIMAction::LogOnly;
    
    /// @brief Remediation result
    bool remediationSuccess = false;
    
    /// @brief Remediation error
    std::wstring remediationError;
};

/**
 * @brief Monitoring rule.
 */
struct MonitoringRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::wstring name;
    
    /// @brief Rule description
    std::wstring description;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Priority
    uint32_t priority = 0;
    
    /// @brief Path pattern (supports wildcards)
    std::wstring pathPattern;
    
    /// @brief Is recursive
    bool recursive = true;
    
    /// @brief File extensions to include (empty = all)
    std::vector<std::wstring> includeExtensions;
    
    /// @brief File extensions to exclude
    std::vector<std::wstring> excludeExtensions;
    
    /// @brief Monitoring mode
    MonitoringMode mode = MonitoringMode::RealTime;
    
    /// @brief Verification interval (seconds)
    uint32_t verifyIntervalSec = FIMConstants::DEFAULT_VERIFY_INTERVAL_SEC;
    
    /// @brief Category to assign
    FileCategory category = FileCategory::Custom;
    
    /// @brief Is critical
    bool isCritical = false;
    
    /// @brief Action on violation
    FIMAction violationAction = FIMAction::Alert;
    
    /// @brief Auto-restore enabled
    bool autoRestore = false;
    
    /// @brief Track content changes
    bool trackContent = true;
    
    /// @brief Track attribute changes
    bool trackAttributes = true;
    
    /// @brief Track permission changes
    bool trackPermissions = true;
    
    /// @brief Track alternate data streams
    bool trackADS = true;
    
    /// @brief Compliance tags
    std::vector<std::string> complianceTags;
    
    /// @brief Created time
    std::chrono::system_clock::time_point created{};
};

/**
 * @brief Verification result.
 */
struct VerificationResult {
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Verification status
    VerificationStatus status = VerificationStatus::NotVerified;
    
    /// @brief Baseline exists
    bool hasBaseline = false;
    
    /// @brief Hash matches
    bool hashMatches = true;
    
    /// @brief Attributes match
    bool attributesMatch = true;
    
    /// @brief Permissions match
    bool permissionsMatch = true;
    
    /// @brief Signature valid
    bool signatureValid = true;
    
    /// @brief Violations found
    std::vector<FileChangeType> violations;
    
    /// @brief Current hash
    std::string currentHash;
    
    /// @brief Expected hash
    std::string expectedHash;
    
    /// @brief Verification time (ms)
    uint64_t verificationTimeMs = 0;
    
    /// @brief Error message (if any)
    std::wstring errorMessage;
};

/**
 * @brief Batch verification result.
 */
struct BatchVerificationResult {
    /// @brief Total files verified
    size_t totalFiles = 0;
    
    /// @brief Files verified OK
    size_t verifiedOK = 0;
    
    /// @brief Files with violations
    size_t violations = 0;
    
    /// @brief Files not found
    size_t notFound = 0;
    
    /// @brief Files with errors
    size_t errors = 0;
    
    /// @brief Individual results
    std::vector<VerificationResult> results;
    
    /// @brief Total verification time (ms)
    uint64_t totalTimeMs = 0;
    
    /// @brief Start time
    std::chrono::system_clock::time_point startTime{};
    
    /// @brief End time
    std::chrono::system_clock::time_point endTime{};
};

/**
 * @brief Configuration for file integrity monitor.
 */
struct FIMConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable FIM
    bool enabled = true;
    
    /// @brief Default monitoring mode
    MonitoringMode defaultMode = MonitoringMode::RealTime;
    
    /// @brief Enable real-time monitoring
    bool realTimeMonitoring = true;
    
    /// @brief Enable scheduled verification
    bool scheduledVerification = true;
    
    // -------------------------------------------------------------------------
    // Verification Settings
    // -------------------------------------------------------------------------
    
    /// @brief Default verification interval (seconds)
    uint32_t verifyIntervalSec = FIMConstants::DEFAULT_VERIFY_INTERVAL_SEC;
    
    /// @brief Critical file interval (seconds)
    uint32_t criticalIntervalSec = FIMConstants::CRITICAL_VERIFY_INTERVAL_SEC;
    
    /// @brief Verify on startup
    bool verifyOnStartup = true;
    
    /// @brief Hash algorithm
    HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256;
    
    /// @brief Calculate secondary hash
    bool calculateSecondaryHash = false;
    
    // -------------------------------------------------------------------------
    // Action Settings
    // -------------------------------------------------------------------------
    
    /// @brief Default action on violation
    FIMAction defaultAction = FIMAction::Alert;
    
    /// @brief Action for critical files
    FIMAction criticalAction = FIMAction::Restore;
    
    /// @brief Auto-restore system files
    bool autoRestoreSystem = true;
    
    /// @brief Block access on violation
    bool blockOnViolation = false;
    
    // -------------------------------------------------------------------------
    // Tracking Settings
    // -------------------------------------------------------------------------
    
    /// @brief Track content changes
    bool trackContent = true;
    
    /// @brief Track attribute changes
    bool trackAttributes = true;
    
    /// @brief Track permission changes
    bool trackPermissions = true;
    
    /// @brief Track ADS
    bool trackADS = true;
    
    /// @brief Track timestamps
    bool trackTimestamps = false;  // Often noisy
    
    // -------------------------------------------------------------------------
    // Performance Settings
    // -------------------------------------------------------------------------
    
    /// @brief Maximum monitored files
    size_t maxMonitoredFiles = FIMConstants::MAX_MONITORED_FILES;
    
    /// @brief Change debounce time (ms)
    uint32_t debounceMs = FIMConstants::CHANGE_DEBOUNCE_MS;
    
    /// @brief Parallel verification threads
    uint32_t verificationThreads = 4;
    
    // -------------------------------------------------------------------------
    // System File Monitoring
    // -------------------------------------------------------------------------
    
    /// @brief Monitor Windows system files
    bool monitorSystemFiles = true;
    
    /// @brief Monitor drivers
    bool monitorDrivers = true;
    
    /// @brief Monitor boot files
    bool monitorBootFiles = true;
    
    /// @brief Monitor hosts file
    bool monitorHostsFile = true;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static FIMConfig CreateDefault() noexcept {
        return FIMConfig{};
    }
    
    /**
     * @brief Create strict configuration.
     */
    [[nodiscard]] static FIMConfig CreateStrict() noexcept {
        FIMConfig config;
        config.defaultAction = FIMAction::Restore;
        config.blockOnViolation = true;
        config.calculateSecondaryHash = true;
        config.criticalIntervalSec = 60;
        config.trackTimestamps = true;
        return config;
    }
    
    /**
     * @brief Create compliance configuration.
     */
    [[nodiscard]] static FIMConfig CreateCompliance() noexcept {
        FIMConfig config;
        config.trackContent = true;
        config.trackAttributes = true;
        config.trackPermissions = true;
        config.trackADS = true;
        config.trackTimestamps = true;
        config.calculateSecondaryHash = true;
        config.verifyIntervalSec = 900;  // 15 minutes
        return config;
    }
    
    /**
     * @brief Create lightweight configuration.
     */
    [[nodiscard]] static FIMConfig CreateLightweight() noexcept {
        FIMConfig config;
        config.trackAttributes = false;
        config.trackPermissions = false;
        config.trackADS = false;
        config.verifyIntervalSec = 7200;  // 2 hours
        config.verificationThreads = 2;
        return config;
    }
};

/**
 * @brief FIM statistics.
 */
struct FIMStats {
    /// @brief Total files monitored
    std::atomic<size_t> monitoredFiles{ 0 };
    
    /// @brief Total directories monitored
    std::atomic<size_t> monitoredDirectories{ 0 };
    
    /// @brief Total changes detected
    std::atomic<uint64_t> changesDetected{ 0 };
    
    /// @brief Total violations
    std::atomic<uint64_t> violations{ 0 };
    
    /// @brief Violations remediated
    std::atomic<uint64_t> violationsRemediated{ 0 };
    
    /// @brief Verifications performed
    std::atomic<uint64_t> verificationsPerformed{ 0 };
    
    /// @brief Verifications passed
    std::atomic<uint64_t> verificationsPassed{ 0 };
    
    /// @brief Verifications failed
    std::atomic<uint64_t> verificationsFailed{ 0 };
    
    /// @brief Baselines created
    std::atomic<uint64_t> baselinesCreated{ 0 };
    
    /// @brief Baselines updated
    std::atomic<uint64_t> baselinesUpdated{ 0 };
    
    /// @brief Restores performed
    std::atomic<uint64_t> restoresPerformed{ 0 };
    
    /// @brief Restores failed
    std::atomic<uint64_t> restoresFailed{ 0 };
    
    /// @brief Average verification time (ms)
    std::atomic<uint64_t> avgVerificationTimeMs{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        monitoredFiles.store(0, std::memory_order_relaxed);
        monitoredDirectories.store(0, std::memory_order_relaxed);
        changesDetected.store(0, std::memory_order_relaxed);
        violations.store(0, std::memory_order_relaxed);
        violationsRemediated.store(0, std::memory_order_relaxed);
        verificationsPerformed.store(0, std::memory_order_relaxed);
        verificationsPassed.store(0, std::memory_order_relaxed);
        verificationsFailed.store(0, std::memory_order_relaxed);
        baselinesCreated.store(0, std::memory_order_relaxed);
        baselinesUpdated.store(0, std::memory_order_relaxed);
        restoresPerformed.store(0, std::memory_order_relaxed);
        restoresFailed.store(0, std::memory_order_relaxed);
        avgVerificationTimeMs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using FileChangeCallback = std::function<FIMAction(const FileChangeEvent&)>;
using ViolationCallback = std::function<void(const IntegrityViolation&)>;
using VerificationCallback = std::function<void(const VerificationResult&)>;
using RestoreCallback = std::function<void(const std::wstring& path, bool success)>;

// ============================================================================
// MAIN FILE INTEGRITY MONITOR CLASS
// ============================================================================

/**
 * @brief Enterprise-grade file integrity monitoring and protection.
 *
 * Provides continuous monitoring of critical files for unauthorized changes
 * with automatic remediation and compliance reporting.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& fim = FileIntegrityMonitor::Instance();
 * 
 * // Initialize
 * FIMConfig config = FIMConfig::CreateDefault();
 * fim.Initialize(threadPool, config);
 * 
 * // Register callbacks
 * fim.RegisterViolationCallback([](const IntegrityViolation& violation) {
 *     LOG_ALERT(L"Integrity violation: {} - {}",
 *               violation.filePath,
 *               FileChangeTypeToString(violation.violationType));
 * });
 * 
 * // Start monitoring
 * fim.StartMonitoring();
 * 
 * // Add custom monitoring rule
 * MonitoringRule rule;
 * rule.ruleId = "custom-app";
 * rule.pathPattern = L"C:\\MyApp\\*.exe";
 * rule.isCritical = true;
 * rule.autoRestore = true;
 * fim.AddRule(rule);
 * 
 * // Create baselines
 * fim.CreateBaseline(L"C:\\Windows\\System32\\kernel32.dll");
 * 
 * // Verify integrity
 * auto result = fim.VerifyIntegrity(L"C:\\Windows\\System32\\kernel32.dll");
 * if (result.status == VerificationStatus::Violated) {
 *     LOG_ERROR("Integrity violation detected!");
 * }
 * 
 * // Batch verification
 * auto batchResult = fim.VerifyAll();
 * LOG_INFO("Verified {} files, {} violations", batchResult.totalFiles, batchResult.violations);
 * 
 * fim.StopMonitoring();
 * fim.Shutdown();
 * @endcode
 */
class FileIntegrityMonitor {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     */
    [[nodiscard]] static FileIntegrityMonitor& Instance();

    // Non-copyable, non-movable
    FileIntegrityMonitor(const FileIntegrityMonitor&) = delete;
    FileIntegrityMonitor& operator=(const FileIntegrityMonitor&) = delete;
    FileIntegrityMonitor(FileIntegrityMonitor&&) = delete;
    FileIntegrityMonitor& operator=(FileIntegrityMonitor&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the monitor.
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
        const FIMConfig& config
    );

    /**
     * @brief Shutdown the monitor.
     */
    void Shutdown();

    /**
     * @brief Start monitoring.
     */
    void StartMonitoring();

    /**
     * @brief Stop monitoring.
     */
    void StopMonitoring();

    /**
     * @brief Check if monitoring is active.
     */
    [[nodiscard]] bool IsMonitoring() const noexcept;

    /**
     * @brief Update configuration.
     */
    void UpdateConfig(const FIMConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] FIMConfig GetConfig() const;

    // =========================================================================
    // Baseline Management
    // =========================================================================

    /**
     * @brief Create baseline for file.
     */
    [[nodiscard]] bool CreateBaseline(const std::wstring& filePath);

    /**
     * @brief Create baselines for directory.
     */
    [[nodiscard]] size_t CreateBaselines(const std::wstring& directoryPath, bool recursive = true);

    /**
     * @brief Update baseline for file.
     */
    [[nodiscard]] bool UpdateBaseline(const std::wstring& filePath);

    /**
     * @brief Delete baseline.
     */
    bool DeleteBaseline(const std::wstring& filePath);

    /**
     * @brief Get baseline for file.
     */
    [[nodiscard]] std::optional<FileBaseline> GetBaseline(const std::wstring& filePath) const;

    /**
     * @brief Get all baselines.
     */
    [[nodiscard]] std::vector<FileBaseline> GetAllBaselines() const;

    /**
     * @brief Get baselines by category.
     */
    [[nodiscard]] std::vector<FileBaseline> GetBaselinesByCategory(FileCategory category) const;

    /**
     * @brief Import baselines from file.
     */
    bool ImportBaselines(const std::wstring& filePath);

    /**
     * @brief Export baselines to file.
     */
    bool ExportBaselines(const std::wstring& filePath) const;

    /**
     * @brief Create system file baselines.
     */
    size_t CreateSystemBaselines();

    // =========================================================================
    // Verification
    // =========================================================================

    /**
     * @brief Verify file integrity.
     */
    [[nodiscard]] VerificationResult VerifyIntegrity(const std::wstring& filePath);

    /**
     * @brief Verify directory integrity.
     */
    [[nodiscard]] BatchVerificationResult VerifyDirectory(
        const std::wstring& directoryPath,
        bool recursive = true
    );

    /**
     * @brief Verify all monitored files.
     */
    [[nodiscard]] BatchVerificationResult VerifyAll();

    /**
     * @brief Verify files by category.
     */
    [[nodiscard]] BatchVerificationResult VerifyByCategory(FileCategory category);

    /**
     * @brief Quick hash check.
     */
    [[nodiscard]] bool QuickVerify(const std::wstring& filePath);

    // =========================================================================
    // Change Handling
    // =========================================================================

    /**
     * @brief Handle file change event.
     */
    FIMAction OnFileChanged(const FileChangeEvent& event);

    /**
     * @brief Handle file change (from kernel).
     */
    void OnFileChanged(
        const std::wstring& filePath,
        FileChangeType changeType,
        uint32_t processId
    );

    /**
     * @brief Get recent changes.
     */
    [[nodiscard]] std::vector<FileChangeEvent> GetRecentChanges(size_t count = 100) const;

    /**
     * @brief Get changes for file.
     */
    [[nodiscard]] std::vector<FileChangeEvent> GetFileChanges(const std::wstring& filePath) const;

    // =========================================================================
    // Remediation
    // =========================================================================

    /**
     * @brief Restore file from backup.
     */
    [[nodiscard]] bool RestoreFile(const std::wstring& filePath);

    /**
     * @brief Restore from specific baseline version.
     */
    [[nodiscard]] bool RestoreFile(const std::wstring& filePath, uint32_t version);

    /**
     * @brief Restore all violated files.
     */
    [[nodiscard]] size_t RestoreAllViolations();

    /**
     * @brief Get violations.
     */
    [[nodiscard]] std::vector<IntegrityViolation> GetViolations() const;

    /**
     * @brief Get unresolved violations.
     */
    [[nodiscard]] std::vector<IntegrityViolation> GetUnresolvedViolations() const;

    /**
     * @brief Mark violation as resolved.
     */
    void ResolveViolation(uint64_t violationId);

    // =========================================================================
    // Rule Management
    // =========================================================================

    /**
     * @brief Add monitoring rule.
     */
    bool AddRule(const MonitoringRule& rule);

    /**
     * @brief Remove monitoring rule.
     */
    bool RemoveRule(const std::string& ruleId);

    /**
     * @brief Enable/disable rule.
     */
    void SetRuleEnabled(const std::string& ruleId, bool enabled);

    /**
     * @brief Get rule.
     */
    [[nodiscard]] std::optional<MonitoringRule> GetRule(const std::string& ruleId) const;

    /**
     * @brief Get all rules.
     */
    [[nodiscard]] std::vector<MonitoringRule> GetRules() const;

    /**
     * @brief Load rules from file.
     */
    bool LoadRulesFromFile(const std::wstring& filePath);

    /**
     * @brief Save rules to file.
     */
    bool SaveRulesToFile(const std::wstring& filePath) const;

    // =========================================================================
    // Directory Monitoring
    // =========================================================================

    /**
     * @brief Add directory to monitor.
     */
    bool AddMonitoredDirectory(const std::wstring& directoryPath, bool recursive = true);

    /**
     * @brief Remove monitored directory.
     */
    void RemoveMonitoredDirectory(const std::wstring& directoryPath);

    /**
     * @brief Get monitored directories.
     */
    [[nodiscard]] std::vector<std::wstring> GetMonitoredDirectories() const;

    // =========================================================================
    // Query
    // =========================================================================

    /**
     * @brief Check if file is monitored.
     */
    [[nodiscard]] bool IsFileMonitored(const std::wstring& filePath) const;

    /**
     * @brief Get file category.
     */
    [[nodiscard]] FileCategory GetFileCategory(const std::wstring& filePath) const;

    /**
     * @brief Calculate file hash.
     */
    [[nodiscard]] std::string CalculateFileHash(
        const std::wstring& filePath,
        HashAlgorithm algorithm = HashAlgorithm::SHA256
    ) const;

    /**
     * @brief Get file attributes.
     */
    [[nodiscard]] std::optional<FileAttributes> GetFileAttributes(const std::wstring& filePath) const;

    /**
     * @brief Get file signature info.
     */
    [[nodiscard]] std::optional<FileSignatureInfo> GetFileSignature(const std::wstring& filePath) const;

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get statistics.
     */
    [[nodiscard]] FIMStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Compliance Reporting
    // =========================================================================

    /**
     * @brief Generate compliance report.
     */
    bool GenerateComplianceReport(
        const std::wstring& outputPath,
        const std::vector<std::string>& complianceTags = {}
    ) const;

    /**
     * @brief Get change audit log.
     */
    [[nodiscard]] std::vector<FileChangeEvent> GetAuditLog(
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime
    ) const;

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register file change callback.
     */
    [[nodiscard]] uint64_t RegisterChangeCallback(FileChangeCallback callback);

    /**
     * @brief Unregister change callback.
     */
    bool UnregisterChangeCallback(uint64_t callbackId);

    /**
     * @brief Register violation callback.
     */
    [[nodiscard]] uint64_t RegisterViolationCallback(ViolationCallback callback);

    /**
     * @brief Unregister violation callback.
     */
    bool UnregisterViolationCallback(uint64_t callbackId);

    /**
     * @brief Register verification callback.
     */
    [[nodiscard]] uint64_t RegisterVerificationCallback(VerificationCallback callback);

    /**
     * @brief Unregister verification callback.
     */
    bool UnregisterVerificationCallback(uint64_t callbackId);

    /**
     * @brief Register restore callback.
     */
    [[nodiscard]] uint64_t RegisterRestoreCallback(RestoreCallback callback);

    /**
     * @brief Unregister restore callback.
     */
    bool UnregisterRestoreCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set hash store.
     */
    void SetHashStore(HashStore::HashStore* store);

    /**
     * @brief Set database manager.
     */
    void SetDatabaseManager(Database::DatabaseManager* manager);

    /**
     * @brief Set file backup manager.
     */
    void SetFileBackupManager(Backup::FileBackupManager* manager);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    FileIntegrityMonitor();
    ~FileIntegrityMonitor();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Initialize system file monitoring.
     */
    void InitializeSystemMonitoring();

    /**
     * @brief Directory change notification thread.
     */
    void DirectoryMonitorThread();

    /**
     * @brief Scheduled verification thread.
     */
    void ScheduledVerificationThread();

    /**
     * @brief Process change queue.
     */
    void ProcessChangeQueue();

    /**
     * @brief Classify file category.
     */
    FileCategory ClassifyFile(const std::wstring& filePath) const;

    /**
     * @brief Calculate risk score for change.
     */
    double CalculateRiskScore(const FileChangeEvent& event) const;

    /**
     * @brief Invoke change callbacks.
     */
    FIMAction InvokeChangeCallbacks(const FileChangeEvent& event);

    /**
     * @brief Invoke violation callbacks.
     */
    void InvokeViolationCallbacks(const IntegrityViolation& violation);

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
 * @brief Normalize file path.
 */
[[nodiscard]] std::wstring NormalizeFilePath(const std::wstring& path) noexcept;

/**
 * @brief Check if path matches pattern.
 */
[[nodiscard]] bool PathMatchesPattern(
    const std::wstring& path,
    const std::wstring& pattern
) noexcept;

/**
 * @brief Get Windows system directory.
 */
[[nodiscard]] std::wstring GetSystemDirectory() noexcept;

/**
 * @brief Get Windows directory.
 */
[[nodiscard]] std::wstring GetWindowsDirectory() noexcept;

/**
 * @brief Check if file is a system file.
 */
[[nodiscard]] bool IsSystemFile(const std::wstring& filePath) noexcept;

/**
 * @brief Enumerate directory files.
 */
[[nodiscard]] std::vector<std::wstring> EnumerateDirectory(
    const std::wstring& directoryPath,
    bool recursive = true
) noexcept;

/**
 * @brief Get file version info.
 */
[[nodiscard]] std::optional<std::pair<std::wstring, std::wstring>> GetFileVersionInfo(
    const std::wstring& filePath
) noexcept;

} // namespace RealTime
} // namespace ShadowStrike
