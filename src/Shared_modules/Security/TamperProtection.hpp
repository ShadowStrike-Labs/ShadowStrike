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
 * ShadowStrike Security - TAMPER PROTECTION ENGINE
 * ============================================================================
 *
 * @file TamperProtection.hpp
 * @brief Enterprise-grade tamper protection orchestrator that coordinates
 *        all protection subsystems to ensure antivirus integrity.
 *
 * This module serves as the central coordinator for all tamper protection
 * mechanisms in ShadowStrike. It orchestrates FileProtection, RegistryProtection,
 * ProcessProtection, MemoryProtection, and other security modules to provide
 * comprehensive defense against tampering attempts.
 *
 * ARCHITECTURE:
 * =============
 *
 *                    ┌─────────────────────────┐
 *                    │   TamperProtection      │
 *                    │   (Orchestrator)        │
 *                    └───────────┬─────────────┘
 *                                │
 *         ┌──────────┬───────────┼───────────┬──────────┐
 *         │          │           │           │          │
 *         ▼          ▼           ▼           ▼          ▼
 *    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
 *    │ File   │ │Registry│ │Process │ │Memory  │ │ Code   │
 *    │ Guard  │ │ Guard  │ │ Guard  │ │ Guard  │ │Integrity│
 *    └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
 *
 * PROTECTION DOMAINS:
 * ====================
 *
 * 1. FILE INTEGRITY
 *    - Executable integrity verification
 *    - Configuration file protection
 *    - Signature database protection
 *    - Log file protection
 *    - Real-time file change detection
 *
 * 2. REGISTRY INTEGRITY
 *    - Service configuration protection
 *    - Startup entry protection
 *    - Driver registry protection
 *    - Policy settings protection
 *    - Real-time registry change detection
 *
 * 3. PROCESS INTEGRITY
 *    - Process image verification
 *    - Thread integrity monitoring
 *    - Handle table protection
 *    - Token integrity verification
 *
 * 4. MEMORY INTEGRITY
 *    - Code section CRC monitoring
 *    - IAT/EAT integrity verification
 *    - Stack canary monitoring
 *    - Heap integrity checks
 *
 * 5. CODE INTEGRITY
 *    - Digital signature verification
 *    - Authenticode validation
 *    - Catalog file verification
 *    - Hash-based verification
 *
 * TAMPER DETECTION METHODS:
 * =========================
 *
 * - Cryptographic hash verification (SHA-256, SHA-512)
 * - Digital signature validation
 * - Timing analysis for single-step detection
 * - Memory permission monitoring
 * - Hook detection (inline, IAT, EAT)
 * - Breakpoint detection
 * - Parent process validation
 * - Environment manipulation detection
 *
 * RESPONSE MECHANISMS:
 * ====================
 *
 * - Alert generation with full context
 * - Automatic repair/recovery
 * - Component restart
 * - Evidence collection
 * - Forensic logging
 * - Security escalation
 * - Quarantine of tampering source
 *
 * @note This module coordinates with kernel-mode driver for enhanced protection.
 * @note Full protection requires elevated privileges.
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
#include <queue>
#include <any>
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
#  include <wintrust.h>
#  include <softpub.h>
#  include <mscat.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/CertUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../HashStore/HashStore.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class TamperProtectionImpl;
    class FileProtection;
    class RegistryProtection;
    class ProcessProtection;
    class MemoryProtection;
    class SelfDefense;
    class AntiDebug;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TamperProtectionConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // MONITORING INTERVALS
    // ========================================================================
    
    /// @brief Default integrity check interval (milliseconds)
    inline constexpr uint32_t DEFAULT_CHECK_INTERVAL_MS = 30000;
    
    /// @brief Minimum check interval (milliseconds)
    inline constexpr uint32_t MIN_CHECK_INTERVAL_MS = 5000;
    
    /// @brief Maximum check interval (milliseconds)
    inline constexpr uint32_t MAX_CHECK_INTERVAL_MS = 300000;
    
    /// @brief Fast check interval during threat response (milliseconds)
    inline constexpr uint32_t THREAT_RESPONSE_INTERVAL_MS = 1000;
    
    /// @brief Hash verification interval (milliseconds)
    inline constexpr uint32_t HASH_VERIFY_INTERVAL_MS = 60000;

    // ========================================================================
    // INTEGRITY LIMITS
    // ========================================================================
    
    /// @brief Maximum monitored files
    inline constexpr size_t MAX_MONITORED_FILES = 500;
    
    /// @brief Maximum monitored registry keys
    inline constexpr size_t MAX_MONITORED_REGISTRY_KEYS = 200;
    
    /// @brief Maximum monitored processes
    inline constexpr size_t MAX_MONITORED_PROCESSES = 50;
    
    /// @brief Maximum monitored memory regions
    inline constexpr size_t MAX_MONITORED_MEMORY_REGIONS = 100;
    
    /// @brief Maximum integrity violations before escalation
    inline constexpr uint32_t MAX_VIOLATIONS_BEFORE_ESCALATION = 5;
    
    /// @brief Maximum repair attempts per component
    inline constexpr uint32_t MAX_REPAIR_ATTEMPTS = 3;

    // ========================================================================
    // HASH SIZES
    // ========================================================================
    
    /// @brief SHA-256 hash size (bytes)
    inline constexpr size_t SHA256_SIZE = 32;
    
    /// @brief SHA-512 hash size (bytes)
    inline constexpr size_t SHA512_SIZE = 64;
    
    /// @brief CRC32 size (bytes)
    inline constexpr size_t CRC32_SIZE = 4;

    // ========================================================================
    // FILE MONITORING
    // ========================================================================
    
    /// @brief Maximum file size to hash (100 MB)
    inline constexpr size_t MAX_FILE_SIZE_FOR_HASH = 100 * 1024 * 1024;
    
    /// @brief File change detection timeout (milliseconds)
    inline constexpr uint32_t FILE_CHANGE_TIMEOUT_MS = 100;

    // ========================================================================
    // RECOVERY
    // ========================================================================
    
    /// @brief Recovery cooldown period (seconds)
    inline constexpr uint32_t RECOVERY_COOLDOWN_SECONDS = 60;
    
    /// @brief Backup retention period (days)
    inline constexpr uint32_t BACKUP_RETENTION_DAYS = 7;

    // ========================================================================
    // ALERTING
    // ========================================================================
    
    /// @brief Maximum alerts per minute (rate limiting)
    inline constexpr uint32_t MAX_ALERTS_PER_MINUTE = 10;
    
    /// @brief Alert aggregation window (seconds)
    inline constexpr uint32_t ALERT_AGGREGATION_WINDOW_SECONDS = 60;

}  // namespace TamperProtectionConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Duration = std::chrono::steady_clock::duration;
using Milliseconds = std::chrono::milliseconds;
using Hash256 = std::array<uint8_t, 32>;
using Hash512 = std::array<uint8_t, 64>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Tamper protection mode
 */
enum class TamperProtectionMode : uint8_t {
    Disabled        = 0,    ///< Protection disabled (testing only)
    Monitor         = 1,    ///< Monitor and alert only (no blocking)
    Protect         = 2,    ///< Monitor, alert, and block
    Enforce         = 3,    ///< Strict enforcement with auto-repair
    Lockdown        = 4     ///< Maximum protection, all changes blocked
};

/**
 * @brief Protected resource type
 */
enum class ProtectedResourceType : uint32_t {
    None            = 0x00000000,
    File            = 0x00000001,   ///< Protected file
    Directory       = 0x00000002,   ///< Protected directory
    RegistryKey     = 0x00000004,   ///< Protected registry key
    RegistryValue   = 0x00000008,   ///< Protected registry value
    Process         = 0x00000010,   ///< Protected process
    Thread          = 0x00000020,   ///< Protected thread
    Service         = 0x00000040,   ///< Protected service
    Driver          = 0x00000080,   ///< Protected driver
    MemoryRegion    = 0x00000100,   ///< Protected memory region
    CodeSection     = 0x00000200,   ///< Protected code section
    Configuration   = 0x00000400,   ///< Protected configuration
    Certificate     = 0x00000800,   ///< Protected certificate
    
    // Groups
    FileSystem      = File | Directory,
    Registry        = RegistryKey | RegistryValue,
    ProcessMemory   = Process | Thread | MemoryRegion | CodeSection,
    SystemServices  = Service | Driver,
    All             = 0xFFFFFFFF
};

inline constexpr ProtectedResourceType operator|(ProtectedResourceType a, 
                                                 ProtectedResourceType b) noexcept {
    return static_cast<ProtectedResourceType>(static_cast<uint32_t>(a) | 
                                              static_cast<uint32_t>(b));
}

inline constexpr ProtectedResourceType operator&(ProtectedResourceType a,
                                                 ProtectedResourceType b) noexcept {
    return static_cast<ProtectedResourceType>(static_cast<uint32_t>(a) & 
                                              static_cast<uint32_t>(b));
}

/**
 * @brief Tamper event type
 */
enum class TamperEventType : uint32_t {
    None                = 0x00000000,
    
    // File events
    FileModified        = 0x00000001,
    FileDeleted         = 0x00000002,
    FileRenamed         = 0x00000004,
    FileAttributeChange = 0x00000008,
    FilePermissionChange= 0x00000010,
    
    // Registry events
    RegistryKeyModified = 0x00000020,
    RegistryKeyDeleted  = 0x00000040,
    RegistryValueModified = 0x00000080,
    RegistryValueDeleted= 0x00000100,
    
    // Process events
    ProcessTerminated   = 0x00000200,
    ProcessSuspended    = 0x00000400,
    ProcessMemoryWrite  = 0x00000800,
    ProcessCodeModified = 0x00001000,
    ProcessHooked       = 0x00002000,
    
    // Memory events
    CodeIntegrityFailure= 0x00004000,
    StackCorruption     = 0x00008000,
    HeapCorruption      = 0x00010000,
    IATModified         = 0x00020000,
    EATModified         = 0x00040000,
    
    // Service events
    ServiceStopped      = 0x00080000,
    ServiceConfigChanged= 0x00100000,
    DriverUnloaded      = 0x00200000,
    
    // Certificate events
    CertificateInvalid  = 0x00400000,
    SignatureInvalid    = 0x00800000,
    
    // Debug events
    DebuggerAttached    = 0x01000000,
    BreakpointDetected  = 0x02000000,
    
    // Groups
    AllFileEvents       = 0x0000001F,
    AllRegistryEvents   = 0x000001E0,
    AllProcessEvents    = 0x00003E00,
    AllMemoryEvents     = 0x0007C000,
    AllServiceEvents    = 0x00380000,
    AllCertEvents       = 0x00C00000,
    AllDebugEvents      = 0x03000000,
    All                 = 0xFFFFFFFF
};

inline constexpr TamperEventType operator|(TamperEventType a, TamperEventType b) noexcept {
    return static_cast<TamperEventType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Integrity verification status
 */
enum class IntegrityStatus : uint8_t {
    Unknown         = 0,    ///< Not yet verified
    Valid           = 1,    ///< Integrity verified
    Modified        = 2,    ///< Resource has been modified
    Missing         = 3,    ///< Resource is missing
    Corrupted       = 4,    ///< Resource is corrupted
    Unauthorized    = 5,    ///< Unauthorized modification
    Repaired        = 6,    ///< Modified but repaired
    PendingVerify   = 7     ///< Verification pending
};

/**
 * @brief Tamper response action
 */
enum class TamperResponse : uint32_t {
    None            = 0x00000000,
    Log             = 0x00000001,   ///< Log the event
    Alert           = 0x00000002,   ///< Generate alert
    Block           = 0x00000004,   ///< Block the tampering action
    Revert          = 0x00000008,   ///< Revert to known-good state
    Repair          = 0x00000010,   ///< Attempt automatic repair
    Quarantine      = 0x00000020,   ///< Quarantine attacking process
    Terminate       = 0x00000040,   ///< Terminate attacking process
    Escalate        = 0x00000080,   ///< Escalate to security team
    Lockdown        = 0x00000100,   ///< Enter lockdown mode
    CollectEvidence = 0x00000200,   ///< Collect forensic evidence
    NotifyUser      = 0x00000400,   ///< Notify end user
    
    // Presets
    Passive         = Log | Alert,
    Standard        = Log | Alert | Block,
    Aggressive      = Log | Alert | Block | Revert | Terminate,
    Maximum         = 0xFFFFFFFF
};

inline constexpr TamperResponse operator|(TamperResponse a, TamperResponse b) noexcept {
    return static_cast<TamperResponse>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Tamper protection subsystem
 */
enum class TamperSubsystem : uint8_t {
    FileProtection      = 0,
    RegistryProtection  = 1,
    ProcessProtection   = 2,
    MemoryProtection    = 3,
    ServiceProtection   = 4,
    CodeIntegrity       = 5,
    CertificateIntegrity= 6,
    AntiDebug           = 7,
    SelfDefense         = 8
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,    ///< Running with reduced functionality
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

/**
 * @brief Verification method
 */
enum class VerificationMethod : uint8_t {
    None            = 0,
    CRC32           = 1,    ///< Fast CRC32 check
    SHA256          = 2,    ///< SHA-256 hash
    SHA512          = 3,    ///< SHA-512 hash
    DigitalSignature= 4,    ///< Authenticode signature
    Catalog         = 5,    ///< Windows catalog verification
    Combined        = 6     ///< Multiple methods
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Tamper protection configuration
 */
struct TamperProtectionConfiguration {
    /// @brief Protection mode
    TamperProtectionMode mode = TamperProtectionMode::Protect;
    
    /// @brief Enabled resource types
    ProtectedResourceType enabledResources = ProtectedResourceType::All;
    
    /// @brief Monitored event types
    TamperEventType monitoredEvents = TamperEventType::All;
    
    /// @brief Default response action
    TamperResponse defaultResponse = TamperResponse::Standard;
    
    /// @brief Integrity check interval (milliseconds)
    uint32_t checkIntervalMs = TamperProtectionConstants::DEFAULT_CHECK_INTERVAL_MS;
    
    /// @brief Enable real-time monitoring
    bool enableRealTimeMonitoring = true;
    
    /// @brief Enable periodic integrity checks
    bool enablePeriodicChecks = true;
    
    /// @brief Enable automatic repair
    bool enableAutoRepair = true;
    
    /// @brief Enable backup before repair
    bool createBackupBeforeRepair = true;
    
    /// @brief Maximum repair attempts
    uint32_t maxRepairAttempts = TamperProtectionConstants::MAX_REPAIR_ATTEMPTS;
    
    /// @brief Enable digital signature verification
    bool verifyDigitalSignatures = true;
    
    /// @brief Enable code integrity verification
    bool enableCodeIntegrity = true;
    
    /// @brief Enable certificate chain verification
    bool verifyCertificateChain = true;
    
    /// @brief Enable anti-debug integration
    bool enableAntiDebugIntegration = true;
    
    /// @brief Enable self-defense integration
    bool enableSelfDefenseIntegration = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /// @brief Send telemetry
    bool sendTelemetry = true;
    
    /// @brief Custom protected files
    std::vector<std::wstring> additionalProtectedFiles;
    
    /// @brief Custom protected registry keys
    std::vector<std::wstring> additionalProtectedKeys;
    
    /// @brief Whitelisted modification sources
    std::vector<std::wstring> whitelistedSources;
    
    /**
     * @brief Create configuration from mode
     */
    static TamperProtectionConfiguration FromMode(TamperProtectionMode mode);
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Protected resource baseline
 */
struct ResourceBaseline {
    /// @brief Resource identifier
    std::string resourceId;
    
    /// @brief Resource type
    ProtectedResourceType type = ProtectedResourceType::None;
    
    /// @brief Resource path (file, registry, etc.)
    std::wstring path;
    
    /// @brief SHA-256 hash of content
    Hash256 contentHash{};
    
    /// @brief SHA-512 hash (for critical files)
    Hash512 strongHash{};
    
    /// @brief Fast CRC32 for quick checks
    uint32_t crc32 = 0;
    
    /// @brief File size (for files)
    uint64_t fileSize = 0;
    
    /// @brief Last modification time
    std::chrono::system_clock::time_point lastModified;
    
    /// @brief File attributes (for files)
    uint32_t attributes = 0;
    
    /// @brief Digital signature status
    bool hasValidSignature = false;
    
    /// @brief Signer name
    std::wstring signerName;
    
    /// @brief Certificate thumbprint
    std::string certificateThumbprint;
    
    /// @brief Baseline creation time
    TimePoint baselineCreated = Clock::now();
    
    /// @brief Last verification time
    TimePoint lastVerified;
    
    /// @brief Verification method used
    VerificationMethod verificationMethod = VerificationMethod::SHA256;
    
    /// @brief Current integrity status
    IntegrityStatus status = IntegrityStatus::Unknown;
    
    /// @brief Violation count since baseline
    uint32_t violationCount = 0;
    
    /// @brief Is this resource critical
    bool isCritical = false;
    
    /// @brief Allow modifications (for non-critical files)
    bool allowModifications = false;
};

/**
 * @brief Tamper event details
 */
struct TamperEvent {
    /// @brief Event identifier
    uint64_t eventId = 0;
    
    /// @brief Event type
    TamperEventType type = TamperEventType::None;
    
    /// @brief Event timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Affected resource type
    ProtectedResourceType resourceType = ProtectedResourceType::None;
    
    /// @brief Resource identifier
    std::string resourceId;
    
    /// @brief Resource path
    std::wstring resourcePath;
    
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Source process path
    std::wstring sourceProcessPath;
    
    /// @brief Source thread ID
    uint32_t sourceThreadId = 0;
    
    /// @brief Source user SID
    std::wstring sourceUserSid;
    
    /// @brief Expected hash
    Hash256 expectedHash{};
    
    /// @brief Actual hash (after modification)
    Hash256 actualHash{};
    
    /// @brief Change description
    std::string changeDescription;
    
    /// @brief Response taken
    TamperResponse responseTaken = TamperResponse::None;
    
    /// @brief Was the tampering blocked
    bool wasBlocked = false;
    
    /// @brief Was the resource repaired
    bool wasRepaired = false;
    
    /// @brief Severity level (1-10)
    uint8_t severityLevel = 5;
    
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
 * @brief Integrity verification result
 */
struct VerificationResult {
    /// @brief Resource identifier
    std::string resourceId;
    
    /// @brief Verification status
    IntegrityStatus status = IntegrityStatus::Unknown;
    
    /// @brief Verification method used
    VerificationMethod method = VerificationMethod::None;
    
    /// @brief Verification timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Verification duration
    Milliseconds duration{0};
    
    /// @brief Expected hash
    Hash256 expectedHash{};
    
    /// @brief Computed hash
    Hash256 computedHash{};
    
    /// @brief Hash match
    bool hashMatch = false;
    
    /// @brief Signature valid
    bool signatureValid = false;
    
    /// @brief Signature details
    std::wstring signatureDetails;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Detected changes
    std::vector<std::string> detectedChanges;
};

/**
 * @brief Repair operation result
 */
struct RepairResult {
    /// @brief Resource identifier
    std::string resourceId;
    
    /// @brief Was repair successful
    bool success = false;
    
    /// @brief Repair method used
    std::string repairMethod;
    
    /// @brief Repair timestamp
    TimePoint timestamp = Clock::now();
    
    /// @brief Backup created
    bool backupCreated = false;
    
    /// @brief Backup path
    std::wstring backupPath;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Repair details
    std::string details;
};

/**
 * @brief Subsystem status
 */
struct SubsystemStatus {
    /// @brief Subsystem type
    TamperSubsystem subsystem;
    
    /// @brief Is subsystem active
    bool isActive = false;
    
    /// @brief Current status
    ModuleStatus status = ModuleStatus::Uninitialized;
    
    /// @brief Last check time
    TimePoint lastCheck;
    
    /// @brief Monitored resource count
    size_t monitoredResources = 0;
    
    /// @brief Violations detected
    uint64_t violationsDetected = 0;
    
    /// @brief Violations blocked
    uint64_t violationsBlocked = 0;
    
    /// @brief Repairs performed
    uint64_t repairsPerformed = 0;
    
    /// @brief Error message (if any)
    std::string errorMessage;
};

/**
 * @brief Tamper protection statistics
 */
struct TamperProtectionStatistics {
    /// @brief Total resources monitored
    std::atomic<uint64_t> totalResourcesMonitored{0};
    
    /// @brief Total integrity checks performed
    std::atomic<uint64_t> totalIntegrityChecks{0};
    
    /// @brief Total tampering events detected
    std::atomic<uint64_t> totalTamperingDetected{0};
    
    /// @brief Total tampering blocked
    std::atomic<uint64_t> totalTamperingBlocked{0};
    
    /// @brief Total repairs performed
    std::atomic<uint64_t> totalRepairsPerformed{0};
    
    /// @brief Successful repairs
    std::atomic<uint64_t> successfulRepairs{0};
    
    /// @brief Events by type
    std::unordered_map<TamperEventType, uint64_t> eventsByType;
    
    /// @brief Events by resource type
    std::unordered_map<ProtectedResourceType, uint64_t> eventsByResource;
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last event time
    TimePoint lastEventTime;
    
    /// @brief Last check time
    TimePoint lastCheckTime;
    
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

/// @brief Callback for tamper events
using TamperEventCallback = std::function<void(const TamperEvent&)>;

/// @brief Callback for verification results
using VerificationCallback = std::function<void(const VerificationResult&)>;

/// @brief Callback for repair results
using RepairCallback = std::function<void(const RepairResult&)>;

/// @brief Callback for subsystem status changes
using SubsystemStatusCallback = std::function<void(TamperSubsystem, ModuleStatus)>;

/// @brief Custom response handler (can override default response)
using ResponseHandler = std::function<TamperResponse(const TamperEvent&)>;

// ============================================================================
// TAMPER PROTECTION ENGINE CLASS
// ============================================================================

/**
 * @class TamperProtection
 * @brief Enterprise-grade tamper protection orchestrator
 *
 * Central coordinator for all tamper protection subsystems in ShadowStrike.
 * Manages file, registry, process, memory, and code integrity protection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& tamperProtection = TamperProtection::Instance();
 *     
 *     TamperProtectionConfiguration config;
 *     config.mode = TamperProtectionMode::Enforce;
 *     config.enableAutoRepair = true;
 *     
 *     if (!tamperProtection.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize tamper protection");
 *     }
 *     
 *     // Register for tamper events
 *     tamperProtection.RegisterEventCallback([](const TamperEvent& event) {
 *         LOG_WARNING("Tampering detected: {}", event.GetSummary());
 *     });
 *     
 *     // Add file to protection
 *     tamperProtection.ProtectFile(L"C:\\Program Files\\ShadowStrike\\engine.dll");
 *     
 *     // Verify integrity
 *     auto result = tamperProtection.VerifyAllIntegrity();
 * @endcode
 */
class TamperProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static TamperProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    TamperProtection(const TamperProtection&) = delete;
    TamperProtection& operator=(const TamperProtection&) = delete;
    TamperProtection(TamperProtection&&) = delete;
    TamperProtection& operator=(TamperProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize tamper protection
     * @param config Configuration
     * @return true if successful
     */
    [[nodiscard]] bool Initialize(const TamperProtectionConfiguration& config = {});
    
    /**
     * @brief Initialize with mode preset
     * @param mode Protection mode
     * @return true if successful
     */
    [[nodiscard]] bool Initialize(TamperProtectionMode mode);
    
    /**
     * @brief Shutdown tamper protection
     * @param authorizationToken Security token
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
    
    /**
     * @brief Set protection enabled/disabled
     * @param enabled Enable state
     */
    void SetEnabled(bool enabled);
    
    /**
     * @brief Check if protection is enabled
     */
    [[nodiscard]] bool IsEnabled() const noexcept;
    
    /**
     * @brief Pause protection temporarily
     * @param authorizationToken Security token
     * @param durationMs Duration (0 = until resumed)
     */
    [[nodiscard]] bool Pause(std::string_view authorizationToken, uint32_t durationMs = 0);
    
    /**
     * @brief Resume protection
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const TamperProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] TamperProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection mode
     */
    void SetMode(TamperProtectionMode mode);
    
    /**
     * @brief Get current mode
     */
    [[nodiscard]] TamperProtectionMode GetMode() const noexcept;
    
    /**
     * @brief Set default response action
     */
    void SetDefaultResponse(TamperResponse response);
    
    /**
     * @brief Get default response action
     */
    [[nodiscard]] TamperResponse GetDefaultResponse() const noexcept;
    
    /**
     * @brief Set response for specific event type
     */
    void SetEventResponse(TamperEventType eventType, TamperResponse response);
    
    /**
     * @brief Get response for event type
     */
    [[nodiscard]] TamperResponse GetEventResponse(TamperEventType eventType) const;
    
    /**
     * @brief Set check interval
     */
    void SetCheckInterval(uint32_t intervalMs);
    
    /**
     * @brief Get check interval
     */
    [[nodiscard]] uint32_t GetCheckInterval() const noexcept;
    
    // ========================================================================
    // FILE PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect a file
     * @param filePath Full path to file
     * @param isCritical Is this a critical file
     * @return true if protected
     */
    [[nodiscard]] bool ProtectFile(std::wstring_view filePath, bool isCritical = false);
    
    /**
     * @brief Unprotect a file
     * @param filePath File path
     * @param authorizationToken Security token
     */
    [[nodiscard]] bool UnprotectFile(std::wstring_view filePath, 
                                     std::string_view authorizationToken);
    
    /**
     * @brief Check if file is protected
     */
    [[nodiscard]] bool IsFileProtected(std::wstring_view filePath) const;
    
    /**
     * @brief Verify file integrity
     */
    [[nodiscard]] VerificationResult VerifyFile(std::wstring_view filePath);
    
    /**
     * @brief Get file baseline
     */
    [[nodiscard]] std::optional<ResourceBaseline> GetFileBaseline(std::wstring_view filePath) const;
    
    /**
     * @brief Update file baseline (after authorized change)
     */
    [[nodiscard]] bool UpdateFileBaseline(std::wstring_view filePath, 
                                          std::string_view authorizationToken);
    
    /**
     * @brief Protect directory
     */
    [[nodiscard]] bool ProtectDirectory(std::wstring_view directoryPath, 
                                        bool recursive = true);
    
    /**
     * @brief Protect ShadowStrike installation
     */
    [[nodiscard]] bool ProtectInstallation();
    
    /**
     * @brief Get all protected files
     */
    [[nodiscard]] std::vector<ResourceBaseline> GetAllProtectedFiles() const;
    
    // ========================================================================
    // REGISTRY PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect registry key
     */
    [[nodiscard]] bool ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys = true);
    
    /**
     * @brief Unprotect registry key
     */
    [[nodiscard]] bool UnprotectRegistryKey(std::wstring_view keyPath,
                                            std::string_view authorizationToken);
    
    /**
     * @brief Check if registry key is protected
     */
    [[nodiscard]] bool IsRegistryKeyProtected(std::wstring_view keyPath) const;
    
    /**
     * @brief Verify registry key integrity
     */
    [[nodiscard]] VerificationResult VerifyRegistryKey(std::wstring_view keyPath);
    
    /**
     * @brief Protect registry value
     */
    [[nodiscard]] bool ProtectRegistryValue(std::wstring_view keyPath, 
                                            std::wstring_view valueName);
    
    /**
     * @brief Protect ShadowStrike service registry
     */
    [[nodiscard]] bool ProtectServiceRegistry();
    
    /**
     * @brief Get all protected registry keys
     */
    [[nodiscard]] std::vector<ResourceBaseline> GetAllProtectedRegistryKeys() const;
    
    // ========================================================================
    // PROCESS/MEMORY PROTECTION
    // ========================================================================
    
    /**
     * @brief Protect process
     */
    [[nodiscard]] bool ProtectProcess(uint32_t processId);
    
    /**
     * @brief Verify process integrity
     */
    [[nodiscard]] VerificationResult VerifyProcess(uint32_t processId);
    
    /**
     * @brief Protect memory region
     */
    [[nodiscard]] bool ProtectMemoryRegion(uint32_t processId, uintptr_t address, size_t size);
    
    /**
     * @brief Verify memory integrity
     */
    [[nodiscard]] VerificationResult VerifyMemoryRegion(uint32_t processId, 
                                                        uintptr_t address, size_t size);
    
    /**
     * @brief Protect current process
     */
    [[nodiscard]] bool ProtectSelf();
    
    // ========================================================================
    // CODE INTEGRITY
    // ========================================================================
    
    /**
     * @brief Verify digital signature of file
     */
    [[nodiscard]] VerificationResult VerifyDigitalSignature(std::wstring_view filePath);
    
    /**
     * @brief Verify Authenticode signature
     */
    [[nodiscard]] VerificationResult VerifyAuthenticode(std::wstring_view filePath);
    
    /**
     * @brief Verify catalog signature
     */
    [[nodiscard]] VerificationResult VerifyCatalogSignature(std::wstring_view filePath);
    
    /**
     * @brief Compute file hash
     */
    [[nodiscard]] Hash256 ComputeFileHash(std::wstring_view filePath, 
                                          VerificationMethod method = VerificationMethod::SHA256);
    
    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verify all protected resources
     */
    [[nodiscard]] std::vector<VerificationResult> VerifyAllIntegrity();
    
    /**
     * @brief Verify specific resource type
     */
    [[nodiscard]] std::vector<VerificationResult> VerifyIntegrity(ProtectedResourceType type);
    
    /**
     * @brief Get resources with integrity issues
     */
    [[nodiscard]] std::vector<ResourceBaseline> GetCompromisedResources() const;
    
    /**
     * @brief Force immediate integrity check
     */
    void ForceIntegrityCheck();
    
    // ========================================================================
    // REPAIR OPERATIONS
    // ========================================================================
    
    /**
     * @brief Repair compromised resource
     */
    [[nodiscard]] RepairResult RepairResource(std::string_view resourceId);
    
    /**
     * @brief Repair all compromised resources
     */
    [[nodiscard]] std::vector<RepairResult> RepairAllCompromised();
    
    /**
     * @brief Restore resource from backup
     */
    [[nodiscard]] RepairResult RestoreFromBackup(std::string_view resourceId);
    
    /**
     * @brief Create backup of resource
     */
    [[nodiscard]] bool CreateBackup(std::string_view resourceId);
    
    /**
     * @brief Get available backups for resource
     */
    [[nodiscard]] std::vector<std::wstring> GetAvailableBackups(std::string_view resourceId) const;
    
    // ========================================================================
    // SUBSYSTEM MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Get subsystem status
     */
    [[nodiscard]] SubsystemStatus GetSubsystemStatus(TamperSubsystem subsystem) const;
    
    /**
     * @brief Get all subsystem statuses
     */
    [[nodiscard]] std::vector<SubsystemStatus> GetAllSubsystemStatuses() const;
    
    /**
     * @brief Enable subsystem
     */
    [[nodiscard]] bool EnableSubsystem(TamperSubsystem subsystem);
    
    /**
     * @brief Disable subsystem
     */
    [[nodiscard]] bool DisableSubsystem(TamperSubsystem subsystem, 
                                        std::string_view authorizationToken);
    
    /**
     * @brief Check if subsystem is enabled
     */
    [[nodiscard]] bool IsSubsystemEnabled(TamperSubsystem subsystem) const;
    
    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add source to whitelist
     */
    [[nodiscard]] bool AddToWhitelist(std::wstring_view source, 
                                      std::string_view authorizationToken);
    
    /**
     * @brief Remove source from whitelist
     */
    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view source,
                                           std::string_view authorizationToken);
    
    /**
     * @brief Check if source is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::wstring_view source) const;
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    
    // ========================================================================
    // CALLBACKS AND EVENTS
    // ========================================================================
    
    /**
     * @brief Register tamper event callback
     */
    [[nodiscard]] uint64_t RegisterEventCallback(TamperEventCallback callback);
    
    /**
     * @brief Unregister event callback
     */
    void UnregisterEventCallback(uint64_t callbackId);
    
    /**
     * @brief Register verification callback
     */
    [[nodiscard]] uint64_t RegisterVerificationCallback(VerificationCallback callback);
    
    /**
     * @brief Unregister verification callback
     */
    void UnregisterVerificationCallback(uint64_t callbackId);
    
    /**
     * @brief Register repair callback
     */
    [[nodiscard]] uint64_t RegisterRepairCallback(RepairCallback callback);
    
    /**
     * @brief Unregister repair callback
     */
    void UnregisterRepairCallback(uint64_t callbackId);
    
    /**
     * @brief Register subsystem status callback
     */
    [[nodiscard]] uint64_t RegisterStatusCallback(SubsystemStatusCallback callback);
    
    /**
     * @brief Unregister status callback
     */
    void UnregisterStatusCallback(uint64_t callbackId);
    
    /**
     * @brief Set custom response handler
     */
    void SetResponseHandler(ResponseHandler handler);
    
    /**
     * @brief Clear custom response handler
     */
    void ClearResponseHandler();
    
    // ========================================================================
    // STATISTICS AND REPORTING
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] TamperProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics(std::string_view authorizationToken);
    
    /**
     * @brief Get event history
     */
    [[nodiscard]] std::vector<TamperEvent> GetEventHistory(size_t maxEntries = 100) const;
    
    /**
     * @brief Clear event history
     */
    void ClearEventHistory(std::string_view authorizationToken);
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    /**
     * @brief Export report to file
     */
    [[nodiscard]] bool ExportReportToFile(std::wstring_view filePath) const;
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /**
     * @brief Self-test all protection mechanisms
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Verify authorization token
     */
    [[nodiscard]] bool VerifyAuthorizationToken(std::string_view token) const;
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;
    
    /**
     * @brief Force garbage collection
     */
    void ForceGarbageCollection();

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    TamperProtection();
    ~TamperProtection();
    
    // ========================================================================
    // PRIVATE MEMBERS
    // ========================================================================
    
    std::unique_ptr<TamperProtectionImpl> m_impl;
    std::atomic<bool> m_enabled{true};
    
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
[[nodiscard]] std::string_view GetModeName(TamperProtectionMode mode) noexcept;

/**
 * @brief Get resource type name
 */
[[nodiscard]] std::string_view GetResourceTypeName(ProtectedResourceType type) noexcept;

/**
 * @brief Get event type name
 */
[[nodiscard]] std::string_view GetEventTypeName(TamperEventType type) noexcept;

/**
 * @brief Get integrity status name
 */
[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept;

/**
 * @brief Get response name
 */
[[nodiscard]] std::string_view GetResponseName(TamperResponse response) noexcept;

/**
 * @brief Get subsystem name
 */
[[nodiscard]] std::string_view GetSubsystemName(TamperSubsystem subsystem) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class ScopedProtectionPause
 * @brief RAII wrapper to temporarily pause protection
 */
class ScopedProtectionPause final {
public:
    explicit ScopedProtectionPause(std::string_view authToken, uint32_t durationMs = 0);
    ~ScopedProtectionPause();
    
    ScopedProtectionPause(const ScopedProtectionPause&) = delete;
    ScopedProtectionPause& operator=(const ScopedProtectionPause&) = delete;
    
    [[nodiscard]] bool IsPaused() const noexcept { return m_paused; }

private:
    bool m_paused = false;
};

/**
 * @class ResourceProtectionGuard
 * @brief RAII wrapper to protect a resource for the scope
 */
class ResourceProtectionGuard final {
public:
    ResourceProtectionGuard(std::wstring_view path, ProtectedResourceType type);
    ~ResourceProtectionGuard();
    
    ResourceProtectionGuard(const ResourceProtectionGuard&) = delete;
    ResourceProtectionGuard& operator=(const ResourceProtectionGuard&) = delete;
    
    [[nodiscard]] bool IsProtected() const noexcept { return m_protected; }

private:
    std::wstring m_path;
    ProtectedResourceType m_type;
    bool m_protected = false;
    std::string m_authToken;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Check if tamper protection is active
 */
#define SS_IS_TAMPER_PROTECTED() \
    ::ShadowStrike::Security::TamperProtection::Instance().IsEnabled()

/**
 * @brief Protect current installation
 */
#define SS_PROTECT_INSTALLATION() \
    ::ShadowStrike::Security::TamperProtection::Instance().ProtectInstallation()

/**
 * @brief Force integrity check
 */
#define SS_CHECK_INTEGRITY() \
    ::ShadowStrike::Security::TamperProtection::Instance().ForceIntegrityCheck()
