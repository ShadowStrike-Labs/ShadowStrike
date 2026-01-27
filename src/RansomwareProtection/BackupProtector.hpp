/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - BACKUP PROTECTOR
 * ============================================================================
 *
 * @file BackupProtector.hpp
 * @brief Enterprise-grade protection for Volume Shadow Copies and backup files
 *        preventing ransomware from destroying recovery options.
 *
 * Ransomware almost always attempts to delete backups before encryption:
 * - vssadmin.exe Delete Shadows /All /Quiet
 * - wbadmin.exe DELETE SYSTEMSTATEBACKUP
 * - bcdedit.exe /set {default} recoveryenabled No
 * - wmic shadowcopy delete
 * - PowerShell Get-WmiObject ... Remove-WmiObject
 *
 * This module intercepts and blocks these destructive operations.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. COMMAND LINE INTERCEPTION
 *    - vssadmin.exe monitoring
 *    - wbadmin.exe monitoring
 *    - bcdedit.exe monitoring
 *    - wmic.exe monitoring
 *    - PowerShell command detection
 *    - cmd.exe script detection
 *
 * 2. VSS SERVICE PROTECTION
 *    - Service stop prevention
 *    - Registry protection
 *    - COM interface monitoring
 *    - Scheduled task protection
 *
 * 3. FILE TYPE PROTECTION
 *    - .bkf backup files
 *    - .vhd/.vhdx virtual disks
 *    - .tib/.tibx Acronis images
 *    - .rbk R-Drive images
 *    - System restore points
 *
 * 4. REGISTRY PROTECTION
 *    - VSS service registry keys
 *    - Boot configuration data
 *    - Recovery options
 *    - Backup schedules
 *
 * 5. API HOOKING
 *    - VSS API calls
 *    - WMI calls
 *    - Service control calls
 *    - Process creation
 *
 * 6. ALERTING
 *    - Real-time notifications
 *    - Forensic logging
 *    - Process termination
 *    - Incident creation
 *
 * INTEGRATION:
 * ============
 * - Core::Process::ProcessMonitor for command line interception
 * - Core::Registry::RegistryMonitor for registry protection
 * - Security::ProcessProtection for process termination
 *
 * @note Some legitimate backup tools use the same commands - whitelist them.
 * @note Requires administrative privileges for full protection.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001
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
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
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
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class BackupProtectorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BackupProtectorConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // DANGEROUS TOOLS
    // ========================================================================
    
    /// @brief Tools that can destroy backups
    inline constexpr const wchar_t* DANGEROUS_TOOLS[] = {
        L"vssadmin.exe",
        L"wbadmin.exe",
        L"bcdedit.exe",
        L"wmic.exe",
        L"diskshadow.exe",
        L"vssvc.exe"
    };

    // ========================================================================
    // PROTECTED EXTENSIONS
    // ========================================================================
    
    /// @brief Backup file extensions to protect
    inline constexpr const wchar_t* PROTECTED_EXTENSIONS[] = {
        L".bak", L".bkf", L".backup",
        L".vhd", L".vhdx", L".vmdk",
        L".tib", L".tibx",
        L".rbk", L".rdb",
        L".qic", L".win",
        L".gho", L".v2i"
    };

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum whitelisted processes
    inline constexpr size_t MAX_WHITELIST_SIZE = 100;
    
    /// @brief Maximum blocked attempts to log
    inline constexpr size_t MAX_BLOCKED_LOG = 1000;

}  // namespace BackupProtectorConstants

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
 * @brief Threat type
 */
enum class BackupThreatType : uint8_t {
    Unknown             = 0,
    VSSDelete           = 1,    ///< Shadow copy deletion
    VSSResize           = 2,    ///< Shadow storage resize
    VSSDisable          = 3,    ///< VSS service disable
    BackupDelete        = 4,    ///< Backup file deletion
    RecoveryDisable     = 5,    ///< Recovery options disable
    BootConfigChange    = 6,    ///< BCD modification
    WMIShadowDelete     = 7,    ///< WMI shadow deletion
    ServiceStop         = 8,    ///< Service stop attempt
    ScheduleDelete      = 9     ///< Backup schedule deletion
};

/**
 * @brief Protection action
 */
enum class ProtectionAction : uint8_t {
    Allow       = 0,    ///< Allow operation
    Block       = 1,    ///< Block operation
    BlockKill   = 2,    ///< Block and terminate process
    Warn        = 3,    ///< Allow with warning
    Quarantine  = 4     ///< Quarantine process
};

/**
 * @brief Tool type
 */
enum class DangerousToolType : uint8_t {
    Unknown     = 0,
    VSSAdmin    = 1,
    WBAdmin     = 2,
    BCDEdit     = 3,
    WMIC        = 4,
    PowerShell  = 5,
    CMD         = 6,
    DiskShadow  = 7
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
 * @brief Blocked attempt record
 */
struct BlockedAttempt {
    /// @brief Attempt ID
    uint64_t attemptId = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Parent PID
    uint32_t parentPid = 0;
    
    /// @brief Parent name
    std::wstring parentName;
    
    /// @brief Threat type
    BackupThreatType threatType = BackupThreatType::Unknown;
    
    /// @brief Tool type
    DangerousToolType toolType = DangerousToolType::Unknown;
    
    /// @brief Action taken
    ProtectionAction action = ProtectionAction::Block;
    
    /// @brief Target (file/service/registry key)
    std::wstring target;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief Details
    std::wstring details;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Command pattern for detection
 */
struct CommandPattern {
    /// @brief Pattern name
    std::string patternName;
    
    /// @brief Tool type
    DangerousToolType toolType = DangerousToolType::Unknown;
    
    /// @brief Threat type
    BackupThreatType threatType = BackupThreatType::Unknown;
    
    /// @brief Regex pattern for command line
    std::wstring regexPattern;
    
    /// @brief Keywords to match
    std::vector<std::wstring> keywords;
    
    /// @brief Description
    std::string description;
    
    /// @brief Recommended action
    ProtectionAction recommendedAction = ProtectionAction::Block;
    
    /// @brief Is case sensitive
    bool caseSensitive = false;
    
    /**
     * @brief Check if command matches pattern
     */
    [[nodiscard]] bool Matches(std::wstring_view commandLine) const;
};

/**
 * @brief Protected service
 */
struct ProtectedService {
    /// @brief Service name
    std::wstring serviceName;
    
    /// @brief Display name
    std::wstring displayName;
    
    /// @brief Protect from stop
    bool protectStop = true;
    
    /// @brief Protect from disable
    bool protectDisable = true;
    
    /// @brief Protect from config change
    bool protectConfig = true;
    
    /// @brief Protect from delete
    bool protectDelete = true;
};

/**
 * @brief Protected registry key
 */
struct ProtectedRegistryKey {
    /// @brief Registry path
    std::wstring path;
    
    /// @brief Value name (empty = all values)
    std::wstring valueName;
    
    /// @brief Protect from modification
    bool protectModify = true;
    
    /// @brief Protect from deletion
    bool protectDelete = true;
    
    /// @brief Description
    std::string description;
};

/**
 * @brief Backup protector configuration
 */
struct BackupProtectorConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    /// @brief Protect VSS
    bool protectVSS = true;
    
    /// @brief Protect backup files
    bool protectBackupFiles = true;
    
    /// @brief Protect BCD
    bool protectBCD = true;
    
    /// @brief Protect services
    bool protectServices = true;
    
    /// @brief Protect registry
    bool protectRegistry = true;
    
    /// @brief Kill process on detection
    bool killOnDetection = true;
    
    /// @brief Whitelisted processes (can perform backup operations)
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Whitelisted signers
    std::vector<std::wstring> whitelistedSigners;
    
    /// @brief Command patterns
    std::vector<CommandPattern> commandPatterns;
    
    /// @brief Protected services
    std::vector<ProtectedService> protectedServices;
    
    /// @brief Protected registry keys
    std::vector<ProtectedRegistryKey> protectedRegistryKeys;
    
    /// @brief Protected extensions
    std::vector<std::wstring> protectedExtensions;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Load default patterns
     */
    void LoadDefaultPatterns();
    
    /**
     * @brief Load default services
     */
    void LoadDefaultServices();
};

/**
 * @brief Protection statistics
 */
struct BackupProtectorStatistics {
    /// @brief Attempts blocked
    std::atomic<uint64_t> attemptsBlocked{0};
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{0};
    
    /// @brief VSS deletions blocked
    std::atomic<uint64_t> vssDeletesBlocked{0};
    
    /// @brief File deletions blocked
    std::atomic<uint64_t> fileDeletesBlocked{0};
    
    /// @brief Service stops blocked
    std::atomic<uint64_t> serviceStopsBlocked{0};
    
    /// @brief Registry changes blocked
    std::atomic<uint64_t> registryChangesBlocked{0};
    
    /// @brief Whitelisted operations allowed
    std::atomic<uint64_t> whitelistedAllowed{0};
    
    /// @brief By threat type
    std::array<std::atomic<uint64_t>, 16> byThreatType{};
    
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

/// @brief Block callback
using BlockCallback = std::function<void(const BlockedAttempt&)>;

/// @brief Decision callback (can override action)
using DecisionCallback = std::function<ProtectionAction(
    uint32_t pid, const std::wstring& commandLine, BackupThreatType threatType)>;

// ============================================================================
// BACKUP PROTECTOR CLASS
// ============================================================================

/**
 * @class BackupProtector
 * @brief Enterprise-grade backup and recovery protection
 *
 * Protects system backups and recovery options from ransomware destruction.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& protector = BackupProtector::Instance();
 *     protector.Initialize();
 *     
 *     // Check process creation
 *     if (protector.IsDestructiveTool(imagePath, cmdLine)) {
 *         // Block!
 *     }
 * @endcode
 */
class BackupProtector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static BackupProtector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    BackupProtector(const BackupProtector&) = delete;
    BackupProtector& operator=(const BackupProtector&) = delete;
    BackupProtector(BackupProtector&&) = delete;
    BackupProtector& operator=(BackupProtector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const BackupProtectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DETECTION
    // ========================================================================
    
    /**
     * @brief Analyze if process is a backup destruction tool
     */
    [[nodiscard]] bool IsDestructiveTool(const std::wstring& imagePath,
                                         const std::wstring& commandLine);
    
    /**
     * @brief Analyze with detailed result
     */
    [[nodiscard]] std::optional<BlockedAttempt> AnalyzeProcess(
        uint32_t pid, std::wstring_view imagePath, std::wstring_view commandLine);
    
    /**
     * @brief Check if command line is destructive
     */
    [[nodiscard]] bool IsDestructiveCommand(std::wstring_view commandLine);
    
    /**
     * @brief Check if file is a protected backup file
     */
    [[nodiscard]] bool IsProtectedBackupFile(const std::wstring& filePath);
    
    /**
     * @brief Check if file access should be blocked
     */
    [[nodiscard]] bool ShouldBlockFileAccess(std::wstring_view filePath,
                                             uint32_t pid, uint32_t desiredAccess);
    
    // ========================================================================
    // SERVICE PROTECTION
    // ========================================================================
    
    /**
     * @brief Lock VSS service
     */
    void LockVSSService();
    
    /**
     * @brief Unlock VSS service
     */
    void UnlockVSSService();
    
    /**
     * @brief Check if service operation should be blocked
     */
    [[nodiscard]] bool ShouldBlockServiceOperation(std::wstring_view serviceName,
                                                   uint32_t operation, uint32_t pid);
    
    // ========================================================================
    // REGISTRY PROTECTION
    // ========================================================================
    
    /**
     * @brief Check if registry operation should be blocked
     */
    [[nodiscard]] bool ShouldBlockRegistryOperation(std::wstring_view keyPath,
                                                    std::wstring_view valueName,
                                                    uint32_t operation, uint32_t pid);
    
    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /**
     * @brief Add to whitelist
     */
    void AddToWhitelist(std::wstring_view processPath);
    
    /**
     * @brief Remove from whitelist
     */
    void RemoveFromWhitelist(std::wstring_view processPath);
    
    /**
     * @brief Check if whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processPath) const;
    
    /**
     * @brief Whitelist signer
     */
    void WhitelistSigner(std::wstring_view signerName);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetBlockCallback(BlockCallback callback);
    void SetDecisionCallback(DecisionCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] BackupProtectorStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<BlockedAttempt> GetRecentBlocks(size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    BackupProtector();
    ~BackupProtector();
    
    std::unique_ptr<BackupProtectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetThreatTypeName(BackupThreatType type) noexcept;
[[nodiscard]] std::string_view GetProtectionActionName(ProtectionAction action) noexcept;
[[nodiscard]] std::string_view GetToolTypeName(DangerousToolType type) noexcept;
[[nodiscard]] DangerousToolType IdentifyTool(std::wstring_view processName) noexcept;
[[nodiscard]] BackupThreatType IdentifyThreat(std::wstring_view commandLine) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IS_DESTRUCTIVE_TOOL(path, cmd) \
    ::ShadowStrike::Ransomware::BackupProtector::Instance().IsDestructiveTool((path), (cmd))

#define SS_IS_PROTECTED_BACKUP(path) \
    ::ShadowStrike::Ransomware::BackupProtector::Instance().IsProtectedBackupFile(path)
