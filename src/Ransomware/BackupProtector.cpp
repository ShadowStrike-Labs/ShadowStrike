/**
 * ============================================================================
 * ShadowStrike NGAV - BACKUP PROTECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file BackupProtector.cpp
 * @brief Enterprise-grade ransomware backup protection
 *
 * Implements comprehensive protection against ransomware destruction of:
 * - Volume Shadow Copies (VSS)
 * - Windows Backup files
 * - Boot Configuration Data (BCD)
 * - Backup services and scheduled tasks
 * - Protected backup file extensions
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - std::shared_mutex for concurrent read access
 * - RAII throughout for exception safety
 *
 * PERFORMANCE:
 * ============
 * - Lock-free statistics updates
 * - Compiled regex caching for command patterns
 * - Efficient whitelist lookups with hash sets
 * - LRU eviction for blocked attempt history
 *
 * PROTECTION COVERAGE:
 * ====================
 * - vssadmin.exe (delete shadows, resize shadowstorage)
 * - wbadmin.exe (delete catalog, delete backup)
 * - bcdedit.exe (recoveryenabled No, bootstatuspolicy ignoreallfailures)
 * - wmic.exe (shadowcopy delete, shadowstorage delete)
 * - PowerShell (Get-WmiObject Win32_ShadowCopy...Delete)
 * - diskshadow.exe (automated VSS manipulation)
 * - Service stops (VSS, SDRSVC, wbengine)
 * - Registry changes (VSS settings, BCD)
 * - Backup file deletions (.bak, .vhd, .vmdk, .tib, etc.)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "BackupProtector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <deque>
#include <unordered_set>

// Third-party libraries
#include <nlohmann/json.hpp>

// ShadowStrike infrastructure
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// Windows-specific headers
#ifdef _WIN32
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#pragma comment(lib, "vssapi.lib")
#endif

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

namespace {

/**
 * @brief Built-in command patterns for ransomware detection
 */
std::vector<CommandPattern> CreateBuiltInPatterns() {
    std::vector<CommandPattern> patterns;

    // vssadmin delete shadows
    {
        CommandPattern pattern;
        pattern.patternName = "vssadmin_delete_shadows";
        pattern.toolType = DangerousToolType::VSSAdmin;
        pattern.threatType = BackupThreatType::VSSDelete;
        pattern.regexPattern = LR"(vssadmin\.exe.*delete\s+shadows)";
        pattern.keywords = {L"delete", L"shadows", L"/all", L"/quiet"};
        pattern.description = "VSS shadow copy deletion via vssadmin";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // vssadmin resize shadowstorage
    {
        CommandPattern pattern;
        pattern.patternName = "vssadmin_resize_shadowstorage";
        pattern.toolType = DangerousToolType::VSSAdmin;
        pattern.threatType = BackupThreatType::VSSResize;
        pattern.regexPattern = LR"(vssadmin\.exe.*resize\s+shadowstorage)";
        pattern.keywords = {L"resize", L"shadowstorage", L"/maxsize="};
        pattern.description = "VSS shadow storage resize (often to 0)";
        pattern.recommendedAction = ProtectionAction::Block;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // wbadmin delete catalog
    {
        CommandPattern pattern;
        pattern.patternName = "wbadmin_delete_catalog";
        pattern.toolType = DangerousToolType::WBAdmin;
        pattern.threatType = BackupThreatType::BackupDelete;
        pattern.regexPattern = LR"(wbadmin\.exe.*delete\s+(catalog|backup))";
        pattern.keywords = {L"delete", L"catalog", L"backup", L"/quiet"};
        pattern.description = "Windows Backup catalog deletion";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // bcdedit recovery disable
    {
        CommandPattern pattern;
        pattern.patternName = "bcdedit_recovery_disable";
        pattern.toolType = DangerousToolType::BCDEdit;
        pattern.threatType = BackupThreatType::RecoveryDisable;
        pattern.regexPattern = LR"(bcdedit\.exe.*/set.*recoveryenabled\s+no)";
        pattern.keywords = {L"/set", L"recoveryenabled", L"no"};
        pattern.description = "Disable Windows Recovery";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // bcdedit bootstatuspolicy ignore
    {
        CommandPattern pattern;
        pattern.patternName = "bcdedit_bootstatuspolicy_ignore";
        pattern.toolType = DangerousToolType::BCDEdit;
        pattern.threatType = BackupThreatType::BootConfigChange;
        pattern.regexPattern = LR"(bcdedit\.exe.*/set.*bootstatuspolicy\s+ignoreallfailures)";
        pattern.keywords = {L"/set", L"bootstatuspolicy", L"ignoreallfailures"};
        pattern.description = "Ignore boot failures (hide ransomware damage)";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // wmic shadowcopy delete
    {
        CommandPattern pattern;
        pattern.patternName = "wmic_shadowcopy_delete";
        pattern.toolType = DangerousToolType::WMIC;
        pattern.threatType = BackupThreatType::WMIShadowDelete;
        pattern.regexPattern = LR"(wmic\.exe.*shadowcopy.*delete)";
        pattern.keywords = {L"shadowcopy", L"delete", L"/nointeractive"};
        pattern.description = "WMI-based shadow copy deletion";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // PowerShell WMI shadow copy deletion
    {
        CommandPattern pattern;
        pattern.patternName = "powershell_wmi_shadowcopy_delete";
        pattern.toolType = DangerousToolType::PowerShell;
        pattern.threatType = BackupThreatType::WMIShadowDelete;
        pattern.regexPattern = LR"(Get-WmiObject.*Win32_ShadowCopy.*\.Delete\(\))";
        pattern.keywords = {L"Get-WmiObject", L"Win32_ShadowCopy", L"Delete"};
        pattern.description = "PowerShell WMI shadow copy deletion";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // PowerShell VSS deletion (alternative syntax)
    {
        CommandPattern pattern;
        pattern.patternName = "powershell_vss_delete";
        pattern.toolType = DangerousToolType::PowerShell;
        pattern.threatType = BackupThreatType::VSSDelete;
        pattern.regexPattern = LR"((Get-)?CimInstance.*Win32_ShadowCopy.*Remove)";
        pattern.keywords = {L"CimInstance", L"Win32_ShadowCopy", L"Remove"};
        pattern.description = "PowerShell CIM shadow copy deletion";
        pattern.recommendedAction = ProtectionAction::BlockKill;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    // diskshadow automated
    {
        CommandPattern pattern;
        pattern.patternName = "diskshadow_script";
        pattern.toolType = DangerousToolType::DiskShadow;
        pattern.threatType = BackupThreatType::VSSDelete;
        pattern.regexPattern = LR"(diskshadow\.exe.*/s)";
        pattern.keywords = {L"/s", L"delete", L"shadows"};
        pattern.description = "DiskShadow scripted VSS manipulation";
        pattern.recommendedAction = ProtectionAction::Block;
        pattern.caseSensitive = false;
        patterns.push_back(pattern);
    }

    return patterns;
}

/**
 * @brief Protected services that ransomware tries to stop
 */
const std::vector<std::wstring> PROTECTED_SERVICES = {
    L"VSS",           // Volume Shadow Copy
    L"SDRSVC",        // Windows Backup
    L"wbengine",      // Block Level Backup Engine
    L"swprv",         // Software Shadow Copy Provider
    L"MSSQLServerADHelper100"  // SQL Server VSS Writer
};

/**
 * @brief Protected registry keys (VSS configuration)
 */
const std::vector<std::wstring> PROTECTED_REGISTRY_KEYS = {
    LR"(SYSTEM\CurrentControlSet\Services\VSS)",
    LR"(SYSTEM\CurrentControlSet\Control\BackupRestore)",
    LR"(SYSTEM\CurrentControlSet\Control\Session Manager\Boot Manager)",
    LR"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore)"
};

} // anonymous namespace

// ============================================================================
// BACKUP PROTECTOR IMPLEMENTATION (PIMPL)
// ============================================================================

class BackupProtectorImpl {
public:
    BackupProtectorImpl();
    ~BackupProtectorImpl();

    // Lifecycle
    bool Initialize(const BackupProtectorConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const BackupProtectorConfiguration& config);
    BackupProtectorConfiguration GetConfiguration() const;

    // Detection
    bool IsDestructiveTool(const std::wstring& imagePath, const std::wstring& commandLine);
    std::optional<BlockedAttempt> AnalyzeProcess(uint32_t pid, std::wstring_view imagePath,
                                                   std::wstring_view commandLine);
    bool IsDestructiveCommand(std::wstring_view commandLine);
    bool IsProtectedBackupFile(const std::wstring& filePath);
    bool ShouldBlockFileAccess(std::wstring_view filePath, uint32_t pid, uint32_t desiredAccess);

    // Service Protection
    void LockVSSService();
    void UnlockVSSService();
    bool ShouldBlockServiceOperation(std::wstring_view serviceName, uint32_t operation, uint32_t pid);

    // Registry Protection
    bool ShouldBlockRegistryOperation(std::wstring_view keyPath, std::wstring_view valueName,
                                      uint32_t operation, uint32_t pid);

    // Whitelist
    void AddToWhitelist(std::wstring_view processPath);
    void RemoveFromWhitelist(std::wstring_view processPath);
    bool IsWhitelisted(std::wstring_view processPath) const;
    void WhitelistSigner(std::wstring_view signerName);

    // Callbacks
    void SetBlockCallback(BlockCallback callback);
    void SetDecisionCallback(DecisionCallback callback);

    // Statistics
    BackupProtectorStatistics GetStatistics() const;
    void ResetStatistics();
    std::vector<BlockedAttempt> GetRecentBlocks(size_t maxCount) const;

    bool SelfTest();

private:
    // Helper functions
    DangerousToolType IdentifyTool(std::wstring_view imagePath);
    std::optional<CommandPattern> MatchCommandPattern(std::wstring_view commandLine);
    ProtectionAction DetermineAction(const BlockedAttempt& attempt);
    void RecordBlockedAttempt(const BlockedAttempt& attempt);
    void NotifyBlock(const BlockedAttempt& attempt);
    ProtectionAction QueryDecision(uint32_t pid, const std::wstring& commandLine,
                                    BackupThreatType threatType);
    bool IsFileProtectedExtension(std::wstring_view filePath);
    bool IsServiceProtected(std::wstring_view serviceName);
    bool IsRegistryKeyProtected(std::wstring_view keyPath);
    std::wstring GetProcessImagePath(uint32_t pid);
    std::wstring GetProcessCommandLine(uint32_t pid);
    uint32_t GetParentProcessId(uint32_t pid);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    BackupProtectorConfiguration m_config;

    // Patterns
    std::vector<CommandPattern> m_patterns;
    std::unordered_map<std::wstring, std::wregex> m_compiledPatterns;

    // Whitelist
    mutable std::shared_mutex m_whitelistMutex;
    std::unordered_set<std::wstring> m_whitelistedPaths;
    std::unordered_set<std::wstring> m_whitelistedSigners;

    // Blocked attempts history
    mutable std::mutex m_blockMutex;
    std::deque<BlockedAttempt> m_blockedAttempts;
    static constexpr size_t MAX_BLOCKED_LOG = 1000;
    std::atomic<uint64_t> m_attemptIdCounter{1};

    // Callbacks
    mutable std::mutex m_callbackMutex;
    BlockCallback m_blockCallback;
    DecisionCallback m_decisionCallback;

    // Statistics
    mutable BackupProtectorStatistics m_stats;

    // Infrastructure references
    Whitelist::WhiteListStore* m_whitelistStore = nullptr;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

BackupProtectorImpl::BackupProtectorImpl() {
    Logger::Info("[BackupProtector] Instance created");
}

BackupProtectorImpl::~BackupProtectorImpl() {
    Shutdown();
    Logger::Info("[BackupProtector] Instance destroyed");
}

bool BackupProtectorImpl::Initialize(const BackupProtectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        Logger::Warn("[BackupProtector] Already initialized");
        return true;
    }

    try {
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            Logger::Error("[BackupProtector] Invalid configuration");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize infrastructure references
        try {
            m_whitelistStore = &Whitelist::WhiteListStore::Instance();
        } catch (const std::exception& e) {
            Logger::Warn("[BackupProtector] WhiteListStore not available: {}", e.what());
            m_whitelistStore = nullptr;
        }

        // Load built-in patterns
        m_patterns = CreateBuiltInPatterns();

        // Add custom patterns
        for (const auto& pattern : m_config.customPatterns) {
            m_patterns.push_back(pattern);
        }

        // Compile regex patterns
        for (const auto& pattern : m_patterns) {
            try {
                std::wregex regex(pattern.regexPattern,
                    std::regex_constants::ECMAScript | std::regex_constants::icase);
                m_compiledPatterns[pattern.patternName] = regex;
            } catch (const std::regex_error& e) {
                Logger::Error("[BackupProtector] Failed to compile pattern {}: {}",
                    StringUtils::WStringToString(pattern.patternName), e.what());
            }
        }

        // Initialize whitelist
        for (const auto& path : m_config.trustedProcesses) {
            m_whitelistedPaths.insert(StringUtils::ToLowerW(path));
        }

        // Reset statistics
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        Logger::Info("[BackupProtector] Initialized successfully (Version {}, {} patterns)",
            BackupProtector::GetVersionString(), m_patterns.size());

        return true;

    } catch (const std::exception& e) {
        Logger::Critical("[BackupProtector] Initialization failed: {}", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        Logger::Critical("[BackupProtector] Initialization failed: Unknown error");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void BackupProtectorImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Clear state
        m_patterns.clear();
        m_compiledPatterns.clear();
        m_whitelistedPaths.clear();
        m_whitelistedSigners.clear();
        m_blockedAttempts.clear();

        // Clear callbacks
        {
            std::lock_guard cbLock(m_callbackMutex);
            m_blockCallback = nullptr;
            m_decisionCallback = nullptr;
        }

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Logger::Info("[BackupProtector] Shutdown complete");

    } catch (const std::exception& e) {
        Logger::Error("[BackupProtector] Shutdown error: {}", e.what());
    } catch (...) {
        Logger::Error("[BackupProtector] Shutdown error: Unknown exception");
    }
}

bool BackupProtectorImpl::UpdateConfiguration(const BackupProtectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!config.IsValid()) {
        Logger::Error("[BackupProtector] Invalid configuration");
        return false;
    }

    m_config = config;
    Logger::Info("[BackupProtector] Configuration updated");
    return true;
}

BackupProtectorConfiguration BackupProtectorImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// DETECTION
// ============================================================================

bool BackupProtectorImpl::IsDestructiveTool(const std::wstring& imagePath,
                                             const std::wstring& commandLine) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    // Check if whitelisted
    if (IsWhitelisted(imagePath)) {
        m_stats.whitelistedAllowed++;
        return false;
    }

    // Identify tool type
    DangerousToolType toolType = IdentifyTool(imagePath);
    if (toolType == DangerousToolType::Unknown) {
        return false;
    }

    // Check command line for destructive patterns
    return IsDestructiveCommand(commandLine);
}

std::optional<BlockedAttempt> BackupProtectorImpl::AnalyzeProcess(
    uint32_t pid,
    std::wstring_view imagePath,
    std::wstring_view commandLine) {

    if (!m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    // Check if whitelisted
    if (IsWhitelisted(imagePath)) {
        m_stats.whitelistedAllowed++;
        return std::nullopt;
    }

    // Identify tool
    DangerousToolType toolType = IdentifyTool(imagePath);
    if (toolType == DangerousToolType::Unknown) {
        return std::nullopt;
    }

    // Match command pattern
    auto patternOpt = MatchCommandPattern(commandLine);
    if (!patternOpt) {
        return std::nullopt;
    }

    const auto& pattern = *patternOpt;

    // Create blocked attempt
    BlockedAttempt attempt;
    attempt.attemptId = m_attemptIdCounter.fetch_add(1, std::memory_order_relaxed);
    attempt.timestamp = std::chrono::system_clock::now();
    attempt.pid = pid;
    attempt.processName = fs::path(imagePath).filename().wstring();
    attempt.processPath = std::wstring(imagePath);
    attempt.commandLine = std::wstring(commandLine);
    attempt.parentPid = GetParentProcessId(pid);
    attempt.threatType = pattern.threatType;
    attempt.toolType = toolType;

    // Get parent process name
    if (attempt.parentPid != 0) {
        attempt.parentName = fs::path(GetProcessImagePath(attempt.parentPid)).filename().wstring();
    }

    // Determine action
    attempt.action = DetermineAction(attempt);

    // Query decision callback if present
    ProtectionAction callbackAction = QueryDecision(pid, attempt.commandLine, pattern.threatType);
    if (callbackAction != ProtectionAction::Allow) {
        attempt.action = callbackAction;
    }

    // Record and notify
    if (attempt.action == ProtectionAction::Block || attempt.action == ProtectionAction::BlockKill) {
        RecordBlockedAttempt(attempt);
        NotifyBlock(attempt);

        m_stats.attemptsBlocked++;

        // Update specific counters
        switch (pattern.threatType) {
            case BackupThreatType::VSSDelete:
                m_stats.vssDeletesBlocked++;
                break;
            case BackupThreatType::BackupDelete:
                m_stats.fileDeletesBlocked++;
                break;
            case BackupThreatType::ServiceStop:
                m_stats.serviceStopsBlocked++;
                break;
            default:
                break;
        }

        // Update threat type counter
        if (static_cast<size_t>(pattern.threatType) < m_stats.byThreatType.size()) {
            m_stats.byThreatType[static_cast<size_t>(pattern.threatType)]++;
        }

        Logger::Warn("[BackupProtector] Blocked attempt {} - PID: {}, Tool: {}, Threat: {}",
            attempt.attemptId, pid,
            GetDangerousToolTypeName(toolType),
            GetBackupThreatTypeName(pattern.threatType));
    }

    return attempt;
}

bool BackupProtectorImpl::IsDestructiveCommand(std::wstring_view commandLine) {
    std::shared_lock lock(m_mutex);

    for (const auto& pattern : m_patterns) {
        // Check keywords first (fast path)
        bool hasAllKeywords = true;
        for (const auto& keyword : pattern.keywords) {
            std::wstring cmdLower = StringUtils::ToLowerW(std::wstring(commandLine));
            std::wstring keywordLower = StringUtils::ToLowerW(keyword);

            if (cmdLower.find(keywordLower) == std::wstring::npos) {
                hasAllKeywords = false;
                break;
            }
        }

        if (!hasAllKeywords) {
            continue;
        }

        // Check regex pattern
        auto it = m_compiledPatterns.find(pattern.patternName);
        if (it != m_compiledPatterns.end()) {
            try {
                if (std::regex_search(commandLine.begin(), commandLine.end(), it->second)) {
                    return true;
                }
            } catch (const std::regex_error&) {
                continue;
            }
        }
    }

    return false;
}

bool BackupProtectorImpl::IsProtectedBackupFile(const std::wstring& filePath) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_config.protectBackupFiles) {
        return false;
    }

    return IsFileProtectedExtension(filePath);
}

bool BackupProtectorImpl::ShouldBlockFileAccess(std::wstring_view filePath,
                                                 uint32_t pid,
                                                 uint32_t desiredAccess) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_config.protectBackupFiles) {
        return false;
    }

    // Check if it's a protected backup file
    if (!IsFileProtectedExtension(filePath)) {
        return false;
    }

    // Check if process is whitelisted
    std::wstring imagePath = GetProcessImagePath(pid);
    if (IsWhitelisted(imagePath)) {
        return false;
    }

    // Check if deletion is requested
    constexpr uint32_t DELETE_ACCESS = 0x00010000;  // DELETE
    if (desiredAccess & DELETE_ACCESS) {
        Logger::Warn("[BackupProtector] Blocking delete access to backup file: {} from PID: {}",
            StringUtils::WStringToString(std::wstring(filePath)), pid);

        m_stats.fileDeletesBlocked++;
        return true;
    }

    return false;
}

// ============================================================================
// SERVICE PROTECTION
// ============================================================================

void BackupProtectorImpl::LockVSSService() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    Logger::Info("[BackupProtector] VSS service lock requested (implementation platform-specific)");
    // Platform-specific implementation would go here
}

void BackupProtectorImpl::UnlockVSSService() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    Logger::Info("[BackupProtector] VSS service unlock requested");
}

bool BackupProtectorImpl::ShouldBlockServiceOperation(std::wstring_view serviceName,
                                                       uint32_t operation,
                                                       uint32_t pid) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_config.protectServices) {
        return false;
    }

    // Check if service is protected
    if (!IsServiceProtected(serviceName)) {
        return false;
    }

    // Check if process is whitelisted
    std::wstring imagePath = GetProcessImagePath(pid);
    if (IsWhitelisted(imagePath)) {
        return false;
    }

    // Check operation type
    constexpr uint32_t SERVICE_STOP = 0x0001;
    constexpr uint32_t SERVICE_DELETE = 0x0002;
    constexpr uint32_t SERVICE_CHANGE_CONFIG = 0x0004;

    if (operation & (SERVICE_STOP | SERVICE_DELETE | SERVICE_CHANGE_CONFIG)) {
        Logger::Warn("[BackupProtector] Blocking service operation on {} from PID: {}",
            StringUtils::WStringToString(std::wstring(serviceName)), pid);

        m_stats.serviceStopsBlocked++;
        return true;
    }

    return false;
}

// ============================================================================
// REGISTRY PROTECTION
// ============================================================================

bool BackupProtectorImpl::ShouldBlockRegistryOperation(std::wstring_view keyPath,
                                                        std::wstring_view valueName,
                                                        uint32_t operation,
                                                        uint32_t pid) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_config.protectRegistryKeys) {
        return false;
    }

    // Check if registry key is protected
    if (!IsRegistryKeyProtected(keyPath)) {
        return false;
    }

    // Check if process is whitelisted
    std::wstring imagePath = GetProcessImagePath(pid);
    if (IsWhitelisted(imagePath)) {
        return false;
    }

    // Check operation type
    constexpr uint32_t REG_DELETE = 0x0001;
    constexpr uint32_t REG_SET_VALUE = 0x0002;

    if (operation & (REG_DELETE | REG_SET_VALUE)) {
        Logger::Warn("[BackupProtector] Blocking registry operation on {} from PID: {}",
            StringUtils::WStringToString(std::wstring(keyPath)), pid);

        m_stats.registryChangesBlocked++;
        return true;
    }

    return false;
}

// ============================================================================
// WHITELIST
// ============================================================================

void BackupProtectorImpl::AddToWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPaths.insert(StringUtils::ToLowerW(std::wstring(processPath)));
    Logger::Info("[BackupProtector] Added to whitelist: {}",
        StringUtils::WStringToString(std::wstring(processPath)));
}

void BackupProtectorImpl::RemoveFromWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPaths.erase(StringUtils::ToLowerW(std::wstring(processPath)));
    Logger::Info("[BackupProtector] Removed from whitelist: {}",
        StringUtils::WStringToString(std::wstring(processPath)));
}

bool BackupProtectorImpl::IsWhitelisted(std::wstring_view processPath) const {
    std::shared_lock lock(m_whitelistMutex);

    std::wstring pathLower = StringUtils::ToLowerW(std::wstring(processPath));

    // Check local whitelist
    if (m_whitelistedPaths.find(pathLower) != m_whitelistedPaths.end()) {
        return true;
    }

    // Check WhiteListStore
    if (m_whitelistStore) {
        try {
            if (m_whitelistStore->IsWhitelisted(processPath)) {
                return true;
            }
        } catch (...) {
            // Ignore errors
        }
    }

    return false;
}

void BackupProtectorImpl::WhitelistSigner(std::wstring_view signerName) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedSigners.insert(StringUtils::ToLowerW(std::wstring(signerName)));
    Logger::Info("[BackupProtector] Whitelisted signer: {}",
        StringUtils::WStringToString(std::wstring(signerName)));
}

// ============================================================================
// CALLBACKS
// ============================================================================

void BackupProtectorImpl::SetBlockCallback(BlockCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_blockCallback = std::move(callback);
}

void BackupProtectorImpl::SetDecisionCallback(DecisionCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_decisionCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

BackupProtectorStatistics BackupProtectorImpl::GetStatistics() const {
    return m_stats;
}

void BackupProtectorImpl::ResetStatistics() {
    m_stats.Reset();
    m_stats.startTime = Clock::now();
    Logger::Info("[BackupProtector] Statistics reset");
}

std::vector<BlockedAttempt> BackupProtectorImpl::GetRecentBlocks(size_t maxCount) const {
    std::lock_guard lock(m_blockMutex);

    size_t count = std::min(maxCount, m_blockedAttempts.size());
    std::vector<BlockedAttempt> result;
    result.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        result.push_back(m_blockedAttempts[i]);
    }

    return result;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

DangerousToolType BackupProtectorImpl::IdentifyTool(std::wstring_view imagePath) {
    std::wstring filename = fs::path(imagePath).filename().wstring();
    std::wstring filenameLower = StringUtils::ToLowerW(filename);

    if (filenameLower == L"vssadmin.exe") {
        return DangerousToolType::VSSAdmin;
    } else if (filenameLower == L"wbadmin.exe") {
        return DangerousToolType::WBAdmin;
    } else if (filenameLower == L"bcdedit.exe") {
        return DangerousToolType::BCDEdit;
    } else if (filenameLower == L"wmic.exe") {
        return DangerousToolType::WMIC;
    } else if (filenameLower == L"powershell.exe" || filenameLower == L"pwsh.exe") {
        return DangerousToolType::PowerShell;
    } else if (filenameLower == L"cmd.exe") {
        return DangerousToolType::CMD;
    } else if (filenameLower == L"diskshadow.exe") {
        return DangerousToolType::DiskShadow;
    }

    return DangerousToolType::Unknown;
}

std::optional<CommandPattern> BackupProtectorImpl::MatchCommandPattern(std::wstring_view commandLine) {
    std::shared_lock lock(m_mutex);

    for (const auto& pattern : m_patterns) {
        // Check keywords
        bool hasAllKeywords = true;
        for (const auto& keyword : pattern.keywords) {
            std::wstring cmdLower = StringUtils::ToLowerW(std::wstring(commandLine));
            std::wstring keywordLower = StringUtils::ToLowerW(keyword);

            if (cmdLower.find(keywordLower) == std::wstring::npos) {
                hasAllKeywords = false;
                break;
            }
        }

        if (!hasAllKeywords) {
            continue;
        }

        // Check regex
        auto it = m_compiledPatterns.find(pattern.patternName);
        if (it != m_compiledPatterns.end()) {
            try {
                if (std::regex_search(commandLine.begin(), commandLine.end(), it->second)) {
                    return pattern;
                }
            } catch (const std::regex_error&) {
                continue;
            }
        }
    }

    return std::nullopt;
}

ProtectionAction BackupProtectorImpl::DetermineAction(const BlockedAttempt& attempt) {
    std::shared_lock lock(m_mutex);

    // Use default action
    ProtectionAction action = m_config.defaultAction;

    // Override for critical threats
    if (attempt.threatType == BackupThreatType::VSSDelete ||
        attempt.threatType == BackupThreatType::WMIShadowDelete) {
        action = ProtectionAction::BlockKill;
    }

    return action;
}

void BackupProtectorImpl::RecordBlockedAttempt(const BlockedAttempt& attempt) {
    std::lock_guard lock(m_blockMutex);

    m_blockedAttempts.push_front(attempt);

    // LRU eviction
    if (m_blockedAttempts.size() > MAX_BLOCKED_LOG) {
        m_blockedAttempts.pop_back();
    }
}

void BackupProtectorImpl::NotifyBlock(const BlockedAttempt& attempt) {
    std::lock_guard lock(m_callbackMutex);
    if (m_blockCallback) {
        try {
            m_blockCallback(attempt);
        } catch (const std::exception& e) {
            Logger::Error("[BackupProtector] Block callback exception: {}", e.what());
        }
    }
}

ProtectionAction BackupProtectorImpl::QueryDecision(uint32_t pid,
                                                     const std::wstring& commandLine,
                                                     BackupThreatType threatType) {
    std::lock_guard lock(m_callbackMutex);
    if (m_decisionCallback) {
        try {
            return m_decisionCallback(pid, commandLine, threatType);
        } catch (const std::exception& e) {
            Logger::Error("[BackupProtector] Decision callback exception: {}", e.what());
        }
    }
    return ProtectionAction::Allow;
}

bool BackupProtectorImpl::IsFileProtectedExtension(std::wstring_view filePath) {
    std::wstring ext = fs::path(filePath).extension().wstring();
    std::wstring extLower = StringUtils::ToLowerW(ext);

    for (const auto& protectedExt : PROTECTED_EXTENSIONS) {
        if (extLower == StringUtils::ToLowerW(protectedExt)) {
            return true;
        }
    }

    return false;
}

bool BackupProtectorImpl::IsServiceProtected(std::wstring_view serviceName) {
    std::wstring nameLower = StringUtils::ToLowerW(std::wstring(serviceName));

    for (const auto& protectedService : PROTECTED_SERVICES) {
        if (nameLower == StringUtils::ToLowerW(protectedService)) {
            return true;
        }
    }

    return false;
}

bool BackupProtectorImpl::IsRegistryKeyProtected(std::wstring_view keyPath) {
    std::wstring pathUpper = StringUtils::ToUpperW(std::wstring(keyPath));

    for (const auto& protectedKey : PROTECTED_REGISTRY_KEYS) {
        std::wstring protectedUpper = StringUtils::ToUpperW(protectedKey);
        if (pathUpper.find(protectedUpper) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

std::wstring BackupProtectorImpl::GetProcessImagePath(uint32_t pid) {
    try {
        return ProcessUtils::GetProcessImagePath(pid);
    } catch (...) {
        return L"";
    }
}

std::wstring BackupProtectorImpl::GetProcessCommandLine(uint32_t pid) {
    try {
        return ProcessUtils::GetProcessCommandLine(pid);
    } catch (...) {
        return L"";
    }
}

uint32_t BackupProtectorImpl::GetParentProcessId(uint32_t pid) {
    try {
        return ProcessUtils::GetParentProcessId(pid);
    } catch (...) {
        return 0;
    }
}

bool BackupProtectorImpl::SelfTest() {
    Logger::Info("[BackupProtector] Running self-test...");

    try {
        // Test 1: Tool identification
        {
            if (IdentifyTool(L"C:\\Windows\\System32\\vssadmin.exe") != DangerousToolType::VSSAdmin) {
                Logger::Error("[BackupProtector] Self-test failed: Tool identification");
                return false;
            }
        }

        // Test 2: Command pattern matching
        {
            std::wstring testCmd = L"vssadmin.exe delete shadows /all /quiet";
            if (!IsDestructiveCommand(testCmd)) {
                Logger::Error("[BackupProtector] Self-test failed: Command pattern matching");
                return false;
            }
        }

        // Test 3: Protected file extension
        {
            if (!IsProtectedBackupFile(L"C:\\Backup\\data.vhd")) {
                Logger::Error("[BackupProtector] Self-test failed: Protected file detection");
                return false;
            }
        }

        // Test 4: Whitelist functionality
        {
            AddToWhitelist(L"C:\\Test\\trusted.exe");
            if (!IsWhitelisted(L"C:\\Test\\trusted.exe")) {
                Logger::Error("[BackupProtector] Self-test failed: Whitelist");
                return false;
            }
            RemoveFromWhitelist(L"C:\\Test\\trusted.exe");
        }

        // Test 5: Statistics tracking
        {
            auto stats = GetStatistics();
            if (stats.whitelistedAllowed.load() == 0) {
                Logger::Warn("[BackupProtector] Self-test warning: No whitelist events");
            }
        }

        Logger::Info("[BackupProtector] Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("[BackupProtector] Self-test exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> BackupProtector::s_instanceCreated{false};

BackupProtector::BackupProtector()
    : m_impl(std::make_unique<BackupProtectorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

BackupProtector::~BackupProtector() = default;

BackupProtector& BackupProtector::Instance() noexcept {
    static BackupProtector instance;
    return instance;
}

bool BackupProtector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC API FORWARDING
// ============================================================================

bool BackupProtector::Initialize(const BackupProtectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void BackupProtector::Shutdown() {
    m_impl->Shutdown();
}

bool BackupProtector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus BackupProtector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool BackupProtector::UpdateConfiguration(const BackupProtectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

BackupProtectorConfiguration BackupProtector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

bool BackupProtector::IsDestructiveTool(const std::wstring& imagePath,
                                         const std::wstring& commandLine) {
    return m_impl->IsDestructiveTool(imagePath, commandLine);
}

std::optional<BlockedAttempt> BackupProtector::AnalyzeProcess(
    uint32_t pid,
    std::wstring_view imagePath,
    std::wstring_view commandLine) {
    return m_impl->AnalyzeProcess(pid, imagePath, commandLine);
}

bool BackupProtector::IsDestructiveCommand(std::wstring_view commandLine) {
    return m_impl->IsDestructiveCommand(commandLine);
}

bool BackupProtector::IsProtectedBackupFile(const std::wstring& filePath) {
    return m_impl->IsProtectedBackupFile(filePath);
}

bool BackupProtector::ShouldBlockFileAccess(std::wstring_view filePath,
                                             uint32_t pid,
                                             uint32_t desiredAccess) {
    return m_impl->ShouldBlockFileAccess(filePath, pid, desiredAccess);
}

void BackupProtector::LockVSSService() {
    m_impl->LockVSSService();
}

void BackupProtector::UnlockVSSService() {
    m_impl->UnlockVSSService();
}

bool BackupProtector::ShouldBlockServiceOperation(std::wstring_view serviceName,
                                                   uint32_t operation,
                                                   uint32_t pid) {
    return m_impl->ShouldBlockServiceOperation(serviceName, operation, pid);
}

bool BackupProtector::ShouldBlockRegistryOperation(std::wstring_view keyPath,
                                                    std::wstring_view valueName,
                                                    uint32_t operation,
                                                    uint32_t pid) {
    return m_impl->ShouldBlockRegistryOperation(keyPath, valueName, operation, pid);
}

void BackupProtector::AddToWhitelist(std::wstring_view processPath) {
    m_impl->AddToWhitelist(processPath);
}

void BackupProtector::RemoveFromWhitelist(std::wstring_view processPath) {
    m_impl->RemoveFromWhitelist(processPath);
}

bool BackupProtector::IsWhitelisted(std::wstring_view processPath) const {
    return m_impl->IsWhitelisted(processPath);
}

void BackupProtector::WhitelistSigner(std::wstring_view signerName) {
    m_impl->WhitelistSigner(signerName);
}

void BackupProtector::SetBlockCallback(BlockCallback callback) {
    m_impl->SetBlockCallback(std::move(callback));
}

void BackupProtector::SetDecisionCallback(DecisionCallback callback) {
    m_impl->SetDecisionCallback(std::move(callback));
}

BackupProtectorStatistics BackupProtector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void BackupProtector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<BlockedAttempt> BackupProtector::GetRecentBlocks(size_t maxCount) const {
    return m_impl->GetRecentBlocks(maxCount);
}

bool BackupProtector::SelfTest() {
    return m_impl->SelfTest();
}

std::string BackupProtector::GetVersionString() noexcept {
    return std::to_string(BackupProtectorConstants::VERSION_MAJOR) + "." +
           std::to_string(BackupProtectorConstants::VERSION_MINOR) + "." +
           std::to_string(BackupProtectorConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool CommandPattern::Matches(std::wstring_view commandLine) const {
    // Check keywords
    for (const auto& keyword : keywords) {
        std::wstring cmdLower = StringUtils::ToLowerW(std::wstring(commandLine));
        std::wstring keywordLower = StringUtils::ToLowerW(keyword);

        if (cmdLower.find(keywordLower) == std::wstring::npos) {
            return false;
        }
    }

    // Check regex
    try {
        std::wregex regex(regexPattern,
            caseSensitive ? std::regex_constants::ECMAScript :
                           (std::regex_constants::ECMAScript | std::regex_constants::icase));
        return std::regex_search(commandLine.begin(), commandLine.end(), regex);
    } catch (const std::regex_error&) {
        return false;
    }
}

void BackupProtectorStatistics::Reset() noexcept {
    attemptsBlocked.store(0, std::memory_order_release);
    processesTerminated.store(0, std::memory_order_release);
    vssDeletesBlocked.store(0, std::memory_order_release);
    fileDeletesBlocked.store(0, std::memory_order_release);
    serviceStopsBlocked.store(0, std::memory_order_release);
    registryChangesBlocked.store(0, std::memory_order_release);
    whitelistedAllowed.store(0, std::memory_order_release);

    for (auto& counter : byThreatType) {
        counter.store(0, std::memory_order_release);
    }

    startTime = Clock::now();
}

std::string BackupProtectorStatistics::ToJson() const {
    nlohmann::json j;
    j["attemptsBlocked"] = attemptsBlocked.load(std::memory_order_acquire);
    j["processesTerminated"] = processesTerminated.load(std::memory_order_acquire);
    j["vssDeletesBlocked"] = vssDeletesBlocked.load(std::memory_order_acquire);
    j["fileDeletesBlocked"] = fileDeletesBlocked.load(std::memory_order_acquire);
    j["serviceStopsBlocked"] = serviceStopsBlocked.load(std::memory_order_acquire);
    j["registryChangesBlocked"] = registryChangesBlocked.load(std::memory_order_acquire);
    j["whitelistedAllowed"] = whitelistedAllowed.load(std::memory_order_acquire);

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = elapsed;

    return j.dump();
}

std::string BlockedAttempt::ToJson() const {
    nlohmann::json j;
    j["attemptId"] = attemptId;
    j["pid"] = pid;
    j["processName"] = StringUtils::WStringToString(processName);
    j["processPath"] = StringUtils::WStringToString(processPath);
    j["commandLine"] = StringUtils::WStringToString(commandLine);
    j["parentPid"] = parentPid;
    j["parentName"] = StringUtils::WStringToString(parentName);
    j["threatType"] = static_cast<int>(threatType);
    j["toolType"] = static_cast<int>(toolType);
    j["action"] = static_cast<int>(action);
    j["target"] = StringUtils::WStringToString(target);
    j["userSid"] = StringUtils::WStringToString(userSid);
    j["details"] = StringUtils::WStringToString(details);
    return j.dump();
}

bool BackupProtectorConfiguration::IsValid() const noexcept {
    // Configuration is always valid (all fields are boolean flags or containers)
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetBackupThreatTypeName(BackupThreatType type) noexcept {
    switch (type) {
        case BackupThreatType::VSSDelete:        return "VSSDelete";
        case BackupThreatType::VSSResize:        return "VSSResize";
        case BackupThreatType::VSSDisable:       return "VSSDisable";
        case BackupThreatType::BackupDelete:     return "BackupDelete";
        case BackupThreatType::RecoveryDisable:  return "RecoveryDisable";
        case BackupThreatType::BootConfigChange: return "BootConfigChange";
        case BackupThreatType::WMIShadowDelete:  return "WMIShadowDelete";
        case BackupThreatType::ServiceStop:      return "ServiceStop";
        case BackupThreatType::ScheduleDelete:   return "ScheduleDelete";
        default:                                 return "Unknown";
    }
}

std::string_view GetProtectionActionName(ProtectionAction action) noexcept {
    switch (action) {
        case ProtectionAction::Allow:      return "Allow";
        case ProtectionAction::Block:      return "Block";
        case ProtectionAction::BlockKill:  return "BlockKill";
        case ProtectionAction::Warn:       return "Warn";
        case ProtectionAction::Quarantine: return "Quarantine";
        default:                           return "Unknown";
    }
}

std::string_view GetDangerousToolTypeName(DangerousToolType type) noexcept {
    switch (type) {
        case DangerousToolType::VSSAdmin:   return "VSSAdmin";
        case DangerousToolType::WBAdmin:    return "WBAdmin";
        case DangerousToolType::BCDEdit:    return "BCDEdit";
        case DangerousToolType::WMIC:       return "WMIC";
        case DangerousToolType::PowerShell: return "PowerShell";
        case DangerousToolType::CMD:        return "CMD";
        case DangerousToolType::DiskShadow: return "DiskShadow";
        default:                            return "Unknown";
    }
}

}  // namespace Ransomware
}  // namespace ShadowStrike
