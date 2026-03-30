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
 * - Internal atomic counters, non-atomic public snapshot
 *
 * LOCK ORDERING (to prevent deadlocks):
 *   m_mutex > m_whitelistMutex > m_blockMutex > m_callbackMutex
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
#include <filesystem>
#include <deque>
#include <regex>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Core/Process/ProcessKiller.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

namespace ShadowStrike {
namespace Ransomware {

namespace fs = std::filesystem;
using Utils::StringUtils;

static constexpr const wchar_t* kLogCat = L"BackupProtector";

// RAII wrapper for SC_HANDLE to prevent leaks on error/exception paths
struct ScHandleDeleter {
    void operator()(SC_HANDLE h) const noexcept {
        if (h) ::CloseServiceHandle(h);
    }
};
using UniqueScHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ScHandleDeleter>;

/// @brief Normalize a file path for consistent whitelist comparison.
/// Lowercases, resolves \..\, //, forward-slashes, and trailing dots/spaces.
[[nodiscard]] static std::wstring NormalizePathForWhitelist(std::wstring_view rawPath) {
    if (rawPath.empty())
        return {};
    try {
        // weakly_canonical resolves .., //, etc. without requiring the file to exist
        fs::path canonical = fs::weakly_canonical(fs::path(rawPath));
        return StringUtils::ToLowerCopy(canonical.wstring());
    } catch (...) {
        // Fallback: at minimum lowercase for case-insensitive comparison
        return StringUtils::ToLowerCopy(std::wstring(rawPath));
    }
}
// ============================================================================
// ANONYMOUS NAMESPACE: BUILT-IN DATA
// ============================================================================

namespace {

static constexpr size_t kMaxBlockedHistory = 1000;
static constexpr size_t kMaxCmdLineLen     = 32768;

std::vector<CommandPattern> CreateBuiltInPatterns() {
    std::vector<CommandPattern> patterns;
    patterns.reserve(12);

    // --- vssadmin delete shadows ---
    {
        CommandPattern p;
        p.patternName = "vssadmin_delete_shadows";
        p.toolType = DangerousToolType::VSSAdmin;
        p.threatType = BackupThreatType::VSSDelete;
        p.regexPattern = LR"(vssadmin[\.\s\\/]*exe.*delete\s+shadows)";
        p.keywords = {L"delete", L"shadows"};
        p.description = "VSS shadow copy deletion via vssadmin";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- vssadmin resize shadowstorage ---
    {
        CommandPattern p;
        p.patternName = "vssadmin_resize_shadowstorage";
        p.toolType = DangerousToolType::VSSAdmin;
        p.threatType = BackupThreatType::VSSResize;
        p.regexPattern = LR"(vssadmin[\.\s\\/]*exe.*resize\s+shadowstorage)";
        p.keywords = {L"resize", L"shadowstorage"};
        p.description = "VSS shadow storage resize (ransomware sets to 0)";
        p.recommendedAction = ProtectionAction::Block;
        patterns.push_back(std::move(p));
    }

    // --- wbadmin delete ---
    {
        CommandPattern p;
        p.patternName = "wbadmin_delete";
        p.toolType = DangerousToolType::WBAdmin;
        p.threatType = BackupThreatType::BackupDelete;
        p.regexPattern = LR"(wbadmin[\.\s\\/]*exe.*delete\s+(catalog|backup|systemstatebackup))";
        p.keywords = {L"delete"};
        p.description = "Windows Backup catalog or backup deletion";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- bcdedit recovery disable ---
    {
        CommandPattern p;
        p.patternName = "bcdedit_recovery_disable";
        p.toolType = DangerousToolType::BCDEdit;
        p.threatType = BackupThreatType::RecoveryDisable;
        p.regexPattern = LR"(bcdedit[\.\s\\/]*exe.*/set.*recoveryenabled\s+no)";
        p.keywords = {L"/set", L"recoveryenabled", L"no"};
        p.description = "Disable Windows Recovery via bcdedit";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- bcdedit bootstatuspolicy ---
    {
        CommandPattern p;
        p.patternName = "bcdedit_bootstatuspolicy";
        p.toolType = DangerousToolType::BCDEdit;
        p.threatType = BackupThreatType::BootConfigChange;
        p.regexPattern = LR"(bcdedit[\.\s\\/]*exe.*/set.*bootstatuspolicy\s+ignoreallfailures)";
        p.keywords = {L"/set", L"bootstatuspolicy", L"ignoreallfailures"};
        p.description = "Hide boot failures to mask ransomware damage";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- wmic shadowcopy delete ---
    {
        CommandPattern p;
        p.patternName = "wmic_shadowcopy_delete";
        p.toolType = DangerousToolType::WMIC;
        p.threatType = BackupThreatType::WMIShadowDelete;
        p.regexPattern = LR"(wmic[\.\s\\/]*exe.*shadowcopy.*delete)";
        p.keywords = {L"shadowcopy", L"delete"};
        p.description = "WMI-based shadow copy deletion";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- PowerShell Get-WmiObject Win32_ShadowCopy .Delete() ---
    {
        CommandPattern p;
        p.patternName = "powershell_wmi_shadow_delete";
        p.toolType = DangerousToolType::PowerShell;
        p.threatType = BackupThreatType::WMIShadowDelete;
        p.regexPattern = LR"(Get-WmiObject.*Win32_ShadowCopy.*\.Delete\b)";
        p.keywords = {L"Win32_ShadowCopy", L"Delete"};
        p.description = "PowerShell WMI shadow copy deletion";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- PowerShell CIM shadow copy ---
    {
        CommandPattern p;
        p.patternName = "powershell_cim_shadow_delete";
        p.toolType = DangerousToolType::PowerShell;
        p.threatType = BackupThreatType::VSSDelete;
        p.regexPattern = LR"((Get-|Remove-)?CimInstance.*Win32_ShadowCopy)";
        p.keywords = {L"CimInstance", L"Win32_ShadowCopy"};
        p.description = "PowerShell CIM shadow copy removal";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- diskshadow scripted ---
    {
        CommandPattern p;
        p.patternName = "diskshadow_script";
        p.toolType = DangerousToolType::DiskShadow;
        p.threatType = BackupThreatType::VSSDelete;
        p.regexPattern = LR"(diskshadow[\.\s\\/]*exe.*/s)";
        p.keywords = {L"/s"};
        p.description = "DiskShadow scripted VSS manipulation";
        p.recommendedAction = ProtectionAction::Block;
        patterns.push_back(std::move(p));
    }

    // --- VSS service stop via net/sc/PowerShell ---
    {
        CommandPattern p;
        p.patternName = "vss_service_stop";
        p.toolType = DangerousToolType::CMD;
        p.threatType = BackupThreatType::ServiceStop;
        p.regexPattern = LR"((Stop-Service|sc\s+stop|net\s+stop)\s+.*VSS)";
        p.keywords = {L"VSS"};
        p.description = "VSS service stop via command line";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    // --- bcdedit safeboot (forces safe mode reboot to bypass AV) ---
    {
        CommandPattern p;
        p.patternName = "bcdedit_safeboot";
        p.toolType = DangerousToolType::BCDEdit;
        p.threatType = BackupThreatType::BootConfigChange;
        p.regexPattern = LR"(bcdedit[\.\s\\/]*exe.*/set.*safeboot)";
        p.keywords = {L"/set", L"safeboot"};
        p.description = "Force safe-mode reboot (ransomware evasion)";
        p.recommendedAction = ProtectionAction::BlockKill;
        patterns.push_back(std::move(p));
    }

    return patterns;
}

const std::vector<std::wstring> kProtectedServiceNames = {
    L"VSS",
    L"SDRSVC",
    L"wbengine",
    L"swprv",
    L"MSSQLServerADHelper100"
};

const std::vector<std::wstring> kProtectedRegistryPaths = {
    LR"(SYSTEM\CurrentControlSet\Services\VSS)",
    LR"(SYSTEM\CurrentControlSet\Control\BackupRestore)",
    LR"(SYSTEM\CurrentControlSet\Control\Session Manager\Boot Manager)",
    LR"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore)"
};

}  // anonymous namespace
// ============================================================================
// INTERNAL STATS (THREAD-SAFE ATOMIC COUNTERS)
// ============================================================================

struct InternalStats {
    std::atomic<uint64_t> attemptsBlocked{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> vssDeletesBlocked{0};
    std::atomic<uint64_t> fileDeletesBlocked{0};
    std::atomic<uint64_t> serviceStopsBlocked{0};
    std::atomic<uint64_t> registryChangesBlocked{0};
    std::atomic<uint64_t> whitelistedAllowed{0};
    std::array<std::atomic<uint64_t>, 16> byThreatType{};
    TimePoint startTime = Clock::now();

    void Reset() noexcept {
        attemptsBlocked.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        vssDeletesBlocked.store(0, std::memory_order_relaxed);
        fileDeletesBlocked.store(0, std::memory_order_relaxed);
        serviceStopsBlocked.store(0, std::memory_order_relaxed);
        registryChangesBlocked.store(0, std::memory_order_relaxed);
        whitelistedAllowed.store(0, std::memory_order_relaxed);
        for (auto& c : byThreatType)
            c.store(0, std::memory_order_relaxed);
        startTime = Clock::now();
    }

    [[nodiscard]] BackupProtectorStatistics Snapshot() const noexcept {
        BackupProtectorStatistics s;
        s.attemptsBlocked      = attemptsBlocked.load(std::memory_order_relaxed);
        s.processesTerminated  = processesTerminated.load(std::memory_order_relaxed);
        s.vssDeletesBlocked    = vssDeletesBlocked.load(std::memory_order_relaxed);
        s.fileDeletesBlocked   = fileDeletesBlocked.load(std::memory_order_relaxed);
        s.serviceStopsBlocked  = serviceStopsBlocked.load(std::memory_order_relaxed);
        s.registryChangesBlocked = registryChangesBlocked.load(std::memory_order_relaxed);
        s.whitelistedAllowed   = whitelistedAllowed.load(std::memory_order_relaxed);
        for (size_t i = 0; i < s.byThreatType.size(); ++i)
            s.byThreatType[i] = byThreatType[i].load(std::memory_order_relaxed);
        s.startTime = startTime;
        return s;
    }
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class BackupProtectorImpl {
public:
    BackupProtectorImpl() {
        SS_LOG_DEBUG(kLogCat, L"Impl instance created");
    }

    ~BackupProtectorImpl() {
        Shutdown();
    }

    // --- Lifecycle ---
    bool Initialize(const BackupProtectorConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }
    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }
    bool UpdateConfiguration(const BackupProtectorConfiguration& config);
    BackupProtectorConfiguration GetConfiguration() const;

    // --- Detection ---
    bool IsDestructiveTool(const std::wstring& imagePath, const std::wstring& commandLine);
    std::optional<BlockedAttempt> AnalyzeProcess(uint32_t pid, std::wstring_view imagePath,
                                                  std::wstring_view commandLine);
    bool IsDestructiveCommand(std::wstring_view commandLine);
    bool IsProtectedBackupFile(const std::wstring& filePath);
    bool ShouldBlockFileAccess(std::wstring_view filePath, uint32_t pid, uint32_t desiredAccess);

    // --- Service protection ---
    void LockVSSService();
    void UnlockVSSService();
    bool ShouldBlockServiceOperation(std::wstring_view serviceName, uint32_t operation, uint32_t pid);

    // --- Registry protection ---
    bool ShouldBlockRegistryOperation(std::wstring_view keyPath, std::wstring_view valueName,
                                      uint32_t operation, uint32_t pid);

    // --- Whitelist ---
    void AddToWhitelist(std::wstring_view processPath);
    void RemoveFromWhitelist(std::wstring_view processPath);
    bool IsWhitelisted(std::wstring_view processPath) const;
    void WhitelistSigner(std::wstring_view signerName);

    // --- Callbacks ---
    void SetBlockCallback(BlockCallback callback);
    void SetDecisionCallback(DecisionCallback callback);

    // --- Statistics ---
    BackupProtectorStatistics GetStatistics() const;
    void ResetStatistics();
    std::vector<BlockedAttempt> GetRecentBlocks(size_t maxCount) const;

    bool SelfTest();

private:
    // --- Helpers ---
    DangerousToolType IdentifyToolType(std::wstring_view imagePath);
    std::optional<CommandPattern> MatchCommandPattern(std::wstring_view commandLine);
    ProtectionAction DetermineAction(const BlockedAttempt& attempt);
    void RecordBlockedAttempt(const BlockedAttempt& attempt);
    void NotifyBlock(const BlockedAttempt& attempt);
    ProtectionAction QueryDecision(uint32_t pid, const std::wstring& cmdLine,
                                   BackupThreatType threatType);
    bool IsFileProtectedExtension(std::wstring_view filePath);
    bool IsServiceProtected(std::wstring_view serviceName);
    bool IsRegistryKeyProtected(std::wstring_view keyPath);
    std::wstring GetProcessImagePath(uint32_t pid);
    uint32_t GetParentProcessId(uint32_t pid);
    void ExecuteTermination(uint32_t pid, const BlockedAttempt& attempt);

    // --- Members (lock ordering: m_mutex > m_whitelistMutex > m_blockMutex > m_callbackMutex) ---
    mutable std::shared_mutex m_mutex;
    std::atomic<bool>         m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    BackupProtectorConfiguration m_config;

    std::vector<CommandPattern>                     m_patterns;
    std::unordered_map<std::string, std::wregex>    m_compiledPatterns;

    mutable std::shared_mutex                       m_whitelistMutex;
    std::unordered_set<std::wstring>                m_whitelistedPaths;
    std::unordered_set<std::wstring>                m_whitelistedSigners;

    mutable std::mutex                              m_blockMutex;
    std::deque<BlockedAttempt>                      m_blockedAttempts;
    std::atomic<uint64_t>                           m_attemptIdCounter{1};

    mutable std::mutex                              m_callbackMutex;
    BlockCallback                                   m_blockCallback;
    DecisionCallback                                m_decisionCallback;

    InternalStats                                   m_stats;
    std::atomic<bool>                               m_vssLocked{false};

    Whitelist::WhiteListStore*                      m_whitelistStore = nullptr;
};
// ============================================================================
// LIFECYCLE
// ============================================================================

bool BackupProtectorImpl::Initialize(const BackupProtectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCat, L"Already initialized - ignoring duplicate call");
        return true;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCat, L"Configuration validation failed");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }

    try {
        m_config = config;

        // Resolve WhiteListStore (non-fatal if unavailable)
        try {
            m_whitelistStore = &Whitelist::WhiteListStore::Instance();
        } catch (const std::exception& e) {
            SS_LOG_WARN(kLogCat, L"WhiteListStore unavailable: %hs", e.what());
            m_whitelistStore = nullptr;
        }

        // Load built-in patterns, then append user-supplied patterns
        m_patterns = CreateBuiltInPatterns();
        for (const auto& cp : m_config.commandPatterns)
            m_patterns.push_back(cp);

        // Compile regex for every pattern (cache once)
        m_compiledPatterns.clear();
        m_compiledPatterns.reserve(m_patterns.size());
        for (const auto& pat : m_patterns) {
            try {
                auto flags = std::regex_constants::ECMAScript | std::regex_constants::optimize;
                if (!pat.caseSensitive)
                    flags |= std::regex_constants::icase;
                m_compiledPatterns.emplace(pat.patternName,
                                           std::wregex(pat.regexPattern, flags));
            } catch (const std::regex_error& e) {
                SS_LOG_ERROR(kLogCat, L"Regex compile failed for pattern '%hs': %hs",
                             pat.patternName.c_str(), e.what());
            }
        }

        // Seed whitelist from config
        {
            std::unique_lock wlLock(m_whitelistMutex);
            for (const auto& proc : m_config.whitelistedProcesses) {
                if (proc.size() > 0 && m_whitelistedPaths.size() < BackupProtectorConstants::MAX_WHITELIST_SIZE)
                    m_whitelistedPaths.insert(NormalizePathForWhitelist(proc));
            }
            for (const auto& signer : m_config.whitelistedSigners)
                m_whitelistedSigners.insert(StringUtils::ToLowerCopy(signer));
        }

        // If no custom protected extensions, load defaults
        if (m_config.protectedExtensions.empty()) {
            for (const auto* ext : BackupProtectorConstants::PROTECTED_EXTENSIONS)
                m_config.protectedExtensions.emplace_back(ext);
        }

        m_stats.Reset();
        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(kLogCat, L"Initialized v%hs with %zu patterns, %zu whitelisted",
                    BackupProtector::GetVersionString().c_str(),
                    m_patterns.size(), m_whitelistedPaths.size());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_FATAL(kLogCat, L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_FATAL(kLogCat, L"Initialization failed: unknown exception");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void BackupProtectorImpl::Shutdown() {
    // Fast-path check (no lock needed for atomic read)
    if (!m_initialized.load(std::memory_order_acquire))
        return;

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    // Clear state under locks, respecting lock ordering
    {
        std::unique_lock lock(m_mutex);
        m_patterns.clear();
        m_compiledPatterns.clear();
    }
    {
        std::unique_lock wlLock(m_whitelistMutex);
        m_whitelistedPaths.clear();
        m_whitelistedSigners.clear();
    }
    {
        std::lock_guard blockLock(m_blockMutex);
        m_blockedAttempts.clear();
    }
    {
        std::lock_guard cbLock(m_callbackMutex);
        m_blockCallback = nullptr;
        m_decisionCallback = nullptr;
    }

    m_whitelistStore = nullptr;
    m_initialized.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO(kLogCat, L"Shutdown complete");
}

bool BackupProtectorImpl::UpdateConfiguration(const BackupProtectorConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCat, L"Invalid configuration rejected");
        return false;
    }

    std::unique_lock lock(m_mutex);
    m_config = config;
    SS_LOG_INFO(kLogCat, L"Configuration updated at runtime");
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
    if (!m_initialized.load(std::memory_order_acquire))
        return false;

    if (IsWhitelisted(imagePath)) {
        m_stats.whitelistedAllowed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (IdentifyToolType(imagePath) == DangerousToolType::Unknown)
        return false;

    return IsDestructiveCommand(commandLine);
}

std::optional<BlockedAttempt> BackupProtectorImpl::AnalyzeProcess(
    uint32_t pid, std::wstring_view imagePath, std::wstring_view commandLine) {

    if (!m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    // Validate inputs
    if (imagePath.empty() || commandLine.empty() || commandLine.size() > kMaxCmdLineLen)
        return std::nullopt;

    if (IsWhitelisted(imagePath)) {
        m_stats.whitelistedAllowed.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    DangerousToolType toolType = IdentifyToolType(imagePath);
    if (toolType == DangerousToolType::Unknown)
        return std::nullopt;

    auto patternOpt = MatchCommandPattern(commandLine);
    if (!patternOpt)
        return std::nullopt;

    const auto& matchedPattern = *patternOpt;

    // Build blocked attempt record
    BlockedAttempt attempt;
    attempt.attemptId = m_attemptIdCounter.fetch_add(1, std::memory_order_relaxed);
    attempt.timestamp = std::chrono::system_clock::now();
    attempt.pid = pid;
    attempt.commandLine = std::wstring(commandLine);
    attempt.threatType = matchedPattern.threatType;
    attempt.toolType = toolType;

    // Resolve process metadata (best-effort, failures are non-fatal)
    try {
        fs::path imgFsPath(imagePath);
        attempt.processName = imgFsPath.filename().wstring();
        attempt.processPath = std::wstring(imagePath);
    } catch (...) {
        attempt.processPath = std::wstring(imagePath);
    }

    attempt.parentPid = GetParentProcessId(pid);
    if (attempt.parentPid != 0) {
        try {
            auto parentPath = GetProcessImagePath(attempt.parentPid);
            if (!parentPath.empty())
                attempt.parentName = fs::path(parentPath).filename().wstring();
        } catch (...) { /* best-effort */ }
    }

    // Determine action
    attempt.action = DetermineAction(attempt);

    // Allow external decision callback to override
    ProtectionAction cbAction = QueryDecision(pid, attempt.commandLine, matchedPattern.threatType);
    if (cbAction != ProtectionAction::Allow)
        attempt.action = cbAction;

    // Execute block / block+kill
    if (attempt.action == ProtectionAction::Block ||
        attempt.action == ProtectionAction::BlockKill) {

        RecordBlockedAttempt(attempt);
        NotifyBlock(attempt);

        m_stats.attemptsBlocked.fetch_add(1, std::memory_order_relaxed);

        auto threatIdx = static_cast<size_t>(matchedPattern.threatType);
        if (threatIdx < m_stats.byThreatType.size())
            m_stats.byThreatType[threatIdx].fetch_add(1, std::memory_order_relaxed);

        switch (matchedPattern.threatType) {
            case BackupThreatType::VSSDelete:
            case BackupThreatType::VSSResize:
            case BackupThreatType::VSSDisable:
            case BackupThreatType::WMIShadowDelete:
                m_stats.vssDeletesBlocked.fetch_add(1, std::memory_order_relaxed);
                break;
            case BackupThreatType::BackupDelete:
                m_stats.fileDeletesBlocked.fetch_add(1, std::memory_order_relaxed);
                break;
            case BackupThreatType::ServiceStop:
                m_stats.serviceStopsBlocked.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }

        SS_LOG_WARN(kLogCat,
            L"BLOCKED PID=%u Tool=%hs Threat=%hs Action=%hs CmdLine=%.256ls",
            pid,
            GetToolTypeName(toolType).data(),
            GetThreatTypeName(matchedPattern.threatType).data(),
            GetProtectionActionName(attempt.action).data(),
            std::wstring(commandLine).c_str());

        // Terminate process if BlockKill
        if (attempt.action == ProtectionAction::BlockKill)
            ExecuteTermination(pid, attempt);
    }

    return attempt;
}

bool BackupProtectorImpl::IsDestructiveCommand(std::wstring_view commandLine) {
    if (commandLine.empty() || commandLine.size() > kMaxCmdLineLen)
        return false;

    std::shared_lock lock(m_mutex);

    // Lowercase the command line ONCE outside the loop
    const std::wstring cmdLower = StringUtils::ToLowerCopy(std::wstring(commandLine));

    for (const auto& pattern : m_patterns) {
        // Fast keyword check first
        bool allMatch = true;
        for (const auto& kw : pattern.keywords) {
            if (cmdLower.find(StringUtils::ToLowerCopy(kw)) == std::wstring::npos) {
                allMatch = false;
                break;
            }
        }
        if (!allMatch)
            continue;

        // Regex confirmation against the cached compiled pattern
        auto it = m_compiledPatterns.find(pattern.patternName);
        if (it != m_compiledPatterns.end()) {
            try {
                if (std::regex_search(commandLine.begin(), commandLine.end(), it->second))
                    return true;
            } catch (const std::regex_error&) {
                // Malformed regex in pattern - skip, already logged at init
                continue;
            }
        }
    }
    return false;
}

bool BackupProtectorImpl::IsProtectedBackupFile(const std::wstring& filePath) {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;

    std::shared_lock lock(m_mutex);
    if (!m_config.protectBackupFiles)
        return false;

    return IsFileProtectedExtension(filePath);
}

bool BackupProtectorImpl::ShouldBlockFileAccess(std::wstring_view filePath,
                                                 uint32_t pid,
                                                 uint32_t desiredAccess) {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;

    {
        std::shared_lock lock(m_mutex);
        if (!m_config.protectBackupFiles)
            return false;
    }

    if (!IsFileProtectedExtension(filePath))
        return false;

    // Resolve caller image and check whitelist
    std::wstring callerPath = GetProcessImagePath(pid);
    if (IsWhitelisted(callerPath))
        return false;

    // Block delete, write-data, write-dac, and write-owner on backup files
    constexpr uint32_t DANGEROUS_ACCESS =
        DELETE                  |   // 0x00010000
        FILE_WRITE_DATA         |   // 0x00000002
        WRITE_DAC               |   // 0x00040000
        WRITE_OWNER;                // 0x00080000

    if (desiredAccess & DANGEROUS_ACCESS) {
        SS_LOG_WARN(kLogCat,
            L"Blocking file access: PID=%u Access=0x%08X Path=%.512ls",
            pid, desiredAccess, std::wstring(filePath).c_str());
        m_stats.fileDeletesBlocked.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    return false;
}
// ============================================================================
// SERVICE PROTECTION
// ============================================================================

void BackupProtectorImpl::LockVSSService() {
    if (!m_initialized.load(std::memory_order_acquire))
        return;

    if (m_vssLocked.exchange(true, std::memory_order_acq_rel)) {
        SS_LOG_DEBUG(kLogCat, L"VSS service already locked");
        return;
    }

#ifdef _WIN32
    UniqueScHandle hSCM(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!hSCM) {
        SS_LOG_LAST_ERROR(kLogCat, L"OpenSCManagerW failed for VSS lock");
        m_vssLocked.store(false, std::memory_order_release);
        return;
    }

    UniqueScHandle hService(::OpenServiceW(hSCM.get(), L"VSS",
                                            SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG));
    if (!hService) {
        SS_LOG_LAST_ERROR(kLogCat, L"OpenServiceW(VSS) failed");
        m_vssLocked.store(false, std::memory_order_release);
        return;
    }

    // Set auto-start to prevent disable
    if (!::ChangeServiceConfigW(hService.get(), SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                                 nullptr, nullptr, nullptr, nullptr)) {
        SS_LOG_LAST_ERROR(kLogCat, L"ChangeServiceConfigW(VSS auto-start) failed");
    }

    // Configure failure actions: restart on any failure
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 1000 },
        { SC_ACTION_RESTART, 2000 },
        { SC_ACTION_RESTART, 5000 }
    };
    SERVICE_FAILURE_ACTIONSW failActions{};
    failActions.dwResetPeriod = 86400;  // 24h reset window
    failActions.cActions = 3;
    failActions.lpsaActions = actions;

    if (!::ChangeServiceConfig2W(hService.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failActions)) {
        SS_LOG_LAST_ERROR(kLogCat, L"ChangeServiceConfig2W(VSS failure actions) failed");
    }

    SS_LOG_INFO(kLogCat, L"VSS service locked: auto-start + auto-restart on failure");
#endif
}

void BackupProtectorImpl::UnlockVSSService() {
    if (!m_initialized.load(std::memory_order_acquire))
        return;

    if (!m_vssLocked.exchange(false, std::memory_order_acq_rel))
        return;  // wasn't locked

    SS_LOG_INFO(kLogCat, L"VSS service lock released");
}

bool BackupProtectorImpl::ShouldBlockServiceOperation(std::wstring_view serviceName,
                                                       uint32_t operation,
                                                       uint32_t pid) {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;

    {
        std::shared_lock lock(m_mutex);
        if (!m_config.protectServices)
            return false;
    }

    if (!IsServiceProtected(serviceName))
        return false;

    std::wstring callerPath = GetProcessImagePath(pid);
    if (IsWhitelisted(callerPath))
        return false;

    // Block stop, delete, and config-change operations
    constexpr uint32_t kServiceStop        = 0x0020;  // SERVICE_STOP
    constexpr uint32_t kServiceDelete      = DELETE;
    constexpr uint32_t kServiceChangeConfig = 0x0002;  // SERVICE_CHANGE_CONFIG

    if (operation & (kServiceStop | kServiceDelete | kServiceChangeConfig)) {
        SS_LOG_WARN(kLogCat,
            L"Blocking service op: Service=%ls Op=0x%08X PID=%u Caller=%ls",
            std::wstring(serviceName).c_str(), operation,
            pid, callerPath.c_str());
        m_stats.serviceStopsBlocked.fetch_add(1, std::memory_order_relaxed);
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
    if (!m_initialized.load(std::memory_order_acquire))
        return false;

    {
        std::shared_lock lock(m_mutex);
        if (!m_config.protectRegistry)
            return false;
    }

    if (!IsRegistryKeyProtected(keyPath))
        return false;

    std::wstring callerPath = GetProcessImagePath(pid);
    if (IsWhitelisted(callerPath))
        return false;

    constexpr uint32_t kRegSetValue    = KEY_SET_VALUE;      // 0x0002
    constexpr uint32_t kRegCreateSubKey = KEY_CREATE_SUB_KEY; // 0x0004

    if (operation & (kRegSetValue | kRegCreateSubKey | DELETE)) {
        SS_LOG_WARN(kLogCat,
            L"Blocking registry op: Key=%ls Value=%ls Op=0x%08X PID=%u",
            std::wstring(keyPath).c_str(),
            std::wstring(valueName).c_str(),
            operation, pid);
        m_stats.registryChangesBlocked.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    return false;
}
// ============================================================================
// WHITELIST
// ============================================================================

void BackupProtectorImpl::AddToWhitelist(std::wstring_view processPath) {
    if (processPath.empty())
        return;

    std::unique_lock lock(m_whitelistMutex);
    if (m_whitelistedPaths.size() >= BackupProtectorConstants::MAX_WHITELIST_SIZE) {
        SS_LOG_WARN(kLogCat, L"Whitelist at capacity (%zu), rejecting add",
                    BackupProtectorConstants::MAX_WHITELIST_SIZE);
        return;
    }
    auto normalized = NormalizePathForWhitelist(processPath);
    m_whitelistedPaths.insert(std::move(normalized));
    SS_LOG_INFO(kLogCat, L"Added to whitelist: %ls",
                std::wstring(processPath).c_str());
}

void BackupProtectorImpl::RemoveFromWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPaths.erase(NormalizePathForWhitelist(processPath));
    SS_LOG_INFO(kLogCat, L"Removed from whitelist: %ls",
                std::wstring(processPath).c_str());
}

bool BackupProtectorImpl::IsWhitelisted(std::wstring_view processPath) const {
    if (processPath.empty())
        return false;

    std::wstring pathNormalized = NormalizePathForWhitelist(processPath);

    {
        std::shared_lock lock(m_whitelistMutex);
        if (m_whitelistedPaths.count(pathNormalized))
            return true;
    }

    // Fallback to central WhiteListStore
    if (m_whitelistStore) {
        try {
            auto result = m_whitelistStore->IsWhitelisted(processPath);
            // LookupResult's implicit bool indicates a positive match
            if (static_cast<bool>(result))
                return true;
        } catch (const std::exception& e) {
            SS_LOG_WARN(kLogCat, L"WhiteListStore query failed: %hs", e.what());
        } catch (...) {
            SS_LOG_WARN(kLogCat, L"WhiteListStore query failed: unknown error");
        }
    }

    return false;
}

void BackupProtectorImpl::WhitelistSigner(std::wstring_view signerName) {
    if (signerName.empty())
        return;

    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedSigners.insert(StringUtils::ToLowerCopy(std::wstring(signerName)));
    SS_LOG_INFO(kLogCat, L"Whitelisted signer: %ls",
                std::wstring(signerName).c_str());
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
    return m_stats.Snapshot();
}

void BackupProtectorImpl::ResetStatistics() {
    m_stats.Reset();
    SS_LOG_INFO(kLogCat, L"Statistics reset");
}

std::vector<BlockedAttempt> BackupProtectorImpl::GetRecentBlocks(size_t maxCount) const {
    std::lock_guard lock(m_blockMutex);

    size_t count = std::min(maxCount, m_blockedAttempts.size());
    std::vector<BlockedAttempt> result;
    result.reserve(count);

    // Deque is front-newest, copy the N most recent
    auto it = m_blockedAttempts.begin();
    for (size_t i = 0; i < count; ++i, ++it)
        result.push_back(*it);

    return result;
}
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

DangerousToolType BackupProtectorImpl::IdentifyToolType(std::wstring_view imagePath) {
    std::wstring filename;
    try {
        filename = fs::path(imagePath).filename().wstring();
    } catch (...) {
        return DangerousToolType::Unknown;
    }

    std::wstring lower = StringUtils::ToLowerCopy(filename);

    if (lower == L"vssadmin.exe")                         return DangerousToolType::VSSAdmin;
    if (lower == L"wbadmin.exe")                          return DangerousToolType::WBAdmin;
    if (lower == L"bcdedit.exe")                          return DangerousToolType::BCDEdit;
    if (lower == L"wmic.exe")                             return DangerousToolType::WMIC;
    if (lower == L"powershell.exe" || lower == L"pwsh.exe") return DangerousToolType::PowerShell;
    if (lower == L"cmd.exe")                              return DangerousToolType::CMD;
    if (lower == L"diskshadow.exe")                       return DangerousToolType::DiskShadow;

    return DangerousToolType::Unknown;
}

std::optional<CommandPattern> BackupProtectorImpl::MatchCommandPattern(
    std::wstring_view commandLine) {

    std::shared_lock lock(m_mutex);

    // Lowercase once for all keyword comparisons
    const std::wstring cmdLower = StringUtils::ToLowerCopy(std::wstring(commandLine));

    for (const auto& pattern : m_patterns) {
        // Keyword pre-filter (fast reject)
        bool allKeywordsPresent = true;
        for (const auto& kw : pattern.keywords) {
            if (cmdLower.find(StringUtils::ToLowerCopy(kw)) == std::wstring::npos) {
                allKeywordsPresent = false;
                break;
            }
        }
        if (!allKeywordsPresent)
            continue;

        // Regex confirmation
        auto it = m_compiledPatterns.find(pattern.patternName);
        if (it != m_compiledPatterns.end()) {
            try {
                if (std::regex_search(commandLine.begin(), commandLine.end(), it->second))
                    return pattern;
            } catch (const std::regex_error&) {
                continue;
            }
        }
    }

    return std::nullopt;
}

ProtectionAction BackupProtectorImpl::DetermineAction(const BlockedAttempt& attempt) {
    std::shared_lock lock(m_mutex);

    ProtectionAction action = m_config.defaultAction;

    // Critical threats always get BlockKill if kill-on-detection is enabled
    if (m_config.killOnDetection) {
        switch (attempt.threatType) {
            case BackupThreatType::VSSDelete:
            case BackupThreatType::WMIShadowDelete:
            case BackupThreatType::RecoveryDisable:
                action = ProtectionAction::BlockKill;
                break;
            default:
                break;
        }
    }

    return action;
}

void BackupProtectorImpl::RecordBlockedAttempt(const BlockedAttempt& attempt) {
    std::lock_guard lock(m_blockMutex);
    m_blockedAttempts.push_front(attempt);

    while (m_blockedAttempts.size() > kMaxBlockedHistory)
        m_blockedAttempts.pop_back();
}

void BackupProtectorImpl::NotifyBlock(const BlockedAttempt& attempt) {
    BlockCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_blockCallback;  // copy under lock
    }
    if (cb) {
        try {
            cb(attempt);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Block callback threw: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Block callback threw unknown exception");
        }
    }

    // ── Direct AlertSystem wiring ──
    try {
        using namespace Communication;
        if (AlertSystem::HasInstance()) {
            std::string subject = "Backup threat blocked (PID " + std::to_string(attempt.pid) + ")";
            (void)AlertSystem::Instance().RaiseAlert(
                AlertSeverity::Critical, AlertType::ThreatDetection,
                subject, attempt.ToJson(), "BackupProtector");
        }
    } catch (...) {}

    // ── Direct TelemetryCollector wiring ──
    try {
        using namespace Communication;
        if (TelemetryCollector::HasInstance()) {
            std::map<std::string, std::string> data;
            data["pid"] = std::to_string(attempt.pid);
            data["threat_type"] = std::string(GetThreatTypeName(attempt.threatType));
            data["action"] = std::string(GetProtectionActionName(attempt.action));
            data["process_name"] = Utils::StringUtils::ToNarrow(attempt.processName);
            data["mitre_technique"] = "T1490";
            TelemetryCollector::Instance().RecordCustom("backup_threat_blocked", data);
        }
    } catch (...) {}
}

ProtectionAction BackupProtectorImpl::QueryDecision(uint32_t pid,
                                                     const std::wstring& cmdLine,
                                                     BackupThreatType threatType) {
    DecisionCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_decisionCallback;  // copy under lock
    }
    if (cb) {
        try {
            return cb(pid, cmdLine, threatType);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Decision callback threw: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Decision callback threw unknown exception");
        }
    }
    return ProtectionAction::Allow;
}

bool BackupProtectorImpl::IsFileProtectedExtension(std::wstring_view filePath) {
    std::wstring ext;
    try {
        ext = fs::path(filePath).extension().wstring();
    } catch (...) {
        return false;
    }
    if (ext.empty())
        return false;

    std::wstring extLower = StringUtils::ToLowerCopy(ext);

    std::shared_lock lock(m_mutex);
    for (const auto& protExt : m_config.protectedExtensions) {
        if (extLower == StringUtils::ToLowerCopy(protExt))
            return true;
    }

    return false;
}

bool BackupProtectorImpl::IsServiceProtected(std::wstring_view serviceName) {
    std::wstring lower = StringUtils::ToLowerCopy(std::wstring(serviceName));
    for (const auto& svc : kProtectedServiceNames) {
        if (lower == StringUtils::ToLowerCopy(svc))
            return true;
    }

    // Also check config
    std::shared_lock lock(m_mutex);
    for (const auto& ps : m_config.protectedServices) {
        if (StringUtils::IEquals(serviceName, ps.serviceName))
            return true;
    }
    return false;
}

bool BackupProtectorImpl::IsRegistryKeyProtected(std::wstring_view keyPath) {
    std::wstring pathLower = StringUtils::ToLowerCopy(std::wstring(keyPath));
    for (const auto& protKey : kProtectedRegistryPaths) {
        if (pathLower.find(StringUtils::ToLowerCopy(protKey)) != std::wstring::npos)
            return true;
    }

    std::shared_lock lock(m_mutex);
    for (const auto& prk : m_config.protectedRegistryKeys) {
        std::wstring prkLower = StringUtils::ToLowerCopy(prk.path);
        if (pathLower.find(prkLower) != std::wstring::npos)
            return true;
    }
    return false;
}

std::wstring BackupProtectorImpl::GetProcessImagePath(uint32_t pid) {
    try {
        return Utils::ProcessUtils::GetProcessImagePath(pid);
    } catch (...) {
        return {};
    }
}

uint32_t BackupProtectorImpl::GetParentProcessId(uint32_t pid) {
    try {
        return Utils::ProcessUtils::GetParentProcessId(pid);
    } catch (...) {
        return 0;
    }
}

void BackupProtectorImpl::ExecuteTermination(uint32_t pid, const BlockedAttempt& attempt) {
    SS_LOG_WARN(kLogCat, L"Terminating PID=%u (Threat=%hs)", pid,
                GetThreatTypeName(attempt.threatType).data());

    try {
        auto result = Core::Process::ProcessKiller::Terminate(
            pid, Core::Process::KillMethod::Auto);

        if (result == Core::Process::KillResult::Success ||
            result == Core::Process::KillResult::AlreadyDead) {
            m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(kLogCat, L"Process PID=%u terminated successfully", pid);
        } else {
            SS_LOG_ERROR(kLogCat, L"Process PID=%u termination failed (result=%u)",
                         pid, static_cast<uint32_t>(result));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"Exception terminating PID=%u: %hs", pid, e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCat, L"Unknown exception terminating PID=%u", pid);
    }
}
// ============================================================================
// SELF-TEST
// ============================================================================

bool BackupProtectorImpl::SelfTest() {
    SS_LOG_INFO(kLogCat, L"Running self-test...");

    try {
        // Test 1: Tool identification
        if (IdentifyToolType(L"C:\\Windows\\System32\\vssadmin.exe") != DangerousToolType::VSSAdmin) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: VSSAdmin identification");
            return false;
        }
        if (IdentifyToolType(L"C:\\Windows\\System32\\bcdedit.exe") != DangerousToolType::BCDEdit) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: BCDEdit identification");
            return false;
        }

        // Test 2: Destructive command detection
        if (!IsDestructiveCommand(L"vssadmin.exe delete shadows /all /quiet")) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: vssadmin pattern match");
            return false;
        }
        if (!IsDestructiveCommand(L"wmic.exe shadowcopy delete /nointeractive")) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: wmic pattern match");
            return false;
        }

        // Test 3: Non-destructive command (must NOT match)
        if (IsDestructiveCommand(L"vssadmin.exe list shadows")) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: false positive on list shadows");
            return false;
        }

        // Test 4: Protected backup file extension
        if (m_config.protectBackupFiles && !IsProtectedBackupFile(L"C:\\Backup\\data.vhd")) {
            SS_LOG_ERROR(kLogCat, L"Self-test FAIL: .vhd not detected as protected");
            return false;
        }

        // Test 5: Whitelist round-trip
        {
            const std::wstring testPath = L"C:\\SelfTest\\trusted_test.exe";
            AddToWhitelist(testPath);
            if (!IsWhitelisted(testPath)) {
                SS_LOG_ERROR(kLogCat, L"Self-test FAIL: whitelist add/check");
                return false;
            }
            RemoveFromWhitelist(testPath);
            if (IsWhitelisted(testPath)) {
                SS_LOG_ERROR(kLogCat, L"Self-test FAIL: whitelist remove");
                return false;
            }
        }

        SS_LOG_INFO(kLogCat, L"Self-test PASSED (5/5 checks)");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON + PUBLIC API FORWARDING
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
    uint32_t pid, std::wstring_view imagePath, std::wstring_view commandLine) {
    return m_impl->AnalyzeProcess(pid, imagePath, commandLine);
}

bool BackupProtector::IsDestructiveCommand(std::wstring_view commandLine) {
    return m_impl->IsDestructiveCommand(commandLine);
}

bool BackupProtector::IsProtectedBackupFile(const std::wstring& filePath) {
    return m_impl->IsProtectedBackupFile(filePath);
}

bool BackupProtector::ShouldBlockFileAccess(std::wstring_view filePath,
                                             uint32_t pid, uint32_t desiredAccess) {
    return m_impl->ShouldBlockFileAccess(filePath, pid, desiredAccess);
}

void BackupProtector::LockVSSService() {
    m_impl->LockVSSService();
}

void BackupProtector::UnlockVSSService() {
    m_impl->UnlockVSSService();
}

bool BackupProtector::ShouldBlockServiceOperation(std::wstring_view serviceName,
                                                   uint32_t operation, uint32_t pid) {
    return m_impl->ShouldBlockServiceOperation(serviceName, operation, pid);
}

bool BackupProtector::ShouldBlockRegistryOperation(std::wstring_view keyPath,
                                                    std::wstring_view valueName,
                                                    uint32_t operation, uint32_t pid) {
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
    if (commandLine.empty())
        return false;

    std::wstring cmdLower = StringUtils::ToLowerCopy(std::wstring(commandLine));

    for (const auto& kw : keywords) {
        if (cmdLower.find(StringUtils::ToLowerCopy(kw)) == std::wstring::npos)
            return false;
    }

    try {
        auto flags = std::regex_constants::ECMAScript | std::regex_constants::optimize;
        if (!caseSensitive)
            flags |= std::regex_constants::icase;
        std::wregex rx(regexPattern, flags);
        return std::regex_search(commandLine.begin(), commandLine.end(), rx);
    } catch (const std::regex_error&) {
        return false;
    }
}

void BackupProtectorStatistics::Reset() noexcept {
    attemptsBlocked = 0;
    processesTerminated = 0;
    vssDeletesBlocked = 0;
    fileDeletesBlocked = 0;
    serviceStopsBlocked = 0;
    registryChangesBlocked = 0;
    whitelistedAllowed = 0;
    byThreatType.fill(0);
    startTime = Clock::now();
}

std::string BackupProtectorStatistics::ToJson() const {
    nlohmann::json j;
    j["attemptsBlocked"]      = attemptsBlocked;
    j["processesTerminated"]  = processesTerminated;
    j["vssDeletesBlocked"]    = vssDeletesBlocked;
    j["fileDeletesBlocked"]   = fileDeletesBlocked;
    j["serviceStopsBlocked"]  = serviceStopsBlocked;
    j["registryChangesBlocked"] = registryChangesBlocked;
    j["whitelistedAllowed"]   = whitelistedAllowed;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = elapsed;

    return j.dump();
}

std::string BlockedAttempt::ToJson() const {
    nlohmann::json j;
    j["attemptId"]    = attemptId;
    j["pid"]          = pid;
    j["processName"]  = StringUtils::ToNarrow(processName);
    j["processPath"]  = StringUtils::ToNarrow(processPath);
    j["commandLine"]  = StringUtils::ToNarrow(commandLine);
    j["parentPid"]    = parentPid;
    j["parentName"]   = StringUtils::ToNarrow(parentName);
    j["threatType"]   = static_cast<int>(threatType);
    j["toolType"]     = static_cast<int>(toolType);
    j["action"]       = static_cast<int>(action);
    j["target"]       = StringUtils::ToNarrow(target);
    j["userSid"]      = StringUtils::ToNarrow(userSid);
    j["details"]      = StringUtils::ToNarrow(details);
    return j.dump();
}

bool BackupProtectorConfiguration::IsValid() const noexcept {
    // At least one protection category must be enabled
    if (enabled && !protectVSS && !protectBackupFiles && !protectBCD &&
        !protectServices && !protectRegistry)
        return false;

    // Whitelist size within bounds
    if (whitelistedProcesses.size() > BackupProtectorConstants::MAX_WHITELIST_SIZE)
        return false;

    // Validate that no whitelisted paths are empty strings
    for (const auto& p : whitelistedProcesses) {
        if (p.empty())
            return false;
    }

    return true;
}

void BackupProtectorConfiguration::LoadDefaultPatterns() {
    commandPatterns = CreateBuiltInPatterns();
}

void BackupProtectorConfiguration::LoadDefaultServices() {
    protectedServices.clear();
    for (const auto& svc : kProtectedServiceNames) {
        ProtectedService ps;
        ps.serviceName = svc;
        ps.displayName = svc;
        protectedServices.push_back(std::move(ps));
    }
}

// ============================================================================
// UTILITY FUNCTIONS (match header declarations exactly)
// ============================================================================

std::string_view GetThreatTypeName(BackupThreatType type) noexcept {
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

std::string_view GetToolTypeName(DangerousToolType type) noexcept {
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

DangerousToolType IdentifyTool(std::wstring_view processName) noexcept {
    if (processName.empty())
        return DangerousToolType::Unknown;

    std::wstring lower;
    try {
        lower = StringUtils::ToLowerCopy(std::wstring(processName));
    } catch (...) {
        return DangerousToolType::Unknown;
    }

    // Extract filename if full path provided
    auto pos = lower.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        lower = lower.substr(pos + 1);

    if (lower == L"vssadmin.exe")                         return DangerousToolType::VSSAdmin;
    if (lower == L"wbadmin.exe")                          return DangerousToolType::WBAdmin;
    if (lower == L"bcdedit.exe")                          return DangerousToolType::BCDEdit;
    if (lower == L"wmic.exe")                             return DangerousToolType::WMIC;
    if (lower == L"powershell.exe" || lower == L"pwsh.exe") return DangerousToolType::PowerShell;
    if (lower == L"cmd.exe")                              return DangerousToolType::CMD;
    if (lower == L"diskshadow.exe")                       return DangerousToolType::DiskShadow;

    return DangerousToolType::Unknown;
}

BackupThreatType IdentifyThreat(std::wstring_view commandLine) noexcept {
    if (commandLine.empty())
        return BackupThreatType::Unknown;

    std::wstring lower;
    try {
        lower = StringUtils::ToLowerCopy(std::wstring(commandLine));
    } catch (...) {
        return BackupThreatType::Unknown;
    }

    // Ordered by severity (most critical first)
    if (lower.find(L"delete") != std::wstring::npos && lower.find(L"shadows") != std::wstring::npos)
        return BackupThreatType::VSSDelete;
    if (lower.find(L"shadowcopy") != std::wstring::npos && lower.find(L"delete") != std::wstring::npos)
        return BackupThreatType::WMIShadowDelete;
    if (lower.find(L"win32_shadowcopy") != std::wstring::npos)
        return BackupThreatType::WMIShadowDelete;
    if (lower.find(L"recoveryenabled") != std::wstring::npos && lower.find(L"no") != std::wstring::npos)
        return BackupThreatType::RecoveryDisable;
    if (lower.find(L"bootstatuspolicy") != std::wstring::npos)
        return BackupThreatType::BootConfigChange;
    if (lower.find(L"resize") != std::wstring::npos && lower.find(L"shadowstorage") != std::wstring::npos)
        return BackupThreatType::VSSResize;
    if (lower.find(L"delete") != std::wstring::npos &&
        (lower.find(L"catalog") != std::wstring::npos || lower.find(L"backup") != std::wstring::npos))
        return BackupThreatType::BackupDelete;
    if (lower.find(L"stop") != std::wstring::npos && lower.find(L"vss") != std::wstring::npos)
        return BackupThreatType::ServiceStop;

    return BackupThreatType::Unknown;
}

// ============================================================================
// KERNEL BRIDGE
// ============================================================================

void BackupProtector::OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                                             std::wstring_view commandLine, bool isCreate) {
    try {
        if (!isCreate || !IsInitialized()) return;
        auto result = AnalyzeProcess(processId, imagePath, commandLine);
        if (result.has_value()) {
            SS_LOG_WARN(L"BackupProtector",
                L"Kernel process notify: detected threat PID=%u type=%u",
                processId, static_cast<unsigned>(result->threatType));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"BackupProtector", L"OnKernelProcessNotify error: %hs", e.what());
    }
}

void BackupProtector::OnKernelImageLoad(uint32_t /*processId*/, std::wstring_view /*imagePath*/,
                                         uint64_t /*imageBase*/, size_t /*imageSize*/) {
    // BackupProtector operates on process creation and file access, not image loads.
}

bool BackupProtector::RequestKernelProcessBlock(uint32_t processId, const std::wstring& reason) {
    try {
        using namespace Communication;
        if (!IPCManager::HasInstance() || !IPCManager::Instance().IsFilterPortConnected())
            return false;
#pragma pack(push, 1)
        struct KernelBlockRequest {
            uint32_t messageType;
            uint32_t processId;
            wchar_t  reason[256];
        };
#pragma pack(pop)
        KernelBlockRequest req{};
        req.messageType = 0x30;
        req.processId = processId;
        wcsncpy_s(req.reason, _countof(req.reason), reason.c_str(), _TRUNCATE);
        req.reason[_countof(req.reason) - 1] = L'\0';

        bool result = IPCManager::Instance().SendToKernel(&req, sizeof(req));
        if (result)
            SS_LOG_INFO(L"BackupProtector", L"Kernel block requested for PID=%u", processId);
        return result;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"BackupProtector", L"RequestKernelProcessBlock error: %hs", e.what());
        return false;
    }
}

// ============================================================================
// CROSS-MODULE WIRING
// ============================================================================

void BackupProtector::ReportThreatToAlertSystem(const BlockedAttempt& attempt) {
    try {
        using namespace Communication;
        if (!AlertSystem::HasInstance()) return;

        std::string subject = "Backup Threat " +
            std::string(GetProtectionActionName(attempt.action)) +
            " — " + std::string(GetThreatTypeName(attempt.threatType)) +
            " (PID " + std::to_string(attempt.pid) + ")";

        (void)AlertSystem::Instance().RaiseAlert(
            AlertSeverity::Critical, AlertType::ThreatDetection,
            subject, attempt.ToJson(), "BackupProtector");
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"BackupProtector", L"AlertSystem report failed: %hs", e.what());
    }
}

void BackupProtector::ReportDetectionTelemetry(const BlockedAttempt& attempt) {
    try {
        using namespace Communication;
        if (!TelemetryCollector::HasInstance()) return;

        std::map<std::string, std::string> data;
        data["pid"] = std::to_string(attempt.pid);
        data["threat_type"] = std::string(GetThreatTypeName(attempt.threatType));
        data["action"] = std::string(GetProtectionActionName(attempt.action));
        data["process_name"] = Utils::StringUtils::ToNarrow(attempt.processName);
        data["mitre_technique"] = "T1490";

        TelemetryCollector::Instance().RecordCustom("backup_threat_detection", data);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"BackupProtector", L"Telemetry report failed: %hs", e.what());
    }
}

}  // namespace Ransomware
}  // namespace ShadowStrike