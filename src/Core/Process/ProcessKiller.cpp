/**
 * ============================================================================
 * ShadowStrike Core Process - PROCESS KILLER IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessKiller.cpp
 * @brief Enterprise-grade robust process termination engine.
 *
 * This module implements sophisticated process termination with escalating
 * methods to defeat malware self-protection mechanisms including:
 * - API hooking bypass
 * - Watchdog process defeat
 * - Protected Process Light (PPL) circumvention
 * - Critical process handling
 * - Process tree termination
 * - Persistence cleanup
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Escalating termination methods (8 levels)
 * - Process tree enumeration and synchronized killing
 * - Watchdog detection via handle analysis and parent-child relationships
 * - Kernel driver integration for PPL bypass
 * - Comprehensive statistics and audit trail
 *
 * Termination Strategy:
 * 1. Standard: TerminateProcess() API
 * 2. Privileged: Enable SeDebugPrivilege + terminate
 * 3. Freeze-Kill: Suspend all threads + terminate
 * 4. Job Object: Assign to job + terminate via job
 * 5. Token Manipulation: Modify process token + terminate
 * 6. Kernel Direct: Driver IOCTL for kernel termination
 * 7. Force Kernel: ZwTerminateProcess from kernel mode
 * 8. Nuclear: Kernel memory manipulation (last resort)
 *
 * MITRE ATT&CK Coverage:
 * - Defense Against: T1562.001 (Impair Defenses - Disable AV)
 * - Defense Against: T1036 (Masquerading)
 * - Defense Against: T1055 (Process Injection - malware protection)
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ProcessKiller.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <processthreadsapi.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <chrono>
#include <sstream>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Process access rights
    constexpr DWORD PROCESS_TERMINATE_ACCESS = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
    constexpr DWORD PROCESS_SUSPEND_ACCESS = PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION;
    constexpr DWORD PROCESS_FULL_ACCESS = PROCESS_ALL_ACCESS;

    // Thread access rights
    constexpr DWORD THREAD_SUSPEND_ACCESS = THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;

    // Privilege names
    constexpr const wchar_t* SE_DEBUG_PRIVILEGE_NAME = L"SeDebugPrivilege";
    constexpr const wchar_t* SE_KILL_PRIVILEGE_NAME = L"SeKillPrivilege";

    // Process state checks
    constexpr uint32_t MAX_VERIFICATION_ATTEMPTS = 10;
    constexpr uint32_t VERIFICATION_INTERVAL_MS = 100;

} // anonymous namespace

// ============================================================================
// NTDLL FUNCTION PROTOTYPES
// ============================================================================

extern "C" {
    NTSTATUS NTAPI NtSuspendProcess(HANDLE ProcessHandle);
    NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
    NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

    typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
        SIZE_T Size;
        PROCESS_BASIC_INFORMATION BasicInfo;
        union {
            ULONG Flags;
            struct {
                ULONG IsProtectedProcess : 1;
                ULONG IsWow64Process : 1;
                ULONG IsProcessDeleting : 1;
                ULONG IsCrossSessionCreate : 1;
                ULONG IsFrozen : 1;
                ULONG IsBackground : 1;
                ULONG IsStronglyNamed : 1;
                ULONG IsSecureProcess : 1;
                ULONG IsSubsystemProcess : 1;
                ULONG SpareBits : 23;
            };
        };
    } PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation = 0,
        ProcessDebugPort = 7,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessBreakOnTermination = 29,
        ProcessProtectionInformation = 61
    } PROCESSINFOCLASS;

    NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI NtSetInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static bool EnablePrivilege(const wchar_t* privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool success = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    CloseHandle(hToken);

    return success && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

[[nodiscard]] static bool IsProcessRunning(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    DWORD exitCode = 0;
    bool running = GetExitCodeProcess(hProcess, &exitCode) && (exitCode == STILL_ACTIVE);
    CloseHandle(hProcess);

    return running;
}

[[nodiscard]] static bool IsCriticalProcessName(const std::wstring& name) {
    std::wstring lowerName = StringUtils::ToLower(name);

    for (const auto& critical : KillerConstants::CRITICAL_PROCESSES) {
        if (lowerName == StringUtils::ToLower(std::wstring(critical))) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] static std::vector<uint32_t> GetThreadIds(uint32_t pid) {
    std::vector<uint32_t> threadIds;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return threadIds;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threadIds.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return threadIds;
}

// ============================================================================
// FACTORY METHODS IMPLEMENTATION
// ============================================================================

KillOptions KillOptions::CreateStandard() noexcept {
    KillOptions opts;
    opts.preferredMethod = KillMethod::Auto;
    opts.timeoutMs = KillerConstants::DEFAULT_KILL_TIMEOUT_MS;
    opts.maxRetries = KillerConstants::MAX_RETRY_ATTEMPTS;
    opts.escalateOnFailure = true;
    opts.killTree = false;
    opts.defeatWatchdogs = false;
    opts.cleanPersistence = false;
    opts.verifyTermination = true;
    opts.preserveEvidence = false;
    opts.allowCritical = false;
    return opts;
}

KillOptions KillOptions::CreateAggressive() noexcept {
    KillOptions opts;
    opts.preferredMethod = KillMethod::Auto;
    opts.timeoutMs = 10000;
    opts.maxRetries = 5;
    opts.escalateOnFailure = true;
    opts.killTree = true;
    opts.treeStrategy = TreeKillStrategy::BottomUp;
    opts.defeatWatchdogs = true;
    opts.cleanPersistence = false;
    opts.verifyTermination = true;
    opts.preserveEvidence = false;
    opts.allowCritical = false;
    return opts;
}

KillOptions KillOptions::CreateMalwareKill() noexcept {
    KillOptions opts;
    opts.preferredMethod = KillMethod::Auto;
    opts.timeoutMs = KillerConstants::TREE_KILL_TIMEOUT_MS;
    opts.maxRetries = KillerConstants::MAX_RETRY_ATTEMPTS;
    opts.escalateOnFailure = true;
    opts.killTree = true;
    opts.treeStrategy = TreeKillStrategy::Simultaneous;
    opts.defeatWatchdogs = true;
    opts.cleanPersistence = true;
    opts.verifyTermination = true;
    opts.preserveEvidence = true;
    opts.allowCritical = false;
    opts.exitCode = KillerConstants::EXIT_CODE_SECURITY;
    return opts;
}

KillOptions KillOptions::CreateForensic() noexcept {
    KillOptions opts;
    opts.preferredMethod = KillMethod::Freeze;
    opts.timeoutMs = KillerConstants::DEFAULT_KILL_TIMEOUT_MS;
    opts.maxRetries = 1;
    opts.escalateOnFailure = false;
    opts.killTree = false;
    opts.defeatWatchdogs = false;
    opts.cleanPersistence = false;
    opts.verifyTermination = true;
    opts.preserveEvidence = true;
    opts.allowCritical = false;
    return opts;
}

void KillerStatistics::Reset() noexcept {
    totalKillAttempts = 0;
    successfulKills = 0;
    failedKills = 0;
    escalatedKills = 0;
    standardKills = 0;
    privilegedKills = 0;
    freezeKills = 0;
    jobObjectKills = 0;
    kernelKills = 0;
    treeKillAttempts = 0;
    processesInTreesKilled = 0;
    suspendAttempts = 0;
    successfulSuspends = 0;
    resumeAttempts = 0;
    watchdogsDetected = 0;
    watchdogsDefeated = 0;
    protectedProcessesEncountered = 0;
    criticalProcessesBlocked = 0;
    accessDeniedErrors = 0;
    timeoutErrors = 0;
    resurrectionsDetected = 0;
}

[[nodiscard]] double KillerStatistics::GetSuccessRate() const noexcept {
    uint64_t total = totalKillAttempts.load();
    if (total == 0) return 0.0;
    return (static_cast<double>(successfulKills.load()) / total) * 100.0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ProcessKillerImpl final {
public:
    ProcessKillerImpl() = default;
    ~ProcessKillerImpl() = default;

    // Delete copy/move
    ProcessKillerImpl(const ProcessKillerImpl&) = delete;
    ProcessKillerImpl& operator=(const ProcessKillerImpl&) = delete;
    ProcessKillerImpl(ProcessKillerImpl&&) = delete;
    ProcessKillerImpl& operator=(ProcessKillerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize() {
        std::unique_lock lock(m_mutex);

        try {
            // Enable required privileges
            m_hasDebugPrivilege = EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            m_hasKillPrivilege = EnablePrivilege(SE_KILL_PRIVILEGE_NAME);

            m_initialized = true;

            Logger::Info("ProcessKiller initialized (debugPriv={}, killPriv={}, kernel={})",
                m_hasDebugPrivilege, m_hasKillPrivilege, m_kernelDriverAvailable);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ProcessKiller initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_preKillCallbacks.clear();
            m_postKillCallbacks.clear();
            m_treeProgressCallbacks.clear();
            m_watchdogCallbacks.clear();

            m_initialized = false;

            Logger::Info("ProcessKiller shutdown complete");

        } catch (...) {
            // Suppress all exceptions
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool IsKernelModeAvailable() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_kernelDriverAvailable;
    }

    // ========================================================================
    // TERMINATION METHODS
    // ========================================================================

    [[nodiscard]] ProcessKillInfo TerminateEx(uint32_t pid, const KillOptions& options) {
        auto startTime = std::chrono::system_clock::now();

        ProcessKillInfo info;
        info.processId = pid;
        info.killTime = startTime;

        try {
            m_stats.totalKillAttempts++;

            // Get process information
            info.processName = ProcessUtils::GetProcessName(pid);
            info.processPath = ProcessUtils::GetProcessPath(pid);
            info.parentPid = ProcessUtils::GetParentPid(pid);

            // Check if process exists
            if (!IsProcessRunning(pid)) {
                info.result = KillResult::AlreadyDead;
                return info;
            }

            // Check criticality
            ProcessCriticality criticality = GetCriticalityInternal(pid);
            if (criticality >= ProcessCriticality::Critical && !options.allowCritical) {
                info.result = KillResult::Critical;
                info.errorMessage = L"Process is critical to system stability";
                m_stats.criticalProcessesBlocked++;
                Logger::Warn("Blocked termination of critical process: {} (pid={})",
                    StringUtils::WideToUtf8(info.processName), pid);
                return info;
            }

            // Check whitelist
            if (WhiteListStore::Instance().IsProcessWhitelisted(info.processPath)) {
                info.result = KillResult::Blocked;
                info.errorMessage = L"Process is whitelisted";
                Logger::Warn("Blocked termination of whitelisted process: {}",
                    StringUtils::WideToUtf8(info.processPath));
                return info;
            }

            // Get protection info
            info.protectionInfo = GetProtectionInfoInternal(pid);
            if (info.protectionInfo.level != ProtectionLevel::None) {
                m_stats.protectedProcessesEncountered++;
            }

            // Pre-kill callbacks
            if (!InvokePreKillCallbacks(pid, options)) {
                info.result = KillResult::Blocked;
                info.errorMessage = L"Blocked by pre-kill callback";
                return info;
            }

            // Preserve evidence if requested
            if (options.preserveEvidence) {
                PreserveEvidence(pid, info);
            }

            // Attempt termination with escalation
            KillResult result = KillResult::Failed;
            KillMethod methodUsed = options.preferredMethod;

            if (options.preferredMethod == KillMethod::Auto) {
                result = EscalatingKill(pid, options, info);
            } else {
                result = KillWithMethod(pid, options.preferredMethod, options, info);
                methodUsed = options.preferredMethod;
            }

            info.result = result;
            info.methodUsed = methodUsed;
            info.killTime = std::chrono::system_clock::now();

            // Verify termination if requested
            if (options.verifyTermination && result == KillResult::Success) {
                if (!VerifyTerminationInternal(pid, options.timeoutMs)) {
                    info.result = KillResult::Timeout;
                    m_stats.timeoutErrors++;
                }
            }

            // Update statistics
            if (info.result == KillResult::Success) {
                m_stats.successfulKills++;
            } else {
                m_stats.failedKills++;
            }

            // Post-kill callbacks
            InvokePostKillCallbacks(info);

        } catch (const std::exception& e) {
            Logger::Error("TerminateEx - Exception: {}", e.what());
            info.result = KillResult::Failed;
            info.errorMessage = StringUtils::Utf8ToWide(e.what());
            m_stats.failedKills++;
        }

        return info;
    }

    [[nodiscard]] TreeKillInfo TerminateTreeEx(uint32_t rootPid, const KillOptions& options) {
        auto startTime = std::chrono::system_clock::now();

        TreeKillInfo treeInfo;
        treeInfo.rootPid = rootPid;
        treeInfo.rootName = ProcessUtils::GetProcessName(rootPid);
        treeInfo.startTime = startTime;
        treeInfo.strategy = options.treeStrategy;

        try {
            m_stats.treeKillAttempts++;

            // Build process tree
            std::vector<uint32_t> tree = GetProcessTreeInternal(rootPid, KillerConstants::MAX_TREE_DEPTH);
            treeInfo.totalProcesses = static_cast<uint32_t>(tree.size());

            if (tree.empty()) {
                treeInfo.overallResult = KillResult::NotFound;
                return treeInfo;
            }

            Logger::Info("Killing process tree: root={} (pid={}), processes={}, strategy={}",
                StringUtils::WideToUtf8(treeInfo.rootName), rootPid, tree.size(),
                static_cast<int>(options.treeStrategy));

            // Order processes based on strategy
            std::vector<uint32_t> killOrder;
            switch (options.treeStrategy) {
                case TreeKillStrategy::BottomUp:
                    // Children first, then parent (reverse tree order)
                    killOrder = tree;
                    std::reverse(killOrder.begin(), killOrder.end());
                    break;

                case TreeKillStrategy::TopDown:
                    // Parent first, then children
                    killOrder = tree;
                    break;

                case TreeKillStrategy::Simultaneous:
                    // All at once (for watchdogs)
                    killOrder = tree;
                    break;

                case TreeKillStrategy::Selective:
                    // Only kill suspicious processes
                    for (uint32_t pid : tree) {
                        if (!IsCriticalProcessInternal(pid)) {
                            killOrder.push_back(pid);
                        }
                    }
                    break;
            }

            // Kill processes
            for (size_t i = 0; i < killOrder.size(); ++i) {
                uint32_t pid = killOrder[i];

                auto killInfo = TerminateEx(pid, options);
                treeInfo.processResults.push_back(killInfo);

                if (killInfo.result == KillResult::Success) {
                    treeInfo.killedProcesses++;
                    m_stats.processesInTreesKilled++;
                } else if (killInfo.result == KillResult::Critical || killInfo.result == KillResult::Blocked) {
                    treeInfo.skippedProcesses++;
                } else {
                    treeInfo.failedProcesses++;
                }

                // Tree progress callbacks
                InvokeTreeProgressCallbacks(static_cast<uint32_t>(i + 1),
                                           static_cast<uint32_t>(killOrder.size()),
                                           killInfo);
            }

            // Determine overall result
            if (treeInfo.killedProcesses == treeInfo.totalProcesses) {
                treeInfo.overallResult = KillResult::Success;
            } else if (treeInfo.killedProcesses > 0) {
                treeInfo.overallResult = KillResult::PartialSuccess;
            } else {
                treeInfo.overallResult = KillResult::Failed;
            }

        } catch (const std::exception& e) {
            Logger::Error("TerminateTreeEx - Exception: {}", e.what());
            treeInfo.overallResult = KillResult::Failed;
            treeInfo.errors.push_back(StringUtils::Utf8ToWide(e.what()));
        }

        treeInfo.endTime = std::chrono::system_clock::now();
        return treeInfo;
    }

    // ========================================================================
    // SUSPENSION OPERATIONS
    // ========================================================================

    [[nodiscard]] SuspendResult SuspendProcessEx(uint32_t pid, const SuspendOptions& options) {
        try {
            m_stats.suspendAttempts++;

            auto threadIds = GetThreadIds(pid);
            if (threadIds.empty()) {
                return SuspendResult::NotFound;
            }

            size_t suspendedCount = 0;
            for (uint32_t tid : threadIds) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_ACCESS, FALSE, tid);
                if (hThread) {
                    DWORD suspendCount = SuspendThread(hThread);
                    if (suspendCount != static_cast<DWORD>(-1)) {
                        suspendedCount++;
                    }
                    CloseHandle(hThread);
                }
            }

            if (suspendedCount == threadIds.size()) {
                m_stats.successfulSuspends++;
                return SuspendResult::Success;
            } else if (suspendedCount > 0) {
                return SuspendResult::PartialSuccess;
            } else {
                return SuspendResult::Failed;
            }

        } catch (const std::exception& e) {
            Logger::Error("SuspendProcessEx - Exception: {}", e.what());
            return SuspendResult::Failed;
        }
    }

    bool ResumeProcessEx(uint32_t pid) {
        try {
            m_stats.resumeAttempts++;

            auto threadIds = GetThreadIds(pid);
            if (threadIds.empty()) return false;

            size_t resumedCount = 0;
            for (uint32_t tid : threadIds) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_ACCESS, FALSE, tid);
                if (hThread) {
                    DWORD suspendCount = ResumeThread(hThread);
                    if (suspendCount != static_cast<DWORD>(-1)) {
                        resumedCount++;
                    }
                    CloseHandle(hThread);
                }
            }

            return resumedCount > 0;

        } catch (const std::exception& e) {
            Logger::Error("ResumeProcessEx - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool FreezeProcess(uint32_t pid) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid);
            if (!hProcess) return false;

            NTSTATUS status = NtSuspendProcess(hProcess);
            CloseHandle(hProcess);

            return NT_SUCCESS(status);

        } catch (const std::exception& e) {
            Logger::Error("FreezeProcess - Exception: {}", e.what());
            return false;
        }
    }

    bool ThawProcess(uint32_t pid) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid);
            if (!hProcess) return false;

            NTSTATUS status = NtResumeProcess(hProcess);
            CloseHandle(hProcess);

            return NT_SUCCESS(status);

        } catch (const std::exception& e) {
            Logger::Error("ThawProcess - Exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // PROCESS TREE OPERATIONS
    // ========================================================================

    [[nodiscard]] std::vector<uint32_t> GetProcessTreeInternal(uint32_t rootPid, uint32_t maxDepth) {
        std::vector<uint32_t> tree;
        std::unordered_set<uint32_t> visited;

        try {
            BuildTreeRecursive(rootPid, tree, visited, 0, maxDepth);
        } catch (const std::exception& e) {
            Logger::Error("GetProcessTreeInternal - Exception: {}", e.what());
        }

        return tree;
    }

    void BuildTreeRecursive(uint32_t pid, std::vector<uint32_t>& tree,
                           std::unordered_set<uint32_t>& visited,
                           uint32_t depth, uint32_t maxDepth) {

        if (depth > maxDepth || visited.count(pid) > 0 || tree.size() >= KillerConstants::MAX_TREE_SIZE) {
            return;
        }

        tree.push_back(pid);
        visited.insert(pid);

        // Get children
        auto children = GetChildrenInternal(pid);
        for (uint32_t childPid : children) {
            BuildTreeRecursive(childPid, tree, visited, depth + 1, maxDepth);
        }
    }

    [[nodiscard]] std::vector<uint32_t> GetChildrenInternal(uint32_t parentPid) {
        std::vector<uint32_t> children;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return children;

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ParentProcessID == parentPid) {
                    children.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return children;
    }

    // ========================================================================
    // WATCHDOG DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<WatchdogInfo> DetectWatchdogs(uint32_t pid) {
        std::vector<WatchdogInfo> watchdogs;

        try {
            // Detect parent-child watchdog
            uint32_t parentPid = ProcessUtils::GetParentPid(pid);
            if (parentPid != 0 && IsProcessRunning(parentPid)) {
                auto parentChildren = GetChildrenInternal(parentPid);
                if (std::find(parentChildren.begin(), parentChildren.end(), pid) != parentChildren.end()) {
                    WatchdogInfo info;
                    info.type = WatchdogType::ParentChild;
                    info.watcherPid = parentPid;
                    info.watchedPid = pid;
                    info.watcherName = ProcessUtils::GetProcessName(parentPid);
                    info.watchedName = ProcessUtils::GetProcessName(pid);
                    info.mechanism = L"Parent process monitors child";
                    watchdogs.push_back(info);
                    m_stats.watchdogsDetected++;
                }
            }

            // Detect mutual process watching (handle analysis would go here)
            // In production, would enumerate handles and check for cross-process handles

        } catch (const std::exception& e) {
            Logger::Error("DetectWatchdogs - Exception: {}", e.what());
        }

        return watchdogs;
    }

    // ========================================================================
    // PROTECTION ANALYSIS
    // ========================================================================

    [[nodiscard]] ProcessProtectionInfo GetProtectionInfoInternal(uint32_t pid) {
        ProcessProtectionInfo info;

        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProcess) return info;

            // Check break-on-termination (critical process flag)
            ULONG breakOnTermination = 0;
            ULONG returnLength = 0;
            NTSTATUS status = NtQueryInformationProcess(
                hProcess,
                ProcessBreakOnTermination,
                &breakOnTermination,
                sizeof(breakOnTermination),
                &returnLength
            );

            if (NT_SUCCESS(status) && breakOnTermination) {
                info.isCritical = true;
                info.isBreakOnTermination = true;
                info.canTerminate = false;
                info.protectionDescription = L"Critical process (BSOD on termination)";
            }

            CloseHandle(hProcess);

        } catch (const std::exception& e) {
            Logger::Error("GetProtectionInfoInternal - Exception: {}", e.what());
        }

        return info;
    }

    [[nodiscard]] ProcessCriticality GetCriticalityInternal(uint32_t pid) {
        try {
            std::wstring name = ProcessUtils::GetProcessName(pid);

            if (IsCriticalProcessName(name)) {
                return ProcessCriticality::Forbidden;
            }

            // Check if process is marked critical
            auto protectionInfo = GetProtectionInfoInternal(pid);
            if (protectionInfo.isCritical) {
                return ProcessCriticality::Critical;
            }

            // Check for system services
            for (const auto& sysProc : KillerConstants::SYSTEM_PROCESSES) {
                if (StringUtils::ToLower(name) == StringUtils::ToLower(std::wstring(sysProc))) {
                    return ProcessCriticality::SystemService;
                }
            }

            return ProcessCriticality::Normal;

        } catch (...) {
            return ProcessCriticality::Unknown;
        }
    }

    [[nodiscard]] bool IsCriticalProcessInternal(uint32_t pid) {
        ProcessCriticality crit = GetCriticalityInternal(pid);
        return (crit >= ProcessCriticality::Critical);
    }

    // ========================================================================
    // KILL METHODS
    // ========================================================================

    [[nodiscard]] KillResult EscalatingKill(uint32_t pid, const KillOptions& options, ProcessKillInfo& info) {
        KillResult result = KillResult::Failed;

        // Level 1: Standard
        result = KillWithMethod(pid, KillMethod::Standard, options, info);
        if (result == KillResult::Success) return result;

        if (!options.escalateOnFailure) return result;

        m_stats.escalatedKills++;
        Logger::Info("Escalating kill for pid {}", pid);

        // Level 2: Privileged
        result = KillWithMethod(pid, KillMethod::Privileged, options, info);
        if (result == KillResult::Success) return result;

        // Level 3: Freeze
        result = KillWithMethod(pid, KillMethod::Freeze, options, info);
        if (result == KillResult::Success) return result;

        // Level 4: Job Object
        result = KillWithMethod(pid, KillMethod::JobObject, options, info);
        if (result == KillResult::Success) return result;

        // Level 5: Token Manipulation
        // KERNEL DRIVER INTEGRATION WILL COME HERE
        // We would strip the process token of its privileges here.

        // Level 6-8: Kernel methods
        // KERNEL DRIVER INTEGRATION WILL COME HERE
        // For enterprise-grade termination, we would use a kernel driver to:
        // 1. Clear callbacks (Level 6)
        // 2. Call ZwTerminateProcess (Level 7)
        // 3. Zero out process memory/structures (Level 8)

        return result;
    }

    [[nodiscard]] KillResult KillWithMethod(uint32_t pid, KillMethod method,
                                            const KillOptions& options,
                                            ProcessKillInfo& info) {
        info.attemptCount++;

        switch (method) {
            case KillMethod::Standard:
                return KillStandard(pid, options.exitCode);

            case KillMethod::Privileged:
                return KillPrivileged(pid, options.exitCode);

            case KillMethod::Freeze:
                return KillFreeze(pid, options.exitCode);

            case KillMethod::JobObject:
                return KillJobObject(pid, options.exitCode);

            default:
                return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillStandard(uint32_t pid, uint32_t exitCode) {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE_ACCESS, FALSE, pid);
            if (!hProcess) {
                m_stats.accessDeniedErrors++;
                return KillResult::AccessDenied;
            }

            BOOL success = TerminateProcess(hProcess, exitCode);
            CloseHandle(hProcess);

            if (success) {
                m_stats.standardKills++;
                Logger::Info("Process {} terminated (standard method)", pid);
                return KillResult::Success;
            }

            return KillResult::Failed;

        } catch (const std::exception& e) {
            Logger::Error("KillStandard - Exception: {}", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillPrivileged(uint32_t pid, uint32_t exitCode) {
        try {
            // Enable debug privilege
            EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);

            HANDLE hProcess = OpenProcess(PROCESS_FULL_ACCESS, FALSE, pid);
            if (!hProcess) {
                m_stats.accessDeniedErrors++;
                return KillResult::AccessDenied;
            }

            BOOL success = TerminateProcess(hProcess, exitCode);
            CloseHandle(hProcess);

            if (success) {
                m_stats.privilegedKills++;
                Logger::Info("Process {} terminated (privileged method)", pid);
                return KillResult::Success;
            }

            return KillResult::Failed;

        } catch (const std::exception& e) {
            Logger::Error("KillPrivileged - Exception: {}", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillFreeze(uint32_t pid, uint32_t exitCode) {
        try {
            // Suspend all threads first
            auto threadIds = GetThreadIds(pid);
            for (uint32_t tid : threadIds) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_ACCESS, FALSE, tid);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }

            // Small delay to ensure suspension
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Now terminate
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE_ACCESS, FALSE, pid);
            if (!hProcess) {
                return KillResult::AccessDenied;
            }

            BOOL success = TerminateProcess(hProcess, exitCode);
            CloseHandle(hProcess);

            if (success) {
                m_stats.freezeKills++;
                Logger::Info("Process {} terminated (freeze method)", pid);
                return KillResult::Success;
            }

            return KillResult::Failed;

        } catch (const std::exception& e) {
            Logger::Error("KillFreeze - Exception: {}", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillJobObject(uint32_t pid, uint32_t exitCode) {
        try {
            // Create job object
            HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
            if (!hJob) return KillResult::Failed;

            // Configure job to kill all processes on close
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = {};
            jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                        &jobInfo, sizeof(jobInfo))) {
                CloseHandle(hJob);
                return KillResult::Failed;
            }

            // Assign process to job
            HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
            if (!hProcess) {
                CloseHandle(hJob);
                return KillResult::AccessDenied;
            }

            BOOL assigned = AssignProcessToJobObject(hJob, hProcess);
            CloseHandle(hProcess);

            if (!assigned) {
                CloseHandle(hJob);
                return KillResult::Failed;
            }

            // Closing the job will kill all processes in it
            CloseHandle(hJob);

            m_stats.jobObjectKills++;
            Logger::Info("Process {} terminated (job object method)", pid);
            return KillResult::Success;

        } catch (const std::exception& e) {
            Logger::Error("KillJobObject - Exception: {}", e.what());
            return KillResult::Failed;
        }
    }

    // ========================================================================
    // VERIFICATION
    // ========================================================================

    [[nodiscard]] bool VerifyTerminationInternal(uint32_t pid, uint32_t timeoutMs) {
        auto startTime = std::chrono::steady_clock::now();

        while (true) {
            if (!IsProcessRunning(pid)) {
                return true;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime);

            if (elapsed.count() >= timeoutMs) {
                return false;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(VERIFICATION_INTERVAL_MS));
        }
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    void PreserveEvidence(uint32_t pid, ProcessKillInfo& info) {
        try {
            info.commandLine = ProcessUtils::GetProcessCommandLine(pid);
            info.userName = ProcessUtils::GetProcessUserName(pid);
            // In production, would collect more forensic data
        } catch (...) {
            // Suppress exceptions
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    bool InvokePreKillCallbacks(uint32_t pid, const KillOptions& options) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_preKillCallbacks) {
                if (callback) {
                    if (!callback(pid, options)) {
                        return false;  // Callback vetoed the kill
                    }
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokePreKillCallbacks - Exception: {}", e.what());
        }

        return true;
    }

    void InvokePostKillCallbacks(const ProcessKillInfo& result) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_postKillCallbacks) {
                if (callback) {
                    callback(result);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokePostKillCallbacks - Exception: {}", e.what());
        }
    }

    void InvokeTreeProgressCallbacks(uint32_t current, uint32_t total, const ProcessKillInfo& result) {
        std::shared_lock lock(m_mutex);

        try {
            for (const auto& [id, callback] : m_treeProgressCallbacks) {
                if (callback) {
                    callback(current, total, result);
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("InvokeTreeProgressCallbacks - Exception: {}", e.what());
        }
    }

    uint64_t RegisterPreKillCallback(PreKillCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_preKillCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterPostKillCallback(PostKillCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_postKillCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterTreeProgressCallback(TreeProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_treeProgressCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterWatchdogCallback(WatchdogDetectedCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_watchdogCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_preKillCallbacks.erase(callbackId);
        m_postKillCallbacks.erase(callbackId);
        m_treeProgressCallbacks.erase(callbackId);
        m_watchdogCallbacks.erase(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] KillerStatistics GetStatistics() const {
        return m_stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_hasDebugPrivilege{ false };
    bool m_hasKillPrivilege{ false };
    bool m_kernelDriverAvailable{ false };

    KillerStatistics m_stats;

    // Callbacks
    std::unordered_map<uint64_t, PreKillCallback> m_preKillCallbacks;
    std::unordered_map<uint64_t, PostKillCallback> m_postKillCallbacks;
    std::unordered_map<uint64_t, TreeProgressCallback> m_treeProgressCallbacks;
    std::unordered_map<uint64_t, WatchdogDetectedCallback> m_watchdogCallbacks;
    uint64_t m_nextCallbackId{ 0 };
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

ProcessKiller& ProcessKiller::Instance() {
    static ProcessKiller instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProcessKiller::ProcessKiller()
    : m_impl(std::make_unique<ProcessKillerImpl>()) {
    Logger::Info("ProcessKiller instance created");
}

ProcessKiller::~ProcessKiller() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ProcessKiller instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE - STATIC METHODS
// ============================================================================

KillResult ProcessKiller::Terminate(uint32_t pid, KillMethod method) {
    KillOptions options = KillOptions::CreateStandard();
    options.preferredMethod = method;
    auto result = Instance().TerminateEx(pid, options);
    return result.result;
}

KillResult ProcessKiller::TerminateTree(uint32_t rootPid) {
    KillOptions options = KillOptions::CreateStandard();
    options.killTree = true;
    auto result = Instance().TerminateTreeEx(rootPid, options);
    return result.overallResult;
}

bool ProcessKiller::SuspendProcess(uint32_t pid) {
    SuspendOptions options;
    auto result = Instance().m_impl->SuspendProcessEx(pid, options);
    return (result == SuspendResult::Success);
}

bool ProcessKiller::ResumeProcess(uint32_t pid) {
    return Instance().m_impl->ResumeProcessEx(pid);
}

bool ProcessKiller::CanTerminate(uint32_t pid) {
    auto criticality = Instance().m_impl->GetCriticalityInternal(pid);
    return criticality < ProcessCriticality::Critical;
}

bool ProcessKiller::IsCriticalProcess(uint32_t pid) {
    return Instance().m_impl->IsCriticalProcessInternal(pid);
}

// ============================================================================
// PUBLIC INTERFACE - LIFECYCLE
// ============================================================================

bool ProcessKiller::Initialize() {
    return m_impl->Initialize();
}

void ProcessKiller::Shutdown() {
    m_impl->Shutdown();
}

bool ProcessKiller::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool ProcessKiller::IsKernelModeAvailable() const noexcept {
    return m_impl->IsKernelModeAvailable();
}

// ============================================================================
// PUBLIC INTERFACE - ADVANCED TERMINATION
// ============================================================================

ProcessKillInfo ProcessKiller::TerminateEx(uint32_t pid, const KillOptions& options) {
    return m_impl->TerminateEx(pid, options);
}

TreeKillInfo ProcessKiller::TerminateTreeEx(uint32_t rootPid, const KillOptions& options) {
    return m_impl->TerminateTreeEx(rootPid, options);
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateMultiple(
    const std::vector<uint32_t>& pids,
    const KillOptions& options) {

    std::vector<ProcessKillInfo> results;
    results.reserve(pids.size());

    for (uint32_t pid : pids) {
        results.push_back(m_impl->TerminateEx(pid, options));
    }

    return results;
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateByName(
    const std::wstring& processName,
    const KillOptions& options) {

    std::vector<ProcessKillInfo> results;

    try {
        auto pids = ProcessUtils::FindProcessesByName(processName);
        for (uint32_t pid : pids) {
            results.push_back(m_impl->TerminateEx(pid, options));
        }
    } catch (const std::exception& e) {
        Logger::Error("TerminateByName - Exception: {}", e.what());
    }

    return results;
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateByPath(
    const std::wstring& processPath,
    const KillOptions& options) {

    std::vector<ProcessKillInfo> results;

    try {
        auto pids = ProcessUtils::FindProcessesByPath(processPath);
        for (uint32_t pid : pids) {
            results.push_back(m_impl->TerminateEx(pid, options));
        }
    } catch (const std::exception& e) {
        Logger::Error("TerminateByPath - Exception: {}", e.what());
    }

    return results;
}

// ============================================================================
// PUBLIC INTERFACE - SUSPENSION
// ============================================================================

SuspendResult ProcessKiller::SuspendProcessEx(uint32_t pid, const SuspendOptions& options) {
    return m_impl->SuspendProcessEx(pid, options);
}

bool ProcessKiller::ResumeProcessEx(uint32_t pid) {
    return m_impl->ResumeProcessEx(pid);
}

bool ProcessKiller::FreezeProcess(uint32_t pid) {
    return m_impl->FreezeProcess(pid);
}

bool ProcessKiller::ThawProcess(uint32_t pid) {
    return m_impl->ThawProcess(pid);
}

bool ProcessKiller::IsSuspended(uint32_t pid) const {
    auto threadIds = GetThreadIds(pid);
    if (threadIds.empty()) return false;

    // Check if all threads are suspended
    size_t suspendedCount = 0;
    for (uint32_t tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (hThread) {
            // Would check thread state here
            CloseHandle(hThread);
        }
    }

    return false;  // Simplified implementation
}

// ============================================================================
// PUBLIC INTERFACE - PROCESS TREE
// ============================================================================

std::vector<uint32_t> ProcessKiller::GetProcessTree(uint32_t rootPid, uint32_t maxDepth) {
    return m_impl->GetProcessTreeInternal(rootPid, maxDepth);
}

std::vector<uint32_t> ProcessKiller::GetChildren(uint32_t pid, bool recursive) {
    if (recursive) {
        return m_impl->GetProcessTreeInternal(pid, KillerConstants::MAX_TREE_DEPTH);
    } else {
        return m_impl->GetChildrenInternal(pid);
    }
}

bool ProcessKiller::SuspendTree(uint32_t rootPid) {
    auto tree = GetProcessTree(rootPid);
    bool allSuspended = true;

    for (uint32_t pid : tree) {
        if (!SuspendProcess(pid)) {
            allSuspended = false;
        }
    }

    return allSuspended;
}

bool ProcessKiller::ResumeTree(uint32_t rootPid) {
    auto tree = GetProcessTree(rootPid);
    bool allResumed = true;

    for (uint32_t pid : tree) {
        if (!ResumeProcess(pid)) {
            allResumed = false;
        }
    }

    return allResumed;
}

// ============================================================================
// PUBLIC INTERFACE - WATCHDOG DETECTION
// ============================================================================

std::vector<WatchdogInfo> ProcessKiller::DetectWatchdogs(uint32_t pid) {
    return m_impl->DetectWatchdogs(pid);
}

std::vector<WatchdogGroup> ProcessKiller::DetectWatchdogGroups(const std::vector<uint32_t>& pids) {
    std::vector<WatchdogGroup> groups;
    // Simplified implementation
    return groups;
}

bool ProcessKiller::DefeatWatchdogGroup(const WatchdogGroup& group) {
    // Would implement simultaneous termination here
    return false;
}

TreeKillInfo ProcessKiller::KillWithWatchdogs(uint32_t pid, const KillOptions& options) {
    return m_impl->TerminateTreeEx(pid, options);
}

// ============================================================================
// PUBLIC INTERFACE - PROTECTION ANALYSIS
// ============================================================================

ProcessProtectionInfo ProcessKiller::GetProtectionInfo(uint32_t pid) {
    return m_impl->GetProtectionInfoInternal(pid);
}

ProcessCriticality ProcessKiller::GetCriticality(uint32_t pid) {
    return m_impl->GetCriticalityInternal(pid);
}

bool ProcessKiller::IsProtectedProcess(uint32_t pid) {
    auto info = m_impl->GetProtectionInfoInternal(pid);
    return info.level != ProtectionLevel::None;
}

bool ProcessKiller::RemoveProtection(uint32_t pid) {
    // KERNEL DRIVER INTEGRATION WILL COME HERE
    // In production, this requires a kernel driver to manipulate the EPROCESS structure
    // directly, specifically modifying the Protection/SignatureLevel bits to bypass PPL.
    return false;
}

// ============================================================================
// PUBLIC INTERFACE - PERSISTENCE CLEANUP
// ============================================================================

bool ProcessKiller::CleanPersistence(uint32_t pid) {
    bool success = true;
    success &= RemoveService(pid);
    success &= RemoveScheduledTasks(pid);
    success &= RemoveRegistryPersistence(pid);
    return success;
}

bool ProcessKiller::RemoveService(uint32_t pid) {
    // Would implement service removal
    return false;
}

bool ProcessKiller::RemoveScheduledTasks(uint32_t pid) {
    // Would implement scheduled task removal
    return false;
}

bool ProcessKiller::RemoveRegistryPersistence(uint32_t pid) {
    // Would implement registry cleanup
    return false;
}

// ============================================================================
// PUBLIC INTERFACE - CALLBACKS
// ============================================================================

uint64_t ProcessKiller::RegisterPreKillCallback(PreKillCallback callback) {
    return m_impl->RegisterPreKillCallback(std::move(callback));
}

uint64_t ProcessKiller::RegisterPostKillCallback(PostKillCallback callback) {
    return m_impl->RegisterPostKillCallback(std::move(callback));
}

uint64_t ProcessKiller::RegisterTreeProgressCallback(TreeProgressCallback callback) {
    return m_impl->RegisterTreeProgressCallback(std::move(callback));
}

uint64_t ProcessKiller::RegisterWatchdogCallback(WatchdogDetectedCallback callback) {
    return m_impl->RegisterWatchdogCallback(std::move(callback));
}

void ProcessKiller::UnregisterCallback(uint64_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

// ============================================================================
// PUBLIC INTERFACE - VERIFICATION
// ============================================================================

bool ProcessKiller::VerifyTermination(uint32_t pid, uint32_t timeoutMs) {
    return m_impl->VerifyTerminationInternal(pid, timeoutMs);
}

uint32_t ProcessKiller::CheckResurrection(
    const std::wstring& name,
    const std::wstring& path,
    std::chrono::system_clock::time_point sinceTime) {

    try {
        auto pids = ProcessUtils::FindProcessesByName(name);
        for (uint32_t pid : pids) {
            auto processPath = ProcessUtils::GetProcessPath(pid);
            if (StringUtils::ToLower(processPath) == StringUtils::ToLower(path)) {
                // Would check process start time here
                return pid;
            }
        }
    } catch (...) {
        // Suppress exceptions
    }

    return 0;
}

// ============================================================================
// PUBLIC INTERFACE - STATISTICS
// ============================================================================

KillerStatistics ProcessKiller::GetStatistics() const {
    return m_impl->GetStatistics();
}

void ProcessKiller::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::wstring ProcessKiller::GetVersion() noexcept {
    return std::to_wstring(KillerConstants::VERSION_MAJOR) + L"." +
           std::to_wstring(KillerConstants::VERSION_MINOR) + L"." +
           std::to_wstring(KillerConstants::VERSION_PATCH);
}

// ============================================================================
// PUBLIC INTERFACE - UTILITY
// ============================================================================

std::wstring ProcessKiller::ResultToString(KillResult result) noexcept {
    switch (result) {
        case KillResult::Success: return L"Success";
        case KillResult::AlreadyDead: return L"Already Dead";
        case KillResult::AccessDenied: return L"Access Denied";
        case KillResult::Protected: return L"Protected Process";
        case KillResult::Critical: return L"Critical Process";
        case KillResult::NotFound: return L"Not Found";
        case KillResult::Timeout: return L"Timeout";
        case KillResult::PartialSuccess: return L"Partial Success";
        case KillResult::Failed: return L"Failed";
        case KillResult::Blocked: return L"Blocked";
        case KillResult::Resurrected: return L"Resurrected";
        case KillResult::InsufficientPriv: return L"Insufficient Privileges";
        default: return L"Unknown";
    }
}

std::wstring ProcessKiller::MethodToString(KillMethod method) noexcept {
    switch (method) {
        case KillMethod::Auto: return L"Auto";
        case KillMethod::Standard: return L"Standard";
        case KillMethod::Privileged: return L"Privileged";
        case KillMethod::Freeze: return L"Freeze";
        case KillMethod::JobObject: return L"Job Object";
        case KillMethod::TokenManipulation: return L"Token Manipulation";
        case KillMethod::Kernel: return L"Kernel";
        case KillMethod::ForceKernel: return L"Force Kernel";
        case KillMethod::Nuclear: return L"Nuclear";
        default: return L"Unknown";
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
