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
#include "../../Communication/IPCManager.hpp"
// Shared kernel protocol for process termination requests
#include "../../../../PhantomSensor/Shared/MessageProtocol.h"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <processthreadsapi.h>
#include <winsvc.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <thread>
#include <chrono>
#include <sstream>
#include <future>

#include <comdef.h>
#include <taskschd.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace ShadowStrike {
namespace Core {
namespace Process {

// Bring infrastructure namespaces into scope
using ShadowStrike::Utils::StringUtils::ToNarrow;
using ShadowStrike::Utils::StringUtils::ToWide;
using ShadowStrike::Utils::StringUtils::ToLowerCopy;
using ShadowStrike::Utils::StringUtils::IEquals;

namespace ProcUtils = ShadowStrike::Utils::ProcessUtils;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    constexpr DWORD PROCESS_TERMINATE_ACCESS = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
    constexpr DWORD PROCESS_SUSPEND_ACCESS = PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION;
    constexpr DWORD PROCESS_FULL_ACCESS = PROCESS_ALL_ACCESS;
    constexpr DWORD THREAD_SUSPEND_ACCESS_RIGHTS = THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;

    constexpr const wchar_t* SE_DEBUG_PRIVILEGE_NAME = L"SeDebugPrivilege";

    constexpr uint32_t VERIFICATION_INTERVAL_MS = 100;

    // PID values that must never be targeted
    constexpr uint32_t PID_SYSTEM_IDLE = 0;
    constexpr uint32_t PID_SYSTEM = 4;

    // Our own PID — always live query, never stale
    [[nodiscard]] static uint32_t GetOwnPid() noexcept {
        return static_cast<uint32_t>(::GetCurrentProcessId());
    }

} // anonymous namespace

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================
namespace {

    class ScopedHandle final {
    public:
        ScopedHandle() noexcept = default;
        explicit ScopedHandle(HANDLE h) noexcept : m_handle(h) {}
        ~ScopedHandle() { Close(); }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&& o) noexcept : m_handle(o.m_handle) { o.m_handle = nullptr; }
        ScopedHandle& operator=(ScopedHandle&& o) noexcept {
            if (this != &o) { Close(); m_handle = o.m_handle; o.m_handle = nullptr; }
            return *this;
        }

        [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] bool IsValid() const noexcept {
            return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
        }
        explicit operator bool() const noexcept { return IsValid(); }
        HANDLE Release() noexcept { HANDLE h = m_handle; m_handle = nullptr; return h; }

        void Close() noexcept {
            if (IsValid()) { ::CloseHandle(m_handle); m_handle = nullptr; }
        }

    private:
        HANDLE m_handle = nullptr;
    };

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

    typedef enum _PROCESSINFOCLASS_EX {
        ProcessBasicInformation_Ex = 0,
        ProcessDebugPort_Ex = 7,
        ProcessWow64Information_Ex = 26,
        ProcessImageFileName_Ex = 27,
        ProcessBreakOnTermination_Ex = 29,
        ProcessProtectionInformation_Ex = 61
    } PROCESSINFOCLASS_EX;

    NTSTATUS NTAPI NtSetInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static bool IsReservedPid(uint32_t pid) noexcept {
    return pid == PID_SYSTEM_IDLE || pid == PID_SYSTEM || pid == GetOwnPid();
}

[[nodiscard]] static bool EnablePrivilege(const wchar_t* privilegeName) noexcept {
    ScopedHandle hToken;
    {
        HANDLE rawToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
            return false;
        }
        hToken = ScopedHandle(rawToken);
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken.Get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        return false;
    }
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

[[nodiscard]] static bool IsProcessRunning(uint32_t pid) noexcept {
    if (pid == 0) return false;

    // SYNCHRONIZE access right is the documented requirement for WaitForSingleObject.
    // Fall back to PROCESS_QUERY_LIMITED_INFORMATION if SYNCHRONIZE is unavailable
    // (extremely rare for processes we have any visibility into).
    ScopedHandle hProcess(OpenProcess(SYNCHRONIZE, FALSE, pid));
    if (!hProcess) {
        hProcess = ScopedHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProcess) return false;
    }

    // WaitForSingleObject(0) returns WAIT_TIMEOUT iff the process object is not
    // signaled, i.e. the process is still running. This is correct in the
    // pathological case where the process exited with code STILL_ACTIVE (259),
    // which would otherwise cause GetExitCodeProcess to report a false positive.
    DWORD wr = ::WaitForSingleObject(hProcess.Get(), 0);
    if (wr == WAIT_TIMEOUT) return true;
    if (wr == WAIT_OBJECT_0) return false;

    // SYNCHRONIZE handle was unavailable or wait failed — fall back to exit-code
    // semantics, accepting the well-known STILL_ACTIVE ambiguity as a last resort.
    DWORD exitCode = 0;
    return GetExitCodeProcess(hProcess.Get(), &exitCode) && (exitCode == STILL_ACTIVE);
}

// Best-effort check that a binary path resides in a Windows system directory.
// Used to guard the critical-process name list against malware masquerading as
// e.g. csrss.exe from a non-system path.
[[nodiscard]] static bool IsSystemDirectoryPath(std::wstring_view path) noexcept {
    if (path.empty()) return false;
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) lower.push_back(static_cast<wchar_t>(::towlower(c)));
    return lower.find(L"\\windows\\system32\\") != std::wstring::npos ||
           lower.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
           lower.find(L"\\windows\\winsxs\\")   != std::wstring::npos;
}

[[nodiscard]] static bool IsCriticalProcessName(std::wstring_view name) noexcept {
    for (const auto& critical : KillerConstants::CRITICAL_PROCESSES) {
        if (IEquals(name, critical)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] static std::vector<uint32_t> GetThreadIds(uint32_t pid) {
    std::vector<uint32_t> threadIds;

    ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!hSnapshot) return threadIds;

    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot.Get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threadIds.push_back(te.th32ThreadID);
                if (threadIds.size() >= KillerConstants::MAX_THREADS_PER_PROCESS) break;
            }
        } while (Thread32Next(hSnapshot.Get(), &te));
    }

    return threadIds;
}

// Retrieve creation time for TOCTOU mitigation: compare at open-time and kill-time
[[nodiscard]] static FILETIME GetProcessCreationTime(HANDLE hProcess) noexcept {
    FILETIME creation{}, exit{}, kernel{}, user{};
    ::GetProcessTimes(hProcess, &creation, &exit, &kernel, &user);
    return creation;
}

[[nodiscard]] static bool CreationTimesMatch(FILETIME a, FILETIME b) noexcept {
    return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime;
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
    uint64_t total = totalKillAttempts.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;
    return (static_cast<double>(successfulKills.load(std::memory_order_relaxed)) / total) * 100.0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ProcessKillerImpl final {
public:
    ProcessKillerImpl() = default;
    ~ProcessKillerImpl() = default;

    ProcessKillerImpl(const ProcessKillerImpl&) = delete;
    ProcessKillerImpl& operator=(const ProcessKillerImpl&) = delete;
    ProcessKillerImpl(ProcessKillerImpl&&) = delete;
    ProcessKillerImpl& operator=(ProcessKillerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize() {
        std::unique_lock lock(m_mutex);
        if (m_initialized) return true;

        try {
            m_hasDebugPrivilege = EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);

            // Probe kernel driver availability via IPCManager
            try {
                auto& ipc = ShadowStrike::Communication::IPCManager::Instance();
                m_kernelDriverAvailable = ipc.IsConnected() && ipc.IsFilterPortConnected();
            } catch (...) {
                m_kernelDriverAvailable = false;
            }

            m_initialized = true;

            SS_LOG_INFO(L"ProcessKiller", L"ProcessKiller initialized (debugPriv=%d, kernelDriver=%d)",
                        m_hasDebugPrivilege ? 1 : 0, m_kernelDriverAvailable ? 1 : 0);
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"Initialization failed: %S", e.what());
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
            m_whitelistStore = nullptr;
            m_initialized = false;
            SS_LOG_INFO(L"ProcessKiller", L"ProcessKiller shutdown complete");
        } catch (...) {}
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool IsKernelModeAvailable() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_kernelDriverAvailable;
    }

    void SetWhitelistStore(ShadowStrike::Whitelist::WhitelistStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_whitelistStore = store;
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
            if (!m_initialized) {
                info.result = KillResult::Failed;
                info.errorMessage = L"ProcessKiller not initialized";
                SS_LOG_ERROR(L"ProcessKiller", L"TerminateEx called before initialization (pid=%u)", pid);
                return info;
            }

            if (IsReservedPid(pid)) {
                info.result = KillResult::Critical;
                if (pid == GetOwnPid()) {
                    info.errorMessage = L"Cannot terminate own process (self-protection)";
                    SS_LOG_WARN(L"ProcessKiller", L"Blocked self-termination attempt (pid=%u)", pid);
                } else {
                    info.errorMessage = L"Cannot terminate system reserved process (PID 0 or 4)";
                }
                m_stats.criticalProcessesBlocked++;
                return info;
            }

            m_stats.totalKillAttempts++;

            info.processName = ProcUtils::GetProcessName(pid).value_or(L"<unknown>");
            info.processPath = ProcUtils::GetProcessPath(pid).value_or(L"");
            info.parentPid = ProcUtils::GetParentProcessId(pid).value_or(0);

            if (!IsProcessRunning(pid)) {
                info.result = KillResult::AlreadyDead;
                return info;
            }

            ProcessCriticality criticality = GetCriticalityInternal(pid);
            if (criticality >= ProcessCriticality::Critical && !options.allowCritical) {
                info.result = KillResult::Critical;
                info.errorMessage = L"Process is critical to system stability";
                m_stats.criticalProcessesBlocked++;
                SS_LOG_WARN(L"ProcessKiller", L"Blocked termination of critical process: %s (pid=%u)",
                            info.processName.c_str(), pid);
                return info;
            }

            // Check whitelist
            {
                std::shared_lock lock(m_mutex);
                if (m_whitelistStore && !info.processPath.empty()) {
                    auto lookupResult = m_whitelistStore->IsPathWhitelisted(info.processPath);
                    if (lookupResult.found) {
                        info.result = KillResult::Blocked;
                        info.errorMessage = L"Process is whitelisted";
                        SS_LOG_WARN(L"ProcessKiller", L"Blocked termination of whitelisted process: %s",
                                    info.processPath.c_str());
                        return info;
                    }
                }
            }

            info.protectionInfo = GetProtectionInfoInternal(pid);
            if (info.protectionInfo.level != ProtectionLevel::None) {
                m_stats.protectedProcessesEncountered++;
            }

            if (!InvokePreKillCallbacks(pid, options)) {
                info.result = KillResult::Blocked;
                info.errorMessage = L"Blocked by pre-kill callback";
                return info;
            }

            if (options.preserveEvidence) {
                PreserveEvidence(pid, info);
            }

            // Capture creation time for TOCTOU mitigation
            FILETIME capturedCreationTime{};
            {
                ScopedHandle hProbe(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
                if (hProbe) {
                    capturedCreationTime = GetProcessCreationTime(hProbe.Get());
                }
            }

            KillResult result = KillResult::Failed;
            if (options.preferredMethod == KillMethod::Auto) {
                result = EscalatingKill(pid, options, info, capturedCreationTime);
            } else {
                result = KillWithMethod(pid, options.preferredMethod, options, info, capturedCreationTime);
            }

            info.result = result;
            info.killTime = std::chrono::system_clock::now();

            if (options.verifyTermination && result == KillResult::Success) {
                if (!VerifyTerminationInternal(pid, options.timeoutMs)) {
                    info.result = KillResult::Timeout;
                    m_stats.timeoutErrors++;
                    SS_LOG_WARN(L"ProcessKiller", L"Termination verification timed out for pid %u", pid);
                }
            }

            if (info.result == KillResult::Success || info.result == KillResult::AlreadyDead) {
                m_stats.successfulKills++;
            } else {
                m_stats.failedKills++;
            }

            InvokePostKillCallbacks(info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"TerminateEx exception for pid %u: %S", pid, e.what());
            info.result = KillResult::Failed;
            info.errorMessage = ToWide(e.what());
            m_stats.failedKills++;
        }

        return info;
    }

    [[nodiscard]] TreeKillInfo TerminateTreeEx(uint32_t rootPid, const KillOptions& options) {
        auto startTime = std::chrono::system_clock::now();
        TreeKillInfo treeInfo;
        treeInfo.rootPid = rootPid;
        treeInfo.rootName = ProcUtils::GetProcessName(rootPid).value_or(L"<unknown>");
        treeInfo.startTime = startTime;
        treeInfo.strategy = options.treeStrategy;

        try {
            m_stats.treeKillAttempts++;

            std::vector<uint32_t> tree = GetProcessTreeInternal(rootPid, KillerConstants::MAX_TREE_DEPTH);
            treeInfo.totalProcesses = static_cast<uint32_t>(tree.size());

            if (tree.empty()) {
                treeInfo.overallResult = KillResult::NotFound;
                return treeInfo;
            }

            SS_LOG_INFO(L"ProcessKiller", L"Killing process tree: root=%s (pid=%u), processes=%u, strategy=%u",
                        treeInfo.rootName.c_str(), rootPid,
                        treeInfo.totalProcesses,
                        static_cast<unsigned>(options.treeStrategy));

            std::vector<uint32_t> killOrder;
            switch (options.treeStrategy) {
                case TreeKillStrategy::BottomUp:
                    killOrder = tree;
                    std::reverse(killOrder.begin(), killOrder.end());
                    break;
                case TreeKillStrategy::TopDown:
                    killOrder = tree;
                    break;
                case TreeKillStrategy::Simultaneous:
                    killOrder = tree;
                    break;
                case TreeKillStrategy::Selective:
                    for (uint32_t pid : tree) {
                        if (!IsCriticalProcessInternal(pid)) {
                            killOrder.push_back(pid);
                        } else {
                            treeInfo.skippedProcesses++;
                        }
                    }
                    break;
            }

            // For Simultaneous: freeze all first, then terminate all in parallel
            if (options.treeStrategy == TreeKillStrategy::Simultaneous && killOrder.size() > 1) {
                for (uint32_t pid : killOrder) {
                    ScopedHandle hProc(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
                    if (hProc) { NtSuspendProcess(hProc.Get()); }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));

                std::vector<std::future<ProcessKillInfo>> futures;
                futures.reserve(killOrder.size());
                for (uint32_t pid : killOrder) {
                    futures.push_back(std::async(std::launch::async,
                        [this, pid, &options]() { return TerminateEx(pid, options); }));
                }

                for (size_t i = 0; i < futures.size(); ++i) {
                    auto killInfo = futures[i].get();
                    treeInfo.processResults.push_back(killInfo);
                    if (killInfo.result == KillResult::Success || killInfo.result == KillResult::AlreadyDead) {
                        treeInfo.killedProcesses++;
                        m_stats.processesInTreesKilled++;
                    } else if (killInfo.result == KillResult::Critical || killInfo.result == KillResult::Blocked) {
                        treeInfo.skippedProcesses++;
                    } else {
                        treeInfo.failedProcesses++;
                    }
                    InvokeTreeProgressCallbacks(static_cast<uint32_t>(i + 1),
                                                static_cast<uint32_t>(killOrder.size()), killInfo);
                }
            } else {
                for (size_t i = 0; i < killOrder.size(); ++i) {
                    auto killInfo = TerminateEx(killOrder[i], options);
                    treeInfo.processResults.push_back(killInfo);
                    if (killInfo.result == KillResult::Success || killInfo.result == KillResult::AlreadyDead) {
                        treeInfo.killedProcesses++;
                        m_stats.processesInTreesKilled++;
                    } else if (killInfo.result == KillResult::Critical || killInfo.result == KillResult::Blocked) {
                        treeInfo.skippedProcesses++;
                    } else {
                        treeInfo.failedProcesses++;
                    }
                    InvokeTreeProgressCallbacks(static_cast<uint32_t>(i + 1),
                                                static_cast<uint32_t>(killOrder.size()), killInfo);
                }
            }

            uint32_t actionable = treeInfo.totalProcesses - treeInfo.skippedProcesses;
            if (actionable == 0 || treeInfo.killedProcesses >= actionable) {
                treeInfo.overallResult = KillResult::Success;
            } else if (treeInfo.killedProcesses > 0) {
                treeInfo.overallResult = KillResult::PartialSuccess;
            } else {
                treeInfo.overallResult = KillResult::Failed;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"TerminateTreeEx exception: %S", e.what());
            treeInfo.overallResult = KillResult::Failed;
            treeInfo.errors.push_back(ToWide(e.what()));
        }

        treeInfo.endTime = std::chrono::system_clock::now();
        return treeInfo;
    }

    // ========================================================================
    // SUSPENSION OPERATIONS
    // ========================================================================

    [[nodiscard]] SuspendResult SuspendProcessEx(uint32_t pid, const SuspendOptions& /*options*/) {
        try {
            m_stats.suspendAttempts++;

            ScopedHandle hProcess(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
            if (!hProcess) {
                DWORD err = GetLastError();
                return (err == ERROR_ACCESS_DENIED) ? SuspendResult::AccessDenied : SuspendResult::NotFound;
            }

            NTSTATUS status = NtSuspendProcess(hProcess.Get());
            if (NT_SUCCESS(status)) {
                m_stats.successfulSuspends++;
                return SuspendResult::Success;
            }

            // Fallback: per-thread suspension
            auto threadIds = GetThreadIds(pid);
            if (threadIds.empty()) return SuspendResult::NotFound;

            size_t suspendedCount = 0;
            for (uint32_t tid : threadIds) {
                ScopedHandle hThread(OpenThread(THREAD_SUSPEND_ACCESS_RIGHTS, FALSE, tid));
                if (hThread && SuspendThread(hThread.Get()) != static_cast<DWORD>(-1)) {
                    suspendedCount++;
                }
            }

            if (suspendedCount == threadIds.size()) {
                m_stats.successfulSuspends++;
                return SuspendResult::Success;
            }
            return (suspendedCount > 0) ? SuspendResult::PartialSuccess : SuspendResult::Failed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"SuspendProcessEx exception: %S", e.what());
            return SuspendResult::Failed;
        }
    }

    bool ResumeProcessEx(uint32_t pid) {
        try {
            m_stats.resumeAttempts++;
            ScopedHandle hProcess(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
            if (!hProcess) return false;
            return NT_SUCCESS(NtResumeProcess(hProcess.Get()));
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"ResumeProcessEx exception: %S", e.what());
            return false;
        }
    }

    [[nodiscard]] bool FreezeProcess(uint32_t pid) {
        try {
            ScopedHandle hProcess(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
            if (!hProcess) return false;
            return NT_SUCCESS(NtSuspendProcess(hProcess.Get()));
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"FreezeProcess exception: %S", e.what());
            return false;
        }
    }

    bool ThawProcess(uint32_t pid) {
        try {
            ScopedHandle hProcess(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
            if (!hProcess) return false;
            return NT_SUCCESS(NtResumeProcess(hProcess.Get()));
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"ThawProcess exception: %S", e.what());
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
            SS_LOG_ERROR(L"ProcessKiller", L"GetProcessTreeInternal exception: %S", e.what());
        }
        return tree;
    }

    void BuildTreeRecursive(uint32_t pid, std::vector<uint32_t>& tree,
                           std::unordered_set<uint32_t>& visited,
                           uint32_t depth, uint32_t maxDepth) {
        if (depth > maxDepth || visited.count(pid) || tree.size() >= KillerConstants::MAX_TREE_SIZE) return;
        if (IsReservedPid(pid)) return;

        tree.push_back(pid);
        visited.insert(pid);

        for (uint32_t childPid : GetChildrenInternal(pid)) {
            BuildTreeRecursive(childPid, tree, visited, depth + 1, maxDepth);
        }
    }

    [[nodiscard]] std::vector<uint32_t> GetChildrenInternal(uint32_t parentPid) {
        std::vector<uint32_t> children;
        ScopedHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) return children;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot.Get(), &pe)) {
            do {
                if (pe.th32ParentProcessID == parentPid && !IsReservedPid(pe.th32ProcessID)) {
                    children.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot.Get(), &pe));
        }
        return children;
    }

    // ========================================================================
    // WATCHDOG DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<WatchdogInfo> DetectWatchdogs(uint32_t pid) {
        std::vector<WatchdogInfo> watchdogs;
        try {
            std::wstring targetPath = ProcUtils::GetProcessPath(pid).value_or(L"");
            std::wstring targetName = ProcUtils::GetProcessName(pid).value_or(L"");

            auto parentOpt = ProcUtils::GetParentProcessId(pid);
            if (parentOpt && *parentOpt != 0 && IsProcessRunning(*parentOpt)) {
                uint32_t parentPid = *parentOpt;
                std::wstring parentPath = ProcUtils::GetProcessPath(parentPid).value_or(L"");

                if (!targetPath.empty() && !parentPath.empty() && IEquals(targetPath, parentPath)) {
                    WatchdogInfo info;
                    info.type = WatchdogType::MutualProcess;
                    info.watcherPid = parentPid;
                    info.watchedPid = pid;
                    info.watcherName = ProcUtils::GetProcessName(parentPid).value_or(L"");
                    info.watchedName = targetName;
                    info.mechanism = L"Parent runs same binary as child (self-watchdog)";
                    watchdogs.push_back(info);
                    m_stats.watchdogsDetected++;
                }

                auto siblings = GetChildrenInternal(parentPid);
                uint32_t sameExeCount = 0;
                for (uint32_t sib : siblings) {
                    auto sibPath = ProcUtils::GetProcessPath(sib).value_or(L"");
                    if (!sibPath.empty() && IEquals(sibPath, targetPath)) sameExeCount++;
                }
                if (sameExeCount > 1) {
                    WatchdogInfo info;
                    info.type = WatchdogType::ParentChild;
                    info.watcherPid = parentPid;
                    info.watchedPid = pid;
                    info.watcherName = ProcUtils::GetProcessName(parentPid).value_or(L"");
                    info.watchedName = targetName;
                    info.mechanism = L"Parent spawns multiple instances of same binary";
                    watchdogs.push_back(info);
                    m_stats.watchdogsDetected++;
                }
            }

            // Notify registered watchdog observers (defensive copy avoids
            // re-entrant deadlock if a callback registers/unregisters).
            if (!watchdogs.empty()) {
                InvokeWatchdogCallbacks(watchdogs);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"DetectWatchdogs exception: %S", e.what());
        }
        return watchdogs;
    }

    [[nodiscard]] std::vector<WatchdogGroup> DetectWatchdogGroupsInternal(const std::vector<uint32_t>& pids) {
        std::vector<WatchdogGroup> groups;
        try {
            std::unordered_map<uint32_t, std::unordered_set<uint32_t>> adj;
            std::unordered_set<uint32_t> pidSet(pids.begin(), pids.end());

            for (uint32_t pid : pids) {
                for (const auto& wd : DetectWatchdogs(pid)) {
                    if (pidSet.count(wd.watchedPid) || pidSet.count(wd.watcherPid)) {
                        adj[wd.watcherPid].insert(wd.watchedPid);
                        adj[wd.watchedPid].insert(wd.watcherPid);
                    }
                }
            }

            std::unordered_set<uint32_t> visited;
            for (uint32_t pid : pids) {
                if (visited.count(pid) || adj.find(pid) == adj.end()) continue;
                WatchdogGroup group;
                std::vector<uint32_t> queue = {pid};
                visited.insert(pid);
                while (!queue.empty()) {
                    uint32_t curr = queue.back(); queue.pop_back();
                    group.processIds.push_back(curr);
                    for (uint32_t n : adj[curr]) {
                        if (!visited.count(n)) { visited.insert(n); queue.push_back(n); }
                    }
                }
                if (group.processIds.size() > 1) {
                    group.requiresSimultaneousKill = true;
                    groups.push_back(std::move(group));
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"DetectWatchdogGroups exception: %S", e.what());
        }
        return groups;
    }

    bool DefeatWatchdogGroupInternal(const WatchdogGroup& group) {
        if (group.processIds.empty()) return true;
        try {
            SS_LOG_INFO(L"ProcessKiller", L"Defeating watchdog group of %zu processes", group.processIds.size());

            // Phase 1: Capture creation times AND freeze every member of the
            // group while still under the original PIDs. Capturing creation
            // time before the suspend window closes is required for the
            // TOCTOU verification in Phase 2 — without it, a PID-reuse race
            // between detection and kill could result in killing an innocent
            // process that inherited the PID.
            struct GroupMember {
                uint32_t pid{};
                FILETIME creationTime{};
                bool valid{false};
            };
            std::vector<GroupMember> members;
            members.reserve(group.processIds.size());

            for (uint32_t pid : group.processIds) {
                GroupMember m{};
                m.pid = pid;
                ScopedHandle hProc(OpenProcess(
                    PROCESS_SUSPEND_ACCESS,
                    FALSE, pid));
                if (hProc) {
                    m.creationTime = GetProcessCreationTime(hProc.Get());
                    m.valid = (m.creationTime.dwLowDateTime != 0 ||
                               m.creationTime.dwHighDateTime != 0);
                    NtSuspendProcess(hProc.Get());
                }
                members.push_back(m);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // Phase 2: Terminate all in parallel with creation-time verification.
            std::vector<std::future<bool>> futures;
            futures.reserve(members.size());
            for (const auto& m : members) {
                futures.push_back(std::async(std::launch::async, [m]() -> bool {
                    ScopedHandle hProc(OpenProcess(
                        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE, m.pid));
                    if (!hProc) return false;
                    if (m.valid) {
                        FILETIME current = GetProcessCreationTime(hProc.Get());
                        if (!CreationTimesMatch(m.creationTime, current)) {
                            SS_LOG_WARN(L"ProcessKiller",
                                L"Watchdog defeat: PID %u reused — refusing to kill", m.pid);
                            return false;
                        }
                    }
                    return ::TerminateProcess(hProc.Get(),
                        KillerConstants::EXIT_CODE_SECURITY) != FALSE;
                }));
            }

            bool allKilled = true;
            for (auto& f : futures) { if (!f.get()) allKilled = false; }

            if (allKilled) {
                m_stats.watchdogsDefeated++;
                SS_LOG_INFO(L"ProcessKiller", L"Watchdog group defeated");
            }
            return allKilled;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"DefeatWatchdogGroup exception: %S", e.what());
            return false;
        }
    }

    // ========================================================================
    // PROTECTION ANALYSIS
    // ========================================================================

    [[nodiscard]] ProcessProtectionInfo GetProtectionInfoInternal(uint32_t pid) {
        ProcessProtectionInfo info;
        try {
            ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProcess) return info;

            ULONG breakOnTermination = 0;
            ULONG returnLength = 0;
            NTSTATUS status = NtQueryInformationProcess(
                hProcess.Get(), static_cast<PROCESSINFOCLASS>(ProcessBreakOnTermination_Ex),
                &breakOnTermination, sizeof(breakOnTermination), &returnLength);

            if (NT_SUCCESS(status) && breakOnTermination) {
                info.isCritical = true;
                info.isBreakOnTermination = true;
                info.canTerminate = false;
                info.protectionDescription = L"Critical process (BSOD on termination)";
            }

            PROCESS_EXTENDED_BASIC_INFORMATION extInfo{};
            extInfo.Size = sizeof(extInfo);
            status = NtQueryInformationProcess(
                hProcess.Get(), static_cast<PROCESSINFOCLASS>(ProcessBasicInformation_Ex),
                &extInfo, sizeof(extInfo), &returnLength);

            if (NT_SUCCESS(status)) {
                if (extInfo.IsProtectedProcess) {
                    info.level = ProtectionLevel::Full;
                    info.protectionDescription = L"Protected Process (PP)";
                    info.canTerminate = false;
                } else if (extInfo.IsSecureProcess) {
                    info.isSecure = true;
                    info.level = ProtectionLevel::Full;
                    info.protectionDescription = L"Secure process (VBS-protected)";
                    info.canTerminate = false;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"GetProtectionInfoInternal exception: %S", e.what());
        }
        return info;
    }

    [[nodiscard]] ProcessCriticality GetCriticalityInternal(uint32_t pid) {
        try {
            std::wstring name = ProcUtils::GetProcessName(pid).value_or(L"");
            if (IsCriticalProcessName(name)) {
                // Defense-in-depth: a name match is only authoritative if the
                // binary is actually located in a Windows system directory.
                // Otherwise malware named csrss.exe (etc.) from a non-system
                // path would receive blanket immunity from termination.
                std::wstring path = ProcUtils::GetProcessPath(pid).value_or(L"");
                if (path.empty() || IsSystemDirectoryPath(path)) {
                    return ProcessCriticality::Forbidden;
                }
                SS_LOG_WARN(L"ProcessKiller",
                    L"Process %u uses critical-process name '%ls' but resides at '%ls' "
                    L"(not a system directory) — masquerade suspected, criticality downgraded",
                    pid, name.c_str(), path.c_str());
            }

            auto prot = GetProtectionInfoInternal(pid);
            if (prot.isCritical) return ProcessCriticality::Critical;

            for (const auto& sysProc : KillerConstants::SYSTEM_PROCESSES) {
                if (IEquals(name, sysProc)) {
                    std::wstring path = ProcUtils::GetProcessPath(pid).value_or(L"");
                    if (path.empty() || IsSystemDirectoryPath(path)) {
                        return ProcessCriticality::SystemService;
                    }
                }
            }
            return ProcessCriticality::Normal;
        } catch (...) {
            return ProcessCriticality::Unknown;
        }
    }

    [[nodiscard]] bool IsCriticalProcessInternal(uint32_t pid) {
        return GetCriticalityInternal(pid) >= ProcessCriticality::Critical;
    }

    // ========================================================================
    // KILL METHODS
    // ========================================================================

    [[nodiscard]] KillResult EscalatingKill(uint32_t pid, const KillOptions& options,
                                            ProcessKillInfo& info, FILETIME creationTime) {
        // Level 1: Standard
        KillResult result = KillWithMethod(pid, KillMethod::Standard, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;
        if (!options.escalateOnFailure) return result;

        m_stats.escalatedKills++;
        SS_LOG_INFO(L"ProcessKiller", L"Escalating kill for pid %u", pid);

        // Level 2: Privileged
        result = KillWithMethod(pid, KillMethod::Privileged, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 3: Freeze
        result = KillWithMethod(pid, KillMethod::Freeze, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 4: Job Object
        result = KillWithMethod(pid, KillMethod::JobObject, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 5: Token Manipulation
        result = KillWithMethod(pid, KillMethod::TokenManipulation, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 6: NtTerminateProcess
        result = KillWithMethod(pid, KillMethod::Kernel, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 7: Force (clear BreakOnTermination + NtTerminate)
        result = KillWithMethod(pid, KillMethod::ForceKernel, options, info, creationTime);
        if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;

        // Level 8: Nuclear — kernel driver IOCTL-based termination (PPL bypass)
        if (m_kernelDriverAvailable) {
            // First, try to strip PPL via kernel driver so the next attempt can succeed
            auto prot = GetProtectionInfoInternal(pid);
            if (prot.level != ProtectionLevel::None) {
                SS_LOG_INFO(L"ProcessKiller", L"Attempting kernel PPL strip for protected pid %u", pid);
                RemoveProtectionInternal(pid);
                // Retry NtTerminateProcess after stripping protection
                result = KillWithMethod(pid, KillMethod::ForceKernel, options, info, creationTime);
                if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;
            }

            result = KillWithMethod(pid, KillMethod::Nuclear, options, info, creationTime);
            if (result == KillResult::Success || result == KillResult::AlreadyDead) return result;
        }

        SS_LOG_ERROR(L"ProcessKiller", L"All escalation levels failed for pid %u", pid);
        return result;
    }

    [[nodiscard]] KillResult KillWithMethod(uint32_t pid, KillMethod method,
                                            const KillOptions& options,
                                            ProcessKillInfo& info, FILETIME creationTime) {
        info.attemptCount++;
        info.methodUsed = method;

        if (!IsProcessRunning(pid)) return KillResult::AlreadyDead;

        switch (method) {
            case KillMethod::Standard:        return KillStandard(pid, options.exitCode, creationTime);
            case KillMethod::Privileged:      return KillPrivileged(pid, options.exitCode, creationTime);
            case KillMethod::Freeze:          return KillFreeze(pid, options.exitCode, creationTime);
            case KillMethod::JobObject:       return KillJobObject(pid, options.exitCode, creationTime);
            case KillMethod::TokenManipulation: return KillTokenManipulation(pid, options.exitCode, creationTime);
            case KillMethod::Kernel:          return KillNtTerminate(pid, options.exitCode, creationTime);
            case KillMethod::ForceKernel:     return KillForceNtTerminate(pid, options.exitCode, creationTime);
            case KillMethod::Nuclear:         return KillKernelDriver(pid, options.exitCode, creationTime);
            case KillMethod::Auto:            return EscalatingKill(pid, options, info, creationTime);
            default:                          return KillResult::Failed;
        }
    }

    // TOCTOU-safe: verify creation time between probe and kill
    [[nodiscard]] KillResult KillStandard(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            ScopedHandle hProcess(OpenProcess(PROCESS_TERMINATE_ACCESS, FALSE, pid));
            if (!hProcess) {
                DWORD err = GetLastError();
                if (err == ERROR_ACCESS_DENIED) { m_stats.accessDeniedErrors++; return KillResult::AccessDenied; }
                return IsProcessRunning(pid) ? KillResult::Failed : KillResult::AlreadyDead;
            }

            if (expected.dwLowDateTime || expected.dwHighDateTime) {
                if (!CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                    SS_LOG_WARN(L"ProcessKiller", L"TOCTOU: PID %u reused", pid);
                    return KillResult::NotFound;
                }
            }

            if (!::TerminateProcess(hProcess.Get(), exitCode)) return KillResult::Failed;

            m_stats.standardKills++;
            SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (standard)", pid);
            return KillResult::Success;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillStandard exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillPrivileged(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            (void)EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            // Request only the rights we actually need. PROCESS_ALL_ACCESS is
            // commonly denied for elevated/anti-tampered targets and
            // unnecessarily fails the privileged path before NtTerminate.
            ScopedHandle hProcess(OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProcess) { m_stats.accessDeniedErrors++; return KillResult::AccessDenied; }

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                return KillResult::NotFound;
            }

            if (!::TerminateProcess(hProcess.Get(), exitCode)) return KillResult::Failed;

            m_stats.privilegedKills++;
            SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (privileged)", pid);
            return KillResult::Success;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillPrivileged exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillFreeze(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            {
                ScopedHandle hSuspend(OpenProcess(PROCESS_SUSPEND_ACCESS, FALSE, pid));
                if (hSuspend) NtSuspendProcess(hSuspend.Get());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            ScopedHandle hProcess(OpenProcess(PROCESS_TERMINATE_ACCESS, FALSE, pid));
            if (!hProcess) return IsProcessRunning(pid) ? KillResult::AccessDenied : KillResult::AlreadyDead;

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                return KillResult::NotFound;
            }

            if (!::TerminateProcess(hProcess.Get(), exitCode)) return KillResult::Failed;

            m_stats.freezeKills++;
            SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (freeze)", pid);
            return KillResult::Success;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillFreeze exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    [[nodiscard]] KillResult KillJobObject(uint32_t pid, uint32_t /*exitCode*/, FILETIME expected) {
        try {
            ScopedHandle hJob(CreateJobObjectW(nullptr, nullptr));
            if (!hJob) return KillResult::Failed;

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
            jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(hJob.Get(), JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo)))
                return KillResult::Failed;

            ScopedHandle hProcess(OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (!hProcess) return KillResult::AccessDenied;

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                SS_LOG_WARN(L"ProcessKiller", L"TOCTOU: PID %u reused (job object path)", pid);
                return KillResult::NotFound;
            }

            if (!AssignProcessToJobObject(hJob.Get(), hProcess.Get())) return KillResult::Failed;

            hJob.Close();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            if (IsProcessRunning(pid)) return KillResult::Timeout;

            m_stats.jobObjectKills++;
            SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (job object)", pid);
            return KillResult::Success;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillJobObject exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    // Level 5: Strip token privileges then terminate
    [[nodiscard]] KillResult KillTokenManipulation(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            (void)EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pid));
            if (!hProcess) { m_stats.accessDeniedErrors++; return KillResult::AccessDenied; }

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                return KillResult::NotFound;
            }

            HANDLE rawToken = nullptr;
            if (OpenProcessToken(hProcess.Get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
                ScopedHandle hToken(rawToken);
                AdjustTokenPrivileges(hToken.Get(), TRUE, nullptr, 0, nullptr, nullptr);
            }

            if (!::TerminateProcess(hProcess.Get(), exitCode)) return KillResult::Failed;

            SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (token manipulation)", pid);
            return KillResult::Success;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillTokenManipulation exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    // Level 6: NtTerminateProcess - bypasses user-mode API hooks
    [[nodiscard]] KillResult KillNtTerminate(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            (void)EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            ScopedHandle hProcess(OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (!hProcess) { m_stats.accessDeniedErrors++; return KillResult::AccessDenied; }

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                return KillResult::NotFound;
            }

            NTSTATUS status = NtTerminateProcess(hProcess.Get(), static_cast<NTSTATUS>(exitCode));
            if (NT_SUCCESS(status)) {
                m_stats.kernelKills++;
                SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (NtTerminateProcess)", pid);
                return KillResult::Success;
            }
            return KillResult::Failed;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillNtTerminate exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    // Level 7: Clear BreakOnTermination then NtTerminateProcess
    [[nodiscard]] KillResult KillForceNtTerminate(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            (void)EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            ScopedHandle hProcess(OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid));
            if (!hProcess) { m_stats.accessDeniedErrors++; return KillResult::AccessDenied; }

            if ((expected.dwLowDateTime || expected.dwHighDateTime) &&
                !CreationTimesMatch(expected, GetProcessCreationTime(hProcess.Get()))) {
                return KillResult::NotFound;
            }

            ULONG breakOnTerm = 0;
            NtSetInformationProcess(hProcess.Get(), static_cast<ULONG>(ProcessBreakOnTermination_Ex),
                                     &breakOnTerm, sizeof(breakOnTerm));

            NTSTATUS status = NtTerminateProcess(hProcess.Get(), static_cast<NTSTATUS>(exitCode));
            if (NT_SUCCESS(status)) {
                m_stats.kernelKills++;
                SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (force NtTerminate)", pid);
                return KillResult::Success;
            }
            return KillResult::Failed;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillForceNtTerminate exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    // Level 8: Kernel driver IOCTL — sends termination request to PhantomSensor
    // which can kill PPL-protected processes from ring-0 via ZwTerminateProcess.
    [[nodiscard]] KillResult KillKernelDriver(uint32_t pid, uint32_t exitCode, FILETIME expected) {
        try {
            if (!m_kernelDriverAvailable) {
                SS_LOG_WARN(L"ProcessKiller", L"Kernel driver not available for pid %u", pid);
                return KillResult::Failed;
            }

            // TOCTOU check: verify the process we are about to ask the driver to kill
            // is still the same one we initially targeted.
            if (expected.dwLowDateTime || expected.dwHighDateTime) {
                ScopedHandle hProbe(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
                if (hProbe && !CreationTimesMatch(expected, GetProcessCreationTime(hProbe.Get()))) {
                    SS_LOG_WARN(L"ProcessKiller", L"TOCTOU: PID %u reused (kernel driver path)", pid);
                    return KillResult::NotFound;
                }
            }

            // Build a lightweight control message for the driver.
            // We reuse the ProcessNotify message type with Create=FALSE to signal
            // a termination request.  The driver recognizes this as an
            // authoritative kill order from user-mode when arriving on the
            // control port (not the notification port).
#pragma pack(push, 1)
            struct KernelKillRequest {
                SHADOWSTRIKE_MESSAGE_HEADER header;
                UINT32 targetPid;
                UINT32 requestedExitCode;
            };
#pragma pack(pop)

            KernelKillRequest req{};
            req.header.Magic       = SHADOWSTRIKE_MESSAGE_MAGIC;
            req.header.Version     = SHADOWSTRIKE_PROTOCOL_VERSION;
            req.header.MessageType = static_cast<UINT16>(FilterMessageType_ProcessNotify);
            req.header.TotalSize   = sizeof(KernelKillRequest);
            req.header.DataSize    = sizeof(req.targetPid) + sizeof(req.requestedExitCode);
            req.header.Timestamp   = static_cast<UINT64>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            req.header.Flags       = SHADOWSTRIKE_MSG_FLAG_PRIORITY_HIGH;
            req.targetPid          = pid;
            req.requestedExitCode  = exitCode;

            // Reply buffer: driver sends back a UINT32 NTSTATUS
            UINT32 replyStatus = 0;
            size_t replySize = sizeof(replyStatus);

            auto& ipc = ShadowStrike::Communication::IPCManager::Instance();
            bool sent = ipc.SendToKernel(&req, sizeof(req), &replyStatus, &replySize,
                                          KillerConstants::DEFAULT_KILL_TIMEOUT_MS);

            if (!sent) {
                SS_LOG_ERROR(L"ProcessKiller", L"Kernel kill IOCTL send failed for pid %u", pid);
                return KillResult::Failed;
            }

            // Check reply from driver
            if (replySize >= sizeof(UINT32) && replyStatus == 0 /* STATUS_SUCCESS */) {
                // Verify process is actually gone
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                if (!IsProcessRunning(pid)) {
                    m_stats.kernelKills++;
                    SS_LOG_INFO(L"ProcessKiller", L"Process %u terminated (kernel driver IOCTL)", pid);
                    return KillResult::Success;
                }
                SS_LOG_WARN(L"ProcessKiller", L"Kernel driver reported success but pid %u still running", pid);
                return KillResult::Timeout;
            }

            SS_LOG_WARN(L"ProcessKiller", L"Kernel driver returned NTSTATUS 0x%08X for pid %u",
                        replyStatus, pid);
            return KillResult::Failed;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"KillKernelDriver exception: %S", e.what());
            return KillResult::Failed;
        }
    }

    // ========================================================================
    // VERIFICATION
    // ========================================================================

    [[nodiscard]] bool VerifyTerminationInternal(uint32_t pid, uint32_t timeoutMs) {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            if (!IsProcessRunning(pid)) return true;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            if (static_cast<uint32_t>(elapsed.count()) >= timeoutMs) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(VERIFICATION_INTERVAL_MS));
        }
    }

    void PreserveEvidence(uint32_t pid, ProcessKillInfo& info) {
        try {
            info.commandLine = ProcUtils::GetProcessCommandLine(pid).value_or(L"");
            info.userName = ProcUtils::GetProcessOwner(pid).value_or(L"");
        } catch (...) {}
    }

    // ========================================================================
    // PERSISTENCE CLEANUP
    // ========================================================================

    bool RemoveServiceInternal(uint32_t pid) {
        try {
            std::wstring processPath = ProcUtils::GetProcessPath(pid).value_or(L"");
            if (processPath.empty()) return false;
            std::wstring lowerPath = ToLowerCopy(processPath);

            // RAII wrapper for SC_HANDLEs to prevent leaks on all exit paths
            struct ScopedSCHandle {
                SC_HANDLE h = nullptr;
                ~ScopedSCHandle() { if (h) CloseServiceHandle(h); }
                operator SC_HANDLE() const { return h; }
                explicit operator bool() const { return h != nullptr; }
            };

            ScopedSCHandle hSCM;
            hSCM.h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (!hSCM) return false;

            DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
            EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                 SERVICE_STATE_ALL, nullptr, 0,
                                 &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

            if (::GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0 || bytesNeeded > 4u * 1024 * 1024) {
                return false;
            }

            auto buffer = std::make_unique<uint8_t[]>(bytesNeeded);
            resumeHandle = 0;
            if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                       SERVICE_STATE_ALL, buffer.get(), bytesNeeded,
                                       &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
                return false;
            }

            auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.get());
            bool anyRemoved = false;

            for (DWORD i = 0; i < servicesReturned; ++i) {
                if (services[i].ServiceStatusProcess.dwProcessId != pid) continue;

                ScopedSCHandle hService;
                hService.h = OpenServiceW(hSCM, services[i].lpServiceName,
                                          SERVICE_STOP | DELETE | SERVICE_QUERY_CONFIG);
                if (!hService) continue;

                DWORD cfgSize = 0;
                QueryServiceConfigW(hService, nullptr, 0, &cfgSize);
                if (cfgSize > 0 && cfgSize < 64 * 1024) {
                    auto cfgBuf = std::make_unique<uint8_t[]>(cfgSize);
                    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.get());
                    if (QueryServiceConfigW(hService, config, cfgSize, &cfgSize)) {
                        std::wstring svcPath = ToLowerCopy(
                            config->lpBinaryPathName ? config->lpBinaryPathName : L"");
                        if (svcPath.find(lowerPath) != std::wstring::npos) {
                            SERVICE_STATUS ss{};
                            ControlService(hService, SERVICE_CONTROL_STOP, &ss);
                            if (DeleteService(hService)) {
                                SS_LOG_INFO(L"ProcessKiller", L"Removed malicious service: %s",
                                            services[i].lpServiceName);
                                anyRemoved = true;
                            }
                        }
                    }
                }
                // ScopedSCHandle hService automatically closed here
            }
            // ScopedSCHandle hSCM automatically closed here
            return anyRemoved;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"RemoveServiceInternal exception: %S", e.what());
            return false;
        }
    }

    bool RemoveScheduledTasksInternal(uint32_t pid) {
        try {
            std::wstring processPath = ProcUtils::GetProcessPath(pid).value_or(L"");
            if (processPath.empty()) return false;
            std::wstring lowerPath = ToLowerCopy(processPath);

            // COM must be initialized on the calling thread.
            // Use STA — ITaskService is apartment-threaded.
            HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
                SS_LOG_WARN(L"ProcessKiller", L"CoInitializeEx failed: 0x%08X", static_cast<unsigned>(hrInit));
                return false;
            }
            // Track whether we need to uninitialize
            bool needUninit = SUCCEEDED(hrInit);

            // RAII guard to CoUninitialize
            struct CoGuard {
                bool active;
                ~CoGuard() { if (active) CoUninitialize(); }
            } coGuard{needUninit};

            ITaskService* pService = nullptr;
            HRESULT hr = CoCreateInstance(
                CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                IID_ITaskService, reinterpret_cast<void**>(&pService));
            if (FAILED(hr) || !pService) {
                SS_LOG_WARN(L"ProcessKiller", L"Failed to create ITaskService: 0x%08X", static_cast<unsigned>(hr));
                return false;
            }

            // RAII release
            struct ServiceGuard {
                ITaskService* p;
                ~ServiceGuard() { if (p) p->Release(); }
            } svcGuard{pService};

            // Connect to the local Task Scheduler
            hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
            if (FAILED(hr)) {
                SS_LOG_WARN(L"ProcessKiller", L"ITaskService::Connect failed: 0x%08X", static_cast<unsigned>(hr));
                return false;
            }

            ITaskFolder* pRootFolder = nullptr;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

            struct FolderGuard {
                ITaskFolder* p;
                ~FolderGuard() { if (p) p->Release(); }
            } folderGuard{pRootFolder};

            if (FAILED(hr) || !pRootFolder) return false;

            IRegisteredTaskCollection* pTaskCollection = nullptr;
            hr = pRootFolder->GetTasks(0, &pTaskCollection);

            struct CollGuard {
                IRegisteredTaskCollection* p;
                ~CollGuard() { if (p) p->Release(); }
            } collGuard{pTaskCollection};

            if (FAILED(hr) || !pTaskCollection) return false;

            LONG taskCount = 0;
            pTaskCollection->get_Count(&taskCount);

            bool anyRemoved = false;

            // Cap iteration to prevent runaway in hostile scenarios
            constexpr LONG MAX_TASKS_TO_SCAN = 4096;
            LONG limit = (std::min)(taskCount, MAX_TASKS_TO_SCAN);

            for (LONG i = 1; i <= limit; ++i) {
                IRegisteredTask* pTask = nullptr;
                hr = pTaskCollection->get_Item(_variant_t(i), &pTask);
                if (FAILED(hr) || !pTask) continue;

                struct TaskGuard {
                    IRegisteredTask* p;
                    ~TaskGuard() { if (p) p->Release(); }
                } taskGuard{pTask};

                ITaskDefinition* pDef = nullptr;
                pTask->get_Definition(&pDef);
                if (!pDef) continue;

                struct DefGuard {
                    ITaskDefinition* p;
                    ~DefGuard() { if (p) p->Release(); }
                } defGuard{pDef};

                IActionCollection* pActions = nullptr;
                pDef->get_Actions(&pActions);
                if (!pActions) continue;

                struct ActGuard {
                    IActionCollection* p;
                    ~ActGuard() { if (p) p->Release(); }
                } actGuard{pActions};

                LONG actionCount = 0;
                pActions->get_Count(&actionCount);

                for (LONG j = 1; j <= actionCount; ++j) {
                    IAction* pAction = nullptr;
                    pActions->get_Item(j, &pAction);
                    if (!pAction) continue;

                    struct ActionGuard {
                        IAction* p;
                        ~ActionGuard() { if (p) p->Release(); }
                    } actionGuard{pAction};

                    TASK_ACTION_TYPE actionType;
                    pAction->get_Type(&actionType);
                    if (actionType != TASK_ACTION_EXEC) continue;

                    IExecAction* pExec = nullptr;
                    hr = pAction->QueryInterface(IID_PPV_ARGS(&pExec));
                    if (FAILED(hr) || !pExec) continue;

                    struct ExecGuard {
                        IExecAction* p;
                        ~ExecGuard() { if (p) p->Release(); }
                    } execGuard{pExec};

                    BSTR bstrPath = nullptr;
                    pExec->get_Path(&bstrPath);
                    if (!bstrPath) continue;

                    std::wstring actionPath = ToLowerCopy(std::wstring(bstrPath, SysStringLen(bstrPath)));
                    SysFreeString(bstrPath);

                    if (actionPath.find(lowerPath) != std::wstring::npos) {
                        BSTR bstrName = nullptr;
                        pTask->get_Name(&bstrName);
                        std::wstring taskName = bstrName ? std::wstring(bstrName, SysStringLen(bstrName)) : L"<unknown>";
                        if (bstrName) SysFreeString(bstrName);

                        hr = pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
                        if (SUCCEEDED(hr)) {
                            SS_LOG_INFO(L"ProcessKiller", L"Removed malicious scheduled task: %s", taskName.c_str());
                            anyRemoved = true;
                        } else {
                            SS_LOG_WARN(L"ProcessKiller", L"Failed to delete scheduled task '%s': 0x%08X",
                                        taskName.c_str(), static_cast<unsigned>(hr));
                        }
                        break; // This task matched; move to next task
                    }
                }
            }
            return anyRemoved;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"RemoveScheduledTasksInternal exception: %S", e.what());
            return false;
        } catch (...) {
            SS_LOG_ERROR(L"ProcessKiller", L"RemoveScheduledTasksInternal unknown exception for pid %u", pid);
            return false;
        }
    }

    bool RemoveRegistryPersistenceInternal(uint32_t pid) {
        try {
            std::wstring processPath = ProcUtils::GetProcessPath(pid).value_or(L"");
            if (processPath.empty()) return false;
            std::wstring lowerPath = ToLowerCopy(processPath);
            bool anyRemoved = false;

            // RAII wrapper for HKEY to prevent leaks on exception
            struct ScopedRegKey {
                HKEY h = nullptr;
                ~ScopedRegKey() { if (h) RegCloseKey(h); }
                operator HKEY() const { return h; }
                HKEY* addr() { return &h; }
            };

            struct RegLoc { HKEY root; const wchar_t* path; };
            const RegLoc locs[] = {
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
                { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
            };

            for (const auto& loc : locs) {
                ScopedRegKey hKey;
                if (RegOpenKeyExW(loc.root, loc.path, 0, KEY_READ | KEY_WRITE, hKey.addr()) != ERROR_SUCCESS)
                    continue;

                std::vector<std::wstring> toDelete;
                wchar_t vName[512]{};
                DWORD vNameLen = 512;
                wchar_t vData[2048]{};
                DWORD vDataSize = sizeof(vData);
                DWORD vType = 0;
                DWORD idx = 0;

                while (RegEnumValueW(hKey, idx, vName, &vNameLen, nullptr, &vType,
                                      reinterpret_cast<LPBYTE>(vData), &vDataSize) == ERROR_SUCCESS) {
                    if (vType == REG_SZ || vType == REG_EXPAND_SZ) {
                        if (ToLowerCopy(vData).find(lowerPath) != std::wstring::npos)
                            toDelete.emplace_back(vName);
                    }
                    vNameLen = 512; vDataSize = sizeof(vData); idx++;
                }

                for (const auto& n : toDelete) {
                    if (RegDeleteValueW(hKey, n.c_str()) == ERROR_SUCCESS) {
                        SS_LOG_INFO(L"ProcessKiller", L"Removed registry persistence: %s\\%s", loc.path, n.c_str());
                        anyRemoved = true;
                    }
                }
            }

            // Check IFEO
            std::wstring exeName = ProcUtils::GetProcessName(pid).value_or(L"");
            if (!exeName.empty()) {
                std::wstring ifeo = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                                    L"Image File Execution Options\\" + exeName;
                ScopedRegKey hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeo.c_str(), 0, KEY_READ | KEY_WRITE, hKey.addr()) == ERROR_SUCCESS) {
                    wchar_t dbg[1024]{}; DWORD dbgSz = sizeof(dbg); DWORD type = 0;
                    if (RegQueryValueExW(hKey, L"Debugger", nullptr, &type,
                                          reinterpret_cast<LPBYTE>(dbg), &dbgSz) == ERROR_SUCCESS) {
                        if (ToLowerCopy(dbg).find(lowerPath) != std::wstring::npos) {
                            RegDeleteValueW(hKey, L"Debugger");
                            SS_LOG_INFO(L"ProcessKiller", L"Removed IFEO persistence for %s", exeName.c_str());
                            anyRemoved = true;
                        }
                    }
                }
            }
            return anyRemoved;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"RemoveRegistryPersistenceInternal exception: %S", e.what());
            return false;
        }
    }

    bool RemoveProtectionInternal(uint32_t pid) {
        try {
            (void)EnablePrivilege(SE_DEBUG_PRIVILEGE_NAME);
            ScopedHandle hProcess(OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (!hProcess) {
                // If we can't open the process, try through the kernel driver
                if (m_kernelDriverAvailable) {
                    SS_LOG_INFO(L"ProcessKiller", L"Cannot open pid %u for protection removal, trying kernel driver", pid);
                    return RequestKernelProtectionRemoval(pid);
                }
                return false;
            }

            // First, try to clear BreakOnTermination (works without driver)
            ULONG breakOnTerm = 0;
            NTSTATUS status = NtSetInformationProcess(
                hProcess.Get(), static_cast<ULONG>(ProcessBreakOnTermination_Ex),
                &breakOnTerm, sizeof(breakOnTerm));

            if (NT_SUCCESS(status)) {
                SS_LOG_INFO(L"ProcessKiller", L"Cleared BreakOnTermination for pid %u", pid);
                return true;
            }

            // BreakOnTermination clear failed — this is likely a PPL process.
            // PPL protection can only be stripped from ring-0.
            if (m_kernelDriverAvailable) {
                SS_LOG_INFO(L"ProcessKiller", L"Escalating PPL removal to kernel driver for pid %u", pid);
                return RequestKernelProtectionRemoval(pid);
            }

            SS_LOG_WARN(L"ProcessKiller", L"Cannot remove protection for pid %u (kernel driver unavailable)", pid);
            return false;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"RemoveProtectionInternal exception: %S", e.what());
            return false;
        }
    }

    // Request kernel driver to strip PPL from a target process via
    // the RegisterProtectedProcess message type (repurposed for removal).
    bool RequestKernelProtectionRemoval(uint32_t pid) {
        try {
#pragma pack(push, 1)
            struct KernelProtectRequest {
                SHADOWSTRIKE_MESSAGE_HEADER header;
                UINT32 targetPid;
                UINT32 action;  // 0 = remove protection, 1 = add protection
            };
#pragma pack(pop)

            KernelProtectRequest req{};
            req.header.Magic       = SHADOWSTRIKE_MESSAGE_MAGIC;
            req.header.Version     = SHADOWSTRIKE_PROTOCOL_VERSION;
            req.header.MessageType = static_cast<UINT16>(FilterMessageType_RegisterProtectedProcess);
            req.header.TotalSize   = sizeof(KernelProtectRequest);
            req.header.DataSize    = sizeof(req.targetPid) + sizeof(req.action);
            req.header.Timestamp   = static_cast<UINT64>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            req.header.Flags       = SHADOWSTRIKE_MSG_FLAG_PRIORITY_HIGH;
            req.targetPid          = pid;
            req.action             = 0; // remove

            UINT32 replyStatus = 0;
            size_t replySize = sizeof(replyStatus);

            auto& ipc = ShadowStrike::Communication::IPCManager::Instance();
            bool sent = ipc.SendToKernel(&req, sizeof(req), &replyStatus, &replySize,
                                          KillerConstants::DEFAULT_KILL_TIMEOUT_MS);

            if (sent && replySize >= sizeof(UINT32) && replyStatus == 0) {
                SS_LOG_INFO(L"ProcessKiller", L"Kernel driver stripped protection from pid %u", pid);
                return true;
            }
            SS_LOG_WARN(L"ProcessKiller", L"Kernel driver PPL removal failed for pid %u (status=0x%08X)",
                        pid, replyStatus);
            return false;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessKiller", L"RequestKernelProtectionRemoval exception: %S", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    bool InvokePreKillCallbacks(uint32_t pid, const KillOptions& options) {
        // Copy callbacks under shared_lock, invoke without holding the lock.
        // This avoids re-entrant deadlock if a callback (un)registers another
        // callback (which acquires unique_lock on the same mutex) and ensures
        // long-running callbacks do not block concurrent termination requests.
        std::vector<PreKillCallback> snapshot;
        try {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_preKillCallbacks.size());
            for (const auto& [id, cb] : m_preKillCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return true; }

        for (const auto& cb : snapshot) {
            try {
                if (!cb(pid, options)) return false;
            } catch (const std::exception& e) {
                SS_LOG_WARN(L"ProcessKiller", L"PreKill callback threw: %S", e.what());
            } catch (...) {
                SS_LOG_WARN(L"ProcessKiller", L"PreKill callback threw unknown exception");
            }
        }
        return true;
    }

    void InvokePostKillCallbacks(const ProcessKillInfo& result) {
        std::vector<PostKillCallback> snapshot;
        try {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_postKillCallbacks.size());
            for (const auto& [id, cb] : m_postKillCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& cb : snapshot) {
            try { cb(result); }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"ProcessKiller", L"PostKill callback threw: %S", e.what());
            } catch (...) {
                SS_LOG_WARN(L"ProcessKiller", L"PostKill callback threw unknown exception");
            }
        }
    }

    void InvokeTreeProgressCallbacks(uint32_t current, uint32_t total, const ProcessKillInfo& result) {
        std::vector<TreeProgressCallback> snapshot;
        try {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_treeProgressCallbacks.size());
            for (const auto& [id, cb] : m_treeProgressCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& cb : snapshot) {
            try { cb(current, total, result); }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"ProcessKiller", L"TreeProgress callback threw: %S", e.what());
            } catch (...) {
                SS_LOG_WARN(L"ProcessKiller", L"TreeProgress callback threw unknown exception");
            }
        }
    }

    void InvokeWatchdogCallbacks(const std::vector<WatchdogInfo>& watchdogs) {
        std::vector<WatchdogDetectedCallback> snapshot;
        try {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_watchdogCallbacks.size());
            for (const auto& [id, cb] : m_watchdogCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& cb : snapshot) {
            for (const auto& wd : watchdogs) {
                try { cb(wd); }
                catch (const std::exception& e) {
                    SS_LOG_WARN(L"ProcessKiller", L"Watchdog callback threw: %S", e.what());
                } catch (...) {
                    SS_LOG_WARN(L"ProcessKiller", L"Watchdog callback threw unknown exception");
                }
            }
        }
    }

    uint64_t RegisterPreKillCallback(PreKillCallback cb) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_preKillCallbacks[id] = std::move(cb);
        return id;
    }
    uint64_t RegisterPostKillCallback(PostKillCallback cb) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_postKillCallbacks[id] = std::move(cb);
        return id;
    }
    uint64_t RegisterTreeProgressCallback(TreeProgressCallback cb) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_treeProgressCallbacks[id] = std::move(cb);
        return id;
    }
    uint64_t RegisterWatchdogCallback(WatchdogDetectedCallback cb) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_watchdogCallbacks[id] = std::move(cb);
        return id;
    }
    void UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_preKillCallbacks.erase(callbackId);
        m_postKillCallbacks.erase(callbackId);
        m_treeProgressCallbacks.erase(callbackId);
        m_watchdogCallbacks.erase(callbackId);
    }

    void GetStatistics(KillerStatistics& out) const {
        // Uses the relaxed-load copy constructor
        KillerStatistics snapshot(m_stats);
        // Manually store into out since assignment is deleted
        out.totalKillAttempts.store(snapshot.totalKillAttempts.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.successfulKills.store(snapshot.successfulKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.failedKills.store(snapshot.failedKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.escalatedKills.store(snapshot.escalatedKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.standardKills.store(snapshot.standardKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.privilegedKills.store(snapshot.privilegedKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.freezeKills.store(snapshot.freezeKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.jobObjectKills.store(snapshot.jobObjectKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.kernelKills.store(snapshot.kernelKills.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.treeKillAttempts.store(snapshot.treeKillAttempts.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.processesInTreesKilled.store(snapshot.processesInTreesKilled.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.suspendAttempts.store(snapshot.suspendAttempts.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.successfulSuspends.store(snapshot.successfulSuspends.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.resumeAttempts.store(snapshot.resumeAttempts.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.watchdogsDetected.store(snapshot.watchdogsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.watchdogsDefeated.store(snapshot.watchdogsDefeated.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.protectedProcessesEncountered.store(snapshot.protectedProcessesEncountered.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.criticalProcessesBlocked.store(snapshot.criticalProcessesBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.accessDeniedErrors.store(snapshot.accessDeniedErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.timeoutErrors.store(snapshot.timeoutErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
        out.resurrectionsDetected.store(snapshot.resurrectionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    void ResetStatistics() { m_stats.Reset(); }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================
    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_hasDebugPrivilege{ false };
    bool m_kernelDriverAvailable{ false };
    ShadowStrike::Whitelist::WhitelistStore* m_whitelistStore{ nullptr };
    KillerStatistics m_stats;
    std::unordered_map<uint64_t, PreKillCallback> m_preKillCallbacks;
    std::unordered_map<uint64_t, PostKillCallback> m_postKillCallbacks;
    std::unordered_map<uint64_t, TreeProgressCallback> m_treeProgressCallbacks;
    std::unordered_map<uint64_t, WatchdogDetectedCallback> m_watchdogCallbacks;
    uint64_t m_nextCallbackId{ 0 };
};

// ============================================================================
// SINGLETON / CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProcessKiller& ProcessKiller::Instance() {
    static ProcessKiller instance;
    return instance;
}

ProcessKiller::ProcessKiller()
    : m_impl(std::make_unique<ProcessKillerImpl>()) {
    SS_LOG_INFO(L"ProcessKiller", L"ProcessKiller instance created");
}

ProcessKiller::~ProcessKiller() {
    if (m_impl) m_impl->Shutdown();
}

// ============================================================================
// STATIC METHODS
// ============================================================================

KillResult ProcessKiller::Terminate(uint32_t pid, KillMethod method) {
    KillOptions options = KillOptions::CreateStandard();
    options.preferredMethod = method;
    return Instance().TerminateEx(pid, options).result;
}

KillResult ProcessKiller::TerminateTree(uint32_t rootPid) {
    return Instance().TerminateTreeEx(rootPid, KillOptions::CreateAggressive()).overallResult;
}

bool ProcessKiller::SuspendProcess(uint32_t pid) {
    return Instance().m_impl->SuspendProcessEx(pid, SuspendOptions{}) == SuspendResult::Success;
}

bool ProcessKiller::ResumeProcess(uint32_t pid) {
    return Instance().m_impl->ResumeProcessEx(pid);
}

bool ProcessKiller::CanTerminate(uint32_t pid) {
    return Instance().m_impl->GetCriticalityInternal(pid) < ProcessCriticality::Critical;
}

bool ProcessKiller::IsCriticalProcess(uint32_t pid) {
    return Instance().m_impl->IsCriticalProcessInternal(pid);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ProcessKiller::Initialize() { return m_impl->Initialize(); }

void ProcessKiller::SetWhitelistStore(ShadowStrike::Whitelist::WhitelistStore* store) noexcept {
    m_impl->SetWhitelistStore(store);
}

void ProcessKiller::Shutdown() { m_impl->Shutdown(); }
bool ProcessKiller::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
bool ProcessKiller::IsKernelModeAvailable() const noexcept { return m_impl->IsKernelModeAvailable(); }

// ============================================================================
// ADVANCED TERMINATION
// ============================================================================

ProcessKillInfo ProcessKiller::TerminateEx(uint32_t pid, const KillOptions& options) {
    return m_impl->TerminateEx(pid, options);
}

TreeKillInfo ProcessKiller::TerminateTreeEx(uint32_t rootPid, const KillOptions& options) {
    return m_impl->TerminateTreeEx(rootPid, options);
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateMultiple(
    const std::vector<uint32_t>& pids, const KillOptions& options) {
    std::vector<ProcessKillInfo> results;
    results.reserve(pids.size());
    for (uint32_t pid : pids) results.push_back(m_impl->TerminateEx(pid, options));
    return results;
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateByName(
    const std::wstring& processName, const KillOptions& options) {
    std::vector<ProcessKillInfo> results;
    try {
        for (uint32_t pid : ProcUtils::GetProcessIdsByName(processName))
            results.push_back(m_impl->TerminateEx(pid, options));
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessKiller", L"TerminateByName exception: %S", e.what());
    }
    return results;
}

std::vector<ProcessKillInfo> ProcessKiller::TerminateByPath(
    const std::wstring& processPath, const KillOptions& options) {
    std::vector<ProcessKillInfo> results;
    try {
        std::vector<ProcUtils::ProcessId> allPids;
        ProcUtils::EnumerateProcesses(allPids);
        for (uint32_t pid : allPids) {
            auto p = ProcUtils::GetProcessPath(pid);
            if (p && IEquals(*p, processPath))
                results.push_back(m_impl->TerminateEx(pid, options));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessKiller", L"TerminateByPath exception: %S", e.what());
    }
    return results;
}

// ============================================================================
// SUSPENSION
// ============================================================================

SuspendResult ProcessKiller::SuspendProcessEx(uint32_t pid, const SuspendOptions& options) {
    return m_impl->SuspendProcessEx(pid, options);
}
bool ProcessKiller::ResumeProcessEx(uint32_t pid) { return m_impl->ResumeProcessEx(pid); }
bool ProcessKiller::FreezeProcess(uint32_t pid) { return m_impl->FreezeProcess(pid); }
bool ProcessKiller::ThawProcess(uint32_t pid) { return m_impl->ThawProcess(pid); }

bool ProcessKiller::IsSuspended(uint32_t pid) const {
    return ProcUtils::IsProcessSuspended(pid);
}

// ============================================================================
// PROCESS TREE
// ============================================================================

std::vector<uint32_t> ProcessKiller::GetProcessTree(uint32_t rootPid, uint32_t maxDepth) {
    return m_impl->GetProcessTreeInternal(rootPid, maxDepth);
}

std::vector<uint32_t> ProcessKiller::GetChildren(uint32_t pid, bool recursive) {
    if (recursive) {
        auto tree = m_impl->GetProcessTreeInternal(pid, KillerConstants::MAX_TREE_DEPTH);
        if (!tree.empty() && tree.front() == pid) tree.erase(tree.begin());
        return tree;
    }
    return m_impl->GetChildrenInternal(pid);
}

bool ProcessKiller::SuspendTree(uint32_t rootPid) {
    bool all = true;
    for (uint32_t pid : GetProcessTree(rootPid)) { if (!SuspendProcess(pid)) all = false; }
    return all;
}

bool ProcessKiller::ResumeTree(uint32_t rootPid) {
    bool all = true;
    for (uint32_t pid : GetProcessTree(rootPid)) { if (!ResumeProcess(pid)) all = false; }
    return all;
}

// ============================================================================
// WATCHDOG
// ============================================================================

std::vector<WatchdogInfo> ProcessKiller::DetectWatchdogs(uint32_t pid) {
    return m_impl->DetectWatchdogs(pid);
}

std::vector<WatchdogGroup> ProcessKiller::DetectWatchdogGroups(const std::vector<uint32_t>& pids) {
    return m_impl->DetectWatchdogGroupsInternal(pids);
}

bool ProcessKiller::DefeatWatchdogGroup(const WatchdogGroup& group) {
    return m_impl->DefeatWatchdogGroupInternal(group);
}

TreeKillInfo ProcessKiller::KillWithWatchdogs(uint32_t pid, const KillOptions& options) {
    TreeKillInfo info;
    info.rootPid = pid;
    info.startTime = std::chrono::system_clock::now();
    info.strategy = TreeKillStrategy::Simultaneous;

    auto watchdogs = m_impl->DetectWatchdogs(pid);
    std::unordered_set<uint32_t> allPids;
    allPids.insert(pid);
    for (const auto& wd : watchdogs) { allPids.insert(wd.watcherPid); allPids.insert(wd.watchedPid); }

    // Expand to include the full descendant tree of every watchdog member —
    // not just the root — so a watchdog process can't outlive the kill by
    // forking children we never enumerated.
    for (uint32_t p : std::vector<uint32_t>(allPids.begin(), allPids.end())) {
        for (uint32_t c : m_impl->GetProcessTreeInternal(p, KillerConstants::MAX_TREE_DEPTH))
            allPids.insert(c);
    }

    KillOptions opts = options;
    opts.treeStrategy = TreeKillStrategy::Simultaneous;

    auto rootName = ProcUtils::GetProcessName(pid);
    if (rootName) info.rootName = *rootName;
    info.totalProcesses = static_cast<uint32_t>(allPids.size());

    // Terminate every PID in the consolidated set. Forcing a non-tree call
    // per PID (Simultaneous) prevents nested TerminateTree from re-walking
    // descendants we already enumerated and respects the caller's intent
    // to bring down the whole watchdog cluster atomically.
    KillOptions perPid = opts;
    perPid.killTree = false;

    info.processResults.reserve(allPids.size());
    for (uint32_t p : allPids) {
        auto r = m_impl->TerminateEx(p, perPid);
        switch (r.result) {
            case KillResult::Success:
            case KillResult::AlreadyDead:
                info.killedProcesses++;
                break;
            case KillResult::Critical:
            case KillResult::Blocked:
                info.skippedProcesses++;
                if (!r.errorMessage.empty()) info.warnings.push_back(r.errorMessage);
                break;
            default:
                info.failedProcesses++;
                if (!r.errorMessage.empty()) info.errors.push_back(r.errorMessage);
                break;
        }
        info.processResults.push_back(std::move(r));
    }

    info.endTime = std::chrono::system_clock::now();
    if (info.failedProcesses == 0) info.overallResult = KillResult::Success;
    else if (info.killedProcesses > 0) info.overallResult = KillResult::PartialSuccess;
    else info.overallResult = KillResult::Failed;
    return info;
}

// ============================================================================
// PROTECTION
// ============================================================================

ProcessProtectionInfo ProcessKiller::GetProtectionInfo(uint32_t pid) {
    return m_impl->GetProtectionInfoInternal(pid);
}
ProcessCriticality ProcessKiller::GetCriticality(uint32_t pid) {
    return m_impl->GetCriticalityInternal(pid);
}
bool ProcessKiller::IsProtectedProcess(uint32_t pid) {
    return m_impl->GetProtectionInfoInternal(pid).level != ProtectionLevel::None;
}
bool ProcessKiller::RemoveProtection(uint32_t pid) {
    return m_impl->RemoveProtectionInternal(pid);
}

// ============================================================================
// PERSISTENCE CLEANUP
// ============================================================================

bool ProcessKiller::CleanPersistence(uint32_t pid) {
    bool any = false;
    any |= RemoveService(pid);
    any |= RemoveScheduledTasks(pid);
    any |= RemoveRegistryPersistence(pid);
    return any;
}

bool ProcessKiller::RemoveService(uint32_t pid) { return m_impl->RemoveServiceInternal(pid); }
bool ProcessKiller::RemoveScheduledTasks(uint32_t pid) { return m_impl->RemoveScheduledTasksInternal(pid); }
bool ProcessKiller::RemoveRegistryPersistence(uint32_t pid) { return m_impl->RemoveRegistryPersistenceInternal(pid); }

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ProcessKiller::RegisterPreKillCallback(PreKillCallback cb) { return m_impl->RegisterPreKillCallback(std::move(cb)); }
uint64_t ProcessKiller::RegisterPostKillCallback(PostKillCallback cb) { return m_impl->RegisterPostKillCallback(std::move(cb)); }
uint64_t ProcessKiller::RegisterTreeProgressCallback(TreeProgressCallback cb) { return m_impl->RegisterTreeProgressCallback(std::move(cb)); }
uint64_t ProcessKiller::RegisterWatchdogCallback(WatchdogDetectedCallback cb) { return m_impl->RegisterWatchdogCallback(std::move(cb)); }
void ProcessKiller::UnregisterCallback(uint64_t id) { m_impl->UnregisterCallback(id); }

// ============================================================================
// VERIFICATION
// ============================================================================

bool ProcessKiller::VerifyTermination(uint32_t pid, uint32_t timeoutMs) {
    return m_impl->VerifyTerminationInternal(pid, timeoutMs);
}

uint32_t ProcessKiller::CheckResurrection(
    const std::wstring& name, const std::wstring& path,
    std::chrono::system_clock::time_point sinceTime) {
    try {
        for (uint32_t pid : ProcUtils::GetProcessIdsByName(name)) {
            auto pp = ProcUtils::GetProcessPath(pid);
            if (!pp || !IEquals(*pp, path)) continue;

            ScopedHandle hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
            if (!hProcess) continue;

            FILETIME creation = GetProcessCreationTime(hProcess.Get());
            ULARGE_INTEGER uli;
            uli.LowPart = creation.dwLowDateTime;
            uli.HighPart = creation.dwHighDateTime;

            constexpr uint64_t FILETIME_UNIX_DIFF = 116444736000000000ULL;
            if (uli.QuadPart > FILETIME_UNIX_DIFF) {
                auto tp = std::chrono::system_clock::time_point(
                    std::chrono::microseconds((uli.QuadPart - FILETIME_UNIX_DIFF) / 10));
                if (tp > sinceTime) {
                    m_impl->m_stats.resurrectionsDetected++;
                    SS_LOG_WARN(L"ProcessKiller", L"Process resurrection detected: %s (pid=%u)", name.c_str(), pid);
                    return pid;
                }
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProcessKiller", L"CheckResurrection exception: %S", e.what());
    }
    return 0;
}

// ============================================================================
// STATISTICS & UTILITY
// ============================================================================

KillerStatistics ProcessKiller::GetStatistics() const {
    KillerStatistics snapshot;
    m_impl->GetStatistics(snapshot);
    return snapshot;
}
void ProcessKiller::ResetStatistics() { m_impl->ResetStatistics(); }

std::wstring ProcessKiller::GetVersion() noexcept {
    return std::to_wstring(KillerConstants::VERSION_MAJOR) + L"." +
           std::to_wstring(KillerConstants::VERSION_MINOR) + L"." +
           std::to_wstring(KillerConstants::VERSION_PATCH);
}

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
        case KillMethod::Kernel: return L"Kernel (NtTerminate)";
        case KillMethod::ForceKernel: return L"Force Kernel";
        case KillMethod::Nuclear: return L"Nuclear";
        default: return L"Unknown";
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
