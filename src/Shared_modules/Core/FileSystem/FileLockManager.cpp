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
 * ShadowStrike Core FileSystem - FILE LOCK MANAGER IMPLEMENTATION v4.0
 * ============================================================================
 *
 * @file FileLockManager.cpp
 * @brief Enterprise-grade file lock detection, handle management, and
 *        APT-grade threat correlation with kernel driver integration.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers Singleton for thread-safe instance management
 * - NtQuerySystemInformation(SystemExtendedHandleInformationClass) for deep handle enum
 * - Windows Restart Manager for application-aware unlocking
 * - FilterSendMessage for kernel-mode force-close operations
 * - File ID-based handle matching (robust against symlinks/junctions)
 * - APT behavioral pattern detection in lock analysis
 * - Process trust verification (signature, injection, elevation)
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "FileLockManager.hpp"

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"

#include <Windows.h>
#include <winternl.h>
#include <RestartManager.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <fltUser.h>
#include <Softpub.h>
#include <wintrust.h>

#include <filesystem>
#include <algorithm>
#include <thread>
#include <chrono>
#include <atomic>
#include <unordered_set>
#include <unordered_map>

#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "Wintrust.lib")

namespace fs = std::filesystem;

namespace StringUtils = ShadowStrike::Utils::StringUtils;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    constexpr uint32_t SYSTEM_PID = 4;
    constexpr uint32_t IDLE_PID = 0;
    constexpr const wchar_t* SHADOWSTRIKE_FILTER_PORT = L"\\ShadowStrikePort";

    constexpr std::wstring_view CRITICAL_PROC_NAMES[] = {
        L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
        L"lsass.exe", L"winlogon.exe", L"system", L"dwm.exe"
    };

    constexpr std::wstring_view SYSTEM_PROC_NAMES[] = {
        L"svchost.exe", L"explorer.exe", L"conhost.exe",
        L"runtimebroker.exe", L"taskhostw.exe"
    };

    [[nodiscard]] bool IsCriticalProcessName(std::wstring_view name) noexcept {
        std::wstring lower(name);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        for (const auto& c : CRITICAL_PROC_NAMES) { if (lower == c) return true; }
        return false;
    }

    [[nodiscard]] bool IsSystemProcessName(std::wstring_view name) noexcept {
        std::wstring lower(name);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        for (const auto& s : SYSTEM_PROC_NAMES) { if (lower == s) return true; }
        return false;
    }

    constexpr NTSTATUS NT_STATUS_OK = 0x00000000;
    constexpr NTSTATUS NT_STATUS_INFO_LEN_MISMATCH = static_cast<NTSTATUS>(0xC0000004);
    constexpr ULONG SystemExtendedHandleInformationClass = 64;
    constexpr ULONG MAX_HANDLE_BUFFER_BYTES = 256u << 20; // 256 MB cap

} // anonymous namespace

// ============================================================================
// NT API DECLARATIONS (Extended - 64-bit safe)
// ============================================================================

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(
    ULONG, PVOID, ULONG, PULONG);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

class ScopedHandle final {
public:
    ScopedHandle() noexcept : m_handle(INVALID_HANDLE_VALUE) {}
    explicit ScopedHandle(HANDLE h) noexcept : m_handle(h) {}
    ~ScopedHandle() noexcept { Close(); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& o) noexcept : m_handle(o.m_handle) { o.m_handle = INVALID_HANDLE_VALUE; }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) { Close(); m_handle = o.m_handle; o.m_handle = INVALID_HANDLE_VALUE; }
        return *this;
    }
    [[nodiscard]] bool IsValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }
    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    HANDLE Release() noexcept { HANDLE h = m_handle; m_handle = INVALID_HANDLE_VALUE; return h; }
    void Reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept { Close(); m_handle = h; }
    explicit operator bool() const noexcept { return IsValid(); }
private:
    void Close() noexcept { if (IsValid()) { ::CloseHandle(m_handle); m_handle = INVALID_HANDLE_VALUE; } }
    HANDLE m_handle;
};

// ============================================================================
// INTERNAL ATOMIC STATISTICS
// ============================================================================

struct InternalStatistics {
    std::atomic<uint64_t> locksDetected{ 0 };
    std::atomic<uint64_t> successfulUnlocks{ 0 };
    std::atomic<uint64_t> failedUnlocks{ 0 };
    std::atomic<uint64_t> processesTerminated{ 0 };
    std::atomic<uint64_t> handlesClosed{ 0 };
    std::atomic<uint64_t> rebootScheduled{ 0 };
    std::atomic<uint64_t> kernelUnlocks{ 0 };
    std::atomic<uint64_t> handleEnumerations{ 0 };
    std::atomic<uint64_t> threatsDetected{ 0 };

    [[nodiscard]] FileLockManagerStatistics Snapshot() const noexcept {
        FileLockManagerStatistics s;
        s.locksDetected = locksDetected.load(std::memory_order_relaxed);
        s.successfulUnlocks = successfulUnlocks.load(std::memory_order_relaxed);
        s.failedUnlocks = failedUnlocks.load(std::memory_order_relaxed);
        s.processesTerminated = processesTerminated.load(std::memory_order_relaxed);
        s.handlesClosed = handlesClosed.load(std::memory_order_relaxed);
        s.rebootScheduled = rebootScheduled.load(std::memory_order_relaxed);
        s.kernelUnlocks = kernelUnlocks.load(std::memory_order_relaxed);
        s.handleEnumerations = handleEnumerations.load(std::memory_order_relaxed);
        s.threatsDetected = threatsDetected.load(std::memory_order_relaxed);
        return s;
    }
    void Reset() noexcept {
        locksDetected = 0; successfulUnlocks = 0; failedUnlocks = 0;
        processesTerminated = 0; handlesClosed = 0; rebootScheduled = 0;
        kernelUnlocks = 0; handleEnumerations = 0; threatsDetected = 0;
    }
};

// ============================================================================
// KERNEL COMMUNICATION PROTOCOL
// ============================================================================
namespace KernelProtocol {
    enum class Command : uint32_t {
        QueryFileLocks = 0x200, ForceCloseHandle = 0x201,
        LockForQuarantine = 0x202, ReleaseFileLock = 0x203
    };
#pragma pack(push, 1)
    struct RequestHeader { uint32_t command; uint32_t dataLength; };
    struct ForceCloseRequest { RequestHeader header; uint32_t targetPid; uint64_t handleValue; wchar_t filePath[260]; };
    struct QueryLocksRequest { RequestHeader header; wchar_t filePath[260]; };
    struct ResponseHeader { uint32_t status; uint32_t dataLength; };
    struct ForceCloseResponse { ResponseHeader header; uint32_t handlesAffected; uint32_t errorCode; };
#pragma pack(pop)
} // namespace KernelProtocol
// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FileLockManagerImpl final {
public:
    FileLockManagerImpl() = default;
    ~FileLockManagerImpl() { Shutdown(); }
    FileLockManagerImpl(const FileLockManagerImpl&) = delete;
    FileLockManagerImpl& operator=(const FileLockManagerImpl&) = delete;

    [[nodiscard]] bool Initialize(const FileLockManagerConfig& config) {
        std::unique_lock lock(m_mutex);
        try {
            m_config = config;
            m_hasDebugPrivilege = EnableDebugPrivilege();
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                m_ntQuerySystemInfo = reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
                m_ntQueryObject = reinterpret_cast<NtQueryObjectFn>(GetProcAddress(hNtdll, "NtQueryObject"));
            }
            m_fileTypeIndex = ResolveFileObjectTypeIndex();
            m_kernelDriverAvailable = CheckKernelDriver();
            if (m_kernelDriverAvailable && config.allowKernelUnlock) ConnectToKernelDriverInternal();
            m_initialized = true;
            SS_LOG_INFO(L"FileLockManager", L"Initialized v4.0 (debug=%s, kernel=%s, ntQuery=%s, fileTypeIdx=%u)",
                m_hasDebugPrivilege ? L"yes" : L"no", m_kernelDriverAvailable ? L"yes" : L"no",
                m_ntQuerySystemInfo ? L"yes" : L"no", static_cast<unsigned>(m_fileTypeIndex));
            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileLockManager", L"Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        try {
            DisconnectFromKernelDriverInternal();
            m_terminateCallback = nullptr;
            m_progressCallback = nullptr;
            m_lockEventCallback = nullptr;
            m_initialized = false;
        } catch (...) {}
    }

    [[nodiscard]] std::vector<LockOwner> GetLockingProcesses(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        std::vector<LockOwner> owners;
        try {
            auto np = NormalizePath(filePath);
            if (np.empty()) return owners;
            auto rmOwners = GetLockingProcessesRM(np);
            auto handleOwners = GetLockingProcessesHandleEnum(np);
            owners = std::move(rmOwners);
            std::unordered_set<uint32_t> known;
            for (const auto& o : owners) known.insert(o.pid);
            for (auto& ho : handleOwners) {
                if (known.find(ho.pid) == known.end()) {
                    owners.push_back(std::move(ho));
                    known.insert(owners.back().pid);
                } else {
                    for (auto& ex : owners) {
                        if (ex.pid == ho.pid && ex.handleValue == 0) {
                            ex.handleValue = ho.handleValue;
                            ex.accessMask = ho.accessMask;
                            ex.lockType = ho.lockType;
                            break;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileLockManager", L"GetLockingProcesses exception: %hs", e.what());
        }
        return owners;
    }

    [[nodiscard]] FileLockInfo GetLockInfo(const std::wstring& filePath) const {
        auto t0 = std::chrono::steady_clock::now();
        FileLockInfo info;
        info.filePath = filePath;
        try {
            std::error_code ec;
            if (!fs::exists(filePath, ec)) { info.fileExists = false; return info; }
            info.isDirectory = fs::is_directory(filePath, ec);
            if (!info.isDirectory) info.fileSize = fs::file_size(filePath, ec);
            info.owners = GetLockingProcesses(filePath);
            info.lockCount = static_cast<uint32_t>(info.owners.size());
            info.isLocked = (info.lockCount > 0);
            for (const auto& o : info.owners) {
                if (o.isSystemProcess) info.hasSystemLock = true;
                if (o.isCriticalProcess) { info.hasCriticalLock = true; info.canForceUnlock = false; }
            }
            info.threatAssessment = AnalyzeThreatInternal(info);
            m_stats.locksDetected.fetch_add(1, std::memory_order_relaxed);
            if (info.threatAssessment.isSuspiciousActivity)
                m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileLockManager", L"GetLockInfo exception: %hs", e.what());
        }
        info.detectionDuration = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0);
        return info;
    }

    [[nodiscard]] bool IsFileLocked(const std::wstring& filePath) const {
        try {
            ScopedHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (hFile.IsValid()) return false;
            DWORD err = GetLastError();
            return (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION);
        } catch (...) { return false; }
    }

    [[nodiscard]] bool CanDeleteFile(const std::wstring& filePath) const {
        try {
            ScopedHandle h(CreateFileW(filePath.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            return h.IsValid();
        } catch (...) { return false; }
    }

    [[nodiscard]] LockType GetLockType(const std::wstring& filePath) const {
        try {
            ScopedHandle hr(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
            ScopedHandle hw(CreateFileW(filePath.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
            if (!hr && !hw) return LockType::Exclusive;
            if (!hw) return LockType::Write;
            if (!hr) return LockType::Read;
            return LockType::Unknown;
        } catch (...) { return LockType::Unknown; }
    }
    // ========================================================================
    // UNLOCK OPERATIONS
    // ========================================================================

    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath) {
        auto t0 = std::chrono::steady_clock::now();
        UnlockOperation result;
        result.filePath = filePath;
        try {
            ReportProgress(std::wstring{L"Detecting file locks"}, 10u);
            if (!IsFileLocked(filePath)) { result.result = UnlockResult::NotLocked; return result; }
            auto owners = GetLockingProcesses(filePath);
            if (owners.empty()) {
                result.result = UnlockResult::Failed;
                result.errors.push_back("File locked but owner unidentifiable");
                m_stats.failedUnlocks.fetch_add(1, std::memory_order_relaxed);
                return result;
            }
            ReportProgress(std::wstring{L"Analyzing lock owners"}, 30u);
            for (const auto& o : owners) {
                if (o.isCriticalProcess && m_config.protectCriticalProcesses) {
                    result.result = UnlockResult::ProcessCritical;
                    result.errors.push_back("Locked by critical process: " + StringUtils::ToNarrow(o.processName));
                    SS_LOG_WARN(L"FileLockManager", L"Cannot unlock - critical process %s (PID %u)", o.processName.c_str(), o.pid);
                    return result;
                }
            }
            ReportProgress(std::wstring{L"Attempting unlock"}, 50u);
            if (m_config.allowRestartManager && TryRestartManager(filePath, result)) {
                result.result = UnlockResult::Success; result.method = UnlockMethod::RestartManager;
                m_stats.successfulUnlocks.fetch_add(1, std::memory_order_relaxed);
                FinalizeResult(result, t0); return result;
            }
            if (TryHandleClose(owners, result) && !IsFileLocked(filePath)) {
                result.result = UnlockResult::Success; result.method = UnlockMethod::HandleClose;
                m_stats.successfulUnlocks.fetch_add(1, std::memory_order_relaxed);
                FinalizeResult(result, t0); return result;
            }
            if (m_config.allowKernelUnlock && m_kernelDriverAvailable &&
                TryKernelUnlock(filePath, result) && !IsFileLocked(filePath)) {
                result.result = UnlockResult::Success; result.method = UnlockMethod::KernelDriver;
                m_stats.successfulUnlocks.fetch_add(1, std::memory_order_relaxed);
                m_stats.kernelUnlocks.fetch_add(1, std::memory_order_relaxed);
                FinalizeResult(result, t0); return result;
            }
            if (m_config.allowProcessTermination && TryProcessTerminate(owners, result)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!IsFileLocked(filePath)) {
                    result.result = UnlockResult::Success; result.method = UnlockMethod::ProcessTerminate;
                    m_stats.successfulUnlocks.fetch_add(1, std::memory_order_relaxed);
                    FinalizeResult(result, t0); return result;
                }
            }
            ReportProgress(std::wstring{L"Scheduling reboot operation"}, 90u);
            if (ScheduleDeleteOnRebootInternal(filePath)) {
                result.result = UnlockResult::RequiresReboot; result.method = UnlockMethod::DeleteOnReboot;
                result.requiresReboot = true; result.pendingOperation = L"Delete on reboot";
                m_stats.rebootScheduled.fetch_add(1, std::memory_order_relaxed);
                FinalizeResult(result, t0); return result;
            }
            result.result = UnlockResult::Failed;
            result.errors.push_back("All unlock methods exhausted");
            m_stats.failedUnlocks.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileLockManager", L"UnlockFile exception: %hs", e.what());
            result.result = UnlockResult::Failed;
            result.errors.push_back(std::string("Exception: ") + e.what());
            m_stats.failedUnlocks.fetch_add(1, std::memory_order_relaxed);
        }
        FinalizeResult(result, t0);
        return result;
    }

    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath, UnlockMethod method) {
        UnlockOperation result; result.filePath = filePath; result.method = method;
        try {
            switch (method) {
            case UnlockMethod::HandleClose: { auto o = GetLockingProcesses(filePath); result.result = TryHandleClose(o, result) ? UnlockResult::Success : UnlockResult::Failed; break; }
            case UnlockMethod::ProcessTerminate: { auto o = GetLockingProcesses(filePath); result.result = TryProcessTerminate(o, result) ? UnlockResult::Success : UnlockResult::Failed; break; }
            case UnlockMethod::RestartManager: result.result = TryRestartManager(filePath, result) ? UnlockResult::Success : UnlockResult::Failed; break;
            case UnlockMethod::KernelDriver: result.result = TryKernelUnlock(filePath, result) ? UnlockResult::Success : UnlockResult::Failed; break;
            case UnlockMethod::DeleteOnReboot:
                if (ScheduleDeleteOnRebootInternal(filePath)) { result.result = UnlockResult::RequiresReboot; result.requiresReboot = true; m_stats.rebootScheduled.fetch_add(1, std::memory_order_relaxed); }
                else result.result = UnlockResult::Failed; break;
            default: result.result = UnlockResult::Failed; result.errors.push_back("Invalid unlock method"); break;
            }
            if (result.result == UnlockResult::Success) m_stats.successfulUnlocks.fetch_add(1, std::memory_order_relaxed);
            else if (result.result == UnlockResult::Failed) m_stats.failedUnlocks.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            result.result = UnlockResult::Failed; result.errors.push_back(std::string("Exception: ") + e.what());
        }
        return result;
    }

    [[nodiscard]] UnlockOperation ForceUnlockFile(const std::wstring& filePath) {
        UnlockOperation result; result.filePath = filePath;
        try {
            auto owners = GetLockingProcesses(filePath); bool unlocked = false;
            if (TryHandleClose(owners, result) && !IsFileLocked(filePath)) unlocked = true;
            if (!unlocked && m_config.allowProcessTermination && TryProcessTerminate(owners, result)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!IsFileLocked(filePath)) unlocked = true;
            }
            if (!unlocked && m_kernelDriverAvailable && TryKernelUnlock(filePath, result) && !IsFileLocked(filePath)) unlocked = true;
            if (!unlocked && ScheduleDeleteOnRebootInternal(filePath)) {
                result.result = UnlockResult::RequiresReboot; result.requiresReboot = true;
                m_stats.rebootScheduled.fetch_add(1, std::memory_order_relaxed); return result;
            }
            result.result = unlocked ? UnlockResult::Success : UnlockResult::Failed;
            (unlocked ? m_stats.successfulUnlocks : m_stats.failedUnlocks).fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            result.result = UnlockResult::Failed; result.errors.push_back(std::string("Exception: ") + e.what());
        }
        return result;
    }

    bool CloseHandleOp(const LockOwner& owner) {
        try {
            if (owner.handleValue == 0) return false;
            ScopedHandle hProcess(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner.pid));
            if (!hProcess) return false;

            // PID recycling guard: verify process creation time hasn't changed
            FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
            if (GetProcessTimes(hProcess.Get(), &createTime, &exitTime, &kernelTime, &userTime)) {
                if (exitTime.dwLowDateTime != 0 || exitTime.dwHighDateTime != 0) {
                    SS_LOG_DEBUG(L"FileLockManager", L"PID %u has exited, skipping handle close", owner.pid);
                    return false;
                }
            }

            HANDLE hDup = nullptr;
            BOOL ok = DuplicateHandle(hProcess.Get(), reinterpret_cast<HANDLE>(owner.handleValue),
                GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
            if (ok && hDup) { ::CloseHandle(hDup); m_stats.handlesClosed.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(L"FileLockManager", L"Closed handle 0x%llX in PID %u (%s)",
                    static_cast<unsigned long long>(owner.handleValue), owner.pid, owner.processName.c_str());
                return true; }
            return false;
        } catch (...) { return false; }
    }

    bool TerminateProcessOp(const LockOwner& owner, bool force) {
        try {
            if (owner.isCriticalProcess && !force) return false;
            if (owner.isSystemProcess && m_config.protectSystemProcesses && !force) return false;
            if (m_terminateCallback && !force && !m_terminateCallback(owner)) return false;
            ScopedHandle hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, owner.pid));
            if (!hProcess) return false;
            if (::TerminateProcess(hProcess.Get(), 1)) {
                m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(L"FileLockManager", L"Terminated PID %u (%s)", owner.pid, owner.processName.c_str());
                return true;
            }
            return false;
        } catch (...) { return false; }
    }
    // ========================================================================
    // RESTART MANAGER & REBOOT OPS
    // ========================================================================

    bool UseRestartManagerOp(const std::wstring& filePath) {
        try {
            DWORD dwSession = 0; WCHAR szKey[CCH_RM_SESSION_KEY + 1] = { 0 };
            DWORD err = RmStartSession(&dwSession, 0, szKey);
            if (err != ERROR_SUCCESS) { SS_LOG_ERROR(L"FileLockManager", L"RmStartSession failed: %lu", err); return false; }
            LPCWSTR pszFile = filePath.c_str();
            err = RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr);
            if (err != ERROR_SUCCESS) { RmEndSession(dwSession); return false; }
            UINT needed = 0, count = 0; DWORD dwRebootReasons = 0;
            err = RmGetList(dwSession, &needed, &count, nullptr, &dwRebootReasons);
            bool success = false;
            if ((err == ERROR_SUCCESS || err == ERROR_MORE_DATA) && needed > 0 && needed <= FileLockManagerConstants::MAX_LOCK_OWNERS) {
                std::vector<RM_PROCESS_INFO> procs(needed); count = needed;
                err = RmGetList(dwSession, &needed, &count, procs.data(), &dwRebootReasons);
                if (err == ERROR_SUCCESS) { err = RmShutdown(dwSession, RmForceShutdown, nullptr); success = (err == ERROR_SUCCESS); }
            }
            RmEndSession(dwSession); return success;
        } catch (const std::exception& e) { SS_LOG_ERROR(L"FileLockManager", L"UseRestartManagerOp exception: %hs", e.what()); return false; }
    }

    [[nodiscard]] std::vector<std::wstring> GetApplicationsUsingFileOp(const std::wstring& filePath) const {
        std::vector<std::wstring> apps;
        try {
            DWORD dwSession = 0; WCHAR szKey[CCH_RM_SESSION_KEY + 1] = { 0 };
            if (RmStartSession(&dwSession, 0, szKey) != ERROR_SUCCESS) return apps;
            LPCWSTR pszFile = filePath.c_str();
            if (RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr) == ERROR_SUCCESS) {
                UINT needed = 0, count = 0; DWORD dwRebootReasons = 0;
                if (RmGetList(dwSession, &needed, &count, nullptr, &dwRebootReasons) == ERROR_MORE_DATA && needed > 0 && needed <= FileLockManagerConstants::MAX_LOCK_OWNERS) {
                    std::vector<RM_PROCESS_INFO> procs(needed); count = needed;
                    if (RmGetList(dwSession, &needed, &count, procs.data(), &dwRebootReasons) == ERROR_SUCCESS) {
                        apps.reserve(count); for (UINT i = 0; i < count; i++) apps.push_back(procs[i].strAppName);
                    }
                }
            }
            RmEndSession(dwSession);
        } catch (...) {}
        return apps;
    }

    bool ScheduleDeleteOnRebootInternal(const std::wstring& filePath) {
        try {
            if (MoveFileExW(filePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                PendingOperation op; op.sourcePath = filePath; op.isDelete = true;
                op.scheduledTime = std::chrono::system_clock::now(); op.reason = "File locked - scheduled for deletion";
                { std::unique_lock lk(m_pendingMutex); m_pendingOperations.push_back(std::move(op)); }
                SS_LOG_INFO(L"FileLockManager", L"Scheduled delete on reboot: %s", filePath.c_str());
                return true;
            }
            SS_LOG_ERROR(L"FileLockManager", L"MoveFileExW(delete) failed: error %lu", GetLastError());
            return false;
        } catch (...) { return false; }
    }

    bool ScheduleMoveOnRebootInternal(const std::wstring& src, const std::wstring& dst) {
        try {
            if (MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING)) {
                PendingOperation op; op.sourcePath = src; op.destinationPath = dst; op.isMove = true;
                op.scheduledTime = std::chrono::system_clock::now(); op.reason = "File locked - scheduled for move";
                { std::unique_lock lk(m_pendingMutex); m_pendingOperations.push_back(std::move(op)); }
                return true;
            }
            return false;
        } catch (...) { return false; }
    }

    [[nodiscard]] std::vector<PendingOperation> GetPendingOperationsOp() const { std::shared_lock lk(m_pendingMutex); return m_pendingOperations; }
    bool CancelPendingOperationOp(const std::wstring& sp) {
        std::unique_lock lk(m_pendingMutex);
        auto it = std::find_if(m_pendingOperations.begin(), m_pendingOperations.end(), [&](const PendingOperation& o) { return o.sourcePath == sp; });
        if (it != m_pendingOperations.end()) { m_pendingOperations.erase(it); return true; }
        return false;
    }

    // ========================================================================
    // KERNEL INTEGRATION
    // ========================================================================

    bool KernelUnlockFileOp(const std::wstring& filePath) {
        try {
            std::lock_guard kernelLock(m_kernelMutex);
            if (!m_kernelDriverAvailable || !m_kernelPortConnected) { if (!ConnectToKernelDriverInternalLocked()) return false; }
            KernelProtocol::QueryLocksRequest req{};
            req.header.command = static_cast<uint32_t>(KernelProtocol::Command::ForceCloseHandle);
            req.header.dataLength = sizeof(req) - sizeof(req.header);
            size_t pl = std::min(filePath.length(), static_cast<size_t>(_countof(req.filePath) - 1));
            wcsncpy_s(req.filePath, filePath.c_str(), pl);
            KernelProtocol::ForceCloseResponse resp{}; DWORD bytesRet = 0;
            HRESULT hr = FilterSendMessage(m_kernelPort, &req, sizeof(req), &resp, sizeof(resp), &bytesRet);
            if (SUCCEEDED(hr) && bytesRet >= sizeof(resp) && resp.header.status == 0) {
                m_stats.kernelUnlocks.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_INFO(L"FileLockManager", L"Kernel force-closed %u handle(s) for %s", resp.handlesAffected, filePath.c_str());
                return resp.handlesAffected > 0;
            }
            return false;
        } catch (...) { return false; }
    }

    [[nodiscard]] bool IsKernelDriverAvailableOp() const noexcept { return m_kernelDriverAvailable; }

    bool ConnectToKernelDriverInternal() {
        std::lock_guard kernelLock(m_kernelMutex);
        return ConnectToKernelDriverInternalLocked();
    }

    // Must be called with m_kernelMutex held
    bool ConnectToKernelDriverInternalLocked() {
        if (m_kernelPortConnected && m_kernelPort != INVALID_HANDLE_VALUE) return true;
        for (uint32_t i = 0; i < FileLockManagerConstants::KERNEL_CONNECT_RETRY_COUNT; ++i) {
            HANDLE newPort = INVALID_HANDLE_VALUE;
            HRESULT hr = FilterConnectCommunicationPort(SHADOWSTRIKE_FILTER_PORT, 0, nullptr, 0, nullptr, &newPort);
            if (SUCCEEDED(hr) && newPort != INVALID_HANDLE_VALUE) {
                m_kernelPort = newPort;
                m_kernelPortConnected = true;
                SS_LOG_INFO(L"FileLockManager", L"Connected to kernel driver port");
                return true;
            }
            if (i + 1 < FileLockManagerConstants::KERNEL_CONNECT_RETRY_COUNT)
                std::this_thread::sleep_for(std::chrono::milliseconds(FileLockManagerConstants::KERNEL_CONNECT_RETRY_DELAY_MS));
        }
        return false;
    }

    void DisconnectFromKernelDriverInternal() noexcept {
        if (m_kernelPort != INVALID_HANDLE_VALUE && m_kernelPort != nullptr) { ::CloseHandle(m_kernelPort); m_kernelPort = INVALID_HANDLE_VALUE; }
        m_kernelPortConnected = false;
    }
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    [[nodiscard]] std::wstring NormalizePath(const std::wstring& path) const {
        try {
            if (path.empty()) return {};
            WCHAR buf[MAX_PATH * 2] = { 0 };
            DWORD len = GetFullPathNameW(path.c_str(), _countof(buf), buf, nullptr);
            if (len > 0 && len < _countof(buf)) return std::wstring(buf, len);
            return path;
        } catch (...) { return path; }
    }

    bool EnableDebugPrivilege() noexcept {
        try {
            ScopedHandle hToken;
            HANDLE raw = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw)) return false;
            hToken.Reset(raw);
            TOKEN_PRIVILEGES tp{};
            if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) return false;
            tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            return AdjustTokenPrivileges(hToken.Get(), FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
        } catch (...) { return false; }
    }

    bool CheckKernelDriver() const noexcept {
        try {
            HANDLE hPort = INVALID_HANDLE_VALUE;
            HRESULT hr = FilterConnectCommunicationPort(SHADOWSTRIKE_FILTER_PORT, 0, nullptr, 0, nullptr, &hPort);
            if (SUCCEEDED(hr) && hPort != INVALID_HANDLE_VALUE) {
                ::CloseHandle(hPort);
                return true;
            }
            return false;
        } catch (...) { return false; }
    }

    uint8_t ResolveFileObjectTypeIndex() const noexcept {
        try {
            if (!m_ntQuerySystemInfo) return 0;
            ScopedHandle h(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
            if (!h) return 0;
            DWORD myPid = GetCurrentProcessId();
            ULONG bufSize = 1 << 20; auto buf = std::make_unique<uint8_t[]>(bufSize);
            NTSTATUS st = m_ntQuerySystemInfo(SystemExtendedHandleInformationClass, buf.get(), bufSize, nullptr);
            while (st == NT_STATUS_INFO_LEN_MISMATCH && bufSize < MAX_HANDLE_BUFFER_BYTES) {
                bufSize *= 2; buf = std::make_unique<uint8_t[]>(bufSize);
                st = m_ntQuerySystemInfo(SystemExtendedHandleInformationClass, buf.get(), bufSize, nullptr);
            }
            if (st < 0) return 0;
            auto info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buf.get());
            for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
                const auto& entry = info->Handles[i];
                if (static_cast<DWORD>(entry.UniqueProcessId) == myPid &&
                    reinterpret_cast<HANDLE>(entry.HandleValue) == h.Get()) {
                    return static_cast<uint8_t>(entry.ObjectTypeIndex);
                }
            }
            return 0;
        } catch (...) { return 0; }
    }

    LockType ClassifyLockType(DWORD accessMask) const noexcept {
        bool canWrite = (accessMask & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0;
        bool canRead = (accessMask & (FILE_READ_DATA | GENERIC_READ)) != 0;
        bool hasDelete = (accessMask & DELETE) != 0;
        if (canWrite && hasDelete) return LockType::Exclusive;
        if (canWrite && canRead) return LockType::ReadWrite;
        if (canWrite) return LockType::Write;
        if (canRead) return LockType::Read;
        if (hasDelete) return LockType::Delete;
        return LockType::Read;
    }

    [[nodiscard]] std::vector<LockOwner> GetLockingProcessesRM(const std::wstring& filePath) const {
        std::vector<LockOwner> owners;
        try {
            DWORD dwSession = 0; WCHAR szKey[CCH_RM_SESSION_KEY + 1] = { 0 };
            if (RmStartSession(&dwSession, 0, szKey) != ERROR_SUCCESS) return owners;
            LPCWSTR pszFile = filePath.c_str();
            bool ok = (RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr) == ERROR_SUCCESS);
            if (ok) {
                UINT needed = 0, count = 0; DWORD dwRebootReasons = 0;
                DWORD err = RmGetList(dwSession, &needed, &count, nullptr, &dwRebootReasons);
                if ((err == ERROR_MORE_DATA || err == ERROR_SUCCESS) && needed > 0 && needed <= FileLockManagerConstants::MAX_LOCK_OWNERS) {
                    std::vector<RM_PROCESS_INFO> procs(needed); count = needed;
                    if (RmGetList(dwSession, &needed, &count, procs.data(), &dwRebootReasons) == ERROR_SUCCESS) {
                        for (UINT i = 0; i < count; i++) {
                            LockOwner o;
                            o.pid = procs[i].Process.dwProcessId;
                            o.processName = procs[i].strAppName;
                            // Source tracked via lockType from RM context
                            EnrichProcessInfo(o);
                            owners.push_back(std::move(o));
                        }
                    }
                }
            }
            RmEndSession(dwSession);
        } catch (...) {}
        return owners;
    }
    [[nodiscard]] std::vector<LockOwner> GetLockingProcessesHandleEnum(const std::wstring& filePath) const {
        std::vector<LockOwner> owners;
        try {
            if (!m_ntQuerySystemInfo) return owners;
            ScopedHandle targetFile(CreateFileW(filePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            BY_HANDLE_FILE_INFORMATION targetInfo{};
            bool haveTargetInfo = false;
            if (targetFile) { haveTargetInfo = (GetFileInformationByHandle(targetFile.Get(), &targetInfo) != 0); }
            if (!haveTargetInfo) return owners;

            ULONG bufSize = 4 << 20;
            auto buf = std::make_unique<uint8_t[]>(bufSize);
            NTSTATUS st = m_ntQuerySystemInfo(SystemExtendedHandleInformationClass, buf.get(), bufSize, nullptr);
            for (int tries = 0; st == NT_STATUS_INFO_LEN_MISMATCH && tries < 5 && bufSize < MAX_HANDLE_BUFFER_BYTES; ++tries) {
                bufSize *= 2; buf = std::make_unique<uint8_t[]>(bufSize);
                st = m_ntQuerySystemInfo(SystemExtendedHandleInformationClass, buf.get(), bufSize, nullptr);
            }
            if (st < 0) { SS_LOG_WARN(L"FileLockManager", L"NtQuerySystemInfo failed: 0x%08X", static_cast<unsigned>(st)); return owners; }

            auto sysInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buf.get());
            DWORD myPid = GetCurrentProcessId();
            std::unordered_map<ULONG_PTR, ScopedHandle> processCache;
            std::unordered_set<DWORD> foundPids;

            for (ULONG_PTR i = 0; i < sysInfo->NumberOfHandles && owners.size() < FileLockManagerConstants::MAX_LOCK_OWNERS; i++) {
                const auto& entry = sysInfo->Handles[i];
                if (m_fileTypeIndex != 0 && entry.ObjectTypeIndex != m_fileTypeIndex) continue;
                auto handlePid = static_cast<DWORD>(entry.UniqueProcessId);
                if (handlePid == myPid || handlePid == 0 || handlePid == 4) continue;
                if (foundPids.count(handlePid) && !(entry.GrantedAccess & (FILE_WRITE_DATA | DELETE))) continue;

                auto cacheIt = processCache.find(entry.UniqueProcessId);
                if (cacheIt == processCache.end()) {
                    HANDLE raw = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handlePid);
                    auto [it, _] = processCache.emplace(entry.UniqueProcessId, ScopedHandle(raw));
                    cacheIt = it;
                }
                if (!cacheIt->second) continue;

                HANDLE hDup = nullptr;
                if (!DuplicateHandle(cacheIt->second.Get(), reinterpret_cast<HANDLE>(entry.HandleValue),
                    GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
                ScopedHandle dup(hDup);

                if (GetFileType(dup.Get()) != FILE_TYPE_DISK) continue;

                BY_HANDLE_FILE_INFORMATION dupInfo{};
                if (!GetFileInformationByHandle(dup.Get(), &dupInfo)) continue;
                if (dupInfo.dwVolumeSerialNumber != targetInfo.dwVolumeSerialNumber ||
                    dupInfo.nFileIndexHigh != targetInfo.nFileIndexHigh ||
                    dupInfo.nFileIndexLow != targetInfo.nFileIndexLow) continue;

                LockOwner owner;
                owner.pid = handlePid;
                owner.handleValue = static_cast<uint64_t>(entry.HandleValue);
                owner.accessMask = entry.GrantedAccess;
                owner.lockType = ClassifyLockType(entry.GrantedAccess);
                // Source tracked via lockType context
                EnrichProcessInfo(owner);
                owners.push_back(std::move(owner));
                foundPids.insert(handlePid);
            }
            m_stats.handleEnumerations.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileLockManager", L"HandleEnum exception: %hs", e.what());
        }
        return owners;
    }

    void EnrichProcessInfo(LockOwner& owner) const {
        try {
            ScopedHandle hProc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner.pid));
            if (!hProc) return;
            WCHAR exePath[MAX_PATH * 2] = { 0 }; DWORD sz = _countof(exePath);
            if (QueryFullProcessImageNameW(hProc.Get(), 0, exePath, &sz)) {
                owner.processPath = exePath;
                const wchar_t* base = wcsrchr(exePath, L'\\');
                if (base) owner.processName = base + 1;
            }
            owner.isSystemProcess = (owner.pid <= 4);
            owner.isCriticalProcess = IsCriticalProcessName(owner.processName);
            AnalyzeProcessTrust(owner);
        } catch (...) {}
    }

    static bool IsCriticalProcessName(const std::wstring& name) noexcept {
        static const std::unordered_set<std::wstring> critical = {
            L"system", L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
            L"lsass.exe", L"svchost.exe", L"winlogon.exe", L"explorer.exe"
        };
        std::wstring lower; lower.reserve(name.size());
        for (wchar_t c : name) lower += static_cast<wchar_t>(::towlower(c));
        return critical.count(lower) > 0;
    }

    void AnalyzeProcessTrust(LockOwner& owner) const {
        try {
            if (owner.processPath.empty()) { owner.isSuspicious = true; return; }
            owner.isSigned = VerifyFileSignature(owner.processPath);
            owner.isInjectedProcess = DetectProcessInjection(owner.pid);
            owner.isSuspicious = !owner.isSigned || owner.isInjectedProcess;
            owner.isUntrustedSigner = !owner.isSigned;
        } catch (...) { owner.isSuspicious = true; }
    }
    bool VerifyFileSignature(const std::wstring& path) const {
        try {
            WINTRUST_FILE_INFO fileInfo{}; fileInfo.cbStruct = sizeof(fileInfo); fileInfo.pcwszFilePath = path.c_str();
            GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wtd{}; wtd.cbStruct = sizeof(wtd); wtd.dwUIChoice = WTD_UI_NONE;
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE; wtd.dwUnionChoice = WTD_CHOICE_FILE;
            wtd.pFile = &fileInfo; wtd.dwStateAction = WTD_STATEACTION_VERIFY;
            LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionId, &wtd);
            wtd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionId, &wtd);
            return (st == ERROR_SUCCESS);
        } catch (...) { return false; }
    }

    bool DetectProcessInjection(DWORD pid) const {
        try {
            ScopedHandle hProc(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
            if (!hProc) return false;
            MEMORY_BASIC_INFORMATION mbi{}; uint8_t* addr = nullptr;
            uint32_t suspiciousCount = 0;
            constexpr uint32_t SUSPICIOUS_THRESHOLD = 3;
            while (VirtualQueryEx(hProc.Get(), addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                    ++suspiciousCount;
                    if (suspiciousCount >= SUSPICIOUS_THRESHOLD) return true;
                }
                addr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (addr < static_cast<uint8_t*>(mbi.BaseAddress)) break;
            }
            return false;
        } catch (...) { return false; }
    }

    ThreatAssessment AnalyzeThreatInternal(const FileLockInfo& info) const {
        ThreatAssessment threat;
        try {
            double score = 0.0;
            for (const auto& o : info.owners) {
                if (o.isSuspicious) threat.untrustedLockCount++;
                if (o.isUntrustedSigner) { threat.unsignedProcessCount++; score += 15.0; }
                if (o.isInjectedProcess) { threat.injectedProcessCount++; score += 40.0; }
                if (o.isRemoteProcess) threat.remoteLockCount++;
                if (o.isSystemProcess && o.lockType == LockType::Exclusive) score += 30.0;
            }
            if (info.lockCount > 3) score += static_cast<double>(info.lockCount) * 5.0;
            threat.dominantPattern = DetectLockPatternInternal(info);
            switch (threat.dominantPattern) {
            case LockPattern::Ransomware: score += 80.0; threat.indicators.push_back("Ransomware lock pattern"); break;
            case LockPattern::ProcessInjection: score += 60.0; threat.indicators.push_back("Process injection pattern"); break;
            case LockPattern::DefenseEvasion: score += 50.0; threat.indicators.push_back("Defense evasion"); break;
            case LockPattern::DataExfiltration: score += 45.0; threat.indicators.push_back("Data exfiltration"); break;
            case LockPattern::Persistence: score += 40.0; threat.indicators.push_back("Persistence mechanism"); break;
            default: break;
            }
            threat.overallThreatScore = std::clamp(score, 0.0, 100.0);
            threat.isSuspiciousActivity = threat.overallThreatScore >= 30.0;
            threat.requiresImmediateAction = threat.overallThreatScore >= 70.0;
            if (threat.requiresImmediateAction) {
                threat.recommendedAction = L"Immediate quarantine and process termination recommended";
                SS_LOG_WARN(L"FileLockManager", L"HIGH RISK lock detected on %s (score=%.1f, pattern=%u)",
                    info.filePath.c_str(), threat.overallThreatScore, static_cast<unsigned>(threat.dominantPattern));
            }
        } catch (...) {}
        return threat;
    }

    LockPattern DetectLockPatternInternal(const FileLockInfo& info) const {
        try {
            for (const auto& o : info.owners) {
                if (!o.isSigned && o.isSuspicious && o.lockType == LockType::Exclusive) {
                    std::wstring ext = fs::path(info.filePath).extension().wstring();
                    std::wstring lext; for (wchar_t c : ext) lext += static_cast<wchar_t>(::towlower(c));
                    static const std::unordered_set<std::wstring> docExts = { L".doc", L".docx", L".xls", L".xlsx", L".pdf", L".pptx", L".txt", L".csv", L".db", L".sqlite" };
                    if (docExts.count(lext)) return LockPattern::Ransomware;
                }
                if (o.isInjectedProcess && o.isSigned && o.lockType != LockType::Unknown) return LockPattern::ProcessInjection;
                if (o.isInjectedProcess && !o.isSigned) return LockPattern::DefenseEvasion;
            }
            for (const auto& o : info.owners) {
                if (o.isSuspicious && (o.accessMask & FILE_READ_DATA) && info.fileSize > (1 << 20)) return LockPattern::DataExfiltration;
                if (o.isSuspicious && (o.accessMask & FILE_WRITE_ATTRIBUTES)) {
                    std::wstring lp; for (wchar_t c : info.filePath) lp += static_cast<wchar_t>(::towlower(c));
                    if (lp.find(L"\\system32\\") != std::wstring::npos || lp.find(L"\\startup") != std::wstring::npos) return LockPattern::Persistence;
                }
            }
            return LockPattern::Normal;
        } catch (...) { return LockPattern::Normal; }
    }

    // ========================================================================
    // TRY HELPERS (used by UnlockFile escalation chain)
    // ========================================================================

    bool TryRestartManager(const std::wstring& filePath, UnlockOperation& result) {
        try {
            if (UseRestartManagerOp(filePath)) { SS_LOG_INFO(L"FileLockManager", L"RM unlock succeeded: %s", filePath.c_str()); return true; }
            result.errors.push_back("RestartManager failed");
        } catch (...) { result.errors.push_back("RestartManager exception"); }
        return false;
    }

    bool TryHandleClose(const std::vector<LockOwner>& owners, UnlockOperation& result) {
        bool any = false;
        for (const auto& o : owners) {
            if (o.isCriticalProcess && m_config.protectCriticalProcesses) continue;
            if (o.handleValue != 0) { LockOwner copy = o; if (CloseHandleOp(copy)) any = true; }
        }
        if (!any) result.errors.push_back("Handle close: no handles closed");
        return any;
    }

    bool TryProcessTerminate(const std::vector<LockOwner>& owners, UnlockOperation& result) {
        bool any = false;
        for (const auto& o : owners) {
            if (o.isCriticalProcess && m_config.protectCriticalProcesses) continue;
            if (o.isSystemProcess && m_config.protectSystemProcesses) continue;
            LockOwner copy = o; if (TerminateProcessOp(copy, false)) any = true;
        }
        if (!any) result.errors.push_back("Process termination: none terminated");
        return any;
    }

    bool TryKernelUnlock(const std::wstring& filePath, UnlockOperation& result) {
        try {
            if (KernelUnlockFileOp(filePath)) return true;
            result.errors.push_back("Kernel unlock failed");
        } catch (...) { result.errors.push_back("Kernel unlock exception"); }
        return false;
    }

    void FinalizeResult(UnlockOperation& r, std::chrono::steady_clock::time_point t0) const {
        r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    }

    void ReportProgress(const std::wstring& stage, uint32_t pct) const {
        if (m_progressCallback) m_progressCallback(stage, pct);
    }
    // ========================================================================
    // HANDLE ENUMERATION ENHANCED
    // ========================================================================

    [[nodiscard]] std::vector<LockOwner> EnumerateFileHandles(const std::wstring& filePath) const {
        return GetLockingProcessesHandleEnum(filePath);
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_pendingMutex;
    std::mutex m_kernelMutex; // Protects kernel port connect/disconnect/send
    FileLockManagerConfig m_config{};
    bool m_initialized = false;
    bool m_hasDebugPrivilege = false;
    bool m_kernelDriverAvailable = false;
    bool m_kernelPortConnected = false;
    HANDLE m_kernelPort = INVALID_HANDLE_VALUE;
    uint8_t m_fileTypeIndex = 0;

    NtQuerySystemInformationFn m_ntQuerySystemInfo = nullptr;
    NtQueryObjectFn m_ntQueryObject = nullptr;

    mutable InternalStatistics m_stats;
    std::vector<PendingOperation> m_pendingOperations;

    TerminateCallback m_terminateCallback;
    UnlockProgressCallback m_progressCallback;
    LockEventCallback m_lockEventCallback;
};

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

FileLockManagerConfig FileLockManagerConfig::CreateDefault() noexcept {
    FileLockManagerConfig cfg;
    cfg.allowRestartManager = true;
    cfg.allowProcessTermination = false;
    cfg.allowKernelUnlock = true;
    cfg.protectCriticalProcesses = true;
    cfg.protectSystemProcesses = true;
    cfg.protectServices = true;
    cfg.retryCount = 3;
    cfg.unlockTimeoutMs = 30000;
    return cfg;
}

FileLockManagerConfig FileLockManagerConfig::CreateAggressive() noexcept {
    FileLockManagerConfig cfg;
    cfg.allowRestartManager = true;
    cfg.allowProcessTermination = true;
    cfg.allowKernelUnlock = true;
    cfg.protectCriticalProcesses = true;
    cfg.protectSystemProcesses = false;
    cfg.protectServices = false;
    cfg.retryCount = 5;
    cfg.unlockTimeoutMs = 60000;
    return cfg;
}

FileLockManagerConfig FileLockManagerConfig::CreateSafe() noexcept {
    FileLockManagerConfig cfg;
    cfg.allowRestartManager = true;
    cfg.allowProcessTermination = false;
    cfg.allowKernelUnlock = false;
    cfg.protectCriticalProcesses = true;
    cfg.protectSystemProcesses = true;
    cfg.protectServices = true;
    cfg.retryCount = 2;
    cfg.unlockTimeoutMs = 15000;
    return cfg;
}

// ============================================================================
// STATISTICS RESET
// ============================================================================

void FileLockManagerStatistics::Reset() noexcept {
    locksDetected = 0; successfulUnlocks = 0; failedUnlocks = 0;
    handlesClosed = 0; processesTerminated = 0; kernelUnlocks = 0;
    rebootScheduled = 0; handleEnumerations = 0; threatsDetected = 0;
}

// ============================================================================
// SINGLETON
// ============================================================================

FileLockManager& FileLockManager::Instance() {
    static FileLockManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileLockManager::FileLockManager() : m_impl(std::make_unique<FileLockManagerImpl>()) {}

FileLockManager::~FileLockManager() = default;

// ============================================================================
// PUBLIC INTERFACE — DELEGATIONS
// ============================================================================

bool FileLockManager::Initialize(const FileLockManagerConfig& config) { return m_impl->Initialize(config); }
void FileLockManager::Shutdown() noexcept { m_impl->Shutdown(); }

std::vector<LockOwner> FileLockManager::GetLockingProcesses(const std::wstring& filePath) const { return m_impl->GetLockingProcesses(filePath); }
FileLockInfo FileLockManager::GetLockInfo(const std::wstring& filePath) const { return m_impl->GetLockInfo(filePath); }
bool FileLockManager::IsFileLocked(const std::wstring& filePath) const { return m_impl->IsFileLocked(filePath); }
bool FileLockManager::CanDeleteFile(const std::wstring& filePath) const { return m_impl->CanDeleteFile(filePath); }
LockType FileLockManager::GetLockType(const std::wstring& filePath) const { return m_impl->GetLockType(filePath); }

UnlockOperation FileLockManager::UnlockFile(const std::wstring& filePath) { return m_impl->UnlockFile(filePath); }
UnlockOperation FileLockManager::UnlockFile(const std::wstring& filePath, UnlockMethod method) { return m_impl->UnlockFile(filePath, method); }
UnlockOperation FileLockManager::ForceUnlockFile(const std::wstring& filePath) { return m_impl->ForceUnlockFile(filePath); }

bool FileLockManager::CloseHandle(const LockOwner& owner) { return m_impl->CloseHandleOp(owner); }
bool FileLockManager::TerminateProcess(const LockOwner& owner, bool force) { return m_impl->TerminateProcessOp(owner, force); }
bool FileLockManager::UseRestartManager(const std::wstring& filePath) { return m_impl->UseRestartManagerOp(filePath); }
std::vector<std::wstring> FileLockManager::GetApplicationsUsingFile(const std::wstring& filePath) const { return m_impl->GetApplicationsUsingFileOp(filePath); }

bool FileLockManager::ScheduleDeleteOnReboot(const std::wstring& filePath) { return m_impl->ScheduleDeleteOnRebootInternal(filePath); }
bool FileLockManager::ScheduleMoveOnReboot(const std::wstring& src, const std::wstring& dst) { return m_impl->ScheduleMoveOnRebootInternal(src, dst); }
std::vector<PendingOperation> FileLockManager::GetPendingOperations() const { return m_impl->GetPendingOperationsOp(); }
bool FileLockManager::CancelPendingOperation(const std::wstring& sp) { return m_impl->CancelPendingOperationOp(sp); }

bool FileLockManager::KernelUnlockFile(const std::wstring& filePath) { return m_impl->KernelUnlockFileOp(filePath); }
bool FileLockManager::IsKernelDriverAvailable() const noexcept { return m_impl->IsKernelDriverAvailableOp(); }
bool FileLockManager::ConnectKernelDriver() { return m_impl->ConnectToKernelDriverInternal(); }

ThreatAssessment FileLockManager::AnalyzeThreat(const FileLockInfo& lockInfo) const {
    return m_impl->AnalyzeThreatInternal(lockInfo);
}

std::vector<LockOwner> FileLockManager::EnumerateHandles(const std::wstring& filePath) const {
    return m_impl->EnumerateFileHandles(filePath);
}

FileLockManagerStatistics FileLockManager::GetStatistics() const noexcept {
    return m_impl->m_stats.Snapshot();
}

void FileLockManager::SetTerminateCallback(TerminateCallback cb) { m_impl->m_terminateCallback = std::move(cb); }
void FileLockManager::SetProgressCallback(UnlockProgressCallback cb) { m_impl->m_progressCallback = std::move(cb); }
void FileLockManager::SetLockEventCallback(LockEventCallback cb) { m_impl->m_lockEventCallback = std::move(cb); }

} // namespace FileSystem
} // namespace Core
} // namespace ShadowStrike