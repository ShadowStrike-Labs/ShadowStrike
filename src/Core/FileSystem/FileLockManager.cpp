/**
 * ============================================================================
 * ShadowStrike Core FileSystem - FILE LOCK MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file FileLockManager.cpp
 * @brief Enterprise-grade file lock detection and handle management.
 *
 * This module provides comprehensive capabilities to identify processes
 * holding file locks and safely release them when necessary for malware
 * remediation and quarantine operations.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Windows Restart Manager integration
 * - Kernel handle enumeration via NtQuerySystemInformation
 * - Safe process termination with critical process protection
 * - MoveFileEx for delete-on-reboot scheduling
 *
 * Windows API Integration:
 * - NtQuerySystemInformation: Handle enumeration
 * - Restart Manager: Application-aware unlocking
 * - DuplicateHandle/CloseHandle: Handle management
 * - MoveFileEx: Reboot operations
 * - OpenProcess/TerminateProcess: Process control
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "FileLockManager.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <RestartManager.h>
#include <Psapi.h>
#include <tlhelp32.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <filesystem>
#include <algorithm>
#include <thread>
#include <chrono>

#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // System process PIDs
    constexpr uint32_t SYSTEM_PID = 4;
    constexpr uint32_t IDLE_PID = 0;

    // Critical processes that should never be terminated
    const std::unordered_set<std::wstring> CRITICAL_PROCESSES = {
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"services.exe",
        L"lsass.exe",
        L"winlogon.exe",
        L"System",
        L"dwm.exe"
    };

    // System processes to protect
    const std::unordered_set<std::wstring> SYSTEM_PROCESSES = {
        L"svchost.exe",
        L"explorer.exe",
        L"conhost.exe",
        L"RuntimeBroker.exe",
        L"taskhostw.exe"
    };

    // NT API constants
    constexpr NTSTATUS STATUS_SUCCESS = 0x00000000;
    constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

} // anonymous namespace

// ============================================================================
// NT API DECLARATIONS
// ============================================================================

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FileLockManagerImpl final {
public:
    FileLockManagerImpl() = default;
    ~FileLockManagerImpl() = default;

    // Delete copy/move
    FileLockManagerImpl(const FileLockManagerImpl&) = delete;
    FileLockManagerImpl& operator=(const FileLockManagerImpl&) = delete;
    FileLockManagerImpl(FileLockManagerImpl&&) = delete;
    FileLockManagerImpl& operator=(FileLockManagerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const FileLockManagerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            m_initialized = true;

            // Check if we have SeDebugPrivilege
            m_hasDebugPrivilege = EnableDebugPrivilege();

            // Check kernel driver availability
            m_kernelDriverAvailable = CheckKernelDriver();

            Logger::Info("FileLockManager initialized (debug={}, kernel={})",
                m_hasDebugPrivilege, m_kernelDriverAvailable);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("FileLockManager initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_terminateCallback = nullptr;
            m_progressCallback = nullptr;
            m_initialized = false;

            Logger::Info("FileLockManager shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    // ========================================================================
    // LOCK DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<LockOwner> GetLockingProcesses(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        std::vector<LockOwner> owners;

        try {
            // Normalize path
            auto normalizedPath = NormalizePath(filePath);
            if (normalizedPath.empty()) {
                Logger::Warn("Invalid file path: {}", StringUtils::WideToUtf8(filePath));
                return owners;
            }

            // Try Restart Manager first (faster and more reliable)
            auto rmOwners = GetLockingProcessesRM(normalizedPath);
            if (!rmOwners.empty()) {
                return rmOwners;
            }

            // Fallback to handle enumeration
            owners = GetLockingProcessesHandleEnum(normalizedPath);

        } catch (const std::exception& e) {
            Logger::Error("GetLockingProcesses - Exception: {}", e.what());
        }

        return owners;
    }

    [[nodiscard]] FileLockInfo GetLockInfo(const std::wstring& filePath) const {
        FileLockInfo info;
        info.filePath = filePath;

        try {
            // Check if file exists
            if (!fs::exists(filePath)) {
                info.fileExists = false;
                return info;
            }

            info.isDirectory = fs::is_directory(filePath);
            if (!info.isDirectory) {
                info.fileSize = fs::file_size(filePath);
            }

            // Get locking processes
            info.owners = GetLockingProcesses(filePath);
            info.lockCount = static_cast<uint32_t>(info.owners.size());
            info.isLocked = (info.lockCount > 0);

            // Analyze lock owners
            for (const auto& owner : info.owners) {
                if (owner.isSystemProcess) {
                    info.hasSystemLock = true;
                }
                if (owner.isCriticalProcess) {
                    info.hasCriticalLock = true;
                    info.canForceUnlock = false;
                }
            }

            m_stats.locksDetected++;

        } catch (const std::exception& e) {
            Logger::Error("GetLockInfo - Exception: {}", e.what());
        }

        return info;
    }

    [[nodiscard]] bool IsFileLocked(const std::wstring& filePath) const {
        try {
            // Quick check: try to open with exclusive access
            HANDLE hFile = CreateFileW(
                filePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, // No sharing
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return false; // Not locked
            }

            DWORD error = GetLastError();
            if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
                return true; // Locked
            }

            // File might not exist or other error
            return false;

        } catch (const std::exception& e) {
            Logger::Error("IsFileLocked - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool CanDeleteFile(const std::wstring& filePath) const {
        try {
            // Try to open with DELETE access
            HANDLE hFile = CreateFileW(
                filePath.c_str(),
                DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("CanDeleteFile - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] LockType GetLockType(const std::wstring& filePath) const {
        try {
            // Try different access modes to determine lock type

            // Check for read lock
            HANDLE hRead = CreateFileW(filePath.c_str(), GENERIC_READ,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

            // Check for write lock
            HANDLE hWrite = CreateFileW(filePath.c_str(), GENERIC_WRITE,
                FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

            LockType type = LockType::Unknown;

            if (hRead == INVALID_HANDLE_VALUE && hWrite == INVALID_HANDLE_VALUE) {
                type = LockType::Exclusive;
            } else if (hWrite == INVALID_HANDLE_VALUE) {
                type = LockType::Write;
            } else if (hRead == INVALID_HANDLE_VALUE) {
                type = LockType::Read;
            }

            if (hRead != INVALID_HANDLE_VALUE) CloseHandle(hRead);
            if (hWrite != INVALID_HANDLE_VALUE) CloseHandle(hWrite);

            return type;

        } catch (const std::exception& e) {
            Logger::Error("GetLockType - Exception: {}", e.what());
            return LockType::Unknown;
        }
    }

    // ========================================================================
    // UNLOCK OPERATIONS
    // ========================================================================

    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath) {
        auto startTime = std::chrono::steady_clock::now();
        UnlockOperation result;
        result.filePath = filePath;

        try {
            ReportProgress(L"Detecting file locks", 10);

            // Check if file is locked
            if (!IsFileLocked(filePath)) {
                result.result = UnlockResult::NotLocked;
                result.method = UnlockMethod::None;
                Logger::Info("File not locked: {}", StringUtils::WideToUtf8(filePath));
                return result;
            }

            // Get lock owners
            auto owners = GetLockingProcesses(filePath);
            if (owners.empty()) {
                result.result = UnlockResult::NotLocked;
                return result;
            }

            ReportProgress(L"Analyzing lock owners", 30);

            // Check for critical processes
            for (const auto& owner : owners) {
                if (owner.isCriticalProcess && m_config.protectCriticalProcesses) {
                    result.result = UnlockResult::ProcessCritical;
                    result.errors.push_back("File locked by critical process: " +
                        StringUtils::WideToUtf8(owner.processName));
                    Logger::Warn("Cannot unlock - critical process: {}",
                        StringUtils::WideToUtf8(owner.processName));
                    return result;
                }
            }

            // Try unlock methods in order of preference
            ReportProgress(L"Attempting unlock", 50);

            // 1. Try Restart Manager
            if (m_config.allowRestartManager && TryRestartManager(filePath, result)) {
                result.result = UnlockResult::Success;
                result.method = UnlockMethod::RestartManager;
                m_stats.successfulUnlocks++;
                return result;
            }

            // 2. Try handle closing
            if (TryHandleClose(owners, result)) {
                result.result = UnlockResult::Success;
                result.method = UnlockMethod::HandleClose;
                m_stats.successfulUnlocks++;
                return result;
            }

            // 3. Try kernel unlock
            if (m_config.allowKernelUnlock && m_kernelDriverAvailable) {
                if (TryKernelUnlock(filePath, result)) {
                    result.result = UnlockResult::Success;
                    result.method = UnlockMethod::KernelDriver;
                    m_stats.successfulUnlocks++;
                    return result;
                }
            }

            // 4. Schedule delete on reboot
            ReportProgress(L"Scheduling reboot operation", 90);
            if (ScheduleDeleteOnRebootInternal(filePath)) {
                result.result = UnlockResult::RequiresReboot;
                result.method = UnlockMethod::DeleteOnReboot;
                result.requiresReboot = true;
                result.pendingOperation = L"Delete on reboot";
                m_stats.rebootScheduled++;
                Logger::Info("Scheduled delete on reboot: {}",
                    StringUtils::WideToUtf8(filePath));
                return result;
            }

            // All methods failed
            result.result = UnlockResult::Failed;
            result.errors.push_back("All unlock methods failed");
            m_stats.failedUnlocks++;

        } catch (const std::exception& e) {
            Logger::Error("UnlockFile - Exception: {}", e.what());
            result.result = UnlockResult::Failed;
            result.errors.push_back(std::string("Exception: ") + e.what());
            m_stats.failedUnlocks++;
        }

        auto endTime = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

        ReportProgress(L"Unlock complete", 100);

        return result;
    }

    [[nodiscard]] UnlockOperation UnlockFile(const std::wstring& filePath, UnlockMethod method) {
        UnlockOperation result;
        result.filePath = filePath;
        result.method = method;

        try {
            switch (method) {
                case UnlockMethod::HandleClose: {
                    auto owners = GetLockingProcesses(filePath);
                    if (TryHandleClose(owners, result)) {
                        result.result = UnlockResult::Success;
                        m_stats.successfulUnlocks++;
                    } else {
                        result.result = UnlockResult::Failed;
                        m_stats.failedUnlocks++;
                    }
                    break;
                }

                case UnlockMethod::ProcessTerminate: {
                    auto owners = GetLockingProcesses(filePath);
                    if (TryProcessTerminate(owners, result)) {
                        result.result = UnlockResult::Success;
                        m_stats.successfulUnlocks++;
                    } else {
                        result.result = UnlockResult::Failed;
                        m_stats.failedUnlocks++;
                    }
                    break;
                }

                case UnlockMethod::RestartManager: {
                    if (TryRestartManager(filePath, result)) {
                        result.result = UnlockResult::Success;
                        m_stats.successfulUnlocks++;
                    } else {
                        result.result = UnlockResult::Failed;
                        m_stats.failedUnlocks++;
                    }
                    break;
                }

                case UnlockMethod::KernelDriver: {
                    if (TryKernelUnlock(filePath, result)) {
                        result.result = UnlockResult::Success;
                        m_stats.successfulUnlocks++;
                    } else {
                        result.result = UnlockResult::Failed;
                        m_stats.failedUnlocks++;
                    }
                    break;
                }

                case UnlockMethod::DeleteOnReboot: {
                    if (ScheduleDeleteOnRebootInternal(filePath)) {
                        result.result = UnlockResult::RequiresReboot;
                        result.requiresReboot = true;
                        m_stats.rebootScheduled++;
                    } else {
                        result.result = UnlockResult::Failed;
                        m_stats.failedUnlocks++;
                    }
                    break;
                }

                default:
                    result.result = UnlockResult::Failed;
                    result.errors.push_back("Invalid unlock method");
                    break;
            }

        } catch (const std::exception& e) {
            Logger::Error("UnlockFile (method) - Exception: {}", e.what());
            result.result = UnlockResult::Failed;
            result.errors.push_back(std::string("Exception: ") + e.what());
        }

        return result;
    }

    [[nodiscard]] UnlockOperation ForceUnlockFile(const std::wstring& filePath) {
        UnlockOperation result;
        result.filePath = filePath;

        try {
            auto owners = GetLockingProcesses(filePath);

            // Try all methods aggressively
            bool success = false;

            // 1. Handle close
            if (TryHandleClose(owners, result)) {
                success = true;
            }

            // 2. Process termination (if allowed)
            if (!success && m_config.allowProcessTermination) {
                if (TryProcessTerminate(owners, result)) {
                    success = true;
                }
            }

            // 3. Kernel unlock
            if (!success && m_kernelDriverAvailable) {
                if (TryKernelUnlock(filePath, result)) {
                    success = true;
                }
            }

            // 4. Reboot scheduling
            if (!success) {
                if (ScheduleDeleteOnRebootInternal(filePath)) {
                    result.result = UnlockResult::RequiresReboot;
                    result.requiresReboot = true;
                    m_stats.rebootScheduled++;
                    return result;
                }
            }

            if (success) {
                result.result = UnlockResult::Success;
                m_stats.successfulUnlocks++;
            } else {
                result.result = UnlockResult::Failed;
                m_stats.failedUnlocks++;
            }

        } catch (const std::exception& e) {
            Logger::Error("ForceUnlockFile - Exception: {}", e.what());
            result.result = UnlockResult::Failed;
            result.errors.push_back(std::string("Exception: ") + e.what());
        }

        return result;
    }

    bool CloseHandleOp(const LockOwner& owner) {
        try {
            if (owner.handleValue == 0) {
                return false;
            }

            // Open the target process
            HANDLE hProcess = OpenProcess(
                PROCESS_DUP_HANDLE,
                FALSE,
                owner.pid
            );

            if (!hProcess) {
                Logger::Error("Cannot open process {}: error {}",
                    owner.pid, GetLastError());
                return false;
            }

            // Duplicate the handle into our process
            HANDLE hDuplicate = nullptr;
            BOOL result = DuplicateHandle(
                hProcess,
                reinterpret_cast<HANDLE>(owner.handleValue),
                GetCurrentProcess(),
                &hDuplicate,
                0,
                FALSE,
                DUPLICATE_CLOSE_SOURCE
            );

            CloseHandle(hProcess);

            if (result && hDuplicate) {
                CloseHandle(hDuplicate);
                m_stats.handlesClosed++;
                Logger::Info("Closed handle {} in process {}", owner.handleValue, owner.pid);
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("CloseHandleOp - Exception: {}", e.what());
            return false;
        }
    }

    bool TerminateProcessOp(const LockOwner& owner, bool force) {
        try {
            // Safety checks
            if (owner.isCriticalProcess && !force) {
                Logger::Warn("Refusing to terminate critical process: {}",
                    StringUtils::WideToUtf8(owner.processName));
                return false;
            }

            if (owner.isSystemProcess && m_config.protectSystemProcesses && !force) {
                Logger::Warn("Refusing to terminate system process: {}",
                    StringUtils::WideToUtf8(owner.processName));
                return false;
            }

            // Ask for confirmation via callback
            if (m_terminateCallback && !force) {
                if (!m_terminateCallback(owner)) {
                    Logger::Info("Process termination cancelled by callback");
                    return false;
                }
            }

            // Open process
            HANDLE hProcess = OpenProcess(
                PROCESS_TERMINATE,
                FALSE,
                owner.pid
            );

            if (!hProcess) {
                Logger::Error("Cannot open process {} for termination: error {}",
                    owner.pid, GetLastError());
                return false;
            }

            // Terminate
            BOOL result = TerminateProcess(hProcess, 1);
            CloseHandle(hProcess);

            if (result) {
                m_stats.processesTerminated++;
                Logger::Warn("Terminated process {} ({})",
                    owner.pid, StringUtils::WideToUtf8(owner.processName));
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("TerminateProcessOp - Exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // RESTART MANAGER
    // ========================================================================

    bool UseRestartManagerOp(const std::wstring& filePath) {
        try {
            DWORD dwSession;
            WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };

            // Start Restart Manager session
            DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
            if (dwError != ERROR_SUCCESS) {
                Logger::Error("RmStartSession failed: {}", dwError);
                return false;
            }

            // Register file
            LPCWSTR pszFile = filePath.c_str();
            dwError = RmRegisterResources(
                dwSession,
                1,
                &pszFile,
                0,
                nullptr,
                0,
                nullptr
            );

            if (dwError != ERROR_SUCCESS) {
                RmEndSession(dwSession);
                Logger::Error("RmRegisterResources failed: {}", dwError);
                return false;
            }

            // Get list of applications
            UINT nProcInfoNeeded = 0;
            UINT nProcInfo = 0;
            RM_REBOOT_REASON dwRebootReasons = RmRebootReasonNone;

            dwError = RmGetList(
                dwSession,
                &nProcInfoNeeded,
                &nProcInfo,
                nullptr,
                &dwRebootReasons
            );

            bool success = false;

            if (dwError == ERROR_SUCCESS || dwError == ERROR_MORE_DATA) {
                if (nProcInfoNeeded > 0) {
                    std::vector<RM_PROCESS_INFO> processes(nProcInfoNeeded);
                    nProcInfo = nProcInfoNeeded;

                    dwError = RmGetList(
                        dwSession,
                        &nProcInfoNeeded,
                        &nProcInfo,
                        processes.data(),
                        &dwRebootReasons
                    );

                    if (dwError == ERROR_SUCCESS) {
                        // Shutdown applications
                        dwError = RmShutdown(dwSession, RmForceShutdown, nullptr);
                        if (dwError == ERROR_SUCCESS) {
                            success = true;
                            Logger::Info("Restart Manager successfully closed applications");
                        }
                    }
                }
            }

            RmEndSession(dwSession);
            return success;

        } catch (const std::exception& e) {
            Logger::Error("UseRestartManagerOp - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<std::wstring> GetApplicationsUsingFileOp(const std::wstring& filePath) const {
        std::vector<std::wstring> applications;

        try {
            DWORD dwSession;
            WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };

            DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
            if (dwError != ERROR_SUCCESS) {
                return applications;
            }

            LPCWSTR pszFile = filePath.c_str();
            dwError = RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr);

            if (dwError == ERROR_SUCCESS) {
                UINT nProcInfoNeeded = 0;
                UINT nProcInfo = 0;
                RM_REBOOT_REASON dwRebootReasons;

                dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, nullptr, &dwRebootReasons);

                if (dwError == ERROR_MORE_DATA && nProcInfoNeeded > 0) {
                    std::vector<RM_PROCESS_INFO> processes(nProcInfoNeeded);
                    nProcInfo = nProcInfoNeeded;

                    dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo,
                        processes.data(), &dwRebootReasons);

                    if (dwError == ERROR_SUCCESS) {
                        for (UINT i = 0; i < nProcInfo; i++) {
                            applications.push_back(processes[i].strAppName);
                        }
                    }
                }
            }

            RmEndSession(dwSession);

        } catch (const std::exception& e) {
            Logger::Error("GetApplicationsUsingFileOp - Exception: {}", e.what());
        }

        return applications;
    }

    // ========================================================================
    // REBOOT OPERATIONS
    // ========================================================================

    bool ScheduleDeleteOnRebootInternal(const std::wstring& filePath) {
        try {
            // Use MoveFileEx to schedule deletion
            BOOL result = MoveFileExW(
                filePath.c_str(),
                nullptr,
                MOVEFILE_DELAY_UNTIL_REBOOT
            );

            if (result) {
                // Track pending operation
                PendingOperation op;
                op.sourcePath = filePath;
                op.isDelete = true;
                op.scheduledTime = std::chrono::system_clock::now();
                op.reason = "File locked - scheduled for deletion";

                std::unique_lock lock(m_mutex);
                m_pendingOperations.push_back(op);

                Logger::Info("Scheduled delete on reboot: {}",
                    StringUtils::WideToUtf8(filePath));
                return true;
            }

            DWORD error = GetLastError();
            Logger::Error("MoveFileEx failed: error {}", error);
            return false;

        } catch (const std::exception& e) {
            Logger::Error("ScheduleDeleteOnRebootInternal - Exception: {}", e.what());
            return false;
        }
    }

    bool ScheduleMoveOnRebootInternal(const std::wstring& sourcePath, const std::wstring& destPath) {
        try {
            BOOL result = MoveFileExW(
                sourcePath.c_str(),
                destPath.c_str(),
                MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING
            );

            if (result) {
                PendingOperation op;
                op.sourcePath = sourcePath;
                op.destinationPath = destPath;
                op.isMove = true;
                op.scheduledTime = std::chrono::system_clock::now();
                op.reason = "File locked - scheduled for move";

                std::unique_lock lock(m_mutex);
                m_pendingOperations.push_back(op);

                Logger::Info("Scheduled move on reboot: {} -> {}",
                    StringUtils::WideToUtf8(sourcePath),
                    StringUtils::WideToUtf8(destPath));
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("ScheduleMoveOnRebootInternal - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<PendingOperation> GetPendingOperationsOp() const {
        std::shared_lock lock(m_mutex);
        return m_pendingOperations;
    }

    bool CancelPendingOperationOp(const std::wstring& sourcePath) {
        std::unique_lock lock(m_mutex);

        try {
            auto it = std::find_if(m_pendingOperations.begin(), m_pendingOperations.end(),
                [&sourcePath](const PendingOperation& op) {
                    return op.sourcePath == sourcePath;
                });

            if (it != m_pendingOperations.end()) {
                m_pendingOperations.erase(it);
                Logger::Info("Cancelled pending operation: {}",
                    StringUtils::WideToUtf8(sourcePath));
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("CancelPendingOperationOp - Exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // KERNEL INTEGRATION
    // ========================================================================

    bool KernelUnlockFileOp(const std::wstring& filePath) {
        try {
            if (!m_kernelDriverAvailable) {
                Logger::Warn("Kernel driver not available");
                return false;
            }

            // In production, this would communicate with minifilter driver
            // to force-close file handles at kernel level

            // Placeholder implementation
            Logger::Info("Kernel unlock requested for: {}",
                StringUtils::WideToUtf8(filePath));

            return false; // Not implemented in stub

        } catch (const std::exception& e) {
            Logger::Error("KernelUnlockFileOp - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsKernelDriverAvailableOp() const noexcept {
        return m_kernelDriverAvailable;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetTerminateCallbackOp(TerminateCallback callback) {
        std::unique_lock lock(m_mutex);
        m_terminateCallback = std::move(callback);
    }

    void SetProgressCallbackOp(UnlockProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        m_progressCallback = std::move(callback);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void SetAllowProcessTerminationOp(bool allow) noexcept {
        m_config.allowProcessTermination = allow;
    }

    void SetProtectSystemProcessesOp(bool protect) noexcept {
        m_config.protectSystemProcesses = protect;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileLockManagerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    [[nodiscard]] std::wstring NormalizePath(const std::wstring& path) const {
        try {
            fs::path p(path);
            return fs::absolute(p).wstring();
        } catch (...) {
            return path;
        }
    }

    [[nodiscard]] bool EnableDebugPrivilege() const noexcept {
        try {
            HANDLE hToken;
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                return false;
            }

            TOKEN_PRIVILEGES tp;
            LUID luid;

            if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
                CloseHandle(hToken);
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp,
                sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);

            CloseHandle(hToken);
            return result && (GetLastError() == ERROR_SUCCESS);

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] bool CheckKernelDriver() const noexcept {
        try {
            // Check if minifilter driver is loaded
            // In production, would use FilterFindFirst/FilterFindNext
            // For now, return false (not available)
            return false;

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::vector<LockOwner> GetLockingProcessesRM(const std::wstring& filePath) const {
        std::vector<LockOwner> owners;

        try {
            DWORD dwSession;
            WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };

            if (RmStartSession(&dwSession, 0, szSessionKey) != ERROR_SUCCESS) {
                return owners;
            }

            LPCWSTR pszFile = filePath.c_str();
            if (RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr) == ERROR_SUCCESS) {
                UINT nProcInfoNeeded = 0;
                UINT nProcInfo = 0;
                RM_REBOOT_REASON dwRebootReasons;

                if (RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, nullptr, &dwRebootReasons) == ERROR_MORE_DATA) {
                    if (nProcInfoNeeded > 0) {
                        std::vector<RM_PROCESS_INFO> processes(nProcInfoNeeded);
                        nProcInfo = nProcInfoNeeded;

                        if (RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo,
                            processes.data(), &dwRebootReasons) == ERROR_SUCCESS) {

                            for (UINT i = 0; i < nProcInfo; i++) {
                                LockOwner owner;
                                owner.pid = processes[i].Process.dwProcessId;
                                owner.processName = processes[i].strAppName;

                                // Get additional process info
                                EnrichProcessInfo(owner);
                                owners.push_back(owner);
                            }
                        }
                    }
                }
            }

            RmEndSession(dwSession);

        } catch (const std::exception& e) {
            Logger::Error("GetLockingProcessesRM - Exception: {}", e.what());
        }

        return owners;
    }

    [[nodiscard]] std::vector<LockOwner> GetLockingProcessesHandleEnum(const std::wstring& filePath) const {
        std::vector<LockOwner> owners;

        try {
            // This would use NtQuerySystemInformation to enumerate all handles
            // and match them against the target file
            // Simplified placeholder implementation

            Logger::Debug("Handle enumeration not fully implemented (use Restart Manager)");

        } catch (const std::exception& e) {
            Logger::Error("GetLockingProcessesHandleEnum - Exception: {}", e.what());
        }

        return owners;
    }

    void EnrichProcessInfo(LockOwner& owner) const {
        try {
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                owner.pid
            );

            if (!hProcess) {
                return;
            }

            // Get process path
            WCHAR processPath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                owner.processPath = processPath;
            }

            // Check if system/critical process
            std::wstring procName = owner.processName;
            std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);

            owner.isCriticalProcess = CRITICAL_PROCESSES.find(procName) != CRITICAL_PROCESSES.end();
            owner.isSystemProcess = SYSTEM_PROCESSES.find(procName) != SYSTEM_PROCESSES.end();

            // Determine role
            if (owner.pid == SYSTEM_PID) {
                owner.role = ProcessRole::System;
                owner.isSystemProcess = true;
            } else if (owner.isCriticalProcess) {
                owner.role = ProcessRole::System;
            } else if (owner.processName == L"explorer.exe") {
                owner.role = ProcessRole::Explorer;
            }

            CloseHandle(hProcess);

        } catch (const std::exception& e) {
            Logger::Error("EnrichProcessInfo - Exception: {}", e.what());
        }
    }

    bool TryRestartManager(const std::wstring& filePath, UnlockOperation& result) {
        try {
            if (UseRestartManagerOp(filePath)) {
                result.method = UnlockMethod::RestartManager;
                Logger::Info("Unlocked via Restart Manager: {}",
                    StringUtils::WideToUtf8(filePath));
                return true;
            }
        } catch (const std::exception& e) {
            Logger::Error("TryRestartManager - Exception: {}", e.what());
            result.errors.push_back(std::string("Restart Manager failed: ") + e.what());
        }
        return false;
    }

    bool TryHandleClose(const std::vector<LockOwner>& owners, UnlockOperation& result) {
        uint32_t closed = 0;

        try {
            for (const auto& owner : owners) {
                if (CloseHandleOp(owner)) {
                    closed++;
                }
            }

            result.handlesClosed = closed;

            if (closed > 0) {
                result.method = UnlockMethod::HandleClose;
                Logger::Info("Closed {} handles", closed);
                return true;
            }

        } catch (const std::exception& e) {
            Logger::Error("TryHandleClose - Exception: {}", e.what());
            result.errors.push_back(std::string("Handle close failed: ") + e.what());
        }

        return false;
    }

    bool TryProcessTerminate(const std::vector<LockOwner>& owners, UnlockOperation& result) {
        if (!m_config.allowProcessTermination) {
            result.warnings.push_back("Process termination not allowed");
            return false;
        }

        uint32_t terminated = 0;

        try {
            for (const auto& owner : owners) {
                if (TerminateProcessOp(owner, false)) {
                    terminated++;
                }
            }

            result.processesTerminated = terminated;

            if (terminated > 0) {
                result.method = UnlockMethod::ProcessTerminate;
                Logger::Warn("Terminated {} processes", terminated);
                return true;
            }

        } catch (const std::exception& e) {
            Logger::Error("TryProcessTerminate - Exception: {}", e.what());
            result.errors.push_back(std::string("Process termination failed: ") + e.what());
        }

        return false;
    }

    bool TryKernelUnlock(const std::wstring& filePath, UnlockOperation& result) {
        try {
            if (KernelUnlockFileOp(filePath)) {
                result.method = UnlockMethod::KernelDriver;
                Logger::Info("Unlocked via kernel driver: {}",
                    StringUtils::WideToUtf8(filePath));
                return true;
            }
        } catch (const std::exception& e) {
            Logger::Error("TryKernelUnlock - Exception: {}", e.what());
            result.errors.push_back(std::string("Kernel unlock failed: ") + e.what());
        }
        return false;
    }

    void ReportProgress(const std::wstring& status, uint32_t percent) const {
        try {
            if (m_progressCallback) {
                m_progressCallback(status, percent);
            }
        } catch (...) {
            // Suppress callback exceptions
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    FileLockManagerConfig m_config;
    FileLockManagerStatistics m_stats;

    bool m_hasDebugPrivilege{ false };
    bool m_kernelDriverAvailable{ false };

    std::vector<PendingOperation> m_pendingOperations;

    TerminateCallback m_terminateCallback;
    UnlockProgressCallback m_progressCallback;
};

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

FileLockManagerConfig FileLockManagerConfig::CreateDefault() noexcept {
    FileLockManagerConfig config;
    config.allowProcessTermination = false;
    config.allowKernelUnlock = true;
    config.allowRestartManager = true;
    config.unlockTimeoutMs = 5000;
    config.retryCount = 3;
    config.retryDelayMs = 500;
    config.protectSystemProcesses = true;
    config.protectCriticalProcesses = true;
    config.protectServices = true;
    return config;
}

FileLockManagerConfig FileLockManagerConfig::CreateAggressive() noexcept {
    FileLockManagerConfig config;
    config.allowProcessTermination = true;
    config.allowKernelUnlock = true;
    config.allowRestartManager = true;
    config.unlockTimeoutMs = 10000;
    config.retryCount = 5;
    config.retryDelayMs = 1000;
    config.protectSystemProcesses = false;
    config.protectCriticalProcesses = true; // Still protect critical
    config.protectServices = false;
    return config;
}

FileLockManagerConfig FileLockManagerConfig::CreateSafe() noexcept {
    FileLockManagerConfig config;
    config.allowProcessTermination = false;
    config.allowKernelUnlock = false;
    config.allowRestartManager = true;
    config.unlockTimeoutMs = 3000;
    config.retryCount = 2;
    config.retryDelayMs = 250;
    config.protectSystemProcesses = true;
    config.protectCriticalProcesses = true;
    config.protectServices = true;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void FileLockManagerStatistics::Reset() noexcept {
    locksDetected = 0;
    successfulUnlocks = 0;
    failedUnlocks = 0;
    processesTerminated = 0;
    handlesClosed = 0;
    rebootScheduled = 0;
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

FileLockManager& FileLockManager::Instance() {
    static FileLockManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileLockManager::FileLockManager()
    : m_impl(std::make_unique<FileLockManagerImpl>()) {

    Logger::Info("FileLockManager instance created");
}

FileLockManager::~FileLockManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("FileLockManager instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool FileLockManager::Initialize(const FileLockManagerConfig& config) {
    return m_impl->Initialize(config);
}

void FileLockManager::Shutdown() noexcept {
    m_impl->Shutdown();
}

std::vector<LockOwner> FileLockManager::GetLockingProcesses(const std::wstring& filePath) const {
    return m_impl->GetLockingProcesses(filePath);
}

FileLockInfo FileLockManager::GetLockInfo(const std::wstring& filePath) const {
    return m_impl->GetLockInfo(filePath);
}

bool FileLockManager::IsFileLocked(const std::wstring& filePath) const {
    return m_impl->IsFileLocked(filePath);
}

bool FileLockManager::CanDeleteFile(const std::wstring& filePath) const {
    return m_impl->CanDeleteFile(filePath);
}

LockType FileLockManager::GetLockType(const std::wstring& filePath) const {
    return m_impl->GetLockType(filePath);
}

UnlockOperation FileLockManager::UnlockFile(const std::wstring& filePath) {
    return m_impl->UnlockFile(filePath);
}

UnlockOperation FileLockManager::UnlockFile(const std::wstring& filePath, UnlockMethod method) {
    return m_impl->UnlockFile(filePath, method);
}

UnlockOperation FileLockManager::ForceUnlockFile(const std::wstring& filePath) {
    return m_impl->ForceUnlockFile(filePath);
}

bool FileLockManager::CloseHandle(const LockOwner& owner) {
    return m_impl->CloseHandleOp(owner);
}

bool FileLockManager::TerminateProcess(const LockOwner& owner, bool force) {
    return m_impl->TerminateProcessOp(owner, force);
}

bool FileLockManager::UseRestartManager(const std::wstring& filePath) {
    return m_impl->UseRestartManagerOp(filePath);
}

std::vector<std::wstring> FileLockManager::GetApplicationsUsingFile(const std::wstring& filePath) const {
    return m_impl->GetApplicationsUsingFileOp(filePath);
}

bool FileLockManager::ScheduleDeleteOnReboot(const std::wstring& filePath) {
    return m_impl->ScheduleDeleteOnRebootInternal(filePath);
}

bool FileLockManager::ScheduleMoveOnReboot(const std::wstring& sourcePath, const std::wstring& destPath) {
    return m_impl->ScheduleMoveOnRebootInternal(sourcePath, destPath);
}

std::vector<PendingOperation> FileLockManager::GetPendingOperations() const {
    return m_impl->GetPendingOperationsOp();
}

bool FileLockManager::CancelPendingOperation(const std::wstring& sourcePath) {
    return m_impl->CancelPendingOperationOp(sourcePath);
}

bool FileLockManager::KernelUnlockFile(const std::wstring& filePath) {
    return m_impl->KernelUnlockFileOp(filePath);
}

bool FileLockManager::IsKernelDriverAvailable() const noexcept {
    return m_impl->IsKernelDriverAvailableOp();
}

void FileLockManager::SetTerminateCallback(TerminateCallback callback) {
    m_impl->SetTerminateCallbackOp(std::move(callback));
}

void FileLockManager::SetProgressCallback(UnlockProgressCallback callback) {
    m_impl->SetProgressCallbackOp(std::move(callback));
}

void FileLockManager::SetAllowProcessTermination(bool allow) noexcept {
    m_impl->SetAllowProcessTerminationOp(allow);
}

void FileLockManager::SetProtectSystemProcesses(bool protect) noexcept {
    m_impl->SetProtectSystemProcessesOp(protect);
}

const FileLockManagerStatistics& FileLockManager::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void FileLockManager::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
