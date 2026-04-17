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
 * ShadowStrike NGAV - PERFORMANCE OPTIMIZER IMPLEMENTATION
 * ============================================================================
 *
 * @file PerformanceOptimizer.cpp
 * @brief Enterprise-grade system performance optimization engine
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - Integration with Windows performance APIs
 *
 * OPTIMIZATION LAYERS:
 * 1. Process priority management (CPU, I/O, Memory)
 * 2. I/O throttling (disk, network)
 * 3. Memory optimization (working set trimming, cache flushing)
 * 4. CPU affinity control (P-cores, E-cores)
 * 5. Resource monitoring (CPU, memory, disk, GPU)
 *
 * PERFORMANCE TARGETS:
 * - Priority change: <1ms per process
 * - Working set trim: <100ms for all processes
 * - Resource snapshot: <50ms
 * - Profile switching: <200ms
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
#include "PerformanceOptimizer.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/JSONUtils.hpp"
#include "PhantomCore/Utils/Timer.hpp"
#include <psapi.h>
#include <winternl.h>
#include <powrprof.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <filesystem>            // Fix #2: missing include

#if __has_include(<dxgi1_4.h>)
#  include <dxgi1_4.h>
#  define SS_HAS_DXGI 1
#else
#  define SS_HAS_DXGI 0
#endif

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "iphlpapi.lib")

// ============================================================================
// INTERNAL CONSTANTS AND HELPERS
// ============================================================================

namespace {
    using namespace ShadowStrike::GameMode;
    namespace Utils = ShadowStrike::Utils;

    /// @brief Maximum processes to track
    constexpr size_t MAX_TRACKED_PROCESSES = 1024;

    /// @brief Memory trim chunk size
    constexpr size_t TRIM_CHUNK_SIZE = 100;

    /// @brief Resource monitoring interval (ms)
    constexpr uint32_t MONITORING_INTERVAL_MS = 1000;

    /// @brief Performance counter update interval (ms)
    constexpr uint32_t PERF_COUNTER_UPDATE_MS = 500;

    /// @brief Initial EnumProcesses buffer size (number of DWORDs)
    constexpr size_t ENUM_PROCESSES_INITIAL_COUNT = 2048;

    /// @brief Maximum EnumProcesses buffer size (number of DWORDs)
    constexpr size_t ENUM_PROCESSES_MAX_COUNT = 65536;

    // ========================================================================
    // Fix #6: Remove PROCESSINFOCLASS enum. Use plain ULONG constants to avoid
    // ODR violation with Windows SDK's own PROCESSINFOCLASS declaration.
    // ========================================================================
    constexpr ULONG SS_ProcessIoPriority = 33;
    constexpr ULONG SS_ProcessMemoryPriority = 39;

    /// @brief NT API SystemPerformanceInformation class (for disk I/O)
    constexpr ULONG SS_SystemPerformanceInformation = 2;

    typedef struct _SS_MEMORY_PRIORITY_INFORMATION {
        ULONG MemoryPriority;
    } SS_MEMORY_PRIORITY_INFORMATION;

    /// @brief Partial SYSTEM_PERFORMANCE_INFORMATION for disk I/O tracking.
    /// Only the first seven fields are needed; we allocate a larger buffer to
    /// satisfy the kernel's minimum size requirement.
    struct SS_SYSTEM_PERFORMANCE_INFORMATION {
        LARGE_INTEGER IdleProcessTime;
        LARGE_INTEGER IoReadTransferCount;
        LARGE_INTEGER IoWriteTransferCount;
        LARGE_INTEGER IoOtherTransferCount;
        ULONG IoReadOperationCount;
        ULONG IoWriteOperationCount;
        ULONG IoOtherOperationCount;
    };

    // ========================================================================
    // Fix #11: SYSTEM_CPU_SET_INFORMATION for hybrid CPU detection
    // ========================================================================
    struct SS_SYSTEM_CPU_SET_INFORMATION {
        ULONG Size;
        ULONG Type;
        struct {
            ULONG Id;
            USHORT Group;
            UCHAR LogicalProcessorIndex;
            UCHAR CoreIndex;
            UCHAR LastLevelCacheIndex;
            UCHAR NumaNodeIndex;
            UCHAR EfficiencyClass;
            UCHAR AllFlags;
            ULONG Reserved;
            ULONG64 AllocationTag;
        } CpuSet;
    };

    using GetSystemCpuSetInformationFunc = BOOL(WINAPI*)(
        SS_SYSTEM_CPU_SET_INFORMATION* Information,
        ULONG BufferLength,
        PULONG ReturnedLength,
        HANDLE Process,
        ULONG Flags
    );

    // ========================================================================
    // Fix #6: NT function typedefs use ULONG for info class (not enum)
    // ========================================================================
    typedef NTSTATUS(NTAPI* NtSetInformationProcessFunc)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
    );

    typedef NTSTATUS(NTAPI* NtQueryInformationProcessFunc)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    /// @brief Get NT API function pointers
    NtSetInformationProcessFunc GetNtSetInformationProcess() {
        static NtSetInformationProcessFunc func = reinterpret_cast<NtSetInformationProcessFunc>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
        return func;
    }

    NtQueryInformationProcessFunc GetNtQueryInformationProcess() {
        static NtQueryInformationProcessFunc func = reinterpret_cast<NtQueryInformationProcessFunc>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        return func;
    }

    NtQuerySystemInformationFunc GetNtQuerySystemInformation() {
        static NtQuerySystemInformationFunc func = reinterpret_cast<NtQuerySystemInformationFunc>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return func;
    }

    // ========================================================================
    // Fix #15: RAII handle wrapper for Windows HANDLEs
    // ========================================================================
    struct ScopedHandle {
        HANDLE h = nullptr;
        explicit ScopedHandle(HANDLE handle) : h(handle) {}
        ~ScopedHandle() { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&& other) noexcept : h(other.h) { other.h = nullptr; }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
                h = other.h;
                other.h = nullptr;
            }
            return *this;
        }
        explicit operator HANDLE() const noexcept { return h; }
        explicit operator bool() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
        [[nodiscard]] HANDLE get() const noexcept { return h; }
    };

    // ========================================================================
    // Fix #5: I/O priority translation (our enum is reversed vs Windows)
    // Windows IO_PRIORITY_HINT: VeryLow=0, Low=1, Normal=2, High=3, Critical=4
    // Our enum:                 Critical=0, High=1, Normal=2, Low=3, VeryLow=4
    // ========================================================================
    [[nodiscard]] static ULONG ToWindowsIOPriority(IOPriority priority) noexcept {
        switch (priority) {
            case IOPriority::Critical: return 4; // IoPriorityCritical
            case IOPriority::High:     return 3; // IoPriorityHigh
            case IOPriority::Normal:   return 2; // IoPriorityNormal
            case IOPriority::Low:      return 1; // IoPriorityLow
            case IOPriority::VeryLow:  return 0; // IoPriorityVeryLow
            default:                   return 2; // IoPriorityNormal
        }
    }

    // ========================================================================
    // PO-H5: Reverse translation from Windows I/O priority to our enum
    // ========================================================================
    [[nodiscard]] static IOPriority FromWindowsIOPriority(ULONG windowsPriority) noexcept {
        switch (windowsPriority) {
            case 4: return IOPriority::Critical;
            case 3: return IOPriority::High;
            case 2: return IOPriority::Normal;
            case 1: return IOPriority::Low;
            case 0: return IOPriority::VeryLow;
            default: return IOPriority::Normal;
        }
    }

    // ========================================================================
    // PO-H5: Reverse translation from Windows memory priority to our enum
    // ========================================================================
    [[nodiscard]] static MemoryPriority FromWindowsMemoryPriority(ULONG windowsPriority) noexcept {
        switch (windowsPriority) {
            case 5: return MemoryPriority::VeryHigh;
            case 4: return MemoryPriority::High;
            case 3: return MemoryPriority::Medium;
            case 2: return MemoryPriority::Low;
            case 1: return MemoryPriority::VeryLow;
            default: return MemoryPriority::VeryHigh;
        }
    }

    // ========================================================================
    // Fix #14: Explicit memory priority translation
    // Windows MEMORY_PRIORITY: 1 (lowest) to 5 (default/highest)
    // ========================================================================
    [[nodiscard]] static ULONG ToWindowsMemoryPriority(MemoryPriority p) noexcept {
        switch (p) {
            case MemoryPriority::VeryHigh: return 5;
            case MemoryPriority::High:     return 4;
            case MemoryPriority::Medium:   return 3;
            case MemoryPriority::Low:      return 2;
            case MemoryPriority::VeryLow:  return 1;
            case MemoryPriority::Lowest:   return 1; // Clamp to valid Windows range
            default:                       return 5;
        }
    }

    // ========================================================================
    // Fix #7: System-critical process blocklist for EmptyWorkingSet
    // ========================================================================
    [[nodiscard]] static bool IsSystemCriticalProcess(const std::wstring& processName) noexcept {
        static const std::array<const wchar_t*, 17> kBlocklist = {
            L"csrss.exe",
            L"lsass.exe",
            L"smss.exe",
            L"dwm.exe",
            L"services.exe",
            L"svchost.exe",
            L"System",
            L"wininit.exe",
            L"fontdrvhost.exe",
            L"conhost.exe",
            L"WmiPrvSE.exe",
            L"RuntimeBroker.exe",
            L"SearchIndexer.exe",
            L"Registry",
            L"Memory Compression",
            L"SecurityHealthService.exe",
            L"MsMpEng.exe"
        };
        for (const auto* name : kBlocklist) {
            if (_wcsicmp(processName.c_str(), name) == 0) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // Fix #18: Heap-allocated EnumProcesses with retry loop
    // Returns a vector of PIDs. Empty on failure.
    // ========================================================================
    [[nodiscard]] static std::vector<DWORD> EnumAllProcesses() {
        size_t capacity = ENUM_PROCESSES_INITIAL_COUNT;
        std::vector<DWORD> pids;

        while (capacity <= ENUM_PROCESSES_MAX_COUNT) {
            pids.resize(capacity);
            DWORD bytesNeeded = 0;

            if (!::EnumProcesses(pids.data(),
                                 static_cast<DWORD>(capacity * sizeof(DWORD)),
                                 &bytesNeeded)) {
                Utils::Logger::Error("EnumProcesses failed: error {}",
                                     ::GetLastError());
                return {};
            }

            size_t processCount = bytesNeeded / sizeof(DWORD);

            // If the buffer was fully used, there may be more processes
            if (processCount < capacity) {
                pids.resize(processCount);
                return pids;
            }

            // Double capacity and retry
            capacity *= 2;
        }

        Utils::Logger::Error("EnumProcesses: exceeded maximum buffer size");
        return {};
    }

    // ========================================================================
    // Helper: Enable a named privilege on the current process token
    // ========================================================================
    [[nodiscard]] static bool EnablePrivilege(const wchar_t* privilegeName) {
        HANDLE hToken = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                &hToken)) {
            return false;
        }
        ScopedHandle tokenGuard(hToken);

        TOKEN_PRIVILEGES tp{};
        if (!::LookupPrivilegeValueW(nullptr, privilegeName, &tp.Privileges[0].Luid)) {
            return false;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
            return false;
        }

        return ::GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::GameMode {

class PerformanceOptimizerImpl final {
public:
    PerformanceOptimizerImpl() = default;
    ~PerformanceOptimizerImpl() {
        StopMonitoring();
        CloseThrottleJobObject();
        ReleaseDxgiResources();
    }

    // Delete copy/move
    PerformanceOptimizerImpl(const PerformanceOptimizerImpl&) = delete;
    PerformanceOptimizerImpl& operator=(const PerformanceOptimizerImpl&) = delete;
    PerformanceOptimizerImpl(PerformanceOptimizerImpl&&) = delete;
    PerformanceOptimizerImpl& operator=(PerformanceOptimizerImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    // Fix #12: Separate mutex for callbacks to avoid contention with m_mutex
    mutable std::mutex m_callbackMutex;

    std::atomic<OptimizerStatus> m_status{OptimizerStatus::Uninitialized};
    PerformanceOptimizerConfiguration m_config;
    OptimizerStatistics m_stats;

    // Current state
    std::atomic<OptimizationProfile> m_currentProfile{OptimizationProfile::Normal};
    std::atomic<bool> m_isBoosted{false};
    std::atomic<bool> m_throttlingActive{false};
    ThrottleSettings m_throttleSettings;
    ProfileSettings m_customProfile;
    TimePoint m_boostStartTime;

    // Process state tracking
    std::unordered_map<uint32_t, ProcessResourceState> m_processStates;

    // Callbacks (guarded by m_callbackMutex, NOT m_mutex)
    std::vector<OptimizationCallback> m_optimizationCallbacks;
    std::vector<ResourceCallback> m_resourceCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Monitoring
    std::atomic<bool> m_monitoringActive{false};
    std::thread m_monitoringThread;
    uint32_t m_monitoringIntervalMs = MONITORING_INTERVAL_MS;

    // PO-C2: Dedicated mutex for performance counter fields below
    mutable std::mutex m_perfCounterMutex;

    // Performance counters (guarded by m_perfCounterMutex)
    uint64_t m_lastCpuIdleTime = 0;
    uint64_t m_lastCpuKernelTime = 0;
    uint64_t m_lastCpuUserTime = 0;

    // Fix #8: Disk I/O tracking for delta computation
    uint64_t m_lastDiskReadBytes = 0;
    uint64_t m_lastDiskWriteBytes = 0;
    // PO-M1: Previous I/O operation counts for delta-based queue length
    uint32_t m_lastDiskReadOps = 0;
    uint32_t m_lastDiskWriteOps = 0;
    TimePoint m_lastDiskSampleTime = Clock::now();
    bool m_diskBaselineSet = false;

    // Network I/O tracking (guarded by m_perfCounterMutex) — computes
    // Mbps delta across snapshots using IP Helper GetIfTable2.
    uint64_t m_lastNetInBytes = 0;
    uint64_t m_lastNetOutBytes = 0;
    TimePoint m_lastNetSampleTime = Clock::now();
    bool m_netBaselineSet = false;

    // Fix #10: Job object for CPU throttling
    HANDLE m_throttleJobHandle = nullptr;

    // Fix #10: Scan rate limiting state
    mutable std::mutex m_scanRateMutex;
    uint32_t m_scanRateLimit = OptimizerConstants::DEFAULT_SCAN_RATE_LIMIT;
    mutable TimePoint m_lastScanTime = Clock::now();
    // PO-L3: Plain uint32_t since all access is under m_scanRateMutex
    mutable uint32_t m_scansThisSecond = 0;
    mutable TimePoint m_scanWindowStart = Clock::now();

    // PO-H4: Cached DXGI objects to avoid per-tick recreation
#if SS_HAS_DXGI
    IDXGIFactory1* m_cachedDxgiFactory = nullptr;
    IDXGIAdapter3* m_cachedDxgiAdapter3 = nullptr;
    // H5: Thread-safe lazy init and access for DXGI COM pointers
    std::once_flag m_dxgiInitFlag;
    std::mutex m_dxgiMutex;
#endif

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Invoke error callbacks
     * Fix #12: Uses m_callbackMutex. Copies callbacks under lock, invokes outside.
     */
    void NotifyError(const std::string& message, int code = 0) {
        std::vector<ErrorCallback> callbacksCopy;
        {
            std::lock_guard lock(m_callbackMutex);
            callbacksCopy = m_errorCallbacks;
        }
        for (const auto& callback : callbacksCopy) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Error callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown error callback exception");
            }
        }
    }

    /**
     * @brief Invoke optimization callbacks
     * Fix #12: Uses m_callbackMutex. Copies callbacks under lock, invokes outside.
     */
    void NotifyOptimization(const OptimizationResult& result) {
        std::vector<OptimizationCallback> callbacksCopy;
        {
            std::lock_guard lock(m_callbackMutex);
            callbacksCopy = m_optimizationCallbacks;
        }
        for (const auto& callback : callbacksCopy) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Optimization callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown optimization callback exception");
            }
        }
    }

    /**
     * @brief Invoke resource callbacks
     * Fix #12: Uses m_callbackMutex. Copies callbacks under lock, invokes outside.
     */
    void NotifyResourceUpdate(const SystemResourceSnapshot& snapshot) {
        std::vector<ResourceCallback> callbacksCopy;
        {
            std::lock_guard lock(m_callbackMutex);
            callbacksCopy = m_resourceCallbacks;
        }
        for (const auto& callback : callbacksCopy) {
            try {
                callback(snapshot);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Resource callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown resource callback exception");
            }
        }
    }

    /**
     * @brief Get current CPU usage
     */
    [[nodiscard]] double GetCPUUsage() {
        // PO-C2: Guard perf counter fields against concurrent access
        std::lock_guard perfLock(m_perfCounterMutex);

        FILETIME idleTime, kernelTime, userTime;
        if (!::GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            return 0.0;
        }

        auto FileTimeToUInt64 = [](const FILETIME& ft) -> uint64_t {
            return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        };

        uint64_t idle = FileTimeToUInt64(idleTime);
        uint64_t kernel = FileTimeToUInt64(kernelTime);
        uint64_t user = FileTimeToUInt64(userTime);

        uint64_t idleDelta = idle - m_lastCpuIdleTime;
        uint64_t kernelDelta = kernel - m_lastCpuKernelTime;
        uint64_t userDelta = user - m_lastCpuUserTime;

        m_lastCpuIdleTime = idle;
        m_lastCpuKernelTime = kernel;
        m_lastCpuUserTime = user;

        if (idleDelta == 0 && kernelDelta == 0 && userDelta == 0) {
            return 0.0;
        }

        uint64_t totalDelta = kernelDelta + userDelta;
        if (totalDelta == 0) {
            return 0.0;
        }

        double usage = 100.0 - (100.0 * idleDelta / totalDelta);
        return std::max(0.0, std::min(100.0, usage));
    }

    /**
     * @brief Get memory information
     */
    [[nodiscard]] bool GetMemoryInfo(uint64_t& totalMB, uint64_t& availableMB, double& usagePercent) {
        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(MEMORYSTATUSEX);

        if (!::GlobalMemoryStatusEx(&memStatus)) {
            return false;
        }

        totalMB = memStatus.ullTotalPhys / (1024 * 1024);
        availableMB = memStatus.ullAvailPhys / (1024 * 1024);
        usagePercent = static_cast<double>(memStatus.dwMemoryLoad);

        return true;
    }

    /**
     * @brief Get power status
     */
    [[nodiscard]] bool GetPowerStatus(bool& onBattery, uint8_t& batteryPercent) {
        SYSTEM_POWER_STATUS powerStatus{};
        if (!::GetSystemPowerStatus(&powerStatus)) {
            return false;
        }

        onBattery = (powerStatus.ACLineStatus == 0);
        batteryPercent = powerStatus.BatteryLifePercent == 255 ? 100 : powerStatus.BatteryLifePercent;

        return true;
    }

    /**
     * @brief Open process with required privileges
     * Fix #15: Callers should wrap in ScopedHandle.
     */
    [[nodiscard]] HANDLE OpenProcessWithPrivileges(uint32_t pid) {
        DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
                      PROCESS_VM_READ | PROCESS_SET_QUOTA;
        return ::OpenProcess(access, FALSE, pid);
    }

    /**
     * @brief Save process state before modification
     * Fix #4: Assumes caller already holds m_mutex. No internal locking.
     */
    void SaveProcessState(uint32_t pid, HANDLE hProcess) {
        ProcessResourceState state;
        state.processId = pid;

        // Get process name
        wchar_t processPath[MAX_PATH] = {};
        DWORD pathSize = MAX_PATH;
        if (::QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
            state.processName = std::filesystem::path(processPath).filename().wstring();
        }

        // Get priority class
        DWORD priorityClass = ::GetPriorityClass(hProcess);
        state.originalPriority = WindowsToPriorityClass(priorityClass);
        state.currentPriority = state.originalPriority;

        // Get affinity
        DWORD_PTR processAffinity = 0, systemAffinity = 0;
        if (::GetProcessAffinityMask(hProcess, &processAffinity, &systemAffinity)) {
            state.originalAffinityMask = processAffinity;
            state.currentAffinityMask = processAffinity;
        }

        // PO-H5: Query original I/O priority via NtQueryInformationProcess
        if (auto ntQueryInfo = GetNtQueryInformationProcess()) {
            ULONG ioPriority = 2; // Default: IoPriorityNormal
            ULONG returnLength = 0;
            NTSTATUS status = ntQueryInfo(hProcess, SS_ProcessIoPriority,
                                          &ioPriority, sizeof(ioPriority), &returnLength);
            if (status == 0) {
                state.originalIOPriority = FromWindowsIOPriority(ioPriority);
                state.currentIOPriority = state.originalIOPriority;
            }
        }

        // PO-H5: Query original memory priority via NtQueryInformationProcess
        if (auto ntQueryInfo = GetNtQueryInformationProcess()) {
            SS_MEMORY_PRIORITY_INFORMATION memPriInfo{};
            memPriInfo.MemoryPriority = 5; // Default: MEMORY_PRIORITY_NORMAL
            ULONG returnLength = 0;
            NTSTATUS status = ntQueryInfo(hProcess, SS_ProcessMemoryPriority,
                                          &memPriInfo, sizeof(memPriInfo), &returnLength);
            if (status == 0) {
                state.originalMemoryPriority = FromWindowsMemoryPriority(memPriInfo.MemoryPriority);
                state.currentMemoryPriority = state.originalMemoryPriority;
            }
        }

        // Save to map (no lock here; caller holds m_mutex)
        m_processStates[pid] = state;
    }

    /**
     * @brief Convert Windows priority class to our enum
     */
    [[nodiscard]] ProcessPriorityClass WindowsToPriorityClass(DWORD windowsPriority) const noexcept {
        switch (windowsPriority) {
            case REALTIME_PRIORITY_CLASS: return ProcessPriorityClass::Realtime;
            case HIGH_PRIORITY_CLASS: return ProcessPriorityClass::High;
            case ABOVE_NORMAL_PRIORITY_CLASS: return ProcessPriorityClass::AboveNormal;
            case NORMAL_PRIORITY_CLASS: return ProcessPriorityClass::Normal;
            case BELOW_NORMAL_PRIORITY_CLASS: return ProcessPriorityClass::BelowNormal;
            case IDLE_PRIORITY_CLASS: return ProcessPriorityClass::Idle;
            default: return ProcessPriorityClass::Normal;
        }
    }

    /**
     * @brief Is process excluded from optimization
     */
    [[nodiscard]] bool IsProcessExcluded(const std::wstring& processName) const {
        for (const auto& excluded : m_config.excludedProcesses) {
            if (_wcsicmp(processName.c_str(), excluded.c_str()) == 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Resource monitoring thread
     */
    void MonitoringThreadFunc() {
        Utils::Logger::Info("Resource monitoring thread started");

        // PO-L4: Use sleep_until to prevent drift accumulation
        auto nextTick = Clock::now() + std::chrono::milliseconds(m_monitoringIntervalMs);

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // Get resource snapshot
                auto snapshot = CaptureResourceSnapshot();

                // Notify callbacks
                NotifyResourceUpdate(snapshot);

            } catch (const std::exception& e) {
                Utils::Logger::Error("Monitoring thread error: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown monitoring thread error");
            }

            // PO-L4: Sleep until next tick, then advance; reset if we fell behind
            std::this_thread::sleep_until(nextTick);
            auto now = Clock::now();
            nextTick += std::chrono::milliseconds(m_monitoringIntervalMs);
            if (nextTick < now) {
                nextTick = now + std::chrono::milliseconds(m_monitoringIntervalMs);
            }
        }

        Utils::Logger::Info("Resource monitoring thread stopped");
    }

    /**
     * @brief Capture disk I/O rates via NtQuerySystemInformation
     * Fix #8: Real disk I/O monitoring using SystemPerformanceInformation
     */
    void CaptureDiskIO(double& readMBps, double& writeMBps, double& queueLength) {
        readMBps = 0.0;
        writeMBps = 0.0;
        queueLength = 0.0;

        auto ntQuerySysInfo = GetNtQuerySystemInformation();
        if (!ntQuerySysInfo) {
            return;
        }

        // Allocate a buffer large enough for the full struct (~512 bytes is
        // more than sufficient for SYSTEM_PERFORMANCE_INFORMATION)
        alignas(16) uint8_t buffer[512] = {};
        ULONG returnLength = 0;

        NTSTATUS status = ntQuerySysInfo(SS_SystemPerformanceInformation,
                                         buffer, sizeof(buffer), &returnLength);
        if (status != 0) {
            Utils::Logger::Warn("NtQuerySystemInformation(SystemPerformanceInformation) "
                                "failed: NTSTATUS 0x{:08X}", static_cast<uint32_t>(status));
            return;
        }

        // Cast to our partial struct to read I/O counters
        const auto* perfInfo = reinterpret_cast<const SS_SYSTEM_PERFORMANCE_INFORMATION*>(buffer);

        uint64_t currentReadBytes = static_cast<uint64_t>(perfInfo->IoReadTransferCount.QuadPart);
        uint64_t currentWriteBytes = static_cast<uint64_t>(perfInfo->IoWriteTransferCount.QuadPart);
        uint32_t currentReadOps = perfInfo->IoReadOperationCount;
        uint32_t currentWriteOps = perfInfo->IoWriteOperationCount;
        auto now = Clock::now();

        // PO-C2: Guard perf counter fields against concurrent access
        std::lock_guard perfLock(m_perfCounterMutex);

        if (m_diskBaselineSet) {
            double elapsedSec = std::chrono::duration<double>(now - m_lastDiskSampleTime).count();
            if (elapsedSec > 0.01) { // Avoid division by near-zero
                uint64_t readDelta = (currentReadBytes >= m_lastDiskReadBytes)
                    ? (currentReadBytes - m_lastDiskReadBytes) : 0;
                uint64_t writeDelta = (currentWriteBytes >= m_lastDiskWriteBytes)
                    ? (currentWriteBytes - m_lastDiskWriteBytes) : 0;

                readMBps = static_cast<double>(readDelta) / (1024.0 * 1024.0 * elapsedSec);
                writeMBps = static_cast<double>(writeDelta) / (1024.0 * 1024.0 * elapsedSec);

                // PO-M1: Compute proper delta for I/O operation counts
                uint32_t opsReadDelta = (currentReadOps >= m_lastDiskReadOps)
                    ? (currentReadOps - m_lastDiskReadOps) : 0;
                uint32_t opsWriteDelta = (currentWriteOps >= m_lastDiskWriteOps)
                    ? (currentWriteOps - m_lastDiskWriteOps) : 0;
                queueLength = static_cast<double>(opsReadDelta + opsWriteDelta) / (elapsedSec * 1000.0);
                queueLength = std::min(queueLength, 100.0); // Cap at reasonable value
            }
        }

        m_lastDiskReadBytes = currentReadBytes;
        m_lastDiskWriteBytes = currentWriteBytes;
        m_lastDiskReadOps = currentReadOps;
        m_lastDiskWriteOps = currentWriteOps;
        m_lastDiskSampleTime = now;
        m_diskBaselineSet = true;
    }

    /**
     * @brief Capture network throughput in Mbps using IP Helper GetIfTable2.
     *
     * Design:
     *   - Enumerates all NDIS-managed interfaces and sums InOctets / OutOctets
     *     across those that are operational (IfOperStatusUp) and not
     *     loopback / tunnel pseudo-adapters (those would double-count local
     *     traffic and inflate the measurement).
     *   - Computes a delta over the last sample. First call establishes a
     *     baseline and returns 0.0 (avoids spurious spike on startup).
     *   - Protected against counter wrap / interface table restructuring by
     *     treating any negative delta as 0.
     *   - Called from the monitoring thread only; state is guarded by
     *     m_perfCounterMutex to allow safe concurrent GetResourceSnapshot().
     *
     * @return Combined RX+TX throughput in megabits per second.
     */
    [[nodiscard]] double CaptureNetworkMbps() {
        PMIB_IF_TABLE2 table = nullptr;
        NETIO_STATUS status = ::GetIfTable2(&table);
        if (status != NO_ERROR || table == nullptr) {
            if (table != nullptr) {
                ::FreeMibTable(table);
            }
            Utils::Logger::Warn("GetIfTable2 failed: status {}", static_cast<uint32_t>(status));
            return 0.0;
        }

        uint64_t currentIn = 0;
        uint64_t currentOut = 0;

        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IF_ROW2& row = table->Table[i];

            if (row.OperStatus != IfOperStatusUp) {
                continue;
            }
            // Filter out interfaces that would skew real network throughput:
            //  - Software loopback (IF_TYPE_SOFTWARE_LOOPBACK = 24)
            //  - Tunnel pseudo-interfaces (IF_TYPE_TUNNEL = 131) — they
            //    reflect traffic already accounted for on a physical adapter.
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
                row.Type == IF_TYPE_TUNNEL) {
                continue;
            }
            if (row.InterfaceAndOperStatusFlags.FilterInterface) {
                continue;
            }

            currentIn += row.InOctets;
            currentOut += row.OutOctets;
        }

        ::FreeMibTable(table);

        const auto now = Clock::now();
        double mbps = 0.0;

        // PO-C2: Guard network counter fields against concurrent access
        std::lock_guard perfLock(m_perfCounterMutex);

        if (m_netBaselineSet) {
            const double elapsedSec =
                std::chrono::duration<double>(now - m_lastNetSampleTime).count();
            if (elapsedSec > 0.01) {
                const uint64_t inDelta = (currentIn >= m_lastNetInBytes)
                    ? (currentIn - m_lastNetInBytes) : 0;
                const uint64_t outDelta = (currentOut >= m_lastNetOutBytes)
                    ? (currentOut - m_lastNetOutBytes) : 0;
                const uint64_t totalDeltaBytes = inDelta + outDelta;

                // Bytes -> bits -> megabits = * 8 / 1'000'000
                mbps = (static_cast<double>(totalDeltaBytes) * 8.0) /
                       (1'000'000.0 * elapsedSec);
                // Cap at a sane ceiling to suppress measurement artifacts on
                // counter rollover or interface reconfiguration.
                mbps = std::max(0.0, std::min(mbps, 1'000'000.0));
            }
        }

        m_lastNetInBytes = currentIn;
        m_lastNetOutBytes = currentOut;
        m_lastNetSampleTime = now;
        m_netBaselineSet = true;

        return mbps;
    }

    /**
     * @brief Capture GPU memory usage via DXGI
     * Fix #8: Attempt to load dxgi.dll and query adapter memory.
     * Returns GPU memory usage as a percentage. Returns 0.0 if unavailable.
     */
    [[nodiscard]] double CaptureGPUUsage() {
#if SS_HAS_DXGI
        // Dynamically load dxgi.dll to avoid hard dependency
        static HMODULE hDxgi = ::GetModuleHandleW(L"dxgi.dll");
        if (!hDxgi) {
            static bool sWarned = false;
            if (!sWarned) {
                Utils::Logger::Warn("dxgi.dll not available - GPU memory monitoring disabled");
                sWarned = true;
            }
            return 0.0;
        }

        using CreateDXGIFactory1Func = HRESULT(WINAPI*)(REFIID riid, void** ppFactory);
        static auto pCreateDXGIFactory1 = reinterpret_cast<CreateDXGIFactory1Func>(
            ::GetProcAddress(hDxgi, "CreateDXGIFactory1"));
        if (!pCreateDXGIFactory1) {
            return 0.0;
        }

        // H5: Thread-safe lazy initialization of DXGI COM pointers
        std::call_once(m_dxgiInitFlag, [&] {
            HRESULT hr = pCreateDXGIFactory1(__uuidof(IDXGIFactory1),
                                             reinterpret_cast<void**>(&m_cachedDxgiFactory));
            if (FAILED(hr) || !m_cachedDxgiFactory) {
                m_cachedDxgiFactory = nullptr;
                return;
            }

            IDXGIAdapter1* adapter = nullptr;
            if (SUCCEEDED(m_cachedDxgiFactory->EnumAdapters1(0, &adapter)) && adapter) {
                HRESULT qihr = adapter->QueryInterface(__uuidof(IDXGIAdapter3),
                                                       reinterpret_cast<void**>(&m_cachedDxgiAdapter3));
                adapter->Release();
                if (FAILED(qihr)) {
                    m_cachedDxgiAdapter3 = nullptr;
                }
            }
        });

        // H5: Guard usage and potential release with mutex
        std::lock_guard dxgiLock(m_dxgiMutex);

        if (!m_cachedDxgiAdapter3) {
            return 0.0;
        }

        DXGI_QUERY_VIDEO_MEMORY_INFO memInfo{};
        HRESULT hr = m_cachedDxgiAdapter3->QueryVideoMemoryInfo(
            0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &memInfo);

        if (FAILED(hr)) {
            // Adapter may have been removed or reset; release and retry next tick
            ReleaseDxgiResources();
            return 0.0;
        }

        double gpuUsage = 0.0;
        if (memInfo.Budget > 0) {
            gpuUsage = 100.0 * static_cast<double>(memInfo.CurrentUsage) /
                       static_cast<double>(memInfo.Budget);
            gpuUsage = std::min(100.0, std::max(0.0, gpuUsage));
        }

        return gpuUsage;
#else
        static bool sWarned = false;
        if (!sWarned) {
            Utils::Logger::Warn("DXGI headers not available at build time - "
                                "GPU memory monitoring disabled");
            sWarned = true;
        }
        return 0.0;
#endif
    }

    /**
     * @brief Capture current resource snapshot
     * Fix #8: Implements real disk I/O and GPU monitoring.
     */
    [[nodiscard]] SystemResourceSnapshot CaptureResourceSnapshot() {
        SystemResourceSnapshot snapshot;
        snapshot.timestamp = std::chrono::system_clock::now();

        // CPU usage
        snapshot.cpuUsage = GetCPUUsage();

        // Memory
        uint64_t totalMB = 0;
        if (GetMemoryInfo(totalMB, snapshot.availableMemoryMB, snapshot.memoryUsage)) {
            // Success
        }

        // Power status
        (void)GetPowerStatus(snapshot.onBattery, snapshot.batteryPercent);

        // Disk I/O via NtQuerySystemInformation
        CaptureDiskIO(snapshot.diskReadMBps, snapshot.diskWriteMBps, snapshot.diskQueueLength);

        // Network I/O via IP Helper GetIfTable2 (delta Mbps over sample interval)
        snapshot.networkMbps = CaptureNetworkMbps();

        // GPU via DXGI
        snapshot.gpuUsage = CaptureGPUUsage();

        return snapshot;
    }

    /**
     * @brief Stop monitoring thread
     */
    void StopMonitoring() {
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);
            if (m_monitoringThread.joinable()) {
                m_monitoringThread.join();
            }
        }
    }

    // ========================================================================
    // Fix #3 / #10: Internal throttling methods (no locking)
    // The public EnableThrottling/DisableThrottling lock and delegate here.
    // ApplyCustomSettings and RestoreSystem call these directly while
    // already holding m_mutex, avoiding recursive lock deadlocks.
    // ========================================================================

    /**
     * @brief PO-H4: Release cached DXGI objects
     */
    void ReleaseDxgiResources() {
#if SS_HAS_DXGI
        // H5: Must be called under m_dxgiMutex (or during destruction)
        if (m_cachedDxgiAdapter3) {
            m_cachedDxgiAdapter3->Release();
            m_cachedDxgiAdapter3 = nullptr;
        }
        if (m_cachedDxgiFactory) {
            m_cachedDxgiFactory->Release();
            m_cachedDxgiFactory = nullptr;
        }
#endif
    }

    /**
     * @brief Enable throttling (no lock). Caller must hold m_mutex.
     * Fix #10: Creates a Job Object for CPU rate control and stores the
     * scan rate limit for ShouldThrottleScan().
     */
    void EnableThrottlingInternal(const ThrottleSettings& settings) {
        m_throttleSettings = settings;
        m_throttlingActive.store(true, std::memory_order_release);
        m_stats.throttleActivations++;

        // Store scan rate limit for ShouldThrottleScan()
        {
            std::lock_guard scanLock(m_scanRateMutex);
            m_scanRateLimit = settings.scanRateLimit;
            m_scansThisSecond = 0;
            m_scanWindowStart = Clock::now();
        }

        // Create or update Job Object for CPU rate control
        if (settings.cpuUsageLimit > 0 && settings.cpuUsageLimit < 100) {
            CloseThrottleJobObject(); // Close any existing job

            m_throttleJobHandle = ::CreateJobObjectW(nullptr, nullptr);
            if (!m_throttleJobHandle) {
                Utils::Logger::Error("CreateJobObjectW failed: error {}",
                                     ::GetLastError());
            } else {
                JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRate{};
                cpuRate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                                      JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
                // CpuRate is in hundredths of a percent (100 = 1%)
                cpuRate.CpuRate = static_cast<DWORD>(settings.cpuUsageLimit) * 100;

                if (!::SetInformationJobObject(m_throttleJobHandle,
                                               JobObjectCpuRateControlInformation,
                                               &cpuRate, sizeof(cpuRate))) {
                    Utils::Logger::Error("SetInformationJobObject(CpuRateControl) "
                                         "failed: error {}", ::GetLastError());
                    CloseThrottleJobObject();
                } else {
                    // Assign tracked ShadowStrike processes to the job
                    for (const auto& [pid, state] : m_processStates) {
                        ScopedHandle hProcess(::OpenProcess(
                            PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                            FALSE, pid));
                        if (hProcess) {
                            if (!::AssignProcessToJobObject(m_throttleJobHandle, hProcess.get())) {
                                Utils::Logger::Warn("Failed to assign PID {} to throttle "
                                                     "job: error {}", pid, ::GetLastError());
                            }
                        }
                    }
                    Utils::Logger::Info("CPU throttle job created: {}% hard cap",
                                        settings.cpuUsageLimit);
                }
            }
        }

        Utils::Logger::Info("Throttling enabled: {} MB/s disk, {}% CPU, {} scans/sec",
                           settings.diskThroughputMBps, settings.cpuUsageLimit,
                           settings.scanRateLimit);
    }

    /**
     * @brief Disable throttling (no lock). Caller must hold m_mutex.
     * Fix #10: Closes the Job Object and resets scan rate state.
     */
    void DisableThrottlingInternal() {
        m_throttlingActive.store(false, std::memory_order_release);
        CloseThrottleJobObject();

        {
            std::lock_guard scanLock(m_scanRateMutex);
            m_scanRateLimit = OptimizerConstants::DEFAULT_SCAN_RATE_LIMIT;
            m_scansThisSecond = 0;
        }

        Utils::Logger::Info("Throttling disabled");
    }

    /**
     * @brief Close the throttle Job Object if open
     */
    void CloseThrottleJobObject() {
        if (m_throttleJobHandle) {
            ::CloseHandle(m_throttleJobHandle);
            m_throttleJobHandle = nullptr;
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> PerformanceOptimizer::s_instanceCreated{false};

[[nodiscard]] PerformanceOptimizer& PerformanceOptimizer::Instance() noexcept {
    static PerformanceOptimizer instance;
    return instance;
}

[[nodiscard]] bool PerformanceOptimizer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

PerformanceOptimizer::PerformanceOptimizer()
    : m_impl(std::make_unique<PerformanceOptimizerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    Utils::Logger::Info("PerformanceOptimizer singleton created");
}

PerformanceOptimizer::~PerformanceOptimizer() {
    try {
        Shutdown();
        Utils::Logger::Info("PerformanceOptimizer singleton destroyed");
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool PerformanceOptimizer::Initialize(
    const PerformanceOptimizerConfiguration& config)
{
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != OptimizerStatus::Uninitialized &&
            m_impl->m_status != OptimizerStatus::Stopped) {
            Utils::Logger::Warn("PerformanceOptimizer already initialized");
            return false;
        }

        m_impl->m_status = OptimizerStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid PerformanceOptimizer configuration");
            m_impl->m_status = OptimizerStatus::Error;
            return false;
        }

        m_impl->m_config = config;

        // PO-M3: Enable SeDebugPrivilege for cross-process operations
        if (!EnablePrivilege(SE_DEBUG_NAME)) {
            Utils::Logger::Warn("Failed to enable SE_DEBUG_NAME privilege; "
                                "some cross-process operations may fail");
        }

        // Reset statistics
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        // Initialize default profile
        m_impl->m_currentProfile.store(config.defaultProfile, std::memory_order_release);

        m_impl->m_status = OptimizerStatus::Normal;

        Utils::Logger::Info("PerformanceOptimizer initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("PerformanceOptimizer initialization failed: {}", e.what());
        m_impl->m_status = OptimizerStatus::Error;
        m_impl->NotifyError("Initialization failed: " + std::string(e.what()), -1);
        return false;
    }
}

/**
 * Fix #19: Shutdown lock juggling.
 * 1. Signal m_monitoringActive = false BEFORE acquiring m_mutex.
 * 2. Join the monitoring thread outside the lock.
 * 3. Then acquire m_mutex for the remaining cleanup.
 */
void PerformanceOptimizer::Shutdown() {
    try {
        // Step 1: Signal monitoring thread to stop (no lock needed; atomic)
        m_impl->m_monitoringActive.store(false, std::memory_order_release);

        // Step 2: Join monitoring thread outside of m_mutex to avoid
        // deadlock with the monitoring thread's own lock acquisitions
        if (m_impl->m_monitoringThread.joinable()) {
            m_impl->m_monitoringThread.join();
        }

        // Step 3: Now acquire the main lock for state cleanup
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == OptimizerStatus::Uninitialized ||
            m_impl->m_status == OptimizerStatus::Stopped) {
            return;
        }

        m_impl->m_status = OptimizerStatus::Stopping;

        // Restore all modified processes
        for (auto& [pid, state] : m_impl->m_processStates) {
            if (state.isModified) {
                ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
                if (hProcess) {
                    ::SetPriorityClass(hProcess.get(), GetWindowsPriorityClass(state.originalPriority));
                    ::SetProcessAffinityMask(hProcess.get(), state.originalAffinityMask);

                    // PO-C1: Restore I/O priority
                    if (auto ntSetInfo = GetNtSetInformationProcess()) {
                        ULONG ioPriority = ToWindowsIOPriority(state.originalIOPriority);
                        ntSetInfo(hProcess.get(), SS_ProcessIoPriority,
                                  &ioPriority, sizeof(ioPriority));
                    }

                    // PO-C1: Restore memory priority
                    if (auto ntSetInfo = GetNtSetInformationProcess()) {
                        SS_MEMORY_PRIORITY_INFORMATION memPriority{};
                        memPriority.MemoryPriority = ToWindowsMemoryPriority(state.originalMemoryPriority);
                        ntSetInfo(hProcess.get(), SS_ProcessMemoryPriority,
                                  &memPriority, sizeof(memPriority));
                    }
                }
            }
        }

        m_impl->m_processStates.clear();

        // Disable throttling (internal, no extra lock)
        m_impl->DisableThrottlingInternal();

        m_impl->m_isBoosted.store(false, std::memory_order_release);
        m_impl->m_status = OptimizerStatus::Stopped;

        lock.unlock();

        // Clear callbacks under callback mutex
        {
            std::lock_guard cbLock(m_impl->m_callbackMutex);
            m_impl->m_optimizationCallbacks.clear();
            m_impl->m_resourceCallbacks.clear();
            m_impl->m_errorCallbacks.clear();
        }

        Utils::Logger::Info("PerformanceOptimizer shut down");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool PerformanceOptimizer::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == OptimizerStatus::Normal ||
           status == OptimizerStatus::Optimized ||
           status == OptimizerStatus::Boosted;
}

[[nodiscard]] OptimizerStatus PerformanceOptimizer::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

[[nodiscard]] bool PerformanceOptimizer::UpdateConfiguration(
    const PerformanceOptimizerConfiguration& config)
{
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_impl->m_config = config;

        Utils::Logger::Info("PerformanceOptimizer configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Configuration update failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] PerformanceOptimizerConfiguration
PerformanceOptimizer::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// OPTIMIZATION CONTROL
// ============================================================================

[[nodiscard]] OptimizationResult PerformanceOptimizer::BoostSystem() {
    return ApplyProfile(OptimizationProfile::Performance);
}

[[nodiscard]] OptimizationResult PerformanceOptimizer::ApplyProfile(
    OptimizationProfile profile)
{
    OptimizationResult result;
    result.profile = profile;
    result.appliedTime = std::chrono::system_clock::now();

    try {
        if (!IsInitialized()) {
            result.errorMessage = "Optimizer not initialized";
            return result;
        }

        // Get profile settings
        ProfileSettings settings = GetProfileSettings(profile);

        // PO-C3: Store profile before applying so GetCurrentProfile() is up-to-date
        m_impl->m_currentProfile.store(profile, std::memory_order_release);

        // Apply custom settings
        return ApplyCustomSettings(settings);

    } catch (const std::exception& e) {
        Utils::Logger::Error("ApplyProfile failed: {}", e.what());
        result.errorMessage = e.what();
        m_impl->NotifyError("Profile application failed: " + std::string(e.what()), -1);
        return result;
    }
}

[[nodiscard]] OptimizationResult PerformanceOptimizer::ApplyCustomSettings(
    const ProfileSettings& settings)
{
    OptimizationResult result;
    result.appliedTime = std::chrono::system_clock::now();

    try {
        std::unique_lock lock(m_impl->m_mutex);

        Utils::Logger::Info("Applying optimization profile: {}", settings.name);

        uint32_t processesModified = 0;
        uint64_t memoryFreed = 0;

        // Fix #18: Use heap-allocated EnumProcesses with retry loop
        auto pids = EnumAllProcesses();
        if (pids.empty()) {
            result.errorMessage = "Failed to enumerate processes";
            return result;
        }

        // Apply to ShadowStrike processes
        for (DWORD pid : pids) {
            if (pid == 0) continue;

            // Fix #15: RAII handle
            ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
            if (!hProcess) continue;

            // Get process name
            wchar_t processPath[MAX_PATH] = {};
            DWORD pathSize = MAX_PATH;
            if (!::QueryFullProcessImageNameW(hProcess.get(), 0, processPath, &pathSize)) {
                continue;
            }

            std::wstring processName = std::filesystem::path(processPath).filename().wstring();

            // Check if this is ShadowStrike process or excluded
            bool isShadowStrike = (processName.find(L"ShadowStrike") != std::wstring::npos);
            bool isExcluded = m_impl->IsProcessExcluded(processName);

            if (!isShadowStrike || isExcluded) {
                continue;
            }

            // Save original state if not already saved
            // Fix #4: SaveProcessState no longer locks internally
            if (m_impl->m_processStates.find(pid) == m_impl->m_processStates.end()) {
                m_impl->SaveProcessState(pid, hProcess.get());
            }

            // Apply priority
            DWORD winPriority = GetWindowsPriorityClass(settings.processPriority);
            if (::SetPriorityClass(hProcess.get(), winPriority)) {
                auto& state = m_impl->m_processStates[pid];
                state.currentPriority = settings.processPriority;
                state.isModified = true;
                processesModified++;
                m_impl->m_stats.priorityChanges++;
            }

            // Fix #5 + #16: Apply I/O priority with proper translation and error check
            if (auto ntSetInfo = GetNtSetInformationProcess()) {
                ULONG ioPriority = ToWindowsIOPriority(settings.ioPriority);
                NTSTATUS ntStatus = ntSetInfo(hProcess.get(), SS_ProcessIoPriority,
                                              &ioPriority, sizeof(ioPriority));
                if (ntStatus != 0) {
                    Utils::Logger::Warn("NtSetInformationProcess(IoPriority) failed for "
                                        "PID {}: NTSTATUS 0x{:08X}", pid,
                                        static_cast<uint32_t>(ntStatus));
                }
            }

            // Fix #14 + #16: Apply memory priority with explicit lookup and error check
            if (auto ntSetInfo = GetNtSetInformationProcess()) {
                SS_MEMORY_PRIORITY_INFORMATION memPriority{};
                memPriority.MemoryPriority = ToWindowsMemoryPriority(settings.memoryPriority);
                NTSTATUS ntStatus = ntSetInfo(hProcess.get(), SS_ProcessMemoryPriority,
                                              &memPriority, sizeof(memPriority));
                if (ntStatus != 0) {
                    Utils::Logger::Warn("NtSetInformationProcess(MemoryPriority) failed for "
                                        "PID {}: NTSTATUS 0x{:08X}", pid,
                                        static_cast<uint32_t>(ntStatus));
                }
            }

            // Apply CPU affinity if efficiency cores requested
            if (settings.useEfficiencyCoresOnly) {
                uint64_t efficiencyMask = GetEfficiencyCoresMask();
                if (efficiencyMask != 0) {
                    ::SetProcessAffinityMask(hProcess.get(), efficiencyMask);
                    auto& state = m_impl->m_processStates[pid];
                    state.currentAffinityMask = efficiencyMask;
                }
            }

            // ScopedHandle releases hProcess automatically
        }

        // Trim working set if requested (does not lock m_mutex)
        if (settings.trimWorkingSet) {
            lock.unlock();
            memoryFreed = TrimWorkingSet();
            lock.lock();
        }

        // Fix #3: Call EnableThrottlingInternal (no lock) instead of
        // EnableThrottling (which would deadlock by re-locking m_mutex)
        if (settings.throttle.diskThroughputMBps > 0 ||
            settings.throttle.cpuUsageLimit < 100) {
            m_impl->EnableThrottlingInternal(settings.throttle);
        }

        // Update state
        m_impl->m_isBoosted.store(true, std::memory_order_release);
        m_impl->m_boostStartTime = Clock::now();
        m_impl->m_status = OptimizerStatus::Boosted;

        // Update result
        result.success = true;
        result.processesModified = processesModified;
        result.memoryFreedMB = memoryFreed;
        // H6: Compute rough estimate based on actual throttle ratio
        if (processesModified > 0) {
            const auto totalProcesses = static_cast<uint32_t>(pids.size());
            double throttleRatio = static_cast<double>(processesModified) /
                                   std::max(1u, totalProcesses);
            result.estimatedGainPercent = std::clamp(throttleRatio * 25.0, 1.0, 30.0);
        } else {
            result.estimatedGainPercent = 0.0;
        }

        m_impl->m_stats.boostActivations++;

        lock.unlock();

        // Notify callbacks
        m_impl->NotifyOptimization(result);

        Utils::Logger::Info("Optimization applied: {} processes modified, {} MB freed",
                           processesModified, memoryFreed);

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ApplyCustomSettings failed: {}", e.what());
        result.errorMessage = e.what();
        m_impl->NotifyError("Settings application failed: " + std::string(e.what()), -1);
        return result;
    }
}

[[nodiscard]] OptimizationResult PerformanceOptimizer::RestoreSystem() {
    OptimizationResult result;
    result.appliedTime = std::chrono::system_clock::now();

    try {
        std::unique_lock lock(m_impl->m_mutex);

        Utils::Logger::Info("Restoring system to normal state");

        uint32_t processesRestored = 0;

        // Restore all modified processes
        for (auto& [pid, state] : m_impl->m_processStates) {
            if (!state.isModified) continue;

            // Fix #15: RAII handle
            ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
            if (!hProcess) continue;

            // Restore priority
            DWORD winPriority = GetWindowsPriorityClass(state.originalPriority);
            if (::SetPriorityClass(hProcess.get(), winPriority)) {
                state.currentPriority = state.originalPriority;
                processesRestored++;
            }

            // Restore affinity
            if (state.currentAffinityMask != state.originalAffinityMask) {
                ::SetProcessAffinityMask(hProcess.get(), state.originalAffinityMask);
                state.currentAffinityMask = state.originalAffinityMask;
            }

            // C1: Restore I/O priority (mirrors Shutdown logic)
            if (auto ntSetInfo = GetNtSetInformationProcess()) {
                ULONG ioPriority = ToWindowsIOPriority(state.originalIOPriority);
                NTSTATUS ntStatus = ntSetInfo(hProcess.get(), SS_ProcessIoPriority,
                                              &ioPriority, sizeof(ioPriority));
                if (ntStatus != 0) {
                    Utils::Logger::Warn("RestoreSystem: NtSetInformationProcess(IoPriority) "
                                        "failed for PID {}: NTSTATUS 0x{:08X}", pid,
                                        static_cast<uint32_t>(ntStatus));
                } else {
                    state.currentIOPriority = state.originalIOPriority;
                }
            }

            // C1: Restore memory priority (mirrors Shutdown logic)
            if (auto ntSetInfo = GetNtSetInformationProcess()) {
                SS_MEMORY_PRIORITY_INFORMATION memPriority{};
                memPriority.MemoryPriority = ToWindowsMemoryPriority(state.originalMemoryPriority);
                NTSTATUS ntStatus = ntSetInfo(hProcess.get(), SS_ProcessMemoryPriority,
                                              &memPriority, sizeof(memPriority));
                if (ntStatus != 0) {
                    Utils::Logger::Warn("RestoreSystem: NtSetInformationProcess(MemoryPriority) "
                                        "failed for PID {}: NTSTATUS 0x{:08X}", pid,
                                        static_cast<uint32_t>(ntStatus));
                } else {
                    state.currentMemoryPriority = state.originalMemoryPriority;
                }
            }

            state.isModified = false;
            // ScopedHandle releases hProcess automatically
        }

        // Fix #3: Use internal variant to avoid re-locking deadlock
        m_impl->DisableThrottlingInternal();

        // Update state
        m_impl->m_isBoosted.store(false, std::memory_order_release);
        m_impl->m_status = OptimizerStatus::Normal;

        // Calculate boost duration
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - m_impl->m_boostStartTime).count();
        m_impl->m_stats.totalBoostDurationSeconds += duration;

        result.success = true;
        result.processesModified = processesRestored;

        m_impl->m_stats.restorations++;

        lock.unlock();

        // Notify callbacks
        m_impl->NotifyOptimization(result);

        Utils::Logger::Info("System restored: {} processes", processesRestored);

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RestoreSystem failed: {}", e.what());
        result.errorMessage = e.what();
        m_impl->NotifyError("System restore failed: " + std::string(e.what()), -1);
        return result;
    }
}

[[nodiscard]] bool PerformanceOptimizer::IsBoosted() const noexcept {
    return m_impl->m_isBoosted.load(std::memory_order_acquire);
}

[[nodiscard]] OptimizationProfile PerformanceOptimizer::GetCurrentProfile() const noexcept {
    return m_impl->m_currentProfile.load(std::memory_order_acquire);
}

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

[[nodiscard]] bool PerformanceOptimizer::SetProcessPriority(
    uint32_t pid,
    ProcessPriorityClass priority)
{
    try {
        // M5: Reject REALTIME_PRIORITY_CLASS — never appropriate for a consumer security product
        if (priority == ProcessPriorityClass::Realtime) {
            Utils::Logger::Warn("SetProcessPriority: REALTIME_PRIORITY_CLASS rejected for "
                                "PID {} — use High or lower for consumer endpoints", pid);
            return false;
        }

        // Fix #15: RAII handle
        ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
        if (!hProcess) {
            return false;
        }

        DWORD winPriority = GetWindowsPriorityClass(priority);
        bool success = ::SetPriorityClass(hProcess.get(), winPriority) != 0;

        if (success) {
            std::unique_lock lock(m_impl->m_mutex);

            // Fix #4: SaveProcessState assumes lock is held
            if (m_impl->m_processStates.find(pid) == m_impl->m_processStates.end()) {
                m_impl->SaveProcessState(pid, hProcess.get());
            }

            auto& state = m_impl->m_processStates[pid];
            state.currentPriority = priority;
            state.isModified = true;

            m_impl->m_stats.priorityChanges++;
        }

        return success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetProcessPriority failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool PerformanceOptimizer::SetIOPriority(
    uint32_t pid,
    IOPriority priority)
{
    try {
        // Fix #15: RAII handle
        ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
        if (!hProcess) {
            return false;
        }

        bool success = false;

        if (auto ntSetInfo = GetNtSetInformationProcess()) {
            // Fix #5: Use translation function
            ULONG ioPriority = ToWindowsIOPriority(priority);
            // Fix #6: Use ULONG constant
            // Fix #16: Check NTSTATUS return
            NTSTATUS status = ntSetInfo(hProcess.get(), SS_ProcessIoPriority,
                                       &ioPriority, sizeof(ioPriority));
            success = (status == 0);

            if (!success) {
                Utils::Logger::Warn("NtSetInformationProcess(IoPriority) failed for "
                                    "PID {}: NTSTATUS 0x{:08X}", pid,
                                    static_cast<uint32_t>(status));
            }

            if (success) {
                std::unique_lock lock(m_impl->m_mutex);
                auto& state = m_impl->m_processStates[pid];
                state.currentIOPriority = priority;
            }
        }

        return success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetIOPriority failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool PerformanceOptimizer::SetMemoryPriority(
    uint32_t pid,
    MemoryPriority priority)
{
    try {
        // Fix #15: RAII handle
        ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
        if (!hProcess) {
            return false;
        }

        bool success = false;

        if (auto ntSetInfo = GetNtSetInformationProcess()) {
            SS_MEMORY_PRIORITY_INFORMATION memPriority{};
            // Fix #14: Explicit switch-based translation
            memPriority.MemoryPriority = ToWindowsMemoryPriority(priority);

            // Fix #6: Use ULONG constant
            // Fix #16: Check NTSTATUS return
            NTSTATUS status = ntSetInfo(hProcess.get(), SS_ProcessMemoryPriority,
                                       &memPriority, sizeof(memPriority));
            success = (status == 0);

            if (!success) {
                Utils::Logger::Warn("NtSetInformationProcess(MemoryPriority) failed for "
                                    "PID {}: NTSTATUS 0x{:08X}", pid,
                                    static_cast<uint32_t>(status));
            }

            if (success) {
                std::unique_lock lock(m_impl->m_mutex);
                auto& state = m_impl->m_processStates[pid];
                state.currentMemoryPriority = priority;
            }
        }

        return success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetMemoryPriority failed: {}", e.what());
        return false;
    }
}

/**
 * Fix #17: Validate affinity mask against system affinity before applying.
 * Fix #15: Use ScopedHandle for RAII.
 */
[[nodiscard]] bool PerformanceOptimizer::SetCPUAffinity(
    uint32_t pid,
    uint64_t affinityMask)
{
    try {
        // Fix #17: Validate mask is non-zero
        if (affinityMask == 0) {
            Utils::Logger::Error("SetCPUAffinity: affinity mask must be non-zero");
            return false;
        }

        // Fix #15: RAII handle
        ScopedHandle hProcess(m_impl->OpenProcessWithPrivileges(pid));
        if (!hProcess) {
            return false;
        }

        // Fix #17: Query system affinity and validate mask is a valid subset
        DWORD_PTR processAffinity = 0, systemAffinity = 0;
        if (!::GetProcessAffinityMask(hProcess.get(), &processAffinity, &systemAffinity)) {
            Utils::Logger::Error("SetCPUAffinity: GetProcessAffinityMask failed for "
                                 "PID {}: error {}", pid, ::GetLastError());
            return false;
        }

        if ((affinityMask & systemAffinity) != affinityMask) {
            Utils::Logger::Error("SetCPUAffinity: requested mask 0x{:X} is not a "
                                 "subset of system affinity 0x{:X}",
                                 affinityMask, static_cast<uint64_t>(systemAffinity));
            return false;
        }

        bool success = ::SetProcessAffinityMask(hProcess.get(), affinityMask) != 0;

        if (success) {
            std::unique_lock lock(m_impl->m_mutex);

            // Fix #4: SaveProcessState assumes lock is held
            if (m_impl->m_processStates.find(pid) == m_impl->m_processStates.end()) {
                m_impl->SaveProcessState(pid, hProcess.get());
            }

            auto& state = m_impl->m_processStates[pid];
            state.currentAffinityMask = affinityMask;
            state.isModified = true;
        } else {
            Utils::Logger::Error("SetProcessAffinityMask failed for PID {}: error {}",
                                 pid, ::GetLastError());
        }

        return success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetCPUAffinity failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::optional<ProcessResourceState>
PerformanceOptimizer::GetProcessState(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_processStates.find(pid);
    if (it != m_impl->m_processStates.end()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<ProcessResourceState>
PerformanceOptimizer::GetModifiedProcesses() const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<ProcessResourceState> modified;
    for (const auto& [pid, state] : m_impl->m_processStates) {
        if (state.isModified) {
            modified.push_back(state);
        }
    }

    return modified;
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

/**
 * Fix #1: processesT rimmed -> processesTrimmed
 * Fix #7: Add blocklist for system-critical processes, skip excluded, skip foreground
 * Fix #15: Use ScopedHandle
 * Fix #18: Use heap-allocated EnumProcesses
 */
[[nodiscard]] uint64_t PerformanceOptimizer::TrimWorkingSet() {
    try {
        Utils::Logger::Info("Trimming working sets...");

        uint64_t totalFreed = 0;
        uint32_t processesTrimmed = 0;

        // Fix #18: Heap-allocated EnumProcesses with retry
        auto pids = EnumAllProcesses();
        if (pids.empty()) {
            return 0;
        }

        // Fix #7: Determine the foreground window's process to skip it
        DWORD foregroundPid = 0;
        HWND hForeground = ::GetForegroundWindow();
        if (hForeground) {
            ::GetWindowThreadProcessId(hForeground, &foregroundPid);
        }

        // Get config exclusions under a shared lock
        std::vector<std::wstring> excludedProcesses;
        {
            std::shared_lock lock(m_impl->m_mutex);
            excludedProcesses = m_impl->m_config.excludedProcesses;
        }

        for (DWORD pid : pids) {
            if (pid == 0) continue;

            // Fix #7: Skip the foreground process
            if (pid == foregroundPid) continue;

            // Fix #15: RAII handle
            ScopedHandle hProcess(::OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                FALSE, pid));
            if (!hProcess) continue;

            // Fix #7: Get process name and check blocklist/exclusions
            wchar_t processPath[MAX_PATH] = {};
            DWORD pathSize = MAX_PATH;
            std::wstring processName;
            if (::QueryFullProcessImageNameW(hProcess.get(), 0, processPath, &pathSize)) {
                processName = std::filesystem::path(processPath).filename().wstring();
            } else {
                // Cannot determine name; skip to be safe
                continue;
            }

            // Skip system-critical processes
            if (IsSystemCriticalProcess(processName)) {
                continue;
            }

            // Skip excluded processes from config
            bool excluded = false;
            for (const auto& excl : excludedProcesses) {
                if (_wcsicmp(processName.c_str(), excl.c_str()) == 0) {
                    excluded = true;
                    break;
                }
            }
            if (excluded) continue;

            // Get memory info before
            PROCESS_MEMORY_COUNTERS pmc{};
            pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
            uint64_t before = 0;

            if (::GetProcessMemoryInfo(hProcess.get(), &pmc, sizeof(pmc))) {
                before = pmc.WorkingSetSize;
            }

            // Trim working set
            if (::EmptyWorkingSet(hProcess.get())) {
                // Get memory info after
                if (::GetProcessMemoryInfo(hProcess.get(), &pmc, sizeof(pmc))) {
                    uint64_t after = pmc.WorkingSetSize;
                    if (before > after) {
                        totalFreed += (before - after) / (1024 * 1024);
                        processesTrimmed++;
                    }
                }
            }

            // ScopedHandle releases hProcess automatically
        }

        m_impl->m_stats.workingSetTrims++;
        m_impl->m_stats.totalMemoryFreedMB += totalFreed;

        Utils::Logger::Info("Trimmed {} processes, freed {} MB", processesTrimmed, totalFreed);
        return totalFreed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("TrimWorkingSet failed: {}", e.what());
        return 0;
    }
}

/**
 * Fix #9: Implement real cache flush using SetSystemFileCacheSize with
 * SE_INCREASE_QUOTA_NAME privilege. Falls back to EmptyWorkingSet on self
 * if the privilege is not available.
 */
void PerformanceOptimizer::FlushCaches() {
    try {
        Utils::Logger::Info("Flushing system caches");

        // Attempt to enable SE_INCREASE_QUOTA_NAME privilege
        bool hasPrivilege = EnablePrivilege(SE_INCREASE_QUOTA_NAME);

        if (hasPrivilege) {
            // Use SetSystemFileCacheSize to flush standby page list.
            // Passing (SIZE_T)-1 for both min and max with flags = 0
            // resets the system file cache working set limits, which
            // forces the memory manager to trim the cache.
            SIZE_T minCache = 0, maxCache = 0;
            DWORD flags = 0;

            // First, get current settings so we can restore them
            if (::GetSystemFileCacheSize(&minCache, &maxCache, &flags)) {
                // Flush by setting both to -1 (no limit), which releases cache
                if (!::SetSystemFileCacheSize(static_cast<SIZE_T>(-1),
                                              static_cast<SIZE_T>(-1), 0)) {
                    Utils::Logger::Warn("SetSystemFileCacheSize flush failed: error {}",
                                        ::GetLastError());
                } else {
                    // Restore original cache limits
                    ::SetSystemFileCacheSize(minCache, maxCache, flags);
                    Utils::Logger::Info("System file cache flushed successfully");
                }
            } else {
                Utils::Logger::Warn("GetSystemFileCacheSize failed: error {}",
                                    ::GetLastError());
            }
        } else {
            Utils::Logger::Warn("SE_INCREASE_QUOTA_NAME privilege not available; "
                                "falling back to EmptyWorkingSet on self");

            // Fall back to trimming our own working set
            ScopedHandle hSelf(::OpenProcess(PROCESS_SET_QUOTA, FALSE,
                                             ::GetCurrentProcessId()));
            if (hSelf) {
                if (::EmptyWorkingSet(hSelf.get())) {
                    Utils::Logger::Info("Emptied own working set as cache flush fallback");
                } else {
                    Utils::Logger::Warn("EmptyWorkingSet on self failed: error {}",
                                        ::GetLastError());
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("FlushCaches failed: {}", e.what());
    }
}

[[nodiscard]] uint64_t PerformanceOptimizer::ReleaseMemory(size_t targetMB) {
    try {
        Utils::Logger::Info("Releasing {} MB of memory", targetMB);

        uint64_t totalFreed = TrimWorkingSet();

        if (totalFreed < targetMB && m_impl->m_config.enableAggressiveMemoryRelease) {
            // Additional aggressive techniques
            FlushCaches();
        }

        return totalFreed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ReleaseMemory failed: {}", e.what());
        return 0;
    }
}

[[nodiscard]] uint64_t PerformanceOptimizer::GetAvailableMemoryMB() const {
    try {
        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(MEMORYSTATUSEX);

        if (::GlobalMemoryStatusEx(&memStatus)) {
            return memStatus.ullAvailPhys / (1024 * 1024);
        }

        return 0;

    } catch (...) {
        return 0;
    }
}

// ============================================================================
// THROTTLING
// ============================================================================

/**
 * Fix #3 / #10: Public EnableThrottling locks, then delegates to internal.
 */
void PerformanceOptimizer::EnableThrottling(const ThrottleSettings& settings) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->EnableThrottlingInternal(settings);
}

/**
 * Fix #3 / #10: Public DisableThrottling locks, then delegates to internal.
 */
void PerformanceOptimizer::DisableThrottling() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->DisableThrottlingInternal();
}

[[nodiscard]] bool PerformanceOptimizer::IsThrottlingActive() const noexcept {
    return m_impl->m_throttlingActive.load(std::memory_order_acquire);
}

/**
 * Fix #10: ShouldThrottleScan implementation.
 * Uses a sliding-window token-bucket approach. Returns true if the scan
 * should be deferred (i.e., rate limit exceeded). Returns false if scanning
 * is permitted.
 */
[[nodiscard]] bool PerformanceOptimizer::ShouldThrottleScan() const {
    if (!m_impl->m_throttlingActive.load(std::memory_order_acquire)) {
        return false;
    }

    std::lock_guard lock(m_impl->m_scanRateMutex);

    auto now = Clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_impl->m_scanWindowStart).count();

    // Reset window every second
    if (elapsed >= 1) {
        m_impl->m_scanWindowStart = now;
        m_impl->m_scansThisSecond = 0;
    }

    uint32_t current = m_impl->m_scansThisSecond;
    if (current >= m_impl->m_scanRateLimit) {
        return true; // Throttle: rate exceeded
    }

    m_impl->m_scansThisSecond = current + 1;
    return false; // Scan permitted
}

[[nodiscard]] ThrottleSettings PerformanceOptimizer::GetThrottleSettings() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_throttleSettings;
}

// ============================================================================
// MONITORING
// ============================================================================

[[nodiscard]] SystemResourceSnapshot PerformanceOptimizer::GetResourceSnapshot() const {
    return m_impl->CaptureResourceSnapshot();
}

void PerformanceOptimizer::StartResourceMonitoring(uint32_t intervalMs) {
    try {
        // M3: Validate and clamp intervalMs to [100, 60000]
        const uint32_t originalInterval = intervalMs;
        intervalMs = std::clamp(intervalMs, 100u, 60000u);
        if (originalInterval != intervalMs) {
            Utils::Logger::Warn("StartResourceMonitoring: intervalMs {} clamped to {} "
                                "(valid range: 100-60000)", originalInterval, intervalMs);
        }

        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_monitoringActive.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("Monitoring already active");
            return;
        }

        m_impl->m_monitoringIntervalMs = intervalMs;
        m_impl->m_monitoringActive.store(true, std::memory_order_release);

        // Start monitoring thread
        m_impl->m_monitoringThread = std::thread(
            &PerformanceOptimizerImpl::MonitoringThreadFunc, m_impl.get());

        Utils::Logger::Info("Resource monitoring started (interval: {}ms)", intervalMs);

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartResourceMonitoring failed: {}", e.what());
        m_impl->NotifyError("Failed to start monitoring: " + std::string(e.what()), -1);
    }
}

void PerformanceOptimizer::StopResourceMonitoring() {
    m_impl->StopMonitoring();
    Utils::Logger::Info("Resource monitoring stopped");
}

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

[[nodiscard]] ProfileSettings PerformanceOptimizer::GetProfileSettings(
    OptimizationProfile profile) const
{
    ProfileSettings settings;

    switch (profile) {
        case OptimizationProfile::Normal:
            settings.name = "Normal";
            settings.description = "Normal operation mode";
            settings.processPriority = ProcessPriorityClass::Normal;
            settings.ioPriority = IOPriority::Normal;
            settings.memoryPriority = MemoryPriority::VeryHigh;
            settings.throttle.diskThroughputMBps = 0;
            settings.throttle.cpuUsageLimit = 100;
            settings.trimWorkingSet = false;
            settings.deferBackgroundWork = false;
            break;

        case OptimizationProfile::Balanced:
            settings.name = "Balanced";
            settings.description = "Balanced performance mode";
            settings.processPriority = ProcessPriorityClass::BelowNormal;
            settings.ioPriority = IOPriority::Low;
            settings.memoryPriority = MemoryPriority::Low;
            settings.throttle.diskThroughputMBps = 100;
            settings.throttle.cpuUsageLimit = 50;
            settings.trimWorkingSet = true;
            settings.deferBackgroundWork = true;
            break;

        case OptimizationProfile::Performance:
            settings.name = "Performance";
            settings.description = "Maximum performance mode (gaming)";
            settings.processPriority = ProcessPriorityClass::Idle;
            settings.ioPriority = IOPriority::VeryLow;
            settings.memoryPriority = MemoryPriority::VeryLow;
            settings.throttle.diskThroughputMBps = 50;
            settings.throttle.cpuUsageLimit = 25;
            settings.throttle.scanRateLimit = 5;
            settings.trimWorkingSet = true;
            settings.useEfficiencyCoresOnly = true;
            settings.deferBackgroundWork = true;
            break;

        case OptimizationProfile::PowerSaver:
            settings.name = "Power Saver";
            settings.description = "Battery optimization mode";
            settings.processPriority = ProcessPriorityClass::Idle;
            settings.ioPriority = IOPriority::VeryLow;
            settings.memoryPriority = MemoryPriority::Lowest;
            settings.throttle.diskThroughputMBps = 25;
            settings.throttle.cpuUsageLimit = 15;
            settings.throttle.scanRateLimit = 3;
            settings.trimWorkingSet = true;
            settings.flushCaches = true;
            settings.useEfficiencyCoresOnly = true;
            settings.deferBackgroundWork = true;
            break;

        case OptimizationProfile::Silent:
            settings.name = "Silent";
            settings.description = "Minimal resource usage";
            settings.processPriority = ProcessPriorityClass::Idle;
            settings.ioPriority = IOPriority::VeryLow;
            settings.memoryPriority = MemoryPriority::Lowest;
            settings.throttle.diskThroughputMBps = 10;
            settings.throttle.cpuUsageLimit = 10;
            settings.throttle.scanRateLimit = 1;
            settings.trimWorkingSet = true;
            settings.flushCaches = true;
            settings.useEfficiencyCoresOnly = true;
            settings.deferBackgroundWork = true;
            break;

        // Fix #13: Add braces around Custom case to give the local variable
        // its own scope, preventing jump-over-initialization warnings
        case OptimizationProfile::Custom: {
            std::shared_lock lock(m_impl->m_mutex);
            return m_impl->m_customProfile;
        }

        // M6: Defensive default — log error and fall back to Normal profile
        default:
            Utils::Logger::Error("GetProfileSettings: unknown OptimizationProfile value {}",
                                 static_cast<unsigned>(profile));
            settings.name = "Normal";
            settings.description = "Normal operation mode (fallback)";
            settings.processPriority = ProcessPriorityClass::Normal;
            settings.ioPriority = IOPriority::Normal;
            settings.memoryPriority = MemoryPriority::VeryHigh;
            settings.throttle.diskThroughputMBps = 0;
            settings.throttle.cpuUsageLimit = 100;
            settings.trimWorkingSet = false;
            settings.deferBackgroundWork = false;
            break;
    }

    return settings;
}

void PerformanceOptimizer::SetCustomProfile(const ProfileSettings& settings) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_customProfile = settings;
    Utils::Logger::Info("Custom profile set: {}", settings.name);
}

// ============================================================================
// CALLBACKS
// Fix #12: All callback registration/unregistration uses m_callbackMutex
// ============================================================================

void PerformanceOptimizer::RegisterOptimizationCallback(OptimizationCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_optimizationCallbacks.push_back(std::move(callback));
}

void PerformanceOptimizer::RegisterResourceCallback(ResourceCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_resourceCallbacks.push_back(std::move(callback));
}

void PerformanceOptimizer::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;

    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void PerformanceOptimizer::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->m_callbackMutex);

    m_impl->m_optimizationCallbacks.clear();
    m_impl->m_resourceCallbacks.clear();
    m_impl->m_errorCallbacks.clear();

    Utils::Logger::Info("All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] OptimizerStatistics PerformanceOptimizer::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void PerformanceOptimizer::ResetStatistics() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    m_impl->m_stats.startTime = Clock::now();

    Utils::Logger::Info("Statistics reset");
}

[[nodiscard]] bool PerformanceOptimizer::SelfTest() {
    try {
        Utils::Logger::Info("Running PerformanceOptimizer self-test...");

        bool allPassed = true;

        // Test 1: Configuration validation
        PerformanceOptimizerConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("Self-test failed: Invalid default configuration");
            allPassed = false;
        }

        // Test 2: Resource snapshot
        try {
            auto snapshot = GetResourceSnapshot();
            if (snapshot.cpuUsage < 0.0 || snapshot.cpuUsage > 100.0) {
                Utils::Logger::Error("Self-test failed: Invalid CPU usage");
                allPassed = false;
            }
        } catch (...) {
            Utils::Logger::Error("Self-test failed: Resource snapshot exception");
            allPassed = false;
        }

        // Test 3: Priority class conversion
        for (auto priority : {ProcessPriorityClass::Realtime, ProcessPriorityClass::High,
                             ProcessPriorityClass::Normal, ProcessPriorityClass::Idle}) {
            DWORD winPriority = GetWindowsPriorityClass(priority);
            if (winPriority == 0) {
                Utils::Logger::Error("Self-test failed: Priority conversion");
                allPassed = false;
            }
        }

        // Test 4: Profile settings
        for (auto profile : {OptimizationProfile::Normal, OptimizationProfile::Performance,
                            OptimizationProfile::PowerSaver}) {
            auto settings = GetProfileSettings(profile);
            if (settings.name.empty()) {
                Utils::Logger::Error("Self-test failed: Profile settings");
                allPassed = false;
            }
        }

        // Test 5: I/O priority translation sanity
        if (ToWindowsIOPriority(IOPriority::VeryLow) != 0 ||
            ToWindowsIOPriority(IOPriority::Critical) != 4) {
            Utils::Logger::Error("Self-test failed: I/O priority translation");
            allPassed = false;
        }

        // Test 6: Memory priority translation sanity
        if (ToWindowsMemoryPriority(MemoryPriority::VeryHigh) != 5 ||
            ToWindowsMemoryPriority(MemoryPriority::Lowest) != 1) {
            Utils::Logger::Error("Self-test failed: Memory priority translation");
            allPassed = false;
        }

        if (allPassed) {
            Utils::Logger::Info("Self-test PASSED - All tests successful");
        } else {
            Utils::Logger::Error("Self-test FAILED - See errors above");
        }

        return allPassed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Self-test exception: {}", e.what());
        return false;
    }
}

/**
 * Fix #20: Removed noexcept since std::to_string can throw.
 */
[[nodiscard]] std::string PerformanceOptimizer::GetVersionString() {
    return std::to_string(OptimizerConstants::VERSION_MAJOR) + "." +
           std::to_string(OptimizerConstants::VERSION_MINOR) + "." +
           std::to_string(OptimizerConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

void OptimizerStatistics::Reset() noexcept {
    boostActivations.store(0, std::memory_order_relaxed);
    restorations.store(0, std::memory_order_relaxed);
    workingSetTrims.store(0, std::memory_order_relaxed);
    totalMemoryFreedMB.store(0, std::memory_order_relaxed);
    priorityChanges.store(0, std::memory_order_relaxed);
    throttleActivations.store(0, std::memory_order_relaxed);
    totalBoostDurationSeconds.store(0, std::memory_order_relaxed);
}

[[nodiscard]] std::string OptimizerStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["boostActivations"] = boostActivations.load(std::memory_order_relaxed);
    j["restorations"] = restorations.load(std::memory_order_relaxed);
    j["workingSetTrims"] = workingSetTrims.load(std::memory_order_relaxed);
    j["totalMemoryFreedMB"] = totalMemoryFreedMB.load(std::memory_order_relaxed);
    j["priorityChanges"] = priorityChanges.load(std::memory_order_relaxed);
    j["throttleActivations"] = throttleActivations.load(std::memory_order_relaxed);
    j["totalBoostDurationSeconds"] = totalBoostDurationSeconds.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] bool PerformanceOptimizerConfiguration::IsValid() const noexcept {
    if (minWorkingSetMB < OptimizerConstants::MIN_WORKING_SET_MB) return false;
    if (restoreDelaySeconds > 3600) return false;
    return true;
}

[[nodiscard]] std::string ProcessResourceState::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["processId"] = processId;
    j["processName"] = Utils::StringUtils::ToNarrow(processName);
    j["originalPriority"] = static_cast<int>(originalPriority);
    j["currentPriority"] = static_cast<int>(currentPriority);
    j["originalIOPriority"] = static_cast<int>(originalIOPriority);
    j["currentIOPriority"] = static_cast<int>(currentIOPriority);
    j["originalMemoryPriority"] = static_cast<int>(originalMemoryPriority);
    j["currentMemoryPriority"] = static_cast<int>(currentMemoryPriority);
    j["originalAffinityMask"] = std::format("0x{:X}", originalAffinityMask);
    j["currentAffinityMask"] = std::format("0x{:X}", currentAffinityMask);
    j["isModified"] = isModified;

    return j.dump(2);
}

[[nodiscard]] std::string SystemResourceSnapshot::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["cpuUsage"] = cpuUsage;
    j["memoryUsage"] = memoryUsage;
    j["availableMemoryMB"] = availableMemoryMB;
    j["diskReadMBps"] = diskReadMBps;
    j["diskWriteMBps"] = diskWriteMBps;
    j["diskQueueLength"] = diskQueueLength;
    j["networkMbps"] = networkMbps;
    j["gpuUsage"] = gpuUsage;
    j["onBattery"] = onBattery;
    j["batteryPercent"] = batteryPercent;
    j["timestamp"] = timestamp.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string ThrottleSettings::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["diskThroughputMBps"] = diskThroughputMBps;
    j["iopsLimit"] = iopsLimit;
    j["scanRateLimit"] = scanRateLimit;
    j["networkBandwidthMbps"] = networkBandwidthMbps;
    j["cpuUsageLimit"] = cpuUsageLimit;

    return j.dump(2);
}

[[nodiscard]] std::string ProfileSettings::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["name"] = name;
    j["description"] = description;
    j["processPriority"] = static_cast<int>(processPriority);
    j["ioPriority"] = static_cast<int>(ioPriority);
    j["memoryPriority"] = static_cast<int>(memoryPriority);
    j["throttle"] = Json::object();
    j["throttle"]["diskThroughputMBps"] = throttle.diskThroughputMBps;
    j["throttle"]["iopsLimit"] = throttle.iopsLimit;
    j["throttle"]["scanRateLimit"] = throttle.scanRateLimit;
    j["throttle"]["networkBandwidthMbps"] = throttle.networkBandwidthMbps;
    j["throttle"]["cpuUsageLimit"] = throttle.cpuUsageLimit;
    j["trimWorkingSet"] = trimWorkingSet;
    j["flushCaches"] = flushCaches;
    j["useEfficiencyCoresOnly"] = useEfficiencyCoresOnly;
    j["deferBackgroundWork"] = deferBackgroundWork;

    return j.dump(2);
}

[[nodiscard]] std::string OptimizationResult::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["success"] = success;
    j["profile"] = static_cast<int>(profile);
    j["processesModified"] = processesModified;
    j["memoryFreedMB"] = memoryFreedMB;
    j["estimatedGainPercent"] = estimatedGainPercent;
    j["appliedTime"] = appliedTime.time_since_epoch().count();
    j["errorMessage"] = errorMessage;

    return j.dump(2);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetProfileName(OptimizationProfile profile) noexcept {
    switch (profile) {
        case OptimizationProfile::Normal: return "Normal";
        case OptimizationProfile::Balanced: return "Balanced";
        case OptimizationProfile::Performance: return "Performance";
        case OptimizationProfile::PowerSaver: return "PowerSaver";
        case OptimizationProfile::Silent: return "Silent";
        case OptimizationProfile::Custom: return "Custom";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetPriorityClassName(ProcessPriorityClass priority) noexcept {
    switch (priority) {
        case ProcessPriorityClass::Realtime: return "Realtime";
        case ProcessPriorityClass::High: return "High";
        case ProcessPriorityClass::AboveNormal: return "AboveNormal";
        case ProcessPriorityClass::Normal: return "Normal";
        case ProcessPriorityClass::BelowNormal: return "BelowNormal";
        case ProcessPriorityClass::Idle: return "Idle";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIOPriorityName(IOPriority priority) noexcept {
    switch (priority) {
        case IOPriority::Critical: return "Critical";
        case IOPriority::High: return "High";
        case IOPriority::Normal: return "Normal";
        case IOPriority::Low: return "Low";
        case IOPriority::VeryLow: return "VeryLow";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetMemoryPriorityName(MemoryPriority priority) noexcept {
    switch (priority) {
        case MemoryPriority::VeryHigh: return "VeryHigh";
        case MemoryPriority::High: return "High";
        case MemoryPriority::Medium: return "Medium";
        case MemoryPriority::Low: return "Low";
        case MemoryPriority::VeryLow: return "VeryLow";
        case MemoryPriority::Lowest: return "Lowest";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetResourceTypeName(ResourceType type) noexcept {
    switch (type) {
        case ResourceType::CPU: return "CPU";
        case ResourceType::Memory: return "Memory";
        case ResourceType::DiskIO: return "DiskIO";
        case ResourceType::NetworkIO: return "NetworkIO";
        case ResourceType::GPU: return "GPU";
        default: return "Unknown";
    }
}

[[nodiscard]] DWORD GetWindowsPriorityClass(ProcessPriorityClass priority) noexcept {
    switch (priority) {
        case ProcessPriorityClass::Realtime: return REALTIME_PRIORITY_CLASS;
        case ProcessPriorityClass::High: return HIGH_PRIORITY_CLASS;
        case ProcessPriorityClass::AboveNormal: return ABOVE_NORMAL_PRIORITY_CLASS;
        case ProcessPriorityClass::Normal: return NORMAL_PRIORITY_CLASS;
        case ProcessPriorityClass::BelowNormal: return BELOW_NORMAL_PRIORITY_CLASS;
        case ProcessPriorityClass::Idle: return IDLE_PRIORITY_CLASS;
        default: return NORMAL_PRIORITY_CLASS;
    }
}

/**
 * Fix #11: Implement using GetSystemCpuSetInformation API (Windows 10 1803+).
 * Falls back to heuristic only if the API is unavailable.
 * Queries EfficiencyClass field from SYSTEM_CPU_SET_INFORMATION to
 * accurately identify efficiency cores on hybrid architectures (Intel 12th+).
 */
[[nodiscard]] uint64_t GetEfficiencyCoresMask() {
    // Try the proper API first
    static auto pGetSystemCpuSetInformation =
        reinterpret_cast<GetSystemCpuSetInformationFunc>(
            ::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
                             "GetSystemCpuSetInformation"));

    if (pGetSystemCpuSetInformation) {
        ULONG requiredLength = 0;

        // Query required buffer size
        pGetSystemCpuSetInformation(nullptr, 0, &requiredLength, nullptr, 0);
        if (requiredLength > 0 && requiredLength < 1024 * 1024) {
            std::vector<uint8_t> buffer(requiredLength);
            ULONG returnedLength = 0;

            if (pGetSystemCpuSetInformation(
                    reinterpret_cast<SS_SYSTEM_CPU_SET_INFORMATION*>(buffer.data()),
                    requiredLength, &returnedLength, nullptr, 0)) {

                uint64_t efficiencyMask = 0;
                bool hasHybrid = false;
                ULONG offset = 0;

                // Iterate through the variable-length array of CPU set entries
                while (offset + sizeof(SS_SYSTEM_CPU_SET_INFORMATION) <= returnedLength) {
                    const auto* info = reinterpret_cast<const SS_SYSTEM_CPU_SET_INFORMATION*>(
                        buffer.data() + offset);

                    if (info->Size == 0) break; // Safety: avoid infinite loop

                    // Type 0 = CpuSetInformation
                    if (info->Type == 0) {
                        // EfficiencyClass > 0 means efficiency core on Intel hybrid
                        if (info->CpuSet.EfficiencyClass > 0) {
                            uint8_t logicalIndex = info->CpuSet.LogicalProcessorIndex;
                            if (logicalIndex < 64) {
                                efficiencyMask |= (1ULL << logicalIndex);
                            }
                            hasHybrid = true;
                        }
                    }

                    offset += info->Size;
                }

                if (hasHybrid && efficiencyMask != 0) {
                    return efficiencyMask;
                }

                // If no hybrid topology detected, the system is homogeneous.
                // Fall through to fallback below.
            }
        }
    }

    // Fallback: heuristic for non-hybrid or pre-1803 systems
    SYSTEM_INFO sysInfo{};
    ::GetSystemInfo(&sysInfo);

    uint32_t numCores = sysInfo.dwNumberOfProcessors;

    // For 8+ core homogeneous systems, assume last 4 cores are less
    // critical for foreground tasks
    if (numCores >= 8) {
        uint64_t mask = 0;
        for (uint32_t i = numCores - 4; i < numCores; ++i) {
            mask |= (1ULL << i);
        }
        return mask;
    }

    // For smaller systems, return all cores (no efficiency core distinction)
    return (1ULL << numCores) - 1;
}

[[nodiscard]] uint64_t GetPerformanceCoresMask() {
    // Complement of efficiency cores within the system's logical processor set
    SYSTEM_INFO sysInfo{};
    ::GetSystemInfo(&sysInfo);

    uint32_t numCores = sysInfo.dwNumberOfProcessors;
    uint64_t allCores = (numCores >= 64) ? ~0ULL : ((1ULL << numCores) - 1);
    uint64_t eCores = GetEfficiencyCoresMask();

    uint64_t pCores = allCores & ~eCores;
    // If masking out E-cores would leave nothing (homogeneous system),
    // return all cores
    return (pCores != 0) ? pCores : allCores;
}

}  // namespace ShadowStrike::GameMode
