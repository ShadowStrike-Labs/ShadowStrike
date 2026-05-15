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
 * ShadowStrike Security - ANTI-DEBUG PROTECTION ENGINE
 * ============================================================================
 *
 * @file AntiDebug.cpp
 * @brief Enterprise-grade anti-debugging and tamper protection implementation
 *        for ShadowStrike antivirus self-defense mechanisms.
 *
 * PURPOSE:
 * ========
 * This module provides TAMPER DETECTION for the ShadowStrike security agent.
 * When malware attempts to debug, inject, or disable the AV agent, this module
 * detects these attempts and generates security events for SIEM integration.
 *
 * This is a DEFENSIVE security feature, not an evasion mechanism. All detections
 * are logged for security monitoring and incident response.
 *
 * IMPLEMENTATION NOTES:
 * ====================
 * - Uses PIMPL pattern for ABI stability
 * - Thread-safe via std::shared_mutex
 * - All detections generate security events
 * - Integrates with ShadowStrike logging infrastructure
 * - Statistics tracked for security dashboards
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2024
 * @copyright (c) 2024 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "AntiDebug.hpp"

// ============================================================================
// COMMUNICATION INCLUDES — KERNEL BRIDGE & WIRING
// ============================================================================

#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"
#include "../Utils/StringUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <random>
#include <cwctype>

// ============================================================================
// WINDOWS SDK INCLUDES (Additional)
// ============================================================================

#ifdef _WIN32
#pragma comment(lib, "ntdll.lib")

// NTDLL function typedefs
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtClose_t)(
    HANDLE Handle
);

// Process information classes — prefixed to avoid conflict with winternl.h PROCESSINFOCLASS enum
constexpr PROCESSINFOCLASS SsProcessDebugPort = static_cast<PROCESSINFOCLASS>(7);
constexpr PROCESSINFOCLASS SsProcessDebugFlags = static_cast<PROCESSINFOCLASS>(31);
constexpr PROCESSINFOCLASS SsProcessDebugObjectHandle = static_cast<PROCESSINFOCLASS>(30);

// Thread information class for hiding
constexpr THREADINFOCLASS SsThreadHideFromDebugger = static_cast<THREADINFOCLASS>(17);

// NtGlobalFlag values indicating debugger
constexpr ULONG FLG_HEAP_ENABLE_TAIL_CHECK = 0x10;
constexpr ULONG FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
constexpr ULONG FLG_HEAP_VALIDATE_PARAMETERS = 0x40;
constexpr ULONG NT_GLOBAL_FLAG_DEBUGGED = (FLG_HEAP_ENABLE_TAIL_CHECK |
                                            FLG_HEAP_ENABLE_FREE_CHECK |
                                            FLG_HEAP_VALIDATE_PARAMETERS);

#endif // _WIN32

namespace ShadowStrike {
namespace Security {

// ============================================================================
// ANONYMOUS NAMESPACE FOR INTERNAL HELPERS
// ============================================================================

namespace {

/**
 * @brief Generate unique event ID
 */
[[nodiscard]] uint64_t GenerateEventId() noexcept {
    static std::atomic<uint64_t> s_eventCounter{0};
    return s_eventCounter.fetch_add(1, std::memory_order_relaxed);
}

/**
 * @brief Get current thread ID
 */
[[nodiscard]] uint32_t GetCurrentThreadIdSafe() noexcept {
#ifdef _WIN32
    return ::GetCurrentThreadId();
#else
    return 0;
#endif
}

/**
 * @brief Get current process ID
 */
[[nodiscard]] uint32_t GetCurrentProcessIdSafe() noexcept {
#ifdef _WIN32
    return ::GetCurrentProcessId();
#else
    return 0;
#endif
}

/**
 * @brief Safe string conversion from wide to narrow
 */
[[nodiscard]] std::string WideToNarrow(std::wstring_view wide) {
    if (wide.empty()) return {};

#ifdef _WIN32
    int size = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                      static_cast<int>(wide.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                          static_cast<int>(wide.size()),
                          result.data(), size, nullptr, nullptr);
    return result;
#else
    return std::string(wide.begin(), wide.end());
#endif
}

/**
 * @brief Safe string conversion from narrow to wide
 */
[[nodiscard]] std::wstring NarrowToWide(std::string_view narrow) {
    if (narrow.empty()) return {};

#ifdef _WIN32
    int size = ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                                      static_cast<int>(narrow.size()),
                                      nullptr, 0);
    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                          static_cast<int>(narrow.size()),
                          result.data(), size);
    return result;
#else
    return std::wstring(narrow.begin(), narrow.end());
#endif
}

/**
 * @brief Case-insensitive wide string comparison
 */
[[nodiscard]] bool WideStringEqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;

    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Calculate CRC32 for data
 */
[[nodiscard]] uint32_t CalculateCRC32(std::span<const uint8_t> data) noexcept {
    static constexpr std::array<uint32_t, 256> s_crcTable = []() {
        std::array<uint32_t, 256> table{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (int j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? AntiDebugConstants::CRC32_POLYNOMIAL : 0);
            }
            table[i] = crc;
        }
        return table;
    }();

    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc = s_crcTable[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

/**
 * @brief Read RDTSC timestamp counter
 */
[[nodiscard]] uint64_t ReadTSC() noexcept {
#ifdef _WIN32
    return __rdtsc();
#else
    return 0;
#endif
}

/**
 * @brief Serialization prevention barrier
 */
void SerializeExecution() noexcept {
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
#endif
}

}

// ============================================================================
// SEH HELPER FUNCTIONS (must be in separate functions — no C++ destructors)
// MSVC C2712: __try cannot coexist with objects requiring stack unwinding.
// These helpers use only POD types and return a bool for the SEH outcome.
// ============================================================================

#ifdef _WIN32

/**
 * @brief SEH wrapper for CloseHandle debugger check.
 * @return true if CloseHandle threw an exception (debugger detected).
 */
static bool SehCloseHandleCheck() noexcept {
    HANDLE hInvalid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEADBEEF));
    __try {
        ::CloseHandle(hInvalid);
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

/**
 * @brief SEH wrapper for INT3 breakpoint exception check.
 * @return true if exception was caught (normal — no debugger), false if swallowed.
 */
static bool SehInt3ExceptionCheck() noexcept {
    __try {
        __debugbreak();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;  // Exception caught normally
    }
    return false;  // Debugger swallowed the exception
}

/**
 * @brief SEH wrapper for guard page exception check.
 * @param pMem VirtualAlloc'd memory with PAGE_GUARD.
 * @return true if guard page exception was caught (normal), false if swallowed.
 */
static bool SehGuardPageCheck(LPVOID pMem) noexcept {
    __try {
        volatile BYTE* p = static_cast<volatile BYTE*>(pMem);
        *p = 0x42;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;  // Exception caught normally
    }
    return false;  // Debugger swallowed the exception
}

/**
 * @brief SEH wrapper for VEH analysis — raises an access violation.
 * @return true if the exception was handled by SEH.
 */
static bool SehRaiseAccessViolation() noexcept {
    __try {
        ::RaiseException(0xC0000005, 0, 0, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}

/**
 * @brief SEH wrapper for scanning memory for software breakpoints (0xCC).
 * @param pStart Start address.
 * @param size Size in bytes.
 * @param outBreakpoints Output: number of 0xCC bytes found.
 * @return true if scan completed, false if access violation occurred.
 */
static bool SehScanBreakpoints(const BYTE* pStart, size_t size, size_t& outBreakpoints) noexcept {
    outBreakpoints = 0;
    __try {
        for (size_t i = 0; i < size; ++i) {
            if (pStart[i] == 0xCC) {
                outBreakpoints++;
            }
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/**
 * @brief SEH-guarded read of a ULONG at an arbitrary address.
 * @return true on success; false if the read faulted.
 */
static bool SehReadUlong(const void* address, ULONG& out) noexcept {
    __try {
        out = *static_cast<const volatile ULONG*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/**
 * @brief SEH-guarded read of a pointer-sized value at an arbitrary address.
 * @return true on success; false if the read faulted.
 */
static bool SehReadPointer(const void* address, void*& out) noexcept {
    __try {
        out = *const_cast<void**>(static_cast<void* const*>(address));
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/**
 * @brief SEH-guarded copy of up to `size` bytes (size capped by caller).
 * @return number of bytes copied; 0 if the read faulted before any byte.
 */
static size_t SehReadBytes(const BYTE* src, BYTE* dst, size_t size) noexcept {
    size_t copied = 0;
    __try {
        for (size_t i = 0; i < size; ++i) {
            dst[i] = src[i];
            ++copied;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return copied;
}

#endif // _WIN32

// ============================================================================
// ANTIDEBUG IMPLEMENTATION CLASS
// ============================================================================

/**
 * @class AntiDebugImpl
 * @brief PIMPL implementation for AntiDebug engine
 */
class AntiDebugImpl final {
public:
    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    AntiDebugImpl();
    ~AntiDebugImpl();

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const AntiDebugConfiguration& config);
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    void Pause() noexcept;
    void Resume() noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const AntiDebugConfiguration& config);
    [[nodiscard]] AntiDebugConfiguration GetConfiguration() const;
    void SetProtectionLevel(AntiDebugProtectionLevel level);
    [[nodiscard]] AntiDebugProtectionLevel GetProtectionLevel() const noexcept;
    void SetMonitoringMode(MonitoringMode mode);
    [[nodiscard]] MonitoringMode GetMonitoringMode() const noexcept;
    void SetMonitoringInterval(uint32_t intervalMs);
    void EnableTechnique(DetectionTechnique technique);
    void DisableTechnique(DetectionTechnique technique);
    [[nodiscard]] bool IsTechniqueEnabled(DetectionTechnique technique) const noexcept;
    void SetResponseActions(ResponseAction actions);
    [[nodiscard]] ResponseAction GetResponseActions() const noexcept;
    void AddToWhitelist(std::wstring_view processName);
    void RemoveFromWhitelist(std::wstring_view processName);
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;

    // ========================================================================
    // DETECTION - FULL SCANS
    // ========================================================================

    [[nodiscard]] DetectionResult PerformFullScan();
    [[nodiscard]] DetectionResult PerformQuickScan();
    [[nodiscard]] DetectionResult PerformScan(DetectionTechnique techniques);
    [[nodiscard]] bool IsDebuggerDetected() const noexcept;
    [[nodiscard]] DetectionResult GetLastResult() const;
    [[nodiscard]] uint32_t GetDetectionScore() const noexcept;

    // ========================================================================
    // DETECTION - PEB/TEB BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckPEB_BeingDebugged();
    [[nodiscard]] DetectionCheckResult CheckPEB_NtGlobalFlag();
    [[nodiscard]] DetectionCheckResult CheckPEB_HeapFlags();
    [[nodiscard]] DetectionCheckResult CheckPEB_ProcessHeap();
    [[nodiscard]] DetectionCheckResult CheckAllPEB();

    // ========================================================================
    // DETECTION - API BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckAPI_IsDebuggerPresent();
    [[nodiscard]] DetectionCheckResult CheckAPI_CheckRemoteDebuggerPresent();
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugPort();
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugFlags();
    [[nodiscard]] DetectionCheckResult CheckAPI_NtQueryInformationProcess_DebugObjectHandle();
    [[nodiscard]] DetectionCheckResult CheckAPI_OutputDebugString();
    [[nodiscard]] DetectionCheckResult CheckAPI_CloseHandle();
    [[nodiscard]] DetectionCheckResult CheckAllAPI();

    // ========================================================================
    // DETECTION - TIMING BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckTiming_RDTSC();
    [[nodiscard]] DetectionCheckResult CheckTiming_QPC();
    [[nodiscard]] DetectionCheckResult CheckTiming_GetTickCount();
    [[nodiscard]] DetectionCheckResult CheckTiming_InstructionExecution();
    [[nodiscard]] TimingAnalysis PerformTimingAnalysis();
    [[nodiscard]] DetectionCheckResult CheckAllTiming();

    // ========================================================================
    // DETECTION - HARDWARE BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckHardware_DebugRegisters();
    [[nodiscard]] DebugRegisterState GetDebugRegisterState();
    [[nodiscard]] DetectionCheckResult CheckHardware_BreakpointsViaContext();
    [[nodiscard]] DetectionCheckResult CheckAllHardware();

    // ========================================================================
    // DETECTION - EXCEPTION BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckException_INT3();
    [[nodiscard]] DetectionCheckResult CheckException_INT2D();
    [[nodiscard]] DetectionCheckResult CheckException_SingleStep();
    [[nodiscard]] DetectionCheckResult CheckException_GuardPage();
    [[nodiscard]] DetectionCheckResult CheckException_VEH();
    [[nodiscard]] DetectionCheckResult CheckAllException();

    // ========================================================================
    // DETECTION - MEMORY BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckMemory_SoftwareBreakpoints();
    [[nodiscard]] DetectionCheckResult CheckMemory_SoftwareBreakpoints(uintptr_t address, size_t size);
    [[nodiscard]] DetectionCheckResult CheckMemory_CodeIntegrity();
    [[nodiscard]] DetectionCheckResult CheckMemory_IATHooks();
    [[nodiscard]] DetectionCheckResult CheckMemory_IATHooks(std::wstring_view moduleName);
    [[nodiscard]] DetectionCheckResult CheckMemory_InlineHooks();
    [[nodiscard]] DetectionCheckResult CheckMemory_InlineHooks(std::wstring_view moduleName);
    [[nodiscard]] std::vector<HookInfo> GetDetectedHooks() const;
    [[nodiscard]] DetectionCheckResult CheckAllMemory();

    // ========================================================================
    // DETECTION - PROCESS BASED
    // ========================================================================

    [[nodiscard]] DetectionCheckResult CheckProcess_ParentProcess();
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerProcesses();
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerWindows();
    [[nodiscard]] DetectionCheckResult CheckProcess_DebuggerDrivers();
    [[nodiscard]] DetectionCheckResult CheckProcess_InstrumentationFrameworks();
    [[nodiscard]] std::vector<DebuggerProcessInfo> GetDetectedDebuggers() const;
    [[nodiscard]] DetectionCheckResult CheckAllProcess();

    // ========================================================================
    // PROTECTION - THREAD HIDING
    // ========================================================================

    [[nodiscard]] bool HideThread(uint32_t threadId);
    [[nodiscard]] size_t HideAllThreads();
    [[nodiscard]] bool IsThreadHidden(uint32_t threadId) const;
    [[nodiscard]] ThreadProtectionState GetThreadProtectionState(uint32_t threadId) const;
    void SecureThread();
    [[nodiscard]] bool ProtectThread(uint32_t threadId);

    // ========================================================================
    // PROTECTION - DEBUG REGISTERS
    // ========================================================================

    [[nodiscard]] bool ClearDebugRegisters(uint32_t threadId);
    [[nodiscard]] size_t ClearAllDebugRegisters();
    void SetAutoClearing(bool enable);

    // ========================================================================
    // PROTECTION - CODE INTEGRITY
    // ========================================================================

    [[nodiscard]] bool RegisterIntegrityRegion(std::string_view id, uintptr_t address, size_t size);
    [[nodiscard]] bool RegisterSelfIntegrity();
    void UnregisterIntegrityRegion(std::string_view id);
    [[nodiscard]] AntiDebugIntegrityStatus VerifyIntegrity(std::string_view id);
    [[nodiscard]] std::unordered_map<std::string, AntiDebugIntegrityStatus> VerifyAllIntegrity();
    [[nodiscard]] std::optional<IntegrityRegion> GetIntegrityRegion(std::string_view id) const;
    [[nodiscard]] std::vector<IntegrityRegion> GetAllIntegrityRegions() const;

    // ========================================================================
    // PROTECTION - RESPONSE ACTIONS
    // ========================================================================

    [[nodiscard]] bool ExecuteResponse(ResponseAction action, const DetectionResult& result);
    [[nodiscard]] ResponseAction ExecuteRecommendedResponse(const DetectionResult& result);

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterDetectionCallback(DetectionCallback callback);
    void UnregisterDetectionCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterResponseCallback(ResponseCallback callback);
    void UnregisterResponseCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterIntegrityCallback(AntiDebugIntegrityCallback callback);
    void UnregisterIntegrityCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterHookCallback(HookCallback callback);
    void UnregisterHookCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterStatusCallback(StatusCallback callback);
    void UnregisterStatusCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] AntiDebugStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<DetectionEvent> GetDetectionHistory(size_t maxEntries) const;
    void ClearDetectionHistory();
    [[nodiscard]] std::string ExportReport() const;

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] bool SelfTest();
    void ForceGarbageCollection();

    // ========================================================================
    // KERNEL BRIDGE & COMMUNICATION WIRING
    // ========================================================================

    void OnKernelProcessNotify(uint32_t processId, uint32_t parentProcessId,
                               std::wstring_view imagePath, bool isCreate);
    void OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                           uintptr_t imageBase, size_t imageSize);
    [[nodiscard]] bool RequestKernelProcessBlock(uint32_t processId, std::string_view reason);
    void ReportDetectionToAlertSystem(const DetectionResult& result);
    void ReportScanTelemetry(const DetectionResult& result);

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    void SetStatus(ModuleStatus newStatus);
    void StartMonitoringThread();
    void StopMonitoringThread();
    void MonitoringThreadFunc();
    void NotifyDetection(const DetectionEvent& event);
    void NotifyStatusChange(ModuleStatus oldStatus, ModuleStatus newStatus);
    void RecordDetection(const DetectionCheckResult& check);
    void UpdateStatistics(const DetectionCheckResult& check, Microseconds duration);
    [[nodiscard]] DetectionResult AggregateResults(const std::vector<DetectionCheckResult>& checks);
    [[nodiscard]] ResponseAction DetermineRecommendedAction(const DetectionResult& result) const;
    [[nodiscard]] bool ValidateConfiguration(const AntiDebugConfiguration& config) const;
    void ApplyProtectionLevel(AntiDebugProtectionLevel level);
    [[nodiscard]] bool LoadNtdllFunctions();
    [[nodiscard]] std::vector<uint32_t> EnumerateThreadIds() const;
    [[nodiscard]] std::vector<std::pair<uint32_t, std::wstring>> EnumerateProcesses() const;

#ifdef _WIN32
    [[nodiscard]] PPEB GetPEB() const noexcept;
#endif

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::mutex m_callbackMutex;
    mutable std::mutex m_historyMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_debuggerDetected{false};
    std::atomic<uint32_t> m_detectionScore{0};

    // Configuration
    AntiDebugConfiguration m_config;

    // Last detection result
    DetectionResult m_lastResult;

    // Monitoring thread
    std::unique_ptr<std::thread> m_monitoringThread;
    std::atomic<bool> m_stopMonitoring{false};
    std::condition_variable m_monitoringCV;
    std::mutex m_monitoringMutex;

    // Thread protection state
    std::unordered_map<uint32_t, ThreadProtectionState> m_threadStates;
    std::atomic<bool> m_autoClearing{false};

    // Integrity regions
    std::unordered_map<std::string, IntegrityRegion> m_integrityRegions;

    // Detected items
    std::vector<HookInfo> m_detectedHooks;
    std::vector<DebuggerProcessInfo> m_detectedDebuggers;

    // Detection history
    std::deque<DetectionEvent> m_detectionHistory;
    static constexpr size_t MAX_HISTORY_SIZE = 1000;

    // Statistics
    AntiDebugStatistics m_stats;

    // Callbacks
    std::unordered_map<uint64_t, DetectionCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, ResponseCallback> m_responseCallbacks;
    std::unordered_map<uint64_t, AntiDebugIntegrityCallback> m_integrityCallbacks;
    std::unordered_map<uint64_t, HookCallback> m_hookCallbacks;
    std::unordered_map<uint64_t, StatusCallback> m_statusCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // NTDLL functions
#ifdef _WIN32
    HMODULE m_hNtdll = nullptr;
    NtQueryInformationProcess_t m_pNtQueryInformationProcess = nullptr;
    NtSetInformationThread_t m_pNtSetInformationThread = nullptr;
    NtQuerySystemInformation_t m_pNtQuerySystemInformation = nullptr;
    NtClose_t m_pNtClose = nullptr;
#endif

    // Timing baseline
    uint64_t m_rdtscBaseline = 0;
    int64_t m_qpcBaseline = 0;
    LARGE_INTEGER m_qpcFrequency{};
};

// ============================================================================
// ANTIDEBUGIMPL IMPLEMENTATION
// ============================================================================

AntiDebugImpl::AntiDebugImpl() {
    m_stats.startTime = Clock::now();

#ifdef _WIN32
    ::QueryPerformanceFrequency(&m_qpcFrequency);
#endif
}

AntiDebugImpl::~AntiDebugImpl() {
    Shutdown();
}

bool AntiDebugImpl::Initialize(const AntiDebugConfiguration& config) {
    {
        std::unique_lock lock(m_mutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"AntiDebug", L"Already initialized");
            return true;
        }

        SetStatus(ModuleStatus::Initializing);

        if (!ValidateConfiguration(config)) {
            SS_LOG_ERROR(L"AntiDebug", L"Invalid configuration");
            SetStatus(ModuleStatus::Error);
            return false;
        }

        m_config = config;

        if (!LoadNtdllFunctions()) {
            SS_LOG_ERROR(L"AntiDebug", L"Failed to load NTDLL functions");
            SetStatus(ModuleStatus::Error);
            return false;
        }

        // Establish timing baselines
        SerializeExecution();
        m_rdtscBaseline = ReadTSC();

#ifdef _WIN32
        LARGE_INTEGER qpc;
        ::QueryPerformanceCounter(&qpc);
        m_qpcBaseline = qpc.QuadPart;
#endif

        ApplyProtectionLevel(m_config.protectionLevel);

        m_initialized.store(true, std::memory_order_release);
        SetStatus(ModuleStatus::Running);
    }
    // Lock released before operations that may re-acquire it

    // Register self integrity if enabled
    if (config.enableCodeIntegrity) {
        if (!RegisterSelfIntegrity()) {
            SS_LOG_WARN(L"AntiDebug", L"Failed to register self integrity");
        }
    }

    // Auto-hide threads if configured
    if (config.autoHideThreads) {
        size_t hiddenCount = HideAllThreads();
        SS_LOG_INFO(L"AntiDebug", L"Auto-hid %zu threads from debugger", hiddenCount);
    }

    // Start monitoring thread if needed (OUTSIDE lock to avoid deadlock)
    if (config.monitoringMode == MonitoringMode::Periodic ||
        config.monitoringMode == MonitoringMode::Continuous ||
        config.monitoringMode == MonitoringMode::Adaptive) {
        StartMonitoringThread();
    }

    SS_LOG_INFO(L"AntiDebug", L"Initialized successfully with protection level: %d",
                        static_cast<int>(config.protectionLevel));

    return true;
}

void AntiDebugImpl::Shutdown() noexcept {
    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SetStatus(ModuleStatus::Stopping);

        // Stop monitoring thread BEFORE acquiring m_mutex to avoid deadlock:
        // The monitoring thread acquires shared_lock(m_mutex) during scans,
        // so joining it while holding unique_lock would deadlock.
        StopMonitoringThread();

        {
            std::unique_lock lock(m_mutex);
            m_detectedHooks.clear();
            m_detectedDebuggers.clear();
            m_integrityRegions.clear();
            m_threadStates.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SetStatus(ModuleStatus::Stopped);

        SS_LOG_INFO(L"AntiDebug", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiDebug", L"Exception during shutdown: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"AntiDebug", L"Unknown exception during shutdown");
    }
}

bool AntiDebugImpl::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

ModuleStatus AntiDebugImpl::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

void AntiDebugImpl::Pause() noexcept {
    if (m_status.load(std::memory_order_acquire) == ModuleStatus::Running) {
        SetStatus(ModuleStatus::Paused);
        SS_LOG_INFO(L"AntiDebug", L"Monitoring paused");
    }
}

void AntiDebugImpl::Resume() noexcept {
    if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
        SetStatus(ModuleStatus::Running);
        m_monitoringCV.notify_one();
        SS_LOG_INFO(L"AntiDebug", L"Monitoring resumed");
    }
}

bool AntiDebugImpl::SetConfiguration(const AntiDebugConfiguration& config) {
    if (!ValidateConfiguration(config)) {
        SS_LOG_ERROR(L"AntiDebug", L"Invalid configuration update");
        return false;
    }

    MonitoringMode oldMode;
    MonitoringMode newMode;
    {
        std::unique_lock lock(m_mutex);
        oldMode = m_config.monitoringMode;
        m_config = config;
        newMode = m_config.monitoringMode;
        ApplyProtectionLevel(m_config.protectionLevel);
    }

    // Handle monitoring mode changes OUTSIDE m_mutex to avoid deadlock
    if (oldMode != newMode) {
        StopMonitoringThread();

        if (newMode == MonitoringMode::Periodic ||
            newMode == MonitoringMode::Continuous ||
            newMode == MonitoringMode::Adaptive) {
            StartMonitoringThread();
        }
    }

    SS_LOG_INFO(L"AntiDebug", L"Configuration updated");
    return true;
}

AntiDebugConfiguration AntiDebugImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

void AntiDebugImpl::SetProtectionLevel(AntiDebugProtectionLevel level) {
    std::unique_lock lock(m_mutex);
    m_config.protectionLevel = level;
    ApplyProtectionLevel(level);
}

AntiDebugProtectionLevel AntiDebugImpl::GetProtectionLevel() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_config.protectionLevel;
}

void AntiDebugImpl::SetMonitoringMode(MonitoringMode mode) {
    MonitoringMode oldMode;
    {
        std::unique_lock lock(m_mutex);
        oldMode = m_config.monitoringMode;
        m_config.monitoringMode = mode;
    }

    // Stop/start monitoring OUTSIDE m_mutex to avoid deadlock
    if (oldMode != mode) {
        StopMonitoringThread();

        if (mode == MonitoringMode::Periodic ||
            mode == MonitoringMode::Continuous ||
            mode == MonitoringMode::Adaptive) {
            StartMonitoringThread();
        }
    }
}

MonitoringMode AntiDebugImpl::GetMonitoringMode() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_config.monitoringMode;
}

void AntiDebugImpl::SetMonitoringInterval(uint32_t intervalMs) {
    std::unique_lock lock(m_mutex);
    m_config.monitoringIntervalMs = std::clamp(intervalMs,
        AntiDebugConstants::MIN_CHECK_INTERVAL_MS,
        AntiDebugConstants::MAX_MONITOR_INTERVAL_MS);
}

void AntiDebugImpl::EnableTechnique(DetectionTechnique technique) {
    std::unique_lock lock(m_mutex);
    m_config.enabledTechniques = m_config.enabledTechniques | technique;
}

void AntiDebugImpl::DisableTechnique(DetectionTechnique technique) {
    std::unique_lock lock(m_mutex);
    m_config.enabledTechniques = m_config.enabledTechniques & ~technique;
}

bool AntiDebugImpl::IsTechniqueEnabled(DetectionTechnique technique) const noexcept {
    std::shared_lock lock(m_mutex);
    return HasFlag(m_config.enabledTechniques, technique);
}

void AntiDebugImpl::SetResponseActions(ResponseAction actions) {
    std::unique_lock lock(m_mutex);
    m_config.responseActions = actions;
}

ResponseAction AntiDebugImpl::GetResponseActions() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_config.responseActions;
}

void AntiDebugImpl::AddToWhitelist(std::wstring_view processName) {
    std::unique_lock lock(m_mutex);

    // Check if already whitelisted
    for (const auto& name : m_config.whitelistedProcesses) {
        if (WideStringEqualsIgnoreCase(name, processName)) {
            return;
        }
    }

    m_config.whitelistedProcesses.emplace_back(processName);
    SS_LOG_INFO(L"AntiDebug", L"Added to whitelist: %hs", WideToNarrow(processName).c_str());
}

void AntiDebugImpl::RemoveFromWhitelist(std::wstring_view processName) {
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_config.whitelistedProcesses.begin(),
                             m_config.whitelistedProcesses.end(),
                             [&processName](const std::wstring& name) {
                                 return WideStringEqualsIgnoreCase(name, processName);
                             });

    if (it != m_config.whitelistedProcesses.end()) {
        m_config.whitelistedProcesses.erase(it, m_config.whitelistedProcesses.end());
        SS_LOG_INFO(L"AntiDebug", L"Removed from whitelist: %hs", WideToNarrow(processName).c_str());
    }
}

bool AntiDebugImpl::IsWhitelisted(std::wstring_view processName) const {
    std::shared_lock lock(m_mutex);

    for (const auto& name : m_config.whitelistedProcesses) {
        if (WideStringEqualsIgnoreCase(name, processName)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// DETECTION - FULL SCANS
// ============================================================================

DetectionResult AntiDebugImpl::PerformFullScan() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    auto startTime = Clock::now();
    std::vector<DetectionCheckResult> results;

    DetectionTechnique techniques;
    {
        std::shared_lock lock(m_mutex);
        techniques = m_config.enabledTechniques;
    }

    // PEB/TEB checks
    if (HasFlag(techniques, DetectionTechnique::All_PEB)) {
        results.push_back(CheckAllPEB());
    }

    // API checks
    if (HasFlag(techniques, DetectionTechnique::All_API)) {
        results.push_back(CheckAllAPI());
    }

    // Timing checks
    if (HasFlag(techniques, DetectionTechnique::All_Timing)) {
        results.push_back(CheckAllTiming());
    }

    // Hardware checks
    if (HasFlag(techniques, DetectionTechnique::All_Hardware)) {
        results.push_back(CheckAllHardware());
    }

    // Exception checks
    if (HasFlag(techniques, DetectionTechnique::All_Exception)) {
        results.push_back(CheckAllException());
    }

    // Memory checks
    if (HasFlag(techniques, DetectionTechnique::All_Memory)) {
        results.push_back(CheckAllMemory());
    }

    // Process checks
    if (HasFlag(techniques, DetectionTechnique::All_Process)) {
        results.push_back(CheckAllProcess());
    }

    auto result = AggregateResults(results);
    result.scanDuration = std::chrono::duration_cast<Milliseconds>(Clock::now() - startTime);

    // Store result
    {
        std::unique_lock lock(m_mutex);
        m_lastResult = result;
        m_debuggerDetected.store(result.debuggerDetected, std::memory_order_release);
        m_detectionScore.store(result.totalScore, std::memory_order_release);
    }

    // Update statistics (under exclusive lock — m_stats is plain uint64_t, not atomic)
    {
        std::unique_lock statsLock(m_mutex);
        m_stats.totalChecks += result.checksPerformed;
        m_stats.lastCheckTime = Clock::now();

        if (result.debuggerDetected) {
            m_stats.totalDetections += 1;
            m_stats.lastDetectionTime = Clock::now();
        }
    }

    if (result.debuggerDetected) {
        // Generate detection event
        DetectionEvent event;
        event.eventId = GenerateEventId();
        event.technique = result.triggeredTechniques;
        event.confidence = result.overallConfidence;
        event.score = result.totalScore;
        event.debuggerType = result.primaryDebuggerType;
        event.message = result.GetSummary();
        event.timestamp = Clock::now();
        event.threadId = GetCurrentThreadIdSafe();
        event.processId = GetCurrentProcessIdSafe();

        NotifyDetection(event);

        // Log the detection
        SS_LOG_WARN(L"AntiDebug", L"TAMPER DETECTED - Score: %u, Confidence: %d, Type: %d",
                           result.totalScore,
                           static_cast<int>(result.overallConfidence),
                           static_cast<int>(result.primaryDebuggerType));

        // Wire to communication subsystems
        ReportDetectionToAlertSystem(result);
    }

    // Always report scan telemetry (detection or clean)
    ReportScanTelemetry(result);

    return result;
}

DetectionResult AntiDebugImpl::PerformQuickScan() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    auto startTime = Clock::now();
    std::vector<DetectionCheckResult> results;

    // Quick checks only - PEB and basic API
    results.push_back(CheckPEB_BeingDebugged());
    results.push_back(CheckAPI_IsDebuggerPresent());
    results.push_back(CheckAPI_CheckRemoteDebuggerPresent());
    results.push_back(CheckHardware_DebugRegisters());

    auto result = AggregateResults(results);
    result.scanDuration = std::chrono::duration_cast<Milliseconds>(Clock::now() - startTime);

    // Store result
    {
        std::unique_lock lock(m_mutex);
        m_lastResult = result;
        m_debuggerDetected.store(result.debuggerDetected, std::memory_order_release);
        m_detectionScore.store(result.totalScore, std::memory_order_release);
    }

    if (result.debuggerDetected) {
        ReportDetectionToAlertSystem(result);
    }
    ReportScanTelemetry(result);

    return result;
}

DetectionResult AntiDebugImpl::PerformScan(DetectionTechnique techniques) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    auto startTime = Clock::now();
    std::vector<DetectionCheckResult> results;

    // Perform selected techniques
    if (HasFlag(techniques, DetectionTechnique::PEB_BeingDebugged)) {
        results.push_back(CheckPEB_BeingDebugged());
    }
    if (HasFlag(techniques, DetectionTechnique::PEB_NtGlobalFlag)) {
        results.push_back(CheckPEB_NtGlobalFlag());
    }
    if (HasFlag(techniques, DetectionTechnique::PEB_HeapFlags)) {
        results.push_back(CheckPEB_HeapFlags());
    }
    if (HasFlag(techniques, DetectionTechnique::API_IsDebuggerPresent)) {
        results.push_back(CheckAPI_IsDebuggerPresent());
    }
    if (HasFlag(techniques, DetectionTechnique::API_CheckRemoteDebugger)) {
        results.push_back(CheckAPI_CheckRemoteDebuggerPresent());
    }
    if (HasFlag(techniques, DetectionTechnique::API_NtQueryInfoProcess)) {
        results.push_back(CheckAPI_NtQueryInformationProcess_DebugPort());
    }
    if (HasFlag(techniques, DetectionTechnique::Timing_RDTSC)) {
        results.push_back(CheckTiming_RDTSC());
    }
    if (HasFlag(techniques, DetectionTechnique::Hardware_DebugRegisters)) {
        results.push_back(CheckHardware_DebugRegisters());
    }
    if (HasFlag(techniques, DetectionTechnique::Process_DebuggerSearch)) {
        results.push_back(CheckProcess_DebuggerProcesses());
    }

    auto result = AggregateResults(results);
    result.scanDuration = std::chrono::duration_cast<Milliseconds>(Clock::now() - startTime);

    return result;
}

bool AntiDebugImpl::IsDebuggerDetected() const noexcept {
    return m_debuggerDetected.load(std::memory_order_acquire);
}

DetectionResult AntiDebugImpl::GetLastResult() const {
    std::shared_lock lock(m_mutex);
    return m_lastResult;
}

uint32_t AntiDebugImpl::GetDetectionScore() const noexcept {
    return m_detectionScore.load(std::memory_order_acquire);
}

// ============================================================================
// DETECTION - PEB/TEB BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckPEB_BeingDebugged() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::PEB_BeingDebugged;
    result.timestamp = startTime;

#ifdef _WIN32
    try {
        PPEB pPeb = GetPEB();
        if (pPeb && pPeb->BeingDebugged) {
            result.detected = true;
            result.confidence = DetectionConfidence::High;
            result.score = AntiDebugConstants::WEIGHT_PEB_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "PEB.BeingDebugged flag is set - debugger attached";
            result.details["peb_address"] = std::to_string(reinterpret_cast<uintptr_t>(pPeb));

            SS_LOG_WARN(L"AntiDebug", L"PEB.BeingDebugged flag detected");
        } else {
            result.message = "PEB.BeingDebugged flag is clear";
        }
    } catch (const std::exception& e) {
        result.errorCode = 1;
        result.message = std::string("PEB check failed: ") + e.what();
        SS_LOG_ERROR(L"AntiDebug", L"PEB.BeingDebugged check failed: %hs", e.what());
    }
#else
    result.message = "PEB check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckPEB_NtGlobalFlag() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::PEB_NtGlobalFlag;
    result.timestamp = startTime;

#ifdef _WIN32
    PPEB pPeb = GetPEB();
    if (pPeb) {
        // NtGlobalFlag is at offset 0x68 (x86) or 0xBC (x64) in PEB.
        // PEB layout is documented but not guaranteed stable; raw access
        // is SEH-guarded because access violations are NOT C++ exceptions
        // under MSVC default /EHsc and would otherwise terminate the process.
#ifdef _WIN64
        constexpr size_t kNtGlobalFlagOffset = 0xBC;
#else
        constexpr size_t kNtGlobalFlagOffset = 0x68;
#endif
        ULONG ntGlobalFlag = 0;
        const void* addr = reinterpret_cast<const BYTE*>(pPeb) + kNtGlobalFlagOffset;
        if (!SehReadUlong(addr, ntGlobalFlag)) {
            result.errorCode = 2;
            result.message = "NtGlobalFlag read faulted (PEB layout unavailable)";
            SS_LOG_WARN(L"AntiDebug", L"NtGlobalFlag read faulted at 0x%IX",
                        reinterpret_cast<uintptr_t>(addr));
        } else if (ntGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED) {
            result.detected = true;
            result.confidence = DetectionConfidence::High;
            result.score = AntiDebugConstants::WEIGHT_PEB_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "NtGlobalFlag indicates debugger presence";
            result.details["ntglobalflag"] = std::to_string(ntGlobalFlag);

            SS_LOG_WARN(L"AntiDebug", L"NtGlobalFlag debug flags detected: 0x%lX", ntGlobalFlag);
        } else {
            result.message = "NtGlobalFlag is clean";
        }
    }
#else
    result.message = "NtGlobalFlag check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckPEB_HeapFlags() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::PEB_HeapFlags;
    result.timestamp = startTime;

#ifdef _WIN32
    PPEB pPeb = GetPEB();
    if (pPeb) {
        // PEB::ProcessHeap is not declared in winternl.h (opaque struct).
        // Access via documented offset: 0x30 on x64, 0x18 on x86.
        // All raw reads are SEH-guarded — PEB layout is not part of the
        // stable Win32 ABI and access violations are not catchable as
        // C++ exceptions under /EHsc.
#ifdef _WIN64
        constexpr size_t kProcessHeapOffset = 0x30;
        constexpr size_t kHeapFlagsOffset   = 0x70;
        constexpr size_t kHeapForceOffset   = 0x74;
#else
        constexpr size_t kProcessHeapOffset = 0x18;
        constexpr size_t kHeapFlagsOffset   = 0x40;
        constexpr size_t kHeapForceOffset   = 0x44;
#endif
        void* processHeap = nullptr;
        const void* heapPtrAddr = reinterpret_cast<const BYTE*>(pPeb) + kProcessHeapOffset;
        if (!SehReadPointer(heapPtrAddr, processHeap)) {
            result.errorCode = 2;
            result.message = "ProcessHeap pointer read faulted";
        } else if (processHeap) {
            ULONG heapFlags = 0;
            ULONG forceFlags = 0;
            const void* flagsAddr = reinterpret_cast<const BYTE*>(processHeap) + kHeapFlagsOffset;
            const void* forceAddr = reinterpret_cast<const BYTE*>(processHeap) + kHeapForceOffset;
            if (!SehReadUlong(flagsAddr, heapFlags) || !SehReadUlong(forceAddr, forceFlags)) {
                result.errorCode = 3;
                result.message = "Heap flag read faulted";
                SS_LOG_WARN(L"AntiDebug", L"Heap flag read faulted");
            } else {
                // Normal heap has Flags = 2 and ForceFlags = 0
                // Debugged heap has additional flags set
                constexpr ULONG kHeapGrowableFlag = 0x00000002;

                if ((heapFlags & ~kHeapGrowableFlag) != 0 || forceFlags != 0) {
                    result.detected = true;
                    result.confidence = DetectionConfidence::Medium;
                    result.score = AntiDebugConstants::WEIGHT_PEB_DETECTION / 2;
                    result.debuggerType = DebuggerType::UserMode;
                    result.message = "Heap flags indicate debugger presence";
                    result.details["heap_flags"] = std::to_string(heapFlags);
                    result.details["force_flags"] = std::to_string(forceFlags);

                    SS_LOG_WARN(L"AntiDebug", L"Heap debug flags detected: Flags=0x%lX, ForceFlags=0x%lX",
                                       heapFlags, forceFlags);
                } else {
                    result.message = "Heap flags are clean";
                }
            }
        }
    }
#else
    result.message = "Heap flags check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckPEB_ProcessHeap() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::PEB_ProcessHeap;
    result.timestamp = startTime;

#ifdef _WIN32
    try {
        HANDLE hHeap = ::GetProcessHeap();
        if (hHeap) {
            // Check if heap was created with debug flags
            ULONG heapInfo = 0;
            SIZE_T returnLength = 0;

            if (::HeapQueryInformation(hHeap, HeapCompatibilityInformation,
                                       &heapInfo, sizeof(heapInfo), &returnLength)) {
                result.details["heap_compatibility"] = std::to_string(heapInfo);
            }

            result.message = "ProcessHeap check complete";
        }
    } catch (const std::exception& e) {
        result.errorCode = 1;
        result.message = std::string("ProcessHeap check failed: ") + e.what();
    }
#else
    result.message = "ProcessHeap check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAllPEB() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckPEB_BeingDebugged());
    results.push_back(CheckPEB_NtGlobalFlag());
    results.push_back(CheckPEB_HeapFlags());
    results.push_back(CheckPEB_ProcessHeap());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_PEB;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
            if (r.debuggerType != DebuggerType::Unknown) {
                combined.debuggerType = r.debuggerType;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "PEB-based debugger detection triggered";
    } else {
        combined.message = "All PEB checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - API BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckAPI_IsDebuggerPresent() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_IsDebuggerPresent;
    result.timestamp = startTime;

#ifdef _WIN32
    if (::IsDebuggerPresent()) {
        result.detected = true;
        result.confidence = DetectionConfidence::Critical;
        result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "IsDebuggerPresent() returned TRUE - debugger attached";

        SS_LOG_WARN(L"AntiDebug", L"IsDebuggerPresent() detected debugger");
    } else {
        result.message = "IsDebuggerPresent() returned FALSE";
    }
#else
    result.message = "IsDebuggerPresent check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_CheckRemoteDebuggerPresent() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_CheckRemoteDebugger;
    result.timestamp = startTime;

#ifdef _WIN32
    BOOL debuggerPresent = FALSE;
    if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &debuggerPresent)) {
        if (debuggerPresent) {
            result.detected = true;
            result.confidence = DetectionConfidence::Critical;
            result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
            result.debuggerType = DebuggerType::Remote;
            result.message = "CheckRemoteDebuggerPresent() detected remote debugger";

            SS_LOG_WARN(L"AntiDebug", L"Remote debugger detected via CheckRemoteDebuggerPresent()");
        } else {
            result.message = "No remote debugger detected";
        }
    } else {
        result.errorCode = ::GetLastError();
        result.message = "CheckRemoteDebuggerPresent() failed";
    }
#else
    result.message = "CheckRemoteDebuggerPresent check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_NtQueryInformationProcess_DebugPort() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_NtQueryInfoProcess;
    result.timestamp = startTime;

#ifdef _WIN32
    if (m_pNtQueryInformationProcess) {
        DWORD_PTR debugPort = 0;
        NTSTATUS status = m_pNtQueryInformationProcess(
            ::GetCurrentProcess(),
            SsProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            nullptr
        );

        if (NT_SUCCESS(status) && debugPort != 0) {
            result.detected = true;
            result.confidence = DetectionConfidence::Critical;
            result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "ProcessDebugPort is non-zero - debugger attached";
            result.details["debug_port"] = std::to_string(debugPort);

            SS_LOG_WARN(L"AntiDebug", L"ProcessDebugPort detected: 0x%IX", debugPort);
        } else {
            result.message = "ProcessDebugPort is zero";
        }
    } else {
        result.errorCode = 1;
        result.message = "NtQueryInformationProcess not available";
    }
#else
    result.message = "NtQueryInformationProcess check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_NtQueryInformationProcess_DebugFlags() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_NtQueryInfoProcess;
    result.timestamp = startTime;

#ifdef _WIN32
    if (m_pNtQueryInformationProcess) {
        DWORD debugFlags = 0;
        NTSTATUS status = m_pNtQueryInformationProcess(
            ::GetCurrentProcess(),
            SsProcessDebugFlags,
            &debugFlags,
            sizeof(debugFlags),
            nullptr
        );

        // If debugFlags is 0, process is being debugged
        if (NT_SUCCESS(status) && debugFlags == 0) {
            result.detected = true;
            result.confidence = DetectionConfidence::High;
            result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "ProcessDebugFlags is zero - debugger attached";

            SS_LOG_WARN(L"AntiDebug", L"ProcessDebugFlags indicates debugger");
        } else {
            result.message = "ProcessDebugFlags indicates no debugger";
        }
    } else {
        result.errorCode = 1;
        result.message = "NtQueryInformationProcess not available";
    }
#else
    result.message = "NtQueryInformationProcess check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_NtQueryInformationProcess_DebugObjectHandle() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_NtQueryInfoProcess;
    result.timestamp = startTime;

#ifdef _WIN32
    if (m_pNtQueryInformationProcess) {
        HANDLE debugObject = nullptr;
        NTSTATUS status = m_pNtQueryInformationProcess(
            ::GetCurrentProcess(),
            SsProcessDebugObjectHandle,
            &debugObject,
            sizeof(debugObject),
            nullptr
        );

        // STATUS_SUCCESS means there's a debug object (debugger attached)
        // STATUS_PORT_NOT_SET means no debugger
        if (NT_SUCCESS(status)) {
            result.detected = true;
            result.confidence = DetectionConfidence::Critical;
            result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "Debug object handle exists - debugger attached";
            result.details["debug_object"] = std::to_string(reinterpret_cast<uintptr_t>(debugObject));

            SS_LOG_WARN(L"AntiDebug", L"Debug object handle detected");
        } else {
            result.message = "No debug object handle";
        }
    } else {
        result.errorCode = 1;
        result.message = "NtQueryInformationProcess not available";
    }
#else
    result.message = "NtQueryInformationProcess check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_OutputDebugString() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_OutputDebugString;
    result.timestamp = startTime;

#ifdef _WIN32
    // Set a known error code
    ::SetLastError(0x12345678);

    // If debugger is attached, OutputDebugString will clear the error code
    ::OutputDebugStringA("ShadowStrike Anti-Debug Check");

    DWORD lastError = ::GetLastError();
    if (lastError == 0) {
        result.detected = true;
        result.confidence = DetectionConfidence::Medium;
        result.score = AntiDebugConstants::WEIGHT_API_DETECTION / 2;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "OutputDebugString behavior indicates debugger";

        SS_LOG_WARN(L"AntiDebug", L"OutputDebugString debugger behavior detected");
    } else {
        result.message = "OutputDebugString behavior normal";
    }

    // Restore error code
    ::SetLastError(0);
#else
    result.message = "OutputDebugString check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAPI_CloseHandle() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::API_CloseHandle;
    result.timestamp = startTime;

#ifdef _WIN32
    if (SehCloseHandleCheck()) {
        result.detected = true;
        result.confidence = DetectionConfidence::High;
        result.score = AntiDebugConstants::WEIGHT_API_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "CloseHandle threw exception - debugger attached";

        SS_LOG_WARN(L"AntiDebug", L"CloseHandle exception detected - debugger present");
    } else {
        result.message = "CloseHandle test passed - no exception";
    }
#else
    result.message = "CloseHandle check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAllAPI() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckAPI_IsDebuggerPresent());
    results.push_back(CheckAPI_CheckRemoteDebuggerPresent());
    results.push_back(CheckAPI_NtQueryInformationProcess_DebugPort());
    results.push_back(CheckAPI_NtQueryInformationProcess_DebugFlags());
    results.push_back(CheckAPI_NtQueryInformationProcess_DebugObjectHandle());
    results.push_back(CheckAPI_OutputDebugString());
    results.push_back(CheckAPI_CloseHandle());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_API;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
            if (r.debuggerType != DebuggerType::Unknown) {
                combined.debuggerType = r.debuggerType;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "API-based debugger detection triggered";
    } else {
        combined.message = "All API checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - TIMING BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckTiming_RDTSC() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Timing_RDTSC;
    result.timestamp = startTime;

#ifdef _WIN32
    // Collect timing samples
    std::array<uint64_t, AntiDebugConstants::TIMING_SAMPLE_COUNT> deltas{};

    for (size_t i = 0; i < AntiDebugConstants::TIMING_SAMPLE_COUNT; ++i) {
        SerializeExecution();
        uint64_t start = ReadTSC();

        // Minimal operations between readings
        volatile int dummy = 0;
        dummy++;

        SerializeExecution();
        uint64_t end = ReadTSC();

        deltas[i] = end - start;
    }

    // Calculate average and standard deviation
    uint64_t sum = 0;
    for (auto d : deltas) {
        sum += d;
    }
    uint64_t avg = sum / deltas.size();

    double variance = 0.0;
    for (auto d : deltas) {
        double diff = static_cast<double>(d) - static_cast<double>(avg);
        variance += diff * diff;
    }
    variance /= static_cast<double>(deltas.size());
    double stdDev = std::sqrt(variance);

    result.details["avg_cycles"] = std::to_string(avg);
    result.details["std_dev"] = std::to_string(static_cast<uint64_t>(stdDev));

    // Check if timing is anomalous (single-stepping detection)
    if (avg > AntiDebugConstants::RDTSC_SINGLE_INSTRUCTION_THRESHOLD) {
        result.detected = true;
        result.confidence = DetectionConfidence::Medium;
        result.score = AntiDebugConstants::WEIGHT_TIMING_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "RDTSC timing anomaly detected - possible single-stepping";

        SS_LOG_WARN(L"AntiDebug", L"RDTSC timing anomaly: avg=%llu cycles (threshold=%llu)",
                           avg, AntiDebugConstants::RDTSC_SINGLE_INSTRUCTION_THRESHOLD);
    } else {
        result.message = "RDTSC timing within normal range";
    }
#else
    result.message = "RDTSC timing check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckTiming_QPC() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Timing_QPC;
    result.timestamp = startTime;

#ifdef _WIN32
    LARGE_INTEGER freq, start, end;
    ::QueryPerformanceFrequency(&freq);

    // Collect timing samples
    std::array<int64_t, AntiDebugConstants::TIMING_SAMPLE_COUNT> deltas{};

    for (size_t i = 0; i < AntiDebugConstants::TIMING_SAMPLE_COUNT; ++i) {
        ::QueryPerformanceCounter(&start);

        // Minimal operations
        volatile int dummy = 0;
        for (int j = 0; j < 100; ++j) dummy++;

        ::QueryPerformanceCounter(&end);

        deltas[i] = end.QuadPart - start.QuadPart;
    }

    // Calculate average
    int64_t sum = 0;
    for (auto d : deltas) {
        sum += d;
    }
    int64_t avg = sum / static_cast<int64_t>(deltas.size());

    // Convert to nanoseconds
    int64_t avgNs = (avg * 1000000000LL) / freq.QuadPart;

    result.details["avg_ns"] = std::to_string(avgNs);
    result.details["avg_ticks"] = std::to_string(avg);

    // Check for anomalous timing (much slower than expected)
    if (avgNs > static_cast<int64_t>(AntiDebugConstants::TIMING_ANOMALY_THRESHOLD_NS)) {
        result.detected = true;
        result.confidence = DetectionConfidence::Low;
        result.score = AntiDebugConstants::WEIGHT_TIMING_DETECTION / 2;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "QPC timing anomaly detected";

        SS_LOG_WARN(L"AntiDebug", L"QPC timing anomaly: avg=%lld ns", avgNs);
    } else {
        result.message = "QPC timing within normal range";
    }
#else
    result.message = "QPC timing check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckTiming_GetTickCount() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Timing_GetTickCount;
    result.timestamp = startTime;

#ifdef _WIN32
    ULONGLONG start = ::GetTickCount64();

    // Perform some operations
    volatile int dummy = 0;
    for (int i = 0; i < 1000; ++i) {
        dummy += i;
    }

    ULONGLONG end = ::GetTickCount64();
    ULONGLONG elapsed = end - start;

    result.details["elapsed_ms"] = std::to_string(elapsed);

    // GetTickCount has millisecond resolution - if we see large deltas
    // for simple operations, something is slowing us down
    if (elapsed > 100) {
        result.detected = true;
        result.confidence = DetectionConfidence::Low;
        result.score = AntiDebugConstants::WEIGHT_TIMING_DETECTION / 4;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "GetTickCount timing anomaly detected";

        SS_LOG_WARN(L"AntiDebug", L"GetTickCount anomaly: %llu ms for simple loop", elapsed);
    } else {
        result.message = "GetTickCount timing within normal range";
    }
#else
    result.message = "GetTickCount timing check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckTiming_InstructionExecution() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Timing_Instruction;
    result.timestamp = startTime;

#ifdef _WIN32
    // Time a block of known instructions
    SerializeExecution();
    uint64_t start = ReadTSC();

    // Known instruction sequence
    volatile int counter = 0;
    for (int i = 0; i < 1000; ++i) {
        counter++;
    }

    SerializeExecution();
    uint64_t end = ReadTSC();

    uint64_t elapsed = end - start;
    result.details["instruction_cycles"] = std::to_string(elapsed);

    // Expected ~1000-5000 cycles for this loop on modern CPUs
    // If significantly higher, may indicate single-stepping
    if (elapsed > AntiDebugConstants::RDTSC_BLOCK_THRESHOLD * 10) {
        result.detected = true;
        result.confidence = DetectionConfidence::Medium;
        result.score = AntiDebugConstants::WEIGHT_TIMING_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "Instruction timing anomaly - possible single-stepping";

        SS_LOG_WARN(L"AntiDebug", L"Instruction block timing anomaly: %llu cycles", elapsed);
    } else {
        result.message = "Instruction timing within normal range";
    }
#else
    result.message = "Instruction timing check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

TimingAnalysis AntiDebugImpl::PerformTimingAnalysis() {
    TimingAnalysis analysis;
    analysis.analysisTime = Clock::now();

#ifdef _WIN32
    // Collect RDTSC samples
    for (size_t i = 0; i < AntiDebugConstants::TIMING_SAMPLE_COUNT; ++i) {
        SerializeExecution();
        uint64_t start = ReadTSC();
        volatile int dummy = 0;
        dummy++;
        SerializeExecution();
        uint64_t end = ReadTSC();
        analysis.rdtscSamples.push_back(end - start);
    }

    // Collect QPC samples
    LARGE_INTEGER freq, qpcStart, qpcEnd;
    ::QueryPerformanceFrequency(&freq);

    for (size_t i = 0; i < AntiDebugConstants::TIMING_SAMPLE_COUNT; ++i) {
        ::QueryPerformanceCounter(&qpcStart);
        volatile int dummy = 0;
        dummy++;
        ::QueryPerformanceCounter(&qpcEnd);
        analysis.qpcSamples.push_back(qpcEnd.QuadPart - qpcStart.QuadPart);
    }

    // Collect GetTickCount64 samples
    for (size_t i = 0; i < AntiDebugConstants::TIMING_SAMPLE_COUNT; ++i) {
        ULONGLONG start = ::GetTickCount64();
        ::Sleep(1);
        ULONGLONG end = ::GetTickCount64();
        analysis.tickCountSamples.push_back(end - start);
    }

    // Calculate averages
    if (!analysis.rdtscSamples.empty()) {
        uint64_t sum = 0;
        for (auto v : analysis.rdtscSamples) sum += v;
        analysis.avgRdtscDelta = sum / analysis.rdtscSamples.size();

        // Calculate standard deviation
        double variance = 0.0;
        for (auto v : analysis.rdtscSamples) {
            double diff = static_cast<double>(v) - static_cast<double>(analysis.avgRdtscDelta);
            variance += diff * diff;
        }
        variance /= static_cast<double>(analysis.rdtscSamples.size());
        analysis.rdtscStdDev = std::sqrt(variance);
    }

    if (!analysis.qpcSamples.empty()) {
        int64_t sum = 0;
        for (auto v : analysis.qpcSamples) sum += v;
        analysis.avgQpcDelta = sum / static_cast<int64_t>(analysis.qpcSamples.size());
    }

    // Calculate anomaly score
    uint32_t score = 0;
    if (analysis.avgRdtscDelta > AntiDebugConstants::RDTSC_SINGLE_INSTRUCTION_THRESHOLD) {
        score += 30;
    }
    if (analysis.rdtscStdDev > static_cast<double>(analysis.avgRdtscDelta)) {
        score += 20;
    }

    analysis.anomalyScore = std::min(score, 100u);
    analysis.anomalyDetected = score >= 30;
#endif

    return analysis;
}

DetectionCheckResult AntiDebugImpl::CheckAllTiming() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckTiming_RDTSC());
    results.push_back(CheckTiming_QPC());
    results.push_back(CheckTiming_GetTickCount());
    results.push_back(CheckTiming_InstructionExecution());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_Timing;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "Timing-based debugger detection triggered";
    } else {
        combined.message = "All timing checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - HARDWARE BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckHardware_DebugRegisters() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Hardware_DebugRegisters;
    result.timestamp = startTime;

#ifdef _WIN32
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
        bool hasBreakpoints = false;

        if (ctx.Dr0 != 0) {
            result.details["dr0"] = std::to_string(ctx.Dr0);
            hasBreakpoints = true;
        }
        if (ctx.Dr1 != 0) {
            result.details["dr1"] = std::to_string(ctx.Dr1);
            hasBreakpoints = true;
        }
        if (ctx.Dr2 != 0) {
            result.details["dr2"] = std::to_string(ctx.Dr2);
            hasBreakpoints = true;
        }
        if (ctx.Dr3 != 0) {
            result.details["dr3"] = std::to_string(ctx.Dr3);
            hasBreakpoints = true;
        }

        // Check Dr7 for enabled breakpoints
        if ((ctx.Dr7 & 0xFF) != 0) {
            result.details["dr7"] = std::to_string(ctx.Dr7);
            hasBreakpoints = true;
        }

        if (hasBreakpoints) {
            result.detected = true;
            result.confidence = DetectionConfidence::Critical;
            result.score = AntiDebugConstants::WEIGHT_HARDWARE_BP_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "Hardware debug registers contain breakpoints";

            SS_LOG_WARN(L"AntiDebug", L"Hardware breakpoints detected: DR0=0x%IX, DR1=0x%IX, DR2=0x%IX, DR3=0x%IX, DR7=0x%IX",
                               ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr7);
        } else {
            result.message = "No hardware breakpoints detected";
        }
    } else {
        result.errorCode = ::GetLastError();
        result.message = "Failed to get thread context";
    }
#else
    result.message = "Debug register check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DebugRegisterState AntiDebugImpl::GetDebugRegisterState() {
    DebugRegisterState state;

#ifdef _WIN32
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
        state.dr0 = ctx.Dr0;
        state.dr1 = ctx.Dr1;
        state.dr2 = ctx.Dr2;
        state.dr3 = ctx.Dr3;
        state.dr6 = ctx.Dr6;
        state.dr7 = ctx.Dr7;
    }
#endif

    return state;
}

DetectionCheckResult AntiDebugImpl::CheckHardware_BreakpointsViaContext() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Hardware_Context;
    result.timestamp = startTime;

#ifdef _WIN32
    // Enumerate all threads and check their debug registers
    std::vector<uint32_t> threadIds = EnumerateThreadIds();
    uint32_t currentThreadId = ::GetCurrentThreadId();

    for (uint32_t tid : threadIds) {
        if (tid == currentThreadId) continue;

        HANDLE hThread = ::OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (hThread) {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (::GetThreadContext(hThread, &ctx)) {
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 ||
                    (ctx.Dr7 & 0xFF) != 0) {
                    result.detected = true;
                    result.confidence = DetectionConfidence::High;
                    result.score = AntiDebugConstants::WEIGHT_HARDWARE_BP_DETECTION;
                    result.debuggerType = DebuggerType::UserMode;
                    result.message = "Hardware breakpoints found on thread " + std::to_string(tid);
                    result.details["thread_id"] = std::to_string(tid);

                    SS_LOG_WARN(L"AntiDebug", L"Hardware breakpoints on thread %u", tid);
                }
            }

            ::CloseHandle(hThread);
        }

        if (result.detected) break;
    }

    if (!result.detected) {
        result.message = "No hardware breakpoints found on other threads";
    }
#else
    result.message = "Context-based breakpoint check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAllHardware() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckHardware_DebugRegisters());
    results.push_back(CheckHardware_BreakpointsViaContext());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_Hardware;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "Hardware-based debugger detection triggered";
    } else {
        combined.message = "All hardware checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - EXCEPTION BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckException_INT3() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Exception_INT3;
    result.timestamp = startTime;

#ifdef _WIN32
    bool exceptionCaught = SehInt3ExceptionCheck();

    if (!exceptionCaught) {
        result.detected = true;
        result.confidence = DetectionConfidence::High;
        result.score = AntiDebugConstants::WEIGHT_EXCEPTION_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "INT3 exception was swallowed - debugger attached";

        SS_LOG_WARN(L"AntiDebug", L"INT3 exception not caught - debugger handling it");
    } else {
        result.message = "INT3 exception caught normally";
    }
#else
    result.message = "INT3 check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckException_INT2D() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Exception_INT2D;
    result.timestamp = startTime;

    // INT 2D uses inline asm - only available on x86 (MSVC has no __asm on x64)
#if defined(_WIN32) && !defined(_WIN64)
    bool exceptionCaught = false;

    __try {
        __asm {
            int 0x2D
            nop
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionCaught = true;
    }

    if (!exceptionCaught) {
        result.detected = true;
        result.confidence = DetectionConfidence::Medium;
        result.score = AntiDebugConstants::WEIGHT_EXCEPTION_DETECTION;
        result.debuggerType = DebuggerType::KernelMode;
        result.message = "INT 2D exception was swallowed - kernel debugger may be present";

        SS_LOG_WARN(L"AntiDebug", L"INT 2D exception not caught");
    } else {
        result.message = "INT 2D exception caught normally";
    }
#else
    result.message = "INT 2D check not supported on x64 or this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckException_SingleStep() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Exception_SingleStep;
    result.timestamp = startTime;

    // Trap flag asm only available on x86
#if defined(_WIN32) && !defined(_WIN64)
    bool exceptionCaught = false;

    __try {
        // Trap flag uses inline asm - only available on x86
        __asm {
            pushfd
            or dword ptr [esp], 0x100
            popfd
            nop
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionCaught = true;
    }

    if (!exceptionCaught) {
        result.detected = true;
        result.confidence = DetectionConfidence::High;
        result.score = AntiDebugConstants::WEIGHT_EXCEPTION_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "Single-step exception was swallowed - debugger attached";

        SS_LOG_WARN(L"AntiDebug", L"Single-step exception not caught");
    } else {
        result.message = "Single-step exception caught normally";
    }
#else
    result.message = "Single-step check not available on x64 or this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckException_GuardPage() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Exception_GuardPage;
    result.timestamp = startTime;

#ifdef _WIN32
    // Allocate a page of memory
    LPVOID pMem = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD);

    if (pMem) {
        bool exceptionCaught = SehGuardPageCheck(pMem);

        if (!exceptionCaught) {
            result.detected = true;
            result.confidence = DetectionConfidence::Medium;
            result.score = AntiDebugConstants::WEIGHT_EXCEPTION_DETECTION / 2;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "Guard page exception was swallowed - possible debugger";

            SS_LOG_WARN(L"AntiDebug", L"Guard page exception not caught");
        } else {
            result.message = "Guard page exception caught normally";
        }

        ::VirtualFree(pMem, 0, MEM_RELEASE);
    } else {
        result.errorCode = ::GetLastError();
        result.message = "Failed to allocate guard page";
    }
#else
    result.message = "Guard page check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckException_VEH() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Exception_VEH;
    result.timestamp = startTime;

#ifdef _WIN32
    // Detect suspicious VEH by installing our own VEH and checking if it fires.
    // Also check for known VEH hooking by testing a known exception path.
    // A debugger may install VEH handlers to intercept exceptions before our SEH.
    static std::atomic<bool> s_vehFired{false};
    s_vehFired.store(false, std::memory_order_release);

    auto vehHandler = [](PEXCEPTION_POINTERS) -> LONG {
        s_vehFired.store(true, std::memory_order_release);
        return EXCEPTION_CONTINUE_SEARCH;
    };

    PVOID handle = ::AddVectoredExceptionHandler(0 /* last */, vehHandler);
    if (handle) {
        // Trigger exception via SEH helper and verify our VEH sees it
        SehRaiseAccessViolation();

        // If our VEH at the end of the chain didn't fire, something intercepted it
        bool fired = s_vehFired.load(std::memory_order_acquire);
        ::RemoveVectoredExceptionHandler(handle);

        if (!fired) {
            result.detected = true;
            result.confidence = DetectionConfidence::Low;
            result.score = AntiDebugConstants::WEIGHT_EXCEPTION_DETECTION / 2;
            result.debuggerType = DebuggerType::Instrumentation;
            result.message = "VEH handler chain may be manipulated";
        } else {
            result.message = "VEH analysis: no anomalies detected";
        }
    } else {
        result.message = "VEH analysis: could not register handler";
    }
#else
    result.message = "VEH analysis not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckAllException() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckException_INT3());
    // Skip INT 2D on x64 - different behavior
#ifndef _WIN64
    results.push_back(CheckException_INT2D());
    results.push_back(CheckException_SingleStep());
#endif
    results.push_back(CheckException_GuardPage());
    results.push_back(CheckException_VEH());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_Exception;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "Exception-based debugger detection triggered";
    } else {
        combined.message = "All exception checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - MEMORY BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckMemory_SoftwareBreakpoints() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Memory_Breakpoints;
    result.timestamp = startTime;

#ifdef _WIN32
    // Scan our own code section for 0xCC (INT 3) bytes
    HMODULE hModule = ::GetModuleHandleW(nullptr);
    if (hModule) {
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            result.errorCode = 3;
            result.message = "Invalid DOS signature";
            result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
            return result;
        }

        PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            result.errorCode = 4;
            result.message = "Invalid NT signature";
            result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
            return result;
        }

        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSection) {
            // Check if this is a code section
            if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                PBYTE pStart = reinterpret_cast<PBYTE>(hModule) + pSection->VirtualAddress;
                SIZE_T size = pSection->Misc.VirtualSize;

                // Limit scan size
                if (size > AntiDebugConstants::MAX_CODE_SECTION_SIZE) {
                    size = AntiDebugConstants::MAX_CODE_SECTION_SIZE;
                }

                // SEH-guarded scan — a partially mapped section tail or a
                // section header pointing past mapped memory must not crash
                // the process. The parametric overload uses the same helper.
                size_t breakpointCount = 0;
                if (!SehScanBreakpoints(pStart, size, breakpointCount)) {
                    SS_LOG_WARN(L"AntiDebug", L"Code section scan faulted (section=%.8hs)",
                                reinterpret_cast<const char*>(pSection->Name));
                    continue;
                }

                if (breakpointCount >= AntiDebugConstants::MAX_BREAKPOINTS_THRESHOLD) {
                    result.detected = true;
                    result.confidence = DetectionConfidence::High;
                    result.score = AntiDebugConstants::WEIGHT_SOFTWARE_BP_DETECTION;
                    result.debuggerType = DebuggerType::UserMode;
                    result.message = "Software breakpoints detected in code section";
                    result.details["breakpoint_count"] = std::to_string(breakpointCount);
                    result.details["section"] = std::string(reinterpret_cast<const char*>(pSection->Name), strnlen(reinterpret_cast<const char*>(pSection->Name), 8));

                    SS_LOG_WARN(L"AntiDebug", L"Software breakpoints detected: %zu in code section", breakpointCount);
                    break;
                }
            }
        }

        if (!result.detected) {
            result.message = "No suspicious software breakpoints detected";
        }
    }
#else
    result.message = "Software breakpoint scan not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckMemory_SoftwareBreakpoints(uintptr_t address, size_t size) {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Memory_Breakpoints;
    result.timestamp = startTime;

#ifdef _WIN32
    if (address != 0 && size > 0 && size <= AntiDebugConstants::MAX_CODE_SECTION_SIZE) {
        const PBYTE pStart = reinterpret_cast<PBYTE>(address);
        size_t breakpointCount = 0;

        if (!SehScanBreakpoints(pStart, size, breakpointCount)) {
            result.errorCode = 1;
            result.message = "Access violation while scanning memory";
            result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
            return result;
        }

        if (breakpointCount >= AntiDebugConstants::MAX_BREAKPOINTS_THRESHOLD) {
            result.detected = true;
            result.confidence = DetectionConfidence::High;
            result.score = AntiDebugConstants::WEIGHT_SOFTWARE_BP_DETECTION;
            result.debuggerType = DebuggerType::UserMode;
            result.message = "Software breakpoints detected in specified region";
            result.details["breakpoint_count"] = std::to_string(breakpointCount);
            result.details["address"] = std::to_string(address);
            result.details["size"] = std::to_string(size);
        } else {
            result.message = "No suspicious breakpoints in specified region";
        }
    } else {
        result.errorCode = 2;
        result.message = "Invalid address or size specified";
    }
#else
    result.message = "Software breakpoint scan not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckMemory_CodeIntegrity() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Memory_CodeIntegrity;
    result.timestamp = startTime;

    std::unique_lock lock(m_mutex);

    bool anyViolation = false;
    for (auto& [id, region] : m_integrityRegions) {
        if (region.startAddress != 0 && region.size > 0) {
            // Calculate current CRC
            const uint8_t* pData = reinterpret_cast<const uint8_t*>(region.startAddress);
            std::span<const uint8_t> data(pData, region.size);

            uint32_t currentCrc = CalculateCRC32(data);
            region.currentCrc32 = currentCrc;
            region.lastVerified = Clock::now();

            if (currentCrc != region.expectedCrc32) {
                region.status = AntiDebugIntegrityStatus::Modified;
                region.failureCount++;
                anyViolation = true;

                result.details[id + "_status"] = "modified";

                SS_LOG_WARN(L"AntiDebug", L"Code integrity violation in region '%hs': expected CRC 0x%08X, got 0x%08X",
                                   id.c_str(), region.expectedCrc32, currentCrc);

                m_stats.integrityViolations += 1;
            } else {
                region.status = AntiDebugIntegrityStatus::Valid;
            }
        }
    }

    if (anyViolation) {
        result.detected = true;
        result.confidence = DetectionConfidence::Critical;
        result.score = AntiDebugConstants::WEIGHT_HOOK_DETECTION;
        result.debuggerType = DebuggerType::Unknown;
        result.message = "Code integrity violations detected";
    } else {
        result.message = "All integrity checks passed";
    }

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckMemory_IATHooks() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Memory_IATHooks;
    result.timestamp = startTime;

#ifdef _WIN32
    HMODULE hModule = ::GetModuleHandleW(nullptr);
    if (!hModule) {
        result.message = "Failed to get module handle";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        result.message = "Invalid DOS signature";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        result.message = "Invalid NT signature";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }

    // Get import directory
    DWORD importRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRva == 0) {
        result.message = "No import directory";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<PBYTE>(hModule) + importRva);

    // Query our own module size so we can bound the import-descriptor and
    // thunk walks. A torn-down or malformed import directory must not cause
    // us to walk past the module image and into unrelated memory.
    MODULEINFO selfInfo = {};
    if (!::GetModuleInformation(::GetCurrentProcess(), hModule, &selfInfo, sizeof(selfInfo))) {
        result.errorCode = 5;
        result.message = "GetModuleInformation failed for host module";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }
    const uintptr_t imgStart = reinterpret_cast<uintptr_t>(hModule);
    const uintptr_t imgEnd   = imgStart + selfInfo.SizeOfImage;

    auto withinImage = [imgStart, imgEnd](const void* p, size_t span) noexcept {
        const uintptr_t a = reinterpret_cast<uintptr_t>(p);
        return a >= imgStart && (a + span) <= imgEnd && (a + span) > a;
    };

    // Hard caps as a belt-and-braces guard against malformed tables that
    // somehow pass the in-range checks.
    constexpr size_t kMaxImportDescriptors = 4096;
    constexpr size_t kMaxThunksPerModule   = 16384;

    size_t hookCount = 0;
    std::vector<HookInfo> foundHooks;

    size_t descCount = 0;
    while (withinImage(pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) &&
           pImportDesc->Name != 0 && descCount++ < kMaxImportDescriptors) {
        if (pImportDesc->Name >= selfInfo.SizeOfImage) {
            break;
        }
        LPCSTR dllName = reinterpret_cast<LPCSTR>(
            reinterpret_cast<PBYTE>(hModule) + pImportDesc->Name);

        if (pImportDesc->FirstThunk == 0 ||
            pImportDesc->FirstThunk >= selfInfo.SizeOfImage) {
            ++pImportDesc;
            continue;
        }

        PIMAGE_THUNK_DATA pThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<PBYTE>(hModule) + pImportDesc->FirstThunk);

        HMODULE hDll = ::GetModuleHandleA(dllName);
        if (hDll) {
            size_t thunkCount = 0;
            while (withinImage(pThunk, sizeof(IMAGE_THUNK_DATA)) &&
                   pThunk->u1.Function != 0 && thunkCount++ < kMaxThunksPerModule) {
                FARPROC pFunc = reinterpret_cast<FARPROC>(pThunk->u1.Function);

                MODULEINFO modInfo = {};
                if (::GetModuleInformation(::GetCurrentProcess(), hDll, &modInfo, sizeof(modInfo))) {
                    uintptr_t dllStart = reinterpret_cast<uintptr_t>(hDll);
                    uintptr_t dllEnd = dllStart + modInfo.SizeOfImage;
                    uintptr_t funcAddr = reinterpret_cast<uintptr_t>(pFunc);

                    if (funcAddr < dllStart || funcAddr >= dllEnd) {
                        hookCount++;

                        HookInfo hookInfo;
                        hookInfo.address = reinterpret_cast<uintptr_t>(pThunk);
                        hookInfo.hookDestination = funcAddr;
                        hookInfo.type = HookType::IAT;
                        hookInfo.moduleName = NarrowToWide(dllName);
                        hookInfo.isSuspicious = true;

                        foundHooks.push_back(std::move(hookInfo));
                    }
                }

                pThunk++;
            }
        }

        pImportDesc++;
    }

    if (hookCount > 0) {
        // Store all found hooks under lock in one batch
        {
            std::unique_lock writeLock(m_mutex);
            for (auto& h : foundHooks) {
                m_detectedHooks.push_back(std::move(h));
            }
            m_stats.hooksDetected += hookCount;
        }

        result.detected = true;
        result.confidence = DetectionConfidence::High;
        result.score = AntiDebugConstants::WEIGHT_HOOK_DETECTION;
        result.debuggerType = DebuggerType::Instrumentation;
        result.message = "IAT hooks detected";
        result.details["hook_count"] = std::to_string(hookCount);

        SS_LOG_WARN(L"AntiDebug", L"Detected %zu IAT hooks", hookCount);
    } else {
        result.message = "No IAT hooks detected";
    }
#else
    result.message = "IAT hook detection not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckMemory_IATHooks(std::wstring_view moduleName) {
    // Delegate to full check for now
    return CheckMemory_IATHooks();
}

DetectionCheckResult AntiDebugImpl::CheckMemory_InlineHooks() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Memory_InlineHooks;
    result.timestamp = startTime;

#ifdef _WIN32
    // Check critical NTDLL functions for inline hooks
    const std::array<std::pair<const char*, const char*>, 5> criticalFunctions = {{
        {"ntdll.dll", "NtQueryInformationProcess"},
        {"ntdll.dll", "NtSetInformationThread"},
        {"kernel32.dll", "IsDebuggerPresent"},
        {"kernel32.dll", "CheckRemoteDebuggerPresent"},
        {"kernel32.dll", "GetThreadContext"}
    }};

    size_t hookCount = 0;
    std::vector<HookInfo> foundHooks;

    for (const auto& [dllName, funcName] : criticalFunctions) {
        HMODULE hDll = ::GetModuleHandleA(dllName);
        if (hDll) {
            FARPROC pFunc = ::GetProcAddress(hDll, funcName);
            if (pFunc) {
                PBYTE pBytes = reinterpret_cast<PBYTE>(pFunc);

                // SEH-guarded read of the first 16 bytes — exported function
                // pages may unmap their tail or be hot-patched into guard
                // regions; a direct dereference would crash the host process.
                BYTE prefix[16] = {};
                const size_t copied = SehReadBytes(pBytes, prefix, sizeof(prefix));
                if (copied < 2) {
                    continue;
                }

                bool isHooked = false;

                if (prefix[0] == 0xE9) {
                    isHooked = true;
                } else if (prefix[0] == 0xFF && prefix[1] == 0x25) {
                    isHooked = true;
                } else if (prefix[0] == 0x68) {
                    isHooked = true;
                }
#ifdef _WIN64
                else if (copied >= 2 && prefix[0] == 0x48 && prefix[1] == 0xB8) {
                    isHooked = true;
                }
#endif

                if (isHooked) {
                    hookCount++;

                    HookInfo hookInfo;
                    hookInfo.address = reinterpret_cast<uintptr_t>(pFunc);
                    hookInfo.type = HookType::InlineJump;
                    hookInfo.moduleName = NarrowToWide(dllName);
                    hookInfo.functionName = funcName;
                    hookInfo.isSuspicious = true;
                    hookInfo.currentBytes.assign(prefix, prefix + copied);

                    foundHooks.push_back(std::move(hookInfo));

                    SS_LOG_WARN(L"AntiDebug", L"Inline hook detected on %hs!%hs", dllName, funcName);
                }
            }
        }
    }

    if (hookCount > 0) {
        {
            std::unique_lock lock(m_mutex);
            for (auto& h : foundHooks) {
                m_detectedHooks.push_back(std::move(h));
            }
            m_stats.hooksDetected += hookCount;
        }

        result.detected = true;
        result.confidence = DetectionConfidence::Critical;
        result.score = AntiDebugConstants::WEIGHT_HOOK_DETECTION;
        result.debuggerType = DebuggerType::Instrumentation;
        result.message = "Inline hooks detected on critical functions";
        result.details["hook_count"] = std::to_string(hookCount);
    } else {
        result.message = "No inline hooks detected on critical functions";
    }
#else
    result.message = "Inline hook detection not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckMemory_InlineHooks(std::wstring_view moduleName) {
    return CheckMemory_InlineHooks();
}

std::vector<HookInfo> AntiDebugImpl::GetDetectedHooks() const {
    std::shared_lock lock(m_mutex);
    return m_detectedHooks;
}

DetectionCheckResult AntiDebugImpl::CheckAllMemory() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckMemory_SoftwareBreakpoints());
    results.push_back(CheckMemory_CodeIntegrity());
    results.push_back(CheckMemory_IATHooks());
    results.push_back(CheckMemory_InlineHooks());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_Memory;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "Memory-based debugger/hook detection triggered";
    } else {
        combined.message = "All memory checks passed";
    }

    return combined;
}

// ============================================================================
// DETECTION - PROCESS BASED
// ============================================================================

DetectionCheckResult AntiDebugImpl::CheckProcess_ParentProcess() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Process_ParentCheck;
    result.timestamp = startTime;

#ifdef _WIN32
    // Get parent process ID
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        result.errorCode = ::GetLastError();
        result.message = "Failed to create process snapshot";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }

    DWORD currentPid = ::GetCurrentProcessId();
    DWORD parentPid = 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (::Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == currentPid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (::Process32NextW(hSnapshot, &pe));
    }

    ::CloseHandle(hSnapshot);

    if (parentPid != 0) {
        // Get parent process name
        hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            pe.dwSize = sizeof(pe);
            if (::Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == parentPid) {
                        std::wstring parentName = pe.szExeFile;
                        result.details["parent_name"] = WideToNarrow(parentName);
                        result.details["parent_pid"] = std::to_string(parentPid);

                        // Check if parent is a known debugger
                        std::wstring lowerName = parentName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

                        for (const auto& dbgName : AntiDebugConstants::DEBUGGER_PROCESSES) {
                            std::wstring wDbgName = NarrowToWide(std::string(dbgName));
                            std::transform(wDbgName.begin(), wDbgName.end(), wDbgName.begin(), ::towlower);

                            if (lowerName == wDbgName) {
                                // Check whitelist
                                if (!IsWhitelisted(parentName)) {
                                    result.detected = true;
                                    result.confidence = DetectionConfidence::High;
                                    result.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION;
                                    result.debuggerType = DebuggerType::UserMode;
                                    result.message = "Parent process is a known debugger: " + WideToNarrow(parentName);

                                    SS_LOG_WARN(L"AntiDebug", L"Parent process is debugger: %ls (PID %u)",
                                                       parentName.c_str(), parentPid);
                                }
                                break;
                            }
                        }
                        break;
                    }
                } while (::Process32NextW(hSnapshot, &pe));
            }
            ::CloseHandle(hSnapshot);
        }
    }

    if (!result.detected) {
        result.message = "Parent process check passed";
    }
#else
    result.message = "Parent process check not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckProcess_DebuggerProcesses() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Process_DebuggerSearch;
    result.timestamp = startTime;

#ifdef _WIN32
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        result.errorCode = ::GetLastError();
        result.message = "Failed to create process snapshot";
        result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
        return result;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    size_t debuggerCount = 0;
    std::vector<std::wstring> foundDebuggers;

    if (::Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring processName = pe.szExeFile;
            std::wstring lowerName = processName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            // Check against known debugger list
            for (const auto& dbgName : AntiDebugConstants::DEBUGGER_PROCESSES) {
                std::wstring wDbgName = NarrowToWide(std::string(dbgName));
                std::transform(wDbgName.begin(), wDbgName.end(), wDbgName.begin(), ::towlower);

                if (lowerName == wDbgName) {
                    if (!IsWhitelisted(processName)) {
                        debuggerCount++;
                        foundDebuggers.push_back(processName);

                        DebuggerProcessInfo info;
                        info.processId = pe.th32ProcessID;
                        info.processName = processName;
                        info.type = DebuggerType::UserMode;
                        info.confidence = DetectionConfidence::High;

                        std::unique_lock lock(m_mutex);
                        m_detectedDebuggers.push_back(info);
                    }
                    break;
                }
            }

            if (debuggerCount >= AntiDebugConstants::MAX_DEBUGGER_PROCESSES) {
                break;
            }

        } while (::Process32NextW(hSnapshot, &pe));
    }

    ::CloseHandle(hSnapshot);

    if (debuggerCount > 0) {
        result.detected = true;
        result.confidence = DetectionConfidence::High;
        result.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "Debugger processes found running";
        result.details["count"] = std::to_string(debuggerCount);

        std::string debuggerList;
        for (const auto& name : foundDebuggers) {
            if (!debuggerList.empty()) debuggerList += ", ";
            debuggerList += WideToNarrow(name);
        }
        result.details["debuggers"] = debuggerList;

        SS_LOG_WARN(L"AntiDebug", L"Found %zu debugger processes: %hs", debuggerCount, debuggerList.c_str());
    } else {
        result.message = "No debugger processes found";
    }
#else
    result.message = "Debugger process search not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckProcess_DebuggerWindows() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Process_WindowSearch;
    result.timestamp = startTime;

#ifdef _WIN32
    size_t foundCount = 0;

    for (const auto& className : AntiDebugConstants::DEBUGGER_WINDOW_CLASSES) {
        std::wstring wClassName = NarrowToWide(std::string(className));

        HWND hWnd = ::FindWindowW(wClassName.c_str(), nullptr);
        if (hWnd) {
            foundCount++;

            // Get window title
            wchar_t title[256] = {};
            ::GetWindowTextW(hWnd, title, 255);

            result.details["window_class"] = WideToNarrow(wClassName);
            result.details["window_title"] = WideToNarrow(title);

            SS_LOG_WARN(L"AntiDebug", L"Debugger window found: class='%hs', title='%ls'",
                               std::string(className).c_str(), title);
        }
    }

    if (foundCount > 0) {
        result.detected = true;
        result.confidence = DetectionConfidence::Medium;
        result.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION;
        result.debuggerType = DebuggerType::UserMode;
        result.message = "Debugger windows detected";
        result.details["count"] = std::to_string(foundCount);
    } else {
        result.message = "No debugger windows found";
    }
#else
    result.message = "Window search not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckProcess_DebuggerDrivers() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Process_DriverSearch;
    result.timestamp = startTime;

#ifdef _WIN32
    size_t foundCount = 0;

    for (const auto& driverName : AntiDebugConstants::DEBUGGER_DRIVERS) {
        std::wstring wDriverPath = L"\\\\.\\" + NarrowToWide(std::string(driverName));

        HANDLE hDriver = ::CreateFileW(
            wDriverPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (hDriver != INVALID_HANDLE_VALUE) {
            foundCount++;
            ::CloseHandle(hDriver);

            result.details["driver"] = std::string(driverName);

            SS_LOG_WARN(L"AntiDebug", L"Debugger driver found: %hs", std::string(driverName).c_str());
        }
    }

    if (foundCount > 0) {
        result.detected = true;
        result.confidence = DetectionConfidence::Critical;
        result.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION * 2;
        result.debuggerType = DebuggerType::KernelMode;
        result.message = "Kernel debugger drivers detected";
        result.details["count"] = std::to_string(foundCount);
    } else {
        result.message = "No debugger drivers found";
    }
#else
    result.message = "Driver search not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

DetectionCheckResult AntiDebugImpl::CheckProcess_InstrumentationFrameworks() {
    auto startTime = Clock::now();
    DetectionCheckResult result;
    result.technique = DetectionTechnique::Process_DebuggerSearch;
    result.timestamp = startTime;

#ifdef _WIN32
    // Check for Frida by looking for frida-agent DLL
    if (::GetModuleHandleW(L"frida-agent.dll") ||
        ::GetModuleHandleW(L"frida-gadget.dll")) {
        result.detected = true;
        result.confidence = DetectionConfidence::Critical;
        result.score = AntiDebugConstants::WEIGHT_INSTRUMENTATION_DETECTION;
        result.debuggerType = DebuggerType::Instrumentation;
        result.message = "Frida instrumentation framework detected";
        result.details["framework"] = "frida";

        SS_LOG_WARN(L"AntiDebug", L"Frida instrumentation detected");
    }

    // Check for other instrumentation frameworks
    const std::array<std::pair<const wchar_t*, const char*>, 4> frameworks = {{
        {L"dynamorio.dll", "DynamoRIO"},
        {L"pinvm.dll", "Intel PIN"},
        {L"detours.dll", "Microsoft Detours"},
        {L"apimonitor.dll", "API Monitor"}
    }};

    for (const auto& [dllName, frameworkName] : frameworks) {
        if (::GetModuleHandleW(dllName)) {
            result.detected = true;
            result.confidence = DetectionConfidence::High;
            result.score += AntiDebugConstants::WEIGHT_INSTRUMENTATION_DETECTION / 2;
            result.debuggerType = DebuggerType::Instrumentation;
            result.message = std::string("Instrumentation framework detected: ") + frameworkName;
            result.details["framework"] = frameworkName;

            SS_LOG_WARN(L"AntiDebug", L"%hs instrumentation detected", frameworkName);
        }
    }

    if (!result.detected) {
        result.message = "No instrumentation frameworks detected";
    }
#else
    result.message = "Instrumentation detection not supported on this platform";
#endif

    result.checkDuration = std::chrono::duration_cast<Microseconds>(Clock::now() - startTime);
    return result;
}

std::vector<DebuggerProcessInfo> AntiDebugImpl::GetDetectedDebuggers() const {
    std::shared_lock lock(m_mutex);
    return m_detectedDebuggers;
}

DetectionCheckResult AntiDebugImpl::CheckAllProcess() {
    std::vector<DetectionCheckResult> results;

    results.push_back(CheckProcess_ParentProcess());
    results.push_back(CheckProcess_DebuggerProcesses());
    results.push_back(CheckProcess_DebuggerWindows());
    results.push_back(CheckProcess_DebuggerDrivers());
    results.push_back(CheckProcess_InstrumentationFrameworks());

    // Combine results
    DetectionCheckResult combined;
    combined.technique = DetectionTechnique::All_Process;
    combined.timestamp = Clock::now();

    for (const auto& r : results) {
        if (r.detected) {
            combined.detected = true;
            combined.score += r.score;
            if (static_cast<uint8_t>(r.confidence) > static_cast<uint8_t>(combined.confidence)) {
                combined.confidence = r.confidence;
            }
            if (r.debuggerType != DebuggerType::Unknown) {
                combined.debuggerType = r.debuggerType;
            }
        }
        combined.checkDuration += r.checkDuration;
    }

    if (combined.detected) {
        combined.message = "Process-based debugger detection triggered";
    } else {
        combined.message = "All process checks passed";
    }

    return combined;
}

// ============================================================================
// PROTECTION - THREAD HIDING
// ============================================================================

bool AntiDebugImpl::HideThread(uint32_t threadId) {
#ifdef _WIN32
    if (!m_pNtSetInformationThread) {
        SS_LOG_ERROR(L"AntiDebug", L"NtSetInformationThread not available");
        return false;
    }

    uint32_t tid = threadId == 0 ? ::GetCurrentThreadId() : threadId;

    // For the current thread use the pseudohandle directly; for other threads open a real handle
    HANDLE hThread = nullptr;
    bool needsClose = false;

    if (threadId == 0) {
        hThread = ::GetCurrentThread();
    } else {
        hThread = ::OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
        if (!hThread) {
            SS_LOG_ERROR(L"AntiDebug", L"Failed to open thread %u for hiding", tid);
            return false;
        }
        needsClose = true;
    }

    NTSTATUS status = m_pNtSetInformationThread(
        hThread,
        SsThreadHideFromDebugger,
        nullptr,
        0
    );

    if (needsClose) {
        ::CloseHandle(hThread);
    }

    if (NT_SUCCESS(status)) {
        std::unique_lock lock(m_mutex);
        auto& state = m_threadStates[tid];
        state.threadId = tid;
        state.isHidden = true;
        state.protectionTime = Clock::now();

        m_stats.threadsHidden += 1;

        SS_LOG_INFO(L"AntiDebug", L"Thread %u hidden from debugger", tid);
        return true;
    } else {
        SS_LOG_ERROR(L"AntiDebug", L"Failed to hide thread %u: NTSTATUS 0x%08lX", tid, static_cast<unsigned long>(status));
        return false;
    }
#else
    return false;
#endif
}

size_t AntiDebugImpl::HideAllThreads() {
    size_t count = 0;

#ifdef _WIN32
    std::vector<uint32_t> threadIds = EnumerateThreadIds();

    for (uint32_t tid : threadIds) {
        if (HideThread(tid)) {
            count++;
        }
    }

    SS_LOG_INFO(L"AntiDebug", L"Hidden %zu threads from debugger", count);
#endif

    return count;
}

bool AntiDebugImpl::IsThreadHidden(uint32_t threadId) const {
    std::shared_lock lock(m_mutex);

    uint32_t tid = threadId == 0 ? GetCurrentThreadIdSafe() : threadId;
    auto it = m_threadStates.find(tid);

    return it != m_threadStates.end() && it->second.isHidden;
}

ThreadProtectionState AntiDebugImpl::GetThreadProtectionState(uint32_t threadId) const {
    std::shared_lock lock(m_mutex);

    uint32_t tid = threadId == 0 ? GetCurrentThreadIdSafe() : threadId;
    auto it = m_threadStates.find(tid);

    if (it != m_threadStates.end()) {
        return it->second;
    }

    return {};
}

void AntiDebugImpl::SecureThread() {
    (void)HideThread(0);
    (void)ClearDebugRegisters(0);
}

bool AntiDebugImpl::ProtectThread(uint32_t threadId) {
    bool success = true;

    if (!HideThread(threadId)) {
        success = false;
    }

    if (!ClearDebugRegisters(threadId)) {
        success = false;
    }

    return success;
}

// ============================================================================
// PROTECTION - DEBUG REGISTERS
// ============================================================================

bool AntiDebugImpl::ClearDebugRegisters(uint32_t threadId) {
#ifdef _WIN32
    uint32_t tid = threadId == 0 ? ::GetCurrentThreadId() : threadId;

    HANDLE hThread = nullptr;
    bool needsClose = false;

    if (threadId == 0) {
        hThread = ::GetCurrentThread();
    } else {
        hThread = ::OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, tid);
        if (!hThread) {
            SS_LOG_ERROR(L"AntiDebug", L"Failed to open thread %u for DR clearing", tid);
            return false;
        }
        needsClose = true;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!::GetThreadContext(hThread, &ctx)) {
        if (needsClose) ::CloseHandle(hThread);
        SS_LOG_ERROR(L"AntiDebug", L"Failed to get context for thread %u", tid);
        return false;
    }

    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0;

    if (!::SetThreadContext(hThread, &ctx)) {
        if (needsClose) ::CloseHandle(hThread);
        SS_LOG_ERROR(L"AntiDebug", L"Failed to set context for thread %u", tid);
        return false;
    }

    if (needsClose) {
        ::CloseHandle(hThread);
    }

    {
        std::unique_lock lock(m_mutex);
        auto& state = m_threadStates[tid];
        state.threadId = tid;
        state.debugRegistersClear = true;
        m_stats.breakpointsCleared += 1;
    }

    SS_LOG_INFO(L"AntiDebug", L"Debug registers cleared for thread %u", tid);
    return true;
#else
    return false;
#endif
}

size_t AntiDebugImpl::ClearAllDebugRegisters() {
    size_t count = 0;

#ifdef _WIN32
    std::vector<uint32_t> threadIds = EnumerateThreadIds();

    for (uint32_t tid : threadIds) {
        if (ClearDebugRegisters(tid)) {
            count++;
        }
    }

    SS_LOG_INFO(L"AntiDebug", L"Cleared debug registers for %zu threads", count);
#endif

    return count;
}

void AntiDebugImpl::SetAutoClearing(bool enable) {
    m_autoClearing.store(enable, std::memory_order_release);
}

// ============================================================================
// PROTECTION - CODE INTEGRITY
// ============================================================================

bool AntiDebugImpl::RegisterIntegrityRegion(std::string_view id, uintptr_t address, size_t size) {
    if (id.empty() || address == 0 || size == 0) {
        return false;
    }

    if (size > AntiDebugConstants::MAX_CODE_SECTION_SIZE) {
        SS_LOG_WARN(L"AntiDebug", L"Integrity region too large: %zu bytes", size);
        return false;
    }

    std::unique_lock lock(m_mutex);

    if (m_integrityRegions.size() >= AntiDebugConstants::MAX_INTEGRITY_REGIONS) {
        SS_LOG_WARN(L"AntiDebug", L"Maximum integrity regions reached");
        return false;
    }

    IntegrityRegion region;
    region.id = std::string(id);
    region.startAddress = address;
    region.size = size;

    // Calculate initial CRC32
    const uint8_t* pData = reinterpret_cast<const uint8_t*>(address);
    std::span<const uint8_t> data(pData, size);
    region.expectedCrc32 = CalculateCRC32(data);
    region.currentCrc32 = region.expectedCrc32;
    region.status = AntiDebugIntegrityStatus::Valid;
    region.lastVerified = Clock::now();

    m_integrityRegions[std::string(id)] = region;

    SS_LOG_INFO(L"AntiDebug", L"Registered integrity region '%hs': addr=0x%IX, size=%zu, crc=0x%08X",
                       std::string(id).c_str(), address, size, region.expectedCrc32);

    return true;
}

bool AntiDebugImpl::RegisterSelfIntegrity() {
#ifdef _WIN32
    HMODULE hModule = ::GetModuleHandleW(nullptr);
    if (!hModule) {
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(hModule) + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

    bool registered = false;
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uintptr_t address = reinterpret_cast<uintptr_t>(hModule) + pSection->VirtualAddress;
            size_t size = std::min(static_cast<size_t>(pSection->Misc.VirtualSize),
                                   AntiDebugConstants::MAX_CODE_SECTION_SIZE);

            std::string sectionName(reinterpret_cast<const char*>(pSection->Name), 8);
            sectionName.erase(std::find(sectionName.begin(), sectionName.end(), '\0'), sectionName.end());

            std::string regionId = "self_" + sectionName;

            if (RegisterIntegrityRegion(regionId, address, size)) {
                registered = true;
            }
        }
    }

    return registered;
#else
    return false;
#endif
}

void AntiDebugImpl::UnregisterIntegrityRegion(std::string_view id) {
    std::unique_lock lock(m_mutex);
    m_integrityRegions.erase(std::string(id));
}

AntiDebugIntegrityStatus AntiDebugImpl::VerifyIntegrity(std::string_view id) {
    std::unique_lock lock(m_mutex);

    auto it = m_integrityRegions.find(std::string(id));
    if (it == m_integrityRegions.end()) {
        return AntiDebugIntegrityStatus::Unknown;
    }

    auto& region = it->second;

    const uint8_t* pData = reinterpret_cast<const uint8_t*>(region.startAddress);
    std::span<const uint8_t> data(pData, region.size);

    region.currentCrc32 = CalculateCRC32(data);
    region.lastVerified = Clock::now();

    if (region.currentCrc32 != region.expectedCrc32) {
        region.status = AntiDebugIntegrityStatus::Modified;
        region.failureCount++;

        m_stats.integrityViolations += 1;

        SS_LOG_WARN(L"AntiDebug", L"Integrity violation in '%.*hs': expected 0x%08X, got 0x%08X",
                           static_cast<int>(id.size()), id.data(), region.expectedCrc32, region.currentCrc32);
    } else {
        region.status = AntiDebugIntegrityStatus::Valid;
    }

    return region.status;
}

std::unordered_map<std::string, AntiDebugIntegrityStatus> AntiDebugImpl::VerifyAllIntegrity() {
    std::unordered_map<std::string, AntiDebugIntegrityStatus> results;

    // Collect IDs under lock, then verify each outside to avoid iterator invalidation
    std::vector<std::string> ids;
    {
        std::shared_lock lock(m_mutex);
        ids.reserve(m_integrityRegions.size());
        for (const auto& [id, region] : m_integrityRegions) {
            ids.push_back(id);
        }
    }

    for (const auto& id : ids) {
        results[id] = VerifyIntegrity(id);
    }

    return results;
}

std::optional<IntegrityRegion> AntiDebugImpl::GetIntegrityRegion(std::string_view id) const {
    std::shared_lock lock(m_mutex);

    auto it = m_integrityRegions.find(std::string(id));
    if (it != m_integrityRegions.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<IntegrityRegion> AntiDebugImpl::GetAllIntegrityRegions() const {
    std::shared_lock lock(m_mutex);

    std::vector<IntegrityRegion> regions;
    regions.reserve(m_integrityRegions.size());

    for (const auto& [id, region] : m_integrityRegions) {
        regions.push_back(region);
    }

    return regions;
}

// ============================================================================
// PROTECTION - RESPONSE ACTIONS
// ============================================================================

bool AntiDebugImpl::ExecuteResponse(ResponseAction action, const DetectionResult& result) {
    bool executed = false;

    // Log action
    if ((static_cast<uint32_t>(action) & static_cast<uint32_t>(ResponseAction::Log)) != 0) {
        SS_LOG_WARN(L"AntiDebug", L"Detection logged: score=%u, confidence=%d",
                           result.totalScore, static_cast<int>(result.overallConfidence));
        executed = true;
    }

    // Alert
    if ((static_cast<uint32_t>(action) & static_cast<uint32_t>(ResponseAction::Alert)) != 0) {
        // Generate alert event
        DetectionEvent event;
        event.eventId = GenerateEventId();
        event.technique = result.triggeredTechniques;
        event.confidence = result.overallConfidence;
        event.score = result.totalScore;
        event.debuggerType = result.primaryDebuggerType;
        event.message = "ALERT: " + result.GetSummary();
        event.timestamp = Clock::now();
        event.threadId = GetCurrentThreadIdSafe();
        event.processId = GetCurrentProcessIdSafe();
        event.actionsTaken = action;

        NotifyDetection(event);
        executed = true;
    }

    // Hide threads
    if ((static_cast<uint32_t>(action) & static_cast<uint32_t>(ResponseAction::HideThreads)) != 0) {
        (void)HideAllThreads();
        executed = true;
    }

    // Clear breakpoints
    if ((static_cast<uint32_t>(action) & static_cast<uint32_t>(ResponseAction::ClearBreakpoints)) != 0) {
        (void)ClearAllDebugRegisters();
        executed = true;
    }

    if (executed) {
        std::unique_lock lock(m_mutex);
        m_stats.actionsExecuted += 1;
    }

    return executed;
}

ResponseAction AntiDebugImpl::ExecuteRecommendedResponse(const DetectionResult& result) {
    ResponseAction recommended = DetermineRecommendedAction(result);
    ResponseAction configured;

    {
        std::shared_lock lock(m_mutex);
        configured = m_config.responseActions;
    }

    // Only execute actions that are both recommended and configured
    ResponseAction toExecute = recommended & configured;

    (void)ExecuteResponse(toExecute, result);

    return toExecute;
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t AntiDebugImpl::RegisterDetectionCallback(DetectionCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId += 1;
    m_detectionCallbacks[id] = std::move(callback);
    return id;
}

void AntiDebugImpl::UnregisterDetectionCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_detectionCallbacks.erase(callbackId);
}

uint64_t AntiDebugImpl::RegisterResponseCallback(ResponseCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId += 1;
    m_responseCallbacks[id] = std::move(callback);
    return id;
}

void AntiDebugImpl::UnregisterResponseCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_responseCallbacks.erase(callbackId);
}

uint64_t AntiDebugImpl::RegisterIntegrityCallback(AntiDebugIntegrityCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId += 1;
    m_integrityCallbacks[id] = std::move(callback);
    return id;
}

void AntiDebugImpl::UnregisterIntegrityCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_integrityCallbacks.erase(callbackId);
}

uint64_t AntiDebugImpl::RegisterHookCallback(HookCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId += 1;
    m_hookCallbacks[id] = std::move(callback);
    return id;
}

void AntiDebugImpl::UnregisterHookCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_hookCallbacks.erase(callbackId);
}

uint64_t AntiDebugImpl::RegisterStatusCallback(StatusCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId += 1;
    m_statusCallbacks[id] = std::move(callback);
    return id;
}

void AntiDebugImpl::UnregisterStatusCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_statusCallbacks.erase(callbackId);
}

// ============================================================================
// STATISTICS
// ============================================================================

AntiDebugStatistics AntiDebugImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void AntiDebugImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats = AntiDebugStatistics{};
    m_stats.startTime = Clock::now();
}

std::vector<DetectionEvent> AntiDebugImpl::GetDetectionHistory(size_t maxEntries) const {
    std::lock_guard lock(m_historyMutex);

    size_t count = std::min(maxEntries, m_detectionHistory.size());
    std::vector<DetectionEvent> result;
    result.reserve(count);

    auto it = m_detectionHistory.rbegin();
    for (size_t i = 0; i < count && it != m_detectionHistory.rend(); ++i, ++it) {
        result.push_back(*it);
    }

    return result;
}

void AntiDebugImpl::ClearDetectionHistory() {
    std::lock_guard lock(m_historyMutex);
    m_detectionHistory.clear();
}

std::string AntiDebugImpl::ExportReport() const {
    std::shared_lock lock(m_mutex);

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"module\": \"AntiDebug\",\n";
    oss << "  \"version\": \"" << AntiDebug::GetVersionString() << "\",\n";
    oss << "  \"status\": " << static_cast<int>(m_status.load()) << ",\n";
    oss << "  \"debuggerDetected\": " << (m_debuggerDetected.load() ? "true" : "false") << ",\n";
    oss << "  \"detectionScore\": " << m_detectionScore.load() << ",\n";
    oss << "  \"statistics\": {\n";
    oss << "    \"totalChecks\": " << m_stats.totalChecks << ",\n";
    oss << "    \"totalDetections\": " << m_stats.totalDetections << ",\n";
    oss << "    \"falsePositives\": " << m_stats.falsePositives << ",\n";
    oss << "    \"actionsExecuted\": " << m_stats.actionsExecuted << ",\n";
    oss << "    \"threadsHidden\": " << m_stats.threadsHidden << ",\n";
    oss << "    \"breakpointsCleared\": " << m_stats.breakpointsCleared << ",\n";
    oss << "    \"hooksDetected\": " << m_stats.hooksDetected << ",\n";
    oss << "    \"integrityViolations\": " << m_stats.integrityViolations << ",\n";
    oss << "    \"uptimeSeconds\": " << m_stats.GetUptimeSeconds() << "\n";
    oss << "  },\n";
    oss << "  \"integrityRegions\": " << m_integrityRegions.size() << ",\n";
    oss << "  \"detectedHooks\": " << m_detectedHooks.size() << ",\n";
    oss << "  \"detectedDebuggers\": " << m_detectedDebuggers.size() << "\n";
    oss << "}\n";

    return oss.str();
}

// ============================================================================
// UTILITY
// ============================================================================

bool AntiDebugImpl::SelfTest() {
    SS_LOG_INFO(L"AntiDebug", L"Starting self-test...");

    bool passed = true;

    // Test 1: Configuration validation
    AntiDebugConfiguration testConfig;
    if (!testConfig.IsValid()) {
        SS_LOG_ERROR(L"AntiDebug", L"Self-test FAILED: Default config invalid");
        passed = false;
    }

    // Test 2: PEB check (should return result without crash)
    try {
        auto pebResult = CheckPEB_BeingDebugged();
        SS_LOG_INFO(L"AntiDebug", L"Self-test: PEB check completed, detected=%d",
                           static_cast<int>(pebResult.detected));
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiDebug", L"Self-test FAILED: PEB check threw: %hs", e.what());
        passed = false;
    }

    // Test 3: API check
    try {
        auto apiResult = CheckAPI_IsDebuggerPresent();
        SS_LOG_INFO(L"AntiDebug", L"Self-test: API check completed, detected=%d",
                           static_cast<int>(apiResult.detected));
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiDebug", L"Self-test FAILED: API check threw: %hs", e.what());
        passed = false;
    }

    // Test 4: Debug register state retrieval
    try {
        auto drState = GetDebugRegisterState();
        SS_LOG_INFO(L"AntiDebug", L"Self-test: DR state retrieved");
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AntiDebug", L"Self-test FAILED: DR state threw: %hs", e.what());
        passed = false;
    }

    // Test 5: Statistics
    {
        std::shared_lock statsLock(m_mutex);
        if (m_stats.GetUptimeSeconds() == 0 && m_initialized) {
            // May be okay if just started
        }
    }

    SS_LOG_INFO(L"AntiDebug", L"Self-test completed: %hs", passed ? "PASSED" : "FAILED");

    return passed;
}

void AntiDebugImpl::ForceGarbageCollection() {
    // Trim history under its own lock (not holding m_mutex)
    {
        std::lock_guard historyLock(m_historyMutex);
        while (m_detectionHistory.size() > MAX_HISTORY_SIZE / 2) {
            m_detectionHistory.pop_front();
        }
    }

    // Clear stale thread states under m_mutex
    {
        std::unique_lock lock(m_mutex);
        auto now = Clock::now();
        for (auto it = m_threadStates.begin(); it != m_threadStates.end();) {
            auto age = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.protectionTime);
            if (age.count() > 60) {
                it = m_threadStates.erase(it);
            } else {
                ++it;
            }
        }
    }

    SS_LOG_INFO(L"AntiDebug", L"Garbage collection completed");
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

void AntiDebugImpl::SetStatus(ModuleStatus newStatus) {
    ModuleStatus oldStatus = m_status.exchange(newStatus, std::memory_order_acq_rel);

    if (oldStatus != newStatus) {
        NotifyStatusChange(oldStatus, newStatus);
    }
}

void AntiDebugImpl::StartMonitoringThread() {
    if (m_monitoringThread && m_monitoringThread->joinable()) {
        return;
    }

    m_stopMonitoring.store(false, std::memory_order_release);
    m_monitoringThread = std::make_unique<std::thread>(&AntiDebugImpl::MonitoringThreadFunc, this);

    SS_LOG_INFO(L"AntiDebug", L"Monitoring thread started");
}

void AntiDebugImpl::StopMonitoringThread() {
    m_stopMonitoring.store(true, std::memory_order_release);
    m_monitoringCV.notify_one();

    if (m_monitoringThread && m_monitoringThread->joinable()) {
        m_monitoringThread->join();
        m_monitoringThread.reset();
    }

    SS_LOG_INFO(L"AntiDebug", L"Monitoring thread stopped");
}

void AntiDebugImpl::MonitoringThreadFunc() {
    SS_LOG_INFO(L"AntiDebug", L"Monitoring thread running");

    while (!m_stopMonitoring.load(std::memory_order_acquire)) {
        // Wait for interval or stop signal
        uint32_t intervalMs;
        {
            std::shared_lock lock(m_mutex);
            intervalMs = m_config.monitoringIntervalMs;
        }

        {
            std::unique_lock lock(m_monitoringMutex);
            m_monitoringCV.wait_for(lock, Milliseconds(intervalMs), [this]() {
                return m_stopMonitoring.load(std::memory_order_acquire);
            });
        }

        if (m_stopMonitoring.load(std::memory_order_acquire)) {
            break;
        }

        // Skip if paused
        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
            continue;
        }

        // Perform scan based on monitoring mode
        MonitoringMode mode;
        {
            std::shared_lock lock(m_mutex);
            mode = m_config.monitoringMode;
        }

        if (mode == MonitoringMode::Continuous) {
            (void)PerformFullScan();
        } else if (mode == MonitoringMode::Periodic) {
            (void)PerformQuickScan();
        } else if (mode == MonitoringMode::Adaptive) {
            // Use quick scan normally, full scan if something was detected recently
            if (m_debuggerDetected.load(std::memory_order_acquire)) {
                (void)PerformFullScan();
            } else {
                (void)PerformQuickScan();
            }
        }

        // Auto-clear debug registers if enabled
        if (m_autoClearing.load(std::memory_order_acquire)) {
            (void)ClearAllDebugRegisters();
        }
    }
}

void AntiDebugImpl::NotifyDetection(const DetectionEvent& event) {
    // Add to history
    {
        std::lock_guard lock(m_historyMutex);
        m_detectionHistory.push_back(event);

        while (m_detectionHistory.size() > MAX_HISTORY_SIZE) {
            m_detectionHistory.pop_front();
        }
    }

    // Notify callbacks
    std::vector<DetectionCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        callbacks.reserve(m_detectionCallbacks.size());
        for (const auto& [id, cb] : m_detectionCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(event);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiDebug", L"Detection callback threw: %hs", e.what());
        }
    }
}

void AntiDebugImpl::NotifyStatusChange(ModuleStatus oldStatus, ModuleStatus newStatus) {
    std::vector<StatusCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        callbacks.reserve(m_statusCallbacks.size());
        for (const auto& [id, cb] : m_statusCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(oldStatus, newStatus);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiDebug", L"Status callback threw: %hs", e.what());
        }
    }
}

void AntiDebugImpl::RecordDetection(const DetectionCheckResult& check) {
    if (check.detected) {
        DetectionEvent event;
        event.eventId = GenerateEventId();
        event.technique = check.technique;
        event.confidence = check.confidence;
        event.score = check.score;
        event.debuggerType = check.debuggerType;
        event.message = check.message;
        event.timestamp = check.timestamp;
        event.threadId = GetCurrentThreadIdSafe();
        event.processId = GetCurrentProcessIdSafe();

        NotifyDetection(event);
    }
}

void AntiDebugImpl::UpdateStatistics(const DetectionCheckResult& check, Microseconds duration) {
    std::unique_lock lock(m_mutex);
    m_stats.totalChecks += 1;

    uint64_t durationUs = static_cast<uint64_t>(duration.count());
    if (durationUs > m_stats.maxCheckDurationUs) {
        m_stats.maxCheckDurationUs = durationUs;
    }
}

DetectionResult AntiDebugImpl::AggregateResults(const std::vector<DetectionCheckResult>& checks) {
    DetectionResult result;
    result.scanTimestamp = Clock::now();

    for (const auto& check : checks) {
        result.checkResults.push_back(check);
        result.checksPerformed++;

        if (check.detected) {
            result.debuggerDetected = true;
            result.checksTriggered++;
            result.totalScore += check.score;
            result.triggeredTechniques = result.triggeredTechniques | check.technique;

            if (static_cast<uint8_t>(check.confidence) > static_cast<uint8_t>(result.overallConfidence)) {
                result.overallConfidence = check.confidence;
            }

            if (check.debuggerType != DebuggerType::Unknown) {
                result.primaryDebuggerType = check.debuggerType;
            }
        }
    }

    // Determine recommended action based on score
    result.recommendedAction = DetermineRecommendedAction(result);

    return result;
}

ResponseAction AntiDebugImpl::DetermineRecommendedAction(const DetectionResult& result) const {
    if (!result.debuggerDetected) {
        return ResponseAction::None;
    }

    if (result.totalScore >= AntiDebugConstants::CRITICAL_SCORE) {
        return ResponseAction::Aggressive;
    } else if (result.totalScore >= AntiDebugConstants::HIGH_CONFIDENCE_SCORE) {
        return ResponseAction::Moderate;
    } else if (result.totalScore >= AntiDebugConstants::MIN_DETECTION_SCORE) {
        return ResponseAction::Passive;
    }

    return ResponseAction::Log;
}

bool AntiDebugImpl::ValidateConfiguration(const AntiDebugConfiguration& config) const {
    if (config.monitoringIntervalMs < AntiDebugConstants::MIN_CHECK_INTERVAL_MS) {
        return false;
    }

    if (config.monitoringIntervalMs > AntiDebugConstants::MAX_MONITOR_INTERVAL_MS) {
        return false;
    }

    if (config.detectionThreshold > 100) {
        return false;
    }

    return true;
}

void AntiDebugImpl::ApplyProtectionLevel(AntiDebugProtectionLevel level) {
    switch (level) {
        case AntiDebugProtectionLevel::Disabled:
            m_config.enabledTechniques = DetectionTechnique::None;
            m_config.responseActions = ResponseAction::None;
            break;

        case AntiDebugProtectionLevel::Minimal:
            m_config.enabledTechniques = DetectionTechnique::API_IsDebuggerPresent |
                                         DetectionTechnique::PEB_BeingDebugged;
            m_config.responseActions = ResponseAction::Log;
            break;

        case AntiDebugProtectionLevel::Standard:
            m_config.enabledTechniques = DetectionTechnique::All_PEB |
                                         DetectionTechnique::All_API;
            m_config.responseActions = ResponseAction::Passive;
            break;

        case AntiDebugProtectionLevel::Enhanced:
            m_config.enabledTechniques = DetectionTechnique::All_PEB |
                                         DetectionTechnique::All_API |
                                         DetectionTechnique::All_Hardware |
                                         DetectionTechnique::All_Process;
            m_config.responseActions = ResponseAction::Moderate;
            break;

        case AntiDebugProtectionLevel::Maximum:
        case AntiDebugProtectionLevel::Paranoid:
            m_config.enabledTechniques = DetectionTechnique::All;
            m_config.responseActions = ResponseAction::Aggressive;
            break;
    }
}

bool AntiDebugImpl::LoadNtdllFunctions() {
#ifdef _WIN32
    m_hNtdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!m_hNtdll) {
        return false;
    }

    m_pNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        ::GetProcAddress(m_hNtdll, "NtQueryInformationProcess"));

    m_pNtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(
        ::GetProcAddress(m_hNtdll, "NtSetInformationThread"));

    m_pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        ::GetProcAddress(m_hNtdll, "NtQuerySystemInformation"));

    m_pNtClose = reinterpret_cast<NtClose_t>(
        ::GetProcAddress(m_hNtdll, "NtClose"));

    return m_pNtQueryInformationProcess != nullptr;
#else
    return true;
#endif
}

std::vector<uint32_t> AntiDebugImpl::EnumerateThreadIds() const {
    std::vector<uint32_t> threadIds;

#ifdef _WIN32
    DWORD currentPid = ::GetCurrentProcessId();
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);

        if (::Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == currentPid) {
                    threadIds.push_back(te.th32ThreadID);
                }
            } while (::Thread32Next(hSnapshot, &te));
        }

        ::CloseHandle(hSnapshot);
    }
#endif

    return threadIds;
}

std::vector<std::pair<uint32_t, std::wstring>> AntiDebugImpl::EnumerateProcesses() const {
    std::vector<std::pair<uint32_t, std::wstring>> processes;

#ifdef _WIN32
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        if (::Process32FirstW(hSnapshot, &pe)) {
            do {
                processes.emplace_back(pe.th32ProcessID, pe.szExeFile);
            } while (::Process32NextW(hSnapshot, &pe));
        }

        ::CloseHandle(hSnapshot);
    }
#endif

    return processes;
}

#ifdef _WIN32
PPEB AntiDebugImpl::GetPEB() const noexcept {
#ifdef _WIN64
    return reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    return reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
}
#endif

// ============================================================================
// ANTIDEBUG CLASS IMPLEMENTATION (PUBLIC WRAPPER)
// ============================================================================

std::atomic<bool> AntiDebug::s_instanceCreated{false};

AntiDebug& AntiDebug::Instance() noexcept {
    static AntiDebug instance;
    return instance;
}

bool AntiDebug::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

AntiDebug::AntiDebug() : m_impl(std::make_unique<AntiDebugImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

AntiDebug::~AntiDebug() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool AntiDebug::Initialize(const AntiDebugConfiguration& config) {
    return m_impl->Initialize(config);
}

bool AntiDebug::Initialize(AntiDebugProtectionLevel level) {
    return m_impl->Initialize(AntiDebugConfiguration::FromProtectionLevel(level));
}

void AntiDebug::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool AntiDebug::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus AntiDebug::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

void AntiDebug::Pause() noexcept {
    m_impl->Pause();
}

void AntiDebug::Resume() noexcept {
    m_impl->Resume();
}

bool AntiDebug::SetConfiguration(const AntiDebugConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

AntiDebugConfiguration AntiDebug::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void AntiDebug::SetProtectionLevel(AntiDebugProtectionLevel level) {
    m_impl->SetProtectionLevel(level);
}

AntiDebugProtectionLevel AntiDebug::GetProtectionLevel() const noexcept {
    return m_impl->GetProtectionLevel();
}

void AntiDebug::SetMonitoringMode(MonitoringMode mode) {
    m_impl->SetMonitoringMode(mode);
}

MonitoringMode AntiDebug::GetMonitoringMode() const noexcept {
    return m_impl->GetMonitoringMode();
}

void AntiDebug::SetMonitoringInterval(uint32_t intervalMs) {
    m_impl->SetMonitoringInterval(intervalMs);
}

void AntiDebug::EnableTechnique(DetectionTechnique technique) {
    m_impl->EnableTechnique(technique);
}

void AntiDebug::DisableTechnique(DetectionTechnique technique) {
    m_impl->DisableTechnique(technique);
}

bool AntiDebug::IsTechniqueEnabled(DetectionTechnique technique) const noexcept {
    return m_impl->IsTechniqueEnabled(technique);
}

void AntiDebug::SetResponseActions(ResponseAction actions) {
    m_impl->SetResponseActions(actions);
}

ResponseAction AntiDebug::GetResponseActions() const noexcept {
    return m_impl->GetResponseActions();
}

void AntiDebug::AddToWhitelist(std::wstring_view processName) {
    m_impl->AddToWhitelist(processName);
}

void AntiDebug::RemoveFromWhitelist(std::wstring_view processName) {
    m_impl->RemoveFromWhitelist(processName);
}

bool AntiDebug::IsWhitelisted(std::wstring_view processName) const {
    return m_impl->IsWhitelisted(processName);
}

DetectionResult AntiDebug::PerformFullScan() {
    return m_impl->PerformFullScan();
}

DetectionResult AntiDebug::PerformQuickScan() {
    return m_impl->PerformQuickScan();
}

DetectionResult AntiDebug::PerformScan(DetectionTechnique techniques) {
    return m_impl->PerformScan(techniques);
}

bool AntiDebug::IsDebuggerDetected() const noexcept {
    return m_impl->IsDebuggerDetected();
}

DetectionResult AntiDebug::GetLastResult() const {
    return m_impl->GetLastResult();
}

uint32_t AntiDebug::GetDetectionScore() const noexcept {
    return m_impl->GetDetectionScore();
}

DetectionCheckResult AntiDebug::CheckPEB_BeingDebugged() {
    return m_impl->CheckPEB_BeingDebugged();
}

DetectionCheckResult AntiDebug::CheckPEB_NtGlobalFlag() {
    return m_impl->CheckPEB_NtGlobalFlag();
}

DetectionCheckResult AntiDebug::CheckPEB_HeapFlags() {
    return m_impl->CheckPEB_HeapFlags();
}

DetectionCheckResult AntiDebug::CheckPEB_ProcessHeap() {
    return m_impl->CheckPEB_ProcessHeap();
}

DetectionCheckResult AntiDebug::CheckAllPEB() {
    return m_impl->CheckAllPEB();
}

DetectionCheckResult AntiDebug::CheckAPI_IsDebuggerPresent() {
    return m_impl->CheckAPI_IsDebuggerPresent();
}

DetectionCheckResult AntiDebug::CheckAPI_CheckRemoteDebuggerPresent() {
    return m_impl->CheckAPI_CheckRemoteDebuggerPresent();
}

DetectionCheckResult AntiDebug::CheckAPI_NtQueryInformationProcess_DebugPort() {
    return m_impl->CheckAPI_NtQueryInformationProcess_DebugPort();
}

DetectionCheckResult AntiDebug::CheckAPI_NtQueryInformationProcess_DebugFlags() {
    return m_impl->CheckAPI_NtQueryInformationProcess_DebugFlags();
}

DetectionCheckResult AntiDebug::CheckAPI_NtQueryInformationProcess_DebugObjectHandle() {
    return m_impl->CheckAPI_NtQueryInformationProcess_DebugObjectHandle();
}

DetectionCheckResult AntiDebug::CheckAPI_OutputDebugString() {
    return m_impl->CheckAPI_OutputDebugString();
}

DetectionCheckResult AntiDebug::CheckAPI_CloseHandle() {
    return m_impl->CheckAPI_CloseHandle();
}

DetectionCheckResult AntiDebug::CheckAllAPI() {
    return m_impl->CheckAllAPI();
}

DetectionCheckResult AntiDebug::CheckTiming_RDTSC() {
    return m_impl->CheckTiming_RDTSC();
}

DetectionCheckResult AntiDebug::CheckTiming_QPC() {
    return m_impl->CheckTiming_QPC();
}

DetectionCheckResult AntiDebug::CheckTiming_GetTickCount() {
    return m_impl->CheckTiming_GetTickCount();
}

DetectionCheckResult AntiDebug::CheckTiming_InstructionExecution() {
    return m_impl->CheckTiming_InstructionExecution();
}

TimingAnalysis AntiDebug::PerformTimingAnalysis() {
    return m_impl->PerformTimingAnalysis();
}

DetectionCheckResult AntiDebug::CheckAllTiming() {
    return m_impl->CheckAllTiming();
}

DetectionCheckResult AntiDebug::CheckHardware_DebugRegisters() {
    return m_impl->CheckHardware_DebugRegisters();
}

DebugRegisterState AntiDebug::GetDebugRegisterState() {
    return m_impl->GetDebugRegisterState();
}

DetectionCheckResult AntiDebug::CheckHardware_BreakpointsViaContext() {
    return m_impl->CheckHardware_BreakpointsViaContext();
}

DetectionCheckResult AntiDebug::CheckAllHardware() {
    return m_impl->CheckAllHardware();
}

DetectionCheckResult AntiDebug::CheckException_INT3() {
    return m_impl->CheckException_INT3();
}

DetectionCheckResult AntiDebug::CheckException_INT2D() {
    return m_impl->CheckException_INT2D();
}

DetectionCheckResult AntiDebug::CheckException_SingleStep() {
    return m_impl->CheckException_SingleStep();
}

DetectionCheckResult AntiDebug::CheckException_GuardPage() {
    return m_impl->CheckException_GuardPage();
}

DetectionCheckResult AntiDebug::CheckException_VEH() {
    return m_impl->CheckException_VEH();
}

DetectionCheckResult AntiDebug::CheckAllException() {
    return m_impl->CheckAllException();
}

DetectionCheckResult AntiDebug::CheckMemory_SoftwareBreakpoints() {
    return m_impl->CheckMemory_SoftwareBreakpoints();
}

DetectionCheckResult AntiDebug::CheckMemory_SoftwareBreakpoints(uintptr_t address, size_t size) {
    return m_impl->CheckMemory_SoftwareBreakpoints(address, size);
}

DetectionCheckResult AntiDebug::CheckMemory_CodeIntegrity() {
    return m_impl->CheckMemory_CodeIntegrity();
}

DetectionCheckResult AntiDebug::CheckMemory_IATHooks() {
    return m_impl->CheckMemory_IATHooks();
}

DetectionCheckResult AntiDebug::CheckMemory_IATHooks(std::wstring_view moduleName) {
    return m_impl->CheckMemory_IATHooks(moduleName);
}

DetectionCheckResult AntiDebug::CheckMemory_InlineHooks() {
    return m_impl->CheckMemory_InlineHooks();
}

DetectionCheckResult AntiDebug::CheckMemory_InlineHooks(std::wstring_view moduleName) {
    return m_impl->CheckMemory_InlineHooks(moduleName);
}

std::vector<HookInfo> AntiDebug::GetDetectedHooks() const {
    return m_impl->GetDetectedHooks();
}

DetectionCheckResult AntiDebug::CheckAllMemory() {
    return m_impl->CheckAllMemory();
}

DetectionCheckResult AntiDebug::CheckProcess_ParentProcess() {
    return m_impl->CheckProcess_ParentProcess();
}

DetectionCheckResult AntiDebug::CheckProcess_DebuggerProcesses() {
    return m_impl->CheckProcess_DebuggerProcesses();
}

DetectionCheckResult AntiDebug::CheckProcess_DebuggerWindows() {
    return m_impl->CheckProcess_DebuggerWindows();
}

DetectionCheckResult AntiDebug::CheckProcess_DebuggerDrivers() {
    return m_impl->CheckProcess_DebuggerDrivers();
}

DetectionCheckResult AntiDebug::CheckProcess_InstrumentationFrameworks() {
    return m_impl->CheckProcess_InstrumentationFrameworks();
}

std::vector<DebuggerProcessInfo> AntiDebug::GetDetectedDebuggers() const {
    return m_impl->GetDetectedDebuggers();
}

DetectionCheckResult AntiDebug::CheckAllProcess() {
    return m_impl->CheckAllProcess();
}

bool AntiDebug::HideThread(uint32_t threadId) {
    return m_impl->HideThread(threadId);
}

size_t AntiDebug::HideAllThreads() {
    return m_impl->HideAllThreads();
}

bool AntiDebug::IsThreadHidden(uint32_t threadId) const {
    return m_impl->IsThreadHidden(threadId);
}

ThreadProtectionState AntiDebug::GetThreadProtectionState(uint32_t threadId) const {
    return m_impl->GetThreadProtectionState(threadId);
}

void AntiDebug::SecureThread() {
    m_impl->SecureThread();
}

bool AntiDebug::ProtectThread(uint32_t threadId) {
    return m_impl->ProtectThread(threadId);
}

bool AntiDebug::ClearDebugRegisters(uint32_t threadId) {
    return m_impl->ClearDebugRegisters(threadId);
}

size_t AntiDebug::ClearAllDebugRegisters() {
    return m_impl->ClearAllDebugRegisters();
}

void AntiDebug::SetAutoClearing(bool enable) {
    m_impl->SetAutoClearing(enable);
}

bool AntiDebug::RegisterIntegrityRegion(std::string_view id, uintptr_t address, size_t size) {
    return m_impl->RegisterIntegrityRegion(id, address, size);
}

bool AntiDebug::RegisterSelfIntegrity() {
    return m_impl->RegisterSelfIntegrity();
}

void AntiDebug::UnregisterIntegrityRegion(std::string_view id) {
    m_impl->UnregisterIntegrityRegion(id);
}

AntiDebugIntegrityStatus AntiDebug::VerifyIntegrity(std::string_view id) {
    return m_impl->VerifyIntegrity(id);
}

std::unordered_map<std::string, AntiDebugIntegrityStatus> AntiDebug::VerifyAllIntegrity() {
    return m_impl->VerifyAllIntegrity();
}

std::optional<IntegrityRegion> AntiDebug::GetIntegrityRegion(std::string_view id) const {
    return m_impl->GetIntegrityRegion(id);
}

std::vector<IntegrityRegion> AntiDebug::GetAllIntegrityRegions() const {
    return m_impl->GetAllIntegrityRegions();
}

bool AntiDebug::ExecuteResponse(ResponseAction action, const DetectionResult& result) {
    return m_impl->ExecuteResponse(action, result);
}

ResponseAction AntiDebug::ExecuteRecommendedResponse(const DetectionResult& result) {
    return m_impl->ExecuteRecommendedResponse(result);
}

uint64_t AntiDebug::RegisterDetectionCallback(DetectionCallback callback) {
    return m_impl->RegisterDetectionCallback(std::move(callback));
}

void AntiDebug::UnregisterDetectionCallback(uint64_t callbackId) {
    m_impl->UnregisterDetectionCallback(callbackId);
}

uint64_t AntiDebug::RegisterResponseCallback(ResponseCallback callback) {
    return m_impl->RegisterResponseCallback(std::move(callback));
}

void AntiDebug::UnregisterResponseCallback(uint64_t callbackId) {
    m_impl->UnregisterResponseCallback(callbackId);
}

uint64_t AntiDebug::RegisterIntegrityCallback(AntiDebugIntegrityCallback callback) {
    return m_impl->RegisterIntegrityCallback(std::move(callback));
}

void AntiDebug::UnregisterIntegrityCallback(uint64_t callbackId) {
    m_impl->UnregisterIntegrityCallback(callbackId);
}

uint64_t AntiDebug::RegisterHookCallback(HookCallback callback) {
    return m_impl->RegisterHookCallback(std::move(callback));
}

void AntiDebug::UnregisterHookCallback(uint64_t callbackId) {
    m_impl->UnregisterHookCallback(callbackId);
}

uint64_t AntiDebug::RegisterStatusCallback(StatusCallback callback) {
    return m_impl->RegisterStatusCallback(std::move(callback));
}

void AntiDebug::UnregisterStatusCallback(uint64_t callbackId) {
    m_impl->UnregisterStatusCallback(callbackId);
}

AntiDebugStatistics AntiDebug::GetStatistics() const {
    return m_impl->GetStatistics();
}

void AntiDebug::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<DetectionEvent> AntiDebug::GetDetectionHistory(size_t maxEntries) const {
    return m_impl->GetDetectionHistory(maxEntries);
}

void AntiDebug::ClearDetectionHistory() {
    m_impl->ClearDetectionHistory();
}

std::string AntiDebug::ExportReport() const {
    return m_impl->ExportReport();
}

std::string AntiDebug::GetVersionString() noexcept {
    return std::to_string(AntiDebugConstants::VERSION_MAJOR) + "." +
           std::to_string(AntiDebugConstants::VERSION_MINOR) + "." +
           std::to_string(AntiDebugConstants::VERSION_PATCH);
}

std::string AntiDebug::GetBuildInfo() noexcept {
    return "ShadowStrike AntiDebug v" + GetVersionString() + " (Tamper Protection Module)";
}

bool AntiDebug::SelfTest() {
    return m_impl->SelfTest();
}

void AntiDebug::ForceGarbageCollection() {
    m_impl->ForceGarbageCollection();
}

// ============================================================================
// KERNEL BRIDGE — INBOUND NOTIFICATIONS
// ============================================================================

void AntiDebug::OnKernelProcessNotify(uint32_t processId, uint32_t parentProcessId,
                                       std::wstring_view imagePath, bool isCreate) {
    m_impl->OnKernelProcessNotify(processId, parentProcessId, imagePath, isCreate);
}

void AntiDebug::OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                                   uintptr_t imageBase, size_t imageSize) {
    m_impl->OnKernelImageLoad(processId, imagePath, imageBase, imageSize);
}

bool AntiDebug::RequestKernelProcessBlock(uint32_t processId, std::string_view reason) {
    return m_impl->RequestKernelProcessBlock(processId, reason);
}

void AntiDebug::ReportDetectionToAlertSystem(const DetectionResult& result) {
    m_impl->ReportDetectionToAlertSystem(result);
}

void AntiDebug::ReportScanTelemetry(const DetectionResult& result) {
    m_impl->ReportScanTelemetry(result);
}

// ============================================================================
// KERNEL BRIDGE & WIRING IMPLEMENTATIONS (AntiDebugImpl)
// ============================================================================

void AntiDebugImpl::OnKernelProcessNotify(uint32_t processId, uint32_t parentProcessId,
                                           std::wstring_view imagePath, bool isCreate) {
    if (!isCreate || !IsInitialized()) {
        return;
    }

    // Extract process name from full image path
    std::wstring_view processName = imagePath;
    auto lastSlash = imagePath.find_last_of(L'\\');
    if (lastSlash != std::wstring_view::npos && lastSlash + 1 < imagePath.size()) {
        processName = imagePath.substr(lastSlash + 1);
    }

    // Check if the newly created process is a known debugger
    std::wstring lowerName(processName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    bool isDebugger = false;
    for (const auto& dbgName : AntiDebugConstants::DEBUGGER_PROCESSES) {
        std::wstring wDbgName = NarrowToWide(std::string(dbgName));
        std::transform(wDbgName.begin(), wDbgName.end(), wDbgName.begin(), ::towlower);

        if (lowerName == wDbgName) {
            isDebugger = true;
            break;
        }
    }

    if (!isDebugger) {
        return;
    }

    // Check whitelist before flagging
    if (IsWhitelisted(std::wstring(processName))) {
        SS_LOG_INFO(L"AntiDebug", L"Kernel: whitelisted debugger process %u (%.*ls)",
                    processId, static_cast<int>(processName.size()), processName.data());
        return;
    }

    SS_LOG_WARN(L"AntiDebug", L"Kernel: debugger process detected PID=%u parent=%u path=%.*ls",
                processId, parentProcessId,
                static_cast<int>(imagePath.size()), imagePath.data());

    // Record detection
    DebuggerProcessInfo info;
    info.processId = processId;
    info.processName = std::wstring(processName);
    info.type = DebuggerType::UserMode;
    info.confidence = DetectionConfidence::High;

    {
        std::unique_lock lock(m_mutex);
        m_detectedDebuggers.push_back(info);
    }

    m_debuggerDetected.store(true, std::memory_order_release);

    // Generate detection event
    DetectionEvent event;
    event.eventId = GenerateEventId();
    event.technique = DetectionTechnique::Process_DebuggerSearch;
    event.confidence = DetectionConfidence::High;
    event.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION;
    event.debuggerType = DebuggerType::UserMode;
    event.message = "Kernel: debugger process launched — PID " + std::to_string(processId);
    event.timestamp = Clock::now();
    event.threadId = GetCurrentThreadIdSafe();
    event.processId = GetCurrentProcessIdSafe();

    NotifyDetection(event);

    // Report to AlertSystem
    DetectionResult detResult;
    detResult.debuggerDetected = true;
    detResult.totalScore = AntiDebugConstants::WEIGHT_PROCESS_DETECTION;
    detResult.overallConfidence = DetectionConfidence::High;
    detResult.primaryDebuggerType = DebuggerType::UserMode;
    detResult.checksPerformed = 1;
    detResult.scanTimestamp = Clock::now();
    ReportDetectionToAlertSystem(detResult);

    // Request kernel to block if response actions include termination
    ResponseAction configured;
    {
        std::shared_lock lock(m_mutex);
        configured = m_config.responseActions;
    }
    if ((static_cast<uint32_t>(configured) &
         static_cast<uint32_t>(ResponseAction::SuspendDebugger)) != 0) {
        (void)RequestKernelProcessBlock(processId, "Known debugger process detected via kernel notify");
    }
}

void AntiDebugImpl::OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                                       uintptr_t imageBase, size_t imageSize) {
    if (!IsInitialized()) {
        return;
    }

    // Only care about images loaded into our own process
    if (processId != GetCurrentProcessIdSafe()) {
        return;
    }

    // Extract DLL name from full path
    std::wstring_view dllName = imagePath;
    auto lastSlash = imagePath.find_last_of(L'\\');
    if (lastSlash != std::wstring_view::npos && lastSlash + 1 < imagePath.size()) {
        dllName = imagePath.substr(lastSlash + 1);
    }

    // Check for known debugger DLLs being injected
    std::wstring lowerDll(dllName);
    std::transform(lowerDll.begin(), lowerDll.end(), lowerDll.begin(), ::towlower);

    static constexpr std::array<std::wstring_view, 8> kDebuggerDlls = {
        L"dbghelp.dll", L"dbgcore.dll", L"symsrv.dll", L"srcsrv.dll",
        L"vehdebug.dll", L"titanengine.dll", L"scyllahide.dll", L"sharpod.dll"
    };

    bool suspicious = false;
    for (const auto& dbgDll : kDebuggerDlls) {
        if (lowerDll == dbgDll) {
            suspicious = true;
            break;
        }
    }

    if (!suspicious) {
        return;
    }

    SS_LOG_WARN(L"AntiDebug", L"Kernel: suspicious DLL loaded into our process: %.*ls at 0x%IX size=%zu",
                static_cast<int>(dllName.size()), dllName.data(), imageBase, imageSize);

    // Register the loaded region for integrity monitoring
    std::string regionId = "kernel_img_" + WideToNarrow(std::wstring(dllName));
    (void)RegisterIntegrityRegion(regionId, imageBase, std::min(imageSize, static_cast<size_t>(4096)));

    // Generate detection event
    DetectionEvent event;
    event.eventId = GenerateEventId();
    event.technique = DetectionTechnique::Process_DebuggerSearch;
    event.confidence = DetectionConfidence::Medium;
    event.score = AntiDebugConstants::WEIGHT_PROCESS_DETECTION / 2;
    event.debuggerType = DebuggerType::Instrumentation;
    event.message = "Kernel: debugger DLL loaded — " + WideToNarrow(std::wstring(dllName));
    event.timestamp = Clock::now();
    event.threadId = GetCurrentThreadIdSafe();
    event.processId = processId;

    NotifyDetection(event);
}

bool AntiDebugImpl::RequestKernelProcessBlock(uint32_t processId, std::string_view reason) {
    using namespace Communication;

    if (!IPCManager::HasInstance()) {
        SS_LOG_DEBUG(L"AntiDebug", L"RequestKernelProcessBlock: IPCManager not available");
        return false;
    }

    auto& ipc = IPCManager::Instance();
    if (!ipc.IsFilterPortConnected()) {
        SS_LOG_WARN(L"AntiDebug", L"RequestKernelProcessBlock: kernel port not connected");
        return false;
    }

    // Build IPC message: msgType(4) + PID(4) + reasonLen(4) + reason(N)
    constexpr uint32_t kMsgTypeAntiDebugBlock = 0x00AD0001;
    const uint32_t reasonLen = static_cast<uint32_t>(std::min(reason.size(), static_cast<size_t>(256)));
    const size_t totalSize = sizeof(uint32_t) * 3 + reasonLen;

    std::vector<uint8_t> buffer(totalSize);
    uint8_t* ptr = buffer.data();

    std::memcpy(ptr, &kMsgTypeAntiDebugBlock, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    std::memcpy(ptr, &processId, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    std::memcpy(ptr, &reasonLen, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    std::memcpy(ptr, reason.data(), reasonLen);

    bool sent = ipc.SendToKernel(buffer.data(), buffer.size());
    if (sent) {
        SS_LOG_INFO(L"AntiDebug", L"Kernel process block requested for PID %u", processId);
    } else {
        SS_LOG_ERROR(L"AntiDebug", L"Failed to send kernel block request for PID %u", processId);
    }
    return sent;
}

void AntiDebugImpl::ReportDetectionToAlertSystem(const DetectionResult& result) {
    using namespace Communication;

    if (!AlertSystem::HasInstance()) {
        return;
    }

    auto& alerts = AlertSystem::Instance();

    // Map detection confidence to alert severity
    AlertSeverity severity = AlertSeverity::Medium;
    if (result.overallConfidence == DetectionConfidence::Critical) {
        severity = AlertSeverity::Critical;
    } else if (result.overallConfidence == DetectionConfidence::High) {
        severity = AlertSeverity::High;
    } else if (result.overallConfidence == DetectionConfidence::Low) {
        severity = AlertSeverity::Low;
    }

    std::string summary = "Debugger/tampering detected — score: " + std::to_string(result.totalScore)
                        + ", type: " + std::string(GetDebuggerTypeName(result.primaryDebuggerType));

    (void)alerts.RaiseAlert(
        severity,
        AlertType::ThreatDetection,
        "AntiDebug",
        summary,
        "AntiDebug module v" + AntiDebug::GetVersionString()
    );
}

void AntiDebugImpl::ReportScanTelemetry(const DetectionResult& result) {
    using namespace Communication;

    if (!TelemetryCollector::HasInstance()) {
        return;
    }

    auto& telemetry = TelemetryCollector::Instance();

    std::map<std::string, std::string> fields;
    fields["module"] = "AntiDebug";
    fields["version"] = AntiDebug::GetVersionString();
    fields["debugger_detected"] = result.debuggerDetected ? "true" : "false";
    fields["total_score"] = std::to_string(result.totalScore);
    fields["checks_performed"] = std::to_string(result.checksPerformed);
    fields["confidence"] = std::string(GetConfidenceName(result.overallConfidence));
    fields["debugger_type"] = std::string(GetDebuggerTypeName(result.primaryDebuggerType));
    fields["scan_duration_us"] = std::to_string(
        std::chrono::duration_cast<Microseconds>(Clock::now() - result.scanTimestamp).count());

    telemetry.RecordCustom("antidebug_scan", fields);
}

// ============================================================================
// CONFIGURATION METHODS
// ============================================================================

AntiDebugConfiguration AntiDebugConfiguration::FromProtectionLevel(AntiDebugProtectionLevel level) {
    AntiDebugConfiguration config;
    config.protectionLevel = level;

    switch (level) {
        case AntiDebugProtectionLevel::Disabled:
            config.enabledTechniques = DetectionTechnique::None;
            config.responseActions = ResponseAction::None;
            config.monitoringMode = MonitoringMode::Disabled;
            config.enableCodeIntegrity = false;
            config.enableHookDetection = false;
            config.enableTimingDetection = false;
            config.enableExceptionDetection = false;
            config.enableProcessDetection = false;
            config.enableHardwareDetection = false;
            config.autoHideThreads = false;
            config.autoClearDebugRegisters = false;
            config.sendTelemetry = false;
            break;

        case AntiDebugProtectionLevel::Minimal:
            config.enabledTechniques = DetectionTechnique::API_IsDebuggerPresent |
                                       DetectionTechnique::PEB_BeingDebugged;
            config.responseActions = ResponseAction::Log;
            config.monitoringMode = MonitoringMode::OnDemand;
            break;

        case AntiDebugProtectionLevel::Standard:
            config.enabledTechniques = DetectionTechnique::All_PEB |
                                       DetectionTechnique::All_API;
            config.responseActions = ResponseAction::Passive;
            config.monitoringMode = MonitoringMode::Periodic;
            break;

        case AntiDebugProtectionLevel::Enhanced:
            config.enabledTechniques = DetectionTechnique::All_PEB |
                                       DetectionTechnique::All_API |
                                       DetectionTechnique::All_Hardware |
                                       DetectionTechnique::All_Process;
            config.responseActions = ResponseAction::Moderate;
            config.monitoringMode = MonitoringMode::Periodic;
            config.enableCodeIntegrity = true;
            config.enableHookDetection = true;
            break;

        case AntiDebugProtectionLevel::Maximum:
        case AntiDebugProtectionLevel::Paranoid:
            config.enabledTechniques = DetectionTechnique::All;
            config.responseActions = ResponseAction::Aggressive;
            config.monitoringMode = MonitoringMode::Continuous;
            config.enableCodeIntegrity = true;
            config.enableHookDetection = true;
            config.enableTimingDetection = true;
            config.enableExceptionDetection = true;
            config.autoHideThreads = true;
            config.autoClearDebugRegisters = true;
            break;
    }

    return config;
}

bool AntiDebugConfiguration::IsValid() const noexcept {
    if (monitoringIntervalMs < AntiDebugConstants::MIN_CHECK_INTERVAL_MS) {
        return false;
    }

    if (monitoringIntervalMs > AntiDebugConstants::MAX_MONITOR_INTERVAL_MS) {
        return false;
    }

    if (detectionThreshold > 100) {
        return false;
    }

    return true;
}

void AntiDebugConfiguration::Merge(const AntiDebugConfiguration& other) {
    if (other.protectionLevel != AntiDebugProtectionLevel::Standard) {
        protectionLevel = other.protectionLevel;
    }

    enabledTechniques = enabledTechniques | other.enabledTechniques;
    responseActions = responseActions | other.responseActions;

    if (!other.whitelistedProcesses.empty()) {
        for (const auto& proc : other.whitelistedProcesses) {
            whitelistedProcesses.push_back(proc);
        }
    }
}

// ============================================================================
// STRUCTURE METHODS
// ============================================================================

std::string DetectionResult::GetSummary() const {
    std::ostringstream oss;

    if (debuggerDetected) {
        oss << "DEBUGGER DETECTED - ";
    } else {
        oss << "No debugger detected - ";
    }

    oss << "Score: " << totalScore << ", ";
    oss << "Checks: " << checksTriggered << "/" << checksPerformed << ", ";
    oss << "Confidence: " << static_cast<int>(overallConfidence) << ", ";
    oss << "Duration: " << scanDuration.count() << "ms";

    return oss.str();
}

std::string DetectionResult::ToJson() const {
    std::ostringstream oss;

    oss << "{\n";
    oss << "  \"debuggerDetected\": " << (debuggerDetected ? "true" : "false") << ",\n";
    oss << "  \"totalScore\": " << totalScore << ",\n";
    oss << "  \"overallConfidence\": " << static_cast<int>(overallConfidence) << ",\n";
    oss << "  \"primaryDebuggerType\": " << static_cast<int>(primaryDebuggerType) << ",\n";
    oss << "  \"checksPerformed\": " << checksPerformed << ",\n";
    oss << "  \"checksTriggered\": " << checksTriggered << ",\n";
    oss << "  \"scanDurationMs\": " << scanDuration.count() << ",\n";
    oss << "  \"possibleFalsePositive\": " << (possibleFalsePositive ? "true" : "false") << "\n";
    oss << "}";

    return oss.str();
}

uint32_t DebugRegisterState::GetActiveBreakpointCount() const noexcept {
    uint32_t count = 0;
    const uintptr_t addresses[4] = {dr0, dr1, dr2, dr3};

    for (uint32_t slot = 0; slot < 4; ++slot) {
        const uintptr_t enableMask = static_cast<uintptr_t>(0x3u) << (slot * 2u);
        if (addresses[slot] != 0 || (dr7 & enableMask) != 0) {
            ++count;
        }
    }

    return count;
}

void AntiDebugStatistics::Reset() noexcept {
    totalChecks = 0;
    totalDetections = 0;
    falsePositives = 0;
    actionsExecuted = 0;
    threadsHidden = 0;
    breakpointsCleared = 0;
    hooksDetected = 0;
    integrityViolations = 0;
    avgCheckDurationUs = 0;
    maxCheckDurationUs = 0;
    detectionsByTechnique.clear();
    detectionsByType.clear();
    startTime = Clock::now();
    lastDetectionTime = TimePoint{};
    lastCheckTime = TimePoint{};
}

std::string AntiDebugStatistics::ToJson() const {
    std::ostringstream oss;

    oss << "{\n";
    oss << "  \"totalChecks\": " << totalChecks << ",\n";
    oss << "  \"totalDetections\": " << totalDetections << ",\n";
    oss << "  \"falsePositives\": " << falsePositives << ",\n";
    oss << "  \"actionsExecuted\": " << actionsExecuted << ",\n";
    oss << "  \"threadsHidden\": " << threadsHidden << ",\n";
    oss << "  \"breakpointsCleared\": " << breakpointsCleared << ",\n";
    oss << "  \"hooksDetected\": " << hooksDetected << ",\n";
    oss << "  \"integrityViolations\": " << integrityViolations << ",\n";
    oss << "  \"avgCheckDurationUs\": " << avgCheckDurationUs << ",\n";
    oss << "  \"maxCheckDurationUs\": " << maxCheckDurationUs << ",\n";
    oss << "  \"uptimeSeconds\": " << GetUptimeSeconds() << "\n";
    oss << "}";

    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetTechniqueName(DetectionTechnique technique) noexcept {
    switch (technique) {
        case DetectionTechnique::None: return "None";
        case DetectionTechnique::PEB_BeingDebugged: return "PEB.BeingDebugged";
        case DetectionTechnique::PEB_NtGlobalFlag: return "PEB.NtGlobalFlag";
        case DetectionTechnique::PEB_HeapFlags: return "PEB.HeapFlags";
        case DetectionTechnique::API_IsDebuggerPresent: return "IsDebuggerPresent";
        case DetectionTechnique::API_CheckRemoteDebugger: return "CheckRemoteDebuggerPresent";
        case DetectionTechnique::API_NtQueryInfoProcess: return "NtQueryInformationProcess";
        case DetectionTechnique::Timing_RDTSC: return "RDTSC Timing";
        case DetectionTechnique::Timing_QPC: return "QPC Timing";
        case DetectionTechnique::Hardware_DebugRegisters: return "Debug Registers";
        case DetectionTechnique::Memory_Breakpoints: return "Software Breakpoints";
        case DetectionTechnique::Memory_InlineHooks: return "Inline Hooks";
        case DetectionTechnique::Process_DebuggerSearch: return "Debugger Process Search";
        default: return "Unknown";
    }
}

std::string_view GetDebuggerTypeName(DebuggerType type) noexcept {
    switch (type) {
        case DebuggerType::Unknown: return "Unknown";
        case DebuggerType::UserMode: return "User-Mode";
        case DebuggerType::KernelMode: return "Kernel-Mode";
        case DebuggerType::Remote: return "Remote";
        case DebuggerType::Attached: return "Attached";
        case DebuggerType::JustInTime: return "Just-In-Time";
        case DebuggerType::Instrumentation: return "Instrumentation";
        case DebuggerType::Sandbox: return "Sandbox";
        case DebuggerType::VirtualMachine: return "Virtual Machine";
        default: return "Unknown";
    }
}

std::string_view GetConfidenceName(DetectionConfidence confidence) noexcept {
    switch (confidence) {
        case DetectionConfidence::None: return "None";
        case DetectionConfidence::Low: return "Low";
        case DetectionConfidence::Medium: return "Medium";
        case DetectionConfidence::High: return "High";
        case DetectionConfidence::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetResponseActionName(ResponseAction action) noexcept {
    switch (action) {
        case ResponseAction::None: return "None";
        case ResponseAction::Log: return "Log";
        case ResponseAction::Alert: return "Alert";
        case ResponseAction::HideThreads: return "Hide Threads";
        case ResponseAction::ClearBreakpoints: return "Clear Breakpoints";
        default: return "Multiple";
    }
}

std::string_view GetHookTypeName(HookType type) noexcept {
    switch (type) {
        case HookType::None: return "None";
        case HookType::InlineJump: return "Inline Jump";
        case HookType::InlineCall: return "Inline Call";
        case HookType::IAT: return "IAT";
        case HookType::EAT: return "EAT";
        case HookType::VTable: return "VTable";
        case HookType::HotPatch: return "Hot Patch";
        case HookType::Trampoline: return "Trampoline";
        case HookType::PageGuard: return "Page Guard";
        case HookType::Hardware: return "Hardware";
        default: return "Unknown";
    }
}

std::string_view GetProtectionLevelName(AntiDebugProtectionLevel level) noexcept {
    switch (level) {
        case AntiDebugProtectionLevel::Disabled: return "Disabled";
        case AntiDebugProtectionLevel::Minimal: return "Minimal";
        case AntiDebugProtectionLevel::Standard: return "Standard";
        case AntiDebugProtectionLevel::Enhanced: return "Enhanced";
        case AntiDebugProtectionLevel::Maximum: return "Maximum";
        case AntiDebugProtectionLevel::Paranoid: return "Paranoid";
        default: return "Unknown";
    }
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

ScopedThreadProtection::ScopedThreadProtection() noexcept
    : m_threadId(GetCurrentThreadIdSafe()) {

    if (AntiDebug::HasInstance()) {
        m_protected = AntiDebug::Instance().ProtectThread(m_threadId);
    }
}

ScopedThreadProtection::ScopedThreadProtection(uint32_t threadId) noexcept
    : m_threadId(threadId == 0 ? GetCurrentThreadIdSafe() : threadId) {

    if (AntiDebug::HasInstance()) {
        m_protected = AntiDebug::Instance().ProtectThread(m_threadId);
    }
}

ScopedAntiDebugPause::ScopedAntiDebugPause() noexcept {
    if (AntiDebug::HasInstance()) {
        m_wasPaused = AntiDebug::Instance().GetStatus() == ModuleStatus::Paused;
        if (!m_wasPaused) {
            AntiDebug::Instance().Pause();
        }
    }
}

ScopedAntiDebugPause::~ScopedAntiDebugPause() noexcept {
    if (AntiDebug::HasInstance() && !m_wasPaused) {
        AntiDebug::Instance().Resume();
    }
}

IntegrityGuard::IntegrityGuard(std::string_view id, uintptr_t address, size_t size)
    : m_id(id) {

    if (AntiDebug::HasInstance()) {
        m_registered = AntiDebug::Instance().RegisterIntegrityRegion(id, address, size);
    }
}

IntegrityGuard::~IntegrityGuard() {
    if (m_registered && AntiDebug::HasInstance()) {
        AntiDebug::Instance().UnregisterIntegrityRegion(m_id);
    }
}

IntegrityGuard::IntegrityGuard(IntegrityGuard&& other) noexcept
    : m_id(std::move(other.m_id))
    , m_registered(other.m_registered) {
    other.m_registered = false;
}

IntegrityGuard& IntegrityGuard::operator=(IntegrityGuard&& other) noexcept {
    if (this != &other) {
        if (m_registered && AntiDebug::HasInstance()) {
            AntiDebug::Instance().UnregisterIntegrityRegion(m_id);
        }

        m_id = std::move(other.m_id);
        m_registered = other.m_registered;
        other.m_registered = false;
    }
    return *this;
}

AntiDebugIntegrityStatus IntegrityGuard::Verify() {
    if (m_registered && AntiDebug::HasInstance()) {
        return AntiDebug::Instance().VerifyIntegrity(m_id);
    }
    return AntiDebugIntegrityStatus::Unknown;
}

}  // namespace Security
}  // namespace ShadowStrike
