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
 * ShadowStrike Core Process - THREAD HIJACK DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ThreadHijackDetector.cpp
 * @brief Enterprise-grade thread execution hijacking detection engine implementation
 *
 * Production-level implementation competing with enterprise-grade enterprise-grade EDR,
 * enterprise-grade EDR, and enterprise-grade GravityZone for thread hijack detection.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Real-time monitoring with dedicated worker thread
 * - Thread context validation (RIP/EIP, RSP/ESP, segments)
 * - Cross-process context modification detection
 * - Suspend→SetContext→Resume sequence correlation (100ms window)
 * - RIP validation (module-backed vs unbacked memory)
 * - Stack validation (valid stack region vs pivot)
 * - Call stack analysis (unbacked frame detection)
 * - Debug register monitoring (hardware breakpoints)
 * - Shellcode pattern detection at RIP
 * - Confidence scoring (None/Low/Medium/High/Confirmed)
 * - Risk scoring (0-100 scale)
 * - MITRE ATT&CK T1055.003 mapping
 * - Automatic response (block/restore/terminate)
 * - Infrastructure reuse (ThreatIntel, PatternStore, Whitelist)
 * - Comprehensive statistics tracking
 * - Alert generation with callbacks
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ThreadHijackDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "MemoryScanner.hpp"

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <thread>
#include <deque>
#include <unordered_set>
#include <map>
#include <condition_variable>

namespace ShadowStrike {
namespace Core {
namespace Process {

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// RAII HANDLE GUARD — eliminates all handle leaks
// ============================================================================

class HandleGuard {
public:
    explicit HandleGuard(HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~HandleGuard() noexcept { if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_handle && m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle = nullptr;
};

// ============================================================================
// NTDLL DYNAMIC LINKAGE — for thread start address and TEB access
// ============================================================================

// ThreadInformationClass values not in winternl.h
constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

// THREAD_BASIC_INFORMATION may not be fully exposed by the SDK
struct SS_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

static NtQueryInformationThreadFn GetNtQueryInformationThread() noexcept {
    static auto fn = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread")
    );
    return fn;
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Check if address is within any module in the process.
 */
[[nodiscard]] static bool IsAddressInModule(uint32_t pid, uintptr_t address) noexcept {
    try {
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(pid, modules)) {
            return false;
        }
        for (const auto& mod : modules) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mod.baseAddress);
            const uintptr_t end = base + mod.size;
            if (address >= base && address < end) {
                return true;
            }
        }
    } catch (...) {
        // Swallow — process may have exited
    }
    return false;
}

/**
 * @brief Get module name containing an address.
 */
[[nodiscard]] static std::wstring GetModuleForAddress(uint32_t pid, uintptr_t address) noexcept {
    try {
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        if (!Utils::ProcessUtils::EnumerateProcessModules(pid, modules)) {
            return L"<unknown>";
        }
        for (const auto& mod : modules) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mod.baseAddress);
            const uintptr_t end = base + mod.size;
            if (address >= base && address < end) {
                return mod.name;
            }
        }
    } catch (...) {
    }
    return L"<unbacked>";
}

/**
 * @brief Detect shellcode patterns at an address using MemoryScanner integration.
 *
 * First queries MemoryScanner for region metadata (RWX/private/entropy),
 * then falls back to pattern matching if scanner unavailable.
 */
[[nodiscard]] static bool HasShellcodeAtAddress(uint32_t pid, uintptr_t address) noexcept {
    try {
        // Primary: use MemoryScanner for professional shellcode detection
        auto& scanner = MemoryScanner::Instance();
        if (scanner.IsInitialized()) {
            auto regionInfo = scanner.GetRegionInfo(pid, address);
            if (regionInfo.has_value()) {
                // Private + executable memory is highly suspicious
                if (regionInfo->isPrivate && regionInfo->isExecutable) {
                    return true;
                }
                // RWX memory is almost always shellcode
                if (regionInfo->isExecutable && regionInfo->isWritable && regionInfo->isPrivate) {
                    return true;
                }
            }
        }

        // Fallback: direct memory read for signature patterns
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return false;

        std::array<uint8_t, 256> buffer{};
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess.get(), reinterpret_cast<LPCVOID>(address),
                             buffer.data(), buffer.size(), &bytesRead)) {
            return false;
        }

        if (bytesRead < 20) return false;

        // NOP sled detection (20+ consecutive NOPs = likely shellcode)
        uint32_t nopCount = 0;
        for (size_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == 0x90) {
                nopCount++;
                if (nopCount >= 20) return true;
            } else {
                nopCount = 0;
            }
        }

        // Common x64 shellcode prologues
        const std::array<std::pair<std::array<uint8_t, 4>, const char*>, 3> shellcodeSignatures = {{
            {{0x48, 0x31, 0xC9, 0x48}, "x64 xor rcx,rcx; rex prefix"},
            {{0x48, 0x83, 0xEC, 0x28}, "x64 sub rsp,0x28 (shadow space)"},
            {{0xFC, 0x48, 0x83, 0xE4}, "x64 cld; and rsp (align stack)"},
        }};

        for (const auto& [sig, _] : shellcodeSignatures) {
            for (size_t i = 0; i + 4 <= bytesRead; ++i) {
                if (std::memcmp(&buffer[i], sig.data(), 4) == 0) {
                    return true;
                }
            }
        }

    } catch (...) {
    }
    return false;
}

/**
 * @brief Check if context change is suspicious.
 */
[[nodiscard]] static bool IsSuspiciousContextChange(
    uint64_t oldRIP,
    uint64_t newRIP,
    uint64_t oldRSP,
    uint64_t newRSP) noexcept
{
    const bool ripChanged = (oldRIP != newRIP);

    // Stack pivot: compute absolute delta safely (avoid signed overflow UB)
    const uint64_t stackDelta = (newRSP > oldRSP) ? (newRSP - oldRSP) : (oldRSP - newRSP);
    const bool stackPivoted = (stackDelta > 0x100000);  // >1MB change

    return ripChanged || stackPivoted;
}

/**
 * @brief Check if a memory region at an address has executable + private attributes.
 */
[[nodiscard]] static bool IsAddressInRWXPrivate(uint32_t pid, uintptr_t address) noexcept {
    try {
        auto& scanner = MemoryScanner::Instance();
        if (scanner.IsInitialized()) {
            auto region = scanner.GetRegionInfo(pid, address);
            if (region.has_value()) {
                return region->isPrivate && region->isExecutable;
            }
        }

        // Fallback: VirtualQueryEx
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(address),
                          &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        const bool isPrivate = (mbi.Type == MEM_PRIVATE);
        const bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        return isPrivate && isExec;
    } catch (...) {
        return false;
    }
}

/**
 * @brief Get thread's actual stack bounds via NtQueryInformationThread(ThreadBasicInformation).
 */
[[nodiscard]] static bool GetThreadStackBounds(
    HANDLE hThread,
    uintptr_t& stackBase,
    uintptr_t& stackLimit) noexcept
{
    auto ntQueryThread = GetNtQueryInformationThread();
    if (!ntQueryThread) return false;

    SS_THREAD_BASIC_INFORMATION tbi{};
    ULONG returnLength = 0;
    NTSTATUS status = ntQueryThread(
        hThread, 0 /* ThreadBasicInformation */, &tbi, sizeof(tbi), &returnLength);

    if (status != 0 || !tbi.TebBaseAddress) return false;

    // Read stack bounds from TEB (Thread Environment Block)
    // TEB.NtTib.StackBase is at offset 0x08 (x64)
    // TEB.NtTib.StackLimit is at offset 0x10 (x64)
    HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE,
        GetProcessIdOfThread(hThread)));
    if (!hProcess) return false;

    struct {
        uintptr_t stackBaseVal;
        uintptr_t stackLimitVal;
    } stackInfo{};

    SIZE_T bytesRead = 0;
    // TEB offset 0x08 = StackBase, 0x10 = StackLimit
    const auto tebAddr = reinterpret_cast<const uint8_t*>(tbi.TebBaseAddress);
    if (!ReadProcessMemory(hProcess.get(), tebAddr + 0x08,
                          &stackInfo, sizeof(stackInfo), &bytesRead)) {
        return false;
    }

    if (bytesRead < sizeof(stackInfo)) return false;

    stackBase = stackInfo.stackBaseVal;
    stackLimit = stackInfo.stackLimitVal;
    return (stackBase > stackLimit && stackBase > 0x10000);
}

/**
 * @brief Calculate risk score for a hijack event.
 */
[[nodiscard]] static uint32_t CalculateRiskScore(
    bool ripUnbacked,
    bool hasShellcode,
    bool crossProcess,
    bool stackPivoted,
    bool debugRegsActive,
    uint32_t suspendDurationMs,
    bool isRWXPrivate = false) noexcept
{
    uint32_t risk = 0;

    if (ripUnbacked)     risk += 40;
    if (hasShellcode)    risk += 25;
    if (crossProcess)    risk += 20;
    if (stackPivoted)    risk += 15;
    if (isRWXPrivate)    risk += 15;
    if (debugRegsActive) risk += 10;
    if (suspendDurationMs > 500) risk += 5;

    return std::min(risk, 100u);
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

ThreadHijackConfig ThreadHijackConfig::CreateDefault() noexcept {
    return ThreadHijackConfig{};
}

ThreadHijackConfig ThreadHijackConfig::CreateHighSensitivity() noexcept {
    ThreadHijackConfig config;
    config.mode = MonitoringMode::Active;
    config.enableRealTimeMonitoring = true;
    config.enableOnDemandScanning = true;
    config.validateInstructionPointer = true;
    config.validateStackPointer = true;
    config.validateSegmentRegisters = true;
    config.checkDebugRegisters = true;
    config.analyzeCallStack = true;
    config.trackContextChanges = true;
    config.detectCrossProcessModification = true;
    config.alertThreshold = DetectionConfidence::Low;
    config.maxUnbackedFrames = 0;  // Zero tolerance
    config.blockSuspiciousChanges = true;
    return config;
}

ThreadHijackConfig ThreadHijackConfig::CreatePerformance() noexcept {
    ThreadHijackConfig config;
    config.mode = MonitoringMode::PassiveOnly;
    config.enableRealTimeMonitoring = false;
    config.enableOnDemandScanning = true;
    config.validateInstructionPointer = true;
    config.validateStackPointer = false;
    config.validateSegmentRegisters = false;
    config.checkDebugRegisters = false;
    config.analyzeCallStack = false;
    config.trackContextChanges = false;
    config.detectCrossProcessModification = true;
    config.alertThreshold = DetectionConfidence::High;
    config.blockSuspiciousChanges = false;
    return config;
}

void ThreadHijackStatistics::Reset() noexcept {
    threadsMonitored.store(0, std::memory_order_relaxed);
    threadValidations.store(0, std::memory_order_relaxed);
    contextReads.store(0, std::memory_order_relaxed);
    hijacksDetected.store(0, std::memory_order_relaxed);
    ripModifications.store(0, std::memory_order_relaxed);
    stackPivots.store(0, std::memory_order_relaxed);
    crossProcessChanges.store(0, std::memory_order_relaxed);
    unbackedRIPDetected.store(0, std::memory_order_relaxed);
    shellcodeRIPDetected.store(0, std::memory_order_relaxed);
    lowConfidenceDetections.store(0, std::memory_order_relaxed);
    mediumConfidenceDetections.store(0, std::memory_order_relaxed);
    highConfidenceDetections.store(0, std::memory_order_relaxed);
    confirmedHijacks.store(0, std::memory_order_relaxed);
    changesBlocked.store(0, std::memory_order_relaxed);
    contextsRestored.store(0, std::memory_order_relaxed);
    attackersTerminated.store(0, std::memory_order_relaxed);
    callStacksAnalyzed.store(0, std::memory_order_relaxed);
    unbackedFramesDetected.store(0, std::memory_order_relaxed);
    totalScanTimeMs.store(0, std::memory_order_relaxed);
    scansPerformed.store(0, std::memory_order_relaxed);
    scanErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    timeoutErrors.store(0, std::memory_order_relaxed);
}

[[nodiscard]] double ThreadHijackStatistics::GetDetectionRate() const noexcept {
    const uint64_t total = threadValidations.load(std::memory_order_relaxed);
    const uint64_t detected = hijacksDetected.load(std::memory_order_relaxed);

    if (total == 0) return 0.0;
    return (static_cast<double>(detected) / total) * 100.0;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ThreadHijackDetectorImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    ThreadHijackConfig m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};

    /// @brief Statistics
    ThreadHijackStatistics m_statistics;

    /// @brief Monitored threads
    std::unordered_map<uint32_t, MonitoredThread> m_threads;
    mutable std::shared_mutex m_threadsMutex;

    /// @brief Hijack events
    std::deque<HijackEvent> m_hijackEvents;
    mutable std::shared_mutex m_eventsMutex;
    std::atomic<uint64_t> m_nextEventId{1};

    /// @brief Thread state tracking (for suspend/resume correlation)
    struct ThreadStateTracking {
        uint32_t tid;
        uint32_t suspenderPid{0};
        TimePoint suspendTime;
        bool isSuspended{false};
    };
    std::unordered_map<uint32_t, ThreadStateTracking> m_threadStates;
    mutable std::shared_mutex m_statesMutex;

    /// @brief Callbacks
    std::unordered_map<uint64_t, HijackDetectedCallback> m_hijackCallbacks;
    std::unordered_map<uint64_t, ContextChangeCallback> m_contextCallbacks;
    std::unordered_map<uint64_t, ValidationCallback> m_validationCallbacks;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    /// @brief Infrastructure integrations
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    /// @brief Monitoring thread
    std::thread m_monitorThread;
    std::atomic<bool> m_stopMonitoring{false};
    std::mutex m_monitorCvMutex;
    std::condition_variable m_monitorCv;

    /// @brief Cleanup thread
    std::thread m_cleanupThread;
    std::atomic<bool> m_stopCleanup{false};
    std::mutex m_cleanupCvMutex;
    std::condition_variable m_cleanupCv;

    // ========================================================================
    // METHODS
    // ========================================================================

    ThreadHijackDetectorImpl() = default;
    ~ThreadHijackDetectorImpl() = default;

    [[nodiscard]] bool Initialize(const ThreadHijackConfig& config);
    void Shutdown();
    bool StartMonitoring();
    void StopMonitoring();

    // Thread validation
    [[nodiscard]] ThreadValidation ValidateThreadInternal(uint32_t tid);
    [[nodiscard]] bool ValidateThreadStartInternal(uint32_t tid);
    [[nodiscard]] bool IsRIPValidInternal(uint32_t tid);
    [[nodiscard]] bool IsStackValidInternal(uint32_t tid);
    [[nodiscard]] std::vector<uintptr_t> GetCallStackInternal(uint32_t tid, uint32_t maxFrames);
    [[nodiscard]] uint32_t CountUnbackedFramesInternal(uint32_t tid);

    // Context analysis
    [[nodiscard]] ThreadContext64 GetThreadContextInternal(uint32_t tid);
    [[nodiscard]] std::vector<ContextChange> CompareContextsInternal(
        const ThreadContext64& before,
        const ThreadContext64& after,
        uint32_t pid);
    [[nodiscard]] ValidationResult AnalyzeContextInternal(const ThreadContext64& context, uint32_t pid);
    [[nodiscard]] bool HasActiveDebugRegistersInternal(uint32_t tid);

    // Hijack detection
    [[nodiscard]] std::optional<HijackEvent> DetectHijackInternal(uint32_t tid);
    [[nodiscard]] ScanResult ScanProcessInternal(uint32_t pid);

    // Event handlers
    void OnThreadSuspendInternal(uint32_t targetTid, uint32_t suspenderPid);
    void OnThreadResumeInternal(uint32_t targetTid, uint32_t resumerPid);
    void OnContextChangeInternal(uint32_t targetTid, uint32_t modifierPid, uint32_t contextFlags);
    void OnSetContextThreadInternal(uint32_t callerPid, uint32_t targetTid, const ThreadContext64& newContext);

    // Response actions
    bool BlockContextChangeInternal(uint32_t targetTid, uint32_t modifierPid);
    bool RestoreContextInternal(uint32_t tid);
    bool TerminateAttackerInternal(const HijackEvent& event);

    // Baseline management
    void EstablishBaselineInternal(uint32_t tid);
    void ClearBaselineInternal(uint32_t tid);
    [[nodiscard]] std::optional<ThreadContext64> GetBaselineInternal(uint32_t tid) const;

    // Worker threads
    void MonitoringThreadWorker();
    void CleanupThreadWorker();

    // Helpers
    void InvokeHijackCallbacks(const HijackEvent& event);
    void InvokeContextCallbacks(uint32_t tid, const ContextChange& change);
    void InvokeValidationCallbacks(const ThreadValidation& validation);
    [[nodiscard]] bool ShouldExclude(uint32_t pid) const;
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool ThreadHijackDetectorImpl::Initialize(const ThreadHijackConfig& config) {
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"ThreadHijack", L"Already initialized");
            return true;
        }

        SS_LOG_INFO(L"ThreadHijack", L"Initializing...");

        m_config = config;

        // Start cleanup thread
        m_stopCleanup.store(false, std::memory_order_release);
        m_cleanupThread = std::thread([this]() { CleanupThreadWorker(); });

        SS_LOG_INFO(L"ThreadHijack", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Initialization failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void ThreadHijackDetectorImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        SS_LOG_INFO(L"ThreadHijack", L"Shutting down...");

        StopMonitoring();

        // Stop cleanup thread (signal CV for immediate wake)
        m_stopCleanup.store(true, std::memory_order_release);
        m_cleanupCv.notify_all();
        if (m_cleanupThread.joinable()) {
            m_cleanupThread.join();
        }

        // Clear all data
        {
            std::unique_lock lock(m_threadsMutex);
            m_threads.clear();
        }

        {
            std::unique_lock lock(m_eventsMutex);
            m_hijackEvents.clear();
        }

        {
            std::unique_lock lock(m_statesMutex);
            m_threadStates.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_hijackCallbacks.clear();
            m_contextCallbacks.clear();
            m_validationCallbacks.clear();
        }

        SS_LOG_INFO(L"ThreadHijack", L"Shutdown complete");

    } catch (...) {
        SS_LOG_ERROR(L"ThreadHijack", L"Exception during shutdown");
    }
}

bool ThreadHijackDetectorImpl::StartMonitoring() {
    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"ThreadHijack", L"Not initialized");
            return false;
        }

        if (m_monitoring.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"ThreadHijack", L"Already monitoring");
            return true;
        }

        if (!m_config.enableRealTimeMonitoring) {
            SS_LOG_WARN(L"ThreadHijack", L"Real-time monitoring disabled in config");
            m_monitoring.store(false, std::memory_order_release);
            return false;
        }

        // Start monitoring thread
        m_stopMonitoring.store(false, std::memory_order_release);
        m_monitorThread = std::thread([this]() { MonitoringThreadWorker(); });

        SS_LOG_INFO(L"ThreadHijack", L"Monitoring started");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Failed to start monitoring - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
        m_monitoring.store(false, std::memory_order_release);
        return false;
    }
}

void ThreadHijackDetectorImpl::StopMonitoring() {
    if (!m_monitoring.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    m_stopMonitoring.store(true, std::memory_order_release);
    m_monitorCv.notify_all();
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    SS_LOG_INFO(L"ThreadHijack", L"Monitoring stopped");
}

// ============================================================================
// IMPL: THREAD VALIDATION
// ============================================================================

ThreadValidation ThreadHijackDetectorImpl::ValidateThreadInternal(uint32_t tid) {
    ThreadValidation validation;
    validation.threadId = tid;
    validation.validationTime = Clock::now();

    try {
        m_statistics.threadValidations.fetch_add(1, std::memory_order_relaxed);

        // Get thread context
        validation.context64 = GetThreadContextInternal(tid);
        validation.instructionPointer = validation.context64.rip;
        validation.stackPointer = validation.context64.rsp;

        // Get owner process — RAII handle
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (!hThread) {
            // ACCESS_DENIED or thread exited — do NOT assume valid
            const DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                m_statistics.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_DEBUG(L"ThreadHijack", L"Access denied validating TID %u", tid);
            }
            validation.issues.push_back(L"Cannot open thread for validation");
            return validation;
        }

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());
        validation.ownerPid = ownerPid;

        auto procName = Utils::ProcessUtils::GetProcessName(ownerPid);
        if (procName.has_value()) {
            validation.ownerProcessName = *procName;
        }

        // Validate RIP
        if (m_config.validateInstructionPointer) {
            validation.ripInKnownModule = IsAddressInModule(ownerPid, validation.instructionPointer);
            validation.ripModule = GetModuleForAddress(ownerPid, validation.instructionPointer);
            validation.ripIsBacked = validation.ripInKnownModule;

            if (!validation.ripInKnownModule) {
                validation.ripHasShellcodePattern = HasShellcodeAtAddress(ownerPid, validation.instructionPointer);
                validation.result = validation.ripHasShellcodePattern ?
                    ValidationResult::ShellcodeRIP : ValidationResult::UnbackedRIP;
                validation.isCompromised = true;
                validation.issues.push_back(
                    std::format(L"RIP 0x{:X} points to unbacked memory", validation.instructionPointer));
                validation.riskScore += 50;

                m_statistics.unbackedRIPDetected.fetch_add(1, std::memory_order_relaxed);
                if (validation.ripHasShellcodePattern) {
                    m_statistics.shellcodeRIPDetected.fetch_add(1, std::memory_order_relaxed);
                }
            } else if (IsAddressInRWXPrivate(ownerPid, validation.instructionPointer)) {
                // RIP in module but region is private RWX — possible module stomping
                validation.issues.push_back(L"RIP in private executable memory (possible module stomping)");
                validation.riskScore += 30;
            }
        }

        // Validate stack pointer — real TEB-based validation
        if (m_config.validateStackPointer) {
            uintptr_t stackBase = 0, stackLimit = 0;
            if (GetThreadStackBounds(hThread.get(), stackBase, stackLimit)) {
                validation.stackBase = stackBase;
                validation.stackLimit = stackLimit;
                validation.stackInValidRange =
                    (validation.stackPointer >= stackLimit &&
                     validation.stackPointer <= stackBase);

                if (!validation.stackInValidRange) {
                    validation.stackPivoted = true;
                    validation.isCompromised = true;
                    validation.result = ValidationResult::StackPivoted;
                    validation.issues.push_back(
                        std::format(L"Stack pivot: RSP 0x{:X} outside stack [0x{:X}-0x{:X}]",
                                   validation.stackPointer, stackLimit, stackBase));
                    validation.riskScore += 40;
                    m_statistics.stackPivots.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                // Fallback: basic RSP sanity check
                if (validation.stackPointer < 0x10000 ||
                    validation.stackPointer > 0x7FFFFFFFFFFF ||
                    validation.stackPointer % 8 != 0) {
                    validation.stackPivoted = true;
                    validation.isCompromised = true;
                    validation.result = ValidationResult::InvalidRSP;
                    validation.issues.push_back(L"RSP outside valid user-mode range or unaligned");
                    validation.riskScore += 30;
                } else {
                    validation.stackInValidRange = true;
                }
            }
        }

        // Validate segments
        if (m_config.validateSegmentRegisters) {
            validation.segmentsValid = (
                validation.context64.segCs == ThreadHijackConstants::USER_CS_64 &&
                validation.context64.segSs == ThreadHijackConstants::USER_SS_64
            );

            if (!validation.segmentsValid) {
                // WoW64 threads may have different selectors — check before flagging
                const bool isWow64Cs = (validation.context64.segCs == ThreadHijackConstants::USER_CS_32);
                if (!isWow64Cs) {
                    validation.result = ValidationResult::InvalidSegments;
                    validation.isCompromised = true;
                    validation.issues.push_back(
                        std::format(L"Invalid segments: CS=0x{:X} SS=0x{:X}",
                                   validation.context64.segCs, validation.context64.segSs));
                    validation.riskScore += 30;
                } else {
                    validation.segmentsValid = true;  // WoW64 is OK
                }
            }
        }

        // Check debug registers
        if (m_config.checkDebugRegisters) {
            validation.hasHardwareBreakpoints = HasActiveDebugRegistersInternal(tid);
            if (validation.hasHardwareBreakpoints) {
                if (validation.context64.dr7 & 0x1)  validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x4)  validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x10) validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x40) validation.activeBreakpointCount++;

                validation.result = ValidationResult::DebugRegistersSet;
                validation.issues.push_back(
                    std::format(L"Hardware breakpoints active (count={})", validation.activeBreakpointCount));
                validation.riskScore += 20;
            }
        }

        // Analyze call stack
        if (m_config.analyzeCallStack) {
            validation.callStack = GetCallStackInternal(tid, ThreadHijackConstants::MAX_STACK_FRAMES);
            m_statistics.callStacksAnalyzed.fetch_add(1, std::memory_order_relaxed);

            // Count unbacked frames from the walked stack
            uint32_t unbackedCount = 0;
            for (uintptr_t frame : validation.callStack) {
                if (!IsAddressInModule(ownerPid, frame)) {
                    unbackedCount++;
                }
            }
            validation.unbackedFrameCount = unbackedCount;

            if (validation.unbackedFrameCount > m_config.maxUnbackedFrames) {
                validation.isCompromised = true;
                validation.issues.push_back(
                    std::format(L"Unbacked stack frames: {} (max={})",
                               validation.unbackedFrameCount, m_config.maxUnbackedFrames));
                validation.riskScore += 25;

                m_statistics.unbackedFramesDetected.fetch_add(
                    validation.unbackedFrameCount, std::memory_order_relaxed);
            }
        }

        // Set MultipleAnomalies if multiple issues found
        if (validation.issues.size() > 1 && validation.isCompromised) {
            validation.result = ValidationResult::MultipleAnomalies;
        }

        // Invoke validation callbacks
        InvokeValidationCallbacks(validation);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Thread validation failed for TID %u - %ls",
            tid, Utils::StringUtils::ToWide(e.what()).c_str());
        m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);
    }

    return validation;
}

bool ThreadHijackDetectorImpl::ValidateThreadStartInternal(uint32_t tid) {
    try {
        HandleGuard hThread(OpenThread(
            THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
        if (!hThread) return true;  // Can't validate

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());

        // Use NtQueryInformationThread to get actual start address
        auto ntQueryThread = GetNtQueryInformationThread();
        if (ntQueryThread) {
            PVOID startAddress = nullptr;
            ULONG returnLength = 0;
            NTSTATUS status = ntQueryThread(
                hThread.get(), ThreadQuerySetWin32StartAddress,
                &startAddress, sizeof(startAddress), &returnLength);

            if (status == 0 && startAddress != nullptr) {
                const auto addr = reinterpret_cast<uintptr_t>(startAddress);
                if (!IsAddressInModule(ownerPid, addr)) {
                    SS_LOG_WARN(L"ThreadHijack",
                        L"Thread TID %u has unbacked start address 0x%llX",
                        tid, static_cast<unsigned long long>(addr));
                    return false;
                }
                return true;
            }
        }

        // Fallback: validate current RIP
        return IsRIPValidInternal(tid);

    } catch (...) {
        return true;
    }
}

bool ThreadHijackDetectorImpl::IsRIPValidInternal(uint32_t tid) {
    try {
        auto context = GetThreadContextInternal(tid);

        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (!hThread) return true;

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());

        return IsAddressInModule(ownerPid, context.rip);

    } catch (...) {
        return true;
    }
}

bool ThreadHijackDetectorImpl::IsStackValidInternal(uint32_t tid) {
    try {
        auto context = GetThreadContextInternal(tid);

        // RSP must be 8-byte aligned on x64
        if (context.rsp % 8 != 0) return false;

        // RSP must be in user-mode address space
        if (context.rsp < 0x10000 || context.rsp > 0x7FFFFFFFFFFF) return false;

        // Validate against actual stack bounds from TEB
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (hThread) {
            uintptr_t stackBase = 0, stackLimit = 0;
            if (GetThreadStackBounds(hThread.get(), stackBase, stackLimit)) {
                return (context.rsp >= stackLimit && context.rsp <= stackBase);
            }
        }

        return true;  // Passed basic checks

    } catch (...) {
        return true;
    }
}

std::vector<uintptr_t> ThreadHijackDetectorImpl::GetCallStackInternal(
    uint32_t tid,
    uint32_t maxFrames)
{
    std::vector<uintptr_t> callStack;

    try {
        HandleGuard hThread(OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid));
        if (!hThread) return callStack;

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ownerPid));
        if (!hProcess) return callStack;

        // Get thread context for StackWalk64 initialization
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!::GetThreadContext(hThread.get(), &ctx)) {
            // Fallback: just return RIP
            auto context = GetThreadContextInternal(tid);
            if (context.rip != 0) {
                callStack.push_back(context.rip);
            }
            return callStack;
        }

        // Initialize STACKFRAME64 for x64
        STACKFRAME64 frame{};
        frame.AddrPC.Offset = ctx.Rip;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = ctx.Rbp;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = ctx.Rsp;
        frame.AddrStack.Mode = AddrModeFlat;

        const uint32_t frameLimit = std::min(maxFrames, ThreadHijackConstants::MAX_STACK_FRAMES);

        for (uint32_t i = 0; i < frameLimit; ++i) {
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64,
                            hProcess.get(), hThread.get(),
                            &frame, &ctx,
                            nullptr,       // ReadMemoryRoutine (use default)
                            SymFunctionTableAccess64,
                            SymGetModuleBase64,
                            nullptr)) {
                break;
            }

            if (frame.AddrPC.Offset == 0) break;

            callStack.push_back(static_cast<uintptr_t>(frame.AddrPC.Offset));
        }

        // If StackWalk64 yielded nothing, at least return RIP
        if (callStack.empty() && ctx.Rip != 0) {
            callStack.push_back(ctx.Rip);
        }

    } catch (...) {
    }

    return callStack;
}

uint32_t ThreadHijackDetectorImpl::CountUnbackedFramesInternal(uint32_t tid) {
    try {
        auto callStack = GetCallStackInternal(tid, ThreadHijackConstants::MAX_STACK_FRAMES);

        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (!hThread) return 0;

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());

        uint32_t unbackedCount = 0;
        for (uintptr_t frame : callStack) {
            if (!IsAddressInModule(ownerPid, frame)) {
                unbackedCount++;
            }
        }

        return unbackedCount;

    } catch (...) {
        return 0;
    }
}

// ============================================================================
// IMPL: CONTEXT ANALYSIS
// ============================================================================

ThreadContext64 ThreadHijackDetectorImpl::GetThreadContextInternal(uint32_t tid) {
    ThreadContext64 result{};

    try {
        m_statistics.contextReads.fetch_add(1, std::memory_order_relaxed);

        HandleGuard hThread(OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid));
        if (!hThread) {
            m_statistics.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        if (::GetThreadContext(hThread.get(), &ctx)) {
            result.rip = ctx.Rip;
            result.rsp = ctx.Rsp;
            result.rbp = ctx.Rbp;
            result.rflags = ctx.EFlags;
            result.rax = ctx.Rax;
            result.rbx = ctx.Rbx;
            result.rcx = ctx.Rcx;
            result.rdx = ctx.Rdx;
            result.rsi = ctx.Rsi;
            result.rdi = ctx.Rdi;
            result.r8 = ctx.R8;
            result.r9 = ctx.R9;
            result.r10 = ctx.R10;
            result.r11 = ctx.R11;
            result.r12 = ctx.R12;
            result.r13 = ctx.R13;
            result.r14 = ctx.R14;
            result.r15 = ctx.R15;
            result.segCs = ctx.SegCs;
            result.segSs = ctx.SegSs;
            result.segDs = ctx.SegDs;
            result.segEs = ctx.SegEs;
            result.segFs = ctx.SegFs;
            result.segGs = ctx.SegGs;
            result.dr0 = ctx.Dr0;
            result.dr1 = ctx.Dr1;
            result.dr2 = ctx.Dr2;
            result.dr3 = ctx.Dr3;
            result.dr6 = ctx.Dr6;
            result.dr7 = ctx.Dr7;
            result.contextFlags = ctx.ContextFlags;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"GetThreadContext failed for TID %u - %ls",
            tid, Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return result;
}

std::vector<ContextChange> ThreadHijackDetectorImpl::CompareContextsInternal(
    const ThreadContext64& before,
    const ThreadContext64& after,
    uint32_t pid)
{
    std::vector<ContextChange> changes;

    try {
        // Check RIP change
        if (before.rip != after.rip) {
            ContextChange change;
            change.type = ContextModificationType::InstructionPointer;
            change.oldValue = before.rip;
            change.newValue = after.rip;
            change.oldModule = GetModuleForAddress(pid, before.rip);
            change.newModule = GetModuleForAddress(pid, after.rip);
            change.newRIPIsBacked = IsAddressInModule(pid, after.rip);
            change.isSuspicious = !change.newRIPIsBacked;

            if (!change.newRIPIsBacked) {
                change.suspicionReason = L"RIP changed to unbacked memory";
            } else if (change.oldModule != change.newModule) {
                change.suspicionReason = L"RIP changed to different module";
            }

            change.description = std::format(L"RIP: 0x{:X} -> 0x{:X}", before.rip, after.rip);
            changes.push_back(change);

            m_statistics.ripModifications.fetch_add(1, std::memory_order_relaxed);
        }

        // Check RSP change (stack pivot)
        if (before.rsp != after.rsp) {
            const int64_t delta = std::abs(static_cast<int64_t>(after.rsp - before.rsp));

            ContextChange change;
            change.type = ContextModificationType::StackPointer;
            change.oldValue = before.rsp;
            change.newValue = after.rsp;
            change.isSuspicious = (delta > 0x100000);  // >1MB change

            if (change.isSuspicious) {
                change.suspicionReason = L"Stack pivot detected (large RSP change)";
                m_statistics.stackPivots.fetch_add(1, std::memory_order_relaxed);
            }

            change.description = std::format(L"RSP: 0x{:X} -> 0x{:X} (delta: 0x{:X})",
                                            before.rsp, after.rsp, delta);
            changes.push_back(change);
        }

        // Check debug registers
        if (before.dr7 != after.dr7) {
            ContextChange change;
            change.type = ContextModificationType::DebugRegisters;
            change.oldValue = before.dr7;
            change.newValue = after.dr7;
            change.isSuspicious = (after.dr7 != 0);
            change.suspicionReason = L"Debug registers modified";
            change.description = L"DR7 changed (hardware breakpoints)";
            changes.push_back(change);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Context comparison failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return changes;
}

ValidationResult ThreadHijackDetectorImpl::AnalyzeContextInternal(
    const ThreadContext64& context,
    uint32_t pid)
{
    // Check RIP validity
    if (!IsAddressInModule(pid, context.rip)) {
        if (HasShellcodeAtAddress(pid, context.rip)) {
            return ValidationResult::ShellcodeRIP;
        }
        return ValidationResult::UnbackedRIP;
    }

    // Check segment selectors
    if (context.segCs != ThreadHijackConstants::USER_CS_64 ||
        context.segSs != ThreadHijackConstants::USER_SS_64) {
        return ValidationResult::InvalidSegments;
    }

    // Check debug registers
    if (context.dr7 != 0) {
        return ValidationResult::DebugRegistersSet;
    }

    return ValidationResult::Valid;
}

bool ThreadHijackDetectorImpl::HasActiveDebugRegistersInternal(uint32_t tid) {
    try {
        auto context = GetThreadContextInternal(tid);

        // Check DR7 enable bits
        // Bits 0,1 = DR0, 2,3 = DR1, 4,5 = DR2, 6,7 = DR3
        return (context.dr7 & 0xFF) != 0;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// IMPL: HIJACK DETECTION
// ============================================================================

std::optional<HijackEvent> ThreadHijackDetectorImpl::DetectHijackInternal(uint32_t tid) {
    try {
        // Validate thread
        auto validation = ValidateThreadInternal(tid);

        if (!validation.isCompromised) {
            return std::nullopt;  // Thread is clean
        }

        // Create hijack event
        HijackEvent event;
        event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = Clock::now();
        event.victimTid = tid;
        event.victimPid = validation.ownerPid;
        event.victimProcessName = validation.ownerProcessName;
        event.targetAddress = validation.instructionPointer;
        event.targetModule = validation.ripModule;
        event.targetIsUnbacked = !validation.ripIsBacked;
        event.targetIsShellcode = validation.ripHasShellcodePattern;

        // Determine hijack type
        if (validation.ripHasShellcodePattern) {
            event.hijackType = HijackType::RIPModification;
        } else if (validation.stackPivoted) {
            event.hijackType = HijackType::StackPivot;
        } else if (validation.hasHardwareBreakpoints) {
            event.hijackType = HijackType::HardwareBreakpoint;
        } else if (!validation.ripIsBacked) {
            event.hijackType = HijackType::RIPModification;
        } else {
            event.hijackType = HijackType::Unknown;
        }

        // Calculate confidence
        if (validation.ripHasShellcodePattern && (!validation.ripIsBacked)) {
            event.confidence = DetectionConfidence::Confirmed;
            m_statistics.confirmedHijacks.fetch_add(1, std::memory_order_relaxed);
        } else if ((!validation.ripIsBacked)) {
            event.confidence = DetectionConfidence::High;
            m_statistics.highConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        } else if (validation.unbackedFrameCount > 0) {
            event.confidence = DetectionConfidence::Medium;
            m_statistics.mediumConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        } else {
            event.confidence = DetectionConfidence::Low;
            m_statistics.lowConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        }

        // Calculate risk score — include RWX and cross-process tracking
        const bool isRWX = (!validation.ripIsBacked) ?
            IsAddressInRWXPrivate(validation.ownerPid, validation.instructionPointer) : false;

        // Check if there's pending cross-process state for this thread
        bool crossProcessDetected = false;
        uint32_t suspendDurationMs = 0;
        {
            std::shared_lock lock(m_statesMutex);
            auto stateIt = m_threadStates.find(tid);
            if (stateIt != m_threadStates.end()) {
                crossProcessDetected = (stateIt->second.suspenderPid != 0 &&
                                       stateIt->second.suspenderPid != validation.ownerPid);
                if (stateIt->second.isSuspended) {
                    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now() - stateIt->second.suspendTime).count();
                    suspendDurationMs = static_cast<uint32_t>(std::min<long long>(duration, UINT32_MAX));
                }
            }
        }

        if (crossProcessDetected) {
            m_statistics.crossProcessChanges.fetch_add(1, std::memory_order_relaxed);
        }

        event.riskScore = CalculateRiskScore(
            (!validation.ripIsBacked),
            validation.ripHasShellcodePattern,
            crossProcessDetected,
            validation.stackPivoted,
            validation.hasHardwareBreakpoints,
            suspendDurationMs,
            isRWX
        );

        // Add detection reasons
        for (const auto& issue : validation.issues) {
            event.detectionReasons.push_back(issue);
        }

        // MITRE ATT&CK mapping
        event.mitreAttackId = "T1055.003";  // Thread Execution Hijacking

        m_statistics.hijacksDetected.fetch_add(1, std::memory_order_relaxed);

        // Store event
        {
            std::unique_lock lock(m_eventsMutex);
            m_hijackEvents.push_back(event);
            if (m_hijackEvents.size() > ThreadHijackConstants::MAX_HIJACK_EVENTS) {
                m_hijackEvents.pop_front();
            }
        }

        // Invoke callbacks
        InvokeHijackCallbacks(event);

        return event;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Hijack detection failed for TID %u - %ls",
            tid, Utils::StringUtils::ToWide(e.what()).c_str());
        return std::nullopt;
    }
}

ScanResult ThreadHijackDetectorImpl::ScanProcessInternal(uint32_t pid) {
    ScanResult result;
    result.scanTime = Clock::now();
    result.targetPid = pid;

    const auto startTime = Clock::now();

    try {
        m_statistics.scansPerformed.fetch_add(1, std::memory_order_relaxed);

        if (ShouldExclude(pid)) {
            result.scanComplete = true;
            return result;
        }

        // Enumerate threads in process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            result.scanError = L"Failed to create thread snapshot";
            m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        THREADENTRY32 te{};
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    result.threadsScanned++;

                    // Validate thread
                    auto validation = ValidateThreadInternal(te.th32ThreadID);
                    result.validations.push_back(validation);
                    result.threadsValidated++;

                    if (validation.isCompromised) {
                        result.compromisedThreads.push_back(validation);
                        result.compromisedThreadsFound++;
                        result.hijackDetected = true;

                        // Detect hijack
                        if (auto hijack = DetectHijackInternal(te.th32ThreadID)) {
                            result.detectedHijacks.push_back(*hijack);

                            if (static_cast<uint8_t>(hijack->confidence) >
                                static_cast<uint8_t>(result.highestConfidence)) {
                                result.highestConfidence = hijack->confidence;
                            }

                            if (hijack->riskScore > result.highestRiskScore) {
                                result.highestRiskScore = hijack->riskScore;
                            }
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);
        result.scanComplete = true;

    } catch (const std::exception& e) {
        result.scanError = Utils::StringUtils::ToWide(e.what());
        m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);
    }

    const auto endTime = Clock::now();
    result.scanDurationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
    );

    m_statistics.totalScanTimeMs.fetch_add(result.scanDurationMs, std::memory_order_relaxed);

    return result;
}

// ============================================================================
// IMPL: EVENT HANDLERS
// ============================================================================

void ThreadHijackDetectorImpl::OnThreadSuspendInternal(
    uint32_t targetTid,
    uint32_t suspenderPid)
{
    try {
        std::unique_lock lock(m_statesMutex);

        auto& state = m_threadStates[targetTid];
        state.tid = targetTid;
        state.suspenderPid = suspenderPid;
        state.suspendTime = Clock::now();
        state.isSuspended = true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"OnThreadSuspend failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void ThreadHijackDetectorImpl::OnThreadResumeInternal(
    uint32_t targetTid,
    uint32_t resumerPid)
{
    try {
        std::unique_lock lock(m_statesMutex);

        auto it = m_threadStates.find(targetTid);
        if (it != m_threadStates.end()) {
            it->second.isSuspended = false;

            // Check suspend duration
            const auto now = Clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.suspendTime
            ).count();

            if (duration > static_cast<long long>(m_config.suspendDurationThresholdMs)) {
                SS_LOG_WARN(L"ThreadHijack",
                    L"Long suspend duration %lldms for TID %u (suspended by PID %u, resumed by PID %u)",
                    static_cast<long long>(duration), targetTid,
                    it->second.suspenderPid, resumerPid);

                // Release lock before calling DetectHijackInternal to avoid deadlock
                lock.unlock();

                // Validate thread after long suspend
                if (m_config.enableRealTimeMonitoring) {
                    (void)DetectHijackInternal(targetTid);
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"OnThreadResume failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void ThreadHijackDetectorImpl::OnContextChangeInternal(
    uint32_t targetTid,
    uint32_t modifierPid,
    uint32_t contextFlags)
{
    try {
        // Get owner PID — RAII
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, targetTid));
        if (!hThread) return;

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());

        // Check if cross-process modification
        if (modifierPid != ownerPid) {
            m_statistics.crossProcessChanges.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_WARN(L"ThreadHijack",
                L"Cross-process context change - TID %u modified by PID %u (owner PID %u), flags=0x%X",
                targetTid, modifierPid, ownerPid, contextFlags);

            // Validate thread
            if (m_config.detectCrossProcessModification) {
                (void)DetectHijackInternal(targetTid);
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"OnContextChange failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void ThreadHijackDetectorImpl::OnSetContextThreadInternal(
    uint32_t callerPid,
    uint32_t targetTid,
    const ThreadContext64& newContext)
{
    try {
        // Get current context before the set
        auto oldContext = GetThreadContextInternal(targetTid);

        // Get owner PID — RAII
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, targetTid));
        if (!hThread) return;

        DWORD ownerPid = GetProcessIdOfThread(hThread.get());

        // Cross-process SetContextThread is always suspicious
        const bool isCrossProcess = (callerPid != ownerPid);
        if (isCrossProcess) {
            SS_LOG_WARN(L"ThreadHijack",
                L"NtSetContextThread cross-process: caller PID %u → TID %u (owner PID %u), "
                L"RIP 0x%llX → 0x%llX",
                callerPid, targetTid, ownerPid,
                static_cast<unsigned long long>(oldContext.rip),
                static_cast<unsigned long long>(newContext.rip));
        }

        // Compare contexts
        auto changes = CompareContextsInternal(oldContext, newContext, ownerPid);

        for (const auto& change : changes) {
            if (change.isSuspicious || isCrossProcess) {
                InvokeContextCallbacks(targetTid, change);

                if (m_config.blockSuspiciousChanges || isCrossProcess) {
                    (void)DetectHijackInternal(targetTid);
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"OnSetContextThread failed - %ls",
            Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

// ============================================================================
// IMPL: RESPONSE ACTIONS
// ============================================================================

bool ThreadHijackDetectorImpl::BlockContextChangeInternal(
    uint32_t targetTid,
    uint32_t modifierPid)
{
    try {
        // Blocking SetThreadContext requires kernel driver (PhantomSensor) interception.
        // The kernel driver's thread notify callback intercepts NtSetContextThread
        // and can deny the syscall. From user-mode, we can only:
        // 1. Detect and alert (done)
        // 2. Restore context after the fact (RestoreContextInternal)
        // 3. Terminate the attacker process

        m_statistics.changesBlocked.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_WARN(L"ThreadHijack",
            L"Context change blocked (post-detection) - TID %u by PID %u", targetTid, modifierPid);

        // Attempt to restore context from baseline
        if (RestoreContextInternal(targetTid)) {
            return true;
        }

        return false;

    } catch (...) {
        return false;
    }
}

bool ThreadHijackDetectorImpl::RestoreContextInternal(uint32_t tid) {
    try {
        // Get baseline
        auto baseline = GetBaselineInternal(tid);
        if (!baseline.has_value()) {
            SS_LOG_WARN(L"ThreadHijack", L"No baseline to restore for TID %u", tid);
            return false;
        }

        // Open thread with SET_CONTEXT permission
        HandleGuard hThread(OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid));
        if (!hThread) {
            SS_LOG_ERROR(L"ThreadHijack", L"Cannot open thread TID %u for context restore", tid);
            return false;
        }

        // Suspend thread before modifying context
        DWORD prevSuspendCount = SuspendThread(hThread.get());
        if (prevSuspendCount == static_cast<DWORD>(-1)) {
            SS_LOG_ERROR(L"ThreadHijack", L"Cannot suspend thread TID %u for restore", tid);
            return false;
        }

        // Build CONTEXT from baseline
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        ctx.Rip = baseline->rip;
        ctx.Rsp = baseline->rsp;
        ctx.Rbp = baseline->rbp;
        ctx.EFlags = static_cast<DWORD>(baseline->rflags);
        ctx.Rax = baseline->rax;
        ctx.Rbx = baseline->rbx;
        ctx.Rcx = baseline->rcx;
        ctx.Rdx = baseline->rdx;
        ctx.Rsi = baseline->rsi;
        ctx.Rdi = baseline->rdi;
        ctx.R8  = baseline->r8;
        ctx.R9  = baseline->r9;
        ctx.R10 = baseline->r10;
        ctx.R11 = baseline->r11;
        ctx.R12 = baseline->r12;
        ctx.R13 = baseline->r13;
        ctx.R14 = baseline->r14;
        ctx.R15 = baseline->r15;

        BOOL setResult = SetThreadContext(hThread.get(), &ctx);

        // Always resume
        ResumeThread(hThread.get());

        if (setResult) {
            m_statistics.contextsRestored.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"ThreadHijack", L"Restored context for TID %u (RIP=0x%llX)",
                tid, static_cast<unsigned long long>(baseline->rip));
            return true;
        } else {
            SS_LOG_ERROR(L"ThreadHijack", L"SetThreadContext failed for TID %u", tid);
            return false;
        }

    } catch (...) {
        return false;
    }
}

bool ThreadHijackDetectorImpl::TerminateAttackerInternal(const HijackEvent& event) {
    try {
        if (event.attackerPid == 0) return false;

        // Safety check: never terminate critical system processes
        if (Utils::ProcessUtils::IsProcessCritical(event.attackerPid)) {
            SS_LOG_WARN(L"ThreadHijack",
                L"Refusing to terminate critical process PID %u", event.attackerPid);
            return false;
        }

        HandleGuard hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, event.attackerPid));
        if (!hProcess) return false;

        BOOL result = TerminateProcess(hProcess.get(), 1);

        if (result) {
            m_statistics.attackersTerminated.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"ThreadHijack", L"Terminated attacker PID %u (%ls)",
                event.attackerPid, event.attackerProcessName.c_str());
        }

        return result != FALSE;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// IMPL: BASELINE MANAGEMENT
// ============================================================================

void ThreadHijackDetectorImpl::EstablishBaselineInternal(uint32_t tid) {
    try {
        // Get current context as baseline
        auto context = GetThreadContextInternal(tid);

        std::unique_lock lock(m_threadsMutex);

        auto& monitored = m_threads[tid];
        monitored.threadId = tid;
        monitored.createTime = Clock::now();
        monitored.lastChecked = Clock::now();

        // Store full context baseline
        monitored.baselineContext = context;
        monitored.baselineEstablished = true;

        // Get owner process — RAII
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (hThread) {
            DWORD ownerPid = GetProcessIdOfThread(hThread.get());
            monitored.ownerPid = ownerPid;
            monitored.baselineModule = GetModuleForAddress(ownerPid, context.rip);
        }

        m_statistics.threadsMonitored.fetch_add(1, std::memory_order_relaxed);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ThreadHijack", L"Baseline establishment failed for TID %u - %ls",
            tid, Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

void ThreadHijackDetectorImpl::ClearBaselineInternal(uint32_t tid) {
    std::unique_lock lock(m_threadsMutex);
    m_threads.erase(tid);
}

std::optional<ThreadContext64> ThreadHijackDetectorImpl::GetBaselineInternal(uint32_t tid) const {
    std::shared_lock lock(m_threadsMutex);

    auto it = m_threads.find(tid);
    if (it == m_threads.end() || !it->second.baselineEstablished) {
        return std::nullopt;
    }

    return it->second.baselineContext;
}

// ============================================================================
// IMPL: WORKER THREADS
// ============================================================================

void ThreadHijackDetectorImpl::MonitoringThreadWorker() {
    SS_LOG_INFO(L"ThreadHijack", L"Monitoring thread started");

    while (!m_stopMonitoring.load(std::memory_order_acquire)) {
        try {
            // Collect TIDs to validate (snapshot under lock)
            std::vector<uint32_t> tidsToValidate;

            {
                std::shared_lock lock(m_threadsMutex);
                tidsToValidate.reserve(m_threads.size());
                for (const auto& [tid, thread] : m_threads) {
                    tidsToValidate.push_back(tid);
                }
            }

            for (uint32_t tid : tidsToValidate) {
                if (m_stopMonitoring.load(std::memory_order_acquire)) break;

                // Verify thread still exists before validating
                HandleGuard hCheck(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
                if (!hCheck) {
                    // Thread exited — remove from monitoring
                    std::unique_lock lock(m_threadsMutex);
                    m_threads.erase(tid);
                    continue;
                }

                (void)DetectHijackInternal(tid);
            }

            // Interruptible sleep via condition variable (1 second scan interval)
            {
                std::unique_lock lock(m_monitorCvMutex);
                m_monitorCv.wait_for(lock, std::chrono::seconds(1),
                    [this]() { return m_stopMonitoring.load(std::memory_order_acquire); });
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreadHijack", L"Monitoring thread error - %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    SS_LOG_INFO(L"ThreadHijack", L"Monitoring thread stopped");
}

void ThreadHijackDetectorImpl::CleanupThreadWorker() {
    SS_LOG_INFO(L"ThreadHijack", L"Cleanup thread started");

    while (!m_stopCleanup.load(std::memory_order_acquire)) {
        try {
            const auto now = Clock::now();
            const auto maxAge = std::chrono::hours(1);

            // Cleanup old thread states
            {
                std::unique_lock lock(m_statesMutex);
                for (auto it = m_threadStates.begin(); it != m_threadStates.end();) {
                    if ((now - it->second.suspendTime) > maxAge) {
                        it = m_threadStates.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Cleanup old monitored threads
            {
                std::unique_lock lock(m_threadsMutex);
                for (auto it = m_threads.begin(); it != m_threads.end();) {
                    if ((now - it->second.lastChecked) > maxAge) {
                        it = m_threads.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Interruptible sleep via condition variable
            {
                std::unique_lock lock(m_cleanupCvMutex);
                m_cleanupCv.wait_for(lock, std::chrono::minutes(5),
                    [this]() { return m_stopCleanup.load(std::memory_order_acquire); });
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreadHijack", L"Cleanup thread error - %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }

    SS_LOG_INFO(L"ThreadHijack", L"Cleanup thread stopped");
}

// ============================================================================
// IMPL: HELPERS
// ============================================================================

void ThreadHijackDetectorImpl::InvokeHijackCallbacks(const HijackEvent& event) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_hijackCallbacks) {
        try {
            callback(event);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreadHijack", L"Hijack callback %llu error - %ls",
                id, Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }
}

void ThreadHijackDetectorImpl::InvokeContextCallbacks(
    uint32_t tid,
    const ContextChange& change)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_contextCallbacks) {
        try {
            callback(tid, change);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreadHijack", L"Context callback %llu error - %ls",
                id, Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }
}

void ThreadHijackDetectorImpl::InvokeValidationCallbacks(const ThreadValidation& validation) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_validationCallbacks) {
        try {
            callback(validation);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ThreadHijack", L"Validation callback %llu error - %ls",
                id, Utils::StringUtils::ToWide(e.what()).c_str());
        }
    }
}

bool ThreadHijackDetectorImpl::ShouldExclude(uint32_t pid) const {
    // Check excluded PIDs
    if (std::find(m_config.excludedPids.begin(), m_config.excludedPids.end(), pid) !=
        m_config.excludedPids.end()) {
        return true;
    }

    // Check excluded process names
    auto procName = Utils::ProcessUtils::GetProcessName(pid);
    if (procName.has_value()) {
        for (const auto& excluded : m_config.excludedProcesses) {
            if (*procName == excluded) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

ThreadHijackDetector& ThreadHijackDetector::Instance() {
    static ThreadHijackDetector instance;
    return instance;
}

ThreadHijackDetector::ThreadHijackDetector()
    : m_impl(std::make_unique<ThreadHijackDetectorImpl>())
{
    SS_LOG_INFO(L"ThreadHijack", L"Constructor called");
}

ThreadHijackDetector::~ThreadHijackDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"ThreadHijack", L"Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ThreadHijackDetector::Initialize(const ThreadHijackConfig& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void ThreadHijackDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool ThreadHijackDetector::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

bool ThreadHijackDetector::UpdateConfig(const ThreadHijackConfig& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

ThreadHijackConfig ThreadHijackDetector::GetConfig() const {
    if (!m_impl) return ThreadHijackConfig{};

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// THREAD VALIDATION
// ============================================================================

ThreadValidation ThreadHijackDetector::ValidateThread(uint32_t tid) {
    return m_impl ? m_impl->ValidateThreadInternal(tid) : ThreadValidation{};
}

bool ThreadHijackDetector::ValidateThreadStart(uint32_t tid) {
    return m_impl ? m_impl->ValidateThreadStartInternal(tid) : true;
}

std::vector<ThreadValidation> ThreadHijackDetector::ValidateProcessThreads(uint32_t pid) {
    std::vector<ThreadValidation> validations;

    if (!m_impl) return validations;

    try {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return validations;

        THREADENTRY32 te{};
        te.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    validations.push_back(m_impl->ValidateThreadInternal(te.th32ThreadID));
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);

    } catch (...) {
        // Return partial results
    }

    return validations;
}

bool ThreadHijackDetector::IsRIPValid(uint32_t tid) {
    return m_impl ? m_impl->IsRIPValidInternal(tid) : true;
}

bool ThreadHijackDetector::IsStackValid(uint32_t tid) {
    return m_impl ? m_impl->IsStackValidInternal(tid) : true;
}

std::vector<uintptr_t> ThreadHijackDetector::GetCallStack(uint32_t tid, uint32_t maxFrames) {
    return m_impl ? m_impl->GetCallStackInternal(tid, maxFrames) : std::vector<uintptr_t>{};
}

uint32_t ThreadHijackDetector::CountUnbackedFrames(uint32_t tid) {
    return m_impl ? m_impl->CountUnbackedFramesInternal(tid) : 0;
}

// ============================================================================
// CONTEXT ANALYSIS
// ============================================================================

ThreadContext64 ThreadHijackDetector::GetThreadContext(uint32_t tid) {
    return m_impl ? m_impl->GetThreadContextInternal(tid) : ThreadContext64{};
}

std::vector<ContextChange> ThreadHijackDetector::CompareContexts(
    const ThreadContext64& before,
    const ThreadContext64& after)
{
    if (!m_impl) return {};

    // Without a PID, module lookup will fail — perform context-only comparison
    // Changes are still flagged as suspicious based on delta magnitude
    return m_impl->CompareContextsInternal(before, after, 0);
}

ValidationResult ThreadHijackDetector::AnalyzeContext(
    const ThreadContext64& context,
    uint32_t pid)
{
    return m_impl ? m_impl->AnalyzeContextInternal(context, pid) : ValidationResult::Valid;
}

bool ThreadHijackDetector::HasActiveDebugRegisters(uint32_t tid) {
    return m_impl ? m_impl->HasActiveDebugRegistersInternal(tid) : false;
}

// ============================================================================
// HIJACK DETECTION
// ============================================================================

ScanResult ThreadHijackDetector::ScanProcess(uint32_t pid) {
    return m_impl ? m_impl->ScanProcessInternal(pid) : ScanResult{};
}

ScanResult ThreadHijackDetector::ScanAllProcesses() {
    ScanResult combinedResult;
    combinedResult.scanTime = Clock::now();

    if (!m_impl) return combinedResult;

    const auto startTime = Clock::now();

    try {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return combinedResult;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                auto result = m_impl->ScanProcessInternal(pe.th32ProcessID);

                combinedResult.threadsScanned += result.threadsScanned;
                combinedResult.threadsValidated += result.threadsValidated;
                combinedResult.compromisedThreadsFound += result.compromisedThreadsFound;

                if (result.hijackDetected) {
                    combinedResult.hijackDetected = true;
                }

                for (const auto& hijack : result.detectedHijacks) {
                    combinedResult.detectedHijacks.push_back(hijack);
                }

            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        combinedResult.scanComplete = true;

    } catch (const std::exception& e) {
        combinedResult.scanError = Utils::StringUtils::ToWide(e.what());
    }

    const auto endTime = Clock::now();
    combinedResult.scanDurationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
    );

    return combinedResult;
}

std::optional<HijackEvent> ThreadHijackDetector::DetectHijack(uint32_t tid) {
    return m_impl ? m_impl->DetectHijackInternal(tid) : std::nullopt;
}

std::vector<HijackEvent> ThreadHijackDetector::GetRecentHijacks() const {
    std::vector<HijackEvent> hijacks;

    if (!m_impl) return hijacks;

    std::shared_lock lock(m_impl->m_eventsMutex);
    hijacks.assign(m_impl->m_hijackEvents.begin(), m_impl->m_hijackEvents.end());

    return hijacks;
}

// ============================================================================
// REAL-TIME MONITORING
// ============================================================================

bool ThreadHijackDetector::StartMonitoring() {
    return m_impl ? m_impl->StartMonitoring() : false;
}

void ThreadHijackDetector::StopMonitoring() {
    if (m_impl) {
        m_impl->StopMonitoring();
    }
}

bool ThreadHijackDetector::IsMonitoring() const noexcept {
    return m_impl ? m_impl->m_monitoring.load(std::memory_order_acquire) : false;
}

void ThreadHijackDetector::SetMonitoringMode(MonitoringMode mode) {
    if (m_impl) {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config.mode = mode;
    }
}

MonitoringMode ThreadHijackDetector::GetMonitoringMode() const noexcept {
    if (!m_impl) return MonitoringMode::Disabled;

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.mode;
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

void ThreadHijackDetector::OnThreadSuspend(uint32_t targetTid, uint32_t suspenderPid) {
    if (m_impl) {
        m_impl->OnThreadSuspendInternal(targetTid, suspenderPid);
    }
}

void ThreadHijackDetector::OnThreadResume(uint32_t targetTid, uint32_t resumerPid) {
    if (m_impl) {
        m_impl->OnThreadResumeInternal(targetTid, resumerPid);
    }
}

void ThreadHijackDetector::OnContextChange(
    uint32_t targetTid,
    uint32_t modifierPid,
    uint32_t contextFlags)
{
    if (m_impl) {
        m_impl->OnContextChangeInternal(targetTid, modifierPid, contextFlags);
    }
}

void ThreadHijackDetector::OnSetContextThread(
    uint32_t callerPid,
    uint32_t targetTid,
    const ThreadContext64& newContext)
{
    if (m_impl) {
        m_impl->OnSetContextThreadInternal(callerPid, targetTid, newContext);
    }
}

// ============================================================================
// RESPONSE ACTIONS
// ============================================================================

bool ThreadHijackDetector::BlockContextChange(uint32_t targetTid, uint32_t modifierPid) {
    return m_impl ? m_impl->BlockContextChangeInternal(targetTid, modifierPid) : false;
}

bool ThreadHijackDetector::RestoreContext(uint32_t tid) {
    return m_impl ? m_impl->RestoreContextInternal(tid) : false;
}

bool ThreadHijackDetector::TerminateAttacker(const HijackEvent& event) {
    return m_impl ? m_impl->TerminateAttackerInternal(event) : false;
}

// ============================================================================
// BASELINE MANAGEMENT
// ============================================================================

void ThreadHijackDetector::EstablishBaseline(uint32_t tid) {
    if (m_impl) {
        m_impl->EstablishBaselineInternal(tid);
    }
}

void ThreadHijackDetector::ClearBaseline(uint32_t tid) {
    if (m_impl) {
        m_impl->ClearBaselineInternal(tid);
    }
}

std::optional<ThreadContext64> ThreadHijackDetector::GetBaseline(uint32_t tid) const {
    return m_impl ? m_impl->GetBaselineInternal(tid) : std::nullopt;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t ThreadHijackDetector::RegisterCallback(HijackDetectedCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_hijackCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ThreadHijackDetector::RegisterContextCallback(ContextChangeCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_contextCallbacks[id] = std::move(callback);
    return id;
}

uint64_t ThreadHijackDetector::RegisterValidationCallback(ValidationCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_validationCallbacks[id] = std::move(callback);
    return id;
}

void ThreadHijackDetector::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_hijackCallbacks.erase(callbackId);
    m_impl->m_contextCallbacks.erase(callbackId);
    m_impl->m_validationCallbacks.erase(callbackId);
}

// ============================================================================
// STATISTICS
// ============================================================================

void ThreadHijackDetector::GetStatistics(ThreadHijackStatistics& stats) const {
    if (!m_impl) {
        stats.Reset();
        return;
    }

    // Snapshot all atomic counters into the local (single return path for NRVO)
    const auto& src = m_impl->m_statistics;
    stats.threadsMonitored.store(src.threadsMonitored.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.threadValidations.store(src.threadValidations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.contextReads.store(src.contextReads.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.hijacksDetected.store(src.hijacksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.ripModifications.store(src.ripModifications.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.stackPivots.store(src.stackPivots.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.crossProcessChanges.store(src.crossProcessChanges.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.unbackedRIPDetected.store(src.unbackedRIPDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.shellcodeRIPDetected.store(src.shellcodeRIPDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.lowConfidenceDetections.store(src.lowConfidenceDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.mediumConfidenceDetections.store(src.mediumConfidenceDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.highConfidenceDetections.store(src.highConfidenceDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.confirmedHijacks.store(src.confirmedHijacks.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.changesBlocked.store(src.changesBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.contextsRestored.store(src.contextsRestored.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.attackersTerminated.store(src.attackersTerminated.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.callStacksAnalyzed.store(src.callStacksAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.unbackedFramesDetected.store(src.unbackedFramesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.totalScanTimeMs.store(src.totalScanTimeMs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.scansPerformed.store(src.scansPerformed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.scanErrors.store(src.scanErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.accessDeniedErrors.store(src.accessDeniedErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stats.timeoutErrors.store(src.timeoutErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
}

void ThreadHijackDetector::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

std::wstring ThreadHijackDetector::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
                      ThreadHijackConstants::VERSION_MAJOR,
                      ThreadHijackConstants::VERSION_MINOR,
                      ThreadHijackConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY
// ============================================================================

std::wstring ThreadHijackDetector::HijackTypeToString(HijackType type) noexcept {
    switch (type) {
        case HijackType::RIPModification: return L"RIP Modification";
        case HijackType::StackPivot: return L"Stack Pivot";
        case HijackType::RegisterModification: return L"Register Modification";
        case HijackType::ReturnAddressOverwrite: return L"Return Address Overwrite";
        case HijackType::TrampolineInjection: return L"Trampoline Injection";
        case HijackType::ContextReplacement: return L"Context Replacement";
        case HijackType::HardwareBreakpoint: return L"Hardware Breakpoint";
        case HijackType::SegmentModification: return L"Segment Modification";
        default: return L"Unknown";
    }
}

std::wstring ThreadHijackDetector::ValidationResultToString(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::Valid: return L"Valid";
        case ValidationResult::InvalidRIP: return L"Invalid RIP";
        case ValidationResult::InvalidRSP: return L"Invalid RSP";
        case ValidationResult::InvalidSegments: return L"Invalid Segments";
        case ValidationResult::SuspiciousFlags: return L"Suspicious Flags";
        case ValidationResult::UnbackedRIP: return L"Unbacked RIP";
        case ValidationResult::ShellcodeRIP: return L"Shellcode RIP";
        case ValidationResult::StackPivoted: return L"Stack Pivoted";
        case ValidationResult::DebugRegistersSet: return L"Debug Registers Set";
        case ValidationResult::MultipleAnomalies: return L"Multiple Anomalies";
        default: return L"Unknown";
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
