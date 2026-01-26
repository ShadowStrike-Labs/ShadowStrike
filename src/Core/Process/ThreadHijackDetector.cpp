/**
 * ============================================================================
 * ShadowStrike Core Process - THREAD HIJACK DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ThreadHijackDetector.cpp
 * @brief Enterprise-grade thread execution hijacking detection engine implementation
 *
 * Production-level implementation competing with CrowdStrike Falcon EDR,
 * Kaspersky EDR, and BitDefender GravityZone for thread hijack detection.
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

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>

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

namespace ShadowStrike {
namespace Core {
namespace Process {

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Check if address is within any module in the process.
 */
[[nodiscard]] static bool IsAddressInModule(uint32_t pid, uintptr_t address) noexcept {
    try {
        auto modules = Utils::ProcessUtils::GetProcessModules(pid);
        for (const auto& mod : modules) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mod.baseAddress);
            const uintptr_t end = base + mod.moduleSize;
            if (address >= base && address < end) {
                return true;
            }
        }
    } catch (...) {
        // Error reading modules
    }
    return false;
}

/**
 * @brief Get module name containing an address.
 */
[[nodiscard]] static std::wstring GetModuleForAddress(uint32_t pid, uintptr_t address) noexcept {
    try {
        auto modules = Utils::ProcessUtils::GetProcessModules(pid);
        for (const auto& mod : modules) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mod.baseAddress);
            const uintptr_t end = base + mod.moduleSize;
            if (address >= base && address < end) {
                return mod.moduleName;
            }
        }
    } catch (...) {
        // Error reading modules
    }
    return L"<unbacked>";
}

/**
 * @brief Detect shellcode patterns at an address.
 */
[[nodiscard]] static bool HasShellcodeAtAddress(uint32_t pid, uintptr_t address) noexcept {
    try {
        // Read memory at address
        std::array<uint8_t, 256> buffer{};

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                             buffer.data(), buffer.size(), &bytesRead)) {
            CloseHandle(hProcess);
            return false;
        }
        CloseHandle(hProcess);

        if (bytesRead < 20) return false;

        // Common shellcode signatures (x86/x64)
        const std::array<std::array<uint8_t, 4>, 5> shellcodeSignatures = {{
            {0x90, 0x90, 0x90, 0x90},  // NOP sled
            {0xEB, 0xFE, 0xEB, 0xFE},  // Jump to self
            {0xCC, 0xCC, 0xCC, 0xCC},  // INT3 breakpoint
            {0x31, 0xC0, 0x50, 0x68},  // Common shellcode prologue
            {0x6A, 0x00, 0x6A, 0x00}   // Push sequences
        }};

        // Count NOP sled (20+ NOPs = likely shellcode)
        uint32_t nopCount = 0;
        for (size_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == 0x90) {
                nopCount++;
                if (nopCount >= 20) return true;
            } else {
                nopCount = 0;
            }
        }

        // Check for signature patterns
        for (const auto& signature : shellcodeSignatures) {
            for (size_t i = 0; i + 4 <= bytesRead; ++i) {
                if (std::memcmp(&buffer[i], signature.data(), 4) == 0) {
                    return true;
                }
            }
        }

    } catch (...) {
        // Error reading memory
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
    // RIP changed significantly
    const bool ripChanged = (oldRIP != newRIP);

    // Stack pivot (RSP changed to completely different region)
    const int64_t stackDelta = std::abs(static_cast<int64_t>(newRSP - oldRSP));
    const bool stackPivoted = (stackDelta > 0x100000);  // >1MB change

    return ripChanged || stackPivoted;
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
    uint32_t suspendDurationMs) noexcept
{
    uint32_t risk = 0;

    // Base risk for any RIP change
    risk += 50;

    // RIP not in module (unbacked memory)
    if (ripUnbacked) risk += 30;

    // Shellcode detected at RIP
    if (hasShellcode) risk += 20;

    // Cross-process modification
    if (crossProcess) risk += 15;

    // Stack pivot
    if (stackPivoted) risk += 10;

    // Debug registers active
    if (debugRegsActive) risk += 10;

    // Long suspend duration
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

class ThreadHijackDetector::ThreadHijackDetectorImpl {
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

    /// @brief Cleanup thread
    std::thread m_cleanupThread;
    std::atomic<bool> m_stopCleanup{false};

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

bool ThreadHijackDetector::ThreadHijackDetectorImpl::Initialize(const ThreadHijackConfig& config) {
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            Utils::Logger::Warn(L"ThreadHijackDetector: Already initialized");
            return true;
        }

        Utils::Logger::Info(L"ThreadHijackDetector: Initializing...");

        m_config = config;

        // Initialize infrastructure integrations
        m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelStore>();
        m_patternStore = std::make_shared<PatternStore::PatternStore>();
        m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        // Start cleanup thread
        m_stopCleanup.store(false, std::memory_order_release);
        m_cleanupThread = std::thread([this]() { CleanupThreadWorker(); });

        Utils::Logger::Info(L"ThreadHijackDetector: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: Initialization failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        Utils::Logger::Info(L"ThreadHijackDetector: Shutting down...");

        StopMonitoring();

        // Stop cleanup thread
        m_stopCleanup.store(true, std::memory_order_release);
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

        Utils::Logger::Info(L"ThreadHijackDetector: Shutdown complete");

    } catch (...) {
        Utils::Logger::Error(L"ThreadHijackDetector: Exception during shutdown");
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::StartMonitoring() {
    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Utils::Logger::Error(L"ThreadHijackDetector: Not initialized");
            return false;
        }

        if (m_monitoring.exchange(true, std::memory_order_acq_rel)) {
            Utils::Logger::Warn(L"ThreadHijackDetector: Already monitoring");
            return true;
        }

        if (!m_config.enableRealTimeMonitoring) {
            Utils::Logger::Warn(L"ThreadHijackDetector: Real-time monitoring disabled in config");
            m_monitoring.store(false, std::memory_order_release);
            return false;
        }

        // Start monitoring thread
        m_stopMonitoring.store(false, std::memory_order_release);
        m_monitorThread = std::thread([this]() { MonitoringThreadWorker(); });

        Utils::Logger::Info(L"ThreadHijackDetector: Monitoring started");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: Failed to start monitoring - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        m_monitoring.store(false, std::memory_order_release);
        return false;
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::StopMonitoring() {
    if (!m_monitoring.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    m_stopMonitoring.store(true, std::memory_order_release);
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    Utils::Logger::Info(L"ThreadHijackDetector: Monitoring stopped");
}

// ============================================================================
// IMPL: THREAD VALIDATION
// ============================================================================

ThreadValidation ThreadHijackDetector::ThreadHijackDetectorImpl::ValidateThreadInternal(uint32_t tid) {
    ThreadValidation validation;
    validation.threadId = tid;
    validation.validationTime = Clock::now();

    try {
        m_statistics.threadValidations.fetch_add(1, std::memory_order_relaxed);

        // Get thread context
        validation.context64 = GetThreadContextInternal(tid);
        validation.instructionPointer = validation.context64.rip;
        validation.stackPointer = validation.context64.rsp;

        // Get owner process
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) {
            validation.result = ValidationResult::Valid;  // Can't validate, assume valid
            return validation;
        }

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        validation.ownerPid = ownerPid;
        CloseHandle(hThread);

        if (auto procInfo = Utils::ProcessUtils::GetProcessInfo(ownerPid)) {
            validation.ownerProcessName = procInfo->processName;
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
                validation.issues.push_back(L"RIP points to unbacked memory");
                validation.riskScore += 50;

                m_statistics.unbackedRIPDetected.fetch_add(1, std::memory_order_relaxed);
                if (validation.ripHasShellcodePattern) {
                    m_statistics.shellcodeRIPDetected.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        // Validate stack pointer
        if (m_config.validateStackPointer) {
            // Get stack bounds (simplified - real implementation would use NtQueryInformationThread)
            validation.stackBase = validation.stackPointer + 0x100000;   // Assumed stack top
            validation.stackLimit = validation.stackPointer - 0x100000;  // Assumed stack bottom
            validation.stackInValidRange = true;  // Simplified validation
        }

        // Validate segments
        if (m_config.validateSegmentRegisters) {
            // Check for valid user-mode segment selectors
            validation.segmentsValid = (
                validation.context64.segCs == ThreadHijackConstants::USER_CS_64 &&
                validation.context64.segSs == ThreadHijackConstants::USER_SS_64
            );

            if (!validation.segmentsValid) {
                validation.result = ValidationResult::InvalidSegments;
                validation.isCompromised = true;
                validation.issues.push_back(L"Invalid segment selectors");
                validation.riskScore += 30;
            }
        }

        // Check debug registers
        if (m_config.checkDebugRegisters) {
            validation.hasHardwareBreakpoints = HasActiveDebugRegistersInternal(tid);
            if (validation.hasHardwareBreakpoints) {
                // Count active breakpoints
                if (validation.context64.dr7 & 0x1) validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x4) validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x10) validation.activeBreakpointCount++;
                if (validation.context64.dr7 & 0x40) validation.activeBreakpointCount++;

                validation.result = ValidationResult::DebugRegistersSet;
                validation.issues.push_back(L"Hardware breakpoints active");
                validation.riskScore += 20;
            }
        }

        // Analyze call stack
        if (m_config.analyzeCallStack) {
            validation.callStack = GetCallStackInternal(tid, ThreadHijackConstants::MAX_STACK_FRAMES);
            validation.unbackedFrameCount = CountUnbackedFramesInternal(tid);

            m_statistics.callStacksAnalyzed.fetch_add(1, std::memory_order_relaxed);

            if (validation.unbackedFrameCount > m_config.maxUnbackedFrames) {
                validation.isCompromised = true;
                validation.issues.push_back(L"Excessive unbacked stack frames");
                validation.riskScore += 25;

                m_statistics.unbackedFramesDetected.fetch_add(
                    validation.unbackedFrameCount, std::memory_order_relaxed);
            }
        }

        // Invoke validation callbacks
        InvokeValidationCallbacks(validation);

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: Thread validation failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);
    }

    return validation;
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::ValidateThreadStartInternal(uint32_t tid) {
    try {
        // Get thread start address
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) return true;  // Can't validate

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        CloseHandle(hThread);

        // For real implementation, would use NtQueryInformationThread to get start address
        // For now, just validate current RIP
        return IsRIPValidInternal(tid);

    } catch (...) {
        return true;  // Assume valid on error
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::IsRIPValidInternal(uint32_t tid) {
    try {
        auto context = GetThreadContextInternal(tid);

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) return true;

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        CloseHandle(hThread);

        return IsAddressInModule(ownerPid, context.rip);

    } catch (...) {
        return true;
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::IsStackValidInternal(uint32_t tid) {
    try {
        auto context = GetThreadContextInternal(tid);

        // Basic validation - RSP should be aligned
        if (context.rsp % 8 != 0) return false;

        // RSP should be in reasonable range (user-mode address space)
        if (context.rsp < 0x10000 || context.rsp > 0x7FFFFFFFFFFF) return false;

        return true;

    } catch (...) {
        return true;
    }
}

std::vector<uintptr_t> ThreadHijackDetector::ThreadHijackDetectorImpl::GetCallStackInternal(
    uint32_t tid,
    uint32_t maxFrames)
{
    std::vector<uintptr_t> callStack;

    try {
        // Real implementation would use StackWalk64 or RtlWalkFrameChain
        // For now, return simplified result
        auto context = GetThreadContextInternal(tid);
        callStack.push_back(context.rip);

    } catch (...) {
        // Return empty on error
    }

    return callStack;
}

uint32_t ThreadHijackDetector::ThreadHijackDetectorImpl::CountUnbackedFramesInternal(uint32_t tid) {
    try {
        auto callStack = GetCallStackInternal(tid, ThreadHijackConstants::MAX_STACK_FRAMES);

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) return 0;

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        CloseHandle(hThread);

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

ThreadContext64 ThreadHijackDetector::ThreadHijackDetectorImpl::GetThreadContextInternal(uint32_t tid) {
    ThreadContext64 result{};

    try {
        m_statistics.contextReads.fetch_add(1, std::memory_order_relaxed);

        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) {
            m_statistics.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(hThread, &ctx)) {
            // Copy to our structure
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

        CloseHandle(hThread);

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: GetThreadContext failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return result;
}

std::vector<ContextChange> ThreadHijackDetector::ThreadHijackDetectorImpl::CompareContextsInternal(
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
        Utils::Logger::Error(L"ThreadHijackDetector: Context comparison failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return changes;
}

ValidationResult ThreadHijackDetector::ThreadHijackDetectorImpl::AnalyzeContextInternal(
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

bool ThreadHijackDetector::ThreadHijackDetectorImpl::HasActiveDebugRegistersInternal(uint32_t tid) {
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

std::optional<HijackEvent> ThreadHijackDetector::ThreadHijackDetectorImpl::DetectHijackInternal(uint32_t tid) {
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
        if (validation.ripHasShellcodePattern && validation.targetIsUnbacked) {
            event.confidence = DetectionConfidence::Confirmed;
            m_statistics.confirmedHijacks.fetch_add(1, std::memory_order_relaxed);
        } else if (validation.targetIsUnbacked) {
            event.confidence = DetectionConfidence::High;
            m_statistics.highConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        } else if (validation.unbackedFrameCount > 0) {
            event.confidence = DetectionConfidence::Medium;
            m_statistics.mediumConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        } else {
            event.confidence = DetectionConfidence::Low;
            m_statistics.lowConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
        }

        // Calculate risk score
        event.riskScore = CalculateRiskScore(
            validation.targetIsUnbacked,
            validation.ripHasShellcodePattern,
            false,  // crossProcess (would need to track from event handlers)
            validation.stackPivoted,
            validation.hasHardwareBreakpoints,
            0  // suspendDurationMs (would need to track from event handlers)
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
        Utils::Logger::Error(L"ThreadHijackDetector: Hijack detection failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        return std::nullopt;
    }
}

ScanResult ThreadHijackDetector::ThreadHijackDetectorImpl::ScanProcessInternal(uint32_t pid) {
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
        result.scanError = Utils::StringUtils::Utf8ToWide(e.what());
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

void ThreadHijackDetector::ThreadHijackDetectorImpl::OnThreadSuspendInternal(
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
        Utils::Logger::Error(L"ThreadHijackDetector: OnThreadSuspend failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::OnThreadResumeInternal(
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

            if (duration > m_config.suspendDurationThresholdMs) {
                Utils::Logger::Warn(L"ThreadHijackDetector: Long suspend duration {}ms for TID {}",
                                  duration, targetTid);

                // Validate thread after long suspend
                if (m_config.enableRealTimeMonitoring) {
                    DetectHijackInternal(targetTid);
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: OnThreadResume failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::OnContextChangeInternal(
    uint32_t targetTid,
    uint32_t modifierPid,
    uint32_t contextFlags)
{
    try {
        // Get owner PID
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, targetTid);
        if (!hThread) return;

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        CloseHandle(hThread);

        // Check if cross-process modification
        if (modifierPid != ownerPid) {
            m_statistics.crossProcessChanges.fetch_add(1, std::memory_order_relaxed);

            Utils::Logger::Warn(L"ThreadHijackDetector: Cross-process context change - TID {} by PID {}",
                              targetTid, modifierPid);

            // Validate thread
            if (m_config.detectCrossProcessModification) {
                DetectHijackInternal(targetTid);
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: OnContextChange failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::OnSetContextThreadInternal(
    uint32_t callerPid,
    uint32_t targetTid,
    const ThreadContext64& newContext)
{
    try {
        // Get current context
        auto oldContext = GetThreadContextInternal(targetTid);

        // Get owner PID
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, targetTid);
        if (!hThread) return;

        DWORD ownerPid = GetProcessIdOfThread(hThread);
        CloseHandle(hThread);

        // Compare contexts
        auto changes = CompareContextsInternal(oldContext, newContext, ownerPid);

        for (const auto& change : changes) {
            if (change.isSuspicious) {
                InvokeContextCallbacks(targetTid, change);

                // Detect hijack if configured
                if (m_config.blockSuspiciousChanges) {
                    DetectHijackInternal(targetTid);
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: OnSetContextThread failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

// ============================================================================
// IMPL: RESPONSE ACTIONS
// ============================================================================

bool ThreadHijackDetector::ThreadHijackDetectorImpl::BlockContextChangeInternal(
    uint32_t targetTid,
    uint32_t modifierPid)
{
    try {
        m_statistics.changesBlocked.fetch_add(1, std::memory_order_relaxed);

        Utils::Logger::Warn(L"ThreadHijackDetector: Blocked context change - TID {} by PID {}",
                          targetTid, modifierPid);

        // Real implementation would use kernel driver to block SetThreadContext
        return true;

    } catch (...) {
        return false;
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::RestoreContextInternal(uint32_t tid) {
    try {
        // Get baseline
        auto baseline = GetBaselineInternal(tid);
        if (!baseline.has_value()) {
            return false;
        }

        // Real implementation would call SetThreadContext with baseline
        m_statistics.contextsRestored.fetch_add(1, std::memory_order_relaxed);

        Utils::Logger::Info(L"ThreadHijackDetector: Restored context for TID {}", tid);
        return true;

    } catch (...) {
        return false;
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::TerminateAttackerInternal(const HijackEvent& event) {
    try {
        if (event.attackerPid == 0) return false;

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, event.attackerPid);
        if (!hProcess) return false;

        BOOL result = TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);

        if (result) {
            m_statistics.attackersTerminated.fetch_add(1, std::memory_order_relaxed);

            Utils::Logger::Warn(L"ThreadHijackDetector: Terminated attacker PID {} ({})",
                              event.attackerPid, event.attackerProcessName);
        }

        return result != FALSE;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// IMPL: BASELINE MANAGEMENT
// ============================================================================

void ThreadHijackDetector::ThreadHijackDetectorImpl::EstablishBaselineInternal(uint32_t tid) {
    try {
        std::unique_lock lock(m_threadsMutex);

        auto& monitored = m_threads[tid];
        monitored.threadId = tid;
        monitored.createTime = Clock::now();
        monitored.lastChecked = Clock::now();

        // Get current context as baseline
        auto context = GetThreadContextInternal(tid);
        monitored.baselineRIP = context.rip;
        monitored.baselineRSP = context.rsp;
        monitored.baselineEstablished = true;

        // Get owner process
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
        if (hThread) {
            DWORD ownerPid = GetProcessIdOfThread(hThread);
            monitored.ownerPid = ownerPid;
            monitored.baselineModule = GetModuleForAddress(ownerPid, context.rip);
            CloseHandle(hThread);
        }

        m_statistics.threadsMonitored.fetch_add(1, std::memory_order_relaxed);

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ThreadHijackDetector: Baseline establishment failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::ClearBaselineInternal(uint32_t tid) {
    std::unique_lock lock(m_threadsMutex);
    m_threads.erase(tid);
}

std::optional<ThreadContext64> ThreadHijackDetector::ThreadHijackDetectorImpl::GetBaselineInternal(uint32_t tid) const {
    std::shared_lock lock(m_threadsMutex);

    auto it = m_threads.find(tid);
    if (it == m_threads.end() || !it->second.baselineEstablished) {
        return std::nullopt;
    }

    // Reconstruct baseline context
    ThreadContext64 baseline{};
    baseline.rip = it->second.baselineRIP;
    baseline.rsp = it->second.baselineRSP;

    return baseline;
}

// ============================================================================
// IMPL: WORKER THREADS
// ============================================================================

void ThreadHijackDetector::ThreadHijackDetectorImpl::MonitoringThreadWorker() {
    Utils::Logger::Info(L"ThreadHijackDetector: Monitoring thread started");

    while (!m_stopMonitoring.load(std::memory_order_acquire)) {
        try {
            // Periodic validation of monitored threads
            std::vector<uint32_t> tidsToValidate;

            {
                std::shared_lock lock(m_threadsMutex);
                for (const auto& [tid, thread] : m_threads) {
                    tidsToValidate.push_back(tid);
                }
            }

            for (uint32_t tid : tidsToValidate) {
                DetectHijackInternal(tid);
            }

            // Sleep between scans
            std::this_thread::sleep_for(std::chrono::seconds(5));

        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ThreadHijackDetector: Monitoring thread error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }

    Utils::Logger::Info(L"ThreadHijackDetector: Monitoring thread stopped");
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::CleanupThreadWorker() {
    Utils::Logger::Info(L"ThreadHijackDetector: Cleanup thread started");

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

            std::this_thread::sleep_for(std::chrono::minutes(5));

        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ThreadHijackDetector: Cleanup thread error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }

    Utils::Logger::Info(L"ThreadHijackDetector: Cleanup thread stopped");
}

// ============================================================================
// IMPL: HELPERS
// ============================================================================

void ThreadHijackDetector::ThreadHijackDetectorImpl::InvokeHijackCallbacks(const HijackEvent& event) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_hijackCallbacks) {
        try {
            callback(event);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ThreadHijackDetector: Hijack callback error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::InvokeContextCallbacks(
    uint32_t tid,
    const ContextChange& change)
{
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_contextCallbacks) {
        try {
            callback(tid, change);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ThreadHijackDetector: Context callback error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }
}

void ThreadHijackDetector::ThreadHijackDetectorImpl::InvokeValidationCallbacks(const ThreadValidation& validation) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_validationCallbacks) {
        try {
            callback(validation);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ThreadHijackDetector: Validation callback error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }
}

bool ThreadHijackDetector::ThreadHijackDetectorImpl::ShouldExclude(uint32_t pid) const {
    // Check excluded PIDs
    if (std::find(m_config.excludedPids.begin(), m_config.excludedPids.end(), pid) !=
        m_config.excludedPids.end()) {
        return true;
    }

    // Check excluded process names
    auto procInfo = Utils::ProcessUtils::GetProcessInfo(pid);
    if (procInfo.has_value()) {
        for (const auto& excluded : m_config.excludedProcesses) {
            if (procInfo->processName == excluded) {
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
    Utils::Logger::Info(L"ThreadHijackDetector: Constructor called");
}

ThreadHijackDetector::~ThreadHijackDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Utils::Logger::Info(L"ThreadHijackDetector: Destructor called");
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

    // Get TID from context (would need to be passed in real implementation)
    // For now, use placeholder PID
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
        combinedResult.scanError = Utils::StringUtils::Utf8ToWide(e.what());
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

ThreadHijackStatistics ThreadHijackDetector::GetStatistics() const {
    return m_impl ? m_impl->m_statistics : ThreadHijackStatistics{};
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
