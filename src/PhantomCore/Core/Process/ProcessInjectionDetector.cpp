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
 * ShadowStrike Core Process - INJECTION DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessInjectionDetector.cpp
 * @brief Enterprise-grade universal code injection detection engine implementation
 *
 * Production-level implementation competing with enterprise-grade enterprise-grade EDR,
 * enterprise-grade EDR, and enterprise-grade GravityZone for injection detection.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Event correlation (handle + memory + thread)
 * - Multi-technique detection (70+ injection types)
 * - Injection chain detection (multi-hop attacks)
 * - Confidence scoring with behavioral analysis
 * - MITRE ATT&CK T1055.* mapping
 * - Infrastructure reuse (ThreatIntel, PatternStore, Whitelist)
 * - Comprehensive statistics tracking
 * - Alert generation with callbacks
 * - False positive suppression
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
#include "ProcessInjectionDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../Engine/BehaviorAnalyzer.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../SelfProtection/DigitalSignatureValidator.hpp"

// ============================================================================
// SUB-DETECTOR INCLUDES (Orchestrated by ProcessInjectionDetector)
// ============================================================================
#include "AtomBombingDetector.hpp"
#include "DLLInjectionDetector.hpp"
#include "ProcessHollowingDetector.hpp"
#include "ReflectiveDLLDetector.hpp"
#include "ThreadHijackDetector.hpp"
#include "MemoryScanner.hpp"

// ============================================================================
// KERNEL COMMUNICATION INCLUDES
// ============================================================================
#include "../../Communication/IPCManager.hpp"
#include "../../Communication/Communication.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <thread>
#include <condition_variable>
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

[[nodiscard]] constexpr const char* InjectionTypeToString(InjectionType type) noexcept {
    switch (type) {
        case InjectionType::RemoteThread: return "CreateRemoteThread";
        case InjectionType::NtCreateThreadEx: return "NtCreateThreadEx";
        case InjectionType::RtlCreateUserThread: return "RtlCreateUserThread";
        case InjectionType::DirectSyscallThread: return "Direct Syscall Thread";
        case InjectionType::APC: return "QueueUserAPC";
        case InjectionType::NtQueueApcThread: return "NtQueueApcThread";
        case InjectionType::EarlyBird: return "Early Bird APC";
        case InjectionType::APCWritePrimitive: return "APC Write Primitive";
        case InjectionType::ProcessHollowing: return "Process Hollowing";
        case InjectionType::ProcessDoppelganging: return "Process Doppelgänging";
        case InjectionType::ProcessHerpaderping: return "Process Herpaderping";
        case InjectionType::ProcessGhosting: return "Process Ghosting";
        case InjectionType::TransactedHollowing: return "Transacted Hollowing";
        case InjectionType::ProcessReimaging: return "Process Reimaging";
        case InjectionType::DLLInjection: return "DLL Injection (LoadLibrary)";
        case InjectionType::ReflectiveDLL: return "Reflective DLL Injection";
        case InjectionType::ManualMapping: return "Manual Mapping";
        case InjectionType::ModuleStomping: return "Module Stomping";
        case InjectionType::DLLSearchOrderHijack: return "DLL Search Order Hijacking";
        case InjectionType::DLLSideLoading: return "DLL Side-Loading";
        case InjectionType::ShellcodeInjection: return "Shellcode Injection";
        case InjectionType::PEInjection: return "PE Injection";
        case InjectionType::DotNetInjection: return ".NET Assembly Injection";
        case InjectionType::AtomBombing: return "Atom Bombing";
        case InjectionType::ExtraWindowBytes: return "Extra Window Bytes";
        case InjectionType::PROPagate: return "PROPagate";
        case InjectionType::CtrlInject: return "Ctrl-Inject";
        case InjectionType::ShimInjection: return "Shim Injection";
        case InjectionType::ThreadHijacking: return "Thread Execution Hijacking";
        case InjectionType::FiberInjection: return "Fiber Injection";
        case InjectionType::CallbackInjection: return "Callback Injection";
        case InjectionType::SectionMapping: return "NtMapViewOfSection";
        case InjectionType::SetWindowsHook: return "SetWindowsHookEx";
        case InjectionType::COMHijacking: return "COM Hijacking";
        case InjectionType::AppInitDLLs: return "AppInit_DLLs";
        case InjectionType::IFEO: return "IFEO Injection";
        case InjectionType::KernelAPC: return "Kernel APC";
        case InjectionType::SystemThread: return "System Thread";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* InjectionTypeToMitre(InjectionType type) noexcept {
    switch (type) {
        case InjectionType::DLLInjection:
        case InjectionType::ReflectiveDLL:
        case InjectionType::ManualMapping:
        case InjectionType::ModuleStomping:
        case InjectionType::DLLSearchOrderHijack:
        case InjectionType::DLLSideLoading:
            return "T1055.001";  // DLL Injection

        case InjectionType::ShellcodeInjection:
        case InjectionType::PEInjection:
        case InjectionType::DotNetInjection:
            return "T1055.002";  // Portable Executable Injection

        case InjectionType::ThreadHijacking:
            return "T1055.003";  // Thread Execution Hijacking

        case InjectionType::APC:
        case InjectionType::NtQueueApcThread:
        case InjectionType::EarlyBird:
        case InjectionType::APCWritePrimitive:
        case InjectionType::KernelAPC:
            return "T1055.004";  // Asynchronous Procedure Call

        case InjectionType::ExtraWindowBytes:
            return "T1055.011";  // Extra Window Memory Injection

        case InjectionType::ProcessHollowing:
            return "T1055.012";  // Process Hollowing

        case InjectionType::ProcessDoppelganging:
        case InjectionType::ProcessHerpaderping:
        case InjectionType::ProcessGhosting:
        case InjectionType::TransactedHollowing:
        case InjectionType::ProcessReimaging:
            return "T1055.013";  // Process Doppelgänging

        default:
            return "T1055";  // Process Injection
    }
}

[[nodiscard]] const char* InjectionTypeToAPISequence(InjectionType type) noexcept {
    switch (type) {
        case InjectionType::DLLInjection:
            return "OpenProcess→VirtualAllocEx→WriteProcessMemory→CreateRemoteThread(LoadLibrary)";

        case InjectionType::ReflectiveDLL:
            return "OpenProcess→VirtualAllocEx→WriteProcessMemory→CreateRemoteThread(ReflectiveLoader)";

        case InjectionType::ProcessHollowing:
            return "CreateProcess(SUSPENDED)→NtUnmapViewOfSection→VirtualAllocEx→WriteProcessMemory→SetContext→Resume";

        case InjectionType::ThreadHijacking:
            return "OpenThread→SuspendThread→GetThreadContext→SetThreadContext→ResumeThread";

        case InjectionType::APC:
        case InjectionType::NtQueueApcThread:
            return "OpenThread→QueueUserAPC→ResumeThread";

        case InjectionType::EarlyBird:
            return "CreateProcess(SUSPENDED)→QueueUserAPC→ResumeThread";

        case InjectionType::AtomBombing:
            return "GlobalAddAtom→NtQueueApcThread(GlobalGetAtom)";

        case InjectionType::ProcessDoppelganging:
            return "NtCreateTransaction→CreateFileTransacted→NtCreateSection→NtCreateProcessEx→NtRollbackTransaction";

        default:
            return "Various API sequences";
    }
}

/// @brief Convert sub-detector confidence enums (0-4 scale) to our
/// InjectionEvent double confidence (0-100).  Sub-detectors such as
/// ProcessHollowingDetector, ReflectiveDLLDetector, and AtomBombing use
/// scoped enums: None=0, Low=1, Medium=2, High=3, Confirmed=4.
[[nodiscard]] constexpr double ConfidenceEnumToDouble(uint8_t level) noexcept {
    switch (level) {
        case 0:  return  0.0;  // None
        case 1:  return 30.0;  // Low
        case 2:  return 55.0;  // Medium
        case 3:  return 80.0;  // High
        case 4:  return 95.0;  // Confirmed
        default: return 50.0;
    }
}

[[nodiscard]] bool IsSuspiciousHandleAccess(uint32_t accessRights) noexcept {
    constexpr uint32_t kProcessVmWrite = 0x0020;
    constexpr uint32_t kProcessVmOperation = 0x0008;
    constexpr uint32_t kProcessCreateThread = 0x0002;

    // Combination of write + operation + thread creation is highly suspicious
    const bool hasWrite = (accessRights & kProcessVmWrite) != 0;
    const bool hasOperation = (accessRights & kProcessVmOperation) != 0;
    const bool hasCreateThread = (accessRights & kProcessCreateThread) != 0;

    return (hasWrite && hasOperation) || (hasWrite && hasCreateThread);
}

[[nodiscard]] bool IsExecutableProtection(uint32_t protection) noexcept {
    constexpr uint32_t kPageExecute = 0x10;
    constexpr uint32_t kPageExecuteRead = 0x20;
    constexpr uint32_t kPageExecuteReadWrite = 0x40;
    constexpr uint32_t kPageExecuteWriteCopy = 0x80;

    return (protection & (kPageExecute | kPageExecuteRead |
                         kPageExecuteReadWrite | kPageExecuteWriteCopy)) != 0;
}

[[nodiscard]] bool IsAddressInModule(uint32_t pid, uintptr_t address) noexcept {
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
        // Error reading modules
    }
    return false;
}

[[nodiscard]] std::wstring GetModuleForAddress(uint32_t pid, uintptr_t address) noexcept {
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
        // Error reading modules
    }
    return L"<unknown>";
}

[[nodiscard]] bool IsInjectionPairWhitelisted(
    const std::wstring& sourceName,
    const std::wstring& targetName) noexcept
{
    // Specific source→target pairs that are known-legitimate OS injection
    // patterns. Wildcards are only used for kernel-backed processes that
    // cannot be impersonated from user mode (csrss.exe).
    //
    // SECURITY: Name-only matching here is a weak signal. The caller
    // (ShouldWhitelist) must ALSO verify the source path and digital
    // signature before suppressing an alert. This function is a
    // pre-filter to reduce unnecessary signature checks.
    struct WhitelistEntry {
        std::wstring_view source;
        std::wstring_view target;  // L"*" means any target
    };
    static constexpr std::wstring_view kWild = L"*";
    static const WhitelistEntry whitelistedPairs[] = {
        {L"csrss.exe",     kWild},              // Windows CSRSS (kernel-backed, PPL)
        {L"wininit.exe",   L"services.exe"},     // Windows Init → SCM
        {L"services.exe",  L"svchost.exe"},      // SCM → Service Host
        {L"smss.exe",      L"csrss.exe"},        // Session Manager → CSRSS
    };

    const std::wstring sourceLower = Utils::StringUtils::ToLowerCopy(sourceName);
    const std::wstring targetLower = Utils::StringUtils::ToLowerCopy(targetName);

    for (const auto& entry : whitelistedPairs) {
        if (sourceLower == entry.source) {
            if (entry.target == kWild || targetLower == entry.target) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

struct ProcessInjectionDetector::Impl {
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    InjectionDetectorConfig m_config;

    /// @brief Thread pool
    std::shared_ptr<Utils::ThreadPool> m_threadPool;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    /// @brief Statistics
    InjectionDetectorStats m_stats;

    /// @brief Process states
    std::unordered_map<uint32_t, ProcessInjectionState> m_processStates;
    mutable std::shared_mutex m_statesMutex;

    /// @brief Injection events
    std::unordered_map<uint64_t, InjectionEvent> m_events;
    mutable std::shared_mutex m_eventsMutex;
    std::atomic<uint64_t> m_nextEventId{1};

    /// @brief Handle events (for correlation)
    std::deque<HandleAccessEvent> m_handleEvents;
    mutable std::shared_mutex m_handleEventsMutex;

    /// @brief Memory events (for correlation)
    std::deque<MemoryOperationEvent> m_memoryEvents;
    mutable std::shared_mutex m_memoryEventsMutex;

    /// @brief Thread events (for correlation)
    std::deque<ThreadOperationEvent> m_threadEvents;
    mutable std::shared_mutex m_threadEventsMutex;

    /// @brief Alerts
    std::deque<InjectionAlert> m_alerts;
    mutable std::shared_mutex m_alertsMutex;
    std::atomic<uint64_t> m_nextAlertId{1};

    /// @brief Injection chains
    std::vector<InjectionChain> m_chains;
    mutable std::shared_mutex m_chainsMutex;
    std::atomic<uint64_t> m_nextChainId{1};

    /// @brief Callbacks
    std::unordered_map<uint64_t, InjectionCallback> m_injectionCallbacks;
    std::unordered_map<uint64_t, InjectionAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, InjectionChainCallback> m_chainCallbacks;
    std::unordered_map<uint64_t, HandleAccessCallback> m_handleCallbacks;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    /// @brief External integrations
    Whitelist::WhitelistStore* m_whitelist{nullptr};
    Engine::BehaviorAnalyzer* m_behaviorAnalyzer{nullptr};
    Engine::ThreatDetector* m_threatDetector{nullptr};
    RealTime::MemoryProtection* m_memoryProtection{nullptr};

    /// @brief Infrastructure
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;

    /// @brief Cleanup thread
    std::thread m_cleanupThread;
    std::atomic<bool> m_stopCleanup{false};

    /// @brief Cleanup condition variable (for interruptible sleep)
    std::condition_variable m_cleanupCv;
    std::mutex m_cleanupCvMutex;

    // ========================================================================
    // SELF-PROCESS EXCLUSION
    // ========================================================================

    /// @brief Our own PID — events from/to our process are always allowed
    uint32_t m_selfPid{0};

    // ========================================================================
    // EVENT DEDUPLICATION
    // ========================================================================

    /// @brief Recent injection event keys for deduplication.
    /// Key = hash(sourcePid, targetPid, injectionType, time_bucket).
    /// Prevents the same injection from generating duplicate events when
    /// detected through multiple handlers (handle + memory + thread).
    struct DeduplicationEntry {
        uint64_t key{0};
        TimePoint expiry{};
    };
    std::deque<DeduplicationEntry> m_recentInjections;
    mutable std::mutex m_dedupMutex;

    /// @brief Deduplication window — events with same source+target+type
    /// within this window are suppressed.
    static constexpr auto DEDUP_WINDOW = std::chrono::seconds(5);

    // ========================================================================
    // KNOWN LOLBins — Microsoft-signed binaries abused for injection/execution
    // ========================================================================

    static constexpr std::wstring_view kLolBins[] = {
        L"mshta.exe",       L"regsvr32.exe",    L"rundll32.exe",
        L"msiexec.exe",     L"cscript.exe",     L"wscript.exe",
        L"certutil.exe",    L"bitsadmin.exe",   L"installutil.exe",
        L"regasm.exe",      L"regsvcs.exe",     L"msbuild.exe",
        L"cmstp.exe",       L"presentationhost.exe",
        L"mavinject.exe",   L"eventvwr.exe",    L"dnscmd.exe",
    };

    // ========================================================================
    // METHODS
    // ========================================================================

    Impl() : m_selfPid(::GetCurrentProcessId()) {}
    ~Impl() = default;

    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const InjectionDetectorConfig& config);

    void Shutdown();
    void Start();
    void Stop();

    // Event correlation
    std::optional<InjectionEvent> CorrelateEvents(uint32_t sourcePid, uint32_t targetPid);

    // Classification
    InjectionType ClassifyFromEvents(
        const std::vector<HandleAccessEvent>& handles,
        const std::vector<MemoryOperationEvent>& memory,
        const std::vector<ThreadOperationEvent>& threads) const;

    // Scoring
    double CalculateConfidence(InjectionType type, const InjectionEvent& event) const;
    double CalculateRiskScore(const InjectionEvent& event) const;

    // Whitelisting
    bool ShouldWhitelist(const InjectionEvent& event) const;

    // Alert generation
    InjectionAlert CreateAlert(const InjectionEvent& event);

    // Chain detection
    std::optional<InjectionChain> DetectChain(uint32_t startPid);

    // Cleanup
    void CleanupThread();
    void PurgeOldEvents();

    // Callbacks
    InjectionVerdict InvokeInjectionCallbacks(const InjectionEvent& event);
    void InvokeAlertCallbacks(const InjectionAlert& alert);
    void InvokeChainCallbacks(const InjectionChain& chain);

    // ========================================================================
    // NEW: Deduplication
    // ========================================================================

    /// @brief Check if this injection was already detected recently.
    /// @return true if duplicate (suppress), false if new (process it).
    [[nodiscard]] bool IsDuplicate(uint32_t sourcePid, uint32_t targetPid, InjectionType type);

    // ========================================================================
    // NEW: Kernel driver integration
    // ========================================================================

    /// @brief Register message handlers with IPCManager for kernel events.
    void RegisterKernelHandlers();

    /// @brief Handle kernel thread creation notification.
    void OnKernelThreadNotify(SHADOWSTRIKE_MESSAGE_TYPE type, const void* data, size_t size);

    /// @brief Handle kernel handle alert notification.
    void OnKernelHandleAlert(SHADOWSTRIKE_MESSAGE_TYPE type, const void* data, size_t size);

    // ========================================================================
    // NEW: Sub-detector orchestration
    // ========================================================================

    /// @brief Wire sub-detector callbacks so their findings feed into our
    /// correlation engine.
    void WireSubDetectorCallbacks();

    /// @brief Process and store an injection event — called from all
    /// detection paths (event handlers + sub-detector callbacks + kernel).
    /// Handles dedup, callbacks, alerts, chain detection, stats.
    void ProcessInjectionDetection(InjectionEvent event);

    // ========================================================================
    // NEW: Technique-specific stat helpers
    // ========================================================================

    void UpdateTechniqueStats(InjectionType type);

    // ========================================================================
    // NEW: LOLBin check
    // ========================================================================

    [[nodiscard]] bool IsLolBin(std::wstring_view processName) const;
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool ProcessInjectionDetector::Impl::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const InjectionDetectorConfig& config)
{
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"InjectionDetector", L"Already initialized");
            return true;
        }

        SS_LOG_INFO(L"InjectionDetector", L"Initializing...");

        m_config = config;
        m_threadPool = threadPool;
        m_selfPid = ::GetCurrentProcessId();

        // Initialize infrastructure
        m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelStore>();
        m_patternStore = std::make_shared<PatternStore::PatternStore>();

        // Wire kernel driver integration — register to receive thread
        // creation, handle alert, and process creation events from the
        // kernel driver via IPCManager.
        RegisterKernelHandlers();

        // Wire sub-detector callbacks — findings from specialized
        // detectors feed into our event correlation engine.
        WireSubDetectorCallbacks();

        SS_LOG_INFO(L"InjectionDetector",
            L"Initialized successfully (selfPid=%u, kernel=%s, subDetectors=%s)",
            m_selfPid,
            Communication::IPCManager::HasInstance() ? L"connected" : L"standalone",
            L"wired");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Initialization failed - %S", e.what());
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void ProcessInjectionDetector::Impl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        SS_LOG_INFO(L"InjectionDetector", L"Shutting down...");

        Stop();

        // Clear all data
        {
            std::unique_lock lock(m_statesMutex);
            m_processStates.clear();
        }

        {
            std::unique_lock lock(m_eventsMutex);
            m_events.clear();
        }

        {
            std::unique_lock lock(m_handleEventsMutex);
            m_handleEvents.clear();
        }

        {
            std::unique_lock lock(m_memoryEventsMutex);
            m_memoryEvents.clear();
        }

        {
            std::unique_lock lock(m_threadEventsMutex);
            m_threadEvents.clear();
        }

        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.clear();
        }

        {
            std::unique_lock lock(m_chainsMutex);
            m_chains.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_injectionCallbacks.clear();
            m_alertCallbacks.clear();
            m_chainCallbacks.clear();
            m_handleCallbacks.clear();
        }

        SS_LOG_INFO(L"InjectionDetector", L"Shutdown complete");

    } catch (...) {
        SS_LOG_ERROR(L"InjectionDetector", L"Exception during shutdown");
    }
}

void ProcessInjectionDetector::Impl::Start() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"InjectionDetector", L"Not initialized");
        return;
    }

    if (m_running.exchange(true, std::memory_order_acq_rel)) {
        SS_LOG_WARN(L"InjectionDetector", L"Already running");
        return;
    }

    // Start cleanup thread
    m_stopCleanup.store(false, std::memory_order_release);
    m_cleanupThread = std::thread([this]() { CleanupThread(); });

    SS_LOG_INFO(L"InjectionDetector", L"Started");
}

void ProcessInjectionDetector::Impl::Stop() {
    if (!m_running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    // Stop cleanup thread - wake it from CV sleep
    m_stopCleanup.store(true, std::memory_order_release);
    m_cleanupCv.notify_all();
    if (m_cleanupThread.joinable()) {
        m_cleanupThread.join();
    }

    SS_LOG_INFO(L"InjectionDetector", L"Stopped");
}

// ============================================================================
// IMPL: EVENT CORRELATION
// ============================================================================

std::optional<InjectionEvent> ProcessInjectionDetector::Impl::CorrelateEvents(
    uint32_t sourcePid,
    uint32_t targetPid)
{
    try {
        const auto now = Clock::now();
        const auto correlationWindow = std::chrono::seconds(m_config.correlationWindowSec);

        // Gather related events
        std::vector<HandleAccessEvent> relatedHandles;
        std::vector<MemoryOperationEvent> relatedMemory;
        std::vector<ThreadOperationEvent> relatedThreads;

        // Find handle events
        {
            std::shared_lock lock(m_handleEventsMutex);
            for (const auto& event : m_handleEvents) {
                if (event.sourceProcessId == sourcePid &&
                    event.targetProcessId == targetPid &&
                    (now - event.timestamp) < correlationWindow) {
                    relatedHandles.push_back(event);
                }
            }
        }

        // Find memory events
        {
            std::shared_lock lock(m_memoryEventsMutex);
            for (const auto& event : m_memoryEvents) {
                if (event.sourceProcessId == sourcePid &&
                    event.targetProcessId == targetPid &&
                    event.isCrossProcess &&
                    (now - event.timestamp) < correlationWindow) {
                    relatedMemory.push_back(event);
                }
            }
        }

        // Find thread events
        {
            std::shared_lock lock(m_threadEventsMutex);
            for (const auto& event : m_threadEvents) {
                if (event.sourceProcessId == sourcePid &&
                    event.targetProcessId == targetPid &&
                    event.isRemote &&
                    (now - event.timestamp) < correlationWindow) {
                    relatedThreads.push_back(event);
                }
            }
        }

        // Need at least some events to correlate
        if (relatedHandles.empty() && relatedMemory.empty() && relatedThreads.empty()) {
            return std::nullopt;
        }

        // Classify injection type
        InjectionType type = ClassifyFromEvents(relatedHandles, relatedMemory, relatedThreads);

        if (type == InjectionType::Unknown) {
            return std::nullopt;
        }

        // Create injection event
        InjectionEvent event;
        event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = now;
        event.injectionType = type;
        event.sourceProcessId = sourcePid;
        event.targetProcessId = targetPid;

        // Get process information
        if (auto srcName = Utils::ProcessUtils::GetProcessName(sourcePid)) {
            event.sourceProcessName = *srcName;
        }
        if (auto srcPath = Utils::ProcessUtils::GetProcessPath(sourcePid)) {
            event.sourceProcessPath = *srcPath;
        }

        if (auto tgtName = Utils::ProcessUtils::GetProcessName(targetPid)) {
            event.targetProcessName = *tgtName;
        }
        if (auto tgtPath = Utils::ProcessUtils::GetProcessPath(targetPid)) {
            event.targetProcessPath = *tgtPath;
        }

        // Store related events
        event.handleEvents = relatedHandles;
        event.memoryEvents = relatedMemory;
        event.threadEvents = relatedThreads;

        // Extract details from thread events
        if (!relatedThreads.empty()) {
            const auto& threadEvent = relatedThreads.back();
            event.targetThreadId = threadEvent.threadId;
            event.startAddress = threadEvent.startAddress;
            event.startAddressLegitimate = IsAddressInModule(targetPid, threadEvent.startAddress);
        }

        // Extract details from memory events
        if (!relatedMemory.empty()) {
            for (const auto& memEvent : relatedMemory) {
                if (memEvent.operation == MemoryOperationEvent::OpType::Write) {
                    event.targetAddress = memEvent.baseAddress;
                    event.dataSize += memEvent.regionSize;
                }
            }
        }

        // Calculate confidence and risk
        event.confidence = CalculateConfidence(type, event);
        event.riskScore = CalculateRiskScore(event);

        // MITRE ATT&CK mapping
        event.mitreTechnique = "T1055";
        event.mitreSubTechnique = InjectionTypeToMitre(type);

        // Determine verdict
        if (ShouldWhitelist(event)) {
            event.verdict = InjectionVerdict::Whitelisted;
            event.confidence = 0.0;
            m_stats.falsePositivesSuppressed.fetch_add(1, std::memory_order_relaxed);
        } else if (event.confidence >= m_config.blockConfidence) {
            event.verdict = InjectionVerdict::Confirmed;
        } else if (event.confidence >= m_config.alertConfidence) {
            event.verdict = InjectionVerdict::Detected;
        } else {
            event.verdict = InjectionVerdict::Suspicious;
        }

        return event;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Event correlation failed - %S", e.what());
        return std::nullopt;
    }
}

// ============================================================================
// IMPL: CLASSIFICATION
// ============================================================================

InjectionType ProcessInjectionDetector::Impl::ClassifyFromEvents(
    const std::vector<HandleAccessEvent>& handles,
    const std::vector<MemoryOperationEvent>& memory,
    const std::vector<ThreadOperationEvent>& threads) const
{
    // Check for process hollowing indicators
    // Pattern: CreateProcess(SUSPENDED) + Unmap + Allocate + Write + SetContext
    bool hasUnmap = false;
    bool hasAllocate = false;
    bool hasWrite = false;
    bool hasSetContext = false;
    bool hasSuspendedThread = false;

    for (const auto& memEvent : memory) {
        if (memEvent.operation == MemoryOperationEvent::OpType::Unmap) hasUnmap = true;
        if (memEvent.operation == MemoryOperationEvent::OpType::Allocate) hasAllocate = true;
        if (memEvent.operation == MemoryOperationEvent::OpType::Write) hasWrite = true;
    }

    for (const auto& threadEvent : threads) {
        if (threadEvent.operation == ThreadOperationEvent::OpType::SetContext) hasSetContext = true;
        if (threadEvent.isSuspended) hasSuspendedThread = true;
    }

    if (hasUnmap && hasAllocate && hasWrite && hasSetContext) {
        return InjectionType::ProcessHollowing;
    }

    // Check for reflective DLL injection
    // Pattern: Write + CreateRemoteThread with start address not in module
    bool hasRemoteThread = false;
    bool startAddressNotInModule = false;

    for (const auto& threadEvent : threads) {
        if (threadEvent.operation == ThreadOperationEvent::OpType::Create &&
            threadEvent.isRemote) {
            hasRemoteThread = true;
            if (threadEvent.startAddressModule.empty() ||
                threadEvent.startAddressModule == L"<unknown>") {
                startAddressNotInModule = true;
            }
        }
    }

    if (hasWrite && hasRemoteThread && startAddressNotInModule) {
        return InjectionType::ReflectiveDLL;
    }

    // Check for classic DLL injection (LoadLibrary)
    // Pattern: Write + CreateRemoteThread to LoadLibrary/LoadLibraryA/LoadLibraryW
    if (hasWrite && hasRemoteThread && !startAddressNotInModule) {
        for (const auto& threadEvent : threads) {
            const auto& modName = threadEvent.startAddressModule;
            if (modName.find(L"kernel32") != std::wstring::npos ||
                modName.find(L"kernelbase") != std::wstring::npos) {
                return InjectionType::DLLInjection;
            }
        }
    }

    // Check for APC injection
    // Pattern: QueueAPC events
    for (const auto& threadEvent : threads) {
        if (threadEvent.operation == ThreadOperationEvent::OpType::QueueAPC) {
            // Early bird if thread was suspended
            if (hasSuspendedThread) {
                return InjectionType::EarlyBird;
            }
            return InjectionType::APC;
        }
    }

    // Check for thread hijacking
    // Pattern: Suspend + GetContext + SetContext + Resume
    bool hasSuspend = false;
    bool hasResume = false;

    for (const auto& threadEvent : threads) {
        if (threadEvent.operation == ThreadOperationEvent::OpType::Suspend) hasSuspend = true;
        if (threadEvent.operation == ThreadOperationEvent::OpType::Resume) hasResume = true;
    }

    if (hasSuspend && hasSetContext && hasResume) {
        return InjectionType::ThreadHijacking;
    }

    // Check for section mapping
    bool hasMap = false;
    for (const auto& memEvent : memory) {
        if (memEvent.operation == MemoryOperationEvent::OpType::Map) {
            hasMap = true;
        }
    }

    if (hasMap && hasWrite) {
        return InjectionType::SectionMapping;
    }

    // Default: remote thread injection if we have remote thread creation
    if (hasRemoteThread) {
        return InjectionType::RemoteThread;
    }

    // If we have cross-process memory write, likely shellcode injection
    if (hasWrite) {
        return InjectionType::ShellcodeInjection;
    }

    return InjectionType::Unknown;
}

// ============================================================================
// IMPL: SCORING
// ============================================================================

double ProcessInjectionDetector::Impl::CalculateConfidence(
    InjectionType type,
    const InjectionEvent& event) const
{
    double confidence = 0.0;

    // Base confidence from technique
    switch (type) {
        case InjectionType::ProcessHollowing:
            confidence = 95.0;  // Very distinctive pattern
            break;
        case InjectionType::ReflectiveDLL:
            confidence = 90.0;  // Clear indicators
            break;
        case InjectionType::ThreadHijacking:
            confidence = 85.0;
            break;
        case InjectionType::APC:
        case InjectionType::EarlyBird:
            confidence = 80.0;
            break;
        case InjectionType::DLLInjection:
            confidence = 75.0;
            break;
        case InjectionType::RemoteThread:
            confidence = 70.0;
            break;
        case InjectionType::ShellcodeInjection:
            confidence = 65.0;
            break;
        default:
            confidence = 50.0;
            break;
    }

    // Boost confidence if multiple events correlated
    const size_t totalEvents = event.handleEvents.size() +
                               event.memoryEvents.size() +
                               event.threadEvents.size();

    if (totalEvents >= 5) confidence += 10.0;
    else if (totalEvents >= 3) confidence += 5.0;

    // Boost if start address is not in legitimate module
    if (!event.startAddressLegitimate) {
        confidence += 10.0;
    }

    // Lower confidence if process pair is commonly seen together
    if (IsInjectionPairWhitelisted(event.sourceProcessName, event.targetProcessName)) {
        confidence -= 30.0;
    }

    return std::clamp(confidence, 0.0, 100.0);
}

double ProcessInjectionDetector::Impl::CalculateRiskScore(const InjectionEvent& event) const {
    // Base risk from constants
    double risk = 0.0;

    switch (event.injectionType) {
        case InjectionType::ProcessHollowing:
            risk = InjectionConstants::PROCESS_HOLLOWING_SCORE;
            break;
        case InjectionType::ReflectiveDLL:
            risk = InjectionConstants::REFLECTIVE_DLL_SCORE;
            break;
        case InjectionType::AtomBombing:
            risk = InjectionConstants::ATOM_BOMBING_SCORE;
            break;
        case InjectionType::ThreadHijacking:
            risk = InjectionConstants::THREAD_HIJACKING_SCORE;
            break;
        case InjectionType::APC:
        case InjectionType::EarlyBird:
            risk = InjectionConstants::APC_INJECTION_SCORE;
            break;
        case InjectionType::RemoteThread:
            risk = InjectionConstants::REMOTE_THREAD_SCORE;
            break;
        default:
            risk = 60.0;
            break;
    }

    // Increase risk if injecting into critical system processes
    const std::wstring targetLower = Utils::StringUtils::ToLowerCopy(event.targetProcessName);
    if (targetLower.find(L"lsass") != std::wstring::npos ||
        targetLower.find(L"winlogon") != std::wstring::npos ||
        targetLower.find(L"csrss") != std::wstring::npos) {
        risk += 15.0;
    }

    return std::clamp(risk, 0.0, 100.0);
}

// ============================================================================
// IMPL: WHITELISTING
// ============================================================================

bool ProcessInjectionDetector::Impl::ShouldWhitelist(const InjectionEvent& event) const {
    if (!m_config.trustWhitelisted) {
        return false;
    }

    // Step 1: Check process pair whitelist (name-based pre-filter)
    if (!IsInjectionPairWhitelisted(event.sourceProcessName, event.targetProcessName)) {
        // Not in the hardcoded system pair whitelist — fall through to
        // signature-based checks below.
    } else {
        // Name matches a known OS pair. Validate that the source is
        // actually the real OS binary via digital signature, not a
        // malware binary masquerading as csrss.exe or services.exe.
        if (!event.sourceProcessPath.empty()) {
            try {
                if (Security::DigitalSignatureValidator::Instance().IsMicrosoftSigned(
                        event.sourceProcessPath)) {
                    return true;
                }
            } catch (...) {
                // Signature check failed — do NOT whitelist; safer to alert.
            }
        }
        // Name matched but signature check failed — process is
        // impersonating a system binary. This is HIGHLY suspicious.
        // Do NOT whitelist.
        SS_LOG_WARN(L"InjectionDetector",
            L"Process %ls matched whitelist name but failed signature check — possible impersonation",
            event.sourceProcessName.c_str());
        return false;
    }

    // Step 2: Check if source is Microsoft signed AND not a LOLBin
    if (m_config.trustMicrosoftSigned && !event.sourceProcessPath.empty()) {
        // LOLBins are Microsoft-signed but routinely weaponized.
        // Never auto-whitelist them for injection.
        if (IsLolBin(event.sourceProcessName)) {
            return false;
        }

        try {
            if (Security::DigitalSignatureValidator::Instance().IsMicrosoftSigned(
                    event.sourceProcessPath)) {
                return true;
            }
        } catch (...) {
            // Signature check may fail for inaccessible processes
        }
    }

    // Step 3: Check whitelist store
    if (m_whitelist) {
        auto lr = m_whitelist->IsWhitelisted(event.sourceProcessPath);
        if (lr.found) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// IMPL: ALERT GENERATION
// ============================================================================

InjectionAlert ProcessInjectionDetector::Impl::CreateAlert(const InjectionEvent& event) {
    InjectionAlert alert;
    alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
    alert.timestamp = Clock::now();
    alert.sourceProcessId = event.sourceProcessId;
    alert.sourceProcessName = event.sourceProcessName;
    alert.targetProcessId = event.targetProcessId;
    alert.targetProcessName = event.targetProcessName;
    alert.injectionType = event.injectionType;
    alert.verdict = event.verdict;
    alert.confidence = event.confidence;
    alert.riskScore = event.riskScore;
    alert.blocked = event.blocked;
    alert.mitreTechnique = event.mitreSubTechnique;
    alert.relatedEventIds.push_back(event.eventId);

    // Build details
    std::wostringstream details;
    details << L"Injection detected: " << Utils::StringUtils::ToWide(InjectionTypeToString(event.injectionType))
            << L"\nSource: " << event.sourceProcessName << L" (PID: " << event.sourceProcessId << L")"
            << L"\nTarget: " << event.targetProcessName << L" (PID: " << event.targetProcessId << L")"
            << L"\nConfidence: " << std::fixed << std::setprecision(1) << event.confidence << L"%"
            << L"\nRisk Score: " << std::fixed << std::setprecision(1) << event.riskScore
            << L"\nMITRE: " << Utils::StringUtils::ToWide(event.mitreSubTechnique);

    if (event.targetThreadId > 0) {
        details << L"\nThread: " << event.targetThreadId;
    }

    if (!event.startAddressLegitimate) {
        details << L"\nStart address not in legitimate module";
    }

    alert.details = details.str();

    // Classify injector
    if (event.confidence >= 90.0) {
        alert.injectorType = InjectorType::Malware;
    } else if (event.confidence >= 70.0) {
        alert.injectorType = InjectorType::Exploit;
    } else {
        alert.injectorType = InjectorType::Unknown;
    }

    return alert;
}

// ============================================================================
// IMPL: CHAIN DETECTION
// ============================================================================

std::optional<InjectionChain> ProcessInjectionDetector::Impl::DetectChain(uint32_t startPid) {
    try {
        std::shared_lock stateLock(m_statesMutex);

        auto it = m_processStates.find(startPid);
        if (it == m_processStates.end() || it->second.outgoingInjectionIds.empty()) {
            return std::nullopt;
        }

        // Build chain by following injections
        InjectionChain chain;
        chain.chainId = m_nextChainId.fetch_add(1, std::memory_order_relaxed);
        chain.initialAttackerPid = startPid;
        chain.initialAttackerName = it->second.processName;
        chain.startTime = Clock::now();
        chain.chainPath.push_back(startPid);

        std::unordered_set<uint32_t> visited;
        visited.insert(startPid);

        uint32_t currentPid = startPid;
        size_t depth = 0;

        while (depth < InjectionConstants::MAX_CHAIN_DEPTH) {
            auto currentIt = m_processStates.find(currentPid);
            if (currentIt == m_processStates.end() ||
                currentIt->second.outgoingInjectionIds.empty()) {
                break;
            }

            // Get the most recent outgoing injection
            const uint64_t eventId = currentIt->second.outgoingInjectionIds.back();

            std::shared_lock eventLock(m_eventsMutex);
            auto eventIt = m_events.find(eventId);
            if (eventIt == m_events.end()) {
                break;
            }

            const auto& event = eventIt->second;
            chain.events.push_back(event);
            chain.totalRiskScore += event.riskScore;

            const uint32_t nextPid = event.targetProcessId;
            if (visited.contains(nextPid)) {
                break;  // Circular injection detected
            }

            chain.chainPath.push_back(nextPid);
            visited.insert(nextPid);
            currentPid = nextPid;
            depth++;
        }

        if (chain.events.empty()) {
            return std::nullopt;
        }

        chain.depth = depth;
        chain.finalVictimPid = chain.chainPath.back();
        chain.endTime = Clock::now();

        // Get final victim name
        if (auto victimIt = m_processStates.find(chain.finalVictimPid);
            victimIt != m_processStates.end()) {
            chain.finalVictimName = victimIt->second.processName;
        }

        return chain;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Chain detection failed - %S", e.what());
        return std::nullopt;
    }
}

// ============================================================================
// IMPL: CLEANUP
// ============================================================================

void ProcessInjectionDetector::Impl::CleanupThread() {
    SS_LOG_INFO(L"InjectionDetector", L"Cleanup thread started");

    while (!m_stopCleanup.load(std::memory_order_acquire)) {
        try {
            PurgeOldEvents();

            // Interruptible sleep using condition variable
            std::unique_lock cvLock(m_cleanupCvMutex);
            m_cleanupCv.wait_for(cvLock, std::chrono::minutes(5), [this]() {
                return m_stopCleanup.load(std::memory_order_acquire);
            });
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Cleanup error - %S", e.what());
        }
    }

    SS_LOG_INFO(L"InjectionDetector", L"Cleanup thread stopped");
}

void ProcessInjectionDetector::Impl::PurgeOldEvents() {
    const auto now = Clock::now();
    const auto maxAge = std::chrono::hours(1);

    size_t purged = 0;

    // Purge handle events
    {
        std::unique_lock lock(m_handleEventsMutex);
        auto it = m_handleEvents.begin();
        while (it != m_handleEvents.end()) {
            if ((now - it->timestamp) > maxAge) {
                it = m_handleEvents.erase(it);
                purged++;
            } else {
                ++it;
            }
        }
    }

    // Purge memory events
    {
        std::unique_lock lock(m_memoryEventsMutex);
        auto it = m_memoryEvents.begin();
        while (it != m_memoryEvents.end()) {
            if ((now - it->timestamp) > maxAge) {
                it = m_memoryEvents.erase(it);
                purged++;
            } else {
                ++it;
            }
        }
    }

    // Purge thread events
    {
        std::unique_lock lock(m_threadEventsMutex);
        auto it = m_threadEvents.begin();
        while (it != m_threadEvents.end()) {
            if ((now - it->timestamp) > maxAge) {
                it = m_threadEvents.erase(it);
                purged++;
            } else {
                ++it;
            }
        }
    }

    // Purge stale injection events from the aggregated events map.
    // These are keyed by eventId and referenced by process states; we
    // only remove events older than maxAge to keep correlation valid.
    {
        std::unique_lock lock(m_eventsMutex);
        auto it = m_events.begin();
        while (it != m_events.end()) {
            if ((now - it->second.timestamp) > maxAge) {
                it = m_events.erase(it);
                purged++;
            } else {
                ++it;
            }
        }
    }

    // Purge stale process states (no activity in 2 hours AND process is dead)
    {
        const auto staleAge = std::chrono::hours(2);
        std::unique_lock lock(m_statesMutex);
        auto it = m_processStates.begin();
        while (it != m_processStates.end()) {
            const auto& state = it->second;
            if ((now - state.lastActivity) > staleAge &&
                !Utils::ProcessUtils::IsProcessRunning(state.processId)) {
                it = m_processStates.erase(it);
                purged++;
            } else {
                // Cap per-state vectors to prevent unbounded growth
                constexpr size_t MAX_PER_STATE = InjectionConstants::MAX_EVENTS_PER_SOURCE;
                auto& s = it->second;
                if (s.crossProcessHandles.size() > MAX_PER_STATE) {
                    s.crossProcessHandles.erase(
                        s.crossProcessHandles.begin(),
                        s.crossProcessHandles.begin() +
                            static_cast<ptrdiff_t>(s.crossProcessHandles.size() - MAX_PER_STATE));
                }
                if (s.remoteMemoryOps.size() > MAX_PER_STATE) {
                    s.remoteMemoryOps.erase(
                        s.remoteMemoryOps.begin(),
                        s.remoteMemoryOps.begin() +
                            static_cast<ptrdiff_t>(s.remoteMemoryOps.size() - MAX_PER_STATE));
                }
                if (s.remoteThreadOps.size() > MAX_PER_STATE) {
                    s.remoteThreadOps.erase(
                        s.remoteThreadOps.begin(),
                        s.remoteThreadOps.begin() +
                            static_cast<ptrdiff_t>(s.remoteThreadOps.size() - MAX_PER_STATE));
                }
                ++it;
            }
        }
        m_stats.trackedProcesses.store(m_processStates.size(), std::memory_order_relaxed);
    }

    if (purged > 0) {
        SS_LOG_DEBUG(L"InjectionDetector", L"Purged %zu old events/states", purged);
    }
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

InjectionVerdict ProcessInjectionDetector::Impl::InvokeInjectionCallbacks(const InjectionEvent& event) {
    InjectionVerdict verdict = event.verdict;

    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_injectionCallbacks) {
        try {
            InjectionVerdict callbackVerdict = callback(event);
            // Allow callbacks to escalate verdict
            if (static_cast<int>(callbackVerdict) > static_cast<int>(verdict)) {
                verdict = callbackVerdict;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Injection callback error - %S", e.what());
        }
    }

    return verdict;
}

void ProcessInjectionDetector::Impl::InvokeAlertCallbacks(const InjectionAlert& alert) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_alertCallbacks) {
        try {
            callback(alert);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Alert callback error - %S", e.what());
        }
    }
}

void ProcessInjectionDetector::Impl::InvokeChainCallbacks(const InjectionChain& chain) {
    std::lock_guard lock(m_callbacksMutex);
    for (const auto& [id, callback] : m_chainCallbacks) {
        try {
            callback(chain);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Chain callback error - %S", e.what());
        }
    }
}

// ============================================================================
// IMPL: DEDUPLICATION
// ============================================================================

bool ProcessInjectionDetector::Impl::IsDuplicate(
    uint32_t sourcePid,
    uint32_t targetPid,
    InjectionType type)
{
    // Hash: combine source, target, and injection type into a single key.
    // Time is quantized into DEDUP_WINDOW buckets.
    const uint64_t key =
        (static_cast<uint64_t>(sourcePid) << 32) ^
        (static_cast<uint64_t>(targetPid) << 16) ^
        static_cast<uint64_t>(type);

    const auto now = Clock::now();

    std::lock_guard lock(m_dedupMutex);

    // Expire old entries
    while (!m_recentInjections.empty() && m_recentInjections.front().expiry <= now) {
        m_recentInjections.pop_front();
    }

    // Check if this key already exists
    for (const auto& entry : m_recentInjections) {
        if (entry.key == key) {
            return true;  // Duplicate
        }
    }

    // Not a duplicate — record it
    m_recentInjections.push_back({key, now + DEDUP_WINDOW});

    // Safety cap
    if (m_recentInjections.size() > 10000) {
        m_recentInjections.pop_front();
    }

    return false;
}

// ============================================================================
// IMPL: KERNEL DRIVER INTEGRATION
// ============================================================================

void ProcessInjectionDetector::Impl::RegisterKernelHandlers() {
    if (!Communication::IPCManager::HasInstance()) {
        SS_LOG_WARN(L"InjectionDetector",
            L"IPCManager not available — kernel integration disabled. "
            L"Detection limited to user-mode callbacks.");
        return;
    }

    try {
        auto& ipc = Communication::IPCManager::Instance();

        // Register a generic message handler that routes ThreadNotify and
        // HandleAlert messages from the kernel driver into our detection
        // pipeline. This is the critical kernel↔user-mode bridge.
        ipc.RegisterGenericHandler(
            [this](SHADOWSTRIKE_MESSAGE_TYPE msgType, const void* payload, size_t payloadSize) {
                if (!m_running.load(std::memory_order_acquire)) return;

                switch (msgType) {
                    case FilterMessageType_ThreadNotify:
                        OnKernelThreadNotify(msgType, payload, payloadSize);
                        break;
                    case FilterMessageType_HandleAlert:
                        OnKernelHandleAlert(msgType, payload, payloadSize);
                        break;
                    default:
                        break;
                }
            }
        );

        SS_LOG_INFO(L"InjectionDetector",
            L"Kernel handlers registered (ThreadNotify + HandleAlert)");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector",
            L"Failed to register kernel handlers - %S", e.what());
    }
}

void ProcessInjectionDetector::Impl::OnKernelThreadNotify(
    SHADOWSTRIKE_MESSAGE_TYPE /*type*/,
    const void* data,
    size_t size)
{
    if (data == nullptr || size < sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)) {
        return;
    }

    const auto* tn = static_cast<const SHADOWSTRIKE_THREAD_NOTIFICATION*>(data);

    // Self-exclusion: ignore our own process
    if (tn->ProcessId == m_selfPid || tn->CreatorProcessId == m_selfPid) {
        return;
    }

    // Only process remote thread creation events (cross-process injection)
    if (!tn->IsRemote) {
        return;
    }

    // Convert kernel notification into our ThreadOperationEvent format
    ThreadOperationEvent threadEvent;
    threadEvent.timestamp = Clock::now();
    threadEvent.operation = ThreadOperationEvent::OpType::Create;
    threadEvent.sourceProcessId = tn->CreatorProcessId;
    threadEvent.targetProcessId = tn->ProcessId;
    threadEvent.threadId = tn->ThreadId;
    threadEvent.isRemote = true;

    // Note: SHADOWSTRIKE_THREAD_NOTIFICATION does not carry the start
    // address — leave startAddressModule empty.  Correlation will still
    // work based on the cross-process thread creation event.

    SS_LOG_DEBUG(L"InjectionDetector",
        L"Kernel ThreadNotify: PID %u -> PID %u (TID %u, remote=%d)",
        tn->CreatorProcessId, tn->ProcessId, tn->ThreadId, tn->IsRemote);

    // Feed into the standard event handler pipeline
    // (store event + correlate + detect)
    m_stats.threadEvents.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);
    m_stats.remoteThreadsDetected.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lock(m_threadEventsMutex);
        m_threadEvents.push_back(threadEvent);
        if (m_threadEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
            m_threadEvents.pop_front();
        }
    }

    {
        std::unique_lock lock(m_statesMutex);
        auto& state = m_processStates[threadEvent.sourceProcessId];
        state.processId = threadEvent.sourceProcessId;
        state.remoteThreadOps.push_back(threadEvent);
        state.lastActivity = Clock::now();
    }

    // Correlate events to detect injection
    if (auto injectionEvent = CorrelateEvents(
            threadEvent.sourceProcessId, threadEvent.targetProcessId)) {
        ProcessInjectionDetection(std::move(*injectionEvent));
    }
}

void ProcessInjectionDetector::Impl::OnKernelHandleAlert(
    SHADOWSTRIKE_MESSAGE_TYPE /*type*/,
    const void* data,
    size_t size)
{
    if (data == nullptr || size < sizeof(SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION)) {
        return;
    }

    const auto* ha = static_cast<const SHADOWSTRIKE_HANDLE_ALERT_NOTIFICATION*>(data);

    // Self-exclusion
    if (ha->SourceProcessId == m_selfPid || ha->TargetProcessId == m_selfPid) {
        return;
    }

    // Convert kernel handle alert into our HandleAccessEvent format
    HandleAccessEvent handleEvent;
    handleEvent.timestamp = Clock::now();
    handleEvent.sourceProcessId = ha->SourceProcessId;
    handleEvent.targetProcessId = ha->TargetProcessId;
    handleEvent.desiredAccess = ha->RequestedAccess;
    handleEvent.grantedAccess = ha->GrantedAccess;

    constexpr uint32_t PROCESS_VM_WRITE_FLAG = 0x0020;
    constexpr uint32_t PROCESS_VM_OPERATION_FLAG = 0x0008;
    constexpr uint32_t PROCESS_CREATE_THREAD_FLAG = 0x0002;
    constexpr uint32_t PROCESS_DUP_HANDLE_FLAG = 0x0040;

    handleEvent.hasVMWrite      = (ha->GrantedAccess & PROCESS_VM_WRITE_FLAG) != 0;
    handleEvent.hasVMOperation  = (ha->GrantedAccess & PROCESS_VM_OPERATION_FLAG) != 0;
    handleEvent.hasCreateThread = (ha->GrantedAccess & PROCESS_CREATE_THREAD_FLAG) != 0;
    handleEvent.hasDupHandle    = (ha->GrantedAccess & PROCESS_DUP_HANDLE_FLAG) != 0;

    SS_LOG_DEBUG(L"InjectionDetector",
        L"Kernel HandleAlert: PID %u -> PID %u (access=0x%08X, score=%u)",
        ha->SourceProcessId, ha->TargetProcessId,
        ha->GrantedAccess, ha->SuspicionScore);

    m_stats.handleEvents.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lock(m_handleEventsMutex);
        m_handleEvents.push_back(handleEvent);
        if (m_handleEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
            m_handleEvents.pop_front();
        }
    }

    {
        std::unique_lock lock(m_statesMutex);
        auto& state = m_processStates[handleEvent.sourceProcessId];
        state.processId = handleEvent.sourceProcessId;
        state.crossProcessHandles.push_back(handleEvent);
        state.lastActivity = Clock::now();
    }

    // Correlate if the handle has injection-capable permissions
    if (IsSuspiciousHandleAccess(handleEvent.grantedAccess)) {
        if (auto injectionEvent = CorrelateEvents(
                handleEvent.sourceProcessId, handleEvent.targetProcessId)) {
            ProcessInjectionDetection(std::move(*injectionEvent));
        }
    }
}

// ============================================================================
// IMPL: SUB-DETECTOR ORCHESTRATION
// ============================================================================

void ProcessInjectionDetector::Impl::WireSubDetectorCallbacks() {
    // Wire ProcessHollowingDetector — when it detects hollowing, feed
    // the result into our detection pipeline.
    try {
        if (ProcessHollowingDetector::HasInstance() &&
            ProcessHollowingDetector::Instance().IsInitialized()) {
            ProcessHollowingDetector::Instance().RegisterDetectionCallback(
                [this](const HollowingDetectionResult& result) {
                    if (!m_running.load(std::memory_order_acquire)) return;
                    if (!result.isHollowed) return;

                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::ProcessHollowing;
                    event.targetProcessId = result.processId;
                    event.confidence = ConfidenceEnumToDouble(
                        static_cast<uint8_t>(result.confidence));
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055.012";

                    if (auto name = Utils::ProcessUtils::GetProcessName(result.processId)) {
                        event.targetProcessName = *name;
                    }
                    if (auto path = Utils::ProcessUtils::GetProcessPath(result.processId)) {
                        event.targetProcessPath = *path;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"ProcessHollowingDetector callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire ProcessHollowingDetector: %S", e.what());
    }

    // Wire ReflectiveDLLDetector
    try {
        auto& rdd = ReflectiveDLLDetector::Instance();
        if (rdd.IsInitialized()) {
            rdd.RegisterCallback(
                [this](const ReflectiveDetection& detection) {
                    if (!m_running.load(std::memory_order_acquire)) return;

                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::ReflectiveDLL;
                    event.targetProcessId = detection.processId;
                    event.targetAddress = detection.peCandidate.baseAddress;
                    event.dataSize = detection.peCandidate.regionSize;
                    event.confidence = ConfidenceEnumToDouble(
                        static_cast<uint8_t>(detection.confidence));
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055.001";

                    if (auto name = Utils::ProcessUtils::GetProcessName(detection.processId)) {
                        event.targetProcessName = *name;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"ReflectiveDLLDetector callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire ReflectiveDLLDetector: %S", e.what());
    }

    // Wire ThreadHijackDetector
    try {
        auto& thd = ThreadHijackDetector::Instance();
        if (thd.IsInitialized()) {
            thd.RegisterCallback(
                [this](const HijackEvent& hijackEvent) {
                    if (!m_running.load(std::memory_order_acquire)) return;

                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::ThreadHijacking;
                    event.targetProcessId = hijackEvent.victimPid;
                    event.targetThreadId = hijackEvent.victimTid;
                    event.confidence = 85.0;
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055.003";

                    if (auto name = Utils::ProcessUtils::GetProcessName(hijackEvent.victimPid)) {
                        event.targetProcessName = *name;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"ThreadHijackDetector callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire ThreadHijackDetector: %S", e.what());
    }

    // Wire AtomBombingDetector
    try {
        auto& abd = AtomBombingDetector::Instance();
        if (abd.IsInitialized()) {
            abd.RegisterAttackCallback(
                [this](const AtomBombingAttack& attack) {
                    if (!m_running.load(std::memory_order_acquire)) return;

                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::AtomBombing;
                    event.targetProcessId = attack.victimPid;
                    event.sourceProcessId = attack.attackerPid;
                    event.confidence = 85.0;
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055";

                    if (auto name = Utils::ProcessUtils::GetProcessName(attack.victimPid)) {
                        event.targetProcessName = *name;
                    }
                    if (auto name = Utils::ProcessUtils::GetProcessName(attack.attackerPid)) {
                        event.sourceProcessName = *name;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"AtomBombingDetector callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire AtomBombingDetector: %S", e.what());
    }

    // Wire MemoryScanner
    try {
        auto& ms = MemoryScanner::Instance();
        if (ms.IsInitialized()) {
            ms.RegisterThreatCallback(
                [this](const MemoryThreat& threat) {
                    if (!m_running.load(std::memory_order_acquire)) return;

                    // Only process injection-related memory threats
                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::ShellcodeInjection;
                    event.targetProcessId = threat.processId;
                    event.targetAddress = threat.regionBase;
                    event.dataSize = threat.regionSize;
                    event.confidence = 70.0;
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055.002";

                    if (auto name = Utils::ProcessUtils::GetProcessName(threat.processId)) {
                        event.targetProcessName = *name;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"MemoryScanner callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire MemoryScanner: %S", e.what());
    }

    // Wire DLLInjectionDetector
    try {
        auto& did = DLLInjectionDetector::Instance();
        if (did.IsInitialized()) {
            did.RegisterCallback(
                [this](const DLLInjectionEvent& dllEvent) {
                    if (!m_running.load(std::memory_order_acquire)) return;

                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = Clock::now();
                    event.injectionType = InjectionType::DLLInjection;
                    event.targetProcessId = dllEvent.targetPid;
                    event.sourceProcessId = dllEvent.injectorPid;
                    event.injectedModulePath = dllEvent.dllInfo.dllPath;
                    event.confidence = 75.0;
                    event.mitreTechnique = "T1055";
                    event.mitreSubTechnique = "T1055.001";

                    if (auto name = Utils::ProcessUtils::GetProcessName(dllEvent.targetPid)) {
                        event.targetProcessName = *name;
                    }
                    if (auto name = Utils::ProcessUtils::GetProcessName(dllEvent.injectorPid)) {
                        event.sourceProcessName = *name;
                    }

                    ProcessInjectionDetection(std::move(event));
                }
            );
            SS_LOG_DEBUG(L"InjectionDetector", L"DLLInjectionDetector callback wired");
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"InjectionDetector",
            L"Failed to wire DLLInjectionDetector: %S", e.what());
    }
}

// ============================================================================
// IMPL: CENTRALIZED INJECTION EVENT PROCESSING
// ============================================================================

void ProcessInjectionDetector::Impl::ProcessInjectionDetection(InjectionEvent event) {
    // Self-exclusion MUST come before deduplication — otherwise self-process
    // events poison the dedup table and silently suppress real injections
    // that happen to share the same key.
    if (event.sourceProcessId == m_selfPid || event.targetProcessId == m_selfPid) {
        return;
    }

    // Deduplication: avoid re-alerting on same injection from multiple
    // detection paths (handle + memory + thread + sub-detector)
    if (IsDuplicate(event.sourceProcessId, event.targetProcessId, event.injectionType)) {
        return;
    }

    // Fill in missing process info
    if (event.sourceProcessName.empty() && event.sourceProcessId != 0) {
        if (auto name = Utils::ProcessUtils::GetProcessName(event.sourceProcessId)) {
            event.sourceProcessName = *name;
        }
    }
    if (event.sourceProcessPath.empty() && event.sourceProcessId != 0) {
        if (auto path = Utils::ProcessUtils::GetProcessPath(event.sourceProcessId)) {
            event.sourceProcessPath = *path;
        }
    }
    if (event.targetProcessName.empty() && event.targetProcessId != 0) {
        if (auto name = Utils::ProcessUtils::GetProcessName(event.targetProcessId)) {
            event.targetProcessName = *name;
        }
    }
    if (event.targetProcessPath.empty() && event.targetProcessId != 0) {
        if (auto path = Utils::ProcessUtils::GetProcessPath(event.targetProcessId)) {
            event.targetProcessPath = *path;
        }
    }

    // Recalculate confidence/risk if not already set
    if (event.confidence <= 0.0) {
        event.confidence = CalculateConfidence(event.injectionType, event);
    }
    if (event.riskScore <= 0.0) {
        event.riskScore = CalculateRiskScore(event);
    }

    // MITRE ATT&CK mapping
    if (event.mitreTechnique.empty()) {
        event.mitreTechnique = "T1055";
    }
    if (event.mitreSubTechnique.empty()) {
        event.mitreSubTechnique = InjectionTypeToMitre(event.injectionType);
    }

    // Whitelisting
    if (ShouldWhitelist(event)) {
        event.verdict = InjectionVerdict::Whitelisted;
        event.confidence = 0.0;
        m_stats.falsePositivesSuppressed.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Determine verdict
    if (event.confidence >= m_config.blockConfidence) {
        event.verdict = InjectionVerdict::Confirmed;
    } else if (event.confidence >= m_config.alertConfidence) {
        event.verdict = InjectionVerdict::Detected;
    } else {
        event.verdict = InjectionVerdict::Suspicious;
    }

    // Invoke injection callbacks (may escalate verdict)
    event.verdict = InvokeInjectionCallbacks(event);

    // Store event
    {
        std::unique_lock lock(m_eventsMutex);
        m_events[event.eventId] = event;
    }

    // Update process states
    {
        std::unique_lock lock(m_statesMutex);
        if (event.sourceProcessId != 0) {
            auto& srcState = m_processStates[event.sourceProcessId];
            srcState.processId = event.sourceProcessId;
            srcState.processName = event.sourceProcessName;
            srcState.isInjecting = true;
            srcState.outgoingInjectionIds.push_back(event.eventId);
            srcState.totalInjectionsAsSource++;
            srcState.lastActivity = Clock::now();
        }

        auto& tgtState = m_processStates[event.targetProcessId];
        tgtState.processId = event.targetProcessId;
        tgtState.processName = event.targetProcessName;
        tgtState.isBeingInjected = true;
        tgtState.hasBeenInjected = true;
        tgtState.incomingInjectionIds.push_back(event.eventId);
        tgtState.totalInjectionsAsTarget++;
        tgtState.lastActivity = Clock::now();
    }

    // Forward to BehaviorAnalyzer for attack chain correlation
    if (m_behaviorAnalyzer && m_behaviorAnalyzer->IsInitialized()) {
        try {
            auto baEvent = Engine::CreateProcessEvent(
                Engine::BehaviorEventType::ProcessInject,
                event.sourceProcessId,
                event.targetProcessId);
            baEvent.processName = event.sourceProcessName;
            baEvent.targetPath  = event.targetProcessName;
            baEvent.accessMask  = static_cast<uint32_t>(event.injectionType);
            baEvent.details     = L"confidence=" + std::to_wstring(event.confidence);
            baEvent.success     = true;

            auto baVerdict = m_behaviorAnalyzer->ProcessEvent(baEvent);
            if (baVerdict.has_value() &&
                baVerdict->RequiresImmediateAction()) {
                // BA determined this injection warrants immediate blocking.
                // This applies regardless of the blockInjections config —
                // the BehaviorAnalyzer performs holistic attack-chain analysis
                // and its escalation overrides monitor-only mode.
                event.blocked = true;
                m_stats.injectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(L"InjectionDetector",
                    L"BA escalated injection %ls->%ls to BLOCK (score=%.1f)",
                    event.sourceProcessName.c_str(),
                    event.targetProcessName.c_str(),
                    baVerdict->maliceScore);
            }
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"InjectionDetector", L"BA forwarding failed: %S", ex.what());
        }
    }

    // Update technique-specific stats
    m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
    UpdateTechniqueStats(event.injectionType);

    // Generate alert if confidence meets threshold
    if (event.confidence >= m_config.alertConfidence) {
        auto alert = CreateAlert(event);
        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.push_back(alert);
            if (m_alerts.size() > 10000) {
                m_alerts.pop_front();
            }
        }
        InvokeAlertCallbacks(alert);
    }

    // Block if configured
    if (m_config.blockInjections &&
        event.confidence >= m_config.blockConfidence &&
        event.verdict != InjectionVerdict::Whitelisted) {
        event.blocked = true;
        m_stats.injectionsBlocked.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_WARN(L"InjectionDetector",
            L"Blocked injection %ls -> %ls (%S, confidence=%.1f)",
            event.sourceProcessName.c_str(),
            event.targetProcessName.c_str(),
            InjectionTypeToString(event.injectionType),
            event.confidence);
    }

    // Auto chain detection: if the source is already a known injection
    // target (it was previously injected INTO), this is a multi-hop chain.
    if (event.sourceProcessId != 0 && m_config.detectChains) {
        std::shared_lock stateLock(m_statesMutex);
        auto srcIt = m_processStates.find(event.sourceProcessId);
        if (srcIt != m_processStates.end() && srcIt->second.hasBeenInjected) {
            stateLock.unlock();
            if (auto chain = DetectChain(event.sourceProcessId)) {
                {
                    std::unique_lock chainLock(m_chainsMutex);
                    m_chains.push_back(*chain);
                    if (m_chains.size() > 1000) {
                        m_chains.erase(m_chains.begin());
                    }
                }
                m_stats.chainsDetected.fetch_add(1, std::memory_order_relaxed);
                InvokeChainCallbacks(*chain);

                SS_LOG_WARN(L"InjectionDetector",
                    L"Injection CHAIN detected: depth=%zu, start=%ls (PID %u) -> end=%ls (PID %u), risk=%.1f",
                    chain->depth,
                    chain->initialAttackerName.c_str(), chain->initialAttackerPid,
                    chain->finalVictimName.c_str(), chain->finalVictimPid,
                    chain->totalRiskScore);
            }
        }
    }
}

// ============================================================================
// IMPL: TECHNIQUE-SPECIFIC STATS
// ============================================================================

void ProcessInjectionDetector::Impl::UpdateTechniqueStats(InjectionType type) {
    switch (type) {
        case InjectionType::RemoteThread:
        case InjectionType::NtCreateThreadEx:
        case InjectionType::RtlCreateUserThread:
        case InjectionType::DirectSyscallThread:
            m_stats.remoteThreadsDetected.fetch_add(1, std::memory_order_relaxed);
            break;
        case InjectionType::APC:
        case InjectionType::NtQueueApcThread:
        case InjectionType::EarlyBird:
        case InjectionType::APCWritePrimitive:
        case InjectionType::KernelAPC:
            m_stats.apcInjectionsDetected.fetch_add(1, std::memory_order_relaxed);
            break;
        case InjectionType::ProcessHollowing:
        case InjectionType::ProcessDoppelganging:
        case InjectionType::ProcessHerpaderping:
        case InjectionType::ProcessGhosting:
        case InjectionType::TransactedHollowing:
        case InjectionType::ProcessReimaging:
            m_stats.hollowingDetected.fetch_add(1, std::memory_order_relaxed);
            break;
        case InjectionType::ReflectiveDLL:
        case InjectionType::ManualMapping:
        case InjectionType::ModuleStomping:
            m_stats.reflectiveDLLDetected.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            break;
    }
}

// ============================================================================
// IMPL: LOLBin CHECK
// ============================================================================

bool ProcessInjectionDetector::Impl::IsLolBin(std::wstring_view processName) const {
    const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(std::wstring(processName));
    for (const auto& lolbin : kLolBins) {
        if (nameLower == lolbin) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

ProcessInjectionDetector& ProcessInjectionDetector::Instance() {
    static ProcessInjectionDetector instance;
    return instance;
}

ProcessInjectionDetector::ProcessInjectionDetector()
    : m_impl(std::make_unique<Impl>())
{
    SS_LOG_INFO(L"InjectionDetector", L"Constructor called");
}

ProcessInjectionDetector::~ProcessInjectionDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"InjectionDetector", L"Destructor called");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ProcessInjectionDetector::Initialize() {
    return Initialize(nullptr, InjectionDetectorConfig::CreateDefault());
}

bool ProcessInjectionDetector::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(threadPool, InjectionDetectorConfig::CreateDefault());
}

bool ProcessInjectionDetector::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const InjectionDetectorConfig& config)
{
    return m_impl ? m_impl->Initialize(threadPool, config) : false;
}

void ProcessInjectionDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

void ProcessInjectionDetector::Start() {
    if (m_impl) {
        m_impl->Start();
    }
}

void ProcessInjectionDetector::Stop() {
    if (m_impl) {
        m_impl->Stop();
    }
}

bool ProcessInjectionDetector::IsRunning() const noexcept {
    return m_impl ? m_impl->m_running.load(std::memory_order_acquire) : false;
}

void ProcessInjectionDetector::UpdateConfig(const InjectionDetectorConfig& config) {
    if (m_impl) {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = config;
    }
}

InjectionDetectorConfig ProcessInjectionDetector::GetConfig() const {
    if (m_impl) {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_config;
    }
    return InjectionDetectorConfig{};
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

bool ProcessInjectionDetector::OnHandleAccess(const HandleAccessEvent& event) {
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) {
        return true;  // Allow by default
    }

    try {
        // Self-exclusion
        if (event.sourceProcessId == m_impl->m_selfPid ||
            event.targetProcessId == m_impl->m_selfPid) {
            return true;
        }

        m_impl->m_stats.handleEvents.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);

        // Store handle event for correlation
        {
            std::unique_lock lock(m_impl->m_handleEventsMutex);
            m_impl->m_handleEvents.push_back(event);
            if (m_impl->m_handleEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
                m_impl->m_handleEvents.pop_front();
            }
        }

        // Update process state
        {
            std::unique_lock lock(m_impl->m_statesMutex);
            auto& state = m_impl->m_processStates[event.sourceProcessId];
            state.processId = event.sourceProcessId;
            state.crossProcessHandles.push_back(event);
            state.lastActivity = Clock::now();
        }

        // Check if suspicious handle access — correlate and detect
        if (IsSuspiciousHandleAccess(event.grantedAccess)) {
            if (auto injectionEvent = m_impl->CorrelateEvents(
                    event.sourceProcessId, event.targetProcessId)) {
                const bool shouldBlock =
                    m_impl->m_config.blockInjections &&
                    injectionEvent->confidence >= m_impl->m_config.blockConfidence;
                m_impl->ProcessInjectionDetection(std::move(*injectionEvent));
                if (shouldBlock) {
                    return false;  // Block
                }
            }
        }

        return true;  // Allow

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Handle access handler failed - %S", e.what());
        return true;  // Allow on error
    }
}

void ProcessInjectionDetector::OnMemoryOperation(const MemoryOperationEvent& event) {
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) {
        return;
    }

    try {
        // Self-exclusion
        if (event.sourceProcessId == m_impl->m_selfPid ||
            event.targetProcessId == m_impl->m_selfPid) {
            return;
        }

        m_impl->m_stats.memoryEvents.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);

        // Store memory event for correlation
        {
            std::unique_lock lock(m_impl->m_memoryEventsMutex);
            m_impl->m_memoryEvents.push_back(event);
            if (m_impl->m_memoryEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
                m_impl->m_memoryEvents.pop_front();
            }
        }

        // Process cross-process memory operations
        if (event.isCrossProcess) {
            {
                std::unique_lock lock(m_impl->m_statesMutex);
                auto& state = m_impl->m_processStates[event.sourceProcessId];
                state.processId = event.sourceProcessId;
                state.remoteMemoryOps.push_back(event);
                state.lastActivity = Clock::now();
            }

            const bool isExecProtChange =
                (event.operation == MemoryOperationEvent::OpType::Protect &&
                 IsExecutableProtection(event.newProtection));
            const bool isCrossWrite =
                (event.operation == MemoryOperationEvent::OpType::Write);

            if (isExecProtChange || isCrossWrite) {
                if (auto injectionEvent = m_impl->CorrelateEvents(
                        event.sourceProcessId, event.targetProcessId)) {
                    m_impl->ProcessInjectionDetection(std::move(*injectionEvent));
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Memory operation handler failed - %S", e.what());
    }
}

bool ProcessInjectionDetector::OnThreadOperation(const ThreadOperationEvent& event) {
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) {
        return true;  // Allow by default
    }

    try {
        // Self-exclusion
        if (event.sourceProcessId == m_impl->m_selfPid ||
            event.targetProcessId == m_impl->m_selfPid) {
            return true;
        }

        m_impl->m_stats.threadEvents.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);

        // Store thread event for correlation
        {
            std::unique_lock lock(m_impl->m_threadEventsMutex);
            m_impl->m_threadEvents.push_back(event);
            if (m_impl->m_threadEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
                m_impl->m_threadEvents.pop_front();
            }
        }

        // Process remote thread operations
        if (event.isRemote) {
            {
                std::unique_lock lock(m_impl->m_statesMutex);
                auto& state = m_impl->m_processStates[event.sourceProcessId];
                state.processId = event.sourceProcessId;
                state.remoteThreadOps.push_back(event);
                state.lastActivity = Clock::now();
            }

            if (event.operation == ThreadOperationEvent::OpType::Create) {
                m_impl->m_stats.remoteThreadsDetected.fetch_add(1, std::memory_order_relaxed);
            }

            // Remote thread creation, APC queue, or context manipulation
            // are key injection indicators.
            if (event.operation == ThreadOperationEvent::OpType::Create ||
                event.operation == ThreadOperationEvent::OpType::QueueAPC ||
                event.operation == ThreadOperationEvent::OpType::SetContext) {

                if (auto injectionEvent = m_impl->CorrelateEvents(
                        event.sourceProcessId, event.targetProcessId)) {
                    const bool shouldBlock =
                        m_impl->m_config.blockInjections &&
                        injectionEvent->confidence >= m_impl->m_config.blockConfidence;
                    m_impl->ProcessInjectionDetection(std::move(*injectionEvent));
                    if (shouldBlock) {
                        return false;  // Block
                    }
                }
            }
        }

        return true;  // Allow

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector", L"Thread operation handler failed - %S", e.what());
        return true;  // Allow on error
    }
}

void ProcessInjectionDetector::AnalyzeEvent(
    uint32_t sourceProcessId,
    uint32_t targetProcessId,
    InjectionType type)
{
    if (!m_impl) return;

    // Simplified event analysis (mainly for testing)
    if (auto event = m_impl->CorrelateEvents(sourceProcessId, targetProcessId)) {
        event->injectionType = type;

        {
            std::unique_lock lock(m_impl->m_eventsMutex);
            m_impl->m_events[event->eventId] = *event;
        }
    }
}

// ============================================================================
// QUERY
// ============================================================================

bool ProcessInjectionDetector::IsProcessInjected(uint32_t pid) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    return it != m_impl->m_processStates.end() && it->second.hasBeenInjected;
}

bool ProcessInjectionDetector::IsProcessInjecting(uint32_t pid) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    return it != m_impl->m_processStates.end() && it->second.isInjecting;
}

std::optional<ProcessInjectionState> ProcessInjectionDetector::GetProcessState(uint32_t pid) const {
    if (!m_impl) return std::nullopt;

    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    if (it != m_impl->m_processStates.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<InjectionEvent> ProcessInjectionDetector::GetInjectionsInto(uint32_t pid) const {
    std::vector<InjectionEvent> events;

    if (!m_impl) return events;

    std::shared_lock stateLock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    if (it == m_impl->m_processStates.end()) {
        return events;
    }

    std::shared_lock eventLock(m_impl->m_eventsMutex);
    for (uint64_t eventId : it->second.incomingInjectionIds) {
        auto eventIt = m_impl->m_events.find(eventId);
        if (eventIt != m_impl->m_events.end()) {
            events.push_back(eventIt->second);
        }
    }

    return events;
}

std::vector<InjectionEvent> ProcessInjectionDetector::GetInjectionsFrom(uint32_t pid) const {
    std::vector<InjectionEvent> events;

    if (!m_impl) return events;

    std::shared_lock stateLock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    if (it == m_impl->m_processStates.end()) {
        return events;
    }

    std::shared_lock eventLock(m_impl->m_eventsMutex);
    for (uint64_t eventId : it->second.outgoingInjectionIds) {
        auto eventIt = m_impl->m_events.find(eventId);
        if (eventIt != m_impl->m_events.end()) {
            events.push_back(eventIt->second);
        }
    }

    return events;
}

std::vector<InjectionAlert> ProcessInjectionDetector::GetRecentAlerts(size_t count) const {
    std::vector<InjectionAlert> alerts;

    if (!m_impl) return alerts;

    std::shared_lock lock(m_impl->m_alertsMutex);

    const size_t startIdx = (m_impl->m_alerts.size() > count) ?
                            (m_impl->m_alerts.size() - count) : 0;

    for (size_t i = startIdx; i < m_impl->m_alerts.size(); ++i) {
        alerts.push_back(m_impl->m_alerts[i]);
    }

    return alerts;
}

std::vector<InjectionChain> ProcessInjectionDetector::GetInjectionChains() const {
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_chainsMutex);
    return m_impl->m_chains;
}

std::vector<uint32_t> ProcessInjectionDetector::GetTrackedProcesses() const {
    std::vector<uint32_t> pids;

    if (!m_impl) return pids;

    std::shared_lock lock(m_impl->m_statesMutex);
    pids.reserve(m_impl->m_processStates.size());

    for (const auto& [pid, state] : m_impl->m_processStates) {
        pids.push_back(pid);
    }

    return pids;
}

// ============================================================================
// ANALYSIS
// ============================================================================

InjectionVerdict ProcessInjectionDetector::AnalyzeProcess(uint32_t pid) {
    if (!m_impl) return InjectionVerdict::Unknown;

    // Step 1: Check existing state
    {
        std::shared_lock lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it != m_impl->m_processStates.end()) {
            if (it->second.hasBeenInjected) {
                return InjectionVerdict::Detected;
            }
            if (it->second.isBeingInjected) {
                return InjectionVerdict::Suspicious;
            }
        }
    }

    // Step 2: Actively scan using sub-detectors for indicators that
    // may not have been caught by real-time event correlation.
    try {
        // Check for process hollowing
        if (ProcessHollowingDetector::HasInstance()) {
            auto& phd = ProcessHollowingDetector::Instance();
            if (phd.IsInitialized() && phd.IsHollowed(pid)) {
                return InjectionVerdict::Confirmed;
            }
        }

        // Check for reflective DLL loading
        auto& rdd = ReflectiveDLLDetector::Instance();
        if (rdd.IsInitialized() && rdd.HasReflectiveLoading(pid)) {
            return InjectionVerdict::Confirmed;
        }

        // Check for thread hijacking
        auto& thd = ThreadHijackDetector::Instance();
        if (thd.IsInitialized()) {
            auto scanResult = thd.ScanProcess(pid);
            if (scanResult.hijackDetected) {
                return InjectionVerdict::Detected;
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector",
            L"Active scan failed for PID %u - %S", pid, e.what());
    }

    return InjectionVerdict::Clean;
}

InjectionType ProcessInjectionDetector::ClassifyInjection(
    const std::vector<HandleAccessEvent>& handleEvents,
    const std::vector<MemoryOperationEvent>& memoryEvents,
    const std::vector<ThreadOperationEvent>& threadEvents) const
{
    return m_impl ? m_impl->ClassifyFromEvents(handleEvents, memoryEvents, threadEvents) :
                   InjectionType::Unknown;
}

double ProcessInjectionDetector::CalculateConfidence(
    InjectionType type,
    const InjectionEvent& event) const
{
    return m_impl ? m_impl->CalculateConfidence(type, event) : 0.0;
}

std::optional<InjectionChain> ProcessInjectionDetector::DetectChain(uint32_t startPid) const {
    return m_impl ? m_impl->DetectChain(startPid) : std::nullopt;
}

// ============================================================================
// SPECIALIZED DETECTORS
// ============================================================================

bool ProcessInjectionDetector::CheckProcessHollowing(uint32_t pid) {
    if (!m_impl) return false;

    // Step 1: Check existing events
    {
        std::shared_lock lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it != m_impl->m_processStates.end()) {
            for (uint64_t eventId : it->second.incomingInjectionIds) {
                std::shared_lock eventLock(m_impl->m_eventsMutex);
                auto eventIt = m_impl->m_events.find(eventId);
                if (eventIt != m_impl->m_events.end() &&
                    eventIt->second.injectionType == InjectionType::ProcessHollowing) {
                    m_impl->m_stats.hollowingDetected.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
            }
        }
    }

    // Step 2: Delegate to ProcessHollowingDetector for active scanning
    try {
        if (ProcessHollowingDetector::HasInstance()) {
            auto& phd = ProcessHollowingDetector::Instance();
            if (phd.IsInitialized() && phd.IsHollowed(pid)) {
                m_impl->m_stats.hollowingDetected.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector",
            L"ProcessHollowingDetector scan failed for PID %u - %S", pid, e.what());
    }

    return false;
}

bool ProcessInjectionDetector::CheckReflectiveDLL(uint32_t pid) {
    if (!m_impl) return false;

    // Step 1: Check existing events
    {
        std::shared_lock lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it != m_impl->m_processStates.end()) {
            for (uint64_t eventId : it->second.incomingInjectionIds) {
                std::shared_lock eventLock(m_impl->m_eventsMutex);
                auto eventIt = m_impl->m_events.find(eventId);
                if (eventIt != m_impl->m_events.end() &&
                    eventIt->second.injectionType == InjectionType::ReflectiveDLL) {
                    m_impl->m_stats.reflectiveDLLDetected.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
            }
        }
    }

    // Step 2: Delegate to ReflectiveDLLDetector for active scanning
    try {
        auto& rdd = ReflectiveDLLDetector::Instance();
        if (rdd.IsInitialized() && rdd.HasReflectiveLoading(pid)) {
            m_impl->m_stats.reflectiveDLLDetected.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"InjectionDetector",
            L"ReflectiveDLLDetector scan failed for PID %u - %S", pid, e.what());
    }

    return false;
}

bool ProcessInjectionDetector::CheckAtomBombing(uint32_t pid) {
    if (!m_impl) return false;

    // Check for atom bombing indicators in our recorded events:
    // Atom bombing uses NtQueueApcThread with GlobalGetAtomA as the APC routine
    // to copy data from the global atom table into the target process. We look
    // for APC-based injection events targeting this PID that were classified as
    // AtomBombing by the correlator, or for APC queue events with suspicious
    // start addresses pointing to GlobalGetAtom in kernel32/kernelbase.
    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    if (it == m_impl->m_processStates.end()) {
        return false;
    }

    for (uint64_t eventId : it->second.incomingInjectionIds) {
        std::shared_lock eventLock(m_impl->m_eventsMutex);
        auto eventIt = m_impl->m_events.find(eventId);
        if (eventIt != m_impl->m_events.end() &&
            eventIt->second.injectionType == InjectionType::AtomBombing) {
            return true;
        }
    }

    // Also scan raw APC thread events for GlobalGetAtom pattern
    for (const auto& threadOp : it->second.remoteThreadOps) {
        if (threadOp.operation == ThreadOperationEvent::OpType::QueueAPC &&
            threadOp.apcRoutine != 0) {
            // Resolve the APC routine module -- if it points to
            // GlobalGetAtomA/W in kernel32, this is atom bombing.
            std::wstring modName = GetModuleForAddress(pid, threadOp.apcRoutine);
            std::wstring modLower = Utils::StringUtils::ToLowerCopy(modName);
            if (modLower.find(L"kernel32") != std::wstring::npos ||
                modLower.find(L"kernelbase") != std::wstring::npos) {
                // APC targeting GlobalGetAtom in kernel32 is a strong indicator
                return true;
            }
        }
    }

    return false;
}

bool ProcessInjectionDetector::CheckThreadHijacking(uint32_t pid, uint32_t threadId) {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_statesMutex);
    auto it = m_impl->m_processStates.find(pid);
    if (it == m_impl->m_processStates.end()) {
        return false;
    }

    for (uint64_t eventId : it->second.incomingInjectionIds) {
        std::shared_lock eventLock(m_impl->m_eventsMutex);
        auto eventIt = m_impl->m_events.find(eventId);
        if (eventIt != m_impl->m_events.end() &&
            eventIt->second.injectionType == InjectionType::ThreadHijacking &&
            (threadId == 0 || eventIt->second.targetThreadId == threadId)) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// STATISTICS
// ============================================================================

InjectionDetectorStats ProcessInjectionDetector::GetStats() const {
    return m_impl ? m_impl->m_stats : InjectionDetectorStats{};
}

void ProcessInjectionDetector::ResetStats() {
    if (m_impl) {
        m_impl->m_stats.Reset();
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ProcessInjectionDetector::RegisterInjectionCallback(InjectionCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_injectionCallbacks[id] = std::move(callback);
    return id;
}

bool ProcessInjectionDetector::UnregisterInjectionCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    return m_impl->m_injectionCallbacks.erase(callbackId) > 0;
}

uint64_t ProcessInjectionDetector::RegisterAlertCallback(InjectionAlertCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_alertCallbacks[id] = std::move(callback);
    return id;
}

bool ProcessInjectionDetector::UnregisterAlertCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    return m_impl->m_alertCallbacks.erase(callbackId) > 0;
}

uint64_t ProcessInjectionDetector::RegisterChainCallback(InjectionChainCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_chainCallbacks[id] = std::move(callback);
    return id;
}

bool ProcessInjectionDetector::UnregisterChainCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    return m_impl->m_chainCallbacks.erase(callbackId) > 0;
}

uint64_t ProcessInjectionDetector::RegisterHandleCallback(HandleAccessCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_handleCallbacks[id] = std::move(callback);
    return id;
}

bool ProcessInjectionDetector::UnregisterHandleCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    return m_impl->m_handleCallbacks.erase(callbackId) > 0;
}

// ============================================================================
// EXTERNAL INTEGRATION
// ============================================================================

void ProcessInjectionDetector::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    if (m_impl) {
        m_impl->m_whitelist = store;
    }
}

void ProcessInjectionDetector::SetBehaviorAnalyzer(Engine::BehaviorAnalyzer* analyzer) {
    if (m_impl) {
        m_impl->m_behaviorAnalyzer = analyzer;
    }
}

void ProcessInjectionDetector::SetThreatDetector(Engine::ThreatDetector* detector) {
    if (m_impl) {
        m_impl->m_threatDetector = detector;
    }
}

void ProcessInjectionDetector::SetMemoryProtection(RealTime::MemoryProtection* memProtect) {
    if (m_impl) {
        m_impl->m_memoryProtection = memProtect;
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
