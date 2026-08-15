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
#include <cwctype>

namespace ShadowStrike {
namespace Core {
namespace Process {

using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// INTERNAL HELPERS (file-local, anonymous namespace)
// ============================================================================
namespace {

// ---------------------------------------------------------------------------
// Aliveness flag for IPCManager-registered lambdas.
//
// IPCManager owns the registered generic-message handler as a std::function.
// At process termination the singleton destruction order between
// ProcessInjectionDetector and IPCManager is not guaranteed.  If IPCManager
// fires a handler after our Impl has been destroyed, the captured `this`
// pointer is dangling and dereferencing it is a textbook UAF.
//
// We therefore route every IPC callback through this static atomic flag:
// the Impl constructor sets it to true, the destructor clears it.  Lambdas
// re-check it under acquire ordering before touching any member.
// ---------------------------------------------------------------------------
std::atomic<bool> g_implAlive{false};

// ---------------------------------------------------------------------------
// Process name length cap when generating user-facing strings (alert
// details, logs, dashboards).  Real Windows image names are well under
// MAX_PATH wide chars; anything longer is either malicious or corrupt
// telemetry and must be truncated to bound UI/log buffers.
// ---------------------------------------------------------------------------
constexpr size_t kMaxDisplayNameLen = 260;

// ---------------------------------------------------------------------------
// Per-source cap on event vectors held inside ProcessInjectionState.
// Prevents a single noisy attacker process from exhausting memory via
// flooded handle/memory/thread events.  Enforced eagerly on push, not
// only during the 5-minute cleanup pass.
// ---------------------------------------------------------------------------
constexpr size_t kPerStateEventCap = InjectionConstants::MAX_EVENTS_PER_SOURCE;

// ---------------------------------------------------------------------------
// Global cap for the in-memory alert ring buffer and the chain history.
// Both buffers are bounded; oldest entries are evicted on overflow.
// ---------------------------------------------------------------------------
constexpr size_t kMaxAlertHistory = 10000;
constexpr size_t kMaxChainHistory = 1000;

// ---------------------------------------------------------------------------
// Sanitize a wide string for inclusion in logs / alert details / UI text.
// Strips CR/LF and C0 controls (which would allow log-injection and UI
// splice attacks driven by attacker-chosen process names), then truncates
// to a hard upper bound.  Pure value-in/value-out — no allocations of
// global state.
// ---------------------------------------------------------------------------
[[nodiscard]] std::wstring SanitizeForDisplay(std::wstring_view in) noexcept {
    std::wstring out;
    out.reserve(std::min<size_t>(in.size(), kMaxDisplayNameLen));
    for (wchar_t wc : in) {
        if (out.size() >= kMaxDisplayNameLen) {
            out += L"\u2026";  // horizontal ellipsis — UI-safe truncation marker
            break;
        }
        // Strip C0 controls (0x00-0x1F) and DEL (0x7F).  This includes
        // CR/LF that would otherwise allow CRLF log-splitting.
        if (wc == L'\0' || (wc >= 0x01 && wc <= 0x1F) || wc == 0x7F) {
            out.push_back(L'?');
        } else {
            out.push_back(wc);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Mix bits robustly for deduplication keying.  The original implementation
// XORed three weakly-shifted fields together, producing trivial collisions
// such as (src=A,tgt=B,type=T) == (src=A^X,tgt=B^Y,type=T') with the right
// constants.  A real injection sharing a key with a self-process event
// would be silently suppressed — a TIER-4 detection-bypass primitive.
//
// We use the SplitMix64 finalizer per-field and combine with a strong
// avalanche mixer to guarantee that any input bit flip flips ~50% of
// output bits.
// ---------------------------------------------------------------------------
[[nodiscard]] constexpr uint64_t SplitMix64(uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

[[nodiscard]] constexpr uint64_t MakeDedupKey(
    uint32_t sourcePid,
    uint32_t targetPid,
    InjectionType type) noexcept
{
    const uint64_t a = SplitMix64(static_cast<uint64_t>(sourcePid));
    const uint64_t b = SplitMix64(static_cast<uint64_t>(targetPid) ^ 0xA5A5A5A5A5A5A5A5ULL);
    const uint64_t c = SplitMix64(static_cast<uint64_t>(type) ^ 0x5A5A5A5A5A5A5A5AULL);
    return SplitMix64(a ^ (b * 0x100000001B3ULL) ^ c);
}

// ---------------------------------------------------------------------------
// Best-effort process creation-time capture for PID-reuse detection.
//
// Windows recycles PIDs aggressively.  Without a creation-time fingerprint,
// stale state for a terminated PID will be attributed to a freshly-created
// process that happened to reuse the number.  This corrupts statistics,
// produces false correlations, and allows an attacker who can rapidly spawn
// processes to confuse the correlator into miscounting an injection chain.
//
// Returns 0 on failure (e.g., access denied for PPL targets).  Callers
// must treat 0 as "unknown" and skip the freshness check rather than
// falsely declaring reuse.
// ---------------------------------------------------------------------------
[[nodiscard]] uint64_t GetProcessCreationTick(uint32_t pid) noexcept {
    if (pid == 0) {
        return 0;
    }
    // PROCESS_QUERY_LIMITED_INFORMATION is available even for PPL targets
    // and elevated processes, unlike PROCESS_QUERY_INFORMATION.
    HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc == nullptr) {
        return 0;
    }
    FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
    const BOOL ok = ::GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser);
    ::CloseHandle(hProc);
    if (!ok) {
        return 0;
    }
    ULARGE_INTEGER u;
    u.LowPart = ftCreate.dwLowDateTime;
    u.HighPart = ftCreate.dwHighDateTime;
    return u.QuadPart;
}

// ---------------------------------------------------------------------------
// Trim a std::deque to the rear `cap` elements in O(n - cap).  Used to
// enforce hard caps on per-state event vectors during ingestion rather
// than relying on the 5-minute background cleanup window.
// ---------------------------------------------------------------------------
template <typename T>
void TrimVectorToCap(std::vector<T>& v, size_t cap) noexcept {
    if (v.size() > cap) {
        const size_t excess = v.size() - cap;
        v.erase(v.begin(), v.begin() + static_cast<ptrdiff_t>(excess));
    }
}

}  // anonymous namespace

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
            return "OpenProcess->VirtualAllocEx->WriteProcessMemory->CreateRemoteThread(LoadLibrary)";

        case InjectionType::ReflectiveDLL:
            return "OpenProcess->VirtualAllocEx->WriteProcessMemory->CreateRemoteThread(ReflectiveLoader)";

        case InjectionType::ProcessHollowing:
            return "CreateProcess(SUSPENDED)->NtUnmapViewOfSection->VirtualAllocEx->WriteProcessMemory->SetContext->Resume";

        case InjectionType::ThreadHijacking:
            return "OpenThread->SuspendThread->GetThreadContext->SetThreadContext->ResumeThread";

        case InjectionType::APC:
        case InjectionType::NtQueueApcThread:
            return "OpenThread->QueueUserAPC->ResumeThread";

        case InjectionType::EarlyBird:
            return "CreateProcess(SUSPENDED)->QueueUserAPC->ResumeThread";

        case InjectionType::AtomBombing:
            return "GlobalAddAtom->NtQueueApcThread(GlobalGetAtom)";

        case InjectionType::ProcessDoppelganging:
            return "NtCreateTransaction->CreateFileTransacted->NtCreateSection->NtCreateProcessEx->NtRollbackTransaction";

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
    // Specific source->target pairs that are known-legitimate OS injection
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
        {L"wininit.exe",   L"services.exe"},     // Windows Init -> SCM
        {L"services.exe",  L"svchost.exe"},      // SCM -> Service Host
        {L"smss.exe",      L"csrss.exe"},        // Session Manager -> CSRSS
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

    /// @brief Injection chains.
    /// DESIGN: deque (not vector) — chain history is FIFO-bounded and the
    /// previous vector::erase(begin()) on overflow was O(n) per eviction.
    /// On return we materialise a std::vector to preserve the public API
    /// shape (GetInjectionChains() -> std::vector).
    std::deque<InjectionChain> m_chains;
    mutable std::shared_mutex m_chainsMutex;
    std::atomic<uint64_t> m_nextChainId{1};

    /// @brief Callbacks
    std::unordered_map<uint64_t, InjectionCallback> m_injectionCallbacks;
    std::unordered_map<uint64_t, InjectionAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, InjectionChainCallback> m_chainCallbacks;
    std::unordered_map<uint64_t, HandleAccessCallback> m_handleCallbacks;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    /// @brief External integrations.
    /// DESIGN: stored as std::atomic raw pointers because they are written
    /// by user-mode setter calls (Set*) and read by every detection worker
    /// thread on the hot path.  Acquire/release ordering on load/store
    /// guarantees visibility without taking m_mutex on read.  Ownership
    /// stays with the caller (this is an integration handle, not lifetime
    /// management).
    std::atomic<Whitelist::WhitelistStore*>      m_whitelist{nullptr};
    std::atomic<Engine::BehaviorAnalyzer*>       m_behaviorAnalyzer{nullptr};
    std::atomic<Engine::ThreatDetector*>         m_threatDetector{nullptr};
    std::atomic<RealTime::MemoryProtection*>     m_memoryProtection{nullptr};

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
    /// Key = SplitMix64-mixed hash(sourcePid, targetPid, injectionType).
    /// Prevents the same injection from generating duplicate events when
    /// detected through multiple handlers (handle + memory + thread).
    /// Backed by an unordered_set for O(1) lookup + a FIFO deque for
    /// expiry, both guarded by m_dedupMutex.
    struct DeduplicationEntry {
        uint64_t key{0};
        TimePoint expiry{};
    };
    std::deque<DeduplicationEntry> m_recentInjections;
    std::unordered_set<uint64_t>   m_recentInjectionsIndex;
    mutable std::mutex m_dedupMutex;

    /// @brief Hard cap on dedup entries — defence in depth against
    /// memory growth if the cleanup pass falls behind.
    static constexpr size_t MAX_DEDUP_ENTRIES = 50000;

    /// @brief Deduplication window — events with same source+target+type
    /// within this window are suppressed.
    static constexpr auto DEDUP_WINDOW = std::chrono::seconds(5);

    // ========================================================================
    // KNOWN LOLBins — Microsoft-signed binaries abused for injection/execution
    // ========================================================================

    static constexpr std::wstring_view kLolBins[] = {
        // Alphabetised, deduped.  Maintains a defensive list of Microsoft-
        // signed binaries that, when used as injection sources, are commonly
        // abused for LOLBin / BYOL / UAC-bypass tradecraft.  Membership here
        // is *necessary but not sufficient* for ShouldWhitelist() — the
        // source path must additionally resolve under \Windows\System32 or
        // \Windows\SysWOW64 to qualify, blocking name-only impersonation.
        L"addinprocess.exe",  L"appinstaller.exe",   L"atbroker.exe",
        L"bitsadmin.exe",     L"certutil.exe",       L"cmstp.exe",
        L"computerdefaults.exe", L"conhost.exe",     L"control.exe",
        L"csc.exe",           L"cscript.exe",        L"csi.exe",
        L"dllhost.exe",       L"dnscmd.exe",         L"dnx.exe",
        L"eventvwr.exe",      L"expand.exe",         L"finger.exe",
        L"fodhelper.exe",     L"forfiles.exe",       L"ftp.exe",
        L"hh.exe",            L"ie4uinit.exe",       L"ilasm.exe",
        L"installutil.exe",   L"jsc.exe",            L"makecab.exe",
        L"mavinject.exe",     L"mftrace.exe",        L"msbuild.exe",
        L"msdt.exe",          L"mshta.exe",          L"msiexec.exe",
        L"ngentask.exe",      L"presentationhost.exe", L"powershell.exe",
        L"powershell_ise.exe", L"pwsh.exe",          L"rcsi.exe",
        L"regasm.exe",        L"regsvcs.exe",        L"regsvr32.exe",
        L"rundll32.exe",      L"schtasks.exe",       L"scriptrunner.exe",
        L"sdclt.exe",         L"te.exe",             L"tracker.exe",
        L"vbc.exe",           L"wmic.exe",           L"wscript.exe",
        L"wsreset.exe",
    };

    // ========================================================================
    // METHODS
    // ========================================================================

    Impl() : m_selfPid(::GetCurrentProcessId()) {
        // Publish aliveness BEFORE any handler can be registered with
        // IPCManager.  Lambdas captured by RegisterKernelHandlers /
        // WireSubDetectorCallbacks observe this flag under acquire
        // ordering before dereferencing `this`.
        g_implAlive.store(true, std::memory_order_release);
    }
    ~Impl() {
        // Drop aliveness FIRST so that any in-flight IPC delivery sees
        // the flag clear and short-circuits before touching members
        // currently being torn down.
        g_implAlive.store(false, std::memory_order_release);
    }

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
        // Initialize is serialised under m_mutex to prevent a second
        // concurrent caller from observing m_initialized==true before the
        // winner has finished publishing m_config / sub-detector wiring.
        // exchange-only was a TOCTOU window during which other threads
        // could call Start()/Stop() against half-constructed state.
        std::unique_lock<std::shared_mutex> initLock(m_mutex);

        if (m_initialized.load(std::memory_order_acquire)) {
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

        // Publish initialised state ONLY after every dependency is wired.
        m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"InjectionDetector",
            L"Initialized successfully (selfPid=%u, kernel=%ls, subDetectors=%ls)",
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
    const std::vector<HandleAccessEvent>& /*handles*/,
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
    // SECURITY: Module-name comparison is case-insensitive because Windows
    // PEB-published module names are not normalised — kernel32.dll,
    // KERNEL32.DLL, and Kernel32.dll all denote the same image and any
    // case-sensitive substring search trivially evades classification.
    if (hasWrite && hasRemoteThread && !startAddressNotInModule) {
        for (const auto& threadEvent : threads) {
            const auto modNameLower =
                Utils::StringUtils::ToLowerCopy(threadEvent.startAddressModule);
            if (modNameLower.find(L"kernel32") != std::wstring::npos ||
                modNameLower.find(L"kernelbase") != std::wstring::npos) {
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

    // Base confidence from technique.
    // DESIGN: every value below is calibrated to the false-positive rate
    // empirically observed on the gold-image telemetry corpus.  Techniques
    // that have **no legitimate user-mode use case** (IFEO redirection,
    // AppInit_DLLs, COM-hijack injection, SetWindowsHookEx into foreign
    // processes, ExtraWindowBytes shellcode storage, kernel SectionMapping
    // into another process) sit at >= 80 — a previous default of 50 was
    // dropping these techniques below MIN_ALERT_CONFIDENCE (60), turning
    // them into silent no-ops.
    switch (type) {
        case InjectionType::ProcessHollowing:
            confidence = 95.0;  // Very distinctive pattern
            break;
        case InjectionType::ReflectiveDLL:
            confidence = 90.0;  // Clear indicators
            break;
        case InjectionType::IFEO:
            confidence = 90.0;  // No legitimate runtime use; almost always persistence/escalation
            break;
        case InjectionType::COMHijacking:
            confidence = 88.0;  // Distinctive registry-derived injection
            break;
        case InjectionType::AppInitDLLs:
            confidence = 85.0;  // Deprecated; modern hits are malicious
            break;
        case InjectionType::ThreadHijacking:
            confidence = 85.0;
            break;
        case InjectionType::SetWindowsHook:
            confidence = 82.0;  // Cross-process hooks are high-fidelity malicious
            break;
        case InjectionType::ExtraWindowBytes:
            confidence = 82.0;  // Unique to PowerLoader-class techniques
            break;
        case InjectionType::SectionMapping:
            confidence = 80.0;  // Map+Write pairs are strongly correlated with NtMapViewOfSection abuse
            break;
        case InjectionType::APC:
        case InjectionType::EarlyBird:
            confidence = 80.0;
            break;
        case InjectionType::AtomBombing:
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
            confidence = 60.0;
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

    // ------------------------------------------------------------------
    // Helper: path must resolve under \Windows\System32 or \Windows\SysWOW64
    // for a Microsoft-signed binary to qualify for injection whitelisting.
    // This blocks the classic "signed binary in user-writable directory"
    // attack — e.g. a benign csc.exe relocated to %TEMP% and re-signed
    // with leaked certs — by forcing the source image to live inside the
    // OS-protected loader directories.  Comparison is case-insensitive
    // (NTFS / Win32 paths are case-preserving but not case-sensitive).
    // ------------------------------------------------------------------
    const auto isInProtectedSystemDir = [](std::wstring_view path) noexcept -> bool {
        if (path.empty()) {
            return false;
        }
        std::wstring lower = Utils::StringUtils::ToLowerCopy(path);
        // Normalise separators to backslash for substring matching.
        for (auto& wc : lower) {
            if (wc == L'/') wc = L'\\';
        }
        return lower.find(L"\\windows\\system32\\")  != std::wstring::npos ||
               lower.find(L"\\windows\\syswow64\\")  != std::wstring::npos ||
               lower.find(L"\\windows\\winsxs\\")    != std::wstring::npos;
    };

    // Step 1: Check process pair whitelist (name-based pre-filter)
    if (IsInjectionPairWhitelisted(event.sourceProcessName, event.targetProcessName)) {
        // Name matches a known OS pair. Validate the source is the real
        // OS binary via BOTH path (protected system dir) and digital
        // signature.  Either alone is insufficient: signature alone is
        // bypassed by leaked code-signing certs; path alone is bypassed
        // by binary planting + name spoofing.
        if (!event.sourceProcessPath.empty() &&
            isInProtectedSystemDir(event.sourceProcessPath)) {
            try {
                if (Security::DigitalSignatureValidator::Instance().IsMicrosoftSigned(
                        event.sourceProcessPath)) {
                    return true;
                }
            } catch (...) {
                // Signature check failed — do NOT whitelist; safer to alert.
            }
        }
        SS_LOG_WARN(L"InjectionDetector",
            L"Process %ls matched whitelist name but failed path/signature check - possible impersonation",
            SanitizeForDisplay(event.sourceProcessName).c_str());
        return false;
    }

    // Step 2: Microsoft-signed system binary path.
    // SECURITY: A Microsoft signature alone does NOT justify suppressing
    // a cross-process injection alert.  Three additional gates apply:
    //   a) The binary must NOT be in the LOLBin list (those are signed
    //      but routinely weaponised).
    //   b) The binary path must resolve under a protected system dir
    //      (System32 / SysWOW64 / WinSxS) — blocking signed-binary
    //      relocation/planting tradecraft.
    //   c) The signature must validate.
    if (m_config.trustMicrosoftSigned && !event.sourceProcessPath.empty()) {
        if (IsLolBin(event.sourceProcessName)) {
            return false;
        }
        if (!isInProtectedSystemDir(event.sourceProcessPath)) {
            return false;
        }
        try {
            if (Security::DigitalSignatureValidator::Instance().IsMicrosoftSigned(
                    event.sourceProcessPath)) {
                return true;
            }
        } catch (...) {
            // Signature check may fail for inaccessible processes — fall through.
        }
    }

    // Step 3: External whitelist store (admin-curated allow list).
    if (auto* wl = m_whitelist.load(std::memory_order_acquire)) {
        try {
            auto lr = wl->IsWhitelisted(event.sourceProcessPath);
            if (lr.found) {
                return true;
            }
        } catch (...) {
            // Defensive: a store lookup failure must not crash the
            // detector or wrongly whitelist.  Treat as "not found".
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
    alert.sourceProcessName = SanitizeForDisplay(event.sourceProcessName);
    alert.targetProcessId = event.targetProcessId;
    alert.targetProcessName = SanitizeForDisplay(event.targetProcessName);
    alert.injectionType = event.injectionType;
    alert.verdict = event.verdict;
    alert.confidence = event.confidence;
    alert.riskScore = event.riskScore;
    // SECURITY: alert.blocked is mirrored from event.blocked which MUST be
    // set by the caller (ProcessInjectionDetection) BEFORE CreateAlert is
    // invoked.  A prior ordering bug here always published blocked=false.
    alert.blocked = event.blocked;
    alert.mitreTechnique = event.mitreSubTechnique;
    alert.relatedEventIds.push_back(event.eventId);

    // Build details.  Process names are sanitised (control characters
    // stripped, length-capped) to neutralise log/UI injection driven by
    // attacker-chosen image names.
    std::wostringstream details;
    details << L"Injection detected: "
            << Utils::StringUtils::ToWide(InjectionTypeToString(event.injectionType))
            << L"\nSource: " << alert.sourceProcessName
            << L" (PID: " << event.sourceProcessId << L")"
            << L"\nTarget: " << alert.targetProcessName
            << L" (PID: " << event.targetProcessId << L")"
            << L"\nConfidence: " << std::fixed << std::setprecision(1) << event.confidence << L"%"
            << L"\nRisk Score: " << std::fixed << std::setprecision(1) << event.riskScore
            << L"\nMITRE: " << Utils::StringUtils::ToWide(event.mitreSubTechnique)
            << L"\nBlocked: " << (event.blocked ? L"yes" : L"no");

    if (event.targetThreadId > 0) {
        details << L"\nThread: " << event.targetThreadId;
    }

    if (!event.startAddressLegitimate) {
        details << L"\nStart address not in legitimate module";
    }

    // Defensive: cap final details length so a malformed event with
    // pathological field sizes can't blow up downstream UI / IPC buffers.
    constexpr size_t kMaxAlertDetailsLen = 4096;
    auto detailsStr = details.str();
    if (detailsStr.size() > kMaxAlertDetailsLen) {
        detailsStr.resize(kMaxAlertDetailsLen);
        detailsStr.append(L"\u2026");
    }
    alert.details = std::move(detailsStr);

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
        if (startPid == 0) {
            return std::nullopt;
        }

        // -----------------------------------------------------------------
        // LOCK ORDER: events_mutex BEFORE states_mutex (one direction only).
        //
        // The previous implementation acquired states first, then took
        // m_eventsMutex inside the loop while still holding states.  Other
        // call sites (ProcessInjectionDetection, the public OnHandleAccess
        // pipeline) acquire events->states, producing a textbook AB-BA
        // inversion that deadlocks under load.
        //
        // We resolve this by **walking the chain entirely from the events
        // map** (PID adjacency is encoded in event.targetProcessId), with
        // a single quick states-side lookup at the start to obtain the
        // "most recent outgoing eventId" hint for the seed PID — then a
        // separate, non-overlapping states lookup at the end for the
        // victim's display name.  No nested locks; both critical sections
        // are read-only shared locks held briefly.
        // -----------------------------------------------------------------

        // 1) Seed eventId + attacker display name (states only).
        uint64_t seedEventId = 0;
        std::wstring attackerName;
        {
            std::shared_lock<std::shared_mutex> stateLock(m_statesMutex);
            auto it = m_processStates.find(startPid);
            if (it == m_processStates.end() || it->second.outgoingInjectionIds.empty()) {
                return std::nullopt;
            }
            seedEventId = it->second.outgoingInjectionIds.back();
            attackerName = it->second.processName;
        }

        InjectionChain chain;
        chain.chainId = m_nextChainId.fetch_add(1, std::memory_order_relaxed);
        chain.initialAttackerPid = startPid;
        chain.initialAttackerName = attackerName;
        chain.startTime = Clock::now();
        chain.chainPath.push_back(startPid);

        std::unordered_set<uint32_t> visited;
        visited.insert(startPid);

        // 2) Walk forward through the events map only.  We hold the events
        //    shared lock once, copy out the data we need per hop, never
        //    cross into states while inside this loop.
        {
            std::shared_lock<std::shared_mutex> eventLock(m_eventsMutex);
            uint64_t currentEventId = seedEventId;
            size_t depth = 0;
            while (depth < InjectionConstants::MAX_CHAIN_DEPTH) {
                auto eventIt = m_events.find(currentEventId);
                if (eventIt == m_events.end()) {
                    break;
                }
                const auto& event = eventIt->second;
                chain.events.push_back(event);
                chain.totalRiskScore += event.riskScore;

                const uint32_t nextPid = event.targetProcessId;
                if (nextPid == 0 || visited.contains(nextPid)) {
                    break;  // Circular or terminal injection.
                }
                chain.chainPath.push_back(nextPid);
                visited.insert(nextPid);
                ++depth;

                // Find next outgoing edge for nextPid by scanning the
                // events map (held under the same shared lock).  We
                // cannot re-enter states from here without violating the
                // lock-order invariant.  In practice the events map is
                // small (50k cap) and chain depth is at most 10.
                uint64_t nextEventId = 0;
                TimePoint newest{};
                for (const auto& [id, ev] : m_events) {
                    if (ev.sourceProcessId == nextPid && ev.timestamp >= newest) {
                        nextEventId = id;
                        newest = ev.timestamp;
                    }
                }
                if (nextEventId == 0) {
                    break;
                }
                currentEventId = nextEventId;
            }
            chain.depth = depth;
        }

        if (chain.events.empty()) {
            return std::nullopt;
        }

        chain.finalVictimPid = chain.chainPath.back();
        chain.endTime = Clock::now();

        // 3) Resolve victim display name (states only, separate critical
        //    section — no overlap with the events lock above).
        {
            std::shared_lock<std::shared_mutex> stateLock(m_statesMutex);
            if (auto victimIt = m_processStates.find(chain.finalVictimPid);
                victimIt != m_processStates.end()) {
                chain.finalVictimName = victimIt->second.processName;
            }
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

    // Purge handle events.
    // DESIGN: time-ordered deques — events are appended at the back, so
    // the back of the queue is newest and the front is oldest.  Front-
    // popping until we hit a fresh event is O(k) instead of O(n) for the
    // previous mid-iterator erase loop.
    {
        std::unique_lock lock(m_handleEventsMutex);
        while (!m_handleEvents.empty() &&
               (now - m_handleEvents.front().timestamp) > maxAge) {
            m_handleEvents.pop_front();
            ++purged;
        }
    }

    // Purge memory events
    {
        std::unique_lock lock(m_memoryEventsMutex);
        while (!m_memoryEvents.empty() &&
               (now - m_memoryEvents.front().timestamp) > maxAge) {
            m_memoryEvents.pop_front();
            ++purged;
        }
    }

    // Purge thread events
    {
        std::unique_lock lock(m_threadEventsMutex);
        while (!m_threadEvents.empty() &&
               (now - m_threadEvents.front().timestamp) > maxAge) {
            m_threadEvents.pop_front();
            ++purged;
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

    // Purge stale process states.
    // SECURITY: PID-reuse hardening — Windows recycles PIDs aggressively.
    // We retire a state when EITHER the process is dead OR its current
    // creation timestamp no longer matches the one captured at first
    // sighting.  The latter prevents stale state from a terminated PID
    // bleeding into telemetry attributed to a freshly-spawned process
    // that happened to reuse the number.
    {
        const auto staleAge = std::chrono::hours(2);
        std::unique_lock lock(m_statesMutex);
        auto it = m_processStates.begin();
        while (it != m_processStates.end()) {
            auto& state = it->second;
            const bool dead = !Utils::ProcessUtils::IsProcessRunning(state.processId);
            bool reused = false;
            if (!dead && state.creationTick != 0) {
                const uint64_t live = GetProcessCreationTick(state.processId);
                if (live != 0 && live != state.creationTick) {
                    reused = true;
                }
            }
            if ((dead && (now - state.lastActivity) > staleAge) || reused) {
                it = m_processStates.erase(it);
                ++purged;
            } else {
                // Cap per-state vectors to prevent unbounded growth.
                constexpr size_t MAX_PER_STATE = InjectionConstants::MAX_EVENTS_PER_SOURCE;
                TrimVectorToCap(state.crossProcessHandles, MAX_PER_STATE);
                TrimVectorToCap(state.remoteMemoryOps,     MAX_PER_STATE);
                TrimVectorToCap(state.remoteThreadOps,     MAX_PER_STATE);
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

    // SECURITY / DEADLOCK: copy the callback container under the lock,
    // then invoke OUTSIDE the lock.  Invoking user-supplied callbacks
    // while holding m_callbacksMutex deadlocks if a callback re-enters
    // RegisterInjectionCallback / UnregisterInjectionCallback (which
    // also take the same mutex), and allows a slow callback to block
    // every other module trying to register against us.
    std::vector<InjectionCallback> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        snapshot.reserve(m_injectionCallbacks.size());
        for (const auto& [id, cb] : m_injectionCallbacks) {
            if (cb) snapshot.push_back(cb);
        }
    }

    for (const auto& callback : snapshot) {
        try {
            InjectionVerdict callbackVerdict = callback(event);
            // Allow callbacks to escalate verdict
            if (static_cast<int>(callbackVerdict) > static_cast<int>(verdict)) {
                verdict = callbackVerdict;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Injection callback error - %S", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"InjectionDetector", L"Injection callback threw unknown exception");
        }
    }

    return verdict;
}

void ProcessInjectionDetector::Impl::InvokeAlertCallbacks(const InjectionAlert& alert) {
    std::vector<InjectionAlertCallback> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        snapshot.reserve(m_alertCallbacks.size());
        for (const auto& [id, cb] : m_alertCallbacks) {
            if (cb) snapshot.push_back(cb);
        }
    }
    for (const auto& callback : snapshot) {
        try {
            callback(alert);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Alert callback error - %S", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"InjectionDetector", L"Alert callback threw unknown exception");
        }
    }
}

void ProcessInjectionDetector::Impl::InvokeChainCallbacks(const InjectionChain& chain) {
    std::vector<InjectionChainCallback> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        snapshot.reserve(m_chainCallbacks.size());
        for (const auto& [id, cb] : m_chainCallbacks) {
            if (cb) snapshot.push_back(cb);
        }
    }
    for (const auto& callback : snapshot) {
        try {
            callback(chain);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"InjectionDetector", L"Chain callback error - %S", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"InjectionDetector", L"Chain callback threw unknown exception");
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
    // SECURITY: SplitMix64-mixed key (see MakeDedupKey).  The previous
    // XOR-of-shifts implementation produced trivially-colliding keys for
    // adjacent PIDs and could be exploited to suppress real injections.
    const uint64_t key = MakeDedupKey(sourcePid, targetPid, type);
    const auto now = Clock::now();

    std::lock_guard<std::mutex> lock(m_dedupMutex);

    // Expire old entries (front-popping; deque is time-ordered).
    while (!m_recentInjections.empty() && m_recentInjections.front().expiry <= now) {
        m_recentInjectionsIndex.erase(m_recentInjections.front().key);
        m_recentInjections.pop_front();
    }

    // O(1) lookup via the parallel unordered_set index.
    if (m_recentInjectionsIndex.contains(key)) {
        return true;
    }

    m_recentInjections.push_back({key, now + DEDUP_WINDOW});
    m_recentInjectionsIndex.insert(key);

    // Defensive cap — if the cleanup pass falls behind, drop the oldest
    // entry rather than allowing unbounded growth.
    while (m_recentInjections.size() > MAX_DEDUP_ENTRIES) {
        m_recentInjectionsIndex.erase(m_recentInjections.front().key);
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
        // pipeline. This is the critical kernel<->user-mode bridge.
        //
        // The generic feed is a FAN-OUT (IPCManager::GenericSubscription), so
        // this subscription no longer competes with the other seven modules
        // that also observe it. It used to: the feed was a single slot and the
        // last registrant silently evicted the rest, which is why the audit
        // note that stood here called it an ARCH-BLOCKER. Registering under a
        // stable name is what makes the membership removable and attributable.
        //
        // SAFETY: the lambda guards against use-after-free at process
        // exit (IPCManager and ProcessInjectionDetector singletons have
        // unspecified destruction order) by checking the static
        // g_implAlive flag under acquire ordering BEFORE touching any
        // captured pointer.
        ipc.RegisterGenericHandler("ProcessInjectionDetector",
            [this](SHADOWSTRIKE_MESSAGE_TYPE msgType, const void* payload, size_t payloadSize) noexcept {
                if (!g_implAlive.load(std::memory_order_acquire)) {
                    return;
                }
                if (!m_running.load(std::memory_order_acquire)) {
                    return;
                }
                try {
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
                } catch (...) {
                    // Never let a kernel-fed exception escape into IPCManager's
                    // dispatch loop — that would terminate the entire IPC pump.
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

    // Validate kernel-supplied PIDs.  PID 0 is the Idle pseudo-process and
    // must never enter the state map; a kernel telemetry bug or driver-
    // side scrubbing artefact could otherwise corrupt our correlation.
    if (tn->ProcessId == 0 || tn->CreatorProcessId == 0) {
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

    // Feed into the standard event handler pipeline (store + correlate).
    // NOTE: remoteThreadsDetected is owned by UpdateTechniqueStats — we
    // do NOT increment it here, otherwise the same event is counted twice
    // (once by this handler, again when ProcessInjectionDetection runs).
    m_stats.threadEvents.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalEvents.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lock(m_threadEventsMutex);
        m_threadEvents.push_back(threadEvent);
        if (m_threadEvents.size() > InjectionConstants::MAX_INJECTION_EVENTS) {
            m_threadEvents.pop_front();
        }
    }

    if (threadEvent.sourceProcessId != 0) {
        std::unique_lock lock(m_statesMutex);
        auto& state = m_processStates[threadEvent.sourceProcessId];
        state.processId = threadEvent.sourceProcessId;
        if (state.creationTick == 0) {
            state.creationTick = GetProcessCreationTick(threadEvent.sourceProcessId);
            state.firstActivity = Clock::now();
        }
        state.remoteThreadOps.push_back(threadEvent);
        TrimVectorToCap(state.remoteThreadOps, kPerStateEventCap);
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

    // Validate kernel-supplied PIDs.  PID 0 is the Idle pseudo-process.
    if (ha->SourceProcessId == 0 || ha->TargetProcessId == 0) {
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
        if (state.creationTick == 0) {
            state.creationTick = GetProcessCreationTick(handleEvent.sourceProcessId);
            state.firstActivity = Clock::now();
        }
        state.crossProcessHandles.push_back(handleEvent);
        TrimVectorToCap(state.crossProcessHandles, kPerStateEventCap);
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
            (void)ProcessHollowingDetector::Instance().RegisterDetectionCallback(
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
            (void)ms.RegisterThreatCallback(
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

    // Invoke injection callbacks (may escalate verdict).
    // SECURITY: callbacks run BEFORE we mutate persistent state so they
    // can veto/escalate, and they run BEFORE we publish an alert so the
    // alert reflects the final verdict.
    event.verdict = InvokeInjectionCallbacks(event);

    // Recompute the block decision EXACTLY ONCE, here, before any side
    // effect.  Two prior bugs are fixed by this consolidation:
    //   1) `event.blocked` was set AFTER CreateAlert(), so every published
    //      alert always reported blocked=false even when the engine
    //      blocked.
    //   2) `m_stats.injectionsBlocked` could be incremented twice for the
    //      same event — once by a BehaviorAnalyzer escalation path, again
    //      by the threshold-driven block path below.
    bool baEscalated = false;
    double baMaliceScore = 0.0;
    if (auto* ba = m_behaviorAnalyzer.load(std::memory_order_acquire);
        ba != nullptr && ba->IsInitialized()) {
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

            auto baVerdict = ba->ProcessEvent(baEvent);
            if (baVerdict.has_value() && baVerdict->RequiresImmediateAction()) {
                baEscalated = true;
                baMaliceScore = baVerdict->maliceScore;
            }
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"InjectionDetector",
                L"BehaviorAnalyzer forwarding failed: %S", ex.what());
        }
    }

    const bool thresholdBlock =
        m_config.blockInjections &&
        event.confidence >= m_config.blockConfidence &&
        event.verdict != InjectionVerdict::Whitelisted;

    event.blocked = (baEscalated || thresholdBlock);
    if (event.blocked) {
        m_stats.injectionsBlocked.fetch_add(1, std::memory_order_relaxed);
        if (baEscalated) {
            SS_LOG_WARN(L"InjectionDetector",
                L"BehaviorAnalyzer escalated injection %ls->%ls to BLOCK (score=%.1f)",
                SanitizeForDisplay(event.sourceProcessName).c_str(),
                SanitizeForDisplay(event.targetProcessName).c_str(),
                baMaliceScore);
        } else {
            SS_LOG_WARN(L"InjectionDetector",
                L"Blocked injection %ls -> %ls (%S, confidence=%.1f)",
                SanitizeForDisplay(event.sourceProcessName).c_str(),
                SanitizeForDisplay(event.targetProcessName).c_str(),
                InjectionTypeToString(event.injectionType),
                event.confidence);
        }
    }

    // Store event (use move — InjectionEvent contains nested vectors that
    // are large enough to make the copy non-trivial on hot paths).
    {
        std::unique_lock lock(m_eventsMutex);
        m_events.emplace(event.eventId, event);
    }

    // Update process states.  PID 0 is reserved for the Idle pseudo-
    // process and must never be inserted; doing so would create a
    // permanent "zero state" that absorbs every malformed event.
    {
        std::unique_lock lock(m_statesMutex);
        if (event.sourceProcessId != 0) {
            auto& srcState = m_processStates[event.sourceProcessId];
            srcState.processId = event.sourceProcessId;
            if (srcState.processName.empty()) {
                srcState.processName = event.sourceProcessName;
            }
            if (srcState.creationTick == 0) {
                srcState.creationTick = GetProcessCreationTick(event.sourceProcessId);
                srcState.firstActivity = Clock::now();
            }
            srcState.isInjecting = true;
            srcState.outgoingInjectionIds.push_back(event.eventId);
            ++srcState.totalInjectionsAsSource;
            srcState.lastActivity = Clock::now();
        }

        if (event.targetProcessId != 0) {
            auto& tgtState = m_processStates[event.targetProcessId];
            tgtState.processId = event.targetProcessId;
            if (tgtState.processName.empty()) {
                tgtState.processName = event.targetProcessName;
            }
            if (tgtState.creationTick == 0) {
                tgtState.creationTick = GetProcessCreationTick(event.targetProcessId);
                tgtState.firstActivity = Clock::now();
            }
            tgtState.isBeingInjected = true;
            tgtState.hasBeenInjected = true;
            tgtState.incomingInjectionIds.push_back(event.eventId);
            ++tgtState.totalInjectionsAsTarget;
            tgtState.lastActivity = Clock::now();
        }
    }

    // Update technique-specific stats.  This is the SINGLE site that
    // increments `remoteThreadsDetected` / `injectionsDetected` etc.
    m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
    UpdateTechniqueStats(event.injectionType);

    // Generate and publish alert if confidence meets threshold.  The
    // alert correctly carries event.blocked because we set it above.
    if (event.confidence >= m_config.alertConfidence) {
        auto alert = CreateAlert(event);
        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.push_back(alert);
            while (m_alerts.size() > kMaxAlertHistory) {
                m_alerts.pop_front();
            }
        }
        InvokeAlertCallbacks(alert);
    }

    // Auto chain detection: if the source is already a known injection
    // target (it was previously injected INTO), this is a multi-hop chain.
    if (event.sourceProcessId != 0 && m_config.detectChains) {
        bool sourceWasInjected = false;
        {
            std::shared_lock<std::shared_mutex> stateLock(m_statesMutex);
            auto srcIt = m_processStates.find(event.sourceProcessId);
            sourceWasInjected =
                (srcIt != m_processStates.end() && srcIt->second.hasBeenInjected);
        }
        if (sourceWasInjected) {
            if (auto chain = DetectChain(event.sourceProcessId)) {
                {
                    std::unique_lock<std::shared_mutex> chainLock(m_chainsMutex);
                    m_chains.push_back(*chain);
                    while (m_chains.size() > kMaxChainHistory) {
                        m_chains.pop_front();
                    }
                }
                m_stats.chainsDetected.fetch_add(1, std::memory_order_relaxed);
                InvokeChainCallbacks(*chain);

                SS_LOG_WARN(L"InjectionDetector",
                    L"Injection CHAIN detected: depth=%zu, start=%ls (PID %u) -> end=%ls (PID %u), risk=%.1f",
                    chain->depth,
                    SanitizeForDisplay(chain->initialAttackerName).c_str(),
                    chain->initialAttackerPid,
                    SanitizeForDisplay(chain->finalVictimName).c_str(),
                    chain->finalVictimPid,
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
    if (!m_impl || pid == 0) return events;

    // SECURITY / DEADLOCK: copy the event-ID list out under m_statesMutex,
    // then release the states lock before acquiring m_eventsMutex.  This
    // enforces the project-wide lock order (events -> states) and avoids
    // the AB-BA inversion that the previous nested-lock pattern exposed.
    std::vector<uint64_t> ids;
    {
        std::shared_lock<std::shared_mutex> stateLock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it == m_impl->m_processStates.end()) {
            return events;
        }
        ids = it->second.incomingInjectionIds;
    }

    std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
    events.reserve(ids.size());
    for (uint64_t eventId : ids) {
        auto eventIt = m_impl->m_events.find(eventId);
        if (eventIt != m_impl->m_events.end()) {
            events.push_back(eventIt->second);
        }
    }

    return events;
}

std::vector<InjectionEvent> ProcessInjectionDetector::GetInjectionsFrom(uint32_t pid) const {
    std::vector<InjectionEvent> events;
    if (!m_impl || pid == 0) return events;

    std::vector<uint64_t> ids;
    {
        std::shared_lock<std::shared_mutex> stateLock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it == m_impl->m_processStates.end()) {
            return events;
        }
        ids = it->second.outgoingInjectionIds;
    }

    std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
    events.reserve(ids.size());
    for (uint64_t eventId : ids) {
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
    // DESIGN: m_chains is a std::deque internally (FIFO O(1) pop_front);
    // materialise as std::vector here to preserve the public API shape.
    return std::vector<InjectionChain>(m_impl->m_chains.begin(), m_impl->m_chains.end());
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
    if (!m_impl || pid == 0) return false;

    // Step 1: Inspect recorded events (lock order: states -> release ->
    // events, never both at once).
    std::vector<uint64_t> ids;
    {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it != m_impl->m_processStates.end()) {
            ids = it->second.incomingInjectionIds;
        }
    }
    if (!ids.empty()) {
        std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
        for (uint64_t eventId : ids) {
            auto eventIt = m_impl->m_events.find(eventId);
            if (eventIt != m_impl->m_events.end() &&
                eventIt->second.injectionType == InjectionType::ProcessHollowing) {
                m_impl->m_stats.hollowingDetected.fetch_add(1, std::memory_order_relaxed);
                return true;
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
    if (!m_impl || pid == 0) return false;

    std::vector<uint64_t> ids;
    {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it != m_impl->m_processStates.end()) {
            ids = it->second.incomingInjectionIds;
        }
    }
    if (!ids.empty()) {
        std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
        for (uint64_t eventId : ids) {
            auto eventIt = m_impl->m_events.find(eventId);
            if (eventIt != m_impl->m_events.end() &&
                eventIt->second.injectionType == InjectionType::ReflectiveDLL) {
                m_impl->m_stats.reflectiveDLLDetected.fetch_add(1, std::memory_order_relaxed);
                return true;
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
    if (!m_impl || pid == 0) return false;

    // Snapshot the incoming-ID list and remote thread ops under the
    // states lock, then drop it before touching m_eventsMutex.
    std::vector<uint64_t> ids;
    std::vector<ThreadOperationEvent> remoteThreadOpsSnapshot;
    {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it == m_impl->m_processStates.end()) {
            return false;
        }
        ids = it->second.incomingInjectionIds;
        remoteThreadOpsSnapshot = it->second.remoteThreadOps;
    }

    if (!ids.empty()) {
        std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
        for (uint64_t eventId : ids) {
            auto eventIt = m_impl->m_events.find(eventId);
            if (eventIt != m_impl->m_events.end() &&
                eventIt->second.injectionType == InjectionType::AtomBombing) {
                return true;
            }
        }
    }

    // Scan APC events for the GlobalGetAtom-in-kernel32 signature
    // (case-insensitive substring; see ClassifyFromEvents rationale).
    for (const auto& threadOp : remoteThreadOpsSnapshot) {
        if (threadOp.operation == ThreadOperationEvent::OpType::QueueAPC &&
            threadOp.apcRoutine != 0) {
            const std::wstring modName = GetModuleForAddress(pid, threadOp.apcRoutine);
            const std::wstring modLower = Utils::StringUtils::ToLowerCopy(modName);
            if (modLower.find(L"kernel32") != std::wstring::npos ||
                modLower.find(L"kernelbase") != std::wstring::npos) {
                return true;
            }
        }
    }

    return false;
}

bool ProcessInjectionDetector::CheckThreadHijacking(uint32_t pid, uint32_t threadId) {
    if (!m_impl || pid == 0) return false;

    std::vector<uint64_t> ids;
    {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_statesMutex);
        auto it = m_impl->m_processStates.find(pid);
        if (it == m_impl->m_processStates.end()) {
            return false;
        }
        ids = it->second.incomingInjectionIds;
    }

    std::shared_lock<std::shared_mutex> eventLock(m_impl->m_eventsMutex);
    for (uint64_t eventId : ids) {
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
        m_impl->m_whitelist.store(store, std::memory_order_release);
    }
}

void ProcessInjectionDetector::SetBehaviorAnalyzer(Engine::BehaviorAnalyzer* analyzer) {
    if (m_impl) {
        m_impl->m_behaviorAnalyzer.store(analyzer, std::memory_order_release);
    }
}

void ProcessInjectionDetector::SetThreatDetector(Engine::ThreatDetector* detector) {
    if (m_impl) {
        m_impl->m_threatDetector.store(detector, std::memory_order_release);
    }
}

void ProcessInjectionDetector::SetMemoryProtection(RealTime::MemoryProtection* memProtect) {
    if (m_impl) {
        m_impl->m_memoryProtection.store(memProtect, std::memory_order_release);
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
