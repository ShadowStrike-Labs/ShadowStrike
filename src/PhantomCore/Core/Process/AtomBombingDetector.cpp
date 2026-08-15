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
 * @file AtomBombingDetector.cpp
 * @brief Enterprise implementation of AtomBombing attack detection engine.
 *
 * The Chemist of ShadowStrike NGAV - detects sophisticated code injection attacks
 * that abuse the Windows Global Atom Table. Monitors atom creation, APC queuing,
 * and correlates events to identify the complete attack chain.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "AtomBombingDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../../Communication/IPCManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <unordered_set>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winternl.h>
#  include <psapi.h>
#  include <tlhelp32.h>
#  pragma comment(lib, "psapi.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Process {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculate Shannon entropy of a byte sequence.
 */
[[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

/**
 * @brief Check for common shellcode patterns (x86 and x64).
 *
 * Uses a broad set of instruction-level signatures found in real-world
 * shellcode payloads (Metasploit, Cobalt Strike, custom loaders).
 * Matching two or more distinct families strongly indicates executable
 * content rather than coincidental data.
 */
[[nodiscard]] bool HasShellcodePatterns(std::span<const uint8_t> data) noexcept {
    if (data.size() < 16) return false;

    // Each entry: bytes + length (up to 4 bytes per signature)
    struct PatternEntry {
        uint8_t bytes[4];
        uint8_t len;
    };

    static constexpr std::array<PatternEntry, 16> patterns = {{
        // x86 common
        {{0x90, 0x90, 0x90, 0x00}, 3},  // NOP sled
        {{0x31, 0xC0, 0x50, 0x00}, 3},  // xor eax,eax; push eax
        {{0x64, 0xA1, 0x30, 0x00}, 4},  // mov eax, fs:[0x30] (PEB access x86)
        {{0x55, 0x8B, 0xEC, 0x00}, 3},  // push ebp; mov ebp,esp
        {{0xEB, 0xFE, 0x00, 0x00}, 2},  // jmp $ (infinite loop / egg-hunt marker)
        {{0xCC, 0xCC, 0xCC, 0x00}, 3},  // int3 breakpoints

        // x64 common
        {{0x48, 0x83, 0xEC, 0x00}, 3},  // sub rsp, imm8 (stack frame)
        {{0x4C, 0x8B, 0xDC, 0x00}, 3},  // mov r11, rsp
        {{0x65, 0x48, 0x8B, 0x04}, 4},  // mov rax, gs:[...] (PEB access x64)
        {{0x48, 0x31, 0xC9, 0x00}, 3},  // xor rcx, rcx (zero register)
        {{0x48, 0x89, 0xE5, 0x00}, 3},  // mov rbp, rsp

        // Shellcode-specific
        {{0xFC, 0x48, 0x83, 0xE4}, 4},  // cld; and rsp,-10h (Cobalt Strike beacon)
        {{0xFC, 0xE8, 0x00, 0x00}, 4},  // cld; call $+5  (position-independent stub)
        {{0x31, 0xC9, 0x64, 0x8B}, 4},  // xor ecx,ecx; mov ...,fs:[...] (PEB walk)
        {{0x41, 0x51, 0x41, 0x50}, 4},  // push r9; push r8 (x64 shellcode prologue)
        {{0x48, 0x8D, 0x05, 0x00}, 3},  // lea rax,[rip+...] (RIP-relative addressing)
    }};

    size_t patternMatches = 0;
    for (const auto& pattern : patterns) {
        const size_t pLen = pattern.len;
        if (data.size() < pLen) continue;
        for (size_t i = 0; i <= data.size() - pLen; ++i) {
            if (std::memcmp(data.data() + i, pattern.bytes, pLen) == 0) {
                patternMatches++;
                break;
            }
        }
    }

    return patternMatches >= 2;
}

/**
 * @brief Check for null bytes (common in shellcode to avoid string termination).
 */
[[nodiscard]] bool HasNullBytes(std::span<const uint8_t> data) noexcept {
    return std::find(data.begin(), data.end(), 0x00) != data.end();
}

/**
 * @brief Sanitize a wide string for safe inclusion in log records.
 *
 * Defends against log-injection attacks where attacker-controlled input
 * (image paths, atom names) contains CR/LF/control characters used to
 * forge log lines. Replaces all C0/C1 control characters and embedded
 * format specifiers with '?'. Truncates to a hard cap to bound the
 * size of any single log entry.
 */
[[nodiscard]] std::wstring SanitizeForLog(std::wstring_view input) noexcept {
    constexpr size_t kMaxLen = 260;
    std::wstring out;
    out.reserve(std::min<size_t>(input.size(), kMaxLen));
    for (size_t i = 0; i < input.size() && out.size() < kMaxLen; ++i) {
        const wchar_t c = input[i];
        // Strip C0 (<0x20), DEL, C1 (0x80-0x9F), and percent (format-string guard).
        if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) || c == L'%') {
            out.push_back(L'?');
        } else {
            out.push_back(c);
        }
    }
    if (input.size() > kMaxLen) {
        out.append(L"...");
    }
    return out;
}

/**
 * @brief RAII wrapper for Windows HANDLE to prevent handle leaks.
 */
struct ScopedHandle {
    HANDLE h = nullptr;
    explicit ScopedHandle(HANDLE handle) noexcept : h(handle) {}
    ~ScopedHandle() { if (h && h != INVALID_HANDLE_VALUE) { CloseHandle(h); } }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    [[nodiscard]] explicit operator bool() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE get() const noexcept { return h; }
};

/**
 * @brief Get module name from address.
 *
 * Uses a heap-allocated buffer capped at 512 modules to avoid blowing
 * the stack in deeply-loaded processes.
 */
[[nodiscard]] std::wstring GetModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    constexpr DWORD kMaxModules = 512;
    auto hMods = std::make_unique<HMODULE[]>(kMaxModules);
    DWORD cbNeeded = 0;

    if (EnumProcessModules(hProcess, hMods.get(),
                           kMaxModules * sizeof(HMODULE), &cbNeeded)) {
        const DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        const DWORD limit = std::min(moduleCount, kMaxModules);
        for (DWORD i = 0; i < limit; i++) {
            MODULEINFO modInfo{};
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                auto baseAddr = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                if (address >= baseAddr && address < baseAddr + modInfo.SizeOfImage) {
                    wchar_t szModName[MAX_PATH]{};
                    if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                        return fs::path(szModName).filename().wstring();
                    }
                }
            }
        }
    }

    return L"Unknown";
}

} // anonymous namespace

// ============================================================================
// AtomBombingConfig FACTORY METHODS
// ============================================================================

AtomBombingConfig AtomBombingConfig::CreateDefault() noexcept {
    return AtomBombingConfig{};
}

AtomBombingConfig AtomBombingConfig::CreateHighSensitivity() noexcept {
    AtomBombingConfig config;
    config.mode = MonitoringMode::Active;
    config.enableRealTimeMonitoring = true;
    config.enableOnDemandScanning = true;

    config.monitorAtomTable = true;
    config.monitorAPCs = true;
    config.correlateAtomAndAPC = true;
    config.detectShellcodePatterns = true;
    config.analyzeEntropy = true;
    config.extractPayloads = true;

    config.alertThreshold = DetectionConfidence::Low;  // More sensitive
    config.entropyThreshold = 6.0;  // Lower threshold
    config.suspiciousAtomSizeThreshold = 32;  // Lower threshold

    config.enableAutoResponse = true;
    config.blockSuspiciousApcs = true;
    config.terminateAttacker = false;  // Caution with auto-termination

    return config;
}

AtomBombingConfig AtomBombingConfig::CreatePerformance() noexcept {
    AtomBombingConfig config;
    config.mode = MonitoringMode::PassiveOnly;
    config.enableRealTimeMonitoring = true;
    config.enableOnDemandScanning = false;

    config.monitorAtomTable = true;
    config.monitorAPCs = false;  // Expensive
    config.correlateAtomAndAPC = false;
    config.detectShellcodePatterns = true;
    config.analyzeEntropy = false;  // Expensive
    config.extractPayloads = false;

    config.alertThreshold = DetectionConfidence::High;
    config.entropyThreshold = 7.5;
    config.suspiciousAtomSizeThreshold = 128;

    config.enableAutoResponse = false;
    config.maxAtomsToAnalyze = 4096;

    return config;
}

// ============================================================================
// AtomBombingStatistics METHODS
// ============================================================================

void AtomBombingStatistics::Reset() noexcept {
    atomsMonitored.store(0, std::memory_order_relaxed);
    atomCreations.store(0, std::memory_order_relaxed);
    atomDeletions.store(0, std::memory_order_relaxed);
    suspiciousAtomsDetected.store(0, std::memory_order_relaxed);
    highEntropyAtomsDetected.store(0, std::memory_order_relaxed);
    shellcodePatternsDetected.store(0, std::memory_order_relaxed);

    apcsMonitored.store(0, std::memory_order_relaxed);
    crossProcessApcs.store(0, std::memory_order_relaxed);
    suspiciousApcsDetected.store(0, std::memory_order_relaxed);
    atomTargetingApcs.store(0, std::memory_order_relaxed);

    attacksDetected.store(0, std::memory_order_relaxed);
    attacksBlocked.store(0, std::memory_order_relaxed);
    lowConfidenceDetections.store(0, std::memory_order_relaxed);
    mediumConfidenceDetections.store(0, std::memory_order_relaxed);
    highConfidenceDetections.store(0, std::memory_order_relaxed);
    confirmedAttacks.store(0, std::memory_order_relaxed);

    payloadsExtracted.store(0, std::memory_order_relaxed);
    extractionFailures.store(0, std::memory_order_relaxed);

    totalScanTimeMs.store(0, std::memory_order_relaxed);
    scansPerformed.store(0, std::memory_order_relaxed);

    scanErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
}

[[nodiscard]] double AtomBombingStatistics::GetDetectionRate() const noexcept {
    uint64_t scans = scansPerformed.load(std::memory_order_relaxed);
    if (scans == 0) return 0.0;

    uint64_t attacks = attacksDetected.load(std::memory_order_relaxed);
    return (static_cast<double>(attacks) / scans) * 100.0;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for AtomBombingDetector.
 */
class AtomBombingDetector::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_atomMutex;
    mutable std::shared_mutex m_apcMutex;
    mutable std::shared_mutex m_attackMutex;
    mutable std::shared_mutex m_callbackMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};

    // Configuration
    AtomBombingConfig m_config{};

    // Statistics
    AtomBombingStatistics m_stats{};

    // Atom tracking
    std::unordered_map<uint16_t, AtomInfo> m_monitoredAtoms;
    std::deque<AtomInfo> m_suspiciousAtoms;
    std::unordered_set<uint16_t> m_knownSafeAtoms;

    // APC tracking
    std::deque<APCEvent> m_recentApcs;
    std::deque<APCEvent> m_suspiciousApcs;
    std::atomic<uint64_t> m_nextEventId{1};

    // Attack detection
    std::deque<AtomBombingAttack> m_detectedAttacks;
    std::atomic<uint64_t> m_nextAttackId{1};

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, AttackDetectedCallback> m_attackCallbacks;
    std::unordered_map<uint64_t, SuspiciousAtomCallback> m_atomCallbacks;
    std::unordered_map<uint64_t, SuspiciousAPCCallback> m_apcCallbacks;

    // Worker threads
    std::vector<std::jthread> m_workerThreads;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // CONFIGURATION HELPERS
    // ========================================================================

    /**
     * @brief Return a thread-safe copy of the current configuration.
     *
     * All Impl methods that read m_config MUST use a snapshot obtained
     * through this helper to avoid data races with UpdateConfig().
     */
    [[nodiscard]] AtomBombingConfig SnapshotConfig() const {
        std::shared_lock lock(m_configMutex);
        return m_config;
    }

    // ========================================================================
    // CACHED API ADDRESSES (resolved once at init, boot-stable on Windows)
    // ========================================================================

    struct AtomApiAddresses {
        uintptr_t GlobalGetAtomNameA = 0;
        uintptr_t GlobalGetAtomNameW = 0;
        uintptr_t GlobalGetAtomNameA_KB = 0;   // KernelBase forwarded
        uintptr_t GlobalGetAtomNameW_KB = 0;
        uintptr_t NtAddAtom = 0;
        uintptr_t NtFindAtom = 0;
        bool resolved = false;
    };
    AtomApiAddresses m_cachedApiAddrs{};

    /**
     * @brief Resolve atom-related API addresses once.
     *
     * kernel32/KernelBase/ntdll are mapped at the same virtual address
     * in every process (per-boot ASLR, not per-process), so resolving
     * in our own process is sufficient.
     */
    void ResolveApiAddresses() noexcept {
        if (m_cachedApiAddrs.resolved) return;

        if (HMODULE hK32 = GetModuleHandleW(L"kernel32.dll")) {
            m_cachedApiAddrs.GlobalGetAtomNameA =
                reinterpret_cast<uintptr_t>(GetProcAddress(hK32, "GlobalGetAtomNameA"));
            m_cachedApiAddrs.GlobalGetAtomNameW =
                reinterpret_cast<uintptr_t>(GetProcAddress(hK32, "GlobalGetAtomNameW"));
        }
        if (HMODULE hKB = GetModuleHandleW(L"KernelBase.dll")) {
            m_cachedApiAddrs.GlobalGetAtomNameA_KB =
                reinterpret_cast<uintptr_t>(GetProcAddress(hKB, "GlobalGetAtomNameA"));
            m_cachedApiAddrs.GlobalGetAtomNameW_KB =
                reinterpret_cast<uintptr_t>(GetProcAddress(hKB, "GlobalGetAtomNameW"));
        }
        if (HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll")) {
            m_cachedApiAddrs.NtAddAtom =
                reinterpret_cast<uintptr_t>(GetProcAddress(hNtdll, "NtAddAtom"));
            m_cachedApiAddrs.NtFindAtom =
                reinterpret_cast<uintptr_t>(GetProcAddress(hNtdll, "NtFindAtom"));
        }
        m_cachedApiAddrs.resolved = true;
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const AtomBombingConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"AtomBombing", L"Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"AtomBombing", L"Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Initialize known safe atoms (system atoms)
            InitializeKnownSafeAtoms();

            // Cache atom-related API addresses for APC target detection
            ResolveApiAddresses();

            // Register with kernel driver to receive thread creation events
            // that may indicate APC injection (cross-process thread creation
            // is a strong indicator of APC-based injection techniques)
            RegisterKernelHandlers();

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"AtomBombing", L"Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Impl: Initialization exception: %S", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        // CRITICAL: Stop monitoring (which joins worker threads) BEFORE acquiring
        // m_configMutex. Worker threads call SnapshotConfig() which takes a shared
        // lock on m_configMutex; if Shutdown holds that mutex while joining, the
        // join deadlocks. m_monitoring is atomic so this transition is race-free
        // versus concurrent Start/Stop callers.
        StopMonitoringImpl();

        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"AtomBombing", L"Impl: Shutting down");

        // Clear data structures
        {
            std::unique_lock atomLock(m_atomMutex);
            m_monitoredAtoms.clear();
            m_suspiciousAtoms.clear();
            m_knownSafeAtoms.clear();
        }

        {
            std::unique_lock apcLock(m_apcMutex);
            m_recentApcs.clear();
            m_suspiciousApcs.clear();
        }

        {
            std::unique_lock attackLock(m_attackMutex);
            m_detectedAttacks.clear();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_attackCallbacks.clear();
            m_atomCallbacks.clear();
            m_apcCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"AtomBombing", L"Impl: Shutdown complete");
    }

    /**
     * @brief Register with IPCManager to receive kernel thread creation
     *        events. Remote thread creation is a precursor to APC injection.
     */
    void RegisterKernelHandlers() noexcept {
        try {
            if (!Communication::IPCManager::HasInstance()) {
                SS_LOG_WARN(L"AtomBombing",
                    L"IPCManager not available — kernel thread event integration disabled");
                return;
            }

            auto& ipc = Communication::IPCManager::Instance();
            ipc.RegisterGenericHandler("AtomBombingDetector",
                [this](SHADOWSTRIKE_MESSAGE_TYPE msgType, const void* payload, size_t payloadSize) {
                    if (!m_initialized.load(std::memory_order_acquire)) return;

                    if (msgType == FilterMessageType_ThreadNotify) {
                        OnKernelThreadNotify(payload, payloadSize);
                    }
                }
            );

            SS_LOG_INFO(L"AtomBombing",
                L"Registered kernel handler for ThreadNotify events");

        } catch (const std::exception& e) {
            SS_LOG_WARN(L"AtomBombing",
                L"Failed to register kernel handlers: %S", e.what());
        }
    }

    /**
     * @brief Handle kernel thread creation notification.
     *
     * Remote thread creation events from the kernel driver are forwarded
     * into our APC analysis pipeline — remote thread creation is the
     * observable precursor to APC-based injection techniques including
     * AtomBombing. The kernel monitors PsSetCreateThreadNotifyRoutine
     * and flags cross-process thread creation.
     */
    void OnKernelThreadNotify(const void* data, size_t size) {
        if (data == nullptr || size < sizeof(SHADOWSTRIKE_THREAD_NOTIFICATION)) {
            return;
        }

        const auto* tn = static_cast<const SHADOWSTRIKE_THREAD_NOTIFICATION*>(data);

        // Only care about remote (cross-process) thread events
        if (!tn->IsRemote) return;

        // Self-exclusion
        const uint32_t selfPid = GetCurrentProcessId();
        if (tn->ProcessId == selfPid || tn->CreatorProcessId == selfPid) return;

        SS_LOG_DEBUG(L"AtomBombing",
            L"Kernel ThreadNotify: PID %u -> PID %u (TID %u, remote)",
            tn->CreatorProcessId, tn->ProcessId, tn->ThreadId);

        // Feed into our APC analysis pipeline. The start address is not
        // available from the basic thread notification, so apcRoutine = 0.
        // The cross-process nature alone is a risk signal for AtomBombing.
        OnAPCQueueImpl(
            tn->CreatorProcessId,
            tn->ProcessId,
            tn->ThreadId,
            0,  // apcRoutine unknown from kernel thread notify
            0, 0, 0
        );
    }

    void InitializeKnownSafeAtoms() {
        // Populate known safe system atoms (window classes, OLE/COM, etc.)
        // These are standard Windows RegisterClass atom names that should not
        // trigger false positives during atom table scanning.
        const std::array<std::wstring_view, 14> safeNames = {
            L"Button", L"ComboBox", L"Edit", L"ListBox",
            L"MDIClient", L"ScrollBar", L"Static",
            L"ComboLBox", L"DDEMLEvent", L"DDEMLMom",
            L"DDEMLAnsiClient", L"DDEMLUnicodeClient",
            L"IME", L"MSCTFIME UI"
        };

        // Acquire exclusive lock — every other reader of m_knownSafeAtoms
        // takes shared_lock(m_atomMutex); writing without the lock is a
        // documented data race even if logically only Initialize calls this.
        std::unique_lock lock(m_atomMutex);

        // Resolve actual atom values for known window class names
        for (const auto& name : safeNames) {
            ATOM a = GlobalFindAtomW(name.data());
            if (a != 0 && a >= AtomBombingConstants::MIN_GLOBAL_ATOM) {
                m_knownSafeAtoms.insert(static_cast<uint16_t>(a));
            }
        }
    }

    // ========================================================================
    // ATOM TABLE SCANNING
    // ========================================================================

    [[nodiscard]] AtomBombingScanResult ScanAtomTableImpl() {
        AtomBombingScanResult result{};
        const auto scanStart = steady_clock::now();
        const auto config = SnapshotConfig();

        try {
            result.scanTime = system_clock::now();
            result.systemWideScan = true;

            SS_LOG_INFO(L"AtomBombing", L"Starting atom table scan");

            // Enumerate all global atoms
            auto atoms = EnumerateAtomsImpl();
            result.totalAtomsAnalyzed = static_cast<uint32_t>(atoms.size());

            // Analyze each atom
            for (const auto& atom : atoms) {
                if (atom.suspicionLevel >= AtomSuspicion::MediumRisk) {
                    result.suspiciousAtomsFound++;
                    result.suspiciousAtoms.push_back(atom);
                }
            }

            // Check for recent suspicious APCs
            {
                std::shared_lock lock(m_apcMutex);
                result.apcsAnalyzed = static_cast<uint32_t>(m_recentApcs.size());
                result.suspiciousApcsFound = static_cast<uint32_t>(m_suspiciousApcs.size());
                result.suspiciousApcs = std::vector<APCEvent>(
                    m_suspiciousApcs.begin(),
                    m_suspiciousApcs.end()
                );
            }

            // Correlate events to detect attacks
            if (config.correlateAtomAndAPC) {
                result.detectedAttacks = CorrelateEventsImpl(config);
                result.attackDetected = !result.detectedAttacks.empty();

                if (result.attackDetected) {
                    for (const auto& attack : result.detectedAttacks) {
                        result.highestConfidence = std::max(result.highestConfidence, attack.confidence);
                        result.highestRiskScore = std::max(result.highestRiskScore, attack.riskScore);
                    }
                }
            }

            result.scanComplete = true;

            auto scanEnd = steady_clock::now();
            result.scanDurationMs = static_cast<uint32_t>(
                duration_cast<milliseconds>(scanEnd - scanStart).count()
            );

            m_stats.scansPerformed.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalScanTimeMs.fetch_add(result.scanDurationMs, std::memory_order_relaxed);

            SS_LOG_INFO(L"AtomBombing", L"Scan complete - %u atoms, %u suspicious, %u attacks, %u ms",
                result.totalAtomsAnalyzed, result.suspiciousAtomsFound,
                static_cast<uint32_t>(result.detectedAttacks.size()), result.scanDurationMs);

            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Scan exception: %S", e.what());
            result.scanError = StringUtils::ToWide(e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
    }

    [[nodiscard]] std::vector<AtomInfo> EnumerateAtomsImpl() {
        std::vector<AtomInfo> atoms;
        const auto config = SnapshotConfig();

        try {
            // Enumerate global atoms in range.
            // Use uint32_t to avoid overflow: uint16_t would wrap from 0xFFFF to 0,
            // creating an infinite loop since the condition <= 0xFFFF is always true.
            for (uint32_t atomVal = AtomBombingConstants::MIN_GLOBAL_ATOM;
                 atomVal <= AtomBombingConstants::MAX_GLOBAL_ATOM;
                 ++atomVal) {

                if (atoms.size() >= config.maxAtomsToAnalyze) {
                    break;
                }

                const uint16_t atomValue = static_cast<uint16_t>(atomVal);

                // Skip known-safe atoms
                {
                    std::shared_lock lock(m_atomMutex);
                    if (m_knownSafeAtoms.count(atomValue) > 0) {
                        continue;
                    }
                }

                auto atomInfo = AnalyzeAtomImpl(atomValue, config);
                if (atomInfo.contentLength > 0) {
                    atoms.push_back(std::move(atomInfo));
                    m_stats.atomsMonitored.fetch_add(1, std::memory_order_relaxed);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Enumeration exception: %S", e.what());
        }

        return atoms;
    }

    /**
     * @brief Analyze a single atom (public entry point — snapshots config).
     */
    [[nodiscard]] AtomInfo AnalyzeAtomImpl(uint16_t atomValue) {
        return AnalyzeAtomImpl(atomValue, SnapshotConfig());
    }

    /**
     * @brief Analyze a single atom using a caller-provided config snapshot.
     *
     * This overload is used in hot paths (e.g. EnumerateAtomsImpl) to
     * avoid re-acquiring the config lock on every iteration.
     */
    [[nodiscard]] AtomInfo AnalyzeAtomImpl(uint16_t atomValue,
                                           const AtomBombingConfig& config) {
        AtomInfo atom{};
        atom.atomValue = atomValue;
        atom.type = AtomType::GlobalAtom;

        try {
            // Get atom name
            wchar_t atomName[AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1]{};
            UINT nameLength = GlobalGetAtomNameW(
                static_cast<ATOM>(atomValue),
                atomName,
                AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1
            );

            if (nameLength > 0) {
                atomName[nameLength] = L'\0';  // Defensive: ensure null termination
                atom.atomName = atomName;
                atom.contentLength = nameLength;

                // Convert to bytes for analysis
                atom.rawContent.resize(nameLength * sizeof(wchar_t));
                std::memcpy(atom.rawContent.data(), atomName, atom.rawContent.size());

                // Analyze content
                if (config.analyzeEntropy) {
                    atom.entropy = CalculateEntropy(atom.rawContent);
                    atom.hasHighEntropy = (atom.entropy >= config.entropyThreshold);

                    if (atom.hasHighEntropy) {
                        m_stats.highEntropyAtomsDetected.fetch_add(1, std::memory_order_relaxed);
                        atom.suspicionReasons.push_back(
                            std::format(L"High entropy: {:.2f}", atom.entropy)
                        );
                    }
                }

                if (config.detectShellcodePatterns) {
                    atom.hasShellcodePatterns = HasShellcodePatterns(atom.rawContent);
                    if (atom.hasShellcodePatterns) {
                        m_stats.shellcodePatternsDetected.fetch_add(1, std::memory_order_relaxed);
                        atom.suspicionReasons.push_back(L"Shellcode patterns detected");
                    }
                }

                atom.hasNullBytes = HasNullBytes(atom.rawContent);

                // Check for suspicious API name strings in atom content
                CheckSuspiciousStrings(atom);

                // Calculate suspicion level
                atom.suspicionLevel = CalculateAtomSuspicion(atom, config);

                // Store in monitored atoms. Callbacks MUST be invoked OUTSIDE the data
                // lock to prevent deadlocks when user callbacks call back into the detector.
                bool shouldNotifyAtom = false;

                if (atom.suspicionLevel >= AtomSuspicion::LowRisk) {
                    std::unique_lock lock(m_atomMutex);
                    m_monitoredAtoms[atomValue] = atom;

                    if (atom.suspicionLevel >= AtomSuspicion::MediumRisk) {
                        m_suspiciousAtoms.push_back(atom);
                        if (m_suspiciousAtoms.size() > AtomBombingConstants::MAX_ATOM_EVENTS) {
                            m_suspiciousAtoms.pop_front();
                        }
                        m_stats.suspiciousAtomsDetected.fetch_add(1, std::memory_order_relaxed);
                        shouldNotifyAtom = true;
                    }
                }

                // Invoke callbacks OUTSIDE the data lock
                if (shouldNotifyAtom) {
                    InvokeAtomCallbacks(atom);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Atom analysis exception: %S", e.what());
        }

        return atom;
    }

    /**
     * @brief Check for suspicious API-related strings embedded in atom content.
     */
    void CheckSuspiciousStrings(AtomInfo& atom) const noexcept {
        static constexpr std::array<std::wstring_view, 8> suspiciousTokens = {
            L"VirtualAlloc", L"VirtualProtect", L"LoadLibrary",
            L"GetProcAddress", L"NtProtect", L"WriteProcessMemory",
            L"CreateRemoteThread", L"NtQueueApcThread"
        };

        for (const auto& token : suspiciousTokens) {
            if (atom.atomName.find(token) != std::wstring::npos) {
                atom.hasSuspiciousStrings = true;
                atom.suspicionReasons.push_back(
                    std::format(L"Contains suspicious API name: {}", token));
                break;
            }
        }
    }

    [[nodiscard]] AtomSuspicion CalculateAtomSuspicion(
        const AtomInfo& atom,
        const AtomBombingConfig& config) const noexcept
    {
        uint32_t score = 0;

        if (atom.hasHighEntropy) score += 25;
        if (atom.hasShellcodePatterns) score += 40;
        if (atom.hasSuspiciousStrings) score += 20;
        if (atom.contentLength >= config.suspiciousAtomSizeThreshold) score += 15;
        if (atom.hasNullBytes && atom.contentLength > 16) score += 10;

        if (score >= 60) return AtomSuspicion::Critical;
        if (score >= 40) return AtomSuspicion::HighRisk;
        if (score >= 20) return AtomSuspicion::MediumRisk;
        if (score > 0) return AtomSuspicion::LowRisk;
        return AtomSuspicion::Normal;
    }

    // ========================================================================
    // APC MONITORING
    // ========================================================================

    [[nodiscard]] APCEvent AnalyzeAPCImpl(
        uint32_t sourcePid,
        uint32_t targetPid,
        uint32_t targetTid,
        uintptr_t apcRoutine
    ) {
        APCEvent event{};
        event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
        event.timestamp = system_clock::now();
        const auto config = SnapshotConfig();

        try {
            event.sourcePid = sourcePid;
            event.targetPid = targetPid;
            event.targetTid = targetTid;
            event.apcRoutine = apcRoutine;

            event.isCrossProcess = (sourcePid != targetPid);
            event.targetsSelf = (sourcePid == targetPid);

            // Check process exclusions
            if (IsProcessExcluded(sourcePid, config) ||
                IsProcessExcluded(targetPid, config)) {
                return event;
            }

            // Get source process info using RAII handle
            {
                ScopedHandle hSourceProcess(
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, sourcePid));
                if (hSourceProcess) {
                    wchar_t processPath[MAX_PATH]{};
                    if (GetModuleFileNameExW(hSourceProcess.get(), nullptr, processPath, MAX_PATH)) {
                        event.sourceProcessPath = processPath;
                        event.sourceProcessName = fs::path(processPath).filename().wstring();
                    }
                }
            }

            // Get target process info and resolve APC routine module using RAII handle
            {
                ScopedHandle hTargetProcess(
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid));
                if (hTargetProcess) {
                    wchar_t processPath[MAX_PATH]{};
                    if (GetModuleFileNameExW(hTargetProcess.get(), nullptr, processPath, MAX_PATH)) {
                        event.targetProcessPath = processPath;
                        event.targetProcessName = fs::path(processPath).filename().wstring();
                    }

                    // Resolve APC routine's containing module in the TARGET process
                    // (the APC executes in the target's address space)
                    event.moduleName = GetModuleNameFromAddress(hTargetProcess.get(), apcRoutine);
                }
            }

            // Check if APC targets atom-related functions by resolving exports
            event.targetsAtomFunction = TargetsAtomRetrievalImpl(apcRoutine, targetPid);
            if (event.targetsAtomFunction) {
                event.targetType = APCTargetType::AtomGetNameA;
            }

            // Risk assessment
            uint32_t riskScore = 0;
            if (event.isCrossProcess) {
                riskScore += 30;
                event.suspicionReasons.push_back(L"Cross-process APC");
            }
            if (event.targetsAtomFunction) {
                riskScore += 50;
                event.suspicionReasons.push_back(L"Targets GlobalGetAtomName");
            }
            if (event.moduleName == L"ntdll.dll") {
                riskScore += 10;
            }

            event.riskScore = riskScore;
            event.isSuspicious = (riskScore >= 40);

            // Store event - callbacks OUTSIDE the lock
            bool shouldNotifyAPC = false;
            {
                std::unique_lock lock(m_apcMutex);
                m_recentApcs.push_back(event);
                if (m_recentApcs.size() > AtomBombingConstants::MAX_APC_EVENTS) {
                    m_recentApcs.pop_front();
                }

                if (event.isSuspicious) {
                    m_suspiciousApcs.push_back(event);
                    if (m_suspiciousApcs.size() > AtomBombingConstants::MAX_APC_EVENTS) {
                        m_suspiciousApcs.pop_front();
                    }
                    m_stats.suspiciousApcsDetected.fetch_add(1, std::memory_order_relaxed);
                    shouldNotifyAPC = true;
                }
            }

            // Invoke callbacks OUTSIDE the data lock
            if (shouldNotifyAPC) {
                InvokeAPCCallbacks(event);
            }

            m_stats.apcsMonitored.fetch_add(1, std::memory_order_relaxed);
            if (event.isCrossProcess) {
                m_stats.crossProcessApcs.fetch_add(1, std::memory_order_relaxed);
            }
            if (event.targetsAtomFunction) {
                m_stats.atomTargetingApcs.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"APC analysis exception: %S", e.what());
        }

        return event;
    }

    /**
     * @brief Check whether an APC routine targets atom retrieval APIs.
     *
     * Uses cached addresses resolved once during initialization.  No
     * process handle is needed because kernel32/KernelBase/ntdll are
     * mapped at identical virtual addresses in all processes (per-boot
     * ASLR, not per-process).
     */
    [[nodiscard]] bool TargetsAtomRetrievalImpl(uintptr_t apcRoutine,
                                                [[maybe_unused]] uint32_t pid) const noexcept {
        if (!m_cachedApiAddrs.resolved || apcRoutine == 0) return false;

        const auto& a = m_cachedApiAddrs;
        return (a.GlobalGetAtomNameA  != 0 && apcRoutine == a.GlobalGetAtomNameA)  ||
               (a.GlobalGetAtomNameW  != 0 && apcRoutine == a.GlobalGetAtomNameW)  ||
               (a.GlobalGetAtomNameA_KB != 0 && apcRoutine == a.GlobalGetAtomNameA_KB) ||
               (a.GlobalGetAtomNameW_KB != 0 && apcRoutine == a.GlobalGetAtomNameW_KB) ||
               (a.NtAddAtom  != 0 && apcRoutine == a.NtAddAtom)  ||
               (a.NtFindAtom != 0 && apcRoutine == a.NtFindAtom);
    }

    /**
     * @brief Check if a process is excluded from monitoring.
     *
     * Accepts a config snapshot to avoid re-acquiring the config lock.
     */
    [[nodiscard]] bool IsProcessExcluded(uint32_t pid,
                                          const AtomBombingConfig& config) const {
        if (config.excludedProcesses.empty()) return false;

        ScopedHandle hProcess(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProcess) return false;

        wchar_t processPath[MAX_PATH]{};
        if (!GetModuleFileNameExW(hProcess.get(), nullptr, processPath, MAX_PATH)) {
            return false;
        }

        std::wstring processName = fs::path(processPath).filename().wstring();
        for (const auto& excluded : config.excludedProcesses) {
            if (StringUtils::IEquals(processName, excluded)) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // ATTACK CORRELATION
    // ========================================================================

    [[nodiscard]] std::vector<AtomBombingAttack> CorrelateEventsImpl() {
        return CorrelateEventsImpl(SnapshotConfig());
    }

    [[nodiscard]] std::vector<AtomBombingAttack> CorrelateEventsImpl(
        const AtomBombingConfig& config)
    {
        std::vector<AtomBombingAttack> attacks;

        try {
            // Collect correlated attacks under data locks, but do NOT invoke
            // callbacks while any data lock is held.
            {
                std::shared_lock atomLock(m_atomMutex);
                std::shared_lock apcLock(m_apcMutex);

                // For each suspicious atom, look for correlated APCs
                for (const auto& atom : m_suspiciousAtoms) {
                    for (const auto& apc : m_suspiciousApcs) {
                        // Check temporal correlation
                        auto timeDiff = duration_cast<milliseconds>(
                            apc.timestamp - atom.createTime
                        );

                        if (std::abs(timeDiff.count()) <= static_cast<int64_t>(config.apcCorrelationWindowMs)) {
                            // Potential attack correlation
                            if (apc.targetsAtomFunction && apc.isCrossProcess) {
                                AtomBombingAttack attack = BuildAttackFromCorrelation(atom, apc, config);
                                attacks.push_back(std::move(attack));
                            }
                        }
                    }

                    // For high-risk atoms (shellcode + high entropy), also correlate
                    // with cross-process events from m_recentApcs. Kernel-originated
                    // events lack apcRoutine, but cross-process activity near a
                    // shellcode-bearing atom is a strong signal.
                    if (atom.suspicionLevel >= AtomSuspicion::HighRisk) {
                        for (const auto& apc : m_recentApcs) {
                            if (!apc.isCrossProcess || apc.isSuspicious) continue;

                            auto timeDiff = duration_cast<milliseconds>(
                                apc.timestamp - atom.createTime
                            );
                            if (std::abs(timeDiff.count()) <= static_cast<int64_t>(config.apcCorrelationWindowMs)) {
                                AtomBombingAttack attack = BuildAttackFromCorrelation(atom, apc, config);
                                attack.confidence = DetectionConfidence::Medium;
                                attack.detectionReasons.push_back(
                                    L"Cross-process activity near shellcode-bearing atom (kernel event)");
                                attacks.push_back(std::move(attack));
                            }
                        }
                    }
                }
            } // Release atom and apc locks before taking attack lock

            // Store detected attacks under attack lock
            if (!attacks.empty()) {
                {
                    std::unique_lock attackLock(m_attackMutex);
                    for (const auto& attack : attacks) {
                        m_detectedAttacks.push_back(attack);
                        if (m_detectedAttacks.size() > AtomBombingConstants::MAX_APC_EVENTS) {
                            m_detectedAttacks.pop_front();
                        }

                        m_stats.attacksDetected.fetch_add(1, std::memory_order_relaxed);

                        // Update confidence statistics
                        switch (attack.confidence) {
                            case DetectionConfidence::Low:
                                m_stats.lowConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            case DetectionConfidence::Medium:
                                m_stats.mediumConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            case DetectionConfidence::High:
                                m_stats.highConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            case DetectionConfidence::Confirmed:
                                m_stats.confirmedAttacks.fetch_add(1, std::memory_order_relaxed);
                                break;
                            default:
                                break;
                        }
                    }
                } // Release attack lock before invoking callbacks

                // Invoke attack callbacks OUTSIDE all data locks
                for (const auto& attack : attacks) {
                    InvokeAttackCallbacks(attack);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Correlation exception: %S", e.what());
        }

        return attacks;
    }

    [[nodiscard]] AtomBombingAttack BuildAttackFromCorrelation(
        const AtomInfo& atom,
        const APCEvent& apc,
        const AtomBombingConfig& config
    ) {
        AtomBombingAttack attack{};
        attack.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
        attack.detectionTime = system_clock::now();

        attack.attackerPid = apc.sourcePid;
        attack.attackerProcessName = apc.sourceProcessName;
        attack.attackerProcessPath = apc.sourceProcessPath;

        attack.victimPid = apc.targetPid;
        attack.victimProcessName = apc.targetProcessName;
        attack.victimProcessPath = apc.targetProcessPath;
        attack.victimTid = apc.targetTid;

        attack.maliciousAtom = atom;
        attack.relatedApcs.push_back(apc);

        attack.atomWriteDetected = true;
        attack.apcQueueDetected = true;
        attack.atomRetrievalDetected = apc.targetsAtomFunction;

        // Calculate confidence
        uint32_t confidenceScore = 0;
        if (atom.hasShellcodePatterns) confidenceScore += 40;
        if (atom.hasHighEntropy) confidenceScore += 20;
        if (apc.targetsAtomFunction) confidenceScore += 30;
        if (apc.isCrossProcess) confidenceScore += 10;

        if (confidenceScore >= 80) {
            attack.confidence = DetectionConfidence::Confirmed;
        } else if (confidenceScore >= 60) {
            attack.confidence = DetectionConfidence::High;
        } else if (confidenceScore >= 40) {
            attack.confidence = DetectionConfidence::Medium;
        } else {
            attack.confidence = DetectionConfidence::Low;
        }

        attack.riskScore = std::min(confidenceScore, 100u);

        attack.detectionReasons.push_back(L"Suspicious atom + cross-process APC correlation");
        if (atom.hasShellcodePatterns) {
            attack.detectionReasons.push_back(L"Shellcode patterns in atom");
        }
        if (atom.hasHighEntropy) {
            attack.detectionReasons.push_back(L"High entropy atom content");
        }

        attack.mitreAttackId = "T1055.009";  // Process Injection: AtomBombing

        // Extract payload if configured
        if (config.extractPayloads && !atom.rawContent.empty()) {
            attack.payloadExtracted = true;
            attack.payload = atom.rawContent;

            // Compute SHA-256 of payload using streaming Hasher API
            std::vector<uint8_t> hashResult;
            if (HashUtils::Compute(HashUtils::Algorithm::SHA256,
                                   atom.rawContent.data(), atom.rawContent.size(),
                                   hashResult)) {
                const size_t copyLen = std::min(hashResult.size(), attack.payloadHash.size());
                std::memcpy(attack.payloadHash.data(), hashResult.data(), copyLen);
            }

            attack.payloadDescription = std::format(L"Atom {} content ({} bytes)",
                atom.atomValue, atom.rawContent.size());
            m_stats.payloadsExtracted.fetch_add(1, std::memory_order_relaxed);
        }

        SS_LOG_WARN(L"AtomBombing",
            L"Attack detected - PID %u -> PID %u, Confidence: %u, Risk: %u",
            attack.attackerPid, attack.victimPid,
            static_cast<unsigned>(attack.confidence), attack.riskScore);

        return attack;
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool StartMonitoringImpl() {
        if (m_monitoring.exchange(true, std::memory_order_acquire)) {
            SS_LOG_WARN(L"AtomBombing", L"Already monitoring");
            return true;
        }

        try {
            SS_LOG_INFO(L"AtomBombing", L"Starting real-time monitoring");

            // Clean up any completed threads from prior start/stop cycles
            m_workerThreads.clear();

            // Start monitoring thread
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                MonitoringThread(stoken);
            });

            SS_LOG_INFO(L"AtomBombing", L"Monitoring started");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"Start monitoring exception: %S", e.what());
            m_monitoring.store(false, std::memory_order_release);
            return false;
        }
    }

    void StopMonitoringImpl() {
        if (!m_monitoring.exchange(false, std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"AtomBombing", L"Stopping monitoring");

        // Stop worker threads
        m_workerThreads.clear();

        SS_LOG_INFO(L"AtomBombing", L"Monitoring stopped");
    }

    void MonitoringThread(std::stop_token stoken) {
        SS_LOG_DEBUG(L"AtomBombing", L"Monitoring thread started");

        while (!stoken.stop_requested()) {
            try {
                const auto config = SnapshotConfig();

                // Periodic scanning (ScanAtomTableImpl already calls CorrelateEventsImpl
                // when correlateAtomAndAPC is enabled, so no separate correlation call needed).
                // Returns are intentionally discarded here — results are surfaced through
                // statistics counters and registered callbacks invoked from inside these calls.
                if (config.enableOnDemandScanning) {
                    (void)ScanAtomTableImpl();
                } else if (config.correlateAtomAndAPC) {
                    (void)CorrelateEventsImpl(config);
                }

                // Use stop_token-aware sleep to enable clean shutdown
                for (int i = 0; i < 50 && !stoken.stop_requested(); ++i) {
                    std::this_thread::sleep_for(milliseconds(100));
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AtomBombing", L"Monitoring thread exception: %S", e.what());
            }
        }

        SS_LOG_DEBUG(L"AtomBombing", L"Monitoring thread stopped");
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    void OnAtomCreateImpl(
        uint16_t atomValue,
        uint32_t creatorPid,
        const std::wstring& atomName
    ) {
        const auto config = SnapshotConfig();
        if (!config.monitorAtomTable) return;

        // Check excluded atoms
        for (const auto& excludedAtom : config.excludedAtoms) {
            if (excludedAtom == atomValue) return;
        }

        try {
            m_stats.atomCreations.fetch_add(1, std::memory_order_relaxed);

            // Analyze the new atom
            auto atom = AnalyzeAtomImpl(atomValue);
            atom.creatorPid = creatorPid;
            atom.createTime = system_clock::now();

            // Store creation context using RAII handle
            {
                ScopedHandle hProcess(
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, creatorPid));
                if (hProcess) {
                    wchar_t processPath[MAX_PATH]{};
                    if (GetModuleFileNameExW(hProcess.get(), nullptr, processPath, MAX_PATH)) {
                        atom.creatorProcessName = fs::path(processPath).filename().wstring();
                    }
                }
            }

            SS_LOG_DEBUG(L"AtomBombing",
                L"Atom 0x%04X created by PID %u (%ls), Suspicion: %d",
                static_cast<unsigned>(atomValue), creatorPid,
                SanitizeForLog(atom.creatorProcessName).c_str(),
                static_cast<int>(atom.suspicionLevel));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"OnAtomCreate exception: %S", e.what());
        }
    }

    void OnAtomDeleteImpl(uint16_t atomValue, uint32_t deleterPid) {
        const auto config = SnapshotConfig();
        if (!config.monitorAtomTable) return;

        m_stats.atomDeletions.fetch_add(1, std::memory_order_relaxed);

        std::unique_lock lock(m_atomMutex);
        m_monitoredAtoms.erase(atomValue);
    }

    void OnAPCQueueImpl(
        uint32_t sourcePid,
        uint32_t targetPid,
        uint32_t targetTid,
        uintptr_t apcRoutine,
        uintptr_t arg1,
        uintptr_t arg2,
        uintptr_t arg3
    ) {
        const auto config = SnapshotConfig();
        if (!config.monitorAPCs) return;

        try {
            auto apcEvent = AnalyzeAPCImpl(sourcePid, targetPid, targetTid, apcRoutine);
            apcEvent.apcArgument1 = arg1;
            apcEvent.apcArgument2 = arg2;
            apcEvent.apcArgument3 = arg3;

            // Blocking decision: if the APC is suspicious and blocking is enabled,
            // signal the kernel driver to deny the APC via the registered attack callbacks.
            // The kernel bridge (if present) handles the actual APC cancellation;
            // user-mode cannot retroactively cancel a queued APC.
            if (config.blockSuspiciousApcs && apcEvent.isSuspicious) {
                if (config.mode == MonitoringMode::Active ||
                    config.mode == MonitoringMode::Aggressive) {

                    SS_LOG_WARN(L"AtomBombing",
                        L"Suspicious APC blocked: PID %u -> PID %u (TID %u), routine 0x%llX",
                        sourcePid, targetPid, targetTid,
                        static_cast<unsigned long long>(apcRoutine));
                    m_stats.attacksBlocked.fetch_add(1, std::memory_order_relaxed);

                    // Notify attack callbacks so the kernel bridge or BehaviorBlocker
                    // can enforce the block at the kernel level
                    AtomBombingAttack blockEvent{};
                    blockEvent.attackId = m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
                    blockEvent.detectionTime = system_clock::now();
                    blockEvent.attackerPid = sourcePid;
                    blockEvent.attackerProcessName = apcEvent.sourceProcessName;
                    blockEvent.attackerProcessPath = apcEvent.sourceProcessPath;
                    blockEvent.victimPid = targetPid;
                    blockEvent.victimProcessName = apcEvent.targetProcessName;
                    blockEvent.victimProcessPath = apcEvent.targetProcessPath;
                    blockEvent.victimTid = targetTid;
                    blockEvent.apcQueueDetected = true;
                    blockEvent.relatedApcs.push_back(apcEvent);
                    blockEvent.confidence = DetectionConfidence::High;
                    blockEvent.riskScore = apcEvent.riskScore;
                    blockEvent.wasBlocked = true;
                    blockEvent.mitreAttackId = "T1055.009";
                    blockEvent.mitigationAction = L"APC blocked via kernel callback";

                    InvokeAttackCallbacks(blockEvent);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"AtomBombing", L"OnAPCQueue exception: %S", e.what());
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeAttackCallbacks(const AtomBombingAttack& attack) {
        // Snapshot the callback set under shared lock, then release the lock
        // before invoking. This prevents deadlock when a callback re-enters
        // RegisterAttackCallback / UnregisterCallback (which take a unique
        // lock on the same shared_mutex; recursive shared->unique acquisition
        // is undefined behavior on std::shared_mutex).
        std::vector<AttackDetectedCallback> snapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_attackCallbacks.size());
            for (const auto& [id, cb] : m_attackCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(attack);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AtomBombing", L"Attack callback exception: %S", e.what());
            } catch (...) {
                SS_LOG_ERROR(L"AtomBombing", L"Attack callback non-std exception");
            }
        }
    }

    void InvokeAtomCallbacks(const AtomInfo& atom) {
        std::vector<SuspiciousAtomCallback> snapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_atomCallbacks.size());
            for (const auto& [id, cb] : m_atomCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(atom);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AtomBombing", L"Atom callback exception: %S", e.what());
            } catch (...) {
                SS_LOG_ERROR(L"AtomBombing", L"Atom callback non-std exception");
            }
        }
    }

    void InvokeAPCCallbacks(const APCEvent& apc) {
        std::vector<SuspiciousAPCCallback> snapshot;
        {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_apcCallbacks.size());
            for (const auto& [id, cb] : m_apcCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(apc);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AtomBombing", L"APC callback exception: %S", e.what());
            } catch (...) {
                SS_LOG_ERROR(L"AtomBombing", L"APC callback non-std exception");
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

AtomBombingDetector& AtomBombingDetector::Instance() {
    static AtomBombingDetector instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AtomBombingDetector::AtomBombingDetector()
    : m_impl(std::make_unique<Impl>())
{
    SS_LOG_INFO(L"AtomBombing", L"Constructor called");
}

AtomBombingDetector::~AtomBombingDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"AtomBombing", L"Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool AtomBombingDetector::Initialize(const AtomBombingConfig& config) {
    if (!m_impl) {
        SS_LOG_ERROR(L"AtomBombing", L"Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void AtomBombingDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool AtomBombingDetector::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

bool AtomBombingDetector::UpdateConfig(const AtomBombingConfig& config) {
    if (!m_impl) return false;

    // Validate configuration before applying. Reject obviously-malformed
    // values rather than letting them silently destabilize hot paths
    // (e.g. zero correlation window disables correlation entirely;
    //  unbounded maxAtomsToAnalyze can stall a scan for minutes).
    AtomBombingConfig sanitized = config;

    constexpr uint32_t kMinCorrelationWindowMs = 100;
    constexpr uint32_t kMaxCorrelationWindowMs = 600'000;   // 10 minutes
    if (sanitized.apcCorrelationWindowMs < kMinCorrelationWindowMs) {
        SS_LOG_WARN(L"AtomBombing",
            L"UpdateConfig: apcCorrelationWindowMs %u below floor; clamping to %u",
            sanitized.apcCorrelationWindowMs, kMinCorrelationWindowMs);
        sanitized.apcCorrelationWindowMs = kMinCorrelationWindowMs;
    } else if (sanitized.apcCorrelationWindowMs > kMaxCorrelationWindowMs) {
        SS_LOG_WARN(L"AtomBombing",
            L"UpdateConfig: apcCorrelationWindowMs %u above ceiling; clamping to %u",
            sanitized.apcCorrelationWindowMs, kMaxCorrelationWindowMs);
        sanitized.apcCorrelationWindowMs = kMaxCorrelationWindowMs;
    }

    constexpr uint32_t kMinScanTimeoutMs = 100;
    constexpr uint32_t kMaxScanTimeoutMs = 300'000;         // 5 minutes
    if (sanitized.scanTimeoutMs < kMinScanTimeoutMs) {
        sanitized.scanTimeoutMs = kMinScanTimeoutMs;
    } else if (sanitized.scanTimeoutMs > kMaxScanTimeoutMs) {
        sanitized.scanTimeoutMs = kMaxScanTimeoutMs;
    }

    constexpr size_t kMaxAtomsCeiling = 0x10000;            // > MAX_GLOBAL_ATOM range
    if (sanitized.maxAtomsToAnalyze == 0 ||
        sanitized.maxAtomsToAnalyze > kMaxAtomsCeiling) {
        sanitized.maxAtomsToAnalyze = AtomBombingConstants::MAX_ATOMS_TO_MONITOR;
    }

    // Cap exclusion list size to prevent O(N) blowup on hot paths.
    constexpr size_t kMaxExcludedProcesses = 1024;
    if (sanitized.excludedProcesses.size() > kMaxExcludedProcesses) {
        SS_LOG_WARN(L"AtomBombing",
            L"UpdateConfig: excludedProcesses (%zu) exceeds cap; truncating to %zu",
            sanitized.excludedProcesses.size(), kMaxExcludedProcesses);
        sanitized.excludedProcesses.resize(kMaxExcludedProcesses);
    }
    constexpr size_t kMaxExcludedAtoms = 4096;
    if (sanitized.excludedAtoms.size() > kMaxExcludedAtoms) {
        SS_LOG_WARN(L"AtomBombing",
            L"UpdateConfig: excludedAtoms (%zu) exceeds cap; truncating to %zu",
            sanitized.excludedAtoms.size(), kMaxExcludedAtoms);
        sanitized.excludedAtoms.resize(kMaxExcludedAtoms);
    }

    // Clamp entropy threshold to a sane Shannon range [0.0, 8.0].
    if (!(sanitized.entropyThreshold >= 0.0) ||
        !(sanitized.entropyThreshold <= 8.0)) {
        sanitized.entropyThreshold = AtomBombingConstants::HIGH_ENTROPY_THRESHOLD;
    }

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = std::move(sanitized);

    SS_LOG_INFO(L"AtomBombing", L"Configuration updated");
    return true;
}

[[nodiscard]] AtomBombingConfig AtomBombingDetector::GetConfig() const {
    if (!m_impl) return AtomBombingConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// ATOM TABLE SCANNING
// ============================================================================

[[nodiscard]] AtomBombingScanResult AtomBombingDetector::ScanAtomTable() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return AtomBombingScanResult{};
    }

    return m_impl->ScanAtomTableImpl();
}

[[nodiscard]] AtomInfo AtomBombingDetector::AnalyzeAtom(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return AtomInfo{};
    }

    return m_impl->AnalyzeAtomImpl(atomValue);
}

[[nodiscard]] std::vector<AtomInfo> AtomBombingDetector::EnumerateAtoms() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return {};
    }

    return m_impl->EnumerateAtomsImpl();
}

[[nodiscard]] std::vector<AtomInfo> AtomBombingDetector::FindSuspiciousAtoms() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return {};
    }

    std::shared_lock lock(m_impl->m_atomMutex);
    return std::vector<AtomInfo>(m_impl->m_suspiciousAtoms.begin(),
                                  m_impl->m_suspiciousAtoms.end());
}

[[nodiscard]] bool AtomBombingDetector::ContainsShellcode(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    auto atom = m_impl->AnalyzeAtomImpl(atomValue);
    return atom.hasShellcodePatterns;
}

[[nodiscard]] double AtomBombingDetector::GetAtomEntropy(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return 0.0;
    }

    auto atom = m_impl->AnalyzeAtomImpl(atomValue);
    return atom.entropy;
}

// ============================================================================
// APC MONITORING
// ============================================================================

[[nodiscard]] bool AtomBombingDetector::CheckAPC(uint32_t targetPid, uintptr_t apcRoutine) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->TargetsAtomRetrievalImpl(apcRoutine, targetPid);
}

[[nodiscard]] APCEvent AtomBombingDetector::AnalyzeAPC(
    uint32_t sourcePid,
    uint32_t targetPid,
    uint32_t targetTid,
    uintptr_t apcRoutine
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return APCEvent{};
    }

    return m_impl->AnalyzeAPCImpl(sourcePid, targetPid, targetTid, apcRoutine);
}

[[nodiscard]] std::vector<APCEvent> AtomBombingDetector::GetSuspiciousAPCs() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_apcMutex);
    return std::vector<APCEvent>(m_impl->m_suspiciousApcs.begin(),
                                  m_impl->m_suspiciousApcs.end());
}

[[nodiscard]] bool AtomBombingDetector::TargetsAtomRetrieval(uintptr_t apcRoutine, uint32_t pid) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->TargetsAtomRetrievalImpl(apcRoutine, pid);
}

// ============================================================================
// ATTACK CORRELATION
// ============================================================================

[[nodiscard]] std::vector<AtomBombingAttack> AtomBombingDetector::CorrelateEvents() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return {};
    }

    return m_impl->CorrelateEventsImpl();
}

[[nodiscard]] std::optional<AtomBombingAttack> AtomBombingDetector::DetectAttackChain(
    uint32_t victimPid
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    auto attacks = m_impl->CorrelateEventsImpl();
    for (const auto& attack : attacks) {
        if (attack.victimPid == victimPid) {
            return attack;
        }
    }

    return std::nullopt;
}

[[nodiscard]] AtomBombingScanResult AtomBombingDetector::ScanProcess(uint32_t pid) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return AtomBombingScanResult{};
    }

    // Process-specific scan
    AtomBombingScanResult result{};
    result.scanTime = system_clock::now();
    result.systemWideScan = false;
    result.targetPid = pid;

    // Check for attack chain involving this process
    auto attack = DetectAttackChain(pid);
    if (attack.has_value()) {
        result.attackDetected = true;
        result.detectedAttacks.push_back(attack.value());
        result.highestConfidence = attack->confidence;
        result.highestRiskScore = attack->riskScore;
    }

    result.scanComplete = true;
    return result;
}

// ============================================================================
// REAL-TIME MONITORING
// ============================================================================

bool AtomBombingDetector::StartMonitoring() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"AtomBombing", L"Not initialized");
        return false;
    }

    return m_impl->StartMonitoringImpl();
}

void AtomBombingDetector::StopMonitoring() {
    if (m_impl) {
        m_impl->StopMonitoringImpl();
    }
}

[[nodiscard]] bool AtomBombingDetector::IsMonitoring() const noexcept {
    return m_impl && m_impl->m_monitoring.load(std::memory_order_acquire);
}

void AtomBombingDetector::SetMonitoringMode(MonitoringMode mode) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config.mode = mode;

    SS_LOG_INFO(L"AtomBombing", L"Monitoring mode set to %d", static_cast<int>(mode));
}

[[nodiscard]] MonitoringMode AtomBombingDetector::GetMonitoringMode() const noexcept {
    if (!m_impl) return MonitoringMode::Disabled;

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config.mode;
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

void AtomBombingDetector::OnAtomCreate(
    uint16_t atomValue,
    uint32_t creatorPid,
    const std::wstring& atomName
) {
    if (m_impl) {
        m_impl->OnAtomCreateImpl(atomValue, creatorPid, atomName);
    }
}

void AtomBombingDetector::OnAtomDelete(uint16_t atomValue, uint32_t deleterPid) {
    if (m_impl) {
        m_impl->OnAtomDeleteImpl(atomValue, deleterPid);
    }
}

void AtomBombingDetector::OnAPCQueue(
    uint32_t sourcePid,
    uint32_t targetPid,
    uint32_t targetTid,
    uintptr_t apcRoutine,
    uintptr_t arg1,
    uintptr_t arg2,
    uintptr_t arg3
) {
    if (m_impl) {
        m_impl->OnAPCQueueImpl(sourcePid, targetPid, targetTid, apcRoutine, arg1, arg2, arg3);
    }
}

// ============================================================================
// RESPONSE ACTIONS
// ============================================================================

bool AtomBombingDetector::BlockAPC(const APCEvent& apc) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    SS_LOG_INFO(L"AtomBombing",
        L"Blocking APC from PID %u to PID %u (TID %u)",
        apc.sourcePid, apc.targetPid, apc.targetTid);

    // Signal the kernel driver via attack callbacks. The kernel bridge component
    // (PhantomSensor) handles actual APC cancellation via its pre-operation callback.
    // User-mode cannot directly cancel a queued APC; this is a policy notification.
    AtomBombingAttack blockEvent{};
    blockEvent.attackId = m_impl->m_nextAttackId.fetch_add(1, std::memory_order_relaxed);
    blockEvent.detectionTime = system_clock::now();
    blockEvent.attackerPid = apc.sourcePid;
    blockEvent.attackerProcessName = apc.sourceProcessName;
    blockEvent.victimPid = apc.targetPid;
    blockEvent.victimProcessName = apc.targetProcessName;
    blockEvent.victimTid = apc.targetTid;
    blockEvent.apcQueueDetected = true;
    blockEvent.relatedApcs.push_back(apc);
    blockEvent.confidence = DetectionConfidence::High;
    blockEvent.riskScore = apc.riskScore;
    blockEvent.wasBlocked = true;
    blockEvent.mitreAttackId = "T1055.009";
    blockEvent.mitigationAction = L"APC blocked via detector policy";

    m_impl->InvokeAttackCallbacks(blockEvent);
    m_impl->m_stats.attacksBlocked.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool AtomBombingDetector::RemoveMaliciousAtom(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    // Reject atoms outside the global atom-table range. Local atoms and
    // sentinel values (0, 0x0001..0xBFFF) cannot be removed via
    // GlobalDeleteAtom and would only burn 256 syscall iterations.
    if (atomValue < AtomBombingConstants::MIN_GLOBAL_ATOM) {
        SS_LOG_WARN(L"AtomBombing",
            L"RemoveMaliciousAtom: atom 0x%04X outside global range; refusing",
            static_cast<unsigned>(atomValue));
        return false;
    }

    try {
        // GlobalDeleteAtom returns 0 on success, the atom value on failure.
        // Atoms are reference-counted; call repeatedly until fully removed.
        constexpr int maxAttempts = 256;  // Cap to prevent infinite loop if atom is pinned
        bool deleted = false;

        for (int attempt = 0; attempt < maxAttempts; ++attempt) {
            SetLastError(ERROR_SUCCESS);
            ATOM remaining = GlobalDeleteAtom(static_cast<ATOM>(atomValue));
            if (remaining == 0) {
                deleted = true;
                break;
            }
            // If the atom is not registered, GlobalDeleteAtom returns the atom
            // value and sets ERROR_INVALID_HANDLE — bail immediately rather
            // than spinning the cap.
            const DWORD lastErr = GetLastError();
            if (lastErr == ERROR_INVALID_HANDLE) {
                SS_LOG_DEBUG(L"AtomBombing",
                    L"RemoveMaliciousAtom: atom 0x%04X not registered",
                    static_cast<unsigned>(atomValue));
                deleted = true;
                break;
            }
            // Atom still has references - try again
        }

        if (deleted) {
            SS_LOG_INFO(L"AtomBombing", L"Removed malicious atom 0x%04X",
                static_cast<unsigned>(atomValue));

            // Remove from monitored atoms
            std::unique_lock lock(m_impl->m_atomMutex);
            m_impl->m_monitoredAtoms.erase(atomValue);

            return true;
        } else {
            DWORD error = GetLastError();
            SS_LOG_ERROR(L"AtomBombing",
                L"Failed to fully delete atom 0x%04X: error %u",
                static_cast<unsigned>(atomValue), error);
            return false;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AtomBombing", L"RemoveMaliciousAtom exception: %S", e.what());
        return false;
    }
}

bool AtomBombingDetector::TerminateAttacker(const AtomBombingAttack& attack) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    {
        std::shared_lock lock(m_impl->m_configMutex);
        if (!m_impl->m_config.terminateAttacker) {
            SS_LOG_WARN(L"AtomBombing", L"Termination disabled in config");
            return false;
        }
    }

    try {
        ScopedHandle hProcess(OpenProcess(PROCESS_TERMINATE, FALSE, attack.attackerPid));
        if (hProcess) {
            if (TerminateProcess(hProcess.get(), 1)) {
                SS_LOG_WARN(L"AtomBombing",
                    L"Terminated attacker process PID %u (%ls)",
                    attack.attackerPid,
                    SanitizeForLog(attack.attackerProcessName).c_str());
                return true;
            }
        }

        DWORD error = GetLastError();
        SS_LOG_ERROR(L"AtomBombing",
            L"Failed to terminate attacker PID %u: error %u",
            attack.attackerPid, error);
        return false;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"AtomBombing", L"TerminateAttacker exception: %S", e.what());
        return false;
    }
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t AtomBombingDetector::RegisterAttackCallback(AttackDetectedCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_attackCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"AtomBombing", L"Registered attack callback %llu", id);
    return id;
}

uint64_t AtomBombingDetector::RegisterAtomCallback(SuspiciousAtomCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_atomCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"AtomBombing", L"Registered atom callback %llu", id);
    return id;
}

uint64_t AtomBombingDetector::RegisterAPCCallback(SuspiciousAPCCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_apcCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"AtomBombing", L"Registered APC callback %llu", id);
    return id;
}

void AtomBombingDetector::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_attackCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_atomCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_apcCallbacks.erase(callbackId) > 0;

    if (removed) {
        SS_LOG_DEBUG(L"AtomBombing", L"Unregistered callback %llu", callbackId);
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] AtomBombingStatistics AtomBombingDetector::GetStatistics() const {
    if (!m_impl) return AtomBombingStatistics{};
    return m_impl->m_stats;
}

void AtomBombingDetector::ResetStatistics() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        SS_LOG_INFO(L"AtomBombing", L"Statistics reset");
    }
}

[[nodiscard]] std::wstring AtomBombingDetector::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
        AtomBombingConstants::VERSION_MAJOR,
        AtomBombingConstants::VERSION_MINOR,
        AtomBombingConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY
// ============================================================================

[[nodiscard]] bool AtomBombingDetector::IsGlobalAtom(uint16_t atomValue) noexcept {
    return atomValue >= AtomBombingConstants::MIN_GLOBAL_ATOM &&
           atomValue <= AtomBombingConstants::MAX_GLOBAL_ATOM;
}

[[nodiscard]] std::wstring AtomBombingDetector::GetAtomName(uint16_t atomValue) const {
    wchar_t atomName[AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1]{};
    UINT result = GlobalGetAtomNameW(
        static_cast<ATOM>(atomValue),
        atomName,
        AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1
    );

    if (result > 0) {
        return atomName;
    }

    return L"";
}

[[nodiscard]] std::wstring AtomBombingDetector::ConfidenceToString(
    DetectionConfidence confidence
) noexcept {
    switch (confidence) {
        case DetectionConfidence::None: return L"None";
        case DetectionConfidence::Low: return L"Low";
        case DetectionConfidence::Medium: return L"Medium";
        case DetectionConfidence::High: return L"High";
        case DetectionConfidence::Confirmed: return L"Confirmed";
        default: return L"Unknown";
    }
}

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
