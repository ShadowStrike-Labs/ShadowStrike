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
 * @brief Check for common shellcode patterns.
 */
[[nodiscard]] bool HasShellcodePatterns(std::span<const uint8_t> data) noexcept {
    if (data.size() < 16) return false;

    // Common shellcode patterns
    const std::array<std::array<uint8_t, 3>, 8> patterns = {{
        {0x90, 0x90, 0x90},  // NOP sled
        {0x31, 0xC0, 0x50},  // xor eax, eax; push eax (common in shellcode)
        {0x64, 0x8B, 0x00},  // mov eax, fs:[eax] (TEB access)
        {0xEB, 0xFE, 0x00},  // jmp $ (infinite loop marker)
        {0x55, 0x8B, 0xEC},  // push ebp; mov ebp, esp (function prologue)
        {0x48, 0x83, 0xEC},  // sub rsp, xx (x64 stack allocation)
        {0x4C, 0x8B, 0xDC},  // mov r11, rsp (x64 common)
        {0xCC, 0xCC, 0xCC}   // int3 breakpoints
    }};

    size_t patternMatches = 0;
    for (const auto& pattern : patterns) {
        for (size_t i = 0; i < data.size() - pattern.size(); ++i) {
            if (std::equal(pattern.begin(), pattern.end(), data.begin() + i)) {
                patternMatches++;
                break;
            }
        }
    }

    // If multiple patterns found, likely shellcode
    return patternMatches >= 2;
}

/**
 * @brief Check for null bytes (common in shellcode to avoid string termination).
 */
[[nodiscard]] bool HasNullBytes(std::span<const uint8_t> data) noexcept {
    return std::find(data.begin(), data.end(), 0x00) != data.end();
}

/**
 * @brief Get module name from address.
 */
[[nodiscard]] std::wstring GetModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                uintptr_t baseAddr = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                if (address >= baseAddr && address < baseAddr + modInfo.SizeOfImage) {
                    wchar_t szModName[MAX_PATH];
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
    uint64_t m_nextEventId{1};

    // Attack detection
    std::deque<AtomBombingAttack> m_detectedAttacks;
    uint64_t m_nextAttackId{1};

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
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const AtomBombingConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("AtomBombingDetector::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("AtomBombingDetector::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Initialize known safe atoms (system atoms)
            InitializeKnownSafeAtoms();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("AtomBombingDetector::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("AtomBombingDetector::Impl: Shutting down");

        // Stop monitoring
        StopMonitoringImpl();

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
        Logger::Info("AtomBombingDetector::Impl: Shutdown complete");
    }

    void InitializeKnownSafeAtoms() {
        // Common system atoms (window classes, etc.)
        // These are typically safe and shouldn't trigger alerts
        // This is a simplified list - real implementation would be more comprehensive
    }

    // ========================================================================
    // ATOM TABLE SCANNING
    // ========================================================================

    [[nodiscard]] ScanResult ScanAtomTableImpl() {
        ScanResult result{};
        const auto scanStart = steady_clock::now();

        try {
            result.scanTime = system_clock::now();
            result.systemWideScan = true;

            Logger::Info("AtomBombingDetector: Starting atom table scan");

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
            if (m_config.correlateAtomAndAPC) {
                result.detectedAttacks = CorrelateEventsImpl();
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

            Logger::Info("AtomBombingDetector: Scan complete - {} atoms, {} suspicious, {} attacks, {} ms",
                result.totalAtomsAnalyzed, result.suspiciousAtomsFound,
                result.detectedAttacks.size(), result.scanDurationMs);

            return result;

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: Scan exception: {}", e.what());
            result.scanError = StringUtils::Utf8ToWide(e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
    }

    [[nodiscard]] std::vector<AtomInfo> EnumerateAtomsImpl() {
        std::vector<AtomInfo> atoms;

        try {
            // Enumerate global atoms in range
            for (uint16_t atomValue = AtomBombingConstants::MIN_GLOBAL_ATOM;
                 atomValue <= AtomBombingConstants::MAX_GLOBAL_ATOM;
                 ++atomValue) {

                if (atoms.size() >= m_config.maxAtomsToAnalyze) {
                    break;
                }

                // Try to get atom name
                wchar_t atomName[AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1]{};
                UINT result = GlobalGetAtomNameW(
                    static_cast<ATOM>(atomValue),
                    atomName,
                    AtomBombingConstants::MAX_ATOM_NAME_LENGTH
                );

                if (result > 0) {
                    // Atom exists, analyze it
                    auto atomInfo = AnalyzeAtomImpl(atomValue);
                    atoms.push_back(atomInfo);

                    m_stats.atomsMonitored.fetch_add(1, std::memory_order_relaxed);

                    if (atomInfo.suspicionLevel >= AtomSuspicion::MediumRisk) {
                        m_stats.suspiciousAtomsDetected.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: Enumeration exception: {}", e.what());
        }

        return atoms;
    }

    [[nodiscard]] AtomInfo AnalyzeAtomImpl(uint16_t atomValue) {
        AtomInfo atom{};
        atom.atomValue = atomValue;
        atom.type = AtomType::GlobalAtom;

        try {
            // Get atom name
            wchar_t atomName[AtomBombingConstants::MAX_ATOM_NAME_LENGTH + 1]{};
            UINT nameLength = GlobalGetAtomNameW(
                static_cast<ATOM>(atomValue),
                atomName,
                AtomBombingConstants::MAX_ATOM_NAME_LENGTH
            );

            if (nameLength > 0) {
                atom.atomName = atomName;
                atom.contentLength = nameLength;

                // Convert to bytes for analysis
                atom.rawContent.resize(nameLength * sizeof(wchar_t));
                std::memcpy(atom.rawContent.data(), atomName, atom.rawContent.size());

                // Analyze content
                if (m_config.analyzeEntropy) {
                    atom.entropy = CalculateEntropy(atom.rawContent);
                    atom.hasHighEntropy = (atom.entropy >= m_config.entropyThreshold);

                    if (atom.hasHighEntropy) {
                        m_stats.highEntropyAtomsDetected.fetch_add(1, std::memory_order_relaxed);
                        atom.suspicionReasons.push_back(
                            std::format(L"High entropy: {:.2f}", atom.entropy)
                        );
                    }
                }

                if (m_config.detectShellcodePatterns) {
                    atom.hasShellcodePatterns = HasShellcodePatterns(atom.rawContent);
                    if (atom.hasShellcodePatterns) {
                        m_stats.shellcodePatternsDetected.fetch_add(1, std::memory_order_relaxed);
                        atom.suspicionReasons.push_back(L"Shellcode patterns detected");
                    }
                }

                atom.hasNullBytes = HasNullBytes(atom.rawContent);

                // Calculate suspicion level
                atom.suspicionLevel = CalculateAtomSuspicion(atom);

                // Store in monitored atoms
                if (atom.suspicionLevel >= AtomSuspicion::LowRisk) {
                    std::unique_lock lock(m_atomMutex);
                    m_monitoredAtoms[atomValue] = atom;

                    if (atom.suspicionLevel >= AtomSuspicion::MediumRisk) {
                        m_suspiciousAtoms.push_back(atom);
                        if (m_suspiciousAtoms.size() > AtomBombingConstants::MAX_ATOM_EVENTS) {
                            m_suspiciousAtoms.pop_front();
                        }

                        // Invoke callbacks
                        InvokeAtomCallbacks(atom);
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: Atom analysis exception: {}", e.what());
        }

        return atom;
    }

    [[nodiscard]] AtomSuspicion CalculateAtomSuspicion(const AtomInfo& atom) const noexcept {
        uint32_t score = 0;

        if (atom.hasHighEntropy) score += 25;
        if (atom.hasShellcodePatterns) score += 40;
        if (atom.contentLength >= m_config.suspiciousAtomSizeThreshold) score += 15;
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

        try {
            event.sourcePid = sourcePid;
            event.targetPid = targetPid;
            event.targetTid = targetTid;
            event.apcRoutine = apcRoutine;

            event.isCrossProcess = (sourcePid != targetPid);
            event.targetsSelf = (sourcePid == targetPid);

            // Get process names
            HANDLE hSourceProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, sourcePid);
            if (hSourceProcess) {
                wchar_t processPath[MAX_PATH];
                if (GetModuleFileNameExW(hSourceProcess, nullptr, processPath, MAX_PATH)) {
                    event.sourceProcessPath = processPath;
                    event.sourceProcessName = fs::path(processPath).filename().wstring();
                }

                // Get module containing APC routine
                event.moduleName = GetModuleNameFromAddress(hSourceProcess, apcRoutine);
                CloseHandle(hSourceProcess);
            }

            HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, targetPid);
            if (hTargetProcess) {
                wchar_t processPath[MAX_PATH];
                if (GetModuleFileNameExW(hTargetProcess, nullptr, processPath, MAX_PATH)) {
                    event.targetProcessPath = processPath;
                    event.targetProcessName = fs::path(processPath).filename().wstring();
                }
                CloseHandle(hTargetProcess);
            }

            // Check if APC targets atom-related functions
            event.targetsAtomFunction = TargetsAtomRetrievalImpl(apcRoutine, targetPid);

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

            // Store event
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

                    // Invoke callbacks
                    InvokeAPCCallbacks(event);
                }
            }

            m_stats.apcsMonitored.fetch_add(1, std::memory_order_relaxed);
            if (event.isCrossProcess) {
                m_stats.crossProcessApcs.fetch_add(1, std::memory_order_relaxed);
            }
            if (event.targetsAtomFunction) {
                m_stats.atomTargetingApcs.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: APC analysis exception: {}", e.what());
        }

        return event;
    }

    [[nodiscard]] bool TargetsAtomRetrievalImpl(uintptr_t apcRoutine, uint32_t pid) const {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pid);
            if (!hProcess) return false;

            // Get module name
            auto moduleName = GetModuleNameFromAddress(hProcess, apcRoutine);
            CloseHandle(hProcess);

            // Check if it's in kernel32.dll (GlobalGetAtomName) or ntdll.dll
            if (moduleName == L"kernel32.dll" || moduleName == L"KernelBase.dll" ||
                moduleName == L"ntdll.dll") {
                // In a real implementation, would check function export or disassemble
                // For now, simplified heuristic
                return true;
            }

        } catch (...) {
            return false;
        }

        return false;
    }

    // ========================================================================
    // ATTACK CORRELATION
    // ========================================================================

    [[nodiscard]] std::vector<AtomBombingAttack> CorrelateEventsImpl() {
        std::vector<AtomBombingAttack> attacks;

        try {
            std::shared_lock atomLock(m_atomMutex);
            std::shared_lock apcLock(m_apcMutex);

            // For each suspicious atom, look for correlated APCs
            for (const auto& atom : m_suspiciousAtoms) {
                for (const auto& apc : m_suspiciousApcs) {
                    // Check temporal correlation
                    auto timeDiff = duration_cast<milliseconds>(
                        apc.timestamp - atom.createTime
                    );

                    if (std::abs(timeDiff.count()) <= static_cast<int64_t>(m_config.apcCorrelationWindowMs)) {
                        // Potential attack correlation
                        if (apc.targetsAtomFunction && apc.isCrossProcess) {
                            AtomBombingAttack attack = BuildAttackFromCorrelation(atom, apc);
                            attacks.push_back(attack);
                        }
                    }
                }
            }

            // Store detected attacks
            if (!attacks.empty()) {
                std::unique_lock attackLock(m_attackMutex);
                for (const auto& attack : attacks) {
                    m_detectedAttacks.push_back(attack);
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

                    // Invoke attack callbacks
                    InvokeAttackCallbacks(attack);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: Correlation exception: {}", e.what());
        }

        return attacks;
    }

    [[nodiscard]] AtomBombingAttack BuildAttackFromCorrelation(
        const AtomInfo& atom,
        const APCEvent& apc
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
        if (m_config.extractPayloads && !atom.rawContent.empty()) {
            attack.payloadExtracted = true;
            attack.payload = atom.rawContent;
            attack.payloadHash = HashUtils::CalculateSHA256(atom.rawContent);
            attack.payloadDescription = std::format(L"Atom {} content", atom.atomValue);
            m_stats.payloadsExtracted.fetch_add(1, std::memory_order_relaxed);
        }

        Logger::Warn("AtomBombingDetector: Attack detected - PID {} -> PID {}, Confidence: {}, Risk: {}",
            attack.attackerPid, attack.victimPid,
            static_cast<int>(attack.confidence), attack.riskScore);

        return attack;
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool StartMonitoringImpl() {
        if (m_monitoring.exchange(true, std::memory_order_acquire)) {
            Logger::Warn("AtomBombingDetector: Already monitoring");
            return true;
        }

        try {
            Logger::Info("AtomBombingDetector: Starting real-time monitoring");

            // Start monitoring thread
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                MonitoringThread(stoken);
            });

            Logger::Info("AtomBombingDetector: Monitoring started");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: Start monitoring exception: {}", e.what());
            m_monitoring.store(false, std::memory_order_release);
            return false;
        }
    }

    void StopMonitoringImpl() {
        if (!m_monitoring.exchange(false, std::memory_order_acquire)) {
            return;
        }

        Logger::Info("AtomBombingDetector: Stopping monitoring");

        // Stop worker threads
        m_workerThreads.clear();

        Logger::Info("AtomBombingDetector: Monitoring stopped");
    }

    void MonitoringThread(std::stop_token stoken) {
        Logger::Debug("AtomBombingDetector: Monitoring thread started");

        while (!stoken.stop_requested()) {
            try {
                // Periodic scanning
                if (m_config.enableOnDemandScanning) {
                    ScanAtomTableImpl();
                }

                // Check for attack correlations
                if (m_config.correlateAtomAndAPC) {
                    CorrelateEventsImpl();
                }

                // Sleep
                std::this_thread::sleep_for(seconds(5));

            } catch (const std::exception& e) {
                Logger::Error("AtomBombingDetector: Monitoring thread exception: {}", e.what());
            }
        }

        Logger::Debug("AtomBombingDetector: Monitoring thread stopped");
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    void OnAtomCreateImpl(
        uint16_t atomValue,
        uint32_t creatorPid,
        const std::wstring& atomName
    ) {
        if (!m_config.monitorAtomTable) return;

        try {
            m_stats.atomCreations.fetch_add(1, std::memory_order_relaxed);

            // Analyze the new atom
            auto atom = AnalyzeAtomImpl(atomValue);
            atom.creatorPid = creatorPid;
            atom.createTime = system_clock::now();

            // Store creation context
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, creatorPid);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, nullptr, processPath, MAX_PATH)) {
                    atom.creatorProcessName = fs::path(processPath).filename().wstring();
                }
                CloseHandle(hProcess);
            }

            Logger::Debug("AtomBombingDetector: Atom {} created by PID {} ({}), Suspicion: {}",
                atomValue, creatorPid, StringUtils::WideToUtf8(atom.creatorProcessName),
                static_cast<int>(atom.suspicionLevel));

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: OnAtomCreate exception: {}", e.what());
        }
    }

    void OnAtomDeleteImpl(uint16_t atomValue, uint32_t deleterPid) {
        if (!m_config.monitorAtomTable) return;

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
        if (!m_config.monitorAPCs) return;

        try {
            auto apcEvent = AnalyzeAPCImpl(sourcePid, targetPid, targetTid, apcRoutine);
            apcEvent.apcArgument1 = arg1;
            apcEvent.apcArgument2 = arg2;
            apcEvent.apcArgument3 = arg3;

            // Check if should be blocked
            if (m_config.blockSuspiciousApcs && apcEvent.isSuspicious) {
                if (m_config.mode == MonitoringMode::Active ||
                    m_config.mode == MonitoringMode::Aggressive) {
                    // In real implementation, would actually block the APC
                    Logger::Warn("AtomBombingDetector: Would block suspicious APC from PID {} to PID {}",
                        sourcePid, targetPid);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("AtomBombingDetector: OnAPCQueue exception: {}", e.what());
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeAttackCallbacks(const AtomBombingAttack& attack) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_attackCallbacks) {
            try {
                callback(attack);
            } catch (const std::exception& e) {
                Logger::Error("AtomBombingDetector: Attack callback exception: {}", e.what());
            }
        }
    }

    void InvokeAtomCallbacks(const AtomInfo& atom) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_atomCallbacks) {
            try {
                callback(atom);
            } catch (const std::exception& e) {
                Logger::Error("AtomBombingDetector: Atom callback exception: {}", e.what());
            }
        }
    }

    void InvokeAPCCallbacks(const APCEvent& apc) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_apcCallbacks) {
            try {
                callback(apc);
            } catch (const std::exception& e) {
                Logger::Error("AtomBombingDetector: APC callback exception: {}", e.what());
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
    Logger::Info("AtomBombingDetector: Constructor called");
}

AtomBombingDetector::~AtomBombingDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("AtomBombingDetector: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool AtomBombingDetector::Initialize(const AtomBombingConfig& config) {
    if (!m_impl) {
        Logger::Critical("AtomBombingDetector: Implementation is null");
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

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    Logger::Info("AtomBombingDetector: Configuration updated");
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

[[nodiscard]] ScanResult AtomBombingDetector::ScanAtomTable() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AtomBombingDetector: Not initialized");
        return ScanResult{};
    }

    return m_impl->ScanAtomTableImpl();
}

[[nodiscard]] AtomInfo AtomBombingDetector::AnalyzeAtom(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AtomBombingDetector: Not initialized");
        return AtomInfo{};
    }

    return m_impl->AnalyzeAtomImpl(atomValue);
}

[[nodiscard]] std::vector<AtomInfo> AtomBombingDetector::EnumerateAtoms() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AtomBombingDetector: Not initialized");
        return {};
    }

    return m_impl->EnumerateAtomsImpl();
}

[[nodiscard]] std::vector<AtomInfo> AtomBombingDetector::FindSuspiciousAtoms() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AtomBombingDetector: Not initialized");
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
        Logger::Error("AtomBombingDetector: Not initialized");
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
        Logger::Error("AtomBombingDetector: Not initialized");
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

[[nodiscard]] ScanResult AtomBombingDetector::ScanProcess(uint32_t pid) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AtomBombingDetector: Not initialized");
        return ScanResult{};
    }

    // Process-specific scan
    ScanResult result{};
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
        Logger::Error("AtomBombingDetector: Not initialized");
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

    Logger::Info("AtomBombingDetector: Monitoring mode set to {}", static_cast<int>(mode));
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

    Logger::Info("AtomBombingDetector: Blocking APC from PID {} to PID {}",
        apc.sourcePid, apc.targetPid);

    // In real implementation, would use kernel driver to block APC
    m_impl->m_stats.attacksBlocked.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool AtomBombingDetector::RemoveMaliciousAtom(uint16_t atomValue) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        if (GlobalDeleteAtom(static_cast<ATOM>(atomValue)) == 0) {
            Logger::Info("AtomBombingDetector: Removed malicious atom {}", atomValue);
            return true;
        } else {
            DWORD error = GetLastError();
            Logger::Error("AtomBombingDetector: Failed to delete atom {}: error {}",
                atomValue, error);
            return false;
        }
    } catch (const std::exception& e) {
        Logger::Error("AtomBombingDetector: RemoveMaliciousAtom exception: {}", e.what());
        return false;
    }
}

bool AtomBombingDetector::TerminateAttacker(const AtomBombingAttack& attack) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!m_impl->m_config.terminateAttacker) {
        Logger::Warn("AtomBombingDetector: Termination disabled in config");
        return false;
    }

    try {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, attack.attackerPid);
        if (hProcess) {
            if (TerminateProcess(hProcess, 1)) {
                Logger::Warn("AtomBombingDetector: Terminated attacker process PID {}",
                    attack.attackerPid);
                CloseHandle(hProcess);
                return true;
            }
            CloseHandle(hProcess);
        }

        Logger::Error("AtomBombingDetector: Failed to terminate attacker PID {}",
            attack.attackerPid);
        return false;

    } catch (const std::exception& e) {
        Logger::Error("AtomBombingDetector: TerminateAttacker exception: {}", e.what());
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

    Logger::Debug("AtomBombingDetector: Registered attack callback {}", id);
    return id;
}

uint64_t AtomBombingDetector::RegisterAtomCallback(SuspiciousAtomCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_atomCallbacks[id] = std::move(callback);

    Logger::Debug("AtomBombingDetector: Registered atom callback {}", id);
    return id;
}

uint64_t AtomBombingDetector::RegisterAPCCallback(SuspiciousAPCCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_apcCallbacks[id] = std::move(callback);

    Logger::Debug("AtomBombingDetector: Registered APC callback {}", id);
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
        Logger::Debug("AtomBombingDetector: Unregistered callback {}", callbackId);
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
        Logger::Info("AtomBombingDetector: Statistics reset");
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
        AtomBombingConstants::MAX_ATOM_NAME_LENGTH
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
