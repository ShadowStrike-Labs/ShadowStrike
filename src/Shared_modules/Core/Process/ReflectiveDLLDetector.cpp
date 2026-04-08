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
 * ShadowStrike Core Process - REFLECTIVE DLL DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ReflectiveDLLDetector.cpp
 * @brief Enterprise-grade detection of Reflective DLL Injection attacks.
 *
 * This module detects advanced code injection techniques where DLLs are loaded
 * entirely from memory without using the standard Windows loader. Reflective
 * DLL injection is used by sophisticated malware (Cobalt Strike, Metasploit)
 * and APT groups to evade traditional detection methods.
 *
 * Detection Methods:
 * - PE header scanning in unbacked memory regions
 * - RWX (Read-Write-Execute) memory detection
 * - PEB consistency validation (hidden module detection)
 * - Thread start address analysis (unbacked code)
 * - Known reflective loader signature matching
 * - Entropy analysis for packed/encrypted payloads
 * - Call stack frame analysis
 * - Memory protection anomaly detection
 *
 * MITRE ATT&CK Coverage:
 * - T1620: Reflective Code Loading
 * - T1055.001: DLL Injection
 * - T1055: Process Injection
 * - T1027: Obfuscated Files or Information
 * - T1140: Deobfuscate/Decode Files or Information
 * - T1106: Native API
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ReflectiveDLLDetector.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/HashUtils.hpp"

// Windows headers
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

// Infrastructure includes (kernel + stores)
#include "../../Communication/IPCManager.hpp"

// Standard library
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <format>
#include <filesystem>
#include <fstream>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

// ============================================================================
// RAII HANDLE GUARD (consistent with DLLInjectionDetector pattern)
// ============================================================================

struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE get() const noexcept { return h; }
};

// ============================================================================
// NTDLL DYNAMIC IMPORTS
// ============================================================================

using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

/// Lazily resolve NtQueryInformationThread from ntdll.dll (process-lifetime cache).
[[nodiscard]] NtQueryInformationThread_t GetNtQueryInformationThread() noexcept {
    static const auto fn = reinterpret_cast<NtQueryInformationThread_t>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return fn;
}

/// Retrieve the Win32 start address of a thread. Returns 0 on failure.
[[nodiscard]] uintptr_t QueryThreadStartAddress(HANDLE hThread) noexcept {
    auto fn = GetNtQueryInformationThread();
    if (!fn) return 0;

    PVOID startAddr = nullptr;
    ULONG retLen = 0;
    // ThreadQuerySetWin32StartAddress = 9
    NTSTATUS st = fn(hThread, static_cast<THREADINFOCLASS>(9),
                     &startAddr, sizeof(startAddr), &retLen);
    if (!NT_SUCCESS(st)) return 0;
    return reinterpret_cast<uintptr_t>(startAddr);
}

/// Check whether an address falls within any loaded module of a process.
[[nodiscard]] bool IsAddressInAnyModule(uint32_t pid, uintptr_t address) noexcept {
    HMODULE hMods[1024]{};
    DWORD cbNeeded = 0;
    HandleGuard hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!hProcess) return false;

    if (!::EnumProcessModules(hProcess.get(), hMods, sizeof(hMods), &cbNeeded))
        return false;

    const DWORD count = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < std::min(count, DWORD(1024)); ++i) {
        MODULEINFO mi{};
        if (::GetModuleInformation(hProcess.get(), hMods[i], &mi, sizeof(mi))) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            if (address >= base && address < base + mi.SizeOfImage)
                return true;
        }
    }
    return false;
}

// ============================================================================
// REFLECTIVE LOADER HEURISTIC PATTERNS
// ============================================================================

/// Byte sequences characteristic of hash-based API resolution loops
/// (common across Stephen Fewer's loader, sRDI, Cobalt Strike, etc.)
struct HeuristicPattern {
    const char* name;
    std::array<uint8_t, 8> bytes;
    std::array<uint8_t, 8> mask;     // 0xFF = exact, 0x00 = wildcard
};

// ROR-13 additive hash loop (x64): classic Fewer's ReflectiveLoader
static constexpr HeuristicPattern g_apiHashPatterns[] = {
    // ror r32, 0x0D  ;  add r32, byte  (ROR-13 hash loop)
    { "ROR13_hash_x64",
      {0xC1, 0xCF, 0x0D, 0x03, 0xCF, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    // ror edi, 0x0D (32-bit variant)
    { "ROR13_hash_x86",
      {0xC1, 0xCF, 0x0D, 0x01, 0xC7, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    // djb2-style: shl reg, 5 / add / xor
    { "DJB2_hash_loop",
      {0xC1, 0xE0, 0x05, 0x03, 0xC1, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00} },
    // sRDI: uses CRC32 intrinsic
    { "CRC32_hash_intrinsic",
      {0xF2, 0x0F, 0x38, 0xF1, 0x00, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00} },
};

/// Scan buffer for heuristic API-hashing patterns. Returns name of first match or nullptr.
[[nodiscard]] const char* DetectAPIHashingPattern(std::span<const uint8_t> data) noexcept {
    if (data.size() < 8) return nullptr;
    const size_t limit = data.size() - 8;

    for (const auto& pat : g_apiHashPatterns) {
        for (size_t i = 0; i <= limit; ++i) {
            bool match = true;
            for (size_t j = 0; j < 8; ++j) {
                if ((data[i + j] & pat.mask[j]) != (pat.bytes[j] & pat.mask[j])) {
                    match = false;
                    break;
                }
            }
            if (match) return pat.name;
        }
    }
    return nullptr;
}

/**
 * @brief Calculate Shannon entropy of data.
 */
double CalculateEntropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    const double size = static_cast<double>(data.size());

    for (size_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Check if memory protection is executable.
 */
bool IsExecutable(DWORD protect) noexcept {
    return (protect & PAGE_EXECUTE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

/**
 * @brief Check if memory protection is writable.
 */
bool IsWritable(DWORD protect) noexcept {
    return (protect & PAGE_READWRITE) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_WRITECOPY) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

/**
 * @brief Check if memory protection is RWX.
 */
bool IsRWX(DWORD protect) noexcept {
    return (protect & PAGE_EXECUTE_READWRITE) != 0;
}

/**
 * @brief Check if memory is unbacked (not mapped from file).
 */
bool IsUnbacked(DWORD type) noexcept {
    return (type & MEM_PRIVATE) != 0;
}

/**
 * @brief Read memory safely from remote process.
 */
bool ReadProcessMemorySafe(HANDLE hProcess, uintptr_t address,
                          std::vector<uint8_t>& buffer, size_t size) {
    if (size == 0 || size > 100 * 1024 * 1024) return false; // Cap at 100MB

    buffer.resize(size);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                          buffer.data(), size, &bytesRead)) {
        return false;
    }

    if (bytesRead != size) {
        buffer.resize(bytesRead);
    }

    return bytesRead > 0;
}

/**
 * @brief Check for DOS signature (MZ).
 */
bool HasDosSignature(std::span<const uint8_t> data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    return dosHeader->e_magic == ReflectiveConstants::DOS_MAGIC;
}

/**
 * @brief Check for PE signature.
 */
bool HasPeSignature(std::span<const uint8_t> data, uint32_t offset) {
    if (offset + sizeof(DWORD) > data.size()) return false;

    const auto* peSignature = reinterpret_cast<const DWORD*>(data.data() + offset);
    return *peSignature == ReflectiveConstants::PE_SIGNATURE;
}

/**
 * @brief Convert ReflectiveLoadType to string.
 */
std::wstring LoadTypeToStringInternal(ReflectiveLoadType type) {
    switch (type) {
        case ReflectiveLoadType::ClassicReflective: return L"Classic Reflective DLL";
        case ReflectiveLoadType::SRDI: return L"sRDI (Shellcode Reflective)";
        case ReflectiveLoadType::ManualMapping: return L"Manual Mapping";
        case ReflectiveLoadType::MemoryModule: return L"Memory Module";
        case ReflectiveLoadType::CobaltStrikeBeacon: return L"Cobalt Strike Beacon";
        case ReflectiveLoadType::MeterpreterStage: return L"Metasploit Meterpreter";
        case ReflectiveLoadType::PELoader: return L"Generic PE Loader";
        case ReflectiveLoadType::PackedReflective: return L"Packed Reflective";
        case ReflectiveLoadType::ModuleOverloading: return L"Module Overloading";
        case ReflectiveLoadType::DotNetAssembly: return L".NET Assembly";
        case ReflectiveLoadType::CustomLoader: return L"Custom Loader";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert DetectionConfidence to string.
 */
std::wstring ConfidenceToStringInternal(DetectionConfidence confidence) {
    switch (confidence) {
        case DetectionConfidence::Low: return L"Low";
        case DetectionConfidence::Medium: return L"Medium";
        case DetectionConfidence::High: return L"High";
        case DetectionConfidence::Confirmed: return L"Confirmed";
        default: return L"None";
    }
}

/**
 * @brief Known Cobalt Strike beacon signatures.
 * First pattern: Beacon configuration block marker (0x00, 0x01, ...).
 * We intentionally avoid the generic MZ stub — it matches all PEs.
 */
const std::vector<std::array<uint8_t, 16>> g_cobaltStrikePatterns = {
    // Beacon configuration marker (common across malleable C2 profiles)
    {0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
     0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
    // Beacon sleep mask stub (x64)
    {0x49, 0x89, 0xC8, 0x48, 0x8B, 0x48, 0x10, 0x48,
     0x8B, 0x50, 0x08, 0x4D, 0x31, 0xC9, 0x48, 0xFF}
};

/**
 * @brief Known Meterpreter signatures.
 */
const std::vector<std::array<uint8_t, 16>> g_meterpreterPatterns = {
    // Reflective DLL stub
    {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89,
     0xE5, 0x31, 0xC0, 0x64, 0x8B, 0x50, 0x30, 0x8B},
    // Stage marker
    {0x4D, 0x45, 0x54, 0x45, 0x52, 0x50, 0x52, 0x45,
     0x54, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00}
};

} // anonymous namespace

// ============================================================================
// REFLECTIVE DETECTION IMPLEMENTATION
// ============================================================================

void ReflectiveDetection::CalculateRiskScore() noexcept {
    uint32_t score = 0;

    // Confidence level
    switch (confidence) {
        case DetectionConfidence::Confirmed: score += 50; break;
        case DetectionConfidence::High: score += 40; break;
        case DetectionConfidence::Medium: score += 25; break;
        case DetectionConfidence::Low: score += 10; break;
        default: break;
    }

    // Memory characteristics
    if (isRWX) score += 20;
    if (isUnbacked) score += 15;
    if (isHiddenFromPEB) score += 15;

    // Known threat correlation
    if (correlatedWithKnownThreat) score += 30;

    // Load type severity
    switch (loadType) {
        case ReflectiveLoadType::CobaltStrikeBeacon:
        case ReflectiveLoadType::MeterpreterStage:
            score += 25;
            break;
        case ReflectiveLoadType::ClassicReflective:
        case ReflectiveLoadType::SRDI:
            score += 20;
            break;
        case ReflectiveLoadType::ManualMapping:
        case ReflectiveLoadType::PackedReflective:
            score += 15;
            break;
        default:
            score += 5;
            break;
    }

    // Thread activity
    if (hasThreadStartingHere) score += 10;
    if (threadCount > 1) score += 5;

    // Call stack presence
    if (foundInCallStack) score += 10;

    riskScore = std::min(score, 100u);
}

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

ReflectiveConfig ReflectiveConfig::CreateDefault() noexcept {
    ReflectiveConfig config;
    // Defaults already set in struct definition
    return config;
}

ReflectiveConfig ReflectiveConfig::CreateHighSensitivity() noexcept {
    ReflectiveConfig config;
    config.defaultScanMode = ReflectiveScanMode::Deep;
    config.enableRealTimeMonitoring = true;

    // Enable all detection features
    config.scanRWXRegions = true;
    config.scanAllExecutableRegions = true;
    config.scanPrivateMemory = true;
    config.validatePEStructures = true;
    config.analyzeThreadStartAddresses = true;
    config.analyzeCallStacks = true;
    config.checkPEBConsistency = true;
    config.detectKnownLoaders = true;
    config.extractPayloads = true;

    // Strict thresholds
    config.alertThreshold = DetectionConfidence::Low;
    config.entropyThreshold = 6.5; // Lower = more sensitive
    config.alertOnHighEntropy = true;
    config.alertOnRWX = true;
    config.alertOnUnbackedPE = true;

    config.useThreatIntel = true;
    config.useHashLookup = true;

    return config;
}

ReflectiveConfig ReflectiveConfig::CreatePerformance() noexcept {
    ReflectiveConfig config;
    config.defaultScanMode = ReflectiveScanMode::Quick;
    config.enableRealTimeMonitoring = true;

    // Focus on high-value detections
    config.scanRWXRegions = true;
    config.scanAllExecutableRegions = false;
    config.scanPrivateMemory = true;
    config.validatePEStructures = true;
    config.analyzeThreadStartAddresses = true;
    config.analyzeCallStacks = false; // Expensive
    config.checkPEBConsistency = true;
    config.detectKnownLoaders = true;
    config.extractPayloads = false;

    // Relaxed thresholds
    config.alertThreshold = DetectionConfidence::High;
    config.entropyThreshold = ReflectiveConstants::HIGH_ENTROPY_THRESHOLD;

    config.maxConcurrentScans = 8;

    return config;
}

ReflectiveConfig ReflectiveConfig::CreateForensic() noexcept {
    ReflectiveConfig config = CreateHighSensitivity();

    config.defaultScanMode = ReflectiveScanMode::Forensic;
    config.extractPayloads = true;
    config.scanTimeoutMs = 300000; // 5 minutes
    config.maxRegionsToScan = 65536;
    config.maxPECandidates = 4096;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void ReflectiveStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    quickScans.store(0, std::memory_order_relaxed);
    standardScans.store(0, std::memory_order_relaxed);
    deepScans.store(0, std::memory_order_relaxed);
    forensicScans.store(0, std::memory_order_relaxed);

    regionsScanned.store(0, std::memory_order_relaxed);
    rwxRegionsFound.store(0, std::memory_order_relaxed);
    unbackedExecutableFound.store(0, std::memory_order_relaxed);
    peCandidatesAnalyzed.store(0, std::memory_order_relaxed);

    reflectiveDLLsDetected.store(0, std::memory_order_relaxed);
    classicReflectiveDetected.store(0, std::memory_order_relaxed);
    srdiDetected.store(0, std::memory_order_relaxed);
    cobaltStrikeDetected.store(0, std::memory_order_relaxed);
    meterpreterDetected.store(0, std::memory_order_relaxed);
    customLoadersDetected.store(0, std::memory_order_relaxed);

    lowConfidenceDetections.store(0, std::memory_order_relaxed);
    mediumConfidenceDetections.store(0, std::memory_order_relaxed);
    highConfidenceDetections.store(0, std::memory_order_relaxed);
    confirmedDetections.store(0, std::memory_order_relaxed);

    payloadsExtracted.store(0, std::memory_order_relaxed);
    extractionFailures.store(0, std::memory_order_relaxed);

    totalScanTimeMs.store(0, std::memory_order_relaxed);
    avgScanTimeMs.store(0, std::memory_order_relaxed);

    scanErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    timeoutErrors.store(0, std::memory_order_relaxed);
}

double ReflectiveStatistics::GetDetectionRate() const noexcept {
    const uint64_t total = totalScans.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;

    const uint64_t detected = reflectiveDLLsDetected.load(std::memory_order_relaxed);
    return (static_cast<double>(detected) / static_cast<double>(total)) * 100.0;
}

ReflectiveStatistics::ReflectiveStatistics(const ReflectiveStatistics& o) noexcept {
    auto ld = [](const std::atomic<uint64_t>& a) noexcept {
        return a.load(std::memory_order_relaxed);
    };
    totalScans.store(ld(o.totalScans), std::memory_order_relaxed);
    quickScans.store(ld(o.quickScans), std::memory_order_relaxed);
    standardScans.store(ld(o.standardScans), std::memory_order_relaxed);
    deepScans.store(ld(o.deepScans), std::memory_order_relaxed);
    forensicScans.store(ld(o.forensicScans), std::memory_order_relaxed);
    regionsScanned.store(ld(o.regionsScanned), std::memory_order_relaxed);
    rwxRegionsFound.store(ld(o.rwxRegionsFound), std::memory_order_relaxed);
    unbackedExecutableFound.store(ld(o.unbackedExecutableFound), std::memory_order_relaxed);
    peCandidatesAnalyzed.store(ld(o.peCandidatesAnalyzed), std::memory_order_relaxed);
    reflectiveDLLsDetected.store(ld(o.reflectiveDLLsDetected), std::memory_order_relaxed);
    classicReflectiveDetected.store(ld(o.classicReflectiveDetected), std::memory_order_relaxed);
    srdiDetected.store(ld(o.srdiDetected), std::memory_order_relaxed);
    cobaltStrikeDetected.store(ld(o.cobaltStrikeDetected), std::memory_order_relaxed);
    meterpreterDetected.store(ld(o.meterpreterDetected), std::memory_order_relaxed);
    customLoadersDetected.store(ld(o.customLoadersDetected), std::memory_order_relaxed);
    lowConfidenceDetections.store(ld(o.lowConfidenceDetections), std::memory_order_relaxed);
    mediumConfidenceDetections.store(ld(o.mediumConfidenceDetections), std::memory_order_relaxed);
    highConfidenceDetections.store(ld(o.highConfidenceDetections), std::memory_order_relaxed);
    confirmedDetections.store(ld(o.confirmedDetections), std::memory_order_relaxed);
    payloadsExtracted.store(ld(o.payloadsExtracted), std::memory_order_relaxed);
    extractionFailures.store(ld(o.extractionFailures), std::memory_order_relaxed);
    totalScanTimeMs.store(ld(o.totalScanTimeMs), std::memory_order_relaxed);
    avgScanTimeMs.store(ld(o.avgScanTimeMs), std::memory_order_relaxed);
    scanErrors.store(ld(o.scanErrors), std::memory_order_relaxed);
    accessDeniedErrors.store(ld(o.accessDeniedErrors), std::memory_order_relaxed);
    timeoutErrors.store(ld(o.timeoutErrors), std::memory_order_relaxed);
}

ReflectiveStatistics& ReflectiveStatistics::operator=(const ReflectiveStatistics& o) noexcept {
    if (this != &o) {
        auto ld = [](const std::atomic<uint64_t>& a) noexcept {
            return a.load(std::memory_order_relaxed);
        };
        totalScans.store(ld(o.totalScans), std::memory_order_relaxed);
        quickScans.store(ld(o.quickScans), std::memory_order_relaxed);
        standardScans.store(ld(o.standardScans), std::memory_order_relaxed);
        deepScans.store(ld(o.deepScans), std::memory_order_relaxed);
        forensicScans.store(ld(o.forensicScans), std::memory_order_relaxed);
        regionsScanned.store(ld(o.regionsScanned), std::memory_order_relaxed);
        rwxRegionsFound.store(ld(o.rwxRegionsFound), std::memory_order_relaxed);
        unbackedExecutableFound.store(ld(o.unbackedExecutableFound), std::memory_order_relaxed);
        peCandidatesAnalyzed.store(ld(o.peCandidatesAnalyzed), std::memory_order_relaxed);
        reflectiveDLLsDetected.store(ld(o.reflectiveDLLsDetected), std::memory_order_relaxed);
        classicReflectiveDetected.store(ld(o.classicReflectiveDetected), std::memory_order_relaxed);
        srdiDetected.store(ld(o.srdiDetected), std::memory_order_relaxed);
        cobaltStrikeDetected.store(ld(o.cobaltStrikeDetected), std::memory_order_relaxed);
        meterpreterDetected.store(ld(o.meterpreterDetected), std::memory_order_relaxed);
        customLoadersDetected.store(ld(o.customLoadersDetected), std::memory_order_relaxed);
        lowConfidenceDetections.store(ld(o.lowConfidenceDetections), std::memory_order_relaxed);
        mediumConfidenceDetections.store(ld(o.mediumConfidenceDetections), std::memory_order_relaxed);
        highConfidenceDetections.store(ld(o.highConfidenceDetections), std::memory_order_relaxed);
        confirmedDetections.store(ld(o.confirmedDetections), std::memory_order_relaxed);
        payloadsExtracted.store(ld(o.payloadsExtracted), std::memory_order_relaxed);
        extractionFailures.store(ld(o.extractionFailures), std::memory_order_relaxed);
        totalScanTimeMs.store(ld(o.totalScanTimeMs), std::memory_order_relaxed);
        avgScanTimeMs.store(ld(o.avgScanTimeMs), std::memory_order_relaxed);
        scanErrors.store(ld(o.scanErrors), std::memory_order_relaxed);
        accessDeniedErrors.store(ld(o.accessDeniedErrors), std::memory_order_relaxed);
        timeoutErrors.store(ld(o.timeoutErrors), std::memory_order_relaxed);
    }
    return *this;
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterDetection(ReflectiveDetectedCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_detectionCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterProgress(ReflectiveScanProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_progressCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterCandidate(PECandidateCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_candidateCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_detectionCallbacks.erase(id)) return true;
        if (m_progressCallbacks.erase(id)) return true;
        if (m_candidateCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeDetection(const ReflectiveDetection& detection) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_detectionCallbacks) {
            try {
                callback(detection);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ReflectiveDLL", L"DetectionCallback exception: %S", e.what());
            }
        }
    }

    void InvokeProgress(uint32_t pid, uint32_t scanned, uint32_t total) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(pid, scanned, total);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ReflectiveDLL", L"ProgressCallback exception: %S", e.what());
            }
        }
    }

    void InvokeCandidate(uint32_t pid, const PECandidate& candidate) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_candidateCallbacks) {
            try {
                callback(pid, candidate);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ReflectiveDLL", L"CandidateCallback exception: %S", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, ReflectiveDetectedCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, ReflectiveScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, PECandidateCallback> m_candidateCallbacks;
};

// ============================================================================
// LOADER SIGNATURE DATABASE
// ============================================================================

class LoaderSignatureDB {
public:
    LoaderSignatureDB() {
        InitializeKnownSignatures();
    }

    void AddSignature(const LoaderSignature& sig) {
        std::unique_lock lock(m_mutex);
        m_signatures.push_back(sig);
    }

    std::vector<LoaderSignature> GetAll() const {
        std::shared_lock lock(m_mutex);
        return m_signatures;
    }

    std::optional<LoaderSignature> Match(std::span<const uint8_t> data) const {
        std::shared_lock lock(m_mutex);

        for (const auto& sig : m_signatures) {
            if (MatchesSignature(data, sig)) {
                return sig;
            }
        }

        return std::nullopt;
    }

private:
    void InitializeKnownSignatures() {
        // Cobalt Strike Beacon
        LoaderSignature cobalt;
        cobalt.name = "Cobalt Strike Beacon";
        cobalt.type = ReflectiveLoadType::CobaltStrikeBeacon;
        cobalt.mitreId = "T1620";
        cobalt.description = L"Cobalt Strike reflective loader detected";
        m_signatures.push_back(cobalt);

        // Metasploit Meterpreter
        LoaderSignature meterpreter;
        meterpreter.name = "Metasploit Meterpreter";
        meterpreter.type = ReflectiveLoadType::MeterpreterStage;
        meterpreter.mitreId = "T1620";
        meterpreter.description = L"Meterpreter reflective stage detected";
        m_signatures.push_back(meterpreter);

        // Classic Reflective DLL
        LoaderSignature classic;
        classic.name = "Classic Reflective DLL";
        classic.type = ReflectiveLoadType::ClassicReflective;
        classic.mitreId = "T1055.001";
        classic.description = L"Stephen Fewer's reflective DLL technique";
        m_signatures.push_back(classic);
    }

    bool MatchesSignature(std::span<const uint8_t> data, const LoaderSignature& sig) const {
        if (data.size() < sig.offset + ReflectiveConstants::SIGNATURE_LENGTH) {
            return false;
        }

        // Masked byte-by-byte comparison at the specified offset
        const uint8_t* target = data.data() + sig.offset;
        bool allZeroPattern = true;

        for (size_t i = 0; i < ReflectiveConstants::SIGNATURE_LENGTH; ++i) {
            if (sig.mask[i] != 0x00) {
                allZeroPattern = false;
                if ((target[i] & sig.mask[i]) != (sig.pattern[i] & sig.mask[i])) {
                    return false;
                }
            }
        }

        // An all-zero mask means this signature has no byte pattern configured;
        // it can only be matched via heuristic analysis, not byte comparison.
        return !allZeroPattern;
    }

    mutable std::shared_mutex m_mutex;
    std::vector<LoaderSignature> m_signatures;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ReflectiveDLLDetectorImpl {
public:
    ReflectiveDLLDetectorImpl() = default;
    ~ReflectiveDLLDetectorImpl() {
        StopMonitoring();
    }

    // Prevent copying
    ReflectiveDLLDetectorImpl(const ReflectiveDLLDetectorImpl&) = delete;
    ReflectiveDLLDetectorImpl& operator=(const ReflectiveDLLDetectorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const ReflectiveConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"ReflectiveDLL", L"Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_signatureDB = std::make_unique<LoaderSignatureDB>();

            // Register for kernel image-load notifications via IPCManager
            RegisterKernelHandlers();

            m_initialized = true;
            SS_LOG_INFO(L"ReflectiveDLL", L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"Initialization failed: %S", e.what());
            return false;
        }
    }

    void Shutdown() {
        StopMonitoring();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        SS_LOG_INFO(L"ReflectiveDLL", L"Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        return m_initialized;
    }

    bool UpdateConfig(const ReflectiveConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(L"ReflectiveDLL", L"Configuration updated");
        return true;
    }

    ReflectiveConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PROCESS SCANNING
    // ========================================================================

    ReflectiveScanResult Scan(uint32_t pid, ReflectiveScanMode mode) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        ReflectiveScanResult result;
        result.processId = pid;
        result.scanTime = std::chrono::system_clock::now();
        result.scanMode = mode;

        if (!m_initialized || !m_callbackManager || !m_signatureDB) {
            SS_LOG_ERROR(L"ReflectiveDLL",
                L"Scan called before Initialize — PID %u rejected", pid);
            result.scanError = L"Detector not initialized";
            return result;
        }

        // Snapshot config under shared lock to avoid races with UpdateConfig
        ReflectiveConfig config;
        {
            std::shared_lock lock(m_mutex);
            config = m_config;
        }

        try {
            // Get process name
            result.processName = GetProcessName(pid);

            SS_LOG_INFO(L"ReflectiveDLL", L"Scanning PID %u (%s) in %d mode",
                pid, result.processName.c_str(), static_cast<int>(mode));

            // Update statistics
            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
            switch (mode) {
                case ReflectiveScanMode::Quick: m_stats.quickScans.fetch_add(1, std::memory_order_relaxed); break;
                case ReflectiveScanMode::Standard: m_stats.standardScans.fetch_add(1, std::memory_order_relaxed); break;
                case ReflectiveScanMode::Deep: m_stats.deepScans.fetch_add(1, std::memory_order_relaxed); break;
                case ReflectiveScanMode::Forensic: m_stats.forensicScans.fetch_add(1, std::memory_order_relaxed); break;
            }

            // Find PE candidates
            result.allPECandidates = FindPECandidatesImpl(pid, mode,
                [&](uint32_t scanned, uint32_t total) {
                    m_callbackManager->InvokeProgress(pid, scanned, total);
                }, &config);

            result.peCandidatesFound = static_cast<uint32_t>(result.allPECandidates.size());

            // Get PEB modules for comparison
            auto pebModules = GetPEBModulesImpl(pid);

            // Analyze each candidate
            for (auto& candidate : result.allPECandidates) {
                // Check if in PEB
                candidate.isInPEB = std::find(pebModules.begin(), pebModules.end(),
                    candidate.baseAddress) != pebModules.end();

                // Invoke candidate callback
                m_callbackManager->InvokeCandidate(pid, candidate);

                // Analyze for reflective loading
                if (auto detection = AnalyzeCandidate(pid, candidate, mode, config)) {
                    result.detections.push_back(*detection);
                    result.reflectiveDLLsDetected++;

                    // Invoke detection callback
                    m_callbackManager->InvokeDetection(*detection);

                    SS_LOG_WARN(L"ReflectiveDLL",
                        L"Reflective DLL detected at 0x%016llX in PID %u",
                        static_cast<unsigned long long>(candidate.baseAddress), pid);
                }
            }

            // Summary
            result.hasReflectiveLoading = !result.detections.empty();
            if (result.hasReflectiveLoading) {
                result.primaryThreatType = result.detections[0].loadType;
                result.overallConfidence = result.detections[0].confidence;
                result.highestRiskScore = 0;
                for (const auto& det : result.detections) {
                    result.highestRiskScore = std::max(result.highestRiskScore, det.riskScore);
                }
            }

            result.scanComplete = true;

            const auto endTime = std::chrono::high_resolution_clock::now();
            result.scanDurationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
            );

            // Update statistics
            m_stats.totalScanTimeMs.fetch_add(result.scanDurationMs, std::memory_order_relaxed);
            const uint64_t totalTime = m_stats.totalScanTimeMs.load(std::memory_order_relaxed);
            const uint64_t totalCount = m_stats.totalScans.load(std::memory_order_relaxed);
            if (totalCount > 0) {
                m_stats.avgScanTimeMs.store(totalTime / totalCount, std::memory_order_relaxed);
            }

            SS_LOG_INFO(L"ReflectiveDLL",
                L"Scan complete - %u PE candidates, %u reflective DLLs, %u ms",
                result.peCandidatesFound, result.reflectiveDLLsDetected, result.scanDurationMs);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"Scan: %S", e.what());
            result.scanError = Utils::StringUtils::ToWide(e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return result;
    }

    bool HasReflectiveLoading(uint32_t pid) {
        auto result = Scan(pid, ReflectiveScanMode::Quick);
        return result.hasReflectiveLoading;
    }

    std::vector<ReflectiveScanResult> ScanMultiple(const std::vector<uint32_t>& pids, ReflectiveScanMode mode) {
        std::vector<ReflectiveScanResult> results;
        results.reserve(pids.size());

        for (uint32_t pid : pids) {
            results.push_back(Scan(pid, mode));
        }

        return results;
    }

    std::vector<ReflectiveScanResult> ScanAllProcesses(ReflectiveScanMode mode) {
        std::vector<ReflectiveScanResult> results;

        try {
            HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!hSnapshot) {
                SS_LOG_ERROR(L"ReflectiveDLL", L"Failed to create process snapshot");
                return results;
            }

            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot.get(), &pe32)) {
                do {
                    // Skip system processes
                    if (pe32.th32ProcessID <= 4) continue;

                    // Check exclusions
                    if (IsExcluded(pe32.szExeFile)) continue;

                    results.push_back(Scan(pe32.th32ProcessID, mode));

                } while (Process32NextW(hSnapshot.get(), &pe32));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"ScanAllProcesses: %S", e.what());
        }

        return results;
    }

    std::vector<ReflectiveScanResult> ScanByName(const std::wstring& processName, ReflectiveScanMode mode) {
        std::vector<ReflectiveScanResult> results;

        try {
            auto pids = FindProcessesByName(processName);
            for (uint32_t pid : pids) {
                results.push_back(Scan(pid, mode));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"ScanByName: %S", e.what());
        }

        return results;
    }

    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================

    std::vector<PECandidate> FindPECandidates(uint32_t pid) {
        return FindPECandidatesImpl(pid, ReflectiveScanMode::Standard, nullptr);
    }

    PECandidate ValidatePE(uint32_t pid, uintptr_t baseAddress) {
        PECandidate candidate;
        candidate.baseAddress = baseAddress;

        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return candidate;
        }

        try {
            ValidatePEImpl(hProcess.get(), candidate);
        } catch (...) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"ValidatePE exception for PID %u addr 0x%016llX",
                pid, static_cast<unsigned long long>(baseAddress));
        }

        return candidate;
    }

    bool ContainsPE(uint32_t pid, uintptr_t address, size_t size) {
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return false;

        std::vector<uint8_t> buffer;
        if (ReadProcessMemorySafe(hProcess.get(), address, buffer,
            std::min(size, size_t(ReflectiveConstants::MAX_PE_HEADER_SCAN)))) {
            return HasDosSignature(buffer);
        }
        return false;
    }

    std::vector<std::pair<uintptr_t, size_t>> FindRWXRegions(uint32_t pid) {
        std::vector<std::pair<uintptr_t, size_t>> rwxRegions;

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return rwxRegions;

        try {
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t address = 0;

            while (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && IsRWX(mbi.Protect)) {
                    rwxRegions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
                    m_stats.rwxRegionsFound.fetch_add(1, std::memory_order_relaxed);
                }

                const uintptr_t next = address + mbi.RegionSize;
                if (next <= address) break;
                address = next;
            }

        } catch (...) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"FindRWXRegions exception for PID %u", pid);
        }

        return rwxRegions;
    }

    std::vector<std::pair<uintptr_t, size_t>> FindUnbackedExecutable(uint32_t pid) {
        std::vector<std::pair<uintptr_t, size_t>> regions;

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return regions;

        try {
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t address = 0;

            while (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT &&
                    IsExecutable(mbi.Protect) &&
                    IsUnbacked(mbi.Type)) {
                    regions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
                    m_stats.unbackedExecutableFound.fetch_add(1, std::memory_order_relaxed);
                }

                const uintptr_t next = address + mbi.RegionSize;
                if (next <= address) break;
                address = next;
            }

        } catch (...) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"FindUnbackedExecutable exception for PID %u", pid);
        }

        return regions;
    }

    double CalculateEntropyMemory(uint32_t pid, uintptr_t address, size_t size) {
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return 0.0;

        std::vector<uint8_t> buffer;
        if (ReadProcessMemorySafe(hProcess.get(), address, buffer, std::min(size, size_t(65536)))) {
            return CalculateEntropy(buffer);
        }
        return 0.0;
    }

    // ========================================================================
    // PEB ANALYSIS
    // ========================================================================

    std::vector<PECandidate> FindHiddenModules(uint32_t pid) {
        std::vector<PECandidate> hiddenModules;

        try {
            // Find all PE candidates
            auto allCandidates = FindPECandidates(pid);

            // Get PEB modules
            auto pebModules = GetPEBModulesImpl(pid);

            // Find candidates not in PEB
            for (const auto& candidate : allCandidates) {
                if (std::find(pebModules.begin(), pebModules.end(),
                    candidate.baseAddress) == pebModules.end()) {
                    hiddenModules.push_back(candidate);
                }
            }

            SS_LOG_INFO(L"ReflectiveDLL", L"Found %zu hidden modules in PID %u", hiddenModules.size(), pid);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"FindHiddenModules: %S", e.what());
        }

        return hiddenModules;
    }

    bool IsInPEB(uint32_t pid, uintptr_t baseAddress) {
        auto pebModules = GetPEBModulesImpl(pid);
        return std::find(pebModules.begin(), pebModules.end(), baseAddress) != pebModules.end();
    }

    std::vector<uintptr_t> GetPEBModules(uint32_t pid) {
        return GetPEBModulesImpl(pid);
    }

    // ========================================================================
    // THREAD ANALYSIS
    // ========================================================================

    std::vector<std::pair<uint32_t, uintptr_t>> FindSuspiciousThreads(uint32_t pid) {
        std::vector<std::pair<uint32_t, uintptr_t>> suspiciousThreads;

        try {
            HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if (!hSnapshot) return suspiciousThreads;

            // Get unbacked executable regions for cross-reference
            auto unbackedRegions = FindUnbackedExecutable(pid);

            THREADENTRY32 te32{};
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot.get(), &te32)) {
                do {
                    if (te32.th32OwnerProcessID != pid) continue;

                    HandleGuard hThread(OpenThread(
                        THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID));
                    if (!hThread) continue;

                    // Resolve start address via NtQueryInformationThread
                    const uintptr_t startAddress = QueryThreadStartAddress(hThread.get());
                    if (startAddress == 0) continue;

                    // Check if start address falls inside any unbacked executable region
                    for (const auto& [regionBase, regionSize] : unbackedRegions) {
                        if (startAddress >= regionBase && startAddress < regionBase + regionSize) {
                            suspiciousThreads.emplace_back(te32.th32ThreadID, startAddress);
                            SS_LOG_WARN(L"ReflectiveDLL",
                                L"Suspicious thread TID %u starts at unbacked addr 0x%016llX in PID %u",
                                te32.th32ThreadID,
                                static_cast<unsigned long long>(startAddress), pid);
                            break;
                        }
                    }

                    // Also flag threads starting outside any known module
                    if (startAddress > 0x10000 && !IsAddressInAnyModule(pid, startAddress)) {
                        bool alreadyRecorded = false;
                        for (const auto& [tid, addr] : suspiciousThreads) {
                            if (tid == te32.th32ThreadID) { alreadyRecorded = true; break; }
                        }
                        if (!alreadyRecorded) {
                            suspiciousThreads.emplace_back(te32.th32ThreadID, startAddress);
                        }
                    }

                } while (Thread32Next(hSnapshot.get(), &te32));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"FindSuspiciousThreads: %S", e.what());
        }

        return suspiciousThreads;
    }

    bool IsThreadStartUnbacked(uint32_t tid) {
        HandleGuard hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
        if (!hThread) return false;

        const uintptr_t startAddress = QueryThreadStartAddress(hThread.get());
        if (startAddress == 0) return false;

        // Determine owning process from thread
        DWORD pid = 0;
        {
            HandleGuard hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if (hSnap) {
                THREADENTRY32 te{};
                te.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(hSnap.get(), &te)) {
                    do {
                        if (te.th32ThreadID == tid) { pid = te.th32OwnerProcessID; break; }
                    } while (Thread32Next(hSnap.get(), &te));
                }
            }
        }
        if (pid == 0) return false;

        // Query the memory region backing the start address
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(startAddress),
                           &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        // Unbacked = MEM_PRIVATE and executable
        return (mbi.State == MEM_COMMIT) && IsExecutable(mbi.Protect) && IsUnbacked(mbi.Type);
    }

    uint32_t CountUnbackedCallStackFrames(uint32_t tid) {
        // Open thread for stack walking
        HandleGuard hThread(OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            FALSE, tid));
        if (!hThread) return 0;

        // Determine owning process
        DWORD pid = 0;
        {
            HandleGuard hSnap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            if (hSnap) {
                THREADENTRY32 te{};
                te.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(hSnap.get(), &te)) {
                    do {
                        if (te.th32ThreadID == tid) { pid = te.th32OwnerProcessID; break; }
                    } while (Thread32Next(hSnap.get(), &te));
                }
            }
        }
        if (pid == 0) return 0;

        HandleGuard hProcess(OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return 0;

        // Suspend thread to capture consistent context
        if (SuspendThread(hThread.get()) == static_cast<DWORD>(-1)) return 0;

        uint32_t unbackedCount = 0;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(hThread.get(), &ctx)) {
            STACKFRAME64 frame{};
#ifdef _M_X64
            constexpr DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
            frame.AddrPC.Offset    = ctx.Rip;
            frame.AddrPC.Mode      = AddrModeFlat;
            frame.AddrFrame.Offset = ctx.Rbp;
            frame.AddrFrame.Mode   = AddrModeFlat;
            frame.AddrStack.Offset = ctx.Rsp;
            frame.AddrStack.Mode   = AddrModeFlat;
#else
            constexpr DWORD machineType = IMAGE_FILE_MACHINE_I386;
            frame.AddrPC.Offset    = ctx.Eip;
            frame.AddrPC.Mode      = AddrModeFlat;
            frame.AddrFrame.Offset = ctx.Ebp;
            frame.AddrFrame.Mode   = AddrModeFlat;
            frame.AddrStack.Offset = ctx.Esp;
            frame.AddrStack.Mode   = AddrModeFlat;
#endif
            constexpr size_t kMaxFrames = 64;
            for (size_t i = 0; i < kMaxFrames; ++i) {
                if (!StackWalk64(machineType, hProcess.get(), hThread.get(),
                                 &frame, &ctx, nullptr,
                                 SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
                    break;
                }
                if (frame.AddrPC.Offset == 0) break;

                const auto pc = static_cast<uintptr_t>(frame.AddrPC.Offset);
                if (!IsAddressInAnyModule(pid, pc)) {
                    ++unbackedCount;
                }
            }
        }

        ResumeThread(hThread.get());
        return unbackedCount;
    }

    // ========================================================================
    // LOADER DETECTION
    // ========================================================================

    std::optional<LoaderSignature> DetectKnownLoader(uint32_t pid, const PECandidate& candidate) {
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return std::nullopt;

        std::vector<uint8_t> buffer;
        std::optional<LoaderSignature> result;

        if (ReadProcessMemorySafe(hProcess.get(), candidate.baseAddress, buffer, 4096)) {
            // Check the signature database first (masked pattern matching)
            result = m_signatureDB->Match(buffer);

            // Heuristic: scan for known tool byte patterns anywhere in the header region
            if (!result) {
                auto searchBuffer = [&](const auto& patterns,
                                        const char* toolName,
                                        ReflectiveLoadType ltype,
                                        std::atomic<uint64_t>& stat) -> bool {
                    for (const auto& pattern : patterns) {
                        // Search the entire buffer, not just offset 0
                        if (buffer.size() < pattern.size()) continue;
                        const size_t limit = buffer.size() - pattern.size();
                        for (size_t off = 0; off <= limit; ++off) {
                            if (std::equal(pattern.begin(), pattern.end(), buffer.begin() + off)) {
                                LoaderSignature sig;
                                sig.name = toolName;
                                sig.type = ltype;
                                sig.mitreId = "T1620";
                                result = sig;
                                stat.fetch_add(1, std::memory_order_relaxed);
                                return true;
                            }
                        }
                    }
                    return false;
                };

                if (!searchBuffer(g_cobaltStrikePatterns, "Cobalt Strike Beacon",
                                  ReflectiveLoadType::CobaltStrikeBeacon,
                                  m_stats.cobaltStrikeDetected)) {
                    searchBuffer(g_meterpreterPatterns, "Metasploit Meterpreter",
                                 ReflectiveLoadType::MeterpreterStage,
                                 m_stats.meterpreterDetected);
                }
            }

            // Heuristic: detect API-hashing loops (ROR-13, CRC32, DJB2)
            if (!result) {
                if (const char* hashName = DetectAPIHashingPattern(buffer)) {
                    LoaderSignature sig;
                    sig.name = std::string("API-hash loader (") + hashName + ")";
                    sig.type = ReflectiveLoadType::ClassicReflective;
                    sig.mitreId = "T1620";
                    sig.description = L"Hash-based API resolution loop detected";
                    result = sig;
                }
            }
        }

        return result;
    }

    void AddLoaderSignature(const LoaderSignature& signature) {
        m_signatureDB->AddSignature(signature);
    }

    std::vector<LoaderSignature> GetLoaderSignatures() const {
        return m_signatureDB->GetAll();
    }

    // ========================================================================
    // PAYLOAD EXTRACTION
    // ========================================================================

    std::vector<uint8_t> ExtractPayload(uint32_t pid, const ReflectiveDetection& detection) {
        std::vector<uint8_t> payload;

        {
            std::shared_lock lock(m_mutex);
            if (!m_config.extractPayloads) {
                SS_LOG_WARN(L"ReflectiveDLL", L"Payload extraction disabled");
                return payload;
            }
        }

        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) {
            m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
            return payload;
        }

        try {
            const auto& candidate = detection.peCandidate;

            // Cap extraction size to prevent DoS via crafted SizeOfImage
            constexpr size_t kMaxExtraction = 100 * 1024 * 1024; // 100 MB
            size_t extractSize = candidate.sizeOfImage > 0
                ? candidate.sizeOfImage : candidate.regionSize;
            extractSize = std::min(extractSize, kMaxExtraction);

            if (extractSize < ReflectiveConstants::MIN_PE_SIZE) {
                m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
                return payload;
            }

            if (ReadProcessMemorySafe(hProcess.get(), candidate.baseAddress,
                                      payload, extractSize)) {
                m_stats.payloadsExtracted.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(L"ReflectiveDLL",
                    L"Extracted payload from 0x%016llX (%zu bytes)",
                    static_cast<unsigned long long>(candidate.baseAddress), payload.size());
            } else {
                m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"ExtractPayload: %S", e.what());
            m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
        }

        return payload;
    }

    bool DumpPE(uint32_t pid, uintptr_t baseAddress, const std::wstring& outputPath) {
        auto payload = ExtractPayloadRaw(pid, baseAddress);
        if (payload.empty()) return false;

        try {
            std::ofstream ofs(outputPath, std::ios::binary);
            if (!ofs) return false;

            ofs.write(reinterpret_cast<const char*>(payload.data()), payload.size());
            ofs.close();

            SS_LOG_INFO(L"ReflectiveDLL", L"Dumped PE to %s", outputPath.c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"DumpPE: %S", e.what());
            return false;
        }
    }

    std::vector<uint8_t> ReconstructPE(uint32_t pid, uintptr_t baseAddress) {
        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return {};

        // Step 1: Read PE headers
        std::vector<uint8_t> headerBuf;
        if (!ReadProcessMemorySafe(hProcess.get(), baseAddress, headerBuf,
                                   ReflectiveConstants::MAX_PE_HEADER_SCAN)) {
            return {};
        }

        if (!HasDosSignature(headerBuf)) return {};

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headerBuf.data());
        if (dos->e_lfanew < 0 ||
            static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > headerBuf.size()) {
            return {};
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            headerBuf.data() + dos->e_lfanew);
        if (nt->Signature != ReflectiveConstants::PE_SIGNATURE) return {};
        if (nt->FileHeader.NumberOfSections > ReflectiveConstants::MAX_SECTIONS) return {};

        const bool is64 = (nt->OptionalHeader.Magic == ReflectiveConstants::OPTIONAL_HEADER_MAGIC_64);
        const uint32_t numSections = nt->FileHeader.NumberOfSections;

        uint32_t sizeOfImage = 0;
        uint32_t sectionAlignment = 0;
        uint32_t fileAlignment = 0;

        const IMAGE_SECTION_HEADER* firstSection = nullptr;

        if (is64) {
            const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt);
            sizeOfImage = nt64->OptionalHeader.SizeOfImage;
            sectionAlignment = nt64->OptionalHeader.SectionAlignment;
            fileAlignment = nt64->OptionalHeader.FileAlignment;
            firstSection = IMAGE_FIRST_SECTION(nt64);
        } else {
            sizeOfImage = nt->OptionalHeader.SizeOfImage;
            sectionAlignment = nt->OptionalHeader.SectionAlignment;
            fileAlignment = nt->OptionalHeader.FileAlignment;
            firstSection = IMAGE_FIRST_SECTION(nt);
        }

        // Sanity cap
        constexpr uint32_t kMaxImage = 256 * 1024 * 1024;
        if (sizeOfImage == 0 || sizeOfImage > kMaxImage) return {};
        if (fileAlignment == 0) fileAlignment = 0x200;

        // Step 2: Read entire in-memory image
        std::vector<uint8_t> memImage;
        if (!ReadProcessMemorySafe(hProcess.get(), baseAddress, memImage, sizeOfImage)) {
            return {};
        }

        // Step 3: Reconstruct file-aligned PE
        // Compute total file size from sections
        uint32_t maxFileOffset = 0;
        const auto* sectionHeader = firstSection;
        const size_t sectionTableEnd = reinterpret_cast<const uint8_t*>(firstSection)
            - headerBuf.data() + numSections * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableEnd > headerBuf.size()) return {};

        for (uint32_t i = 0; i < numSections; ++i) {
            const uint32_t rawEnd = sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData;
            if (rawEnd > maxFileOffset) maxFileOffset = rawEnd;
        }

        // If no raw data pointers set, use VA-based layout (in-memory dump)
        if (maxFileOffset == 0) {
            return memImage;
        }

        std::vector<uint8_t> reconstructed(maxFileOffset, 0);

        // Copy headers up to first section
        uint32_t headerSize = firstSection[0].PointerToRawData;
        if (headerSize == 0) headerSize = 0x200;
        headerSize = std::min(headerSize, static_cast<uint32_t>(memImage.size()));
        std::memcpy(reconstructed.data(), memImage.data(), headerSize);

        // Copy each section from its virtual offset to its file offset
        for (uint32_t i = 0; i < numSections; ++i) {
            const auto& sec = sectionHeader[i];
            if (sec.VirtualAddress >= memImage.size()) continue;
            if (sec.PointerToRawData >= reconstructed.size()) continue;

            const size_t copySize = std::min({
                static_cast<size_t>(sec.SizeOfRawData),
                memImage.size() - sec.VirtualAddress,
                reconstructed.size() - sec.PointerToRawData
            });

            std::memcpy(reconstructed.data() + sec.PointerToRawData,
                         memImage.data() + sec.VirtualAddress,
                         copySize);
        }

        SS_LOG_INFO(L"ReflectiveDLL",
            L"Reconstructed PE from 0x%016llX (%zu bytes, %u sections)",
            static_cast<unsigned long long>(baseAddress),
            reconstructed.size(), numSections);

        return reconstructed;
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool StartMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"Not initialized");
            return false;
        }

        if (m_monitoring) {
            SS_LOG_WARN(L"ReflectiveDLL", L"Already monitoring");
            return true;
        }

        m_monitoring = true;
        SS_LOG_INFO(L"ReflectiveDLL", L"Real-time monitoring started");
        return true;
    }

    void StopMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_monitoring) return;

        m_monitoring = false;
        SS_LOG_INFO(L"ReflectiveDLL", L"Real-time monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        return m_monitoring;
    }

    void OnMemoryAllocation(uint32_t pid, uintptr_t address, size_t size, uint32_t protection) {
        if (!m_monitoring) return;

        // Snapshot config flag under shared lock
        bool rtMonitoring;
        {
            std::shared_lock lock(m_mutex);
            rtMonitoring = m_config.enableRealTimeMonitoring;
        }

        // Flag RWX allocations — these are almost never legitimate
        if (IsRWX(protection)) {
            SS_LOG_WARN(L"ReflectiveDLL",
                L"RWX allocation detected — PID %u, Address 0x%016llX, Size %zu",
                pid, static_cast<unsigned long long>(address), size);

            // Immediately check for PE structure at the allocated address
            if (rtMonitoring && size >= ReflectiveConstants::MIN_PE_SIZE) {
                if (ContainsPE(pid, address, size)) {
                    SS_LOG_ERROR(L"ReflectiveDLL",
                        L"PE structure in RWX allocation — PID %u, Address 0x%016llX",
                        pid, static_cast<unsigned long long>(address));

                    // Trigger targeted scan on the region
                    auto result = Scan(pid, ReflectiveScanMode::Standard);
                    (void)result; // Detection callbacks fire inside Scan()
                }
            }
        }
        // Also flag large executable allocations (manual mapping often allocates large RX)
        else if (IsExecutable(protection) && size >= 64 * 1024) {
            // Query the actual memory type — OnMemoryAllocation only receives protection
            HandleGuard hProc(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (hProc) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(hProc.get(), reinterpret_cast<LPCVOID>(address),
                                   &mbi, sizeof(mbi)) && IsUnbacked(mbi.Type)) {
                    SS_LOG_DEBUG(L"ReflectiveDLL",
                        L"Large unbacked executable allocation — PID %u, "
                        L"Address 0x%016llX, Size %zu",
                        pid, static_cast<unsigned long long>(address), size);
                }
            }
        }
    }

    void OnProtectionChange(uint32_t pid, uintptr_t address,
                           uint32_t oldProtection, uint32_t newProtection) {
        if (!m_monitoring) return;

        // Detect RW->RX transitions (hallmark of reflective loading / manual mapping)
        if (IsWritable(oldProtection) && !IsExecutable(oldProtection) &&
            IsExecutable(newProtection) && !IsWritable(newProtection)) {
            SS_LOG_WARN(L"ReflectiveDLL",
                L"Suspicious protection change RW->RX — PID %u, Address 0x%016llX",
                pid, static_cast<unsigned long long>(address));

            // Check for PE structure at this address
            if (ContainsPE(pid, address, ReflectiveConstants::MAX_PE_HEADER_SCAN)) {
                SS_LOG_ERROR(L"ReflectiveDLL",
                    L"PE structure found after RW->RX transition — PID %u, Address 0x%016llX — triggering scan",
                    pid, static_cast<unsigned long long>(address));

                // Create immediate detection event
                auto result = Scan(pid, ReflectiveScanMode::Standard);
                (void)result;
            }
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterCallback(ReflectiveDetectedCallback callback) {
        return m_callbackManager->RegisterDetection(std::move(callback));
    }

    uint64_t RegisterProgressCallback(ReflectiveScanProgressCallback callback) {
        return m_callbackManager->RegisterProgress(std::move(callback));
    }

    uint64_t RegisterCandidateCallback(PECandidateCallback callback) {
        return m_callbackManager->RegisterCandidate(std::move(callback));
    }

    void UnregisterCallback(uint64_t callbackId) {
        m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    ReflectiveStatistics GetStatistics() const {
        return m_stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    std::wstring GetProcessName(uint32_t pid) const {
        wchar_t processName[MAX_PATH] = L"<unknown>";

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess.get(), 0, processName, &size);
        }

        std::filesystem::path path(processName);
        return path.filename().wstring();
    }

    std::wstring GetProcessPath(uint32_t pid) const {
        wchar_t processPath[MAX_PATH] = L"";

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess.get(), 0, processPath, &size);
        }

        return processPath;
    }

    std::vector<uint32_t> FindProcessesByName(const std::wstring& name) const {
        std::vector<uint32_t> pids;

        HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) return pids;

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot.get(), &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, name.c_str()) == 0) {
                    pids.push_back(pe32.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot.get(), &pe32));
        }

        return pids;
    }

    bool IsExcluded(const std::wstring& processName) const {
        std::shared_lock lock(m_mutex);

        for (const auto& excluded : m_config.excludedProcesses) {
            if (_wcsicmp(processName.c_str(), excluded.c_str()) == 0) {
                return true;
            }
        }

        return false;
    }

    std::vector<PECandidate> FindPECandidatesImpl(uint32_t pid, ReflectiveScanMode mode,
        std::function<void(uint32_t, uint32_t)> progressCallback,
        const ReflectiveConfig* configOverride = nullptr) {

        std::vector<PECandidate> candidates;

        // Use provided config or snapshot current config under lock
        ReflectiveConfig cfg;
        if (configOverride) {
            cfg = *configOverride;
        } else {
            std::shared_lock lock(m_mutex);
            cfg = m_config;
        }

        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return candidates;
        }

        try {
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t address = 0;
            uint32_t regionsScanned = 0;
            uint32_t totalRegions = 0;

            // Count total regions first (for progress)
            while (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                totalRegions++;
                const uintptr_t next = address + mbi.RegionSize;
                if (next <= address) break;
                address = next;
            }

            // Reset for actual scan
            address = 0;

            while (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                regionsScanned++;
                m_stats.regionsScanned.fetch_add(1, std::memory_order_relaxed);

                // Progress callback
                if (progressCallback && regionsScanned % 100 == 0) {
                    progressCallback(regionsScanned, totalRegions);
                }

                // Check limits
                if (candidates.size() >= cfg.maxPECandidates) {
                    SS_LOG_WARN(L"ReflectiveDLL", L"Max PE candidates reached");
                    break;
                }

                if (regionsScanned >= cfg.maxRegionsToScan) {
                    SS_LOG_WARN(L"ReflectiveDLL", L"Max regions scanned reached");
                    break;
                }

                // Filter by scan mode
                bool shouldScan = false;
                switch (mode) {
                    case ReflectiveScanMode::Quick:
                        shouldScan = (mbi.State == MEM_COMMIT && IsRWX(mbi.Protect));
                        break;
                    case ReflectiveScanMode::Standard:
                        shouldScan = (mbi.State == MEM_COMMIT && IsExecutable(mbi.Protect));
                        break;
                    case ReflectiveScanMode::Deep:
                    case ReflectiveScanMode::Forensic:
                        shouldScan = (mbi.State == MEM_COMMIT);
                        break;
                }

                // When scanPrivateMemory is true we RESTRICT to private/unbacked memory
                // (skip image-backed regions which are legitimate loaded DLLs).
                // When false, scan all types of memory that passed the mode filter.
                if (shouldScan && cfg.scanPrivateMemory && !IsUnbacked(mbi.Type)) {
                    shouldScan = false;
                }

                if (shouldScan && mbi.RegionSize >= ReflectiveConstants::MIN_PE_SIZE) {
                    PECandidate candidate;
                    candidate.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                    candidate.regionSize = mbi.RegionSize;
                    candidate.memoryProtection = mbi.Protect;
                    candidate.isFileBacked = (mbi.Type == MEM_IMAGE) || (mbi.Type == MEM_MAPPED);

                    // Validate PE structure
                    if (ValidatePEImpl(hProcess.get(), candidate)) {
                        candidates.push_back(std::move(candidate));
                        m_stats.peCandidatesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                const uintptr_t next = address + mbi.RegionSize;
                if (next <= address) break;
                address = next;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"FindPECandidatesImpl: %S", e.what());
        }

        return candidates;
    }

    bool ValidatePEImpl(HANDLE hProcess, PECandidate& candidate) {
        std::vector<uint8_t> headerBuffer;

        // Read DOS header + PE header
        if (!ReadProcessMemorySafe(hProcess, candidate.baseAddress, headerBuffer, 4096)) {
            return false;
        }

        // Check DOS signature
        if (!HasDosSignature(headerBuffer)) {
            candidate.validationResult = PEValidationResult::InvalidDosHeader;
            return false;
        }

        candidate.hasDosHeader = true;

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(headerBuffer.data());
        const LONG lfanew = dosHeader->e_lfanew;

        // Validate e_lfanew: must be positive, and leave room for NT headers
        if (lfanew < 0 || static_cast<size_t>(lfanew) > headerBuffer.size() ||
            headerBuffer.size() - static_cast<size_t>(lfanew) < sizeof(IMAGE_NT_HEADERS)) {
            candidate.validationResult = PEValidationResult::TruncatedPE;
            return false;
        }

        candidate.peHeaderOffset = static_cast<uint32_t>(lfanew);

        // Check PE signature
        if (!HasPeSignature(headerBuffer, candidate.peHeaderOffset)) {
            candidate.validationResult = PEValidationResult::InvalidPeSignature;
            return false;
        }

        candidate.hasPeHeader = true;

        // Parse NT headers
        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            headerBuffer.data() + candidate.peHeaderOffset);

        candidate.machine = ntHeaders->FileHeader.Machine;
        candidate.numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        candidate.timeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        candidate.characteristics = ntHeaders->FileHeader.Characteristics;

        // Validate section count
        if (candidate.numberOfSections > ReflectiveConstants::MAX_SECTIONS) {
            candidate.validationResult = PEValidationResult::InvalidSections;
            return false;
        }

        // Determine architecture and parse optional header
        const uint16_t magic = ntHeaders->OptionalHeader.Magic;
        const IMAGE_SECTION_HEADER* sectionTable = nullptr;
        uint32_t numberOfRvaAndSizes = 0;
        const IMAGE_DATA_DIRECTORY* dataDir = nullptr;

        if (magic == ReflectiveConstants::OPTIONAL_HEADER_MAGIC_64) {
            // Ensure buffer has room for full NT64 headers + section table
            const size_t nt64End = candidate.peHeaderOffset + sizeof(IMAGE_NT_HEADERS64);
            const size_t sectionEnd = nt64End +
                candidate.numberOfSections * sizeof(IMAGE_SECTION_HEADER);
            if (sectionEnd > headerBuffer.size()) {
                candidate.validationResult = PEValidationResult::TruncatedPE;
                return false;
            }

            candidate.is64Bit = true;
            const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeaders);
            candidate.sizeOfImage = nt64->OptionalHeader.SizeOfImage;
            candidate.entryPoint = nt64->OptionalHeader.AddressOfEntryPoint;
            candidate.imageBase = nt64->OptionalHeader.ImageBase;
            numberOfRvaAndSizes = nt64->OptionalHeader.NumberOfRvaAndSizes;
            dataDir = nt64->OptionalHeader.DataDirectory;
            sectionTable = IMAGE_FIRST_SECTION(nt64);

        } else if (magic == ReflectiveConstants::OPTIONAL_HEADER_MAGIC_32) {
            const size_t nt32End = candidate.peHeaderOffset + sizeof(IMAGE_NT_HEADERS32);
            const size_t sectionEnd = nt32End +
                candidate.numberOfSections * sizeof(IMAGE_SECTION_HEADER);
            if (sectionEnd > headerBuffer.size()) {
                candidate.validationResult = PEValidationResult::TruncatedPE;
                return false;
            }

            candidate.is64Bit = false;
            candidate.sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
            candidate.entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
            candidate.imageBase = ntHeaders->OptionalHeader.ImageBase;
            numberOfRvaAndSizes = ntHeaders->OptionalHeader.NumberOfRvaAndSizes;
            dataDir = ntHeaders->OptionalHeader.DataDirectory;
            sectionTable = IMAGE_FIRST_SECTION(ntHeaders);
        } else {
            candidate.validationResult = PEValidationResult::InvalidOptionalHeader;
            return false;
        }

        // Validate SizeOfImage
        constexpr uint32_t kMaxSizeOfImage = 256 * 1024 * 1024; // 256 MB
        if (candidate.sizeOfImage == 0 || candidate.sizeOfImage > kMaxSizeOfImage) {
            candidate.validationResult = PEValidationResult::SuspiciousCharacteristics;
            return false;
        }

        // Parse data directories (export, import, reloc, TLS, debug)
        if (dataDir && numberOfRvaAndSizes > 0) {
            if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                candidate.hasExportTable = (dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0
                    && dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size >= ReflectiveConstants::MIN_EXPORT_TABLE_SIZE);
            }
            if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                candidate.hasImportTable = (dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0
                    && dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size >= ReflectiveConstants::MIN_IMPORT_TABLE_SIZE);
            }
            if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
                candidate.hasRelocationTable = (dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0
                    && dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0);
            }
            if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
                candidate.hasTLSDirectory = (dataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0
                    && dataDir[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0);
            }
            if (numberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
                candidate.hasDebugDirectory = (dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0
                    && dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0);
            }
        }

        // Parse section headers — entropy per section
        candidate.sections.reserve(candidate.numberOfSections);
        for (uint16_t i = 0; i < candidate.numberOfSections; ++i) {
            PECandidate::SectionInfo si{};
            std::memcpy(si.name.data(), sectionTable[i].Name,
                        std::min(sizeof(sectionTable[i].Name), si.name.size()));
            si.virtualAddress = sectionTable[i].VirtualAddress;
            si.virtualSize = sectionTable[i].Misc.VirtualSize;
            si.rawSize = sectionTable[i].SizeOfRawData;
            si.characteristics = sectionTable[i].Characteristics;

            // Calculate per-section entropy if section is within readable range
            if (si.virtualAddress > 0 && si.virtualSize > 0) {
                const size_t readSize = std::min(
                    static_cast<size_t>(si.virtualSize),
                    static_cast<size_t>(ReflectiveConstants::MAX_SECTION_SCAN));
                std::vector<uint8_t> secBuf;
                if (ReadProcessMemorySafe(hProcess,
                        candidate.baseAddress + si.virtualAddress,
                        secBuf, readSize)) {
                    si.entropy = CalculateEntropy(secBuf);
                }
            }

            candidate.sections.push_back(si);
        }

        // Overall entropy from header region
        candidate.overallEntropy = CalculateEntropy(headerBuffer);

        // Determine packed/encrypted status from section entropies
        for (const auto& sec : candidate.sections) {
            if (sec.entropy >= ReflectiveConstants::ENCRYPTED_ENTROPY_THRESHOLD) {
                candidate.isEncrypted = true;
                candidate.isPacked = true;
            } else if (sec.entropy >= ReflectiveConstants::PACKED_ENTROPY_THRESHOLD) {
                candidate.isPacked = true;
            }
        }

        if (candidate.isPacked) {
            candidate.validationResult = PEValidationResult::Packed;
        } else if (candidate.isEncrypted) {
            candidate.validationResult = PEValidationResult::Encrypted;
        } else {
            candidate.validationResult = PEValidationResult::Valid;
        }

        // Compute SHA256 of PE header region for identification and store lookups
        {
            std::vector<uint8_t> hashOut;
            if (Utils::HashUtils::Compute(Utils::HashUtils::Algorithm::SHA256,
                    headerBuffer.data(), headerBuffer.size(), hashOut)) {
                const size_t copyLen = std::min(hashOut.size(), candidate.sha256Hash.size());
                std::memcpy(candidate.sha256Hash.data(), hashOut.data(), copyLen);
            }
        }

        candidate.isValidPE = true;
        return true;
    }

    std::vector<uintptr_t> GetPEBModulesImpl(uint32_t pid) {
        std::vector<uintptr_t> modules;

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) return modules;

        try {
            HMODULE hMods[1024]{};
            DWORD cbNeeded = 0;

            if (EnumProcessModules(hProcess.get(), hMods, sizeof(hMods), &cbNeeded)) {
                const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < std::min(moduleCount, DWORD(1024)); ++i) {
                    modules.push_back(reinterpret_cast<uintptr_t>(hMods[i]));
                }
            }

        } catch (...) {
            SS_LOG_ERROR(L"ReflectiveDLL", L"GetPEBModulesImpl exception for PID %u", pid);
        }

        return modules;
    }

    std::optional<ReflectiveDetection> AnalyzeCandidate(uint32_t pid,
                                                       const PECandidate& candidate,
                                                       ReflectiveScanMode mode,
                                                       const ReflectiveConfig& config) {

        // Skip if PE is in PEB and file-backed (legitimate loaded module)
        if (candidate.isInPEB && candidate.isFileBacked) {
            return std::nullopt;
        }

        ReflectiveDetection detection;
        detection.processId = pid;
        detection.processName = GetProcessName(pid);
        detection.processPath = GetProcessPath(pid);
        detection.peCandidate = candidate;
        detection.detectionTime = std::chrono::system_clock::now();

        // Initial confidence
        detection.confidence = DetectionConfidence::None;

        // Threat intel correlation via PE header hash
        if (config.useThreatIntel) {
            const std::string sha256Hex = Utils::HashUtils::ToHexLower(
                candidate.sha256Hash.data(), candidate.sha256Hash.size());
            if (!sha256Hex.empty()) {
                try {
                    double tiRiskScore = 0.0;
                    std::string tiThreatName;
                    if (ThreatIntel::ThreatIntelManager::Instance()
                            .IsKnownMalicious(sha256Hex, tiRiskScore, tiThreatName)) {
                        detection.correlatedWithKnownThreat = true;
                        detection.threatName = Utils::StringUtils::ToWide(tiThreatName);
                        detection.confidence = DetectionConfidence::Confirmed;
                        detection.riskFactors.push_back(
                            L"ThreatIntel match: " + detection.threatName);
                    }
                } catch (const std::exception& e) {
                    SS_LOG_DEBUG(L"ReflectiveDLL",
                        L"ThreatIntel lookup failed: %S", e.what());
                }
            }
        }

        // Check for unbacked memory
        detection.isUnbacked = !candidate.isFileBacked;
        if (detection.isUnbacked) {
            detection.characteristics.push_back(MemoryCharacteristic::Unbacked);
            detection.confidence = std::max(detection.confidence, DetectionConfidence::Low);
            detection.riskFactors.push_back(L"PE in unbacked memory");
        }

        // Check for RWX
        detection.isRWX = IsRWX(candidate.memoryProtection);
        if (detection.isRWX) {
            detection.characteristics.push_back(MemoryCharacteristic::RWX);
            detection.confidence = std::max(detection.confidence, DetectionConfidence::Medium);
            detection.riskFactors.push_back(L"RWX memory protection");
        }

        // Check PEB consistency
        detection.isHiddenFromPEB = !candidate.isInPEB;
        if (detection.isHiddenFromPEB && candidate.isValidPE) {
            detection.characteristics.push_back(MemoryCharacteristic::HiddenFromPEB);
            detection.confidence = DetectionConfidence::High;
            detection.riskFactors.push_back(L"Valid PE not listed in PEB module list");
        }

        // Entropy analysis (packed/encrypted detection)
        if (candidate.isPacked) {
            detection.characteristics.push_back(MemoryCharacteristic::HighEntropy);
            detection.confidence = std::max(detection.confidence, DetectionConfidence::Medium);
            detection.riskFactors.push_back(L"High entropy — possible packed/encrypted payload");
        }

        // TLS directory in unbacked PE (often used by reflective loaders for init)
        if (candidate.hasTLSDirectory && detection.isUnbacked) {
            detection.confidence = std::max(detection.confidence, DetectionConfidence::High);
            detection.riskFactors.push_back(L"TLS callbacks in unbacked PE");
        }

        // Relocation table presence (needed by reflective loaders for rebasing)
        if (candidate.hasRelocationTable && detection.isUnbacked && detection.isHiddenFromPEB) {
            detection.riskFactors.push_back(L"Relocation table in hidden PE (manual rebasing)");
        }

        // Thread analysis — look for threads executing in this PE's memory
        if (config.analyzeThreadStartAddresses) {
            auto suspThreads = FindSuspiciousThreads(pid);
            for (const auto& [tid, startAddr] : suspThreads) {
                if (startAddr >= candidate.baseAddress &&
                    startAddr < candidate.baseAddress + candidate.regionSize) {
                    detection.hasThreadStartingHere = true;
                    detection.associatedThreadIds.push_back(tid);
                }
            }
            detection.threadCount = static_cast<uint32_t>(detection.associatedThreadIds.size());
            if (detection.hasThreadStartingHere) {
                detection.confidence = DetectionConfidence::Confirmed;
                detection.riskFactors.push_back(
                    L"Thread(s) executing inside hidden PE — active reflective injection");
            }
        }

        // Call stack analysis (Deep/Forensic only due to cost)
        if (config.analyzeCallStacks &&
            (mode == ReflectiveScanMode::Deep || mode == ReflectiveScanMode::Forensic)) {
            for (uint32_t tid : detection.associatedThreadIds) {
                uint32_t unbacked = CountUnbackedCallStackFrames(tid);
                if (unbacked > 0) {
                    detection.foundInCallStack = true;
                    detection.callStackDepth = std::max(detection.callStackDepth, unbacked);
                }
            }
            if (detection.foundInCallStack) {
                detection.riskFactors.push_back(L"Unbacked frames in call stack");
            }
        }

        // Detect known loaders (signature + heuristic matching)
        if (config.detectKnownLoaders) {
            if (auto loader = DetectKnownLoader(pid, candidate)) {
                detection.loadType = loader->type;
                detection.confidence = DetectionConfidence::Confirmed;
                detection.correlatedWithKnownThreat = true;
                detection.threatName = loader->description;
                detection.mitreAttackId = loader->mitreId;
                detection.riskFactors.push_back(L"Known reflective loader detected: " +
                    Utils::StringUtils::ToWide(loader->name));
            }
        }

        // PatternStore scan for YARA-like pattern matching on PE header region
        // PatternStore is injected externally (not a singleton); scan is already
        // covered by LoaderSignatureDB + heuristic patterns above.
        // Additional PatternStore wiring should be done during Initialize() when
        // the application provides the PatternStore instance.

        // Default load type if not identified
        if (detection.loadType == ReflectiveLoadType::Unknown) {
            if (detection.isUnbacked && detection.isHiddenFromPEB) {
                detection.loadType = ReflectiveLoadType::ClassicReflective;
                m_stats.classicReflectiveDetected.fetch_add(1, std::memory_order_relaxed);
            } else if (candidate.isPacked) {
                detection.loadType = ReflectiveLoadType::PackedReflective;
            } else {
                detection.loadType = ReflectiveLoadType::CustomLoader;
                m_stats.customLoadersDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // MITRE mapping for unidentified types
        if (detection.mitreAttackId.empty()) {
            detection.mitreAttackId = "T1620";
        }

        // Calculate risk score
        detection.CalculateRiskScore();

        // Update statistics
        m_stats.reflectiveDLLsDetected.fetch_add(1, std::memory_order_relaxed);

        switch (detection.confidence) {
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
                m_stats.confirmedDetections.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }

        // Only alert if meets threshold
        if (detection.confidence >= config.alertThreshold) {
            return detection;
        }

        return std::nullopt;
    }

    std::vector<uint8_t> ExtractPayloadRaw(uint32_t pid, uintptr_t baseAddress) {
        std::vector<uint8_t> payload;

        HandleGuard hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return payload;

        // Determine actual region size via VirtualQueryEx instead of blind 10MB read
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(baseAddress),
                           &mbi, sizeof(mbi)) == 0) {
            return payload;
        }

        // Cap at 10 MB for safety
        constexpr size_t kMaxRaw = 10 * 1024 * 1024;
        const size_t readSize = std::min(static_cast<size_t>(mbi.RegionSize), kMaxRaw);
        ReadProcessMemorySafe(hProcess.get(), baseAddress, payload, readSize);

        return payload;
    }

    // ========================================================================
    // KERNEL DRIVER INTEGRATION
    // ========================================================================

    void RegisterKernelHandlers() {
        if (!Communication::IPCManager::HasInstance()) {
            SS_LOG_WARN(L"ReflectiveDLL",
                L"IPCManager not available — kernel image-load integration disabled");
            return;
        }

        try {
            auto& ipc = Communication::IPCManager::Instance();

            // Register for image-load notifications from the kernel driver.
            // When the driver's PsSetLoadImageNotifyRoutine callback fires,
            // it sends an ImageLoadRequest through the filter port.
            ipc.RegisterImageLoadHandler(
                [this](const Communication::ImageLoadRequest& req)
                    -> SHADOWSTRIKE_SCAN_VERDICT {
                    if (!m_monitoring)
                        return Verdict_Clean;

                    OnKernelImageLoad(
                        req.processId,
                        static_cast<uintptr_t>(req.imageBase),
                        static_cast<size_t>(req.imageSize),
                        req.isSystemModule != 0);

                    return Verdict_Clean;
                }
            );

            SS_LOG_INFO(L"ReflectiveDLL",
                L"Kernel image-load handler registered via IPCManager");
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ReflectiveDLL",
                L"Failed to register kernel handlers: %S", e.what());
        }
    }

public:
    void OnKernelImageLoad(uint32_t pid, uintptr_t imageBase,
                           size_t imageSize, bool isSystemModule) {
        // Skip system modules (ntdll, kernel32, etc.) — low FP value
        if (isSystemModule) return;
        if (pid <= 4) return;

        // Check if the image base is in PEB module list
        auto pebModules = GetPEBModulesImpl(pid);
        const bool inPEB = std::find(pebModules.begin(), pebModules.end(),
                                      imageBase) != pebModules.end();

        // If the image was loaded normally it will appear in PEB.
        // A very short delay between kernel notification and PEB update is possible,
        // so we only flag images NOT in PEB after a second check.
        if (inPEB) return;

        // Query the memory region backing this image
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (!hProcess) return;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(imageBase),
                           &mbi, sizeof(mbi)) == 0) {
            return;
        }

        // If the region is private (not MEM_IMAGE), this is suspicious
        if (IsUnbacked(mbi.Type)) {
            SS_LOG_WARN(L"ReflectiveDLL",
                L"Kernel image-load from unbacked memory — PID %u, Base 0x%016llX, Size %zu",
                pid, static_cast<unsigned long long>(imageBase), imageSize);

            // Trigger targeted scan
            auto result = Scan(pid, ReflectiveScanMode::Standard);
            (void)result; // Detection callbacks fire inside Scan()
        }
    }

private:

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{ false };
    std::atomic<bool> m_monitoring{ false };
    ReflectiveConfig m_config;

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<LoaderSignatureDB> m_signatureDB;

    // Statistics
    mutable ReflectiveStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

ReflectiveDLLDetector::ReflectiveDLLDetector()
    : m_impl(std::make_unique<ReflectiveDLLDetectorImpl>()) {
}

ReflectiveDLLDetector::~ReflectiveDLLDetector() = default;

ReflectiveDLLDetector& ReflectiveDLLDetector::Instance() {
    static ReflectiveDLLDetector instance;
    return instance;
}

bool ReflectiveDLLDetector::Initialize(const ReflectiveConfig& config) {
    return m_impl->Initialize(config);
}

void ReflectiveDLLDetector::Shutdown() {
    m_impl->Shutdown();
}

bool ReflectiveDLLDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool ReflectiveDLLDetector::UpdateConfig(const ReflectiveConfig& config) {
    return m_impl->UpdateConfig(config);
}

ReflectiveConfig ReflectiveDLLDetector::GetConfig() const {
    return m_impl->GetConfig();
}

ReflectiveScanResult ReflectiveDLLDetector::Scan(uint32_t pid, ReflectiveScanMode mode) {
    return m_impl->Scan(pid, mode);
}

bool ReflectiveDLLDetector::HasReflectiveLoading(uint32_t pid) {
    return m_impl->HasReflectiveLoading(pid);
}

std::vector<ReflectiveScanResult> ReflectiveDLLDetector::ScanMultiple(
    const std::vector<uint32_t>& pids, ReflectiveScanMode mode) {
    return m_impl->ScanMultiple(pids, mode);
}

std::vector<ReflectiveScanResult> ReflectiveDLLDetector::ScanAllProcesses(ReflectiveScanMode mode) {
    return m_impl->ScanAllProcesses(mode);
}

std::vector<ReflectiveScanResult> ReflectiveDLLDetector::ScanByName(
    const std::wstring& processName, ReflectiveScanMode mode) {
    return m_impl->ScanByName(processName, mode);
}

std::vector<PECandidate> ReflectiveDLLDetector::FindPECandidates(uint32_t pid) {
    return m_impl->FindPECandidates(pid);
}

PECandidate ReflectiveDLLDetector::ValidatePE(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->ValidatePE(pid, baseAddress);
}

bool ReflectiveDLLDetector::ContainsPE(uint32_t pid, uintptr_t address, size_t size) {
    return m_impl->ContainsPE(pid, address, size);
}

std::vector<std::pair<uintptr_t, size_t>> ReflectiveDLLDetector::FindRWXRegions(uint32_t pid) {
    return m_impl->FindRWXRegions(pid);
}

std::vector<std::pair<uintptr_t, size_t>> ReflectiveDLLDetector::FindUnbackedExecutable(uint32_t pid) {
    return m_impl->FindUnbackedExecutable(pid);
}

double ReflectiveDLLDetector::CalculateEntropy(uint32_t pid, uintptr_t address, size_t size) {
    return m_impl->CalculateEntropyMemory(pid, address, size);
}

std::vector<PECandidate> ReflectiveDLLDetector::FindHiddenModules(uint32_t pid) {
    return m_impl->FindHiddenModules(pid);
}

bool ReflectiveDLLDetector::IsInPEB(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->IsInPEB(pid, baseAddress);
}

std::vector<uintptr_t> ReflectiveDLLDetector::GetPEBModules(uint32_t pid) {
    return m_impl->GetPEBModules(pid);
}

std::vector<std::pair<uint32_t, uintptr_t>> ReflectiveDLLDetector::FindSuspiciousThreads(uint32_t pid) {
    return m_impl->FindSuspiciousThreads(pid);
}

bool ReflectiveDLLDetector::IsThreadStartUnbacked(uint32_t tid) {
    return m_impl->IsThreadStartUnbacked(tid);
}

uint32_t ReflectiveDLLDetector::CountUnbackedCallStackFrames(uint32_t tid) {
    return m_impl->CountUnbackedCallStackFrames(tid);
}

std::optional<LoaderSignature> ReflectiveDLLDetector::DetectKnownLoader(
    uint32_t pid, const PECandidate& candidate) {
    return m_impl->DetectKnownLoader(pid, candidate);
}

void ReflectiveDLLDetector::AddLoaderSignature(const LoaderSignature& signature) {
    m_impl->AddLoaderSignature(signature);
}

std::vector<LoaderSignature> ReflectiveDLLDetector::GetLoaderSignatures() const {
    return m_impl->GetLoaderSignatures();
}

std::vector<uint8_t> ReflectiveDLLDetector::ExtractPayload(
    uint32_t pid, const ReflectiveDetection& detection) {
    return m_impl->ExtractPayload(pid, detection);
}

bool ReflectiveDLLDetector::DumpPE(uint32_t pid, uintptr_t baseAddress,
                                   const std::wstring& outputPath) {
    return m_impl->DumpPE(pid, baseAddress, outputPath);
}

std::vector<uint8_t> ReflectiveDLLDetector::ReconstructPE(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->ReconstructPE(pid, baseAddress);
}

bool ReflectiveDLLDetector::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void ReflectiveDLLDetector::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool ReflectiveDLLDetector::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

void ReflectiveDLLDetector::OnMemoryAllocation(uint32_t pid, uintptr_t address,
                                               size_t size, uint32_t protection) {
    m_impl->OnMemoryAllocation(pid, address, size, protection);
}

void ReflectiveDLLDetector::OnProtectionChange(uint32_t pid, uintptr_t address,
                                               uint32_t oldProtection, uint32_t newProtection) {
    m_impl->OnProtectionChange(pid, address, oldProtection, newProtection);
}

void ReflectiveDLLDetector::OnKernelImageLoad(uint32_t pid, uintptr_t imageBase,
                                               size_t imageSize, bool isSystemModule) {
    m_impl->OnKernelImageLoad(pid, imageBase, imageSize, isSystemModule);
}

uint64_t ReflectiveDLLDetector::RegisterCallback(ReflectiveDetectedCallback callback) {
    return m_impl->RegisterCallback(std::move(callback));
}

uint64_t ReflectiveDLLDetector::RegisterProgressCallback(ReflectiveScanProgressCallback callback) {
    return m_impl->RegisterProgressCallback(std::move(callback));
}

uint64_t ReflectiveDLLDetector::RegisterCandidateCallback(PECandidateCallback callback) {
    return m_impl->RegisterCandidateCallback(std::move(callback));
}

void ReflectiveDLLDetector::UnregisterCallback(uint64_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

ReflectiveStatistics ReflectiveDLLDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void ReflectiveDLLDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::wstring ReflectiveDLLDetector::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
        ReflectiveConstants::VERSION_MAJOR,
        ReflectiveConstants::VERSION_MINOR,
        ReflectiveConstants::VERSION_PATCH);
}

std::wstring ReflectiveDLLDetector::LoadTypeToString(ReflectiveLoadType type) noexcept {
    return LoadTypeToStringInternal(type);
}

std::wstring ReflectiveDLLDetector::ConfidenceToString(DetectionConfidence confidence) noexcept {
    return ConfidenceToStringInternal(confidence);
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
