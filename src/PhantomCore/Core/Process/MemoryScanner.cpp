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
 * ShadowStrike Core Process - MEMORY SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file MemoryScanner.cpp
 * @brief Enterprise-grade volatile memory inspection for malware detection.
 *
 * This module provides comprehensive in-memory threat detection including:
 * - Fileless malware detection (unbacked executable memory)
 * - Reflective DLL injection detection
 * - Shellcode pattern matching (NOP sleds, API hashing, syscalls)
 * - Cobalt Strike beacon detection
 * - Meterpreter stage identification
 * - Process hollowing detection
 * - PE header scanning in non-image memory
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-threaded scanning with ThreadPool integration
 * - VirtualQueryEx-based memory region enumeration
 * - YARA rule integration via PatternStore
 * - Callback architecture for real-time threat notifications
 *
 * Detection Strategy:
 * 1. Enumerate memory regions (VirtualQueryEx walk)
 * 2. Filter by protection flags (prioritize RWX, unbacked executable)
 * 3. Read region contents (ReadProcessMemory)
 * 4. Apply detection layers (YARA → Patterns → Shellcode → PE → Heuristics)
 * 5. Calculate confidence scores and risk assessment
 * 6. Invoke callbacks for detected threats
 *
 * MITRE ATT&CK Coverage:
 * - T1055: Process Injection
 * - T1620: Reflective Code Loading
 * - T1059: Command and Scripting Interpreter
 * - T1106: Native API
 * - T1027: Obfuscated Files or Information
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "MemoryScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// KERNEL SHARED TYPES (for OnKernelMemoryEvent deserialization)
// ============================================================================
#include "../../../../PhantomSensor/Shared/MemoryTypes.h"
#include "../../../../PhantomSensor/Shared/MessageTypes.h"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <tlhelp32.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Shellcode signatures
    const std::vector<std::vector<uint8_t>> NOP_SLEDS = {
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},  // x86 NOP
        {0x66, 0x90},  // 2-byte NOP
        {0x0F, 0x1F, 0x00},  // 3-byte NOP
    };

    // Common shellcode prologues
    const std::vector<std::vector<uint8_t>> SHELLCODE_PATTERNS = {
        // GetPC (CALL $+5 / POP reg)
        {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58},  // call $+5; pop eax
        {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B},  // call $+5; pop ebx
        {0xE8, 0x00, 0x00, 0x00, 0x00, 0x59},  // call $+5; pop ecx

        // x64 GetRIP
        {0x48, 0x8D, 0x05},  // lea rax, [rip+...]

        // Common decoder stubs
        {0xEB, 0x1A, 0x5B},  // jmp short +0x1A; pop ebx (common in encoded shellcode)
        {0xFC, 0xE8},  // cld; call (Metasploit standard)
    };

    // API hashing constants (used in shellcode)
    const std::vector<std::vector<uint8_t>> API_HASH_PATTERNS = {
        // ROL/ROR hashing loops
        {0xC1, 0xC8},  // ror eax, imm8
        {0xC1, 0xC0},  // rol eax, imm8
        {0xD1, 0xC8},  // ror eax, 1
        {0xD1, 0xC0},  // rol eax, 1
    };

    // Syscall stub patterns (direct syscall)
    const std::vector<std::vector<uint8_t>> SYSCALL_PATTERNS = {
        {0x0F, 0x05},  // syscall (x64)
        {0x0F, 0x34},  // sysenter (x86)
        {0xCD, 0x2E},  // int 2Eh (legacy)
    };

    // Cobalt Strike beacon indicators
    const std::vector<std::vector<uint8_t>> BEACON_PATTERNS = {
        // Cobalt Strike default named pipe prefix "\\\\.\\pipe\\msagent_"
        {0x5C, 0x5C, 0x2E, 0x5C, 0x70, 0x69, 0x70, 0x65, 0x5C, 0x6D, 0x73, 0x61, 0x67, 0x65, 0x6E, 0x74, 0x5F},
    };

    // Known C2 framework named pipe patterns (string form for ExtractStrings matching)
    const std::vector<std::string> BEACON_PIPE_PATTERNS = {
        "\\\\.\\pipe\\msagent_",
        "\\\\.\\pipe\\MSSE-",
        "\\\\.\\pipe\\postex_",
        "\\\\.\\pipe\\status_",
    };

    // Meterpreter stage indicators
    const std::vector<std::vector<uint8_t>> METERPRETER_PATTERNS = {
        {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00},  // block_api
        {0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00},  // block_api_direct
        {0xFC, 0xE8, 0x8F, 0x00, 0x00, 0x00},  // reverse TCP stager
    };

    // ROP chain detection constants
    constexpr size_t MIN_ROP_CHAIN_LENGTH = 5;
    constexpr uint8_t RET_OPCODE = 0xC3;

    // Max strings to extract from a single region (anti-DoS)
    constexpr size_t MAX_EXTRACTED_STRINGS = 500;

    // PE header magic numbers
    constexpr uint16_t DOS_SIGNATURE = 0x5A4D;  // "MZ"
    constexpr uint32_t NT_SIGNATURE = 0x00004550;  // "PE\0\0"

    // Evidence preview size
    constexpr size_t EVIDENCE_PREVIEW_SIZE = 256;

    // String extraction
    constexpr size_t MIN_STRING_LENGTH = 4;
    constexpr size_t MAX_STRING_LENGTH = 256;

} // anonymous namespace

// ============================================================================
// CONSTEXPR HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] constexpr const char* MemoryThreatTypeToString(MemoryThreatType type) noexcept {
    switch (type) {
        case MemoryThreatType::None: return "None";
        case MemoryThreatType::Malware: return "Malware";
        case MemoryThreatType::Shellcode: return "Shellcode";
        case MemoryThreatType::ReflectiveDLL: return "Reflective DLL";
        case MemoryThreatType::PEInjection: return "PE Injection";
        case MemoryThreatType::DotNetInMemory: return ".NET In-Memory";
        case MemoryThreatType::CobaltStrikeBeacon: return "Cobalt Strike Beacon";
        case MemoryThreatType::Meterpreter: return "Meterpreter";
        case MemoryThreatType::Empire: return "Empire Agent";
        case MemoryThreatType::Mimikatz: return "Mimikatz";
        case MemoryThreatType::ProcessHollowing: return "Process Hollowing";
        case MemoryThreatType::ModuleStomping: return "Module Stomping";
        case MemoryThreatType::HiddenModule: return "Hidden Module";
        case MemoryThreatType::SuspiciousCode: return "Suspicious Code";
        case MemoryThreatType::EncryptedPayload: return "Encrypted Payload";
        case MemoryThreatType::APIHashing: return "API Hashing Shellcode";
        case MemoryThreatType::SyscallStub: return "Direct Syscall Stub";
        default: return "Unknown";
    }
}

[[nodiscard]] constexpr const char* MemoryThreatToMitre(MemoryThreatType type) noexcept {
    switch (type) {
        case MemoryThreatType::ReflectiveDLL:
        case MemoryThreatType::PEInjection:
        case MemoryThreatType::ProcessHollowing:
        case MemoryThreatType::ModuleStomping:
            return "T1055";  // Process Injection
        case MemoryThreatType::Shellcode:
        case MemoryThreatType::HiddenModule:
            return "T1620";  // Reflective Code Loading
        case MemoryThreatType::SyscallStub:
            return "T1106";  // Native API
        case MemoryThreatType::EncryptedPayload:
            return "T1027";  // Obfuscated Files
        default:
            return "T1055";
    }
}

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

[[nodiscard]] MemoryProtection WindowsProtectionToEnum(uint32_t protect) noexcept {
    // Check PAGE_GUARD first -- guard pages are used in anti-scan evasion
    // and must be detected regardless of the underlying base protection
    if (protect & PAGE_GUARD) return MemoryProtection::Guard;

    // Strip modifier flags to get base protection
    uint32_t baseProtect = protect & 0xFF;

    if (baseProtect == PAGE_NOACCESS) return MemoryProtection::NoAccess;
    if (baseProtect == PAGE_READONLY) return MemoryProtection::ReadOnly;
    if (baseProtect == PAGE_READWRITE) return MemoryProtection::ReadWrite;
    if (baseProtect == PAGE_EXECUTE) return MemoryProtection::ExecuteOnly;
    if (baseProtect == PAGE_EXECUTE_READ) return MemoryProtection::ReadExecute;
    if (baseProtect == PAGE_EXECUTE_READWRITE) return MemoryProtection::ReadWriteExecute;
    if (baseProtect == PAGE_EXECUTE_WRITECOPY) return MemoryProtection::ReadWriteExecute;
    if (baseProtect == PAGE_WRITECOPY) return MemoryProtection::CopyOnWrite;

    return MemoryProtection::NoAccess;
}

[[nodiscard]] bool IsProtectionExecutable(uint32_t protect) noexcept {
    uint32_t baseProtect = protect & 0xFF;
    return (baseProtect == PAGE_EXECUTE ||
            baseProtect == PAGE_EXECUTE_READ ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY);
}

[[nodiscard]] bool IsProtectionWritable(uint32_t protect) noexcept {
    uint32_t baseProtect = protect & 0xFF;
    return (baseProtect == PAGE_READWRITE ||
            baseProtect == PAGE_WRITECOPY ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY);
}

[[nodiscard]] bool IsProtectionRWX(uint32_t protect) noexcept {
    uint32_t baseProtect = protect & 0xFF;
    return (baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY);
}

[[nodiscard]] std::vector<std::pair<std::wstring, uintptr_t>> GetProcessModules(uint32_t pid) noexcept {
    std::vector<std::pair<std::wstring, uintptr_t>> modules;

    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) return modules;

        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess.Get(), hMods, sizeof(hMods), &cbNeeded)) {
            size_t count = cbNeeded / sizeof(HMODULE);
            if (count > std::size(hMods)) count = std::size(hMods);
            for (size_t i = 0; i < count; i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess.Get(), hMods[i], szModName, MAX_PATH)) {
                    modules.emplace_back(szModName, reinterpret_cast<uintptr_t>(hMods[i]));
                }
            }
        }

    } catch (...) {
        // Suppress exceptions -- handle auto-closed by RAII
    }

    return modules;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static bool ContainsPattern(
    std::span<const uint8_t> data,
    const std::vector<uint8_t>& pattern) noexcept {

    if (data.size() < pattern.size()) return false;

    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }

    return false;
}

[[nodiscard]] static size_t CountNOPSled(std::span<const uint8_t> data) noexcept {
    size_t maxNOPs = 0;
    size_t currentNOPs = 0;

    for (uint8_t byte : data) {
        if (byte == 0x90) {
            currentNOPs++;
            maxNOPs = std::max(maxNOPs, currentNOPs);
        } else {
            currentNOPs = 0;
        }
    }

    return maxNOPs;
}

[[nodiscard]] static double CalculateEntropyInternal(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequency{};
    for (uint8_t byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    double dataSize = static_cast<double>(data.size());

    for (uint64_t count : frequency) {
        if (count > 0) {
            double probability = static_cast<double>(count) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

[[nodiscard]] static std::vector<std::string> ExtractStringsInternal(
    std::span<const uint8_t> data,
    size_t minLength) {

    std::vector<std::string> strings;
    std::string current;
    current.reserve(MAX_STRING_LENGTH);

    for (uint8_t byte : data) {
        if (byte >= 0x20 && byte <= 0x7E) {
            if (current.size() < MAX_STRING_LENGTH) {
                current += static_cast<char>(byte);
            }
        } else {
            if (current.length() >= minLength) {
                strings.push_back(std::move(current));
                current = std::string();
                current.reserve(MAX_STRING_LENGTH);
                if (strings.size() >= MAX_EXTRACTED_STRINGS) break;
            } else {
                current.clear();
            }
        }
    }

    // Add final string
    if (strings.size() < MAX_EXTRACTED_STRINGS &&
        current.length() >= minLength && current.length() <= MAX_STRING_LENGTH) {
        strings.push_back(std::move(current));
    }

    return strings;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

struct MemoryScanner::Impl {
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    MemoryScannerConfig m_config;
    MemoryScannerStats m_stats;

    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    PatternStore::PatternIndex* m_patternIndex{ nullptr };
    Core::Engine::EmulationEngine* m_emulationEngine{ nullptr };
    Core::Engine::ThreatDetector* m_threatDetector{ nullptr };

    // Callbacks
    std::unordered_map<uint64_t, MemoryThreatCallback> m_threatCallbacks;
    std::unordered_map<uint64_t, ScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, ScanCompleteCallback> m_completeCallbacks;
    uint64_t m_nextCallbackId{ 0 };

    // YARA rule sources (file paths or inline rule strings) for bookkeeping
    std::vector<std::string> m_yaraRules;

    // Scan ID counter (mutable: ID generation does not affect logical constness)
    mutable std::atomic<uint64_t> m_nextScanId{ 1 };
    mutable std::atomic<uint64_t> m_nextThreatId{ 1 };

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const MemoryScannerConfig& config) {

        std::unique_lock lock(m_mutex);

        try {
            m_threadPool = threadPool;
            m_config = config;
            m_initialized = true;

            SS_LOG_INFO(L"MemoryScanner", L"MemoryScanner initialized (mode=%d, YARA=%d, patterns=%d)",
                static_cast<int>(config.defaultMode),
                static_cast<int>(config.enableYARA),
                static_cast<int>(config.enablePatternMatching));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"MemoryScanner initialization failed: %S", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_threatCallbacks.clear();
            m_progressCallbacks.clear();
            m_completeCallbacks.clear();
            m_yaraRules.clear();

            m_patternIndex = nullptr;
            m_emulationEngine = nullptr;
            m_threatDetector = nullptr;

            m_initialized = false;

            SS_LOG_INFO(L"MemoryScanner", L"MemoryScanner shutdown complete");

        } catch (...) {
            // Suppress all exceptions
        }
    }

    // ========================================================================
    // MEMORY REGION ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<MemoryRegion> EnumerateRegions(uint32_t pid) const {
        std::vector<MemoryRegion> regions;

        try {
            Utils::ProcessUtils::ProcessHandle hProcess(pid,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
            if (!hProcess.IsValid()) {
                SS_LOG_ERROR(L"MemoryScanner", L"Failed to open process %u for enumeration", pid);
                return regions;
            }

            uintptr_t address = 0;
            MEMORY_BASIC_INFORMATION mbi{};

            while (VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                MemoryRegion region;
                region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);

                // State
                if (mbi.State == MEM_COMMIT) region.state = MemoryState::Committed;
                else if (mbi.State == MEM_RESERVE) region.state = MemoryState::Reserved;
                else region.state = MemoryState::Free;

                // Protection
                region.protection = WindowsProtectionToEnum(mbi.Protect);
                region.initialProtection = WindowsProtectionToEnum(mbi.AllocationProtect);

                // Flags
                region.isExecutable = IsProtectionExecutable(mbi.Protect);
                region.isWritable = IsProtectionWritable(mbi.Protect);
                region.isPrivate = (mbi.Type == MEM_PRIVATE);

                // Type
                if (mbi.Type == MEM_IMAGE) {
                    region.type = MemoryType::Image;
                } else if (mbi.Type == MEM_MAPPED) {
                    region.type = MemoryType::Mapped;
                } else if (mbi.Type == MEM_PRIVATE) {
                    region.type = MemoryType::Private;
                } else {
                    region.type = MemoryType::Unknown;
                }

                // Check for suspicious characteristics
                CheckSuspiciousRegion(region);

                regions.push_back(region);

                // Move to next region
                address = region.baseAddress + region.size;

                // Safety limit -- also guard against address wrap-around
                if (address == 0 || address <= region.baseAddress || regions.size() > 100000) break;
            }

            // Handle auto-closed by RAII ProcessHandle

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"EnumerateRegions - Exception: %S", e.what());
        }

        return regions;
    }

    /**
     * @brief Enumerate regions using an already-open process handle.
     *
     * Avoids the double-open problem when the caller already holds a handle.
     */
    [[nodiscard]] std::vector<MemoryRegion> EnumerateRegionsWithHandle(HANDLE hProcess) const {
        std::vector<MemoryRegion> regions;

        try {
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return regions;

            uintptr_t address = 0;
            MEMORY_BASIC_INFORMATION mbi{};

            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                MemoryRegion region;
                region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                region.size = mbi.RegionSize;
                region.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);

                // State
                if (mbi.State == MEM_COMMIT) region.state = MemoryState::Committed;
                else if (mbi.State == MEM_RESERVE) region.state = MemoryState::Reserved;
                else region.state = MemoryState::Free;

                // Protection
                region.protection = WindowsProtectionToEnum(mbi.Protect);
                region.initialProtection = WindowsProtectionToEnum(mbi.AllocationProtect);

                // Flags
                region.isExecutable = IsProtectionExecutable(mbi.Protect);
                region.isWritable = IsProtectionWritable(mbi.Protect);
                region.isPrivate = (mbi.Type == MEM_PRIVATE);

                // Type
                if (mbi.Type == MEM_IMAGE) {
                    region.type = MemoryType::Image;
                } else if (mbi.Type == MEM_MAPPED) {
                    region.type = MemoryType::Mapped;
                } else if (mbi.Type == MEM_PRIVATE) {
                    region.type = MemoryType::Private;
                } else {
                    region.type = MemoryType::Unknown;
                }

                // Check for suspicious characteristics
                CheckSuspiciousRegion(region);

                regions.push_back(region);

                // Move to next region -- guard against address wrap-around
                uintptr_t nextAddress = region.baseAddress + region.size;
                if (nextAddress == 0 || nextAddress <= region.baseAddress || regions.size() > 100000) break;
                address = nextAddress;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"EnumerateRegionsWithHandle - Exception: %S", e.what());
        }

        return regions;
    }

    void CheckSuspiciousRegion(MemoryRegion& region) const noexcept {
        try {
            // Guard pages are used in anti-scan evasion (PAGE_GUARD trap)
            if (region.protection == MemoryProtection::Guard) {
                region.isSuspicious = true;
                region.suspicionReason = "Guard page (anti-scan evasion indicator)";
                return;
            }

            // RWX private memory (highly suspicious)
            if (region.isPrivate && region.isExecutable && region.isWritable) {
                region.isSuspicious = true;
                region.suspicionReason = "RWX private memory";
                return;
            }

            // Large private executable region
            if (region.isPrivate && region.isExecutable &&
                region.size > MemoryScannerConstants::LARGE_PRIVATE_EXEC_THRESHOLD) {
                region.isSuspicious = true;
                region.suspicionReason = "Large private executable region";
                return;
            }

            // Unbacked executable (not image, not mapped)
            if (region.isExecutable && region.type == MemoryType::Private) {
                region.isSuspicious = true;
                region.suspicionReason = "Unbacked executable memory";
                return;
            }

            // Protection escalated from non-exec to exec (W->X transition)
            if (region.isExecutable && region.type == MemoryType::Private &&
                region.initialProtection != MemoryProtection::NoAccess &&
                region.initialProtection != MemoryProtection::ReadExecute &&
                region.initialProtection != MemoryProtection::ReadWriteExecute &&
                region.initialProtection != MemoryProtection::ExecuteOnly) {
                region.isSuspicious = true;
                region.suspicionReason = "Protection escalated to executable (W->X transition)";
                return;
            }

        } catch (...) {
            // Suppress exceptions
        }
    }

    // ========================================================================
    // REGION SCANNING
    // ========================================================================

    [[nodiscard]] RegionScanResult ScanRegionInternal(
        uint32_t pid,
        HANDLE hProcess,
        const MemoryRegion& region,
        const MemoryScannerConfig& cfg) const {

        RegionScanResult result;
        result.region = region;
        result.scanTime = std::chrono::system_clock::now();

        try {
            // Check if should scan
            if (!ShouldScanRegion(region, cfg.defaultMode)) {
                result.scanned = false;
                result.skipReason = "Filtered by scan mode";
                return result;
            }

            // Size check
            if (region.size > cfg.maxRegionSize) {
                result.scanned = false;
                result.skipReason = "Region too large";
                return result;
            }

            if (region.size == 0) {
                result.scanned = false;
                result.skipReason = "Zero-size region";
                return result;
            }

            // Guard pages: reading triggers STATUS_GUARD_PAGE_VIOLATION and
            // consumes the guard status — which would break the target process.
            // Record them as suspicious threats without reading.
            if (region.protection == MemoryProtection::Guard) {
                result.scanned = true;
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::SuspiciousCode;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.matchedRule = "Guard Page (anti-scan evasion)";
                threat.ruleCategory = "Evasion";
                threat.confidence = 55.0;
                threat.riskScore = 60.0;
                threat.mitreTechnique = "T1497";
                threat.details = L"PAGE_GUARD detected — reading would consume guard "
                    L"status and break target. Flagged as evasion indicator.";
                result.threats.push_back(std::move(threat));
                return result;
            }

            // Read memory -- catch bad_alloc for very large regions
            std::vector<uint8_t> buffer;
            try {
                buffer.resize(region.size);
            } catch (const std::bad_alloc&) {
                result.scanned = false;
                result.skipReason = "Allocation failed (region too large for available memory)";
                SS_LOG_WARN(L"MemoryScanner", L"bad_alloc for %zu-byte region at 0x%llX",
                    region.size, static_cast<unsigned long long>(region.baseAddress));
                return result;
            }
            SIZE_T bytesRead = 0;

            if (!ReadProcessMemory(hProcess,
                                  reinterpret_cast<LPCVOID>(region.baseAddress),
                                  buffer.data(),
                                  buffer.size(),
                                  &bytesRead)) {
                result.scanned = false;
                result.skipReason = "Read failed";
                return result;
            }

            buffer.resize(bytesRead);
            result.scanned = true;

            // Calculate entropy
            result.entropy = CalculateEntropyInternal(buffer);

            // Check for PE header
            result.containsPE = ContainsPEInternal(buffer);
            if (result.containsPE && region.type != MemoryType::Image) {
                // PE in non-image memory - critical indicator
                MemoryThreat threat = CreatePEThreat(pid, region, buffer);
                result.threats.push_back(threat);
            }

            // Unified pattern + YARA scanning (single PatternIndex::Search call
            // to avoid duplicate scanning -- both paths use the same index)
            if ((cfg.enableYARA || cfg.enablePatternMatching) && m_patternIndex) {
                auto allMatches = ScanWithPatterns(buffer);
                for (const auto& [matchName, offset] : allMatches) {
                    MemoryThreat threat = CreatePatternThreat(pid, region, matchName, offset);
                    result.patternMatches.emplace_back(matchName, offset);
                    result.threats.push_back(threat);
                }
            }

            // Shellcode detection
            if (cfg.enableShellcodeDetection) {
                auto shellcodeThreats = DetectShellcode(pid, region, buffer);
                result.hasShellcodeIndicators = !shellcodeThreats.empty();
                for (auto& threat : shellcodeThreats) {
                    result.threats.push_back(std::move(threat));
                }
            }

            // High entropy check -- only flag on private executable memory
            // to avoid false positives on compressed resources in image/mapped regions
            if (result.entropy > cfg.entropyThreshold &&
                region.isExecutable && region.type == MemoryType::Private) {
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::EncryptedPayload;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.confidence = 65.0;
                threat.riskScore = 55.0;
                threat.matchedRule = "High Entropy Executable";
                threat.mitreTechnique = "T1027";
                threat.details = L"High-entropy executable private memory (packed/encrypted payload)";

                result.threats.push_back(threat);
            }

            // Cobalt Strike beacon detection
            if (region.isExecutable || region.type == MemoryType::Private) {
                auto beaconThreats = DetectC2Beacon(pid, region, buffer);
                for (auto& threat : beaconThreats) {
                    result.threats.push_back(std::move(threat));
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"ScanRegionInternal - Exception: %S", e.what());
            result.scanned = false;
            result.skipReason = std::string("Exception: ") + e.what();
        }

        return result;
    }

    [[nodiscard]] bool ShouldScanRegion(const MemoryRegion& region, ScanMode mode) const noexcept {
        // Always scan if free
        if (region.state != MemoryState::Committed) return false;

        // Always scan suspicious regions
        if (region.isSuspicious) return true;

        switch (mode) {
            case ScanMode::Quick:
                // Only executable regions
                return region.isExecutable;

            case ScanMode::Normal:
                // Executable + private
                return region.isExecutable || region.isPrivate;

            case ScanMode::Deep:
            case ScanMode::Forensic:
                // All committed memory
                return true;

            default:
                return region.isExecutable;
        }
    }

    // ========================================================================
    // DETECTION METHODS
    // ========================================================================

    [[nodiscard]] bool ContainsPEInternal(std::span<const uint8_t> data) const noexcept {
        try {
            if (data.size() < 64) return false;

            // Check DOS signature (alignment-safe read)
            uint16_t dosSignature = 0;
            std::memcpy(&dosSignature, data.data(), sizeof(dosSignature));
            if (dosSignature != DOS_SIGNATURE) return false;

            // Get PE offset (alignment-safe read)
            uint32_t peOffset = 0;
            std::memcpy(&peOffset, data.data() + 0x3C, sizeof(peOffset));

            // Validate PE offset is sane -- must leave room for at least the PE signature
            if (peOffset < 0x3C || peOffset > data.size() - 4) return false;

            // Check PE signature (alignment-safe read)
            uint32_t peSignature = 0;
            std::memcpy(&peSignature, data.data() + peOffset, sizeof(peSignature));

            return (peSignature == NT_SIGNATURE);

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] std::vector<MemoryThreat> DetectShellcode(
        uint32_t pid,
        const MemoryRegion& region,
        std::span<const uint8_t> data) const {

        std::vector<MemoryThreat> threats;

        try {
            bool hasShellcodeIndicators = false;
            std::string detectionDetails;

            // Check for NOP sled
            size_t nopCount = CountNOPSled(data);
            if (nopCount >= MemoryScannerConstants::MIN_NOP_SLED_LENGTH) {
                hasShellcodeIndicators = true;
                detectionDetails += "NOP sled detected (" + std::to_string(nopCount) + " bytes); ";
            }

            // Check for shellcode patterns
            for (const auto& pattern : SHELLCODE_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    hasShellcodeIndicators = true;
                    detectionDetails += "Shellcode prologue pattern; ";
                    break;
                }
            }

            // Check for API hashing
            bool hasAPIHashing = false;
            for (const auto& pattern : API_HASH_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    hasAPIHashing = true;
                    detectionDetails += "API hashing pattern; ";
                    break;
                }
            }

            // Check for syscall stubs
            bool hasSyscalls = false;
            for (const auto& pattern : SYSCALL_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    hasSyscalls = true;
                    detectionDetails += "Direct syscall stub; ";
                    break;
                }
            }

            // ROP chain detection: look for sequences of short gadgets
            // ending in RET (0xC3) at aligned intervals — indicates a
            // stack-pivot / ROP payload on the heap or in private memory.
            bool hasROPChain = false;
            if (data.size() >= 64 && region.type == MemoryType::Private) {
                size_t consecutiveGadgets = 0;
                size_t maxGadgetRun = 0;
                // Walk the data looking for RET opcodes spaced 2-20 bytes
                // apart — a hallmark of chained gadget addresses that
                // ultimately land on RET-terminated instruction sequences.
                for (size_t i = 0; i < data.size(); ++i) {
                    if (data[i] == RET_OPCODE) {
                        // Check backward for short instruction sequence (2-20 bytes)
                        if (consecutiveGadgets > 0 || (i >= 2 && i + 1 < data.size())) {
                            consecutiveGadgets++;
                            maxGadgetRun = std::max(maxGadgetRun, consecutiveGadgets);
                        }
                    } else if (consecutiveGadgets > 0) {
                        // Allow short gaps between gadgets (2-20 byte instructions)
                        bool inGap = false;
                        for (size_t look = i; look < std::min(i + 20, data.size()); ++look) {
                            if (data[look] == RET_OPCODE) {
                                inGap = true;
                                break;
                            }
                        }
                        if (!inGap) {
                            consecutiveGadgets = 0;
                        }
                    }
                }
                if (maxGadgetRun >= MIN_ROP_CHAIN_LENGTH) {
                    hasROPChain = true;
                    detectionDetails += "ROP chain (" + std::to_string(maxGadgetRun) + " gadgets); ";
                }
            }

            // Create threats based on findings
            if (hasShellcodeIndicators) {
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::Shellcode;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.matchedRule = "Shellcode Pattern";
                threat.confidence = 75.0;
                threat.riskScore = MemoryScannerConstants::SHELLCODE_PATTERN_SCORE;
                threat.mitreTechnique = "T1620";
                threat.details = Utils::StringUtils::ToWide(detectionDetails);

                // Add evidence preview
                size_t previewSize = std::min(data.size(), EVIDENCE_PREVIEW_SIZE);
                threat.evidencePreview.assign(data.begin(), data.begin() + previewSize);

                threats.push_back(threat);
            }

            if (hasAPIHashing) {
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::APIHashing;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.matchedRule = "API Hashing";
                threat.confidence = 70.0;
                threat.riskScore = 75.0;
                threat.mitreTechnique = "T1620";
                threat.details = L"API hashing shellcode technique detected";

                threats.push_back(threat);
            }

            if (hasSyscalls) {
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::SyscallStub;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.matchedRule = "Direct Syscall";
                threat.confidence = 80.0;
                threat.riskScore = 85.0;
                threat.mitreTechnique = "T1106";
                threat.details = L"Direct syscall usage detected (EDR evasion)";

                threats.push_back(threat);
            }

            if (hasROPChain) {
                MemoryThreat threat;
                threat.threatId = m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.threatType = MemoryThreatType::Shellcode;
                threat.processId = pid;
                threat.regionBase = region.baseAddress;
                threat.regionSize = region.size;
                threat.protection = region.protection;
                threat.memoryType = region.type;
                threat.matchedRule = "ROP Chain";
                threat.ruleCategory = "Exploitation";
                threat.confidence = 72.0;
                threat.riskScore = 80.0;
                threat.mitreTechnique = "T1055";
                threat.details = Utils::StringUtils::ToWide(
                    "ROP gadget chain detected in private memory — " + detectionDetails);

                size_t previewSize = std::min(data.size(), EVIDENCE_PREVIEW_SIZE);
                threat.evidencePreview.assign(data.begin(), data.begin() + previewSize);
                threats.push_back(std::move(threat));
            }

        } catch (const std::exception& e) {
        }

        return threats;
    }

    [[nodiscard]] std::vector<MemoryThreat> DetectC2Beacon(
        uint32_t pid,
        const MemoryRegion& region,
        std::span<const uint8_t> data) const {

        std::vector<MemoryThreat> threats;
        if (data.size() < 64) return threats;

        try {
            // --- Cobalt Strike beacon detection ---
            // Check for known beacon pipe name strings in extracted strings
            auto strings = ExtractStringsInternal(data, MIN_STRING_LENGTH);
            for (const auto& str : strings) {
                for (const auto& pipePattern : BEACON_PIPE_PATTERNS) {
                    if (str.find(pipePattern) != std::string::npos) {
                        MemoryThreat threat;
                        threat.threatId = m_nextThreatId++;
                        threat.timestamp = std::chrono::system_clock::now();
                        threat.threatType = MemoryThreatType::CobaltStrikeBeacon;
                        threat.processId = pid;
                        threat.regionBase = region.baseAddress;
                        threat.regionSize = region.size;
                        threat.protection = region.protection;
                        threat.memoryType = region.type;
                        threat.matchedRule = "CobaltStrike Beacon Pipe";
                        threat.ruleCategory = "C2 Framework";
                        threat.confidence = 90.0;
                        threat.riskScore = 95.0;
                        threat.mitreTechnique = "T1071";
                        threat.details = Utils::StringUtils::ToWide(
                            "Cobalt Strike beacon named pipe pattern: " + pipePattern);
                        threats.push_back(std::move(threat));
                        break;
                    }
                }
                if (!threats.empty()) break;  // One beacon detection per region is sufficient
            }

            // Check for beacon config structure (0x0000/0x0001 pairs at 256-byte offsets)
            for (const auto& pattern : BEACON_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    MemoryThreat threat;
                    threat.threatId = m_nextThreatId++;
                    threat.timestamp = std::chrono::system_clock::now();
                    threat.threatType = MemoryThreatType::CobaltStrikeBeacon;
                    threat.processId = pid;
                    threat.regionBase = region.baseAddress;
                    threat.regionSize = region.size;
                    threat.protection = region.protection;
                    threat.memoryType = region.type;
                    threat.matchedRule = "CobaltStrike Beacon Config";
                    threat.ruleCategory = "C2 Framework";
                    threat.confidence = 85.0;
                    threat.riskScore = 92.0;
                    threat.mitreTechnique = "T1071";
                    threat.details = L"Cobalt Strike beacon configuration structure detected";

                    size_t previewSize = std::min(data.size(), EVIDENCE_PREVIEW_SIZE);
                    threat.evidencePreview.assign(data.begin(), data.begin() + previewSize);
                    threats.push_back(std::move(threat));
                    break;
                }
            }

            // --- Meterpreter detection ---
            for (const auto& pattern : METERPRETER_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    MemoryThreat threat;
                    threat.threatId = m_nextThreatId++;
                    threat.timestamp = std::chrono::system_clock::now();
                    threat.threatType = MemoryThreatType::Meterpreter;
                    threat.processId = pid;
                    threat.regionBase = region.baseAddress;
                    threat.regionSize = region.size;
                    threat.protection = region.protection;
                    threat.memoryType = region.type;
                    threat.matchedRule = "Meterpreter Stage";
                    threat.ruleCategory = "C2 Framework";
                    threat.confidence = 88.0;
                    threat.riskScore = 90.0;
                    threat.mitreTechnique = "T1055";
                    threat.details = L"Meterpreter reflective loader stage detected";

                    size_t previewSize = std::min(data.size(), EVIDENCE_PREVIEW_SIZE);
                    threat.evidencePreview.assign(data.begin(), data.begin() + previewSize);
                    threats.push_back(std::move(threat));
                    break;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"DetectC2Beacon - Exception: %S", e.what());
        }

        return threats;
    }

    [[nodiscard]] MemoryThreat CreatePEThreat(
        uint32_t pid,
        const MemoryRegion& region,
        std::span<const uint8_t> data) const {

        MemoryThreat threat;
        threat.threatId = m_nextThreatId++;
        threat.timestamp = std::chrono::system_clock::now();
        threat.threatType = MemoryThreatType::PEInjection;
        threat.processId = pid;
        threat.regionBase = region.baseAddress;
        threat.regionSize = region.size;
        threat.protection = region.protection;
        threat.memoryType = region.type;
        threat.matchedRule = "PE Header in Non-Image Memory";
        threat.ruleCategory = "Reflective Loading";
        threat.confidence = 95.0;
        threat.riskScore = MemoryScannerConstants::PE_IN_MEMORY_SCORE;
        threat.mitreTechnique = "T1620";
        threat.details = L"PE executable found in non-image memory (reflective DLL injection)";

        // Parse PE info
        threat.peInfo = ParsePEInternal(data);

        // Add evidence preview
        size_t previewSize = std::min(data.size(), EVIDENCE_PREVIEW_SIZE);
        threat.evidencePreview.assign(data.begin(), data.begin() + previewSize);

        return threat;
    }

    [[nodiscard]] MemoryThreat::PEInfo ParsePEInternal(std::span<const uint8_t> data) const noexcept {
        MemoryThreat::PEInfo peInfo;

        try {
            if (data.size() < 64) return peInfo;

            // DOS header -- alignment-safe PE offset read
            uint32_t peOffset = 0;
            std::memcpy(&peOffset, data.data() + 0x3C, sizeof(peOffset));

            // Need at least PE sig (4) + FileHeader (20) + OptionalHeader magic (2)
            constexpr size_t kMinPESize = 4 + 20 + 2;
            if (peOffset < 0x3C || peOffset > data.size() - kMinPESize) return peInfo;

            const uint8_t* peBase = data.data() + peOffset;

            // Validate PE signature
            uint32_t peSig = 0;
            std::memcpy(&peSig, peBase, sizeof(peSig));
            if (peSig != NT_SIGNATURE) return peInfo;

            // File header is at peBase+4
            const uint8_t* fileHdr = peBase + 4;
            uint16_t machine = 0;
            uint16_t characteristics = 0;
            std::memcpy(&machine, fileHdr + 0, sizeof(machine));
            std::memcpy(&characteristics, fileHdr + 18, sizeof(characteristics));

            // Optional header starts at peBase + 4 + 20 = peBase + 24
            const uint8_t* optHdr = peBase + 24;

            // Read optional header magic to discriminate PE32 vs PE32+
            uint16_t optMagic = 0;
            std::memcpy(&optMagic, optHdr, sizeof(optMagic));

            if (optMagic == 0x10B) {
                // PE32 (32-bit)
                constexpr size_t kPE32OptHdrSize = 96;  // standard fields only
                if (peOffset + 24 + kPE32OptHdrSize > data.size()) return peInfo;

                uint32_t entryPoint32 = 0, imageBase32 = 0, imageSize32 = 0;
                std::memcpy(&entryPoint32, optHdr + 16, sizeof(entryPoint32));
                std::memcpy(&imageBase32, optHdr + 28, sizeof(imageBase32));
                std::memcpy(&imageSize32, optHdr + 56, sizeof(imageSize32));

                peInfo.entryPoint = entryPoint32;
                peInfo.imageBase = imageBase32;
                peInfo.imageSize = imageSize32;
            } else if (optMagic == 0x20B) {
                // PE32+ (64-bit)
                constexpr size_t kPE32PlusOptHdrSize = 112;  // standard fields only
                if (peOffset + 24 + kPE32PlusOptHdrSize > data.size()) return peInfo;

                uint32_t entryPoint32 = 0, imageSize32 = 0;
                uint64_t imageBase64 = 0;
                std::memcpy(&entryPoint32, optHdr + 16, sizeof(entryPoint32));
                std::memcpy(&imageBase64, optHdr + 24, sizeof(imageBase64));
                std::memcpy(&imageSize32, optHdr + 56, sizeof(imageSize32));

                peInfo.entryPoint = entryPoint32;
                peInfo.imageBase = static_cast<uintptr_t>(imageBase64);
                peInfo.imageSize = imageSize32;
            } else {
                // Unknown optional header magic -- not a valid PE
                return peInfo;
            }

            peInfo.machine = machine;
            peInfo.characteristics = characteristics;
            peInfo.valid = true;

        } catch (...) {
            peInfo.valid = false;
        }

        return peInfo;
    }

    [[nodiscard]] MemoryThreat CreateYARAThreat(
        uint32_t pid,
        const MemoryRegion& region,
        const std::string& rule,
        size_t offset) const {

        MemoryThreat threat;
        threat.threatId = m_nextThreatId++;
        threat.timestamp = std::chrono::system_clock::now();
        threat.threatType = MemoryThreatType::Malware;
        threat.processId = pid;
        threat.regionBase = region.baseAddress;
        threat.regionSize = region.size;
        threat.detectionOffset = offset;
        threat.protection = region.protection;
        threat.memoryType = region.type;
        threat.matchedRule = rule;
        threat.ruleCategory = "YARA";
        threat.confidence = 85.0;
        threat.riskScore = MemoryScannerConstants::YARA_MATCH_SCORE;
        threat.mitreTechnique = "T1055";
        threat.details = Utils::StringUtils::ToWide("YARA rule matched: " + rule);

        return threat;
    }

    [[nodiscard]] MemoryThreat CreatePatternThreat(
        uint32_t pid,
        const MemoryRegion& region,
        const std::string& pattern,
        size_t offset) const {

        MemoryThreat threat;
        threat.threatId = m_nextThreatId++;
        threat.timestamp = std::chrono::system_clock::now();
        threat.threatType = MemoryThreatType::Malware;
        threat.processId = pid;
        threat.regionBase = region.baseAddress;
        threat.regionSize = region.size;
        threat.detectionOffset = offset;
        threat.protection = region.protection;
        threat.memoryType = region.type;
        threat.matchedRule = pattern;
        threat.ruleCategory = "Pattern";
        threat.confidence = 80.0;
        threat.riskScore = 70.0;
        threat.mitreTechnique = "T1055";
        threat.details = Utils::StringUtils::ToWide("Malware pattern matched: " + pattern);

        return threat;
    }

    [[nodiscard]] std::vector<std::pair<std::string, size_t>> ScanWithYARA(
        std::span<const uint8_t> data) const {

        std::vector<std::pair<std::string, size_t>> matches;

        // YARA scanning is delegated to the PatternIndex infrastructure.
        // When YARA rules are loaded into the PatternStore via ImportFromYaraFile,
        // they are compiled into the same pattern index used by ScanWithPatterns.
        // This method provides a secondary scan path for dynamically loaded rules.
        if (!m_patternIndex) {
            SS_LOG_DEBUG(L"MemoryScanner", L"YARA scan skipped: no PatternIndex configured");
            return matches;
        }

        try {
            // Use PatternIndex::Search which covers both YARA-imported and
            // natively-added patterns in the compiled trie
            auto detections = m_patternIndex->Search(data);

            for (const auto& det : detections) {
                // Cap matches per region to prevent unbounded allocation
                if (matches.size() >= MemoryScannerConstants::MAX_YARA_MATCHES_PER_REGION) {
                    SS_LOG_WARN(L"MemoryScanner",
                        L"YARA match cap reached (%zu) on %zu-byte region",
                        MemoryScannerConstants::MAX_YARA_MATCHES_PER_REGION, data.size());
                    break;
                }
                matches.emplace_back(det.signatureName, static_cast<size_t>(det.fileOffset));
            }

            if (!matches.empty()) {
                SS_LOG_DEBUG(L"MemoryScanner", L"YARA scan on %zu bytes: %zu matches",
                    data.size(), matches.size());
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"ScanWithYARA - Exception: %S", e.what());
        }

        return matches;
    }

    [[nodiscard]] std::vector<std::pair<std::string, size_t>> ScanWithPatterns(
        std::span<const uint8_t> data) const {

        std::vector<std::pair<std::string, size_t>> matches;

        try {
            if (!m_patternIndex) return matches;

            auto detections = m_patternIndex->Search(data);

            for (const auto& det : detections) {
                if (matches.size() >= MemoryScannerConstants::MAX_YARA_MATCHES_PER_REGION) break;
                matches.emplace_back(det.signatureName, static_cast<size_t>(det.fileOffset));
            }

            if (!matches.empty()) {
                SS_LOG_DEBUG(L"MemoryScanner", L"Pattern scan on %zu bytes: %zu matches",
                    data.size(), matches.size());
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"ScanWithPatterns - Exception: %S", e.what());
        }

        return matches;
    }

    // ========================================================================
    // PROCESS SCANNING
    // ========================================================================

    [[nodiscard]] MemoryScanResult ScanProcessMemory(uint32_t pid, ScanMode mode) {
        auto startTime = std::chrono::steady_clock::now();

        MemoryScanResult result;
        result.scanId = m_nextScanId++;
        result.processId = pid;
        result.scanMode = mode;
        result.startTime = std::chrono::system_clock::now();

        // Snapshot config under lock to avoid TOCTOU race with UpdateConfig
        MemoryScannerConfig configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            if (!m_initialized) {
                result.completed = false;
                result.errorMessage = L"Scanner not initialized";
                SS_LOG_WARN(L"MemoryScanner", L"ScanProcessMemory called before initialization");
                return result;
            }
            configSnapshot = m_config;
        }

        const auto scanTimeout = std::chrono::milliseconds(configSnapshot.scanTimeoutMs);

        try {
            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
            m_stats.processesScanned.fetch_add(1, std::memory_order_relaxed);

            // Get process name
            auto optName = Utils::ProcessUtils::GetProcessName(pid);
            result.processName = optName.value_or(L"<unknown>");

            // Open process -- single RAII handle used for both enumeration and scanning
            Utils::ProcessUtils::ProcessHandle hProcess(pid,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
            if (!hProcess.IsValid()) {
                result.completed = false;
                result.errorMessage = L"Failed to open process";
                SS_LOG_ERROR(L"MemoryScanner", L"Failed to open process %u for scanning", pid);
                return result;
            }

            // Enumerate regions using our open handle directly
            auto regions = EnumerateRegionsWithHandle(hProcess.Get());
            result.totalRegions = regions.size();

            SS_LOG_INFO(L"MemoryScanner", L"Scanning process %u (%zu regions, mode=%d)",
                pid, regions.size(), static_cast<int>(mode));

            // Scan regions with timeout enforcement
            size_t scannedCount = 0;
            size_t totalBytesAccum = 0;
            for (const auto& region : regions) {
                // Enforce scan timeout
                auto elapsed = std::chrono::steady_clock::now() - startTime;
                if (elapsed >= scanTimeout) {
                    SS_LOG_WARN(L"MemoryScanner",
                        L"Scan timeout (%u ms) reached for process %u after %zu regions",
                        configSnapshot.scanTimeoutMs, pid, scannedCount);
                    result.errorMessage = L"Scan timeout reached";
                    break;
                }

                // Enforce per-process byte cap
                if (totalBytesAccum >= configSnapshot.maxScanSizePerProcess) {
                    SS_LOG_WARN(L"MemoryScanner",
                        L"Per-process scan cap (%zu bytes) reached for process %u",
                        configSnapshot.maxScanSizePerProcess, pid);
                    break;
                }

                // Progress callback
                InvokeProgressCallbacks(pid, scannedCount, regions.size());

                // Scan region
                auto regionResult = ScanRegionInternal(pid, hProcess.Get(), region, configSnapshot);

                if (regionResult.scanned) {
                    result.regionsScanned++;
                    result.bytesScanned += region.size;
                    totalBytesAccum += region.size;
                    m_stats.regionsScanned.fetch_add(1, std::memory_order_relaxed);
                    m_stats.bytesScanned.fetch_add(region.size, std::memory_order_relaxed);

                    // Collect threats
                    for (auto& threat : regionResult.threats) {
                        threat.processName = result.processName;

                        if (threat.confidence >= configSnapshot.minReportConfidence) {
                            result.threats.push_back(threat);
                            result.threatsFound++;
                            result.threatsByType[threat.threatType]++;
                            m_stats.threatsFound.fetch_add(1, std::memory_order_relaxed);

                            // Update per-type stats
                            switch (threat.threatType) {
                                case MemoryThreatType::Shellcode:
                                case MemoryThreatType::APIHashing:
                                case MemoryThreatType::SyscallStub:
                                    m_stats.shellcodeDetections.fetch_add(1, std::memory_order_relaxed);
                                    break;
                                case MemoryThreatType::PEInjection:
                                case MemoryThreatType::ReflectiveDLL:
                                case MemoryThreatType::ProcessHollowing:
                                case MemoryThreatType::ModuleStomping:
                                    m_stats.peDetections.fetch_add(1, std::memory_order_relaxed);
                                    break;
                                case MemoryThreatType::Malware:
                                    if (threat.ruleCategory == "YARA" || threat.ruleCategory == "Pattern")
                                        m_stats.patternMatches.fetch_add(1, std::memory_order_relaxed);
                                    break;
                                default:
                                    break;
                            }

                            // Invoke threat callbacks
                            InvokeThreatCallbacks(threat);
                        }
                    }

                    // Store in forensic mode
                    if (mode == ScanMode::Forensic) {
                        result.regionResults.push_back(regionResult);
                    }

                    // Track suspicious regions
                    if (region.isSuspicious) {
                        result.suspiciousRegions.push_back(region);
                    }
                } else {
                    result.regionsSkipped++;
                }

                scannedCount++;
            }

            // Handle auto-closed by RAII ProcessHandle

            // Calculate overall risk score
            result.overallRiskScore = CalculateOverallRisk(result);

            result.completed = true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"ScanProcessMemory - Exception: %S", e.what());
            result.completed = false;
            result.errorMessage = Utils::StringUtils::ToWide(e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
        }

        auto endTime = std::chrono::steady_clock::now();
        result.endTime = std::chrono::system_clock::now();
        result.totalScanTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();

        // Update average scan time with exponential moving average to avoid
        // integer overflow and multi-thread races on the read-modify-write.
        // EMA weight: newAvg = (old * 7 + current) / 8
        uint64_t currentAvg = m_stats.avgScanTimeMs.load(std::memory_order_relaxed);
        uint64_t ema = (currentAvg * 7 + result.totalScanTimeMs) / 8;
        m_stats.avgScanTimeMs.store(ema, std::memory_order_relaxed);

        // Invoke complete callbacks
        InvokeCompleteCallbacks(result);

        SS_LOG_INFO(L"MemoryScanner", L"Process %u scan complete: %zu threats found in %zu regions (%llu ms)",
            pid,
            result.threatsFound,
            result.regionsScanned,
            static_cast<unsigned long long>(result.totalScanTimeMs));

        return result;
    }

    [[nodiscard]] double CalculateOverallRisk(const MemoryScanResult& result) const noexcept {
        if (result.threatsFound == 0) return 0.0;

        double maxRisk = 0.0;
        double avgRisk = 0.0;

        for (const auto& threat : result.threats) {
            maxRisk = std::max(maxRisk, threat.riskScore);
            avgRisk += threat.riskScore;
        }

        if (result.threatsFound > 0) {
            avgRisk /= result.threatsFound;
        }

        // Weight: 70% max, 30% average
        return (maxRisk * 0.7) + (avgRisk * 0.3);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeThreatCallbacks(const MemoryThreat& threat) {
        // Copy callbacks under lock to avoid deadlock if a callback
        // calls back into the scanner (e.g., RegisterThreatCallback)
        std::vector<MemoryThreatCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_threatCallbacks.size());
            for (const auto& [id, callback] : m_threatCallbacks) {
                if (callback) callbacksCopy.push_back(callback);
            }
        }

        for (const auto& callback : callbacksCopy) {
            try {
                callback(threat);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"MemoryScanner", L"InvokeThreatCallbacks - callback threw: %S", e.what());
            }
        }
    }

    void InvokeProgressCallbacks(uint32_t pid, size_t current, size_t total) {
        std::vector<ScanProgressCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_progressCallbacks.size());
            for (const auto& [id, callback] : m_progressCallbacks) {
                if (callback) callbacksCopy.push_back(callback);
            }
        }

        for (const auto& callback : callbacksCopy) {
            try {
                callback(pid, current, total);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"MemoryScanner", L"InvokeProgressCallbacks - callback threw: %S", e.what());
            }
        }
    }

    void InvokeCompleteCallbacks(const MemoryScanResult& result) {
        std::vector<ScanCompleteCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_completeCallbacks.size());
            for (const auto& [id, callback] : m_completeCallbacks) {
                if (callback) callbacksCopy.push_back(callback);
            }
        }

        for (const auto& callback : callbacksCopy) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"MemoryScanner", L"InvokeCompleteCallbacks - callback threw: %S", e.what());
            }
        }
    }

    // ========================================================================
    // ANALYSIS METHODS
    // ========================================================================

    [[nodiscard]] ShellcodeAnalysis AnalyzeForShellcode(std::span<const uint8_t> data) const {
        ShellcodeAnalysis analysis;

        try {
            if (data.size() < MemoryScannerConstants::MIN_SHELLCODE_SIZE) {
                return analysis;
            }

            int indicators = 0;

            // Check for NOP sled
            analysis.nopSledLength = CountNOPSled(data);
            if (analysis.nopSledLength >= MemoryScannerConstants::MIN_NOP_SLED_LENGTH) {
                analysis.hasNOPSled = true;
                indicators += 2;
            }

            // Check for shellcode patterns (GetPC, etc.)
            for (const auto& pattern : SHELLCODE_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    analysis.hasGetPC = true;
                    indicators += 3;
                    break;
                }
            }

            // Check for API hashing
            for (const auto& pattern : API_HASH_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    analysis.hasAPIHashing = true;
                    analysis.apiHashAlgorithm = "ROL/ROR";
                    indicators += 2;
                    break;
                }
            }

            // Check for syscalls
            for (const auto& pattern : SYSCALL_PATTERNS) {
                if (ContainsPattern(data, pattern)) {
                    analysis.hasSyscallStubs = true;
                    indicators += 2;
                    break;
                }
            }

            // Determine architecture (simplified)
            if (data.size() >= 4) {
                bool has64Bit = ContainsPattern(data, {0x48, 0x8D});  // lea rax
                analysis.architecture = has64Bit ? "x64" : "x86";
            }

            // Calculate confidence
            if (indicators >= 5) {
                analysis.isShellcode = true;
                analysis.confidence = std::min(90.0, indicators * 15.0);
            } else if (indicators >= 3) {
                analysis.isShellcode = true;
                analysis.confidence = indicators * 20.0;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MemoryScanner", L"AnalyzeForShellcode - Exception: %S", e.what());
        }

        return analysis;
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

MemoryScanner& MemoryScanner::Instance() {
    static MemoryScanner instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

MemoryScanner::MemoryScanner()
    : m_impl(std::make_unique<Impl>()) {
    SS_LOG_INFO(L"MemoryScanner", L"MemoryScanner instance created");
}

MemoryScanner::~MemoryScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"MemoryScanner", L"MemoryScanner instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool MemoryScanner::Initialize() {
    auto config = MemoryScannerConfig::CreateDefault();
    return m_impl->Initialize(nullptr, config);
}

bool MemoryScanner::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    auto config = MemoryScannerConfig::CreateDefault();
    return m_impl->Initialize(threadPool, config);
}

bool MemoryScanner::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const MemoryScannerConfig& config) {
    return m_impl->Initialize(threadPool, config);
}

void MemoryScanner::Shutdown() {
    m_impl->Shutdown();
}

void MemoryScanner::UpdateConfig(const MemoryScannerConfig& config) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
}

MemoryScannerConfig MemoryScanner::GetConfig() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ========================================================================
// PROCESS SCANNING
// ========================================================================

MemoryScanResult MemoryScanner::ScanProcessMemory(uint32_t pid) {
    ScanMode mode;
    {
        std::shared_lock lock(m_impl->m_mutex);
        mode = m_impl->m_config.defaultMode;
    }
    return m_impl->ScanProcessMemory(pid, mode);
}

MemoryScanResult MemoryScanner::ScanProcessMemory(uint32_t pid, ScanMode mode) {
    return m_impl->ScanProcessMemory(pid, mode);
}

uint32_t MemoryScanner::ScanProcessMemory(
    uint32_t pid,
    std::function<void(const std::string& rule, uintptr_t addr)> matchCallback) {

    // Snapshot scan mode under lock to avoid TOCTOU with UpdateConfig
    ScanMode mode;
    {
        std::shared_lock lock(m_impl->m_mutex);
        mode = m_impl->m_config.defaultMode;
    }
    auto result = m_impl->ScanProcessMemory(pid, mode);

    if (matchCallback) {
        for (const auto& threat : result.threats) {
            matchCallback(threat.matchedRule, threat.regionBase);
        }
    }

    // Clamp to UINT32_MAX to avoid silent truncation
    return static_cast<uint32_t>(std::min<size_t>(result.threatsFound, UINT32_MAX));
}

std::vector<MemoryScanResult> MemoryScanner::ScanProcesses(const std::vector<uint32_t>& pids) {
    std::vector<MemoryScanResult> results;
    results.reserve(pids.size());

    // Use the thread pool for parallel scanning when available
    std::shared_ptr<Utils::ThreadPool> pool;
    {
        std::shared_lock lock(m_impl->m_mutex);
        pool = m_impl->m_threadPool;
    }

    if (pool && pids.size() > 1) {
        std::vector<std::shared_future<MemoryScanResult>> futures;
        futures.reserve(pids.size());

        for (uint32_t pid : pids) {
            futures.push_back(pool->Submit(
                [this, pid](const Utils::TaskContext&) -> MemoryScanResult {
                    return ScanProcessMemory(pid);
                }));
        }

        for (auto& fut : futures) {
            try {
                results.push_back(fut.get());
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"MemoryScanner",
                    L"ScanProcesses - future threw: %S", e.what());
            }
        }
    } else {
        for (uint32_t pid : pids) {
            results.push_back(ScanProcessMemory(pid));
        }
    }

    return results;
}

std::vector<MemoryScanResult> MemoryScanner::ScanAllProcesses() {
    std::vector<MemoryScanResult> results;

    try {
        std::vector<Utils::ProcessUtils::ProcessId> pids;
        if (!Utils::ProcessUtils::EnumerateProcesses(pids)) {
            SS_LOG_ERROR(L"MemoryScanner", L"Failed to enumerate processes");
            return results;
        }
        SS_LOG_INFO(L"MemoryScanner", L"Scanning %zu processes",
            pids.size());

        for (uint32_t pid : pids) {
            if (pid == 0 || pid == 4) continue;  // Skip System/Idle
            results.push_back(ScanProcessMemory(pid));
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"ScanAllProcesses - Exception: %S", e.what());
    }

    return results;
}

// ========================================================================
// REGION SCANNING
// ========================================================================

bool MemoryScanner::ScanRegion(uint32_t pid, uintptr_t baseAddress, size_t size) {
    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) return false;

        // Query real protection/type metadata instead of synthetic defaults
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(baseAddress),
                            &mbi, sizeof(mbi))) {
            SS_LOG_WARN(L"MemoryScanner", L"VirtualQueryEx failed for 0x%llX in PID %u",
                static_cast<unsigned long long>(baseAddress), pid);
            return false;
        }

        MemoryRegion region;
        region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        region.size = (size > 0) ? size : mbi.RegionSize;
        region.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        region.state = (mbi.State == MEM_COMMIT) ? MemoryState::Committed :
                       (mbi.State == MEM_RESERVE) ? MemoryState::Reserved : MemoryState::Free;
        region.protection = WindowsProtectionToEnum(mbi.Protect);
        region.initialProtection = WindowsProtectionToEnum(mbi.AllocationProtect);
        region.isExecutable = IsProtectionExecutable(mbi.Protect);
        region.isWritable = IsProtectionWritable(mbi.Protect);
        region.isPrivate = (mbi.Type == MEM_PRIVATE);
        region.type = (mbi.Type == MEM_IMAGE) ? MemoryType::Image :
                      (mbi.Type == MEM_MAPPED) ? MemoryType::Mapped :
                      (mbi.Type == MEM_PRIVATE) ? MemoryType::Private : MemoryType::Unknown;
        m_impl->CheckSuspiciousRegion(region);

        MemoryScannerConfig cfg;
        {
            std::shared_lock lock(m_impl->m_mutex);
            cfg = m_impl->m_config;
        }
        auto result = m_impl->ScanRegionInternal(pid, hProcess.Get(), region, cfg);

        return !result.threats.empty();

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"ScanRegion - Exception: %S", e.what());
        return false;
    }
}

RegionScanResult MemoryScanner::ScanRegionDetailed(
    uint32_t pid,
    uintptr_t baseAddress,
    size_t size) {

    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) {
            RegionScanResult result;
            result.scanned = false;
            result.skipReason = "Failed to open process";
            return result;
        }

        // Query real protection/type metadata
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(baseAddress),
                            &mbi, sizeof(mbi))) {
            RegionScanResult result;
            result.scanned = false;
            result.skipReason = "VirtualQueryEx failed";
            return result;
        }

        MemoryRegion region;
        region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        region.size = (size > 0) ? size : mbi.RegionSize;
        region.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        region.state = (mbi.State == MEM_COMMIT) ? MemoryState::Committed :
                       (mbi.State == MEM_RESERVE) ? MemoryState::Reserved : MemoryState::Free;
        region.protection = WindowsProtectionToEnum(mbi.Protect);
        region.initialProtection = WindowsProtectionToEnum(mbi.AllocationProtect);
        region.isExecutable = IsProtectionExecutable(mbi.Protect);
        region.isWritable = IsProtectionWritable(mbi.Protect);
        region.isPrivate = (mbi.Type == MEM_PRIVATE);
        region.type = (mbi.Type == MEM_IMAGE) ? MemoryType::Image :
                      (mbi.Type == MEM_MAPPED) ? MemoryType::Mapped :
                      (mbi.Type == MEM_PRIVATE) ? MemoryType::Private : MemoryType::Unknown;
        m_impl->CheckSuspiciousRegion(region);

        MemoryScannerConfig cfg;
        {
            std::shared_lock lock(m_impl->m_mutex);
            cfg = m_impl->m_config;
        }
        return m_impl->ScanRegionInternal(pid, hProcess.Get(), region, cfg);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"ScanRegionDetailed - Exception: %S", e.what());
        RegionScanResult result;
        result.scanned = false;
        result.skipReason = e.what();
        return result;
    }
}

std::vector<MemoryThreat> MemoryScanner::ScanBuffer(
    std::span<const uint8_t> data,
    uintptr_t virtualAddress) {

    std::vector<MemoryThreat> threats;

    try {
        MemoryRegion fakeRegion;
        fakeRegion.baseAddress = virtualAddress;
        fakeRegion.size = data.size();
        fakeRegion.type = MemoryType::Private;
        fakeRegion.isPrivate = true;
        fakeRegion.isExecutable = true;
        fakeRegion.state = MemoryState::Committed;

        // Shellcode detection
        auto shellcodeThreats = m_impl->DetectShellcode(0, fakeRegion, data);
        threats.insert(threats.end(),
            std::make_move_iterator(shellcodeThreats.begin()),
            std::make_move_iterator(shellcodeThreats.end()));

        // PE detection
        if (m_impl->ContainsPEInternal(data)) {
            threats.push_back(m_impl->CreatePEThreat(0, fakeRegion, data));
        }

        // Pattern/YARA matching (uses the same PatternIndex as process scans)
        if (m_impl->m_patternIndex) {
            auto matches = m_impl->ScanWithPatterns(data);
            for (const auto& [matchName, offset] : matches) {
                threats.push_back(m_impl->CreatePatternThreat(0, fakeRegion, matchName, offset));
            }
        }

        // C2 beacon detection
        auto beaconThreats = m_impl->DetectC2Beacon(0, fakeRegion, data);
        threats.insert(threats.end(),
            std::make_move_iterator(beaconThreats.begin()),
            std::make_move_iterator(beaconThreats.end()));

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"ScanBuffer - Exception: %S", e.what());
    }

    return threats;
}

// ========================================================================
// REGION ENUMERATION
// ========================================================================

std::vector<MemoryRegion> MemoryScanner::EnumerateRegions(uint32_t pid) const {
    return m_impl->EnumerateRegions(pid);
}

std::vector<MemoryRegion> MemoryScanner::EnumerateExecutableRegions(uint32_t pid) const {
    auto allRegions = m_impl->EnumerateRegions(pid);
    std::vector<MemoryRegion> executable;

    for (const auto& region : allRegions) {
        if (region.isExecutable && region.state == MemoryState::Committed) {
            executable.push_back(region);
        }
    }

    return executable;
}

std::vector<MemoryRegion> MemoryScanner::EnumerateSuspiciousRegions(uint32_t pid) const {
    auto allRegions = m_impl->EnumerateRegions(pid);
    std::vector<MemoryRegion> suspicious;

    for (const auto& region : allRegions) {
        if (region.isSuspicious) {
            suspicious.push_back(region);
        }
    }

    return suspicious;
}

std::optional<MemoryRegion> MemoryScanner::GetRegionInfo(uint32_t pid, uintptr_t address) const {
    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess.IsValid()) return std::nullopt;

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(hProcess.Get(), reinterpret_cast<LPCVOID>(address),
                            &mbi, sizeof(mbi))) {
            return std::nullopt;
        }

        MemoryRegion region;
        region.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        region.size = mbi.RegionSize;
        region.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        region.state = (mbi.State == MEM_COMMIT) ? MemoryState::Committed :
                       (mbi.State == MEM_RESERVE) ? MemoryState::Reserved : MemoryState::Free;
        region.protection = WindowsProtectionToEnum(mbi.Protect);
        region.initialProtection = WindowsProtectionToEnum(mbi.AllocationProtect);
        region.isExecutable = IsProtectionExecutable(mbi.Protect);
        region.isWritable = IsProtectionWritable(mbi.Protect);
        region.isPrivate = (mbi.Type == MEM_PRIVATE);
        region.type = (mbi.Type == MEM_IMAGE) ? MemoryType::Image :
                      (mbi.Type == MEM_MAPPED) ? MemoryType::Mapped :
                      (mbi.Type == MEM_PRIVATE) ? MemoryType::Private : MemoryType::Unknown;
        m_impl->CheckSuspiciousRegion(region);

        return region;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"GetRegionInfo - Exception: %S", e.what());
        return std::nullopt;
    }
}

// ========================================================================
// ANALYSIS
// ========================================================================

ShellcodeAnalysis MemoryScanner::AnalyzeForShellcode(std::span<const uint8_t> data) const {
    return m_impl->AnalyzeForShellcode(data);
}

bool MemoryScanner::ContainsPE(std::span<const uint8_t> data) const {
    return m_impl->ContainsPEInternal(data);
}

std::optional<MemoryThreat::PEInfo> MemoryScanner::ParsePE(std::span<const uint8_t> data) const {
    auto peInfo = m_impl->ParsePEInternal(data);
    if (peInfo.valid) {
        return peInfo;
    }
    return std::nullopt;
}

double MemoryScanner::CalculateEntropy(std::span<const uint8_t> data) const {
    return CalculateEntropyInternal(data);
}

std::vector<std::string> MemoryScanner::ExtractStrings(
    std::span<const uint8_t> data,
    size_t minLength) const {
    return ExtractStringsInternal(data, minLength);
}

bool MemoryScanner::CheckAPIHashing(std::span<const uint8_t> data) const {
    for (const auto& pattern : API_HASH_PATTERNS) {
        if (ContainsPattern(data, pattern)) {
            return true;
        }
    }
    return false;
}

// ========================================================================
// MEMORY READING
// ========================================================================

std::vector<uint8_t> MemoryScanner::ReadMemory(
    uint32_t pid,
    uintptr_t address,
    size_t size) const {

    std::vector<uint8_t> buffer;

    try {
        Utils::ProcessUtils::ProcessHandle hProcess(pid, PROCESS_VM_READ);
        if (!hProcess.IsValid()) {
            SS_LOG_ERROR(L"MemoryScanner", L"Failed to open process %u for reading", pid);
            return buffer;
        }

        buffer = ReadMemory(hProcess.Get(), address, size);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"ReadMemory - Exception: %S", e.what());
    }

    return buffer;
}

std::vector<uint8_t> MemoryScanner::ReadMemory(
    HANDLE processHandle,
    uintptr_t address,
    size_t size) const {

    if (!processHandle || processHandle == INVALID_HANDLE_VALUE) {
        SS_LOG_ERROR(L"MemoryScanner", L"ReadMemory: invalid process handle");
        return {};
    }

    if (size == 0) return {};

    // Cap read size to prevent unbounded allocation
    if (size > MemoryScannerConstants::MAX_REGION_SIZE) {
        SS_LOG_WARN(L"MemoryScanner", L"ReadMemory: clamping request from %zu to %zu bytes",
            size, MemoryScannerConstants::MAX_REGION_SIZE);
        size = MemoryScannerConstants::MAX_REGION_SIZE;
    }

    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(processHandle,
                          reinterpret_cast<LPCVOID>(address),
                          buffer.data(),
                          buffer.size(),
                          &bytesRead)) {
        SS_LOG_ERROR(L"MemoryScanner", L"ReadProcessMemory failed at 0x%llX",
            static_cast<unsigned long long>(address));
        return {};
    }

    buffer.resize(bytesRead);
    return buffer;
}

bool MemoryScanner::DumpRegion(
    uint32_t pid,
    uintptr_t address,
    size_t size,
    const std::wstring& outputPath) const {

    try {
        auto data = ReadMemory(pid, address, size);
        if (data.empty()) return false;

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            SS_LOG_ERROR(L"MemoryScanner", L"Failed to create dump file: %S", Utils::StringUtils::ToNarrow(outputPath).c_str());
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();

        SS_LOG_INFO(L"MemoryScanner", L"Dumped region 0x%llX (%zu bytes) to %S",
            static_cast<unsigned long long>(address),
            size,
            Utils::StringUtils::ToNarrow(outputPath).c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"DumpRegion - Exception: %S", e.what());
        return false;
    }
}

bool MemoryScanner::CreateMemoryDump(uint32_t pid, const std::wstring& outputPath) const {
    try {
        SS_LOG_INFO(L"MemoryScanner", L"Creating full memory dump for process %u", pid);

        auto regions = EnumerateRegions(pid);
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) return false;

        size_t totalDumped = 0;
        for (const auto& region : regions) {
            if (region.state != MemoryState::Committed) continue;

            auto data = ReadMemory(pid, region.baseAddress, region.size);
            if (!data.empty()) {
                outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
                totalDumped += data.size();
            }
        }

        outFile.close();

        SS_LOG_INFO(L"MemoryScanner", L"Memory dump complete: %zu bytes written to %S",
            totalDumped,
            Utils::StringUtils::ToNarrow(outputPath).c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"CreateMemoryDump - Exception: %S", e.what());
        return false;
    }
}

// ========================================================================
// YARA INTEGRATION
// ========================================================================

bool MemoryScanner::LoadYARARules(const std::wstring& rulesPath) {
    std::unique_lock lock(m_impl->m_mutex);

    try {
        // Validate the file exists before accepting it
        if (!Utils::FileUtils::Exists(rulesPath)) {
            SS_LOG_ERROR(L"MemoryScanner",
                L"YARA rules file not found: %s", rulesPath.c_str());
            return false;
        }

        m_impl->m_yaraRules.push_back(
            Utils::StringUtils::ToNarrow(rulesPath));

        // YARA matching is delegated to PatternIndex::Search.  When the
        // caller imports YARA rules via PatternStore::ImportFromYaraFile,
        // the compiled patterns are added to the PatternIndex that this
        // scanner uses.  We record the source path here for reload and
        // diagnostic purposes.
        SS_LOG_INFO(L"MemoryScanner",
            L"YARA rule source registered: %s (%zu total sources)",
            rulesPath.c_str(), m_impl->m_yaraRules.size());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"LoadYARARules - Exception: %S", e.what());
        return false;
    }
}

bool MemoryScanner::LoadYARARulesFromString(const std::string& rules) {
    std::unique_lock lock(m_impl->m_mutex);

    try {
        if (rules.empty()) {
            SS_LOG_WARN(L"MemoryScanner", L"LoadYARARulesFromString: empty rules string");
            return false;
        }

        m_impl->m_yaraRules.push_back(rules);

        SS_LOG_INFO(L"MemoryScanner",
            L"Inline YARA rule source stored (%zu total sources)",
            m_impl->m_yaraRules.size());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner", L"LoadYARARulesFromString - Exception: %S", e.what());
        return false;
    }
}

size_t MemoryScanner::GetYARARuleCount() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_yaraRules.size();
}

void MemoryScanner::UnloadYARARules() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_yaraRules.clear();
}

// ========================================================================
// STATISTICS
// ========================================================================

MemoryScannerStats MemoryScanner::GetStats() const {
    return m_impl->m_stats;
}

void MemoryScanner::ResetStats() {
    m_impl->m_stats.Reset();
}

// ========================================================================
// CALLBACKS
// ========================================================================

uint64_t MemoryScanner::RegisterThreatCallback(MemoryThreatCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    uint64_t id = ++m_impl->m_nextCallbackId;
    m_impl->m_threatCallbacks[id] = std::move(callback);
    return id;
}

bool MemoryScanner::UnregisterThreatCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_threatCallbacks.erase(callbackId) > 0;
}

uint64_t MemoryScanner::RegisterProgressCallback(ScanProgressCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    uint64_t id = ++m_impl->m_nextCallbackId;
    m_impl->m_progressCallbacks[id] = std::move(callback);
    return id;
}

bool MemoryScanner::UnregisterProgressCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_progressCallbacks.erase(callbackId) > 0;
}

uint64_t MemoryScanner::RegisterCompleteCallback(ScanCompleteCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    uint64_t id = ++m_impl->m_nextCallbackId;
    m_impl->m_completeCallbacks[id] = std::move(callback);
    return id;
}

bool MemoryScanner::UnregisterCompleteCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_completeCallbacks.erase(callbackId) > 0;
}

// ========================================================================
// EXTERNAL INTEGRATION
// ========================================================================

void MemoryScanner::SetPatternIndex(PatternStore::PatternIndex* index) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_patternIndex = index;
}

void MemoryScanner::SetEmulationEngine(Core::Engine::EmulationEngine* engine) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_emulationEngine = engine;
}

void MemoryScanner::SetThreatDetector(Core::Engine::ThreatDetector* detector) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_threatDetector = detector;
}

// ========================================================================
// STATE QUERY
// ========================================================================

bool MemoryScanner::IsInitialized() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_initialized;
}

// ========================================================================
// KERNEL INTEGRATION — OnKernelMemoryEvent
// ========================================================================
//
// Deserialises kernel-mode memory events from the PhantomSensor minifilter
// and performs deep user-mode analysis.  Each event type maps to a specific
// threat-hunting path with full telemetry and callback invocation.
//

void MemoryScanner::OnKernelMemoryEvent(
    uint32_t messageType,
    const void* payload,
    size_t payloadSize) {

    if (!payload || payloadSize == 0) {
        SS_LOG_WARN(L"MemoryScanner",
            L"OnKernelMemoryEvent: null/empty payload (type 0x%X)", messageType);
        return;
    }

    {
        std::shared_lock lock(m_impl->m_mutex);
        if (!m_impl->m_initialized) {
            SS_LOG_WARN(L"MemoryScanner",
                L"OnKernelMemoryEvent: scanner not initialised, dropping event 0x%X",
                messageType);
            return;
        }
    }

    try {
        // Dispatch by kernel message sub-type (the messageType field
        // contains the SHADOWSTRIKE_MESSAGE_TYPE enum value)
        switch (static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(messageType)) {

        // =================================================================
        // FilterMessageType_MemoryAlert — umbrella type; the actual event
        // kind is discriminated by the Size / Version fields in the header
        // (each struct has a unique Size value).
        // =================================================================
        case FilterMessageType_MemoryAlert:
        {
            // Peek the Size field (first UINT32) to discriminate
            if (payloadSize < sizeof(UINT32)) break;
            UINT32 structSize = 0;
            std::memcpy(&structSize, payload, sizeof(structSize));

            // ----- MEMORY_ALLOC_EVENT -----
            if (structSize == sizeof(MEMORY_ALLOC_EVENT) &&
                payloadSize >= sizeof(MEMORY_ALLOC_EVENT)) {

                const auto* evt = static_cast<const MEMORY_ALLOC_EVENT*>(payload);

                SS_LOG_DEBUG(L"MemoryScanner",
                    L"Kernel: MEMORY_ALLOC pid=%u base=0x%llX size=0x%llX prot=0x%X score=%u",
                    evt->ProcessId,
                    static_cast<unsigned long long>(evt->BaseAddress),
                    static_cast<unsigned long long>(evt->RegionSize),
                    evt->Protection, evt->ThreatScore);

                // Build a MemoryRegion and scan the freshly-allocated memory
                const uint32_t targetPid = (evt->TargetProcessId != 0)
                    ? evt->TargetProcessId : evt->ProcessId;

                MemoryRegion region;
                region.baseAddress = static_cast<uintptr_t>(evt->BaseAddress);
                region.size = static_cast<size_t>(evt->RegionSize);
                region.isExecutable = IsProtectionExecutable(evt->Protection);
                region.isWritable = IsProtectionWritable(evt->Protection);
                region.isPrivate = true;
                region.type = MemoryType::Private;
                region.state = MemoryState::Committed;
                region.protection = WindowsProtectionToEnum(evt->Protection);
                region.initialProtection = region.protection;

                if (IsProtectionRWX(evt->Protection)) {
                    region.isSuspicious = true;
                    region.suspicionReason = "Kernel: RWX allocation detected";
                }
                if (evt->DetectionFlags & MEMALLOC_FLAG_CROSS_PROCESS) {
                    region.isSuspicious = true;
                    region.suspicionReason = "Kernel: cross-process allocation";
                }

                // Perform a targeted scan of the region
                Utils::ProcessUtils::ProcessHandle hProcess(targetPid,
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
                if (hProcess.IsValid()) {
                    MemoryScannerConfig cfg;
                    {
                        std::shared_lock lock(m_impl->m_mutex);
                        cfg = m_impl->m_config;
                    }
                    auto scanResult = m_impl->ScanRegionInternal(
                        targetPid, hProcess.Get(), region, cfg);

                    for (auto& threat : scanResult.threats) {
                        threat.processName = evt->ProcessImagePath;
                        if (threat.confidence >= cfg.minReportConfidence) {
                            m_impl->InvokeThreatCallbacks(threat);
                            m_impl->m_stats.threatsFound.fetch_add(
                                1, std::memory_order_relaxed);
                        }
                    }
                }
            }
            // ----- MEMORY_PROTECT_EVENT -----
            else if (structSize == sizeof(MEMORY_PROTECT_EVENT) &&
                     payloadSize >= sizeof(MEMORY_PROTECT_EVENT)) {

                const auto* evt = static_cast<const MEMORY_PROTECT_EVENT*>(payload);

                SS_LOG_DEBUG(L"MemoryScanner",
                    L"Kernel: MEMORY_PROTECT pid=%u base=0x%llX old=0x%X new=0x%X score=%u",
                    evt->ProcessId,
                    static_cast<unsigned long long>(evt->BaseAddress),
                    evt->OldProtection, evt->NewProtection, evt->ThreatScore);

                // W→X transition: scan the region that just became executable
                bool wasExec = IsProtectionExecutable(evt->OldProtection);
                bool isExec  = IsProtectionExecutable(evt->NewProtection);

                if (!wasExec && isExec) {
                    const uint32_t targetPid = (evt->TargetProcessId != 0)
                        ? evt->TargetProcessId : evt->ProcessId;

                    Utils::ProcessUtils::ProcessHandle hProcess(targetPid,
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
                    if (hProcess.IsValid()) {
                        MemoryRegion region;
                        region.baseAddress = static_cast<uintptr_t>(evt->BaseAddress);
                        region.size = static_cast<size_t>(evt->RegionSize);
                        region.isExecutable = true;
                        region.isWritable = IsProtectionWritable(evt->NewProtection);
                        region.isPrivate = true;
                        region.type = MemoryType::Private;
                        region.state = MemoryState::Committed;
                        region.protection = WindowsProtectionToEnum(evt->NewProtection);
                        region.initialProtection = WindowsProtectionToEnum(evt->OldProtection);
                        region.isSuspicious = true;
                        region.suspicionReason = "Kernel: W->X protection change";

                        MemoryScannerConfig cfg;
                        {
                            std::shared_lock lock(m_impl->m_mutex);
                            cfg = m_impl->m_config;
                        }
                        auto scanResult = m_impl->ScanRegionInternal(
                            targetPid, hProcess.Get(), region, cfg);

                        for (auto& threat : scanResult.threats) {
                            threat.processName = evt->ProcessImagePath;
                            if (threat.confidence >= cfg.minReportConfidence) {
                                m_impl->InvokeThreatCallbacks(threat);
                                m_impl->m_stats.threatsFound.fetch_add(
                                    1, std::memory_order_relaxed);
                            }
                        }
                    }
                }
            }
            // ----- MEMORY_ACCESS_EVENT (cross-process write) -----
            else if (structSize == sizeof(MEMORY_ACCESS_EVENT) &&
                     payloadSize >= sizeof(MEMORY_ACCESS_EVENT)) {

                const auto* evt = static_cast<const MEMORY_ACCESS_EVENT*>(payload);

                SS_LOG_DEBUG(L"MemoryScanner",
                    L"Kernel: MEMORY_ACCESS src=%u→tgt=%u addr=0x%llX size=0x%llX score=%u",
                    evt->SourceProcessId, evt->TargetProcessId,
                    static_cast<unsigned long long>(evt->TargetAddress),
                    static_cast<unsigned long long>(evt->Size_),
                    evt->ThreatScore);

                // Cross-process write to executable memory: scan the target
                if (evt->SourceProcessId != evt->TargetProcessId &&
                    evt->Size_ > 0 && evt->Size_ <= MemoryScannerConstants::MAX_REGION_SIZE) {

                    Utils::ProcessUtils::ProcessHandle hTarget(evt->TargetProcessId,
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
                    if (hTarget.IsValid()) {
                        MemoryRegion region;
                        region.baseAddress = static_cast<uintptr_t>(evt->TargetAddress);
                        region.size = static_cast<size_t>(evt->Size_);
                        region.isPrivate = true;
                        region.isExecutable = true;
                        region.type = MemoryType::Private;
                        region.state = MemoryState::Committed;
                        region.isSuspicious = true;
                        region.suspicionReason = "Kernel: cross-process write";

                        MemoryScannerConfig cfg;
                        {
                            std::shared_lock lock(m_impl->m_mutex);
                            cfg = m_impl->m_config;
                        }
                        auto scanResult = m_impl->ScanRegionInternal(
                            evt->TargetProcessId, hTarget.Get(), region, cfg);

                        for (auto& threat : scanResult.threats) {
                            threat.processName = evt->TargetProcessPath;
                            if (threat.confidence >= cfg.minReportConfidence) {
                                m_impl->InvokeThreatCallbacks(threat);
                                m_impl->m_stats.threatsFound.fetch_add(
                                    1, std::memory_order_relaxed);
                            }
                        }
                    }
                }
            }
            // ----- SHELLCODE_DETECTION_EVENT -----
            else if (structSize == sizeof(SHELLCODE_DETECTION_EVENT) &&
                     payloadSize >= sizeof(SHELLCODE_DETECTION_EVENT)) {

                const auto* evt = static_cast<const SHELLCODE_DETECTION_EVENT*>(payload);

                SS_LOG_INFO(L"MemoryScanner",
                    L"Kernel: SHELLCODE pid=%u addr=0x%llX type=%d score=%u conf=%u",
                    evt->ProcessId,
                    static_cast<unsigned long long>(evt->DetectionAddress),
                    static_cast<int>(evt->PrimaryType),
                    evt->ThreatScore, evt->Confidence);

                // Build a MemoryThreat directly from the kernel's analysis,
                // then optionally enrich with user-mode deep scan.
                MemoryThreat threat;
                threat.threatId = m_impl->m_nextThreatId++;
                threat.timestamp = std::chrono::system_clock::now();
                threat.processId = evt->ProcessId;
                threat.regionBase = static_cast<uintptr_t>(evt->RegionBase);
                threat.regionSize = static_cast<size_t>(evt->RegionSize);
                threat.detectionOffset =
                    static_cast<size_t>(evt->DetectionAddress - evt->RegionBase);
                threat.protection = WindowsProtectionToEnum(evt->RegionProtection);
                threat.riskScore = static_cast<double>(evt->ThreatScore) / 10.0;
                threat.confidence = static_cast<double>(evt->Confidence);
                threat.processName = evt->ProcessImagePath;
                threat.ruleCategory = "Kernel";

                // Map kernel shellcode type to our threat types
                switch (evt->PrimaryType) {
                    case Shellcode_CobaltStrike:
                        threat.threatType = MemoryThreatType::CobaltStrikeBeacon;
                        threat.matchedRule = "Kernel: Cobalt Strike Shellcode";
                        threat.mitreTechnique = "T1071";
                        break;
                    case Shellcode_Meterpreter:
                        threat.threatType = MemoryThreatType::Meterpreter;
                        threat.matchedRule = "Kernel: Meterpreter Stage";
                        threat.mitreTechnique = "T1055";
                        break;
                    case Shellcode_Syscall:
                        threat.threatType = MemoryThreatType::SyscallStub;
                        threat.matchedRule = "Kernel: Direct Syscall";
                        threat.mitreTechnique = "T1106";
                        break;
                    case Shellcode_ROP:
                        threat.threatType = MemoryThreatType::Shellcode;
                        threat.matchedRule = "Kernel: ROP Chain";
                        threat.mitreTechnique = "T1055";
                        break;
                    default:
                        threat.threatType = MemoryThreatType::Shellcode;
                        threat.matchedRule = "Kernel: Shellcode Detection";
                        threat.mitreTechnique = "T1620";
                        break;
                }

                // Copy evidence preview from kernel content sample
                threat.evidencePreview.assign(
                    evt->ContentSample,
                    evt->ContentSample + sizeof(evt->ContentSample));

                threat.details = L"Kernel-mode shellcode detection — performing user-mode deep scan";

                // Enrich: read the full region and run user-mode analysis
                Utils::ProcessUtils::ProcessHandle hProcess(evt->ProcessId,
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
                if (hProcess.IsValid() &&
                    evt->RegionSize <= MemoryScannerConstants::MAX_REGION_SIZE) {

                    std::vector<uint8_t> regionData(
                        static_cast<size_t>(evt->RegionSize));
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hProcess.Get(),
                            reinterpret_cast<LPCVOID>(evt->RegionBase),
                            regionData.data(), regionData.size(), &bytesRead)) {
                        regionData.resize(bytesRead);

                        // Run full user-mode shellcode analysis
                        auto analysis = m_impl->AnalyzeForShellcode(regionData);
                        if (analysis.isShellcode) {
                            threat.confidence = std::max(
                                threat.confidence, analysis.confidence);
                        }

                        // Check for PE inside the region
                        if (m_impl->ContainsPEInternal(regionData)) {
                            threat.threatType = MemoryThreatType::PEInjection;
                            threat.matchedRule += " + PE Injection";
                            threat.peInfo = m_impl->ParsePEInternal(regionData);
                            threat.confidence = std::max(threat.confidence, 95.0);
                        }
                    }
                }

                MemoryScannerConfig cfg;
                {
                    std::shared_lock lock(m_impl->m_mutex);
                    cfg = m_impl->m_config;
                }

                if (threat.confidence >= cfg.minReportConfidence) {
                    m_impl->InvokeThreatCallbacks(threat);
                    m_impl->m_stats.threatsFound.fetch_add(1, std::memory_order_relaxed);
                    m_impl->m_stats.shellcodeDetections.fetch_add(
                        1, std::memory_order_relaxed);
                }
            }
            else {
                SS_LOG_WARN(L"MemoryScanner",
                    L"OnKernelMemoryEvent: unknown sub-event (structSize=%u, payloadSize=%zu)",
                    structSize, payloadSize);
            }
            break;
        }

        default:
            SS_LOG_DEBUG(L"MemoryScanner",
                L"OnKernelMemoryEvent: unhandled message type 0x%X", messageType);
            break;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MemoryScanner",
            L"OnKernelMemoryEvent - Exception processing type 0x%X: %S",
            messageType, e.what());
    }
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
