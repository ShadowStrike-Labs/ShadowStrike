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
 * @file ZeroDayDetector.cpp
 * @brief Enterprise-grade zero-day exploit detection using heuristic analysis
 *
 * ShadowStrike Core Engine - Zero-Day Detection Module
 *
 * Provides comprehensive zero-day exploit detection using:
 * - Shellcode pattern recognition (NOP sleds, GetPC tricks, decoder stubs)
 * - ROP chain analysis and gadget identification
 * - Heap spray detection (pattern analysis, allocation tracking)
 * - Memory corruption detection (arbitrary write, info leak, bypass techniques)
 * - CVE correlation with known exploit patterns
 * - MITRE ATT&CK technique mapping
 *
 * Implementation: PIMPL, std::shared_mutex, C++20, SS_LOG_* macros.
 */

#include "pch.h"
#include "ZeroDayDetector.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <set>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <Windows.h>

#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"

namespace ShadowStrike::Core::Engine {

namespace {

constexpr const wchar_t* kLogCategory = L"ZeroDayDetector";

// Hard upper bounds on attacker-influenced inputs.  Excessive sizes are clamped
// rather than rejected so that legitimate large modules are still partially
// analysed; the cap exists purely to bound CPU/RAM consumption.
constexpr size_t kMaxStackDumpFrames        = 1u << 16;     // 65 536 frames
constexpr size_t kMaxModuleRangesEntries    = 1u << 12;     // 4 096 modules
constexpr size_t kMaxAllocationsToAnalyse   = 1u << 16;
constexpr size_t kMaxFindGadgetsBytes       = 16u * 1024u * 1024u;
constexpr size_t kMaxGadgetsReturned        = 4096;
constexpr size_t kMaxCveDatabaseEntries     = 1024;
constexpr size_t kMaxShellcodePatterns      = 256;

[[nodiscard]] std::wstring ToWide(std::string_view v) noexcept {
    try { return Utils::StringUtils::ToWide(v); }
    catch (...) { return L"<conversion failed>"; }
}

// SAL-annotated, alignment-safe little-endian 32-bit fetch.  Used in lieu of
// raw pointer dereferences to avoid strict-aliasing UB and unaligned access.
[[nodiscard]] uint32_t ReadU32Safe(_In_reads_bytes_(sizeof(uint32_t)) const void* src) noexcept {
    uint32_t val = 0;
    if (src != nullptr) {
        std::memcpy(&val, src, sizeof(val));
    }
    return val;
}

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ZeroDayDetector::Impl {
public:
    mutable std::shared_mutex m_mutex;
    std::atomic<bool>          m_initialized{false};
    std::atomic<ZeroDayStatus> m_status{ZeroDayStatus::Uninitialized};
    ZeroDayConfiguration       m_config;
    ZeroDayStatistics          m_stats;

    ZeroDayDetectionCallback m_detectionCallback;
    ErrorCallback     m_errorCallback;

    struct ShellcodePattern {
        std::vector<uint8_t> signature;
        ShellcodeType        type;
        std::string          description;
        float                confidence;
    };
    std::vector<ShellcodePattern> m_shellcodePatterns;

    struct CVEEntry {
        std::string          cveId;
        std::string          description;
        ExploitType          exploitType;
        std::vector<uint8_t> pattern;
        float                cvssScore;
        std::string          affectedProduct;
    };
    std::vector<CVEEntry> m_cveDatabase;

    std::unordered_map<std::string, std::string> m_mitreTechniques;

    Impl() = default;
    ~Impl() = default;

    void InitializePatterns() noexcept;
    void InitializeCVEDatabase() noexcept;
    void InitializeMITRE() noexcept;

    [[nodiscard]] std::optional<ShellcodeInfo> DetectShellcodeInternal(std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] bool DetectNOPSled(std::span<const uint8_t> buffer, size_t& sledLength) noexcept;
    [[nodiscard]] bool DetectGetPCTrick(std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] bool DetectDecoderStub(std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] double ComputeEntropy(std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] ShellcodeType ClassifyShellcode(std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] bool ScanForPattern(std::span<const uint8_t> haystack, std::span<const uint8_t> needle) noexcept;

    [[nodiscard]] std::optional<ROPChainInfo> DetectROPChainInternal(
        std::span<const uintptr_t> addresses,
        const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges) noexcept;
    [[nodiscard]] bool IsAddressInModule(uintptr_t address,
        const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges,
        std::string& outModule) noexcept;
    [[nodiscard]] ROPGadget IdentifyGadgetBytes(uintptr_t address,
        std::span<const uint8_t> bytes, const std::string& moduleName) noexcept;

    [[nodiscard]] std::optional<HeapSprayInfo> DetectHeapSprayInternal(
        const std::vector<std::pair<uintptr_t, size_t>>& allocations) noexcept;

    [[nodiscard]] std::optional<MemoryCorruptionInfo> DetectMemoryCorruptionInternal(
        std::span<const uint8_t> buffer) noexcept;

    [[nodiscard]] std::vector<CVEMatch> CorrelateCVEs(
        const ZeroDayResult& result, std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] bool MatchCVEPattern(const CVEEntry& cve, std::span<const uint8_t> buffer) noexcept;
    [[nodiscard]] std::set<std::string> MapToMITRE(const ZeroDayResult& result) noexcept;
    [[nodiscard]] ExploitSeverity CalculateSeverity(const ZeroDayResult& result) noexcept;
    [[nodiscard]] DetectionConfidence CalculateConfidence(const ZeroDayResult& result) noexcept;

    void NotifyDetection(const ZeroDayResult& result) noexcept;
    void NotifyError(const std::string& msg, int code) noexcept;
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

void ZeroDayDetector::Impl::InitializePatterns() noexcept {
    try {
        m_shellcodePatterns.clear();
        m_shellcodePatterns.reserve(16);

        m_shellcodePatterns.push_back({{0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00},
            ShellcodeType::Meterpreter, "Metasploit Meterpreter reverse_tcp", 0.95f});

        m_shellcodePatterns.push_back({{0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00},
            ShellcodeType::Meterpreter, "Metasploit shell_reverse_tcp", 0.90f});

        m_shellcodePatterns.push_back({{0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8},
            ShellcodeType::CobaltStrike, "Cobalt Strike beacon", 0.92f});

        m_shellcodePatterns.push_back({{0x6A, 0x02, 0x5F, 0x6A, 0x01, 0x5E},
            ShellcodeType::ConnectBack, "x86 reverse shell (socket setup)", 0.85f});

        m_shellcodePatterns.push_back({{0x6A, 0x00, 0x6A, 0x01, 0x6A, 0x02},
            ShellcodeType::BindShell, "x86 bind shell (socket setup)", 0.85f});

        m_shellcodePatterns.push_back({{0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42},
            ShellcodeType::Egg_Hunter, "Egg hunter (NtAccessCheckAndAuditAlarm)", 0.88f});

        m_shellcodePatterns.push_back({{0x48, 0x31, 0xC9, 0x48, 0x81, 0xE9},
            ShellcodeType::Custom, "x64 syscall-based shellcode", 0.80f});

        m_shellcodePatterns.push_back({{0x68, 0x33, 0x32, 0x00, 0x00, 0x68, 0x77, 0x73, 0x32, 0x5F},
            ShellcodeType::Downloader, "Download-and-execute (ws2_32 push)", 0.82f});

        // Defensive cap — should never be exceeded with the seed set above but
        // protects against accidental over-population in future revisions.
        if (m_shellcodePatterns.size() > kMaxShellcodePatterns) {
            m_shellcodePatterns.resize(kMaxShellcodePatterns);
        }

    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(kLogCategory, L"OOM during shellcode pattern initialization");
        m_shellcodePatterns.clear();
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during pattern initialization");
        m_shellcodePatterns.clear();
    }
}

void ZeroDayDetector::Impl::InitializeCVEDatabase() noexcept {
    try {
        m_cveDatabase.clear();
        m_cveDatabase.reserve(8);

        m_cveDatabase.push_back({"CVE-2021-40444", "Microsoft MSHTML Remote Code Execution",
            ExploitType::ArbitraryWrite, {0x4D, 0x53, 0x48, 0x54, 0x4D, 0x4C}, 9.8f, "Microsoft MSHTML"});

        m_cveDatabase.push_back({"CVE-2020-0796", "SMBGhost - Windows SMBv3 RCE",
            ExploitType::HeapOverflow, {0x00, 0x00, 0x03, 0x11}, 10.0f, "Windows SMBv3"});

        m_cveDatabase.push_back({"CVE-2019-0708", "BlueKeep - RDP RCE",
            ExploitType::UseAfterFree, {0x03, 0x00, 0x00, 0x13}, 9.8f, "Windows RDP"});

        m_cveDatabase.push_back({"CVE-2021-34527", "PrintNightmare - Print Spooler RCE",
            ExploitType::PrivilegeEscalation, {0x5C, 0x5C, 0x70, 0x69, 0x70, 0x65}, 8.8f, "Windows Print Spooler"});

        m_cveDatabase.push_back({"CVE-2022-30190", "Follina - MSDT RCE",
            ExploitType::ArbitraryWrite, {0x6D, 0x73, 0x2D, 0x6D, 0x73, 0x64, 0x74}, 7.8f, "Windows MSDT"});

        if (m_cveDatabase.size() > kMaxCveDatabaseEntries) {
            m_cveDatabase.resize(kMaxCveDatabaseEntries);
        }

    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(kLogCategory, L"OOM during CVE database initialization");
        m_cveDatabase.clear();
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during CVE database initialization");
        m_cveDatabase.clear();
    }
}

void ZeroDayDetector::Impl::InitializeMITRE() noexcept {
    // Map insertion can throw std::bad_alloc; the original `noexcept`
    // declaration would have triggered std::terminate on OOM.
    try {
        m_mitreTechniques = {
            {"T1055",    "Process Injection"},
            {"T1055.012","Process Hollowing"},
            {"T1059",    "Command and Scripting Interpreter"},
            {"T1068",    "Exploitation for Privilege Escalation"},
            {"T1189",    "Drive-by Compromise"},
            {"T1203",    "Exploitation for Client Execution"},
            {"T1210",    "Exploitation of Remote Services"},
            {"T1211",    "Exploitation for Defense Evasion"},
            {"T1212",    "Exploitation for Credential Access"},
            {"T1574",    "Hijack Execution Flow"},
        };
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during MITRE technique initialization");
        m_mitreTechniques.clear();
    }
}

// ============================================================================
// IMPL: SHELLCODE DETECTION
// ============================================================================

bool ZeroDayDetector::Impl::ScanForPattern(
    std::span<const uint8_t> haystack,
    std::span<const uint8_t> needle) noexcept
{
    if (needle.empty() || haystack.size() < needle.size()) return false;
    return std::search(haystack.begin(), haystack.end(),
                       needle.begin(), needle.end()) != haystack.end();
}

std::optional<ShellcodeInfo> ZeroDayDetector::Impl::DetectShellcodeInternal(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        if (buffer.empty()) return std::nullopt;

        ShellcodeInfo info;
        info.startOffset = 0;
        info.size        = buffer.size();
        info.platform    = "x86/x64";
        info.entropy     = static_cast<float>(ComputeEntropy(buffer));

        size_t nopLen = 0;
        if (DetectNOPSled(buffer, nopLen)) {
            info.hasNopSled    = true;
            info.nopSledLength = nopLen;
        }

        if (DetectGetPCTrick(buffer))  info.hasGetPC = true;
        if (DetectDecoderStub(buffer)) {
            info.hasDecoderStub = true;
            info.isEncoded      = true;
            info.encodingType   = "XOR/ADD loop encoder";
        }

        info.type = ClassifyShellcode(buffer);

        // Network indicator scan
        static const char* kNetSigs[][2] = {
            {"ws2_32",       "ws2_32.dll API usage"},
            {"wininet",      "wininet.dll API usage"},
            {"WinHttpOpen",  "WinHTTP API usage"},
            {"InternetOpen", "WinINet API usage"},
            {"HttpSendReq",  "HTTP request API"},
        };
        for (const auto& ns : kNetSigs) {
            const auto len = std::strlen(ns[0]);
            std::span<const uint8_t> sig(reinterpret_cast<const uint8_t*>(ns[0]), len);
            if (ScanForPattern(buffer, sig))
                info.networkIndicators.emplace_back(ns[1]);
        }

        // Composite scoring: require multiple indicators
        int score = 0;
        if (info.hasNopSled)                              score += 25;
        if (info.hasGetPC)                                score += 35;
        if (info.hasDecoderStub)                          score += 40;
        if (info.entropy >= 5.5f && info.entropy <= 7.5f) score += 15;
        if (!info.networkIndicators.empty())              score += 20;
        if (info.type != ShellcodeType::Unknown)          score += 30;

        if (score >= 50) {
            m_stats.shellcodeDetected.fetch_add(1, std::memory_order_relaxed);
            return info;
        }
        return std::nullopt;

    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during shellcode detection");
        return std::nullopt;
    }
}

bool ZeroDayDetector::Impl::DetectNOPSled(
    std::span<const uint8_t> buffer, size_t& sledLength) noexcept
{
    try {
        sledLength = 0;
        if (buffer.size() < ZeroDayConstants::MIN_NOP_SLED_LENGTH) return false;

        size_t consecutive = 0;
        size_t bestRun     = 0;

        for (const uint8_t b : buffer) {
            if (b == 0x90 || b == 0x91 || b == 0x92 || b == 0x93 ||
                b == 0x94 || b == 0x95 || b == 0x96 || b == 0x97)
            {
                ++consecutive;
                bestRun = (std::max)(bestRun, consecutive);
            } else {
                consecutive = 0;
            }
        }

        if (bestRun >= ZeroDayConstants::MIN_NOP_SLED_LENGTH) {
            sledLength = bestRun;
            return true;
        }
        return false;
    } catch (...) { return false; }
}

bool ZeroDayDetector::Impl::DetectGetPCTrick(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        if (buffer.size() < 6) return false;

        for (size_t i = 0; i + 5 < buffer.size(); ++i) {
            // CALL $+5 / POP reg
            if (buffer[i]     == 0xE8 && buffer[i+1] == 0x00 &&
                buffer[i+2]   == 0x00 && buffer[i+3] == 0x00 &&
                buffer[i+4]   == 0x00 &&
                buffer[i+5] >= 0x58 && buffer[i+5] <= 0x5F)
                return true;

            // FNSTENV [ESP-0Ch]
            if (i+3 < buffer.size() &&
                buffer[i] == 0xD9 && buffer[i+1] == 0x74 &&
                buffer[i+2] == 0x24 && buffer[i+3] == 0xF4)
                return true;

            // JMP/CALL reg then POP
            if (i+2 < buffer.size() && buffer[i] == 0xFF &&
                ((buffer[i+1] >= 0xD0 && buffer[i+1] <= 0xD7) ||
                 (buffer[i+1] >= 0xE0 && buffer[i+1] <= 0xE7)) &&
                buffer[i+2] >= 0x58 && buffer[i+2] <= 0x5F)
                return true;
        }
        return false;
    } catch (...) { return false; }
}

bool ZeroDayDetector::Impl::DetectDecoderStub(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        if (buffer.size() < 12) return false;

        int xorPatterns = 0, loopPatterns = 0, incDecRegs = 0;

        for (size_t i = 0; i + 2 < buffer.size(); ++i) {
            const uint8_t b0 = buffer[i];
            const uint8_t b1 = buffer[i+1];

            if (b0 == 0x80 && (b1 & 0xF8) == 0x70)       ++xorPatterns;
            if (b0 == 0x31 || b0 == 0x33)                 ++xorPatterns;
            if (b0 == 0xE2 || b0 == 0xE1 || b0 == 0xE0)   ++loopPatterns;
            if (b0 >= 0x40 && b0 <= 0x4F)                  ++incDecRegs;
        }

        return (xorPatterns * 8 + loopPatterns * 15 + incDecRegs * 2) >= 40;
    } catch (...) { return false; }
}

double ZeroDayDetector::Impl::ComputeEntropy(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        if (buffer.empty()) return 0.0;
        std::array<uint64_t, 256> counts{};
        for (const uint8_t b : buffer) counts[b]++;

        double entropy = 0.0;
        const double sz = static_cast<double>(buffer.size());
        for (const uint64_t c : counts) {
            if (c == 0) continue;
            const double p = static_cast<double>(c) / sz;
            entropy -= p * std::log2(p);
        }
        return entropy;
    } catch (...) { return 0.0; }
}

ShellcodeType ZeroDayDetector::Impl::ClassifyShellcode(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        for (const auto& pat : m_shellcodePatterns) {
            if (ScanForPattern(buffer, std::span<const uint8_t>(pat.signature)))
                return pat.type;
        }

        struct APIHint { const char* api; ShellcodeType type; };
        static const APIHint hints[] = {
            {"URLDownloadToFile", ShellcodeType::Downloader},
            {"WinExec",           ShellcodeType::Downloader},
            {"InternetOpenUrl",   ShellcodeType::Downloader},
            {"connect",           ShellcodeType::ConnectBack},
            {"WSASocketA",        ShellcodeType::ConnectBack},
            {"bind",              ShellcodeType::BindShell},
            {"listen",            ShellcodeType::BindShell},
            {"CreateRemoteThread",ShellcodeType::Custom},
        };

        for (const auto& h : hints) {
            const auto len = std::strlen(h.api);
            std::span<const uint8_t> needle(reinterpret_cast<const uint8_t*>(h.api), len);
            if (ScanForPattern(buffer, needle)) return h.type;
        }
        return ShellcodeType::Unknown;
    } catch (...) { return ShellcodeType::Unknown; }
}

// ============================================================================
// IMPL: ROP CHAIN DETECTION
// ============================================================================

bool ZeroDayDetector::Impl::IsAddressInModule(
    uintptr_t address,
    const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges,
    std::string& outModule) noexcept
{
    for (const auto& [name, range] : moduleRanges) {
        if (address >= range.first && address < (range.first + range.second)) {
            outModule = name;
            return true;
        }
    }
    return false;
}

ROPGadget ZeroDayDetector::Impl::IdentifyGadgetBytes(
    uintptr_t address, std::span<const uint8_t> bytes, const std::string& moduleName) noexcept
{
    ROPGadget g;
    g.address = static_cast<uint64_t>(address);
    g.module  = moduleName;
    g.type    = GadgetType::Unknown;
    g.bytes.assign(bytes.begin(), bytes.end());

    if (bytes.empty()) { g.disassembly = "<unreadable>"; return g; }

    const size_t sz = bytes.size();

    if (sz >= 2 && bytes[sz-1] == 0xC3) {
        // POP reg + RET
        if (sz == 2 && bytes[0] >= 0x58 && bytes[0] <= 0x5F) {
            g.type = GadgetType::PopRet;
            static const char* rn[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
            g.disassembly = std::string("pop ") + rn[bytes[0]-0x58] + "; ret";
            return g;
        }
        // XCHG EAX, reg + RET
        if (sz == 2 && bytes[0] >= 0x91 && bytes[0] <= 0x97) {
            g.type = GadgetType::XchgRet;
            g.disassembly = "xchg eax, reg; ret";
            return g;
        }
        // SYSCALL + RET
        if (sz >= 3 && bytes[sz-3] == 0x0F && bytes[sz-2] == 0x05) {
            g.type = GadgetType::Syscall;
            g.disassembly = "syscall; ret";
            return g;
        }
        // Stack pivot: XCHG RSP, RAX
        if (sz >= 3 && bytes[0] == 0x48 && bytes[1] == 0x94) {
            g.type = GadgetType::StackPivot;
            g.disassembly = "xchg rsp, rax; ret";
            return g;
        }
    }

    // JMP reg
    if (sz >= 2 && bytes[0] == 0xFF && bytes[1] >= 0xE0 && bytes[1] <= 0xE7) {
        g.type = GadgetType::JmpReg;
        g.disassembly = "jmp reg";
        return g;
    }
    // CALL reg
    if (sz >= 2 && bytes[0] == 0xFF && bytes[1] >= 0xD0 && bytes[1] <= 0xD7) {
        g.type = GadgetType::CallReg;
        g.disassembly = "call reg";
        return g;
    }

    g.disassembly = "unknown gadget";
    return g;
}

std::optional<ROPChainInfo> ZeroDayDetector::Impl::DetectROPChainInternal(
    std::span<const uintptr_t> addresses,
    const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges) noexcept
{
    try {
        if (addresses.empty() || moduleRanges.empty()) return std::nullopt;

        // Defensive cap — public callers already clamp, but the internal
        // helper may be reached from other code paths in the future.
        if (addresses.size() > kMaxStackDumpFrames) {
            addresses = addresses.subspan(0, kMaxStackDumpFrames);
        }

        ROPChainInfo info;
        info.startAddress = static_cast<uint64_t>(addresses[0]);
        size_t inModuleCount = 0;

        for (const uintptr_t addr : addresses) {
            std::string modName;
            if (IsAddressInModule(addr, moduleRanges, modName)) {
                ++inModuleCount;
                ROPGadget g;
                g.address     = static_cast<uint64_t>(addr);
                g.module      = std::move(modName);
                g.type        = GadgetType::Unknown;
                g.disassembly = "addr-in-module";
                info.gadgets.push_back(std::move(g));
            }
        }

        const double ratio = static_cast<double>(inModuleCount) /
                             static_cast<double>(addresses.size());
        if (ratio < 0.5 || inModuleCount < ZeroDayConstants::ROP_CHAIN_THRESHOLD)
            return std::nullopt;

        std::unordered_set<std::string> uniqueModules;
        for (const auto& g : info.gadgets) uniqueModules.insert(g.module);

        if (uniqueModules.size() >= 3)      info.purpose = "Cross-module ROP chain";
        else if (uniqueModules.size() == 1) info.purpose = "Single-module gadget chain";
        else                                info.purpose = "ROP chain";

        info.isComplete = (inModuleCount >= ZeroDayConstants::ROP_CHAIN_THRESHOLD + 2);
        info.targetAPI  = info.isComplete ? "System call or VirtualProtect" : "Unknown";

        m_stats.ropChainsDetected.fetch_add(1, std::memory_order_relaxed);
        return info;

    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during ROP chain detection");
        return std::nullopt;
    }
}

// ============================================================================
// IMPL: HEAP SPRAY DETECTION
// ============================================================================

std::optional<HeapSprayInfo> ZeroDayDetector::Impl::DetectHeapSprayInternal(
    const std::vector<std::pair<uintptr_t, size_t>>& allocations) noexcept
{
    try {
        if (allocations.size() < 10) return std::nullopt;

        // Bound attacker-controlled allocation list size before further work.
        const size_t allocCount =
            (std::min)(allocations.size(), kMaxAllocationsToAnalyse);

        HeapSprayInfo info;
        info.allocationCount = allocCount;

        std::unordered_map<size_t, uint32_t> sizeHist;
        sizeHist.reserve(32);

        // Saturating accumulator to defeat integer-overflow on totalSize.
        size_t totalSize = 0;
        for (size_t i = 0; i < allocCount; ++i) {
            const size_t sz = allocations[i].second;
            if (sz > (SIZE_MAX - totalSize)) {
                totalSize = SIZE_MAX;
            } else {
                totalSize += sz;
            }
            sizeHist[sz]++;
        }
        info.totalSize = totalSize;

        size_t   dominantSize  = 0;
        uint32_t dominantCount = 0;
        for (const auto& [sz, cnt] : sizeHist) {
            if (cnt > dominantCount) { dominantCount = cnt; dominantSize = sz; }
        }

        const bool sizeUniform = (dominantCount >= static_cast<uint32_t>(allocCount / 2));
        const bool highCount   = (info.allocationCount >= ZeroDayConstants::HEAP_SPRAY_THRESHOLD);
        const bool largeTotal  = (info.totalSize >= 10ULL * 1024 * 1024);

        if (!sizeUniform || (!highCount && !largeTotal)) return std::nullopt;

        // Analyse address spacing for evenly-strided spray allocations.
        if (allocCount >= 3) {
            std::vector<uintptr_t> addrs;
            addrs.reserve(allocCount);
            for (size_t i = 0; i < allocCount; ++i) {
                addrs.push_back(allocations[i].first);
            }
            std::sort(addrs.begin(), addrs.end());

            std::unordered_map<uintptr_t, uint32_t> deltaHist;
            for (size_t i = 1; i < addrs.size(); ++i) {
                const uintptr_t delta = addrs[i] - addrs[i-1];
                if (delta > 0) deltaHist[delta]++;
            }

            for (const auto& [delta, cnt] : deltaHist) {
                (void)delta;
                if (cnt >= addrs.size() / 3 && dominantSize >= 4) {
                    const uint8_t fb = static_cast<uint8_t>((dominantSize >> 8) & 0xFF);
                    info.pattern = {fb, fb, fb, fb};
                    info.sprayValue = ReadU32Safe(info.pattern.data());
                    break;
                }
            }
        }

        // Check for canonical heap-spray landing addresses (0x0c0c0c0c, etc.).
        static constexpr uint32_t kSprayValues[] =
            {0x0C0C0C0Cu, 0x0D0D0D0Du, 0x0E0E0E0Eu, 0x0A0A0A0Au};
        for (size_t i = 0; i < allocCount; ++i) {
            const uintptr_t addr = allocations[i].first;
            for (const uint32_t sv : kSprayValues) {
                if ((static_cast<uint32_t>(addr & 0xFFFFFFFFu)) == sv) {
                    info.sprayValue = sv;
                    const uint8_t fb = static_cast<uint8_t>(sv & 0xFFu);
                    info.pattern = {fb, fb, fb, fb};
                }
            }
        }

        m_stats.heapSpraysDetected.fetch_add(1, std::memory_order_relaxed);
        return info;

    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during heap spray detection");
        return std::nullopt;
    }
}

// ============================================================================
// IMPL: MEMORY CORRUPTION DETECTION
// ============================================================================

std::optional<MemoryCorruptionInfo> ZeroDayDetector::Impl::DetectMemoryCorruptionInternal(
    std::span<const uint8_t> buffer) noexcept
{
    try {
        if (buffer.size() < 16) return std::nullopt;

        MemoryCorruptionInfo info;
        int indicators = 0;

        // Detect arbitrary-write primitive clusters: sequences of memory-write
        // opcodes packed within ~20 bytes are a strong proxy for a memory
        // corruption gadget.  The previous loop reset writeCluster to 1 for
        // *every* non-adjacent hit, which silently dropped real cluster
        // counts; we accumulate properly with an explicit "first hit" branch
        // and report the longest observed run.
        {
            int    writeCluster = 0;
            int    maxCluster   = 0;
            bool   havePrev     = false;
            size_t prevPos      = 0;

            const size_t end = (buffer.size() >= 6u) ? (buffer.size() - 6u) : 0u;
            for (size_t i = 0; i < end; ++i) {
                bool isWrite = false;
                // MOV r/m32, imm32 — modr/m must encode memory (mod != 11).
                if (buffer[i] == 0xC7 && (buffer[i+1] & 0xC0) != 0xC0) {
                    isWrite = true;
                }
                // MOV r/m32, r32 with mod==00 (register-indirect, no disp).
                if (buffer[i] == 0x89 && (buffer[i+1] & 0xC0) == 0x00) {
                    isWrite = true;
                }

                if (!isWrite) continue;

                if (!havePrev) {
                    writeCluster = 1;
                    havePrev     = true;
                } else if ((i - prevPos) < 20u) {
                    if (writeCluster < INT_MAX) ++writeCluster;
                } else {
                    if (writeCluster > maxCluster) maxCluster = writeCluster;
                    writeCluster = 1;
                }
                prevPos = i;
            }
            if (writeCluster > maxCluster) maxCluster = writeCluster;

            if (maxCluster >= 4) {
                info.corruptionType     = "Arbitrary Write Primitive";
                info.vulnerableFunction = "write_cluster";
                ++indicators;
            }
        }

        // Detect OOB read patterns: REX.W MOV r64, [r/m + disp32] with very
        // large displacements is a heavy hint for unbounded reads.
        {
            int oobReads = 0;
            const size_t end = (buffer.size() >= 7u) ? (buffer.size() - 7u) : 0u;
            for (size_t i = 0; i < end; ++i) {
                if (buffer[i]   == 0x48 &&
                    buffer[i+1] == 0x8B &&
                    (buffer[i+2] & 0xC0) == 0x80)
                {
                    const uint32_t disp = ReadU32Safe(&buffer[i+3]);
                    if (disp > 0x10000) ++oobReads;
                }
            }
            if (oobReads >= 3) {
                if (info.corruptionType.empty())
                    info.corruptionType = "Information Leak (OOB Read)";
                info.vulnerableFunction = "large_displacement_reads";
                ++indicators;
            }
        }

        if (indicators > 0) {
            m_stats.corruptionsDetected.fetch_add(1, std::memory_order_relaxed);
            return info;
        }
        return std::nullopt;
    } catch (...) { return std::nullopt; }
}

// ============================================================================
// IMPL: CVE CORRELATION
// ============================================================================

bool ZeroDayDetector::Impl::MatchCVEPattern(
    const CVEEntry& cve, std::span<const uint8_t> buffer) noexcept
{
    return ScanForPattern(buffer, std::span<const uint8_t>(cve.pattern));
}

std::vector<CVEMatch> ZeroDayDetector::Impl::CorrelateCVEs(
    const ZeroDayResult& result, std::span<const uint8_t> buffer) noexcept
{
    std::vector<CVEMatch> matches;
    try {
        // SECURITY: do not produce CVE matches purely on cosmetic byte
        // patterns ("MSHTML", "ms-msdt", ...) — those would fire on benign
        // documents and inflate the alert pipeline.  A pattern-only match is
        // accepted ONLY when at least one corroborating exploit indicator
        // (shellcode / ROP / heap-spray / corruption / non-Unknown type)
        // exists.  Pure type matches without a pattern hit are reported only
        // when the result already has corroborating evidence.
        const bool hasCorroborating =
            result.shellcodeInfo.has_value() || result.ropChainInfo.has_value() ||
            result.heapSprayInfo.has_value() || result.corruptionInfo.has_value() ||
            result.type != ExploitType::Unknown;

        for (const auto& cve : m_cveDatabase) {
            const bool typeMatch    = (result.type == cve.exploitType);
            const bool patternMatch = (!buffer.empty() && MatchCVEPattern(cve, buffer));

            if (!typeMatch && !patternMatch) continue;
            if (!hasCorroborating)            continue;
            // Additionally require pattern match when type does not align;
            // a bare type match is not specific enough to attribute a CVE.
            if (!patternMatch)                 continue;

            CVEMatch m;
            m.cveId           = cve.cveId;
            m.description     = cve.description;
            m.cvssScore       = cve.cvssScore;
            m.affectedProduct = cve.affectedProduct;
            m.matchedPattern  = cve.cveId + " pattern";

            if (typeMatch && patternMatch) m.confidence = 0.85f;
            else                            m.confidence = 0.55f;

            matches.push_back(std::move(m));
        }
        m_stats.cveMatches.fetch_add(static_cast<uint64_t>(matches.size()), std::memory_order_relaxed);
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during CVE correlation");
    }
    return matches;
}

// ============================================================================
// IMPL: MITRE MAPPING
// ============================================================================

std::set<std::string> ZeroDayDetector::Impl::MapToMITRE(const ZeroDayResult& result) noexcept {
    std::set<std::string> t;
    try {
        switch (result.type) {
        case ExploitType::Shellcode: case ExploitType::ROPChain: case ExploitType::JOPChain:
            t.insert("T1055"); t.insert("T1203"); break;
        case ExploitType::StackOverflow: case ExploitType::HeapOverflow: case ExploitType::HeapSpray:
            t.insert("T1068"); t.insert("T1211"); break;
        case ExploitType::UseAfterFree: case ExploitType::DoubleFree: case ExploitType::TypeConfusion:
            t.insert("T1210"); t.insert("T1203"); break;
        case ExploitType::ArbitraryWrite: case ExploitType::ArbitraryRead: case ExploitType::InfoLeak:
            t.insert("T1212"); break;
        case ExploitType::KernelExploit: case ExploitType::PrivilegeEscalation:
            t.insert("T1068"); break;
        case ExploitType::DEPBypass: case ExploitType::ASLRBypass: case ExploitType::CFGBypass:
            t.insert("T1211"); break;
        default: break;
        }
        if (result.ropChainInfo.has_value()) t.insert("T1574");
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception during MITRE mapping");
    }
    return t;
}

// ============================================================================
// IMPL: SCORING
// ============================================================================

ExploitSeverity ZeroDayDetector::Impl::CalculateSeverity(const ZeroDayResult& result) noexcept {
    int score = 0;
    if (result.shellcodeInfo.has_value())  score += 30;
    if (result.ropChainInfo.has_value())   score += 40;
    if (result.heapSprayInfo.has_value())  score += 35;
    if (result.corruptionInfo.has_value()) score += 50;
    for (const auto& cve : result.cveMatches) score += static_cast<int>(cve.cvssScore * 2.0f);

    if (score >= 80) return ExploitSeverity::Critical;
    if (score >= 55) return ExploitSeverity::High;
    if (score >= 30) return ExploitSeverity::Medium;
    return ExploitSeverity::Low;
}

DetectionConfidence ZeroDayDetector::Impl::CalculateConfidence(const ZeroDayResult& result) noexcept {
    int conf = 0;
    if (result.shellcodeInfo.has_value())  conf += 25;
    if (result.ropChainInfo.has_value())   conf += 25;
    if (result.heapSprayInfo.has_value())  conf += 20;
    if (result.corruptionInfo.has_value()) conf += 20;
    if (!result.cveMatches.empty())        conf += 30;
    if (result.mitreIds.size() >= 2)       conf += 10;

    if (conf >= 75) return DetectionConfidence::Certain;
    if (conf >= 50) return DetectionConfidence::High;
    if (conf >= 25) return DetectionConfidence::Medium;
    return DetectionConfidence::Low;
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void ZeroDayDetector::Impl::NotifyDetection(const ZeroDayResult& result) noexcept {
    // SECURITY: invoking user callbacks while holding m_mutex is a deadlock
    // hazard — a callback that calls Register/Unregister must take the
    // unique lock.  Therefore we copy the std::function under a shared lock
    // and dispatch outside the lock.
    ZeroDayDetectionCallback cb;
    try {
        std::shared_lock lock(m_mutex);
        cb = m_detectionCallback;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Exception capturing detection callback");
        return;
    }

    if (!cb) return;

    try {
        cb(result);
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Detection callback threw an exception");
    }
}

void ZeroDayDetector::Impl::NotifyError(const std::string& msg, int code) noexcept {
    ErrorCallback cb;
    try {
        std::shared_lock lock(m_mutex);
        cb = m_errorCallback;
    } catch (...) {
        return;
    }

    if (!cb) return;

    try {
        cb(msg, code);
    } catch (...) {
        // Suppress: error callback is best-effort.
    }
}

// ============================================================================
// PUBLIC API: SINGLETON & LIFECYCLE
// ============================================================================

ZeroDayDetector& ZeroDayDetector::Instance() noexcept {
    static ZeroDayDetector instance;
    return instance;
}

bool ZeroDayDetector::HasInstance() noexcept { return true; }

ZeroDayDetector::ZeroDayDetector() : m_impl(std::make_unique<Impl>()) {}

ZeroDayDetector::~ZeroDayDetector() { if (m_impl) Shutdown(); }

bool ZeroDayDetector::Initialize(const ZeroDayConfiguration& config) {
    if (!m_impl) return false;

    // Claim the right to initialize, from any state that means "not running, nothing
    // half-built".
    //
    // The CAS itself is unchanged and is the part that matters: exactly one thread
    // flips into Initializing and performs the work, so a concurrent AnalyzeBuffer
    // cannot observe half-populated pattern/CVE caches. What was wrong was the set of
    // accepted STARTING states - only Uninitialized.
    //
    // Shutdown() leaves the status at Stopped, so the detector was effectively
    // ONE-SHOT: after a single shutdown every later Initialize hit this CAS, fell
    // through to the error branch, and returned false for the remaining life of the
    // process. ScanEngine::Initialize treats that as fatal, so one ScanEngine::Shutdown
    // made the whole engine permanently un-initializable - which is what made
    // RealTimeProtection::Restart(), literally Stop() then Start(), unable to succeed
    // and left the machine with no real-time protection.
    //
    // Error is accepted for the same reason rather than left as a second dead end: a
    // caller correcting an invalid configuration must be able to try again. Retrying
    // from a partially built state is safe because InitializePatterns,
    // InitializeCVEDatabase and InitializeMITRE each clear their container before
    // filling it, so initialization always rebuilds from scratch.
    //
    // Initializing, Stopping and Running are deliberately NOT accepted: the first two
    // are transient states owned by another thread, and Running is reported as success
    // below.
    ZeroDayStatus expected = ZeroDayStatus::Uninitialized;
    bool claimed = m_impl->m_status.compare_exchange_strong(
        expected, ZeroDayStatus::Initializing,
        std::memory_order_acq_rel, std::memory_order_acquire);

    if (!claimed &&
        (expected == ZeroDayStatus::Stopped || expected == ZeroDayStatus::Error)) {
        const ZeroDayStatus restartFrom = expected;
        claimed = m_impl->m_status.compare_exchange_strong(
            expected, ZeroDayStatus::Initializing,
            std::memory_order_acq_rel, std::memory_order_acquire);
        if (claimed) {
            SS_LOG_INFO(kLogCategory, L"Re-initializing from state %u",
                static_cast<unsigned>(restartFrom));
        }
    }

    if (!claimed)
    {
        if (expected == ZeroDayStatus::Running) {
            SS_LOG_WARN(kLogCategory, L"Already initialized");
            return true;
        }
        SS_LOG_ERROR(kLogCategory, L"Initialize called from unexpected state (%u)",
            static_cast<unsigned>(expected));
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration");
        m_impl->m_status.store(ZeroDayStatus::Error, std::memory_order_release);
        return false;
    }

    try {
        // All mutation of pattern/CVE/MITRE caches happens under the unique
        // lock so that any concurrent reader (DetectShellcodeInternal, etc.)
        // observes a fully constructed snapshot.
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = config;
        m_impl->m_stats.Reset();
        m_impl->InitializePatterns();
        m_impl->InitializeCVEDatabase();
        m_impl->InitializeMITRE();
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"Init failed: %ls", ToWide(ex.what()).c_str());
        m_impl->m_status.store(ZeroDayStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_FATAL(kLogCategory, L"Unknown init error");
        m_impl->m_status.store(ZeroDayStatus::Error, std::memory_order_release);
        return false;
    }

    // Publish: order matters - status flip then m_initialized so observers
    // that test IsInitialized() see Running too.
    m_impl->m_status.store(ZeroDayStatus::Running, std::memory_order_release);
    m_impl->m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(kLogCategory, L"Initialized with %zu shellcode patterns, %zu CVE entries",
        m_impl->m_shellcodePatterns.size(), m_impl->m_cveDatabase.size());
    return true;
}

void ZeroDayDetector::Shutdown() {
    if (!m_impl) return;
    if (!m_impl->m_initialized.exchange(false, std::memory_order_acq_rel)) return;
    try {
        m_impl->m_status.store(ZeroDayStatus::Stopping, std::memory_order_release);
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_shellcodePatterns.clear();
            m_impl->m_cveDatabase.clear();
            m_impl->m_mitreTechniques.clear();
            m_impl->m_detectionCallback = nullptr;
            m_impl->m_errorCallback     = nullptr;
        }
        m_impl->m_status.store(ZeroDayStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(kLogCategory, L"Shutdown complete");
    } catch (...) { SS_LOG_ERROR(kLogCategory, L"Exception during shutdown"); }
}

bool ZeroDayDetector::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

ZeroDayStatus ZeroDayDetector::GetStatus() const noexcept {
    if (!m_impl) return ZeroDayStatus::Uninitialized;
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC API: BUFFER ANALYSIS
// ============================================================================

ZeroDayResult ZeroDayDetector::AnalyzeBuffer(const std::vector<uint8_t>& buffer) {
    return AnalyzeBuffer(std::span<const uint8_t>(buffer));
}

ZeroDayResult ZeroDayDetector::AnalyzeBuffer(
    std::span<const uint8_t> buffer, const ZeroDayAnalysisOptions& options)
{
    ZeroDayResult result;
    const auto t0 = Clock::now();
    try {
        if (!IsInitialized()) {
            SS_LOG_WARN(kLogCategory, L"AnalyzeBuffer called before init");
            return result;
        }
        if (buffer.empty()) return result;

        if (buffer.size() > ZeroDayConstants::MAX_BUFFER_SIZE) {
            SS_LOG_WARN(kLogCategory, L"Buffer exceeds max size (%zu) — truncating",
                buffer.size());
            buffer = buffer.subspan(0, ZeroDayConstants::MAX_BUFFER_SIZE);
        }

        std::shared_lock lock(m_impl->m_mutex);

        if (options.detectShellcode) {
            result.shellcodeInfo = m_impl->DetectShellcodeInternal(buffer);
            if (result.shellcodeInfo.has_value()) {
                result.detected = true;
                result.type     = ExploitType::Shellcode;
                result.description = "Shellcode detected: " +
                    std::string(GetShellcodeTypeName(result.shellcodeInfo->type));
            }
        }

        if (options.detectMemoryCorruption) {
            result.corruptionInfo = m_impl->DetectMemoryCorruptionInternal(buffer);
            if (result.corruptionInfo.has_value()) {
                result.detected = true;
                if (result.type == ExploitType::Unknown)
                    result.type = ExploitType::ArbitraryWrite;
                if (result.description.empty())
                    result.description = result.corruptionInfo->corruptionType;
            }
        }

        if (result.detected && options.correlateCVE)
            result.cveMatches = m_impl->CorrelateCVEs(result, buffer);

        if (result.detected) {
            result.mitreIds   = m_impl->MapToMITRE(result);
            result.severity   = m_impl->CalculateSeverity(result);
            result.confidence = m_impl->CalculateConfidence(result);

            const auto idx = static_cast<size_t>(result.type);
            if (idx < m_impl->m_stats.byExploitType.size())
                m_impl->m_stats.byExploitType[idx].fetch_add(1, std::memory_order_relaxed);
        }

        result.analysisTimeUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t0).count());

        m_impl->m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
        if (result.detected) {
            m_impl->m_stats.exploitsDetected.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();
            m_impl->NotifyDetection(result);
        }
        return result;

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"AnalyzeBuffer failed: %ls", ToWide(ex.what()).c_str());
        m_impl->NotifyError(std::string("AnalyzeBuffer: ") + ex.what(), ERROR_INTERNAL_ERROR);
        return result;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"AnalyzeBuffer: unknown error");
        return result;
    }
}

ZeroDayResult ZeroDayDetector::AnalyzeFile(
    const fs::path& filePath, const ZeroDayAnalysisOptions& options)
{
    ZeroDayResult result;
    try {
        if (!IsInitialized()) return result;

        // Reject empty paths early.
        if (filePath.empty()) {
            SS_LOG_WARN(kLogCategory, L"AnalyzeFile: empty path");
            return result;
        }

        std::error_code ec;

        // SECURITY: validate filesystem entity is a regular file.  Following a
        // junction or device handle from an unprivileged caller would expose
        // the service to TOCTOU and DoS (e.g. /dev/zero-equivalents).  We
        // resolve symlinks via status() (not symlink_status()) so junctions
        // landing on a regular file remain analysable, but pipes / devices
        // are rejected outright.
        const auto st = fs::status(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(kLogCategory, L"AnalyzeFile: status() failed (%d): %ls",
                ec.value(), filePath.wstring().c_str());
            return result;
        }
        if (!fs::exists(st)) {
            SS_LOG_ERROR(kLogCategory, L"File not found: %ls", filePath.wstring().c_str());
            return result;
        }
        if (!fs::is_regular_file(st)) {
            SS_LOG_WARN(kLogCategory, L"AnalyzeFile: not a regular file: %ls",
                filePath.wstring().c_str());
            return result;
        }

        const auto fileSize = fs::file_size(filePath, ec);
        if (ec || fileSize == 0) {
            SS_LOG_WARN(kLogCategory, L"File size issue (%llu): %ls",
                static_cast<unsigned long long>(fileSize), filePath.wstring().c_str());
            return result;
        }

        // Clamp to MAX_BUFFER_SIZE rather than refusing to scan large files —
        // a malicious actor would simply pad payloads beyond the limit.
        const size_t toRead = (fileSize > ZeroDayConstants::MAX_BUFFER_SIZE)
            ? ZeroDayConstants::MAX_BUFFER_SIZE
            : static_cast<size_t>(fileSize);

        std::ifstream ifs(filePath, std::ios::binary);
        if (!ifs.is_open()) {
            SS_LOG_ERROR(kLogCategory, L"Cannot open: %ls", filePath.wstring().c_str());
            return result;
        }

        std::vector<uint8_t> buf;
        try {
            buf.resize(toRead);
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(kLogCategory, L"AnalyzeFile: OOM allocating %zu bytes", toRead);
            return result;
        }

        ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(toRead));
        const auto actuallyRead = static_cast<size_t>(ifs.gcount());
        if (actuallyRead == 0) {
            SS_LOG_ERROR(kLogCategory, L"Read returned zero bytes: %ls", filePath.wstring().c_str());
            return result;
        }
        if (actuallyRead < toRead) {
            // Short read is acceptable — analyse what we got.
            buf.resize(actuallyRead);
        }
        return AnalyzeBuffer(std::span<const uint8_t>(buf), options);

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"AnalyzeFile exception: %ls", ToWide(ex.what()).c_str());
        return result;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"AnalyzeFile: unknown error");
        return result;
    }
}

// ============================================================================
// PUBLIC API: STACK ANALYSIS
// ============================================================================

ZeroDayResult ZeroDayDetector::AnalyzeStack(const std::vector<uintptr_t>& stackDump) {
    return AnalyzeStack(std::span<const uintptr_t>(stackDump),
                        std::map<std::string, std::pair<uintptr_t, size_t>>{});
}

ZeroDayResult ZeroDayDetector::AnalyzeStack(
    std::span<const uintptr_t> stackDump,
    const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges)
{
    ZeroDayResult result;
    const auto t0 = Clock::now();
    try {
        if (!IsInitialized() || stackDump.empty()) return result;

        // Bound attacker-influenced inputs to keep ROP detection cost capped.
        if (stackDump.size() > kMaxStackDumpFrames) {
            stackDump = stackDump.subspan(0, kMaxStackDumpFrames);
        }
        if (moduleRanges.size() > kMaxModuleRangesEntries) {
            SS_LOG_WARN(kLogCategory, L"AnalyzeStack: moduleRanges too large (%zu) — refusing",
                moduleRanges.size());
            return result;
        }

        std::shared_lock lock(m_impl->m_mutex);

        result.ropChainInfo = m_impl->DetectROPChainInternal(stackDump, moduleRanges);
        if (result.ropChainInfo.has_value()) {
            result.detected    = true;
            result.type        = ExploitType::ROPChain;
            result.description = "ROP chain: " + result.ropChainInfo->purpose;
        }

        if (result.detected) {
            result.mitreIds   = m_impl->MapToMITRE(result);
            result.severity   = m_impl->CalculateSeverity(result);
            result.confidence = m_impl->CalculateConfidence(result);
        }

        result.analysisTimeUs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t0).count());

        m_impl->m_stats.totalAnalyses.fetch_add(1, std::memory_order_relaxed);
        if (result.detected) {
            m_impl->m_stats.exploitsDetected.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();
            m_impl->NotifyDetection(result);
        }
        return result;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"AnalyzeStack: unknown error");
        return result;
    }
}

// ============================================================================
// PUBLIC API: SHELLCODE / ROP / HEAP / CVE
// ============================================================================

std::optional<ShellcodeInfo> ZeroDayDetector::DetectShellcode(std::span<const uint8_t> buffer) {
    if (!IsInitialized() || buffer.empty()) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->DetectShellcodeInternal(buffer);
}

bool ZeroDayDetector::IsNopSled(std::span<const uint8_t> buffer) {
    if (!IsInitialized()) return false;
    size_t len = 0;
    return m_impl->DetectNOPSled(buffer, len);
}

bool ZeroDayDetector::HasGetPC(std::span<const uint8_t> buffer) {
    if (!IsInitialized()) return false;
    return m_impl->DetectGetPCTrick(buffer);
}

bool ZeroDayDetector::HasDecoderStub(std::span<const uint8_t> buffer) {
    if (!IsInitialized()) return false;
    return m_impl->DetectDecoderStub(buffer);
}

std::optional<ROPChainInfo> ZeroDayDetector::DetectROPChain(
    std::span<const uintptr_t> addresses,
    const std::map<std::string, std::pair<uintptr_t, size_t>>& moduleRanges)
{
    if (!IsInitialized()) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->DetectROPChainInternal(addresses, moduleRanges);
}

std::vector<ROPGadget> ZeroDayDetector::FindGadgets(
    std::span<const uint8_t> moduleData, uintptr_t baseAddress)
{
    std::vector<ROPGadget> gadgets;
    if (!IsInitialized() || moduleData.size() < 2) return gadgets;

    // Bound the scan window — caller-provided modules can legitimately be
    // very large (>100MB for native loaders); the gadget identifier is O(N*6)
    // and we intentionally limit it to keep p99 latency bounded.
    const size_t scanSize = (std::min)(moduleData.size(), kMaxFindGadgetsBytes);

    try {
        gadgets.reserve(64);
    } catch (const std::bad_alloc&) {
        return gadgets;
    }

    for (size_t i = 1; i < scanSize; ++i) {
        if (moduleData[i] != 0xC3) continue;
        const size_t maxBack = (std::min)(i, static_cast<size_t>(6));
        for (size_t back = 1; back <= maxBack; ++back) {
            const size_t start = i - back;
            auto g = m_impl->IdentifyGadgetBytes(
                baseAddress + start, moduleData.subspan(start, back + 1), "scan");
            if (g.type != GadgetType::Unknown) {
                try {
                    gadgets.push_back(std::move(g));
                } catch (const std::bad_alloc&) {
                    return gadgets;
                }
                break;
            }
        }
        if (gadgets.size() >= kMaxGadgetsReturned) break;
    }
    return gadgets;
}

std::optional<HeapSprayInfo> ZeroDayDetector::DetectHeapSpray(
    const std::vector<std::pair<uintptr_t, size_t>>& allocations)
{
    if (!IsInitialized()) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->DetectHeapSprayInternal(allocations);
}

bool ZeroDayDetector::IsHeapSprayPattern(std::span<const uint8_t> data) {
    if (!IsInitialized() || data.size() < 64) return false;
    std::array<uint64_t, 256> counts{};
    for (const uint8_t b : data) counts[b]++;
    uint64_t maxCount = 0;
    for (const uint64_t c : counts) maxCount = (std::max)(maxCount, c);
    return (maxCount >= data.size() * 9 / 10);
}

std::vector<CVEMatch> ZeroDayDetector::LookupCVE(const ZeroDayResult& result) {
    if (!IsInitialized()) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->CorrelateCVEs(result, {});
}

std::optional<CVEMatch> ZeroDayDetector::GetCVEInfo(const std::string& cveId) {
    if (!IsInitialized()) return std::nullopt;
    std::shared_lock lock(m_impl->m_mutex);
    for (const auto& e : m_impl->m_cveDatabase) {
        if (e.cveId == cveId) {
            CVEMatch m;
            m.cveId = e.cveId; m.description = e.description;
            m.cvssScore = e.cvssScore; m.affectedProduct = e.affectedProduct;
            m.confidence = 1.0f;
            return m;
        }
    }
    return std::nullopt;
}

// ============================================================================
// PUBLIC API: CALLBACKS / STATS / SELF-TEST
// ============================================================================

void ZeroDayDetector::RegisterDetectionCallback(ZeroDayDetectionCallback cb) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_detectionCallback = std::move(cb);
}

void ZeroDayDetector::RegisterErrorCallback(ErrorCallback cb) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallback = std::move(cb);
}

void ZeroDayDetector::UnregisterCallbacks() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_detectionCallback = nullptr;
    m_impl->m_errorCallback     = nullptr;
}

ZeroDayStatistics ZeroDayDetector::GetStatistics() const {
    if (!m_impl) return ZeroDayStatistics{};
    return m_impl->m_stats;
}

void ZeroDayDetector::ResetStatistics() {
    if (m_impl) m_impl->m_stats.Reset();
}

bool ZeroDayDetector::SelfTest() {
    try {
        if (!IsInitialized()) return false;

        std::vector<uint8_t> nopSled(32, 0x90);
        nopSled.push_back(0xCC);
        if (!IsNopSled(std::span<const uint8_t>(nopSled))) {
            SS_LOG_ERROR(kLogCategory, L"SelfTest: NOP sled detection failed");
            return false;
        }

        std::vector<uint8_t> getpc = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
        if (!HasGetPC(std::span<const uint8_t>(getpc))) {
            SS_LOG_ERROR(kLogCategory, L"SelfTest: GetPC detection failed");
            return false;
        }

        std::vector<uint8_t> uniform(256);
        std::iota(uniform.begin(), uniform.end(), 0);
        const double ent = m_impl->ComputeEntropy(std::span<const uint8_t>(uniform));
        if (ent < 7.9 || ent > 8.1) {
            SS_LOG_ERROR(kLogCategory, L"SelfTest: Entropy off (%.2f)", ent);
            return false;
        }

        SS_LOG_INFO(kLogCategory, L"SelfTest: all checks passed");
        return true;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"SelfTest: exception");
        return false;
    }
}

std::string ZeroDayDetector::GetVersionString() noexcept {
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
        ZeroDayConstants::VERSION_MAJOR, ZeroDayConstants::VERSION_MINOR, ZeroDayConstants::VERSION_PATCH);
    return std::string(buf);
}

// ============================================================================
// STATISTICS / CONFIG VALIDATION
// ============================================================================

void ZeroDayStatistics::Reset() noexcept {
    totalAnalyses.store(0, std::memory_order_relaxed);
    exploitsDetected.store(0, std::memory_order_relaxed);
    shellcodeDetected.store(0, std::memory_order_relaxed);
    ropChainsDetected.store(0, std::memory_order_relaxed);
    heapSpraysDetected.store(0, std::memory_order_relaxed);
    corruptionsDetected.store(0, std::memory_order_relaxed);
    cveMatches.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    for (auto& a : byExploitType) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string ZeroDayStatistics::ToJson() const {
    std::ostringstream os;
    os << "{\"totalAnalyses\":" << totalAnalyses.load(std::memory_order_relaxed)
       << ",\"exploitsDetected\":" << exploitsDetected.load(std::memory_order_relaxed)
       << ",\"shellcode\":" << shellcodeDetected.load(std::memory_order_relaxed)
       << ",\"ropChains\":" << ropChainsDetected.load(std::memory_order_relaxed)
       << ",\"heapSprays\":" << heapSpraysDetected.load(std::memory_order_relaxed)
       << ",\"corruptions\":" << corruptionsDetected.load(std::memory_order_relaxed)
       << ",\"cveMatches\":" << cveMatches.load(std::memory_order_relaxed)
       << ",\"falsePositives\":" << falsePositives.load(std::memory_order_relaxed) << "}";
    return os.str();
}

bool ZeroDayAnalysisOptions::IsValid() const noexcept {
    return maxAnalysisTimeMs > 0 && maxAnalysisTimeMs <= 120000;
}

bool ZeroDayConfiguration::IsValid() const noexcept {
    return workerThreads > 0 && workerThreads <= 32 && defaultOptions.IsValid();
}

// ============================================================================
// STRUCT ToJson() IMPLEMENTATIONS
// ============================================================================

std::string ROPGadget::ToJson() const {
    std::ostringstream os;
    os << "{\"address\":" << address << ",\"type\":" << static_cast<int>(type)
       << ",\"disasm\":\"" << disassembly << "\",\"module\":\"" << module << "\"}";
    return os.str();
}

std::string ROPChainInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"startAddress\":" << startAddress << ",\"gadgetCount\":" << gadgets.size()
       << ",\"purpose\":\"" << purpose << "\",\"complete\":" << (isComplete ? "true" : "false")
       << ",\"targetAPI\":\"" << targetAPI << "\"}";
    return os.str();
}

std::string ShellcodeInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"type\":" << static_cast<int>(type) << ",\"offset\":" << startOffset
       << ",\"size\":" << size << ",\"entropy\":" << entropy
       << ",\"nopSled\":" << (hasNopSled ? "true" : "false")
       << ",\"getPC\":" << (hasGetPC ? "true" : "false")
       << ",\"decoder\":" << (hasDecoderStub ? "true" : "false") << "}";
    return os.str();
}

std::string HeapSprayInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"allocationCount\":" << allocationCount << ",\"totalSize\":" << totalSize
       << ",\"sprayValue\":" << sprayValue
       << ",\"shellcode\":" << (containsShellcode ? "true" : "false")
       << ",\"rop\":" << (containsROP ? "true" : "false") << "}";
    return os.str();
}

std::string MemoryCorruptionInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"type\":\"" << corruptionType << "\",\"targetAddress\":" << targetAddress
       << ",\"sourceAddress\":" << sourceAddress
       << ",\"function\":\"" << vulnerableFunction << "\"}";
    return os.str();
}

std::string CVEMatch::ToJson() const {
    std::ostringstream os;
    os << "{\"cveId\":\"" << cveId << "\",\"description\":\"" << description
       << "\",\"cvss\":" << cvssScore << ",\"confidence\":" << confidence << "}";
    return os.str();
}

std::string ZeroDayResult::ToJson() const {
    std::ostringstream os;
    os << "{\"detected\":" << (detected ? "true" : "false")
       << ",\"type\":" << static_cast<int>(type)
       << ",\"severity\":" << static_cast<int>(severity)
       << ",\"confidence\":" << static_cast<int>(confidence)
       << ",\"analysisTimeUs\":" << analysisTimeUs;
    if (shellcodeInfo.has_value())  os << ",\"shellcode\":" << shellcodeInfo->ToJson();
    if (ropChainInfo.has_value())   os << ",\"ropChain\":" << ropChainInfo->ToJson();
    if (heapSprayInfo.has_value())  os << ",\"heapSpray\":" << heapSprayInfo->ToJson();
    if (corruptionInfo.has_value()) os << ",\"corruption\":" << corruptionInfo->ToJson();
    os << "}";
    return os.str();
}

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

std::string_view GetExploitTypeName(ExploitType type) noexcept {
    switch (type) {
    case ExploitType::Unknown:             return "Unknown";
    case ExploitType::StackOverflow:       return "StackOverflow";
    case ExploitType::HeapOverflow:        return "HeapOverflow";
    case ExploitType::HeapSpray:           return "HeapSpray";
    case ExploitType::UseAfterFree:        return "UseAfterFree";
    case ExploitType::DoubleFree:          return "DoubleFree";
    case ExploitType::TypeConfusion:       return "TypeConfusion";
    case ExploitType::IntegerOverflow:     return "IntegerOverflow";
    case ExploitType::FormatString:        return "FormatString";
    case ExploitType::ROPChain:            return "ROPChain";
    case ExploitType::JOPChain:            return "JOPChain";
    case ExploitType::Shellcode:           return "Shellcode";
    case ExploitType::StackPivot:          return "StackPivot";
    case ExploitType::InfoLeak:            return "InfoLeak";
    case ExploitType::ArbitraryRead:       return "ArbitraryRead";
    case ExploitType::ArbitraryWrite:      return "ArbitraryWrite";
    case ExploitType::ASLRBypass:          return "ASLRBypass";
    case ExploitType::DEPBypass:           return "DEPBypass";
    case ExploitType::CFGBypass:           return "CFGBypass";
    case ExploitType::KernelExploit:       return "KernelExploit";
    case ExploitType::PrivilegeEscalation: return "PrivilegeEscalation";
    default: return "Unknown";
    }
}

std::string_view GetShellcodeTypeName(ShellcodeType type) noexcept {
    switch (type) {
    case ShellcodeType::Unknown:      return "Unknown";
    case ShellcodeType::ConnectBack:  return "ConnectBack";
    case ShellcodeType::BindShell:    return "BindShell";
    case ShellcodeType::Downloader:   return "Downloader";
    case ShellcodeType::Stager:       return "Stager";
    case ShellcodeType::Egg_Hunter:   return "EggHunter";
    case ShellcodeType::Meterpreter:  return "Meterpreter";
    case ShellcodeType::CobaltStrike: return "CobaltStrike";
    case ShellcodeType::Custom:       return "Custom";
    default: return "Unknown";
    }
}

std::string_view GetGadgetTypeName(GadgetType type) noexcept {
    switch (type) {
    case GadgetType::Unknown:    return "Unknown";
    case GadgetType::PopRet:     return "PopRet";
    case GadgetType::MoveRet:    return "MoveRet";
    case GadgetType::AddRet:     return "AddRet";
    case GadgetType::XchgRet:    return "XchgRet";
    case GadgetType::WriteWhat:  return "WriteWhat";
    case GadgetType::StackPivot: return "StackPivot";
    case GadgetType::Syscall:    return "Syscall";
    case GadgetType::JmpReg:     return "JmpReg";
    case GadgetType::CallReg:    return "CallReg";
    default: return "Unknown";
    }
}

std::string_view GetExploitSeverityName(ExploitSeverity s) noexcept {
    switch (s) {
    case ExploitSeverity::Low:      return "Low";
    case ExploitSeverity::Medium:   return "Medium";
    case ExploitSeverity::High:     return "High";
    case ExploitSeverity::Critical: return "Critical";
    default: return "Unknown";
    }
}

std::string_view GetDetectionConfidenceName(DetectionConfidence c) noexcept {
    switch (c) {
    case DetectionConfidence::Low:     return "Low";
    case DetectionConfidence::Medium:  return "Medium";
    case DetectionConfidence::High:    return "High";
    case DetectionConfidence::Certain: return "Certain";
    default: return "Unknown";
    }
}

float CalculateEntropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0f;
    std::array<uint64_t, 256> counts{};
    for (const uint8_t b : data) counts[b]++;
    double entropy = 0.0;
    const double sz = static_cast<double>(data.size());
    for (const uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / sz;
        entropy -= p * std::log2(p);
    }
    return static_cast<float>(entropy);
}

bool IsPotentialShellcode(std::span<const uint8_t> data) {
    if (data.size() < 16) return false;
    const float ent = CalculateEntropy(data);
    if (ent < ZeroDayConstants::SHELLCODE_ENTROPY_THRESHOLD) return false;

    int indicators = 0;
    for (size_t i = 0; i + 5 < data.size(); ++i) {
        if (data[i] == 0xE8 && data[i+1] == 0x00 && data[i+2] == 0x00 &&
            data[i+3] == 0x00 && data[i+4] == 0x00) { ++indicators; break; }
    }
    size_t nops = 0;
    for (const uint8_t b : data) {
        if (b == 0x90) ++nops; else nops = 0;
        if (nops >= 8) { ++indicators; break; }
    }
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == 0x0F && data[i+1] == 0x05) { ++indicators; break; }
        if (data[i] == 0xCD && data[i+1] == 0x80) { ++indicators; break; }
    }
    return indicators >= 1;
}

}  // namespace ShadowStrike::Core::Engine