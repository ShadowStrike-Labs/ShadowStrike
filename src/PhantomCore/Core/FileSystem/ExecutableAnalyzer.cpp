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
 * ShadowStrike Core FileSystem - EXECUTABLE ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file ExecutableAnalyzer.cpp
 * @brief Enterprise-grade PE/ELF binary analysis engine implementation.
 *
 * This module provides comprehensive executable analysis including:
 * - PE header parsing (DOS, NT, Optional, Sections)
 * - Import/Export table analysis with risk assessment
 * - Resource extraction and analysis
 * - Rich header parsing for compiler detection
 * - Code signature verification
 * - Packer/crypter detection (UPX, Themida, VMProtect, etc.)
 * - Anomaly detection (suspicious sections, imports, characteristics)
 * - Risk scoring based on multiple indicators
 * - Integration with HashStore, PatternStore, ThreatIntel
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ExecutableAnalyzer.hpp"
#include "../../Diagnostics/DiagTrace.hpp"   // SS_DIAG / SS_DIAG_SCOPE
#include <span>

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/HashUtils.hpp"

// Windows includes for PE parsing
#include <Windows.h>
#include <winnt.h>
#include <wintrust.h>
#include <softpub.h>
#include <Imagehlp.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "crypt32.lib")

// Standard library
#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Converts byte array to hex string.
 */
std::string BytesToHex(std::span<const uint8_t> bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        oss << std::setw(2) << static_cast<uint32_t>(byte);
    }
    return oss.str();
}

/**
 * @brief Calculates Shannon entropy of data.
 */
double CalculateEntropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequency{};
    for (const auto byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (const auto count : frequency) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) / dataSize;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

/**
 * @brief Safe RVA to file offset conversion with integer overflow protection.
 */
std::optional<uint32_t> RVAToFileOffset(uint32_t rva, std::span<const PESection> sections) {
    for (const auto& section : sections) {
        // Overflow-safe: rva >= VA && rva - VA < VirtualSize
        if (rva >= section.virtualAddress) {
            const uint32_t delta = rva - section.virtualAddress;
            if (delta < section.virtualSize) {
                // Overflow-safe addition for raw offset
                const uint64_t result = static_cast<uint64_t>(section.rawDataOffset) + delta;
                if (result > UINT32_MAX) {
                    return std::nullopt;
                }
                return static_cast<uint32_t>(result);
            }
        }
    }
    return std::nullopt;
}

/**
 * @brief Strips C0/C1/DEL control characters from a caller-controlled
 *        string before it is passed into the wide-format logger.
 *
 * The analyzer logs paths, DLL names and exported function names that
 * originate from the file under analysis. A crafted PE could embed CR/LF
 * or terminal escape sequences in those strings to forge log lines or
 * corrupt downstream log shippers. This helper strips all C0/C1 and DEL
 * controls and caps the output at 512 bytes (with an explicit truncation
 * marker) so log records remain bounded and machine-parseable.
 */
[[nodiscard]] std::string SanitizeNarrowForLog(std::string_view in) {
    constexpr size_t kCap = 512;
    std::string out;
    out.reserve(std::min(in.size(), kCap));
    for (unsigned char uc : in) {
        if (out.size() >= kCap) { out.append("...[truncated]"); break; }
        if (uc < 0x20u || uc == 0x7Fu || (uc >= 0x80u && uc < 0xA0u)) {
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(uc));
        }
    }
    return out;
}

[[nodiscard]] std::wstring SanitizeWideForLog(std::wstring_view in) {
    constexpr size_t kCap = 512;
    std::wstring out;
    out.reserve(std::min(in.size(), kCap));
    for (wchar_t c : in) {
        if (out.size() >= kCap) { out.append(L"...[truncated]"); break; }
        const auto u = static_cast<uint32_t>(c);
        if (u < 0x20u || u == 0x7Fu || (u >= 0x80u && u < 0xA0u)) {
            out.push_back(L'?');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

/**
 * @brief Sanitizes section name (may contain nulls).
 */
std::string SanitizeSectionName(const char* name, size_t maxLen = 8) {
    std::string result;
    result.reserve(maxLen);
    for (size_t i = 0; i < maxLen && name[i] != '\0'; ++i) {
        if (std::isprint(static_cast<unsigned char>(name[i]))) {
            result += name[i];
        }
    }
    return result;
}

/**
 * @brief Gets subsystem name.
 */
const char* GetSubsystemName(SubsystemType subsystem) {
    switch (subsystem) {
        case SubsystemType::Native: return "Native";
        case SubsystemType::WindowsGUI: return "Windows GUI";
        case SubsystemType::WindowsCUI: return "Windows Console";
        case SubsystemType::OS2CUI: return "OS/2 Console";
        case SubsystemType::POSIXCUI: return "POSIX Console";
        case SubsystemType::EFIApplication: return "EFI Application";
        case SubsystemType::EFIBootServiceDriver: return "EFI Boot Service Driver";
        case SubsystemType::EFIRuntimeDriver: return "EFI Runtime Driver";
        case SubsystemType::XBOX: return "Xbox";
        default: return "Unknown";
    }
}

/**
 * @brief Risky API database for import analysis.
 */
struct RiskyAPIDatabase {
    std::unordered_map<std::string, std::pair<ImportRiskLevel, std::string>> apis;

    RiskyAPIDatabase() {
        // Critical risk APIs (often used by malware)
        apis["VirtualAllocEx"] = {ImportRiskLevel::Critical, "Remote memory allocation (process injection)"};
        apis["WriteProcessMemory"] = {ImportRiskLevel::Critical, "Write to remote process (injection)"};
        apis["CreateRemoteThread"] = {ImportRiskLevel::Critical, "Remote thread creation (injection)"};
        apis["SetWindowsHookEx"] = {ImportRiskLevel::Critical, "Keyboard/mouse hooking (keylogger)"};
        apis["SetWindowsHookExA"] = {ImportRiskLevel::Critical, "Keyboard/mouse hooking (keylogger)"};
        apis["SetWindowsHookExW"] = {ImportRiskLevel::Critical, "Keyboard/mouse hooking (keylogger)"};
        apis["NtSetContextThread"] = {ImportRiskLevel::Critical, "Thread context manipulation (APC injection)"};
        apis["ZwSetContextThread"] = {ImportRiskLevel::Critical, "Thread context manipulation (APC injection)"};
        apis["RtlCreateUserThread"] = {ImportRiskLevel::Critical, "User thread creation (injection)"};

        // High risk APIs
        apis["VirtualAlloc"] = {ImportRiskLevel::High, "Memory allocation (shellcode execution)"};
        apis["VirtualProtect"] = {ImportRiskLevel::High, "Memory protection change (DEP bypass)"};
        apis["VirtualProtectEx"] = {ImportRiskLevel::High, "Remote memory protection (injection)"};
        apis["OpenProcess"] = {ImportRiskLevel::High, "Process handle acquisition (injection prep)"};
        apis["IsDebuggerPresent"] = {ImportRiskLevel::High, "Anti-debugging technique"};
        apis["CheckRemoteDebuggerPresent"] = {ImportRiskLevel::High, "Anti-debugging technique"};
        apis["NtQueryInformationProcess"] = {ImportRiskLevel::High, "Process info query (anti-debug)"};
        apis["ZwQueryInformationProcess"] = {ImportRiskLevel::High, "Process info query (anti-debug)"};
        apis["GetProcAddress"] = {ImportRiskLevel::High, "Dynamic API resolution (obfuscation)"};
        apis["LoadLibrary"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["LoadLibraryA"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["LoadLibraryW"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["LoadLibraryEx"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["LoadLibraryExA"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["LoadLibraryExW"] = {ImportRiskLevel::High, "Dynamic library loading"};
        apis["CreateToolhelp32Snapshot"] = {ImportRiskLevel::High, "Process enumeration"};
        apis["Process32First"] = {ImportRiskLevel::High, "Process enumeration"};
        apis["Process32Next"] = {ImportRiskLevel::High, "Process enumeration"};
        apis["CryptAcquireContext"] = {ImportRiskLevel::High, "Cryptographic operations (ransomware)"};
        apis["CryptEncrypt"] = {ImportRiskLevel::High, "Data encryption (ransomware)"};
        apis["CryptDecrypt"] = {ImportRiskLevel::High, "Data decryption"};

        // Medium risk APIs
        apis["CreateProcess"] = {ImportRiskLevel::Medium, "Process creation"};
        apis["CreateProcessA"] = {ImportRiskLevel::Medium, "Process creation"};
        apis["CreateProcessW"] = {ImportRiskLevel::Medium, "Process creation"};
        apis["ShellExecute"] = {ImportRiskLevel::Medium, "Shell command execution"};
        apis["ShellExecuteA"] = {ImportRiskLevel::Medium, "Shell command execution"};
        apis["ShellExecuteW"] = {ImportRiskLevel::Medium, "Shell command execution"};
        apis["WinExec"] = {ImportRiskLevel::Medium, "Program execution"};
        apis["CreateThread"] = {ImportRiskLevel::Medium, "Thread creation"};
        apis["RegSetValue"] = {ImportRiskLevel::Medium, "Registry modification"};
        apis["RegSetValueEx"] = {ImportRiskLevel::Medium, "Registry modification"};
        apis["RegSetValueExA"] = {ImportRiskLevel::Medium, "Registry modification"};
        apis["RegSetValueExW"] = {ImportRiskLevel::Medium, "Registry modification"};
        apis["RegCreateKey"] = {ImportRiskLevel::Medium, "Registry key creation"};
        apis["RegCreateKeyEx"] = {ImportRiskLevel::Medium, "Registry key creation"};
        apis["InternetOpen"] = {ImportRiskLevel::Medium, "Internet access"};
        apis["InternetOpenUrl"] = {ImportRiskLevel::Medium, "URL access"};
        apis["URLDownloadToFile"] = {ImportRiskLevel::Medium, "File download (dropper)"};
        apis["HttpSendRequest"] = {ImportRiskLevel::Medium, "HTTP communication (C2)"};

        // Low risk APIs (potentially suspicious in certain contexts)
        apis["GetModuleHandle"] = {ImportRiskLevel::Low, "Module handle retrieval"};
        apis["GetModuleFileName"] = {ImportRiskLevel::Low, "Module filename retrieval"};
        apis["FindResource"] = {ImportRiskLevel::Low, "Resource access"};
        apis["LoadResource"] = {ImportRiskLevel::Low, "Resource loading"};
        apis["SizeofResource"] = {ImportRiskLevel::Low, "Resource size query"};

        // Critical: Nation-state APT techniques
        apis["NtAllocateVirtualMemory"] = {ImportRiskLevel::Critical, "Direct syscall memory allocation (injection)"};
        apis["NtWriteVirtualMemory"] = {ImportRiskLevel::Critical, "Direct syscall memory write (injection)"};
        apis["NtCreateThreadEx"] = {ImportRiskLevel::Critical, "Direct syscall thread creation (injection)"};
        apis["NtMapViewOfSection"] = {ImportRiskLevel::Critical, "Section mapping (process hollowing)"};
        apis["NtUnmapViewOfSection"] = {ImportRiskLevel::Critical, "Section unmapping (process hollowing)"};
        apis["NtQueueApcThread"] = {ImportRiskLevel::Critical, "APC injection technique"};
        apis["NtSuspendThread"] = {ImportRiskLevel::High, "Thread suspension (injection prep)"};
        apis["NtResumeThread"] = {ImportRiskLevel::High, "Thread resume (injection finalization)"};
        apis["NtCreateSection"] = {ImportRiskLevel::High, "Section creation (process hollowing prep)"};
        apis["NtProtectVirtualMemory"] = {ImportRiskLevel::High, "Memory protection change via syscall"};
        apis["NtReadVirtualMemory"] = {ImportRiskLevel::High, "Process memory read via syscall"};

        // Credential theft APIs
        apis["CredEnumerateW"] = {ImportRiskLevel::Critical, "Credential enumeration (credential theft)"};
        apis["CredEnumerateA"] = {ImportRiskLevel::Critical, "Credential enumeration (credential theft)"};
        apis["LsaEnumerateLogonSessions"] = {ImportRiskLevel::Critical, "Logon session enum (mimikatz-like)"};
        apis["SamConnect"] = {ImportRiskLevel::Critical, "SAM database access (credential dump)"};
        apis["LdrLoadDll"] = {ImportRiskLevel::High, "Direct DLL loading bypassing LoadLibrary hooks"};

        // Privilege escalation
        apis["AdjustTokenPrivileges"] = {ImportRiskLevel::High, "Token privilege adjustment (privesc)"};
        apis["ImpersonateLoggedOnUser"] = {ImportRiskLevel::Critical, "User impersonation (privesc)"};
        apis["DuplicateToken"] = {ImportRiskLevel::High, "Token duplication (privesc)"};
        apis["DuplicateTokenEx"] = {ImportRiskLevel::High, "Token duplication (privesc)"};
        apis["SetTokenInformation"] = {ImportRiskLevel::High, "Token modification (defense evasion)"};

        // Defense evasion
        apis["NtSetInformationThread"] = {ImportRiskLevel::High, "Thread info manipulation (hide from debugger)"};
        apis["NtSetInformationProcess"] = {ImportRiskLevel::High, "Process info manipulation (defense evasion)"};
        apis["AmsiScanBuffer"] = {ImportRiskLevel::Medium, "AMSI interaction (possible bypass prep)"};
        apis["EtwEventWrite"] = {ImportRiskLevel::Medium, "ETW interaction (possible blind/patch)"};
    }

    std::pair<ImportRiskLevel, std::string> GetAPIRisk(const std::string& apiName) const {
        auto it = apis.find(apiName);
        if (it != apis.end()) {
            return it->second;
        }
        return {ImportRiskLevel::Safe, ""};
    }
};

const RiskyAPIDatabase& GetRiskyAPIs() {
    static const RiskyAPIDatabase instance;
    return instance;
}

/**
 * @brief Packer signature database.
 */
struct PackerSignature {
    PackerType type;
    std::string name;
    std::vector<std::string> sectionNames;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> signatures;  // offset, pattern
    double minEntropy;
    bool checkEntryPoint;
};

static const std::vector<PackerSignature> g_packerSignatures = {
    {
        PackerType::UPX,
        "UPX",
        {"UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1"},
        {{0, {0x55, 0x50, 0x58, 0x21}}},  // "UPX!"
        6.5,
        true
    },
    {
        PackerType::ASPack,
        "ASPack",
        {".aspack", ".adata", "ASPack"},
        {{0, {0x60, 0xE8, 0x03, 0x00, 0x00, 0x00}}},  // Common ASPack stub
        7.0,
        true
    },
    {
        PackerType::Themida,
        "Themida",
        {".themida", ".winlice"},
        {},
        7.5,
        false
    },
    {
        PackerType::VMProtect,
        "VMProtect",
        {".vmp0", ".vmp1", ".vmp2"},
        {},
        7.3,
        false
    },
    {
        PackerType::PECompact,
        "PECompact",
        {"PEC2", "PECompact2"},
        {},
        6.8,
        true
    },
    {
        PackerType::MPress,
        "MPRESS",
        {".MPRESS1", ".MPRESS2"},
        {{0, {0x4D, 0x50, 0x52, 0x45, 0x53, 0x53}}},  // "MPRESS"
        7.0,
        true
    },
    {
        PackerType::Armadillo,
        "Armadillo",
        // Armadillo uses NORMAL section names (.data/.rsrc) -- they cannot
        // identify it, and listing them matched EVERY PE (a universal false
        // positive that routed clean, Microsoft-signed system DLLs into the
        // emulator). Detect the REAL Armadillo CopyMem-II entry-point stub
        // instead: pushad; call $+5; pop ebp; push eax; push ecx; bswap edx;
        // not edx; pushfd -- 14 distinctive bytes at the entry point (the same
        // canonical signature the dedicated AntiEvasion::PackerDetector uses;
        // ~zero false positives, and it detects genuine Armadillo).
        {},
        { {0, {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x50, 0x51,
               0x0F, 0xCA, 0xF7, 0xD2, 0x9C}} },
        6.9,
        true
    },
    {
        PackerType::Obsidium,
        "Obsidium",
        {".obsidium"},
        {},
        7.6,
        false
    },
    {
        PackerType::PETITE,
        "PEtite",
        {".petite"},
        {},
        6.7,
        true
    },
    {
        PackerType::NsPack,
        "NsPack",
        {".nsp0", ".nsp1", ".nsp2"},
        {},
        7.0,
        true
    },
    {
        PackerType::FSG,
        "FSG",
        {},
        {{0, {0x87, 0x25}}},  // Common FSG entry stub
        7.1,
        true
    },
    {
        PackerType::Enigma,
        "Enigma Protector",
        {".enigma1", ".enigma2"},
        {},
        7.4,
        false
    }
};

} // anonymous namespace

// ============================================================================
// ANALYSIS OPTIONS STATIC METHODS
// ============================================================================

AnalysisOptions AnalysisOptions::CreateFull() noexcept {
    AnalysisOptions opts;
    opts.parseHeaders = true;
    opts.parseImports = true;
    opts.parseExports = true;
    opts.parseResources = true;
    opts.parseRichHeader = true;
    opts.parseSignature = true;
    opts.parseDotNet = true;
    opts.detectPackers = true;
    opts.detectAnomalies = true;
    opts.calculateHashes = true;
    opts.calculateEntropy = true;
    opts.extractStrings = false;
    return opts;
}

AnalysisOptions AnalysisOptions::CreateQuick() noexcept {
    AnalysisOptions opts;
    opts.parseHeaders = true;
    opts.parseImports = true;
    opts.parseExports = false;
    opts.parseResources = false;
    opts.parseRichHeader = false;
    opts.parseSignature = true;
    opts.parseDotNet = true;
    opts.detectPackers = true;
    opts.detectAnomalies = true;
    opts.calculateHashes = true;
    opts.calculateEntropy = false;
    opts.extractStrings = false;
    return opts;
}

AnalysisOptions AnalysisOptions::CreateMinimal() noexcept {
    AnalysisOptions opts;
    opts.parseHeaders = true;
    opts.parseImports = false;
    opts.parseExports = false;
    opts.parseResources = false;
    opts.parseRichHeader = false;
    opts.parseSignature = false;
    opts.parseDotNet = false;
    opts.detectPackers = false;
    opts.detectAnomalies = false;
    opts.calculateHashes = false;
    opts.calculateEntropy = false;
    opts.extractStrings = false;
    return opts;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void ExecutableAnalyzerStatistics::Reset() noexcept {
    filesAnalyzed.store(0, std::memory_order_relaxed);
    buffersAnalyzed.store(0, std::memory_order_relaxed);
    pe32Files.store(0, std::memory_order_relaxed);
    pe64Files.store(0, std::memory_order_relaxed);
    dotNetFiles.store(0, std::memory_order_relaxed);
    packedFiles.store(0, std::memory_order_relaxed);
    signedFiles.store(0, std::memory_order_relaxed);
    invalidFiles.store(0, std::memory_order_relaxed);
    anomaliesDetected.store(0, std::memory_order_relaxed);
    bytesProcessed.store(0, std::memory_order_relaxed);
    averageAnalysisTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ExecutableAnalyzerImpl {
public:
    ExecutableAnalyzerImpl() = default;
    ~ExecutableAnalyzerImpl() = default;

    // Prevent copying
    ExecutableAnalyzerImpl(const ExecutableAnalyzerImpl&) = delete;
    ExecutableAnalyzerImpl& operator=(const ExecutableAnalyzerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize() {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"ExecutableAnalyzer", L"ExecutableAnalyzer: Initializing...");

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"ExecutableAnalyzer", L"ExecutableAnalyzer: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer: Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"ExecutableAnalyzer", L"ExecutableAnalyzer: Shutdown complete");
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    ExecutableInfo Analyze(const std::wstring& filePath, const AnalysisOptions& options) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        ExecutableInfo info{};
        info.analysisTime = std::chrono::system_clock::now();

        try {
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Not initialized");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Validate input
            if (filePath.empty()) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Empty file path");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            if (filePath.length() > 32767) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Path too long: %zu", filePath.length());
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Check file exists using real FileUtils API
            SS_DIAG("OnAccess", "Analyze.Exists ENTER");
            if (!Utils::FileUtils::Exists(filePath)) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: File not found: %hs",
                    SanitizeNarrowForLog(Utils::StringUtils::ToNarrow(filePath)).c_str());
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Get file size via Stat
            SS_DIAG("OnAccess", "Analyze.Stat ENTER");
            Utils::FileUtils::FileStat fileStat;
            if (!Utils::FileUtils::Stat(filePath, fileStat)) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Failed to stat file");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            info.fileSize = fileStat.size;
            if (info.fileSize == 0) {
                SS_LOG_WARN(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: File is empty");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            if (info.fileSize > ExecutableAnalyzerConstants::MAX_FILE_SIZE) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: File too large: %llu bytes", info.fileSize);
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Read file into memory for analysis
            SS_DIAG("OnAccess", "Analyze.ReadAllBytes ENTER size=%llu", (unsigned long long)info.fileSize);
            std::vector<std::byte> fileBytes;
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes, &fileErr)) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Failed to read file: %hs",
                    fileErr.message.c_str());
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            if (fileBytes.empty()) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Read returned empty buffer");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            std::span<const uint8_t> fileData(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            // Analyze the buffer
            { SS_DIAG_SCOPE("OnAccess", "Analyze.ParseBuffer");
            info = AnalyzeBufferImpl(fileData, options);
            }

            // Calculate hashes if requested
            if (options.calculateHashes) {
                SS_DIAG_SCOPE("OnAccess", "Analyze.CalculateHashes");
                CalculateHashes(fileBytes, filePath, info);
            }

            // Verify signature if requested (requires file path)
            if (options.parseSignature) {
                SS_DIAG_SCOPE("OnAccess", "Analyze.VerifySignature");
                info.signature = VerifySignatureImpl(filePath);
                if (info.signature.isSigned) {
                    m_stats.signedFiles.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Get version info
            if (options.parseResources) {
                SS_DIAG_SCOPE("OnAccess", "Analyze.GetVersionInfo");
                info.versionInfo = GetVersionInfoImpl(filePath);
            }

            // Update statistics
            m_stats.filesAnalyzed.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesProcessed.fetch_add(info.fileSize, std::memory_order_relaxed);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            // Update average (simple moving average)
            const uint64_t currentAvg = m_stats.averageAnalysisTimeUs.load(std::memory_order_relaxed);
            const uint64_t newAvg = (currentAvg + duration.count()) / 2;
            m_stats.averageAnalysisTimeUs.store(newAvg, std::memory_order_relaxed);

            SS_LOG_INFO(L"ExecutableAnalyzer",
                L"ExecutableAnalyzer: Analyzed %hs in %llu us (type: %u, risk: %u)",
                SanitizeNarrowForLog(Utils::StringUtils::ToNarrow(filePath)).c_str(),
                static_cast<uint64_t>(duration.count()),
                static_cast<unsigned>(info.type),
                static_cast<unsigned>(info.riskScore));

            return info;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::Analyze: Exception: %hs", e.what());
            m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
            return info;
        }
    }

    ExecutableInfo AnalyzeBuffer(std::span<const uint8_t> buffer, const AnalysisOptions& options) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        try {
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::AnalyzeBuffer: Not initialized");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return ExecutableInfo{};
            }

            if (buffer.empty()) {
                SS_LOG_WARN(L"ExecutableAnalyzer", L"ExecutableAnalyzer::AnalyzeBuffer: Empty buffer");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return ExecutableInfo{};
            }

            if (buffer.size() > ExecutableAnalyzerConstants::MAX_FILE_SIZE) {
                SS_LOG_ERROR(L"ExecutableAnalyzer",
                    L"ExecutableAnalyzer::AnalyzeBuffer: Buffer too large: %zu bytes",
                    buffer.size());
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return ExecutableInfo{};
            }

            auto info = AnalyzeBufferImpl(buffer, options);

            m_stats.buffersAnalyzed.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesProcessed.fetch_add(buffer.size(), std::memory_order_relaxed);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            const uint64_t currentAvg = m_stats.averageAnalysisTimeUs.load(std::memory_order_relaxed);
            const uint64_t newAvg = (currentAvg + duration.count()) / 2;
            m_stats.averageAnalysisTimeUs.store(newAvg, std::memory_order_relaxed);

            return info;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::AnalyzeBuffer: Exception: %hs", e.what());
            m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
            return ExecutableInfo{};
        }
    }

    // ========================================================================
    // TYPE DETECTION
    // ========================================================================

    bool IsPE(const std::wstring& filePath) const {
        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return false;
            }
            if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
                return false;
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            return IsPEBuffer(data);

        } catch (...) {
            return false;
        }
    }

    bool IsPEBuffer(std::span<const uint8_t> buffer) const {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            return false;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dosHeader->e_magic != ExecutableAnalyzerConstants::DOS_SIGNATURE) {
            return false;
        }

        // Minimum bytes needed beyond e_lfanew to validate the NT signature
        // and the FileHeader. Using sizeof(IMAGE_NT_HEADERS) here would
        // demand the 64-bit optional header size on x64 builds and falsely
        // reject legitimate PE32 binaries with smaller optional headers.
        constexpr size_t kMinNtHeaderBytes = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);

        if (dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            dosHeader->e_lfanew > 0x400000 ||
            (dosHeader->e_lfanew & 0x3) != 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + kMinNtHeaderBytes > buffer.size()) {
            return false;
        }

        const uint32_t* signature = reinterpret_cast<const uint32_t*>(
            buffer.data() + dosHeader->e_lfanew);
        if (*signature != ExecutableAnalyzerConstants::NT_SIGNATURE) {
            return false;
        }

        const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
            buffer.data() + dosHeader->e_lfanew + sizeof(uint32_t));

        // Optional header must fit inside the buffer.
        const uint64_t optHeaderEnd =
            static_cast<uint64_t>(dosHeader->e_lfanew) + kMinNtHeaderBytes +
            fileHeader->SizeOfOptionalHeader;
        if (optHeaderEnd > buffer.size()) {
            return false;
        }

        return true;
    }

    ExecutableType GetExecutableType(std::span<const uint8_t> buffer) const {
        if (buffer.size() < 4) {
            return ExecutableType::Unknown;
        }

        // Check DOS/PE
        if (buffer.size() >= sizeof(IMAGE_DOS_HEADER)) {
            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
            if (dosHeader->e_magic == ExecutableAnalyzerConstants::DOS_SIGNATURE) {
                if (dosHeader->e_lfanew > 0 &&
                    dosHeader->e_lfanew <= 0x400000 &&
                    static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= buffer.size()) {

                    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                        buffer.data() + dosHeader->e_lfanew
                    );

                    if (ntHeaders->Signature == ExecutableAnalyzerConstants::NT_SIGNATURE) {
                        if (ntHeaders->OptionalHeader.Magic == ExecutableAnalyzerConstants::PE32_MAGIC) {
                            return ExecutableType::PE32;
                        } else if (ntHeaders->OptionalHeader.Magic == ExecutableAnalyzerConstants::PE64_MAGIC) {
                            return ExecutableType::PE64;
                        }
                    }
                }
                return ExecutableType::MSDOS;
            }
        }

        // Check ELF
        if (buffer.size() >= 4) {
            const uint32_t magic = *reinterpret_cast<const uint32_t*>(buffer.data());
            if (magic == ExecutableAnalyzerConstants::ELF_MAGIC) {
                if (buffer.size() >= 5) {
                    const uint8_t elfClass = buffer[4];
                    if (elfClass == 1) return ExecutableType::ELF32;
                    if (elfClass == 2) return ExecutableType::ELF64;
                }
                return ExecutableType::ELF32;  // Default
            }
        }

        // Check Mach-O
        if (buffer.size() >= 4) {
            const uint32_t magic = *reinterpret_cast<const uint32_t*>(buffer.data());
            if (magic == 0xFEEDFACE) return ExecutableType::MachO32;
            if (magic == 0xFEEDFACF) return ExecutableType::MachO64;
            if (magic == 0xCAFEBABE || magic == 0xBEBAFECA) return ExecutableType::MachOUniversal;
        }

        return ExecutableType::Unknown;
    }

    // ========================================================================
    // SPECIFIC PARSERS
    // ========================================================================

    std::vector<ImportedDLL> ParseImports(const std::wstring& filePath) const {
        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return {};
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, false);
            return ParseImportsImpl(data, info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseImports: %hs", e.what());
            return {};
        }
    }

    std::vector<ExportedFunction> ParseExports(const std::wstring& filePath) const {
        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return {};
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, false);
            return ParseExportsImpl(data, info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseExports: %hs", e.what());
            return {};
        }
    }

    PackerInfo DetectPacker(const std::wstring& filePath) const {
        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return PackerInfo{};
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, true);

            return DetectPackerImpl(data, info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::DetectPacker: %hs", e.what());
            return PackerInfo{};
        }
    }

    SignatureInfo VerifySignature(const std::wstring& filePath) const {
        return VerifySignatureImpl(filePath);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const ExecutableAnalyzerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL IMPLEMENTATION (accessible via PIMPL forwarding)
    // ========================================================================

    ExecutableInfo AnalyzeBufferImpl(std::span<const uint8_t> buffer, const AnalysisOptions& options) {
        ExecutableInfo info{};
        info.fileSize = buffer.size();
        info.analysisTime = std::chrono::system_clock::now();

        // Detect type
        info.type = GetExecutableType(buffer);
        if (info.type == ExecutableType::Unknown || info.type == ExecutableType::MSDOS) {
            m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
            return info;
        }

        // Currently only PE analysis is implemented
        if (info.type == ExecutableType::PE32 || info.type == ExecutableType::PE64) {
            info.isValid = true;

            // Parse headers
            if (options.parseHeaders) {
                ParsePEHeaders(buffer, info);
                ParseSections(buffer, info, options.calculateEntropy);
            }

            // Parse imports
            if (options.parseImports) {
                info.imports = ParseImportsImpl(buffer, info);

                // Count risky imports
                for (const auto& dll : info.imports) {
                    info.totalImports += static_cast<uint32_t>(dll.functions.size());
                    info.criticalImports += dll.criticalAPIs;
                    if (dll.isSuspicious) {
                        info.suspiciousImports++;
                    }
                }
            }

            // Parse exports
            if (options.parseExports) {
                info.exports = ParseExportsImpl(buffer, info);
            }

            // Parse resources
            if (options.parseResources) {
                info.resources = ParseResourcesImpl(buffer, info);
            }

            // Parse Rich header
            if (options.parseRichHeader) {
                info.richHeader = ParseRichHeaderImpl(buffer);
            }

            // Detect .NET
            if (options.parseDotNet) {
                info.dotNet = ParseDotNetImpl(buffer, info);
                if (info.dotNet.isDotNet) {
                    m_stats.dotNetFiles.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Parse delay-load imports
            if (options.parseDelayLoadImports) {
                info.delayLoadImports = ParseDelayLoadImportsImpl(buffer, info);
                info.hasDelayLoadImports = !info.delayLoadImports.empty();
            }

            // Parse TLS callbacks (anti-debug / evasion indicator)
            if (options.parseTLSCallbacks) {
                ParseTLSCallbacksImpl(buffer, info);
            }

            // Parse debug directory (PDB path extraction)
            if (options.parseDebugDirectory) {
                ParseDebugDirectoryImpl(buffer, info);
            }

            // Extract detailed security mitigations
            ExtractSecurityMitigationsImpl(buffer, info);

            // Detect packers
            if (options.detectPackers) {
                info.packer = DetectPackerImpl(buffer, info);
                if (info.packer.isPacked) {
                    m_stats.packedFiles.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Detect anomalies
            if (options.detectAnomalies) {
                info.anomalies = DetectAnomaliesImpl(info);
                m_stats.anomaliesDetected.fetch_add(info.anomalies.size(), std::memory_order_relaxed);
            }

            // Detect overlapping sections
            if (options.detectOverlappingSections) {
                DetectOverlappingSectionsImpl(info);
            }

            // Detect entry point anomalies
            if (options.detectEntryPointAnomalies) {
                DetectEntryPointAnomaliesImpl(buffer, info);
            }

            // Analyze overlay
            if (options.analyzeOverlay) {
                AnalyzeOverlayImpl(buffer, info);
            }

            // Calculate risk score
            info.riskScore = CalculateRiskScoreImpl(info);

            // Update type-specific statistics
            if (info.type == ExecutableType::PE32) {
                m_stats.pe32Files.fetch_add(1, std::memory_order_relaxed);
            } else if (info.type == ExecutableType::PE64) {
                m_stats.pe64Files.fetch_add(1, std::memory_order_relaxed);
            }
        }

        return info;
    }

    void ParsePEHeaders(std::span<const uint8_t> buffer, ExecutableInfo& info) const {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            return;
        }

        // DOS header
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dosHeader->e_magic != ExecutableAnalyzerConstants::DOS_SIGNATURE) {
            return;
        }

        // Allow e_lfanew up to 4MB — packers/protectors often relocate PE headers.
        // Restricting to 4096 would miss packed malware we need to detect.
        // The minimum required to read FileHeader is signature(4) + IMAGE_FILE_HEADER(20).
        // The optional header size is checked precisely below using
        // FileHeader.SizeOfOptionalHeader, which avoids falsely rejecting PE32
        // images on x64 builds (where sizeof(IMAGE_NT_HEADERS) == 264 vs the
        // 248 bytes a fully-populated PE32 NT header actually occupies).
        constexpr size_t kMinNtHeaderBytes = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
        if (dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            dosHeader->e_lfanew > 0x400000 ||
            (dosHeader->e_lfanew & 0x3) != 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + kMinNtHeaderBytes > buffer.size()) {
            return;
        }

        // NT headers (check both 32 and 64 bit)
        const auto* ntHeaders32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
            buffer.data() + dosHeader->e_lfanew
        );

        if (ntHeaders32->Signature != ExecutableAnalyzerConstants::NT_SIGNATURE) {
            return;
        }

        // Validate optional header bytes are present using precise size.
        const uint16_t sizeOfOptHeader = ntHeaders32->FileHeader.SizeOfOptionalHeader;
        if (sizeOfOptHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
            static_cast<uint64_t>(dosHeader->e_lfanew) + kMinNtHeaderBytes +
                static_cast<uint64_t>(sizeOfOptHeader) > buffer.size()) {
            return;
        }

        // Determine architecture
        const uint16_t magic = ntHeaders32->OptionalHeader.Magic;
        info.is64Bit = (magic == ExecutableAnalyzerConstants::PE64_MAGIC);
        info.type = info.is64Bit ? ExecutableType::PE64 : ExecutableType::PE32;

        // Machine type
        info.machine = static_cast<MachineType>(ntHeaders32->FileHeader.Machine);

        // Characteristics
        const uint16_t characteristics = ntHeaders32->FileHeader.Characteristics;
        info.isDLL = (characteristics & IMAGE_FILE_DLL) != 0;
        info.isDriver = (characteristics & IMAGE_FILE_SYSTEM) != 0;

        // Timestamp. Skip 0 (unset) and 0xFFFFFFFF (deterministic / reproducible
        // build sentinel) — feeding either to from_time_t produces misleading
        // 1970 / 2106 timestamps.
        info.timestamp = ntHeaders32->FileHeader.TimeDateStamp;
        if (info.timestamp > 0 && info.timestamp != 0xFFFFFFFFu) {
            info.compilationTime = std::chrono::system_clock::from_time_t(info.timestamp);
        }

        // Parse optional header (architecture-specific). For 64-bit, additionally
        // ensure the full 64-bit optional header fits.
        if (info.is64Bit) {
            if (sizeOfOptHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
                return;
            }
            const auto* ntHeaders64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                buffer.data() + dosHeader->e_lfanew
            );
            ParseOptionalHeader64(ntHeaders64->OptionalHeader, info);
        } else {
            ParseOptionalHeader32(ntHeaders32->OptionalHeader, info);
        }
    }

    void ParseOptionalHeader32(const IMAGE_OPTIONAL_HEADER32& optHeader, ExecutableInfo& info) const {
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;
        info.imageSize = optHeader.SizeOfImage;
        info.checksum = optHeader.CheckSum;
        info.subsystem = static_cast<SubsystemType>(optHeader.Subsystem);

        info.isConsole = (info.subsystem == SubsystemType::WindowsCUI);
        info.isGUI = (info.subsystem == SubsystemType::WindowsGUI);

        // DLL characteristics (security features)
        const uint16_t dllCharacteristics = optHeader.DllCharacteristics;
        info.hasDEP = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        info.hasASLR = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        info.hasSEH = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;  // Inverted
        info.hasCFG = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        info.hasHighEntropyVA = false;  // Not available in PE32
    }

    void ParseOptionalHeader64(const IMAGE_OPTIONAL_HEADER64& optHeader, ExecutableInfo& info) const {
        info.entryPoint = optHeader.AddressOfEntryPoint;
        info.imageBase = optHeader.ImageBase;
        info.imageSize = optHeader.SizeOfImage;
        info.checksum = optHeader.CheckSum;
        info.subsystem = static_cast<SubsystemType>(optHeader.Subsystem);

        info.isConsole = (info.subsystem == SubsystemType::WindowsCUI);
        info.isGUI = (info.subsystem == SubsystemType::WindowsGUI);

        // DLL characteristics
        const uint16_t dllCharacteristics = optHeader.DllCharacteristics;
        info.hasDEP = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        info.hasASLR = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        info.hasSEH = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
        info.hasCFG = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        info.hasHighEntropyVA = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    }

    void ParseSections(std::span<const uint8_t> buffer, ExecutableInfo& info, bool calcEntropy) const {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            return;
        }

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        const size_t ntHeadersOffset = dosHeader->e_lfanew;

        // Minimum required: NT signature + FileHeader. Optional header size is
        // variable (PE32 vs PE32+), so we deliberately do NOT require
        // sizeof(IMAGE_NT_HEADERS) (which equals the 64-bit form on x64) and
        // instead validate the optional header size below using
        // FileHeader.SizeOfOptionalHeader.
        constexpr size_t kMinNtHeaderBytes = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
        if (ntHeadersOffset > buffer.size() ||
            ntHeadersOffset + kMinNtHeaderBytes > buffer.size()) {
            return;
        }

        const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
            buffer.data() + ntHeadersOffset + sizeof(uint32_t));

        const uint16_t numSections = fileHeader->NumberOfSections;
        if (numSections == 0 || numSections > ExecutableAnalyzerConstants::MAX_SECTIONS) {
            if (numSections > ExecutableAnalyzerConstants::MAX_SECTIONS) {
                SS_LOG_WARN(L"ExecutableAnalyzer", L"ExecutableAnalyzer: Too many sections: %u", numSections);
            }
            return;
        }

        // Validate optional header fits in buffer using precise size from FileHeader.
        const uint64_t optHeaderEnd =
            static_cast<uint64_t>(ntHeadersOffset) + kMinNtHeaderBytes +
            fileHeader->SizeOfOptionalHeader;
        if (optHeaderEnd > buffer.size()) {
            return;
        }

        const uint64_t sectionHeadersOffset64 = optHeaderEnd;
        const uint64_t sectionsEnd =
            sectionHeadersOffset64 +
            static_cast<uint64_t>(numSections) * sizeof(IMAGE_SECTION_HEADER);
        if (sectionsEnd > buffer.size()) {
            return;
        }
        const size_t sectionHeadersOffset = static_cast<size_t>(sectionHeadersOffset64);

        const auto* sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            buffer.data() + sectionHeadersOffset
        );

        double totalEntropy = 0.0;
        uint32_t validSections = 0;

        for (uint16_t i = 0; i < numSections; ++i) {
            const auto& secHdr = sectionHeaders[i];

            PESection section;
            section.name = SanitizeSectionName(reinterpret_cast<const char*>(secHdr.Name), 8);
            section.nameRaw = std::string(reinterpret_cast<const char*>(secHdr.Name), 8);
            section.virtualAddress = secHdr.VirtualAddress;
            section.virtualSize = secHdr.Misc.VirtualSize;
            section.rawDataOffset = secHdr.PointerToRawData;
            section.rawDataSize = secHdr.SizeOfRawData;
            section.characteristics = secHdr.Characteristics;

            // Parse characteristics
            section.isExecutable = (secHdr.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            section.isWritable = (secHdr.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            section.isReadable = (secHdr.Characteristics & IMAGE_SCN_MEM_READ) != 0;
            section.isEmpty = (section.rawDataSize == 0 || section.virtualSize == 0);

            // Calculate entropy if requested and section has data
            if (calcEntropy && section.rawDataSize > 0 && section.rawDataOffset > 0) {
                const size_t secStart = section.rawDataOffset;
                const size_t secEnd = std::min(
                    secStart + section.rawDataSize,
                    buffer.size()
                );

                if (secStart < secEnd) {
                    std::span<const uint8_t> sectionData = buffer.subspan(secStart, secEnd - secStart);
                    section.entropy = CalculateEntropy(sectionData);

                    totalEntropy += section.entropy;
                    validSections++;

                    // Check if packed
                    if (section.entropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                        section.isPacked = true;
                    }

                    // Calculate section hash
                    if (sectionData.size() > 0) {
                        Utils::HashUtils::Hasher sha(Utils::HashUtils::Algorithm::SHA256);
                        if (sha.Init() && sha.Update(sectionData.data(), sectionData.size())) {
                            std::vector<uint8_t> digest;
                            if (sha.Final(digest) && digest.size() == 32) {
                                std::copy(digest.begin(), digest.end(), section.sha256.begin());
                                section.sha256Hex = BytesToHex(digest);
                            }
                        }
                    }
                }
            }

            info.sections.push_back(std::move(section));
        }

        // Calculate average entropy
        if (validSections > 0) {
            info.averageEntropy = totalEntropy / validSections;
        }

        // Calculate overall file entropy if needed
        if (calcEntropy && buffer.size() > 0) {
            // Sample the file (first 1MB max for performance)
            const size_t sampleSize = std::min(buffer.size(), size_t(1024 * 1024));
            info.overallEntropy = CalculateEntropy(buffer.subspan(0, sampleSize));
        }
    }

    std::vector<ImportedDLL> ParseImportsImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        std::vector<ImportedDLL> imports;

        try {
            if (info.sections.empty()) {
                return imports;
            }

            // Get import directory RVA
            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t importDirRVA = 0;
            uint32_t importDirSize = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    importDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                    importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    importDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                }
            }

            if (importDirRVA == 0 || importDirSize == 0) {
                return imports;  // No imports
            }

            // Convert RVA to file offset
            auto importDirOffset = RVAToFileOffset(importDirRVA, info.sections);
            if (!importDirOffset.has_value()) {
                return imports;
            }

            const size_t offset = importDirOffset.value();
            if (offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buffer.size()) {
                return imports;
            }

            const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buffer.data() + offset);

            // Parse each imported DLL with bounds checking on each descriptor
            for (size_t i = 0; i < ExecutableAnalyzerConstants::MAX_IMPORTS; ++i) {
                // Validate that this descriptor is within the buffer
                const size_t descEnd = offset + (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                if (descEnd > buffer.size()) break;
                if (importDesc[i].Name == 0) break;
                ImportedDLL dll;

                // Get DLL name (bounded read)
                auto nameOffset = RVAToFileOffset(importDesc[i].Name, info.sections);
                if (nameOffset.has_value() && nameOffset.value() < buffer.size()) {
                    const size_t nameStart = nameOffset.value();
                    const size_t maxNameLen = std::min(
                        buffer.size() - nameStart,
                        size_t(260)  // MAX_PATH cap for DLL names
                    );
                    dll.name = std::string(
                        reinterpret_cast<const char*>(buffer.data() + nameStart),
                        strnlen(reinterpret_cast<const char*>(buffer.data() + nameStart), maxNameLen)
                    );

                    // Check if known system DLL
                    std::string lowerName = dll.name;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

                    dll.isKnownSystem = (
                        lowerName.find("kernel32.dll") != std::string::npos ||
                        lowerName.find("user32.dll") != std::string::npos ||
                        lowerName.find("ntdll.dll") != std::string::npos ||
                        lowerName.find("advapi32.dll") != std::string::npos ||
                        lowerName.find("msvcr") != std::string::npos
                    );
                }

                // Parse functions
                const uint32_t thunkRVA = importDesc[i].OriginalFirstThunk ?
                    importDesc[i].OriginalFirstThunk : importDesc[i].FirstThunk;

                auto thunkOffset = RVAToFileOffset(thunkRVA, info.sections);
                if (thunkOffset.has_value()) {
                    ParseImportFunctions(buffer, thunkOffset.value(), info, dll);
                }

                // Aggregate risk assessment
                for (const auto& func : dll.functions) {
                    if (func.riskLevel > dll.highestRisk) {
                        dll.highestRisk = func.riskLevel;
                    }
                    if (func.riskLevel == ImportRiskLevel::Critical) {
                        dll.criticalAPIs++;
                    } else if (func.riskLevel == ImportRiskLevel::High) {
                        dll.highRiskAPIs++;
                    }
                }

                dll.isSuspicious = (dll.criticalAPIs > 0) || (dll.highRiskAPIs >= 3);

                imports.push_back(std::move(dll));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseImportsImpl: %hs", e.what());
        }

        return imports;
    }

    void ParseImportFunctions(std::span<const uint8_t> buffer, size_t thunkOffset,
                              const ExecutableInfo& info, ImportedDLL& dll) const {
        const auto& riskyAPIs = GetRiskyAPIs();

        if (info.is64Bit) {
            for (size_t i = 0; i < ExecutableAnalyzerConstants::MAX_IMPORTS; ++i) {
                const size_t entryOffset = thunkOffset + i * sizeof(IMAGE_THUNK_DATA64);
                if (entryOffset + sizeof(IMAGE_THUNK_DATA64) > buffer.size()) break;

                const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(buffer.data() + entryOffset);
                if (thunk->u1.AddressOfData == 0) break;

                ImportedFunction func;
                func.thunkRVA = static_cast<uint64_t>(thunk->u1.AddressOfData);

                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    func.byOrdinal = true;
                    func.ordinal = IMAGE_ORDINAL64(thunk->u1.Ordinal);
                    func.name = "#" + std::to_string(func.ordinal);
                } else {
                    auto nameOffset = RVAToFileOffset(static_cast<uint32_t>(thunk->u1.AddressOfData), info.sections);
                    if (nameOffset.has_value() &&
                        nameOffset.value() + sizeof(IMAGE_IMPORT_BY_NAME) <= buffer.size()) {
                        const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            buffer.data() + nameOffset.value()
                        );
                        // Safe bounded string read — find null terminator within buffer
                        const size_t nameStart = nameOffset.value() + offsetof(IMAGE_IMPORT_BY_NAME, Name);
                        const size_t maxNameLen = std::min(
                            buffer.size() - nameStart,
                            size_t(512)  // Cap function name length
                        );
                        func.name = std::string(
                            reinterpret_cast<const char*>(buffer.data() + nameStart),
                            strnlen(reinterpret_cast<const char*>(buffer.data() + nameStart), maxNameLen)
                        );
                        func.ordinal = importByName->Hint;
                    }
                }

                auto [riskLevel, reason] = riskyAPIs.GetAPIRisk(func.name);
                func.riskLevel = riskLevel;
                func.riskReason = reason;

                dll.functions.push_back(std::move(func));
            }
        } else {
            for (size_t i = 0; i < ExecutableAnalyzerConstants::MAX_IMPORTS; ++i) {
                const size_t entryOffset = thunkOffset + i * sizeof(IMAGE_THUNK_DATA32);
                if (entryOffset + sizeof(IMAGE_THUNK_DATA32) > buffer.size()) break;

                const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(buffer.data() + entryOffset);
                if (thunk->u1.AddressOfData == 0) break;

                ImportedFunction func;
                func.thunkRVA = thunk->u1.AddressOfData;

                if (IMAGE_SNAP_BY_ORDINAL32(thunk->u1.Ordinal)) {
                    func.byOrdinal = true;
                    func.ordinal = IMAGE_ORDINAL32(thunk->u1.Ordinal);
                    func.name = "#" + std::to_string(func.ordinal);
                } else {
                    auto nameOffset = RVAToFileOffset(thunk->u1.AddressOfData, info.sections);
                    if (nameOffset.has_value() &&
                        nameOffset.value() + sizeof(IMAGE_IMPORT_BY_NAME) <= buffer.size()) {
                        const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            buffer.data() + nameOffset.value()
                        );
                        const size_t nameStart = nameOffset.value() + offsetof(IMAGE_IMPORT_BY_NAME, Name);
                        const size_t maxNameLen = std::min(
                            buffer.size() - nameStart,
                            size_t(512)
                        );
                        func.name = std::string(
                            reinterpret_cast<const char*>(buffer.data() + nameStart),
                            strnlen(reinterpret_cast<const char*>(buffer.data() + nameStart), maxNameLen)
                        );
                        func.ordinal = importByName->Hint;
                    }
                }

                auto [riskLevel, reason] = riskyAPIs.GetAPIRisk(func.name);
                func.riskLevel = riskLevel;
                func.riskReason = reason;

                dll.functions.push_back(std::move(func));
            }
        }
    }

    std::vector<ExportedFunction> ParseExportsImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        std::vector<ExportedFunction> exports;

        try {
            if (info.sections.empty()) {
                return exports;
            }

            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t exportDirRVA = 0;
            uint32_t exportDirSize = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                }
            }

            if (exportDirRVA == 0 || exportDirSize == 0) {
                return exports;
            }

            auto exportDirOffset = RVAToFileOffset(exportDirRVA, info.sections);
            if (!exportDirOffset.has_value() || exportDirOffset.value() + sizeof(IMAGE_EXPORT_DIRECTORY) > buffer.size()) {
                return exports;
            }

            const auto* exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                buffer.data() + exportDirOffset.value()
            );

            const uint32_t numFunctions = exportDir->NumberOfFunctions;
            const uint32_t numNames = exportDir->NumberOfNames;

            if (numFunctions > ExecutableAnalyzerConstants::MAX_EXPORTS || numFunctions == 0) {
                return exports;
            }

            // Parse AddressOfFunctions array
            auto functionsOffset = RVAToFileOffset(exportDir->AddressOfFunctions, info.sections);
            if (!functionsOffset.has_value() ||
                functionsOffset.value() + numFunctions * sizeof(uint32_t) > buffer.size()) {
                return exports;
            }
            const auto* functionRVAs = reinterpret_cast<const uint32_t*>(
                buffer.data() + functionsOffset.value()
            );

            // Parse AddressOfNames and AddressOfNameOrdinals arrays
            const uint32_t* nameRVAs = nullptr;
            const uint16_t* nameOrdinals = nullptr;

            if (numNames > 0) {
                auto namesOffset = RVAToFileOffset(exportDir->AddressOfNames, info.sections);
                auto ordinalsOffset = RVAToFileOffset(exportDir->AddressOfNameOrdinals, info.sections);

                if (namesOffset.has_value() &&
                    namesOffset.value() + numNames * sizeof(uint32_t) <= buffer.size()) {
                    nameRVAs = reinterpret_cast<const uint32_t*>(buffer.data() + namesOffset.value());
                }

                if (ordinalsOffset.has_value() &&
                    ordinalsOffset.value() + numNames * sizeof(uint16_t) <= buffer.size()) {
                    nameOrdinals = reinterpret_cast<const uint16_t*>(buffer.data() + ordinalsOffset.value());
                }
            }

            // Build name-to-ordinal map for named exports
            std::unordered_map<uint16_t, std::string> ordinalToName;
            if (nameRVAs && nameOrdinals) {
                for (uint32_t i = 0; i < numNames; ++i) {
                    auto nameOff = RVAToFileOffset(nameRVAs[i], info.sections);
                    if (nameOff.has_value() && nameOff.value() < buffer.size()) {
                        const size_t maxLen = std::min(buffer.size() - nameOff.value(), size_t(512));
                        std::string name(
                            reinterpret_cast<const char*>(buffer.data() + nameOff.value()),
                            strnlen(reinterpret_cast<const char*>(buffer.data() + nameOff.value()), maxLen)
                        );
                        ordinalToName[nameOrdinals[i]] = std::move(name);
                    }
                }
            }

            // Build export entries
            exports.reserve(std::min(numFunctions, uint32_t(4096)));
            for (uint32_t i = 0; i < numFunctions; ++i) {
                if (functionRVAs[i] == 0) continue;

                ExportedFunction func;
                func.ordinal = static_cast<uint16_t>(exportDir->Base + i);
                func.rva = functionRVAs[i];

                auto nameIt = ordinalToName.find(static_cast<uint16_t>(i));
                if (nameIt != ordinalToName.end()) {
                    func.name = nameIt->second;
                }

                // Detect forwarded exports (RVA points within export directory)
                if (functionRVAs[i] >= exportDirRVA &&
                    functionRVAs[i] < exportDirRVA + exportDirSize) {
                    func.isForwarded = true;
                    auto fwdOffset = RVAToFileOffset(functionRVAs[i], info.sections);
                    if (fwdOffset.has_value() && fwdOffset.value() < buffer.size()) {
                        const size_t maxLen = std::min(buffer.size() - fwdOffset.value(), size_t(512));
                        func.forwardedTo = std::string(
                            reinterpret_cast<const char*>(buffer.data() + fwdOffset.value()),
                            strnlen(reinterpret_cast<const char*>(buffer.data() + fwdOffset.value()), maxLen)
                        );
                    }
                }

                // Flag suspicious exports (common in malicious DLLs)
                if (func.name.empty() && !func.isForwarded) {
                    func.isSuspicious = true;  // Ordinal-only exports are suspicious
                }

                exports.push_back(std::move(func));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseExportsImpl: %hs", e.what());
        }

        return exports;
    }

    std::vector<ResourceEntry> ParseResourcesImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        std::vector<ResourceEntry> resources;

        try {
            if (info.sections.empty()) return resources;

            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t rsrcDirRVA = 0;
            uint32_t rsrcDirSize = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrcDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                    rsrcDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                    rsrcDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                    rsrcDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                }
            }

            if (rsrcDirRVA == 0 || rsrcDirSize == 0) return resources;

            auto rsrcOffset = RVAToFileOffset(rsrcDirRVA, info.sections);
            if (!rsrcOffset.has_value()) return resources;

            const size_t rsrcBase = rsrcOffset.value();
            if (rsrcBase + sizeof(IMAGE_RESOURCE_DIRECTORY) > buffer.size()) return resources;

            // Compute an upper bound for the resource region so that crafted
            // OffsetToDirectory / OffsetToData values cannot redirect parsing
            // outside the resource directory and thus outside any well-formed
            // PE structure. We clamp against both buffer.size() AND the
            // declared resource directory size.
            const size_t rsrcLimit = std::min(buffer.size(),
                rsrcBase + static_cast<size_t>(rsrcDirSize));
            if (rsrcLimit < rsrcBase + sizeof(IMAGE_RESOURCE_DIRECTORY)) return resources;

            // Helper: validate that an OffsetToDirectory points inside the
            // resource region (after stripping the high bit which marks
            // "directory" entries) and leaves room for a directory header.
            auto inRsrc = [&](size_t absOffset, size_t needed) {
                return absOffset >= rsrcBase &&
                    absOffset + needed >= absOffset &&    // overflow guard
                    absOffset + needed <= rsrcLimit;
            };

            // Parse top-level resource directory (Type level)
            const auto* rootDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(buffer.data() + rsrcBase);
            const uint16_t numEntries = rootDir->NumberOfNamedEntries + rootDir->NumberOfIdEntries;

            if (numEntries > ExecutableAnalyzerConstants::MAX_RESOURCES) return resources;

            const auto* entries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
                buffer.data() + rsrcBase + sizeof(IMAGE_RESOURCE_DIRECTORY)
            );

            for (uint16_t i = 0; i < numEntries; ++i) {
                const size_t entryOffset = rsrcBase + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                    i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                if (!inRsrc(entryOffset, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) break;

                const auto& entry = entries[i];
                if (!entry.DataIsDirectory) continue;

                // OffsetToDirectory is the low 31 bits when DataIsDirectory is set.
                const uint32_t entryDirOff = entry.OffsetToDirectory & 0x7FFFFFFFu;

                // Descend to Name/ID level
                const size_t nameDir = rsrcBase + entryDirOff;
                if (!inRsrc(nameDir, sizeof(IMAGE_RESOURCE_DIRECTORY))) continue;

                const auto* nameDirPtr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(
                    buffer.data() + nameDir
                );
                const uint16_t nameEntries = nameDirPtr->NumberOfNamedEntries + nameDirPtr->NumberOfIdEntries;
                const auto* nameEntriesPtr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
                    buffer.data() + nameDir + sizeof(IMAGE_RESOURCE_DIRECTORY)
                );

                for (uint16_t j = 0; j < nameEntries && resources.size() < ExecutableAnalyzerConstants::MAX_RESOURCES; ++j) {
                    const size_t nameEntryOff = nameDir + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                        j * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                    if (!inRsrc(nameEntryOff, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) break;

                    const auto& nameEntry = nameEntriesPtr[j];
                    if (!nameEntry.DataIsDirectory) continue;

                    const uint32_t nameDirOff = nameEntry.OffsetToDirectory & 0x7FFFFFFFu;

                    // Descend to Language level
                    const size_t langDir = rsrcBase + nameDirOff;
                    if (!inRsrc(langDir, sizeof(IMAGE_RESOURCE_DIRECTORY))) continue;

                    const auto* langDirPtr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(
                        buffer.data() + langDir
                    );
                    const uint16_t langEntries = langDirPtr->NumberOfNamedEntries + langDirPtr->NumberOfIdEntries;
                    const auto* langEntriesPtr = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
                        buffer.data() + langDir + sizeof(IMAGE_RESOURCE_DIRECTORY)
                    );

                    for (uint16_t k = 0; k < langEntries && resources.size() < ExecutableAnalyzerConstants::MAX_RESOURCES; ++k) {
                        const size_t langEntryOff = langDir + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                            k * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                        if (!inRsrc(langEntryOff, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) break;

                        const auto& langEntry = langEntriesPtr[k];
                        if (langEntry.DataIsDirectory) continue;

                        // Get data entry. OffsetToData here is a leaf offset
                        // (high bit clear by definition), but mask defensively
                        // in case of corrupt input.
                        const size_t dataEntryOff = rsrcBase + (langEntry.OffsetToData & 0x7FFFFFFFu);
                        if (!inRsrc(dataEntryOff, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) continue;

                        const auto* dataEntry = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(
                            buffer.data() + dataEntryOff
                        );

                        ResourceEntry res;
                        res.type = entry.Id;
                        res.id = nameEntry.Id;
                        res.language = langEntry.Id;
                        res.size = dataEntry->Size;

                        // Map resource type IDs to names
                        switch (res.type) {
                            case 1:  res.typeName = "RT_CURSOR"; break;
                            case 2:  res.typeName = "RT_BITMAP"; break;
                            case 3:  res.typeName = "RT_ICON"; break;
                            case 4:  res.typeName = "RT_MENU"; break;
                            case 5:  res.typeName = "RT_DIALOG"; break;
                            case 6:  res.typeName = "RT_STRING"; break;
                            case 9:  res.typeName = "RT_ACCELERATOR"; break;
                            case 10: res.typeName = "RT_RCDATA"; break;
                            case 14: res.typeName = "RT_GROUP_ICON"; break;
                            case 16: res.typeName = "RT_VERSION"; break;
                            case 24: res.typeName = "RT_MANIFEST"; break;
                            default: res.typeName = "RT_UNKNOWN(" + std::to_string(res.type) + ")"; break;
                        }

                        // Check for embedded PE in resources (malware hiding technique)
                        auto resDataOffset = RVAToFileOffset(dataEntry->OffsetToData, info.sections);
                        if (resDataOffset.has_value() && dataEntry->Size >= 2) {
                            const size_t resStart = resDataOffset.value();
                            const size_t resEnd = std::min(resStart + dataEntry->Size, buffer.size());
                            if (resStart < resEnd) {
                                res.offset = static_cast<uint32_t>(resStart);

                                // Check for MZ header in resource data
                                if (resEnd - resStart >= sizeof(IMAGE_DOS_HEADER)) {
                                    const auto* mz = reinterpret_cast<const IMAGE_DOS_HEADER*>(
                                        buffer.data() + resStart
                                    );
                                    if (mz->e_magic == ExecutableAnalyzerConstants::DOS_SIGNATURE) {
                                        res.isPE = true;
                                    }
                                }

                                // Check for script content
                                if (resEnd - resStart >= 10) {
                                    const auto* textStart = reinterpret_cast<const char*>(buffer.data() + resStart);
                                    std::string_view preview(textStart, std::min(resEnd - resStart, size_t(64)));
                                    if (preview.find("powershell") != std::string_view::npos ||
                                        preview.find("wscript") != std::string_view::npos ||
                                        preview.find("cscript") != std::string_view::npos ||
                                        preview.find("cmd /c") != std::string_view::npos) {
                                        res.isScript = true;
                                    }
                                }

                                // Calculate resource entropy
                                std::span<const uint8_t> resData = buffer.subspan(resStart, resEnd - resStart);
                                res.entropy = CalculateEntropy(resData);
                                if (res.entropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                                    res.isEncrypted = true;
                                }
                            }
                        }

                        resources.push_back(std::move(res));
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseResourcesImpl: %hs", e.what());
        }

        return resources;
    }

    RichHeader ParseRichHeaderImpl(std::span<const uint8_t> buffer) const {
        RichHeader richHeader;

        try {
            if (buffer.size() < sizeof(IMAGE_DOS_HEADER) + 128) {
                return richHeader;
            }

            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
            const size_t peOffset = dosHeader->e_lfanew;

            if (peOffset < 128 || peOffset > buffer.size() || peOffset > 4096) {
                return richHeader;
            }

            // Search for "Rich" signature (backwards from PE header)
            constexpr uint32_t RICH_SIGNATURE = 0x68636952;  // "Rich"
            constexpr uint32_t DANS_SIGNATURE = 0x536E6144;  // "DanS"

            size_t richOffset = 0;
            // Use checked arithmetic: start from peOffset - 8 (need 4 for "Rich" + 4 for checksum)
            if (peOffset < 8) return richHeader;

            for (size_t i = peOffset - 8; i >= sizeof(IMAGE_DOS_HEADER); i -= 4) {
                if (i + 4 > buffer.size()) break;
                uint32_t dword = 0;
                std::memcpy(&dword, buffer.data() + i, sizeof(dword));
                if (dword == RICH_SIGNATURE) {
                    richOffset = i;
                    break;
                }
                if (i < sizeof(IMAGE_DOS_HEADER) + 4) break;  // Prevent underflow
            }

            if (richOffset == 0) return richHeader;

            // Checksum is the DWORD immediately after "Rich"
            if (richOffset + 8 > buffer.size()) return richHeader;
            uint32_t xorKey = 0;
            std::memcpy(&xorKey, buffer.data() + richOffset + 4, sizeof(xorKey));

            richHeader.present = true;
            richHeader.checksum = xorKey;

            // Find "DanS" signature (start of rich header, XORed with key)
            size_t dansOffset = 0;
            for (size_t i = sizeof(IMAGE_DOS_HEADER); i < richOffset; i += 4) {
                if (i + 4 > buffer.size()) break;
                uint32_t dword = 0;
                std::memcpy(&dword, buffer.data() + i, sizeof(dword));
                if ((dword ^ xorKey) == DANS_SIGNATURE) {
                    dansOffset = i;
                    break;
                }
            }

            if (dansOffset == 0) {
                richHeader.isPossibleFake = true;
                return richHeader;
            }

            // Entries start after DanS + 3 padding DWORDs (all XORed with key)
            const size_t entriesStart = dansOffset + 16;  // DanS + 3 padding
            if (entriesStart >= richOffset) return richHeader;

            const size_t entriesSize = richOffset - entriesStart;
            if (entriesSize % 8 != 0) {
                richHeader.isPossibleFake = true;
                return richHeader;
            }

            const size_t numEntries = entriesSize / 8;
            if (numEntries > 256) {
                richHeader.isPossibleFake = true;
                return richHeader;
            }

            richHeader.entries.reserve(numEntries);
            for (size_t i = 0; i < numEntries; ++i) {
                const size_t off = entriesStart + i * 8;
                if (off + 8 > buffer.size()) break;

                uint32_t compIdRaw = 0;
                uint32_t countRaw = 0;
                std::memcpy(&compIdRaw, buffer.data() + off, sizeof(compIdRaw));
                std::memcpy(&countRaw, buffer.data() + off + 4, sizeof(countRaw));
                const uint32_t compId = compIdRaw ^ xorKey;
                const uint32_t count = countRaw ^ xorKey;

                RichHeaderEntry entry;
                entry.productId = static_cast<uint16_t>(compId >> 16);
                entry.buildId = static_cast<uint16_t>(compId & 0xFFFF);
                entry.count = count;

                // Map known product IDs to names (for attribution/APT tracking)
                switch (entry.productId) {
                    case 1: entry.productName = "Import0"; break;
                    case 4: entry.productName = "Linker510"; break;
                    case 5: entry.productName = "Cvtomf510"; break;
                    case 6: entry.productName = "Linker600"; break;
                    case 10: entry.productName = "Linker622"; break;
                    case 19: entry.productName = "Linker700"; break;
                    case 40: entry.productName = "Linker710"; break;
                    case 45: entry.productName = "Linker800"; break;
                    case 83: entry.productName = "Linker900"; break;
                    case 93: entry.productName = "Linker1000"; break;
                    case 170: entry.productName = "Linker1100"; break;
                    case 199: entry.productName = "Linker1200"; break;
                    case 219: entry.productName = "Linker1210"; break;
                    case 258: entry.productName = "Linker1400"; break;
                    default:
                        entry.productName = "ProdId" + std::to_string(entry.productId);
                        break;
                }

                // Extract linker version from highest product ID entry
                if (entry.productId >= 258) {
                    richHeader.linkerVersion = "MSVC " + std::to_string(entry.productId) +
                        " (build " + std::to_string(entry.buildId) + ")";
                }

                richHeader.entries.push_back(std::move(entry));
            }

            // Validate checksum: compute expected and compare
            uint32_t computedChecksum = static_cast<uint32_t>(dansOffset);  // Initial value = offset of DanS
            // Rotate-add the DOS header bytes (excluding e_lfanew at offset 0x3C)
            for (size_t i = 0; i < dansOffset; ++i) {
                if (i >= 0x3C && i < 0x40) continue;  // Skip e_lfanew
                if (i >= buffer.size()) break;
                computedChecksum += _rotl(buffer[i], static_cast<int>(i));
            }
            // Add each entry's contribution
            for (const auto& entry : richHeader.entries) {
                uint32_t compId = (static_cast<uint32_t>(entry.productId) << 16) | entry.buildId;
                computedChecksum += _rotl(compId, static_cast<int>(entry.count & 0x1F));
            }

            richHeader.valid = (computedChecksum == xorKey);
            if (!richHeader.valid) {
                richHeader.isPossibleFake = true;
                SS_LOG_WARN(L"ExecutableAnalyzer",
                    L"Rich header checksum mismatch: expected 0x%08X, computed 0x%08X",
                    xorKey, computedChecksum);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseRichHeaderImpl: %hs", e.what());
        }

        return richHeader;
    }

    DotNetMetadata ParseDotNetImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        DotNetMetadata dotNet;

        try {
            if (info.sections.empty()) {
                return dotNet;
            }

            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t clrDirRVA = 0;
            uint32_t clrDirSize = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    clrDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                    clrDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    clrDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                    clrDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
                }
            }

            if (clrDirRVA == 0 || clrDirSize < sizeof(IMAGE_COR20_HEADER)) {
                return dotNet;
            }

            auto clrOffset = RVAToFileOffset(clrDirRVA, info.sections);
            if (!clrOffset.has_value() || clrOffset.value() + sizeof(IMAGE_COR20_HEADER) > buffer.size()) {
                return dotNet;
            }

            const auto* corHeader = reinterpret_cast<const IMAGE_COR20_HEADER*>(
                buffer.data() + clrOffset.value()
            );

            dotNet.isDotNet = true;
            dotNet.majorRuntimeVersion = corHeader->MajorRuntimeVersion;
            dotNet.minorRuntimeVersion = corHeader->MinorRuntimeVersion;
            dotNet.flags = corHeader->Flags;

            // Check COMIMAGE_FLAGS_ILONLY = 0x00000001
            // COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
            // COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004
            // COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010

            dotNet.isNativeImage = (corHeader->Flags & 0x00000010) != 0;
            dotNet.isMixedMode = !(corHeader->Flags & 0x00000001);  // Not IL-only = mixed mode

            // Parse metadata root if present
            if (corHeader->MetaData.VirtualAddress != 0 && corHeader->MetaData.Size >= 20) {
                auto metaOffset = RVAToFileOffset(corHeader->MetaData.VirtualAddress, info.sections);
                if (metaOffset.has_value() && metaOffset.value() + 20 <= buffer.size()) {
                    const size_t metaBase = metaOffset.value();
                    const size_t metaEnd = std::min(metaBase + corHeader->MetaData.Size, buffer.size());

                    // Metadata root starts with signature 0x424A5342 ("BSJB")
                    if (metaEnd - metaBase >= 16) {
                        uint32_t metaSig = 0;
                        std::memcpy(&metaSig, buffer.data() + metaBase, sizeof(metaSig));
                        if (metaSig == 0x424A5342) {
                            // Read version string at offset 12
                            uint32_t versionLen = 0;
                            std::memcpy(&versionLen, buffer.data() + metaBase + 12, sizeof(versionLen));
                            if (versionLen > 0 && versionLen <= 256 && metaBase + 16 + versionLen <= metaEnd) {
                                dotNet.targetFramework = std::string(
                                    reinterpret_cast<const char*>(buffer.data() + metaBase + 16),
                                    strnlen(reinterpret_cast<const char*>(buffer.data() + metaBase + 16), versionLen)
                                );
                            }
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::ParseDotNetImpl: %hs", e.what());
        }

        return dotNet;
    }

    PackerInfo DetectPackerImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        PackerInfo packerInfo;

        try {
            // Check section names against known packers
            for (const auto& sig : g_packerSignatures) {
                for (const auto& section : info.sections) {
                    for (const auto& packerSection : sig.sectionNames) {
                        if (section.name.find(packerSection) != std::string::npos) {
                            packerInfo.isPacked = true;
                            packerInfo.packerType = sig.type;
                            packerInfo.name = sig.name;
                            packerInfo.confidence = 0.9;
                            packerInfo.indicators.push_back("Section name: " + section.name);
                            return packerInfo;
                        }
                    }
                }
            }

            // Check entropy
            bool highEntropyDetected = false;
            for (const auto& section : info.sections) {
                if (section.entropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                    highEntropyDetected = true;
                    break;
                }
            }

            // Check for signature patterns in entry point section
            if (info.entryPoint > 0 && !info.sections.empty()) {
                for (const auto& sig : g_packerSignatures) {
                    if (!sig.signatures.empty()) {
                        // Find section containing entry point
                        for (const auto& section : info.sections) {
                            if (info.entryPoint >= section.virtualAddress &&
                                info.entryPoint < section.virtualAddress + section.virtualSize) {

                                const size_t epOffset = section.rawDataOffset +
                                    (info.entryPoint - section.virtualAddress);

                                if (epOffset < buffer.size()) {
                                    for (const auto& [patternOffset, pattern] : sig.signatures) {
                                        const size_t checkOffset = epOffset + patternOffset;

                                        if (checkOffset + pattern.size() <= buffer.size()) {
                                            bool match = std::equal(
                                                pattern.begin(), pattern.end(),
                                                buffer.data() + checkOffset
                                            );

                                            if (match) {
                                                packerInfo.isPacked = true;
                                                packerInfo.packerType = sig.type;
                                                packerInfo.name = sig.name;
                                                packerInfo.confidence = 0.95;
                                                packerInfo.indicators.push_back("Signature match at EP");
                                                return packerInfo;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Generic packing heuristics
            if (highEntropyDetected && info.averageEntropy >= 7.0) {
                packerInfo.isPacked = true;
                packerInfo.packerType = PackerType::Unknown;
                packerInfo.name = "Unknown Packer";
                packerInfo.confidence = 0.7;
                packerInfo.indicators.push_back("High entropy: " + std::to_string(info.averageEntropy));
            }

            // Few imports + high entropy = strong packing indicator
            if (!packerInfo.isPacked && highEntropyDetected) {
                size_t totalFunctions = 0;
                for (const auto& dll : info.imports) {
                    totalFunctions += dll.functions.size();
                }
                if (totalFunctions <= 5 && info.imports.size() <= 2) {
                    packerInfo.isPacked = true;
                    packerInfo.packerType = PackerType::Unknown;
                    packerInfo.name = "Unknown Packer/Crypter";
                    packerInfo.confidence = 0.75;
                    packerInfo.indicators.push_back(
                        "Minimal imports (" + std::to_string(totalFunctions) +
                        " functions) + high entropy sections");
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::DetectPackerImpl: %hs", e.what());
        }

        return packerInfo;
    }

    std::vector<DetectedAnomaly> DetectAnomaliesImpl(const ExecutableInfo& info) const {
        std::vector<DetectedAnomaly> anomalies;

        try {
            // Check timestamp
            if (info.timestamp == 0) {
                anomalies.push_back({
                    AnomalyType::InvalidTimestamp,
                    "Invalid or zero timestamp",
                    "",
                    0,
                    30,
                    "T1027"
                });
            } else {
                const auto now = std::chrono::system_clock::now();
                if (info.compilationTime > now) {
                    anomalies.push_back({
                        AnomalyType::FutureTimestamp,
                        "Timestamp is in the future",
                        "",
                        0,
                        40,
                        "T1027"
                    });
                }
            }

            // Check sections
            for (const auto& section : info.sections) {
                // Writable + Executable
                if (section.isWritable && section.isExecutable) {
                    anomalies.push_back({
                        AnomalyType::WritableCode,
                        "Section is both writable and executable",
                        section.name,
                        section.rawDataOffset,
                        70,
                        "T1055"
                    });
                }

                // High entropy
                if (section.entropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                    anomalies.push_back({
                        AnomalyType::HighEntropySections,
                        "Section has very high entropy: " + std::to_string(section.entropy),
                        section.name,
                        section.rawDataOffset,
                        50,
                        "T1027"
                    });
                }

                // Suspicious section names
                if (section.name.empty() || section.name.find('\0') != std::string::npos) {
                    anomalies.push_back({
                        AnomalyType::SuspiciousSectionNames,
                        "Section has suspicious or null name",
                        section.name,
                        section.rawDataOffset,
                        40,
                        "T1027"
                    });
                }

                // Zero size
                if (section.isEmpty && section.isExecutable) {
                    anomalies.push_back({
                        AnomalyType::ZeroSizeSection,
                        "Executable section with zero size",
                        section.name,
                        section.rawDataOffset,
                        30,
                        "T1027"
                    });
                }
            }

            // Check imports
            if (info.imports.empty() && !info.isDLL) {
                anomalies.push_back({
                    AnomalyType::NoImports,
                    "Executable has no imports (possible manual loading)",
                    "",
                    0,
                    80,
                    "T1027"
                });
            }

            // Check for critical APIs
            if (info.criticalImports >= 5) {
                anomalies.push_back({
                    AnomalyType::SuspiciousImports,
                    "Multiple critical/suspicious API imports: " + std::to_string(info.criticalImports),
                    "",
                    0,
                    70,
                    "T1055"
                });
            }

            // Check security features
            if (!info.hasDEP && !info.isDLL) {
                anomalies.push_back({
                    AnomalyType::MitigationDisabled,
                    "DEP (Data Execution Prevention) not enabled",
                    "",
                    0,
                    20,
                    ""
                });
            }

            if (!info.hasASLR && !info.isDLL) {
                anomalies.push_back({
                    AnomalyType::MitigationDisabled,
                    "ASLR (Address Space Layout Randomization) not enabled",
                    "",
                    0,
                    20,
                    ""
                });
            }

            // Check packing
            if (info.packer.isPacked) {
                anomalies.push_back({
                    AnomalyType::PackedBinary,
                    "Binary is packed/compressed: " + info.packer.name,
                    "",
                    0,
                    60,
                    "T1027"
                });
            }

            // Check signature
            if (info.signature.status == SignatureStatus::Invalid) {
                anomalies.push_back({
                    AnomalyType::InvalidSignature,
                    "Invalid digital signature",
                    "",
                    0,
                    50,
                    "T1036"
                });
            } else if (info.signature.status == SignatureStatus::Revoked) {
                anomalies.push_back({
                    AnomalyType::RevokedCertificate,
                    "Certificate has been revoked",
                    "",
                    0,
                    90,
                    "T1036"
                });
            }

            // Check overlay. info.imageSize is the in-memory SizeOfImage and is
            // unrelated to on-disk size; comparing fileSize against it falsely
            // flags any image with a non-zero virtual padding. Use the
            // pre-computed overlaySize, which is derived from the last section's
            // raw end offset by AnalyzeOverlayImpl().
            if (info.overlaySize > 1024 * 1024) {  // > 1MB
                anomalies.push_back({
                    AnomalyType::LargeOverlay,
                    "Large overlay detected: " + std::to_string(info.overlaySize) + " bytes",
                    "",
                    0,
                    40,
                    "T1027"
                });
            }

            // Check TLS callbacks (anti-debug / anti-analysis evasion)
            if (info.hasTLSCallbacks) {
                anomalies.push_back({
                    AnomalyType::AntiDebug,
                    "TLS callbacks detected (" + std::to_string(info.tlsCallbackCount) +
                        ") — common anti-analysis / pre-main execution",
                    "",
                    0,
                    55,
                    "T1497"
                });
            }

            // Check delay-load imports with suspicious APIs
            for (const auto& dll : info.delayLoadImports) {
                if (dll.criticalAPIs > 0) {
                    anomalies.push_back({
                        AnomalyType::SuspiciousImports,
                        "Delay-loaded DLL '" + dll.name + "' has critical APIs (evasion technique)",
                        "",
                        0,
                        50,
                        "T1027"
                    });
                }
            }

            // Check for missing CFG (Control Flow Guard)
            if (!info.hasCFG && !info.isDLL && !info.dotNet.isDotNet) {
                anomalies.push_back({
                    AnomalyType::MitigationDisabled,
                    "Control Flow Guard (CFG) not enabled",
                    "",
                    0,
                    15,
                    ""
                });
            }

            // Check for no imports + high entropy (shellcode indicator)
            if (info.imports.empty() && !info.isDLL &&
                info.averageEntropy >= ExecutableAnalyzerConstants::SUSPICIOUS_ENTROPY_THRESHOLD) {
                anomalies.push_back({
                    AnomalyType::APIHashing,
                    "No imports + high entropy — possible shellcode or API hashing",
                    "",
                    0,
                    85,
                    "T1027"
                });
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::DetectAnomaliesImpl: %hs", e.what());
        }

        return anomalies;
    }

    uint8_t CalculateRiskScoreImpl(const ExecutableInfo& info) const {
        uint32_t score = 0;

        try {
            // Packing (+20)
            if (info.packer.isPacked) {
                score += 20;
            }

            // High entropy (+15)
            if (info.averageEntropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                score += 15;
            } else if (info.averageEntropy >= ExecutableAnalyzerConstants::SUSPICIOUS_ENTROPY_THRESHOLD) {
                score += 8;
            }

            // Critical imports (+5 each, max 25)
            score += std::min(info.criticalImports * 5, 25u);

            // Suspicious imports (+2 each, max 10)
            score += std::min(info.suspiciousImports * 2, 10u);

            // No signature (+10)
            if (info.signature.status == SignatureStatus::NotSigned && !info.isDLL) {
                score += 10;
            }

            // Invalid signature (+20)
            if (info.signature.status == SignatureStatus::Invalid) {
                score += 20;
            }

            // Revoked signature (+40)
            if (info.signature.status == SignatureStatus::Revoked) {
                score += 40;
            }

            // Anomalies (severity-based)
            for (const auto& anomaly : info.anomalies) {
                score += anomaly.severity / 2;  // Scaled down
            }

            // Writable + executable sections (+15 each)
            for (const auto& section : info.sections) {
                if (section.isWritable && section.isExecutable) {
                    score += 15;
                }
            }

            // No DEP/ASLR (+5 each)
            if (!info.hasDEP && !info.isDLL) {
                score += 5;
            }
            if (!info.hasASLR && !info.isDLL) {
                score += 5;
            }

            // TLS callbacks (+15 — common anti-analysis technique)
            if (info.hasTLSCallbacks) {
                score += 15;
            }

            // Delay-load imports with high-risk APIs (+10)
            for (const auto& dll : info.delayLoadImports) {
                if (dll.criticalAPIs > 0) {
                    score += 10;
                    break;
                }
            }

            // Overlapping sections (+20 — strong malware indicator)
            if (info.hasOverlappingSections) {
                score += 20;
            }

            // Entry point outside code (+15)
            if (info.hasEntryPointOutsideCode) {
                score += 15;
            }

            // Overlay with embedded PE (+10)
            if (info.overlayContainsPE) {
                score += 10;
            }

            // Cap at 100
            if (score > 100) {
                score = 100;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::CalculateRiskScoreImpl: %hs", e.what());
        }

        return static_cast<uint8_t>(score);
    }

    VersionInfo GetVersionInfoImpl(const std::wstring& filePath) const {
        VersionInfo versionInfo;

        try {
            DWORD handle = 0;
            DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);

            if (size == 0) {
                return versionInfo;
            }

            std::vector<uint8_t> data(size);
            if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data())) {
                return versionInfo;
            }

            VS_FIXEDFILEINFO* fileInfo = nullptr;
            UINT fileInfoSize = 0;

            if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &fileInfoSize)) {
                versionInfo.hasVersionInfo = true;

                versionInfo.fileMajor = HIWORD(fileInfo->dwFileVersionMS);
                versionInfo.fileMinor = LOWORD(fileInfo->dwFileVersionMS);
                versionInfo.fileBuild = HIWORD(fileInfo->dwFileVersionLS);
                versionInfo.fileRevision = LOWORD(fileInfo->dwFileVersionLS);

                versionInfo.productMajor = HIWORD(fileInfo->dwProductVersionMS);
                versionInfo.productMinor = LOWORD(fileInfo->dwProductVersionMS);
                versionInfo.productBuild = HIWORD(fileInfo->dwProductVersionLS);
                versionInfo.productRevision = LOWORD(fileInfo->dwProductVersionLS);
            }

            // Query string values
            struct Translation {
                WORD language;
                WORD codePage;
            };

            Translation* translation = nullptr;
            UINT translationSize = 0;

            if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                              reinterpret_cast<LPVOID*>(&translation), &translationSize)) {

                if (translationSize >= sizeof(Translation)) {
                    wchar_t subBlock[256];

                    auto queryString = [&](const wchar_t* name, std::wstring& output) {
                        swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
                                  translation->language, translation->codePage, name);

                        wchar_t* value = nullptr;
                        UINT valueSize = 0;
                        if (VerQueryValueW(data.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &valueSize)) {
                            output = value;
                        }
                    };

                    queryString(L"CompanyName", versionInfo.companyName);
                    queryString(L"FileDescription", versionInfo.fileDescription);
                    queryString(L"FileVersion", versionInfo.fileVersion);
                    queryString(L"InternalName", versionInfo.internalName);
                    queryString(L"LegalCopyright", versionInfo.legalCopyright);
                    queryString(L"OriginalFilename", versionInfo.originalFilename);
                    queryString(L"ProductName", versionInfo.productName);
                    queryString(L"ProductVersion", versionInfo.productVersion);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::GetVersionInfoImpl: %hs", e.what());
        }

        return versionInfo;
    }

    SignatureInfo VerifySignatureImpl(const std::wstring& filePath) const {
        SignatureInfo sigInfo;

        try {
            // Use WinVerifyTrust API
            WINTRUST_FILE_INFO fileInfo{};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = filePath.c_str();
            fileInfo.hFile = nullptr;
            fileInfo.pgKnownSubject = nullptr;

            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            WINTRUST_DATA trustData{};
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;

            // WTD_CACHE_ONLY_URL_RETRIEVAL is not optional here: without it this
            // call reaches the network, and this call sits on the synchronous
            // on-access path with a kernel file operation held open behind it.
            //
            // Field evidence, 2026-08-12 trace ring. Two scan workers entered
            // this function and returned 180.1 and 180.3 seconds later, within
            // four milliseconds of each other:
            //     17:58:25.671 t5004 > Analyze.VerifySignature
            //     18:01:25.784 t5004 < Analyze.VerifySignature  180112924 us
            //     17:58:25.493 t3416 > Analyze.VerifySignature
            //     18:01:25.788 t3416 < Analyze.VerifySignature  180293822 us
            // Three minutes on the nose, on two independent threads releasing
            // simultaneously, is a network retrieval timing out with both callers
            // queued behind the same cryptnet fetch. The pool has two workers, so
            // that was three minutes of zero scan capacity: every file operation
            // on the machine waited out a driver timeout and the desktop never
            // finished composing. That is the gray-screen lockdown.
            //
            // WTD_REVOKE_NONE above was not sufficient, which is the subtle part.
            // It suppresses CRL and OCSP revocation checking, but chain building
            // still resolves missing intermediate CA certificates through the
            // Authority Information Access extension, and that retrieval goes to
            // the network regardless of the revocation setting. Only the
            // cache-only flag suppresses URL retrieval as a whole.
            //
            // This costs no detection. Revocation was already disabled on this
            // path, so nothing is lost there. The flag only changes where
            // intermediate certificates come from - local store and cache rather
            // than the network - while the signature cryptography is verified
            // identically either way. When an intermediate genuinely is not
            // available locally the chain is reported incomplete, we treat the
            // file as unverified, and it receives MORE analysis rather than less,
            // so the failure direction is the safe one. And measured against what
            // actually happens today the change can only improve coverage: a check
            // that stalls both scan workers for three minutes leaves the whole
            // machine unscanned while the driver fails open.
            //
            // DigitalSignatureValidator already does exactly this on the same hot
            // path (WTD_REVOKE_NONE plus WTD_CACHE_ONLY_URL_RETRIEVAL) and the same
            // trace shows it completing 528 times with a 7 ms worst case. This
            // brings the second path in line with the one already proven in the
            // field. Full revocation checking with network access belongs in the
            // asynchronous deep-scan stage and in the update and certificate
            // pinning paths, where a slow fetch delays only itself.
            trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

            LONG result = ERROR_SUCCESS;
            {
                // These two scopes exist because a single Analyze.VerifySignature
                // scope could not tell us which half was blocking. In 1.0.89 the
                // trust call was already cache-only and fast while the certificate
                // detail extraction below was the part that never returned, and
                // that was only deducible by comparing against a different code
                // path. The next trace should not need deduction.
                SS_DIAG_SCOPE("OnAccess", "Analyze.WinVerifyTrust");
                result = WinVerifyTrust(nullptr, &policyGUID, &trustData);
            }

            if (result == ERROR_SUCCESS) {
                sigInfo.isSigned = true;
                sigInfo.isValid = true;
                sigInfo.status = SignatureStatus::Valid;
            } else if (result == TRUST_E_NOSIGNATURE) {
                sigInfo.status = SignatureStatus::NotSigned;
            } else if (result == TRUST_E_EXPLICIT_DISTRUST) {
                sigInfo.isSigned = true;
                sigInfo.status = SignatureStatus::Revoked;
            } else if (result == TRUST_E_BAD_DIGEST) {
                sigInfo.isSigned = true;
                sigInfo.status = SignatureStatus::HashMismatch;
            } else {
                sigInfo.isSigned = true;
                sigInfo.status = SignatureStatus::Invalid;
            }

            // Clean up
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policyGUID, &trustData);

            // Get detailed certificate info if signed
            if (sigInfo.isSigned) {
                SS_DIAG_SCOPE("OnAccess", "Analyze.ExtractCertDetails");
                ExtractCertificateDetailsImpl(filePath, sigInfo);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::VerifySignatureImpl: %hs", e.what());
        }

        return sigInfo;
    }

    // Hash the bytes the caller has ALREADY read, rather than re-reading the file.
    //
    // This used to take a path and call ReadAllBytes itself, while its only caller
    // (Analyze) had just read the identical file into memory a few lines earlier.
    // Every scanned file was therefore opened twice and read twice, into two full
    // buffers, on the real-time on-access path.
    //
    // That is not only wasted I/O and memory. Each open is a separate
    // IRP_MJ_CREATE that traverses our own minifilter, so the redundant read
    // doubled the exposure of the scan path to anything that can block a file
    // open - and a scan worker that blocks inside this call stops answering the
    // kernel, which stalls file I/O machine-wide. Field evidence: a trace showing
    // ExecutableAnalyzer::AnalyzeForKernel entered with no matching exit record,
    // after which only the self-protection loop still ran.
    //
    // Taking a span makes the redundant read impossible to reintroduce: there is
    // no path here to open. The path is retained for log messages only.
    void CalculateHashes(std::span<const std::byte> fileBytes,
                         const std::wstring& filePath,
                         ExecutableInfo& info) const {
        try {
            if (fileBytes.empty()) {
                SS_LOG_ERROR(L"ExecutableAnalyzer",
                    L"CalculateHashes: empty buffer for '%ls' - nothing to hash",
                    filePath.c_str());
                return;
            }

            const auto* dataPtr = reinterpret_cast<const uint8_t*>(fileBytes.data());
            const size_t dataSize = fileBytes.size();

            // MD5
            {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::MD5);
                if (hasher.Init() && hasher.Update(dataPtr, dataSize)) {
                    std::vector<uint8_t> digest;
                    if (hasher.Final(digest) && digest.size() == 16) {
                        std::copy(digest.begin(), digest.end(), info.md5.begin());
                        info.md5Hex = BytesToHex(digest);
                    }
                }
            }

            // SHA-1
            {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA1);
                if (hasher.Init() && hasher.Update(dataPtr, dataSize)) {
                    std::vector<uint8_t> digest;
                    if (hasher.Final(digest) && digest.size() == 20) {
                        std::copy(digest.begin(), digest.end(), info.sha1.begin());
                        info.sha1Hex = BytesToHex(digest);
                    }
                }
            }

            // SHA-256
            {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                if (hasher.Init() && hasher.Update(dataPtr, dataSize)) {
                    std::vector<uint8_t> digest;
                    if (hasher.Final(digest) && digest.size() == 32) {
                        std::copy(digest.begin(), digest.end(), info.sha256.begin());
                        info.sha256Hex = BytesToHex(digest);
                    }
                }
            }

            // Calculate ImpHash (Mandiant standard)
            if (!info.imports.empty()) {
                info.imphash = ComputeImpHashImpl(info.imports);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExecutableAnalyzer::CalculateHashes: %hs", e.what());
        }
    }

    std::string ComputeImpHashImpl(const std::vector<ImportedDLL>& imports) const {
        // Mandiant ImpHash standard: "dll_name.function_name" all lowercase, comma-separated
        std::ostringstream oss;
        bool first = true;

        for (const auto& dll : imports) {
            // Strip .dll extension for ImpHash per Mandiant spec
            std::string dllLower = dll.name;
            std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);

            // Remove common extensions
            for (const char* ext : { ".dll", ".sys", ".drv", ".ocx" }) {
                if (dllLower.length() > strlen(ext)) {
                    size_t pos = dllLower.length() - strlen(ext);
                    if (dllLower.compare(pos, strlen(ext), ext) == 0) {
                        dllLower.erase(pos);
                        break;
                    }
                }
            }

            for (const auto& func : dll.functions) {
                if (func.name.empty()) continue;

                if (!first) oss << ',';
                first = false;

                if (func.byOrdinal) {
                    // For ordinal imports: "dll_name.ord<ordinal>"
                    oss << dllLower << ".ord" << func.ordinal;
                } else {
                    std::string funcLower = func.name;
                    std::transform(funcLower.begin(), funcLower.end(), funcLower.begin(), ::tolower);
                    oss << dllLower << '.' << funcLower;
                }
            }
        }

        std::string impString = oss.str();
        if (impString.empty()) return {};

        // Hash with MD5 per Mandiant ImpHash spec
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::MD5);
        if (!hasher.Init()) return {};
        if (!hasher.Update(impString.data(), impString.size())) return {};

        std::string hexResult;
        if (!hasher.FinalHex(hexResult, false)) return {};
        return hexResult;
    }

    // ========================================================================
    // KERNEL REAL-TIME PATH
    // ========================================================================

    void RegisterKernelScanCallback(ExecutableAnalyzer::KernelScanCallback callback) {
        std::unique_lock lock(m_mutex);
        m_kernelCallback = std::move(callback);
        SS_LOG_INFO(L"ExecutableAnalyzer", L"Kernel scan callback registered");
    }

    ExecutableInfo AnalyzeForKernel(const std::wstring& filePath, uint32_t processId, uint64_t fileSize) {
        // Fast-path analysis for kernel real-time scanning
        // Uses quick options + skips expensive operations

        if (fileSize > ExecutableAnalyzerConstants::MAX_FILE_SIZE) {
            // An oversized value is not automatically an oversized file.
            //
            // The size arrives in the kernel scan request, and requests have been
            // observed carrying impossible values - 0x63D8CB7B00000000, roughly
            // seven exabytes, with the low 32 bits zero. Trusting that number
            // meant the file was silently skipped, so anything that produced a
            // bad size also bought immunity from analysis. Confirm against the
            // filesystem before declining: GetFileAttributesEx reads the
            // directory entry without opening the file, so it neither costs a
            // handle nor re-enters the minifilter.
            uint64_t actualSize = 0;
            WIN32_FILE_ATTRIBUTE_DATA attr{};
            const bool haveActual =
                ::GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &attr) != FALSE;
            if (haveActual) {
                actualSize = (static_cast<uint64_t>(attr.nFileSizeHigh) << 32) |
                             static_cast<uint64_t>(attr.nFileSizeLow);
            }

            if (haveActual && actualSize <= ExecutableAnalyzerConstants::MAX_FILE_SIZE) {
                SS_LOG_WARN(L"ExecutableAnalyzer",
                    L"Kernel scan request reported an implausible size (%llu bytes) for "
                    L"'%ls'; actual size is %llu bytes, so analysing it rather than skipping",
                    fileSize, filePath.c_str(), actualSize);
                // fall through and analyse
            } else {
                SS_LOG_WARN(L"ExecutableAnalyzer",
                    L"Kernel scan skipped: file too large (reported %llu bytes, "
                    L"on-disk %llu bytes, queryable=%ls), PID %u",
                    fileSize, actualSize, haveActual ? L"yes" : L"no", processId);
                ExecutableInfo info{};
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }
        }

        auto opts = AnalysisOptions::CreateQuick();
        opts.calculateHashes = true;  // Always hash for kernel path (needed for hash lookups)

        auto info = Analyze(filePath, opts);

        // Notify registered callback
        {
            std::shared_lock lock(m_mutex);
            if (m_kernelCallback) {
                try {
                    m_kernelCallback(filePath, processId, info);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"ExecutableAnalyzer",
                        L"Kernel callback exception: %hs", e.what());
                }
            }
        }

        return info;
    }

    // ========================================================================
    // AI/ML FEATURE EXTRACTION
    // ========================================================================

    std::optional<std::vector<float>> ExtractMLFeatures(const ExecutableInfo& info) const {
        try {
            // EMBER-aligned static PE feature vector
            // Layout: [header_features(62) | section_features(255) | import_features(256) |
            //          export_features(128) | general_features(10) | histogram(256) | byteentropy(256)]
            // Subset: we extract what we have; total ~400 usable features

            std::vector<float> features;
            features.reserve(512);

            // --- Header features ---
            features.push_back(info.is64Bit ? 1.0f : 0.0f);
            features.push_back(static_cast<float>(info.imageBase));
            features.push_back(static_cast<float>(info.entryPoint));
            features.push_back(static_cast<float>(info.fileSize));
            features.push_back(static_cast<float>(info.sections.size()));
            features.push_back(static_cast<float>(info.imports.size()));
            features.push_back(static_cast<float>(info.exports.size()));
            features.push_back(static_cast<float>(info.overallEntropy));
            features.push_back(static_cast<float>(info.averageEntropy));
            features.push_back(info.signature.isSigned ? 1.0f : 0.0f);
            features.push_back(info.dotNet.isDotNet ? 1.0f : 0.0f);
            features.push_back(info.packer.isPacked ? 1.0f : 0.0f);
            features.push_back(info.richHeader.present ? 1.0f : 0.0f);
            features.push_back(info.richHeader.valid ? 1.0f : 0.0f);
            features.push_back(static_cast<float>(info.richHeader.entries.size()));
            features.push_back(static_cast<float>(info.riskScore));

            // --- Per-section features (up to 16 sections, 8 features each = 128) ---
            constexpr size_t MAX_ML_SECTIONS = 16;
            for (size_t i = 0; i < MAX_ML_SECTIONS; ++i) {
                if (i < info.sections.size()) {
                    const auto& s = info.sections[i];
                    features.push_back(static_cast<float>(s.virtualSize));
                    features.push_back(static_cast<float>(s.rawDataSize));
                    features.push_back(static_cast<float>(s.entropy));
                    features.push_back(s.isExecutable ? 1.0f : 0.0f);
                    features.push_back(s.isWritable ? 1.0f : 0.0f);
                    features.push_back(s.isPacked ? 1.0f : 0.0f);
                    features.push_back(s.virtualSize > 0 ? static_cast<float>(s.rawDataSize) / static_cast<float>(s.virtualSize) : 0.0f);
                    features.push_back(static_cast<float>(s.characteristics));
                } else {
                    for (int j = 0; j < 8; ++j) features.push_back(0.0f);
                }
            }

            // --- Import features ---
            size_t totalImportFunctions = 0;
            size_t riskyImportCount = 0;
            size_t ordinalImportCount = 0;
            for (const auto& dll : info.imports) {
                totalImportFunctions += dll.functions.size();
                for (const auto& func : dll.functions) {
                    if (func.byOrdinal) ++ordinalImportCount;
                    if (func.riskLevel >= ImportRiskLevel::High) ++riskyImportCount;
                }
            }
            features.push_back(static_cast<float>(totalImportFunctions));
            features.push_back(static_cast<float>(riskyImportCount));
            features.push_back(static_cast<float>(ordinalImportCount));

            // --- Export features ---
            size_t fwdExportCount = 0;
            size_t ordExportCount = 0;
            for (const auto& exp : info.exports) {
                if (exp.isForwarded) ++fwdExportCount;
                if (exp.name.empty()) ++ordExportCount;
            }
            features.push_back(static_cast<float>(info.exports.size()));
            features.push_back(static_cast<float>(fwdExportCount));
            features.push_back(static_cast<float>(ordExportCount));

            // --- Anomaly features ---
            features.push_back(static_cast<float>(info.anomalies.size()));

            // Count anomalies by severity. Anomaly severities are emitted in the
            // 0..100 range (see DetectedAnomaly::severity / per-anomaly emit
            // sites). Use thresholds aligned with that range so the ML feature
            // vector actually distinguishes critical from medium severities.
            size_t criticalAnomalies = 0, highAnomalies = 0, mediumAnomalies = 0;
            for (const auto& a : info.anomalies) {
                if (a.severity >= 75) ++criticalAnomalies;
                else if (a.severity >= 50) ++highAnomalies;
                else ++mediumAnomalies;
            }
            features.push_back(static_cast<float>(criticalAnomalies));
            features.push_back(static_cast<float>(highAnomalies));
            features.push_back(static_cast<float>(mediumAnomalies));

            // --- Resource features ---
            size_t peResources = 0, encryptedResources = 0, scriptResources = 0;
            for (const auto& r : info.resources) {
                if (r.isPE) ++peResources;
                if (r.isEncrypted) ++encryptedResources;
                if (r.isScript) ++scriptResources;
            }
            features.push_back(static_cast<float>(info.resources.size()));
            features.push_back(static_cast<float>(peResources));
            features.push_back(static_cast<float>(encryptedResources));
            features.push_back(static_cast<float>(scriptResources));

            // --- APT indicator features ---
            features.push_back(info.hasTLSCallbacks ? 1.0f : 0.0f);
            features.push_back(static_cast<float>(info.tlsCallbackCount));
            features.push_back(info.hasDelayLoadImports ? 1.0f : 0.0f);
            features.push_back(static_cast<float>(info.delayLoadImports.size()));
            features.push_back(info.hasOverlappingSections ? 1.0f : 0.0f);
            features.push_back(info.hasEntryPointOutsideCode ? 1.0f : 0.0f);
            features.push_back(info.hasCFG ? 1.0f : 0.0f);
            features.push_back(info.hasCET ? 1.0f : 0.0f);
            features.push_back(info.hasIntegrityCheck ? 1.0f : 0.0f);
            features.push_back(info.overlayContainsPE ? 1.0f : 0.0f);
            features.push_back(static_cast<float>(info.overlayEntropy));
            features.push_back(static_cast<float>(info.overlaySize));
            features.push_back(info.hasDebugDirectory ? 1.0f : 0.0f);

            return features;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExtractMLFeatures failed: %hs", e.what());
            return std::nullopt;
        }
    }

    // ========================================================================
    // EXTRACT RESOURCES FORWARDING
    // ========================================================================

    std::vector<ResourceEntry> ExtractResources(const std::wstring& filePath) const {
        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return {};
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, false);
            return ParseResourcesImpl(data, info);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExtractResources: %hs", e.what());
            return {};
        }
    }

    // ========================================================================
    // DELAY-LOAD IMPORT PARSING
    // ========================================================================

    std::vector<ImportedDLL> ParseDelayLoadImportsImpl(
        std::span<const uint8_t> buffer, const ExecutableInfo& info) const
    {
        std::vector<ImportedDLL> delayImports;
        try {
            if (info.sections.empty()) return delayImports;

            const size_t ntOff = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;
            uint32_t delayDirRVA = 0;
            uint32_t delayDirSize = 0;

            if (info.is64Bit) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
                    delayDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                    delayDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
                }
            } else {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
                    delayDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                    delayDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
                }
            }

            if (delayDirRVA == 0 || delayDirSize == 0) return delayImports;

            auto dirOffset = RVAToFileOffset(delayDirRVA, info.sections);
            if (!dirOffset.has_value()) return delayImports;

            const size_t base = dirOffset.value();

            // ImgDelayDescr is 32 bytes: Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA,
            //   ImportNameTableRVA, BoundImportAddressTableRVA, UnloadInformationTableRVA, TimeDateStamp
            constexpr size_t DESC_SIZE = 32;
            constexpr size_t MAX_DELAY_DESCS = 1000;

            for (size_t i = 0; i < MAX_DELAY_DESCS; ++i) {
                const size_t descOff = base + i * DESC_SIZE;
                if (descOff + DESC_SIZE > buffer.size()) break;

                uint32_t attrs = 0, dllNameRVA = 0, intRVA = 0;
                std::memcpy(&attrs, buffer.data() + descOff, 4);
                std::memcpy(&dllNameRVA, buffer.data() + descOff + 4, 4);
                std::memcpy(&intRVA, buffer.data() + descOff + 16, 4);

                if (dllNameRVA == 0) break;

                ImportedDLL dll;
                dll.isDelayLoad = true;

                // attrs bit 0: if set, RVAs are used; if clear, VAs (old-style).
                // Modern linkers always set bit 0 (RVA-based).
                const bool rvaMode = (attrs & 1) != 0;

                // Read DLL name
                auto nameOff = RVAToFileOffset(dllNameRVA, info.sections);
                if (nameOff.has_value() && nameOff.value() < buffer.size()) {
                    const size_t ns = nameOff.value();
                    const size_t ml = std::min(buffer.size() - ns, size_t(260));
                    dll.name = std::string(
                        reinterpret_cast<const char*>(buffer.data() + ns),
                        strnlen(reinterpret_cast<const char*>(buffer.data() + ns), ml)
                    );
                }

                // Parse delay-loaded functions via INT (ImportNameTable)
                if (intRVA != 0) {
                    auto thunkOff = RVAToFileOffset(intRVA, info.sections);
                    if (thunkOff.has_value()) {
                        ParseImportFunctions(buffer, thunkOff.value(), info, dll);
                    }
                }

                // Aggregate risk
                const auto& riskyAPIs = GetRiskyAPIs();
                for (const auto& func : dll.functions) {
                    if (func.riskLevel > dll.highestRisk) dll.highestRisk = func.riskLevel;
                    if (func.riskLevel == ImportRiskLevel::Critical) dll.criticalAPIs++;
                    else if (func.riskLevel == ImportRiskLevel::High) dll.highRiskAPIs++;
                }
                dll.isSuspicious = (dll.criticalAPIs > 0) || (dll.highRiskAPIs >= 3);

                delayImports.push_back(std::move(dll));
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ParseDelayLoadImportsImpl: %hs", e.what());
        }
        return delayImports;
    }

    // ========================================================================
    // TLS CALLBACK PARSING
    // ========================================================================

    void ParseTLSCallbacksImpl(std::span<const uint8_t> buffer, ExecutableInfo& info) const {
        try {
            if (info.sections.empty()) return;

            const size_t ntOff = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;
            uint32_t tlsDirRVA = 0;
            uint32_t tlsDirSize = 0;

            if (info.is64Bit) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
                    tlsDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                    tlsDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                }
            } else {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
                    tlsDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                    tlsDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
                }
            }

            if (tlsDirRVA == 0 || tlsDirSize == 0) return;

            auto tlsOffset = RVAToFileOffset(tlsDirRVA, info.sections);
            if (!tlsOffset.has_value()) return;

            if (info.is64Bit) {
                if (tlsOffset.value() + sizeof(IMAGE_TLS_DIRECTORY64) > buffer.size()) return;
                const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(
                    buffer.data() + tlsOffset.value());

                if (tls->AddressOfCallBacks == 0) return;

                // AddressOfCallBacks is a VA, convert to RVA then to file offset
                const uint64_t cbVA = tls->AddressOfCallBacks;
                if (cbVA < info.imageBase) return;
                const uint32_t cbRVA = static_cast<uint32_t>(cbVA - info.imageBase);

                auto cbOffset = RVAToFileOffset(cbRVA, info.sections);
                if (!cbOffset.has_value()) return;

                constexpr size_t MAX_TLS_CBS = 256;
                for (size_t i = 0; i < MAX_TLS_CBS; ++i) {
                    const size_t entryOff = cbOffset.value() + i * sizeof(uint64_t);
                    if (entryOff + sizeof(uint64_t) > buffer.size()) break;

                    uint64_t callbackVA = 0;
                    std::memcpy(&callbackVA, buffer.data() + entryOff, sizeof(uint64_t));
                    if (callbackVA == 0) break;

                    info.tlsCallbackRVAs.push_back(
                        callbackVA >= info.imageBase ? callbackVA - info.imageBase : callbackVA);
                }
            } else {
                if (tlsOffset.value() + sizeof(IMAGE_TLS_DIRECTORY32) > buffer.size()) return;
                const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32*>(
                    buffer.data() + tlsOffset.value());

                if (tls->AddressOfCallBacks == 0) return;

                const uint32_t cbVA = tls->AddressOfCallBacks;
                if (cbVA < static_cast<uint32_t>(info.imageBase)) return;
                const uint32_t cbRVA = cbVA - static_cast<uint32_t>(info.imageBase);

                auto cbOffset = RVAToFileOffset(cbRVA, info.sections);
                if (!cbOffset.has_value()) return;

                constexpr size_t MAX_TLS_CBS = 256;
                for (size_t i = 0; i < MAX_TLS_CBS; ++i) {
                    const size_t entryOff = cbOffset.value() + i * sizeof(uint32_t);
                    if (entryOff + sizeof(uint32_t) > buffer.size()) break;

                    uint32_t callbackVA = 0;
                    std::memcpy(&callbackVA, buffer.data() + entryOff, sizeof(uint32_t));
                    if (callbackVA == 0) break;

                    info.tlsCallbackRVAs.push_back(
                        callbackVA >= static_cast<uint32_t>(info.imageBase)
                            ? callbackVA - static_cast<uint32_t>(info.imageBase)
                            : callbackVA);
                }
            }

            info.hasTLSCallbacks = !info.tlsCallbackRVAs.empty();
            info.tlsCallbackCount = static_cast<uint32_t>(info.tlsCallbackRVAs.size());

            if (info.hasTLSCallbacks) {
                SS_LOG_DEBUG(L"ExecutableAnalyzer", L"TLS callbacks detected: %u", info.tlsCallbackCount);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ParseTLSCallbacksImpl: %hs", e.what());
        }
    }

    // ========================================================================
    // DEBUG DIRECTORY PARSING
    // ========================================================================

    void ParseDebugDirectoryImpl(std::span<const uint8_t> buffer, ExecutableInfo& info) const {
        try {
            if (info.sections.empty()) return;

            const size_t ntOff = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;
            uint32_t dbgDirRVA = 0;
            uint32_t dbgDirSize = 0;

            if (info.is64Bit) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
                    dbgDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    dbgDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }
            } else {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntOff);
                if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG) {
                    dbgDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
                    dbgDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                }
            }

            if (dbgDirRVA == 0 || dbgDirSize < sizeof(IMAGE_DEBUG_DIRECTORY)) return;

            auto dbgOffset = RVAToFileOffset(dbgDirRVA, info.sections);
            if (!dbgOffset.has_value()) return;

            const size_t numEntries = dbgDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
            constexpr size_t MAX_DBG_ENTRIES = 64;

            for (size_t i = 0; i < std::min(numEntries, MAX_DBG_ENTRIES); ++i) {
                const size_t entryOff = dbgOffset.value() + i * sizeof(IMAGE_DEBUG_DIRECTORY);
                if (entryOff + sizeof(IMAGE_DEBUG_DIRECTORY) > buffer.size()) break;

                const auto* dbgDir = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
                    buffer.data() + entryOff);

                info.hasDebugDirectory = true;
                info.debugType = dbgDir->Type;

                // Extract PDB path from CodeView (type 2) debug data
                if (dbgDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW &&
                    dbgDir->PointerToRawData > 0 &&
                    dbgDir->SizeOfData >= 24)
                {
                    const size_t cvOff = dbgDir->PointerToRawData;
                    if (cvOff + dbgDir->SizeOfData <= buffer.size()) {
                        uint32_t cvSig = 0;
                        std::memcpy(&cvSig, buffer.data() + cvOff, 4);

                        // RSDS signature (PDB 7.0+)
                        if (cvSig == 0x53445352 && dbgDir->SizeOfData > 24) {
                            const size_t pathStart = cvOff + 24;
                            const size_t maxPathLen = std::min(
                                static_cast<size_t>(dbgDir->SizeOfData) - 24,
                                size_t(1024));
                            if (pathStart + maxPathLen <= buffer.size()) {
                                info.pdbPath = std::string(
                                    reinterpret_cast<const char*>(buffer.data() + pathStart),
                                    strnlen(reinterpret_cast<const char*>(buffer.data() + pathStart), maxPathLen)
                                );
                            }
                        }
                        // NB10 signature (PDB 2.0)
                        else if (cvSig == 0x3031424E && dbgDir->SizeOfData > 16) {
                            const size_t pathStart = cvOff + 16;
                            const size_t maxPathLen = std::min(
                                static_cast<size_t>(dbgDir->SizeOfData) - 16,
                                size_t(1024));
                            if (pathStart + maxPathLen <= buffer.size()) {
                                info.pdbPath = std::string(
                                    reinterpret_cast<const char*>(buffer.data() + pathStart),
                                    strnlen(reinterpret_cast<const char*>(buffer.data() + pathStart), maxPathLen)
                                );
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ParseDebugDirectoryImpl: %hs", e.what());
        }
    }

    // ========================================================================
    // OVERLAPPING SECTION DETECTION
    // ========================================================================

    void DetectOverlappingSectionsImpl(ExecutableInfo& info) const {
        if (info.sections.size() < 2) return;

        for (size_t i = 0; i < info.sections.size(); ++i) {
            const auto& a = info.sections[i];
            if (a.rawDataSize == 0) continue;

            const uint64_t aStart = a.rawDataOffset;
            const uint64_t aEnd = static_cast<uint64_t>(a.rawDataOffset) + a.rawDataSize;

            for (size_t j = i + 1; j < info.sections.size(); ++j) {
                const auto& b = info.sections[j];
                if (b.rawDataSize == 0) continue;

                const uint64_t bStart = b.rawDataOffset;
                const uint64_t bEnd = static_cast<uint64_t>(b.rawDataOffset) + b.rawDataSize;

                if (aStart < bEnd && bStart < aEnd) {
                    info.hasOverlappingSections = true;
                    info.anomalies.push_back({
                        AnomalyType::OverlappingSections,
                        "Overlapping sections: " + a.name + " and " + b.name,
                        a.name,
                        a.rawDataOffset,
                        75,
                        "T1027"
                    });
                }
            }
        }
    }

    // ========================================================================
    // ENTRY POINT ANOMALY DETECTION
    // ========================================================================

    void DetectEntryPointAnomaliesImpl(
        std::span<const uint8_t> buffer, ExecutableInfo& info) const
    {
        if (info.entryPoint == 0 && !info.isDLL) {
            info.anomalies.push_back({
                AnomalyType::InvalidNTHeader,
                "Entry point is zero for non-DLL executable",
                "", 0, 60, "T1027"
            });
            return;
        }

        if (info.entryPoint == 0) return;

        bool foundInSection = false;
        bool inExecutable = false;
        bool inLastSection = false;
        bool inWritable = false;

        for (size_t i = 0; i < info.sections.size(); ++i) {
            const auto& sec = info.sections[i];
            if (info.entryPoint >= sec.virtualAddress &&
                info.entryPoint < static_cast<uint64_t>(sec.virtualAddress) + sec.virtualSize)
            {
                foundInSection = true;
                inExecutable = sec.isExecutable;
                inWritable = sec.isWritable;
                inLastSection = (i == info.sections.size() - 1);

                // Entry point near end of section (common packer pattern)
                const uint64_t epOffsetInSec = info.entryPoint - sec.virtualAddress;
                if (sec.virtualSize > 0 && epOffsetInSec > (sec.virtualSize * 9 / 10)) {
                    info.anomalies.push_back({
                        AnomalyType::SuspiciousSectionNames,
                        "Entry point near end of section " + sec.name +
                            " (offset " + std::to_string(epOffsetInSec) + "/" +
                            std::to_string(sec.virtualSize) + ")",
                        sec.name, sec.rawDataOffset, 45, "T1027"
                    });
                }
                break;
            }
        }

        if (!foundInSection) {
            info.hasEntryPointOutsideCode = true;
            info.anomalies.push_back({
                AnomalyType::InvalidNTHeader,
                "Entry point (0x" + std::to_string(info.entryPoint) +
                    ") outside all sections",
                "", 0, 80, "T1027"
            });
        } else if (!inExecutable) {
            info.hasEntryPointOutsideCode = true;
            info.anomalies.push_back({
                AnomalyType::ExecutableData,
                "Entry point in non-executable section",
                "", 0, 70, "T1055"
            });
        }

        if (inWritable && inExecutable) {
            info.anomalies.push_back({
                AnomalyType::WritableCode,
                "Entry point in writable+executable section (self-modifying code)",
                "", 0, 75, "T1027"
            });
        }

        if (inLastSection && info.sections.size() > 1) {
            info.anomalies.push_back({
                AnomalyType::SuspiciousSectionNames,
                "Entry point in last section (common packer pattern)",
                "", 0, 40, "T1027"
            });
        }

        // Check entry point in header area (before first section VA)
        if (!info.sections.empty() &&
            info.entryPoint < info.sections.front().virtualAddress &&
            info.entryPoint > 0)
        {
            info.anomalies.push_back({
                AnomalyType::InvalidNTHeader,
                "Entry point in PE headers (before first section)",
                "", 0, 85, "T1027"
            });
        }
    }

    // ========================================================================
    // OVERLAY ANALYSIS
    // ========================================================================

    void AnalyzeOverlayImpl(std::span<const uint8_t> buffer, ExecutableInfo& info) const {
        try {
            if (info.sections.empty()) return;

            // Overlay = data after last section's raw data
            uint64_t lastSectionEnd = 0;
            for (const auto& sec : info.sections) {
                if (sec.rawDataSize > 0) {
                    const uint64_t secEnd =
                        static_cast<uint64_t>(sec.rawDataOffset) + sec.rawDataSize;
                    if (secEnd > lastSectionEnd) {
                        lastSectionEnd = secEnd;
                    }
                }
            }

            if (lastSectionEnd == 0 || lastSectionEnd >= buffer.size()) return;

            info.overlayOffset = static_cast<uint32_t>(std::min(lastSectionEnd, uint64_t(UINT32_MAX)));
            const size_t overlaySize = buffer.size() - static_cast<size_t>(lastSectionEnd);
            info.overlaySize = static_cast<uint32_t>(std::min(overlaySize, size_t(UINT32_MAX)));

            if (info.overlaySize == 0) return;

            // Calculate overlay entropy
            std::span<const uint8_t> overlayData = buffer.subspan(
                static_cast<size_t>(lastSectionEnd),
                std::min(overlaySize, size_t(1024 * 1024))  // Sample first 1MB for perf
            );
            info.overlayEntropy = CalculateEntropy(overlayData);

            // Check for embedded PE in overlay
            if (overlaySize >= sizeof(IMAGE_DOS_HEADER)) {
                const auto* mz = reinterpret_cast<const IMAGE_DOS_HEADER*>(
                    buffer.data() + static_cast<size_t>(lastSectionEnd));
                if (mz->e_magic == ExecutableAnalyzerConstants::DOS_SIGNATURE) {
                    info.overlayContainsPE = true;
                    info.anomalies.push_back({
                        AnomalyType::SuspiciousOverlay,
                        "Overlay contains embedded PE (dropper indicator)",
                        "", info.overlayOffset, 70, "T1027"
                    });
                }
            }

            if (info.overlayEntropy >= ExecutableAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                info.anomalies.push_back({
                    AnomalyType::SuspiciousOverlay,
                    "Overlay has high entropy (" + std::to_string(info.overlayEntropy) +
                        ") — likely encrypted payload",
                    "", info.overlayOffset, 55, "T1027"
                });
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"AnalyzeOverlayImpl: %hs", e.what());
        }
    }

    // ========================================================================
    // CERTIFICATE CHAIN EXTRACTION
    // ========================================================================

    void ExtractCertificateDetailsImpl(const std::wstring& filePath, SignatureInfo& sigInfo) const {
        try {
            HCERTSTORE hStore = nullptr;
            HCRYPTMSG hMsg = nullptr;

            if (!CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    filePath.c_str(),
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0, nullptr, nullptr, nullptr,
                    &hStore, &hMsg, nullptr))
            {
                return;
            }

            // Get signer info
            DWORD signerInfoSize = 0;
            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) &&
                signerInfoSize > 0 && signerInfoSize < 64 * 1024)
            {
                std::vector<uint8_t> signerInfoBuf(signerInfoSize);
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.data(), &signerInfoSize))
                {
                    const auto* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());

                    CERT_INFO certInfo{};
                    certInfo.Issuer = signerInfo->Issuer;
                    certInfo.SerialNumber = signerInfo->SerialNumber;

                    PCCERT_CONTEXT pCertCtx = CertFindCertificateInStore(
                        hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

                    if (pCertCtx) {
                        // Extract subject name
                        wchar_t nameBuf[512] = {};
                        DWORD nameLen = CertGetNameStringW(
                            pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                            nameBuf, _countof(nameBuf));
                        if (nameLen > 1) {
                            sigInfo.signerName = nameBuf;
                        }

                        // Extract issuer name
                        nameLen = CertGetNameStringW(
                            pCertCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
                            nullptr, nameBuf, _countof(nameBuf));
                        if (nameLen > 1) {
                            sigInfo.issuerName = nameBuf;
                        }

                        // Check for Microsoft signature
                        if (sigInfo.signerName.find(L"Microsoft") != std::wstring::npos) {
                            sigInfo.isMicrosoftSigned = true;
                        }

                        // Extract certificate validity dates
                        FILETIME localFt{};
                        SYSTEMTIME st{};

                        FileTimeToLocalFileTime(&pCertCtx->pCertInfo->NotBefore, &localFt);
                        FileTimeToSystemTime(&localFt, &st);
                        // Convert SYSTEMTIME to time_point. mktime() returns
                        // (time_t)-1 for unrepresentable inputs (e.g. dates
                        // outside the local time range); preserve epoch instead
                        // of feeding -1 into from_time_t which would yield
                        // 1969-12-31T23:59:59.
                        std::tm tmFrom{};
                        tmFrom.tm_year = st.wYear - 1900;
                        tmFrom.tm_mon = st.wMonth - 1;
                        tmFrom.tm_mday = st.wDay;
                        tmFrom.tm_hour = st.wHour;
                        tmFrom.tm_min = st.wMinute;
                        tmFrom.tm_sec = st.wSecond;
                        tmFrom.tm_isdst = -1;
                        const std::time_t tFrom = std::mktime(&tmFrom);
                        if (tFrom != static_cast<std::time_t>(-1)) {
                            sigInfo.certValidFrom = std::chrono::system_clock::from_time_t(tFrom);
                        }

                        FileTimeToLocalFileTime(&pCertCtx->pCertInfo->NotAfter, &localFt);
                        FileTimeToSystemTime(&localFt, &st);
                        std::tm tmTo{};
                        tmTo.tm_year = st.wYear - 1900;
                        tmTo.tm_mon = st.wMonth - 1;
                        tmTo.tm_mday = st.wDay;
                        tmTo.tm_hour = st.wHour;
                        tmTo.tm_min = st.wMinute;
                        tmTo.tm_sec = st.wSecond;
                        tmTo.tm_isdst = -1;
                        const std::time_t tTo = std::mktime(&tmTo);
                        if (tTo != static_cast<std::time_t>(-1)) {
                            sigInfo.certValidTo = std::chrono::system_clock::from_time_t(tTo);
                        }

                        // Build certificate chain
                        CERT_CHAIN_PARA chainPara{};
                        chainPara.cbSize = sizeof(chainPara);
                        PCCERT_CHAIN_CONTEXT pChainCtx = nullptr;

                        // CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL is required here for
                        // the same reason WTD_CACHE_ONLY_URL_RETRIEVAL is required
                        // in VerifySignatureImpl above, and its absence is why
                        // fixing that one alone did not cure the freeze.
                        //
                        // This function is called from VerifySignatureImpl the
                        // moment WinVerifyTrust reports the file is signed, so it
                        // sits on the synchronous on-access path with a kernel file
                        // operation held open behind it. With dwFlags = 0 the chain
                        // engine resolves missing issuers through the Authority
                        // Information Access extension over the NETWORK, so the
                        // expensive retrieval that was just suppressed one call
                        // earlier was immediately performed again here.
                        //
                        // Field evidence, 1.0.89 trace ring, 2026-08-13. In the
                        // same run, on the same threads:
                        //   step.IsMicrosoftSigned(WinVerifyTrust)  completed
                        //     dozens of times, 7-43 ms - it calls WinVerifyTrust
                        //     and nothing else, and that call is cache-only.
                        //   Analyze.VerifySignature  entered at 00:21:29.532 on
                        //     t9652 and 00:21:31.041 on t10216 and NEVER returned.
                        // The distinguishing factor between the two is precisely
                        // this function: only the second path builds a chain.
                        // t10216 was still completing its own WinVerifyTrust calls
                        // at 00:21:30.9 while t9652 was already stuck in here, so
                        // WinVerifyTrust itself was healthy and the block is in the
                        // chain builder. The service log agrees exactly - scans=32,
                        // clean=30, and the two missing completions are these two
                        // threads. Two workers stuck means zero scan capacity,
                        // which is the machine-wide lag.
                        //
                        // No detection is lost. Revocation is not requested here
                        // and is not being disabled. The flag changes only where
                        // issuer certificates may come from: the local stores and
                        // the caches the startup warm-up populates, rather than the
                        // network. When an issuer genuinely is not available
                        // locally the chain comes back partial, TrustStatus is not
                        // CERT_TRUST_NO_ERROR, and isTrusted is therefore false -
                        // so the file is treated as less trusted and receives more
                        // analysis, never less. The authoritative signature verdict
                        // was already established by WinVerifyTrust before we got
                        // here; this call exists to name the chain elements.
                        //
                        // Deliberately NOT applied blanket-wide. Chain building
                        // that legitimately needs the network - TLS validation in
                        // NetworkSecurity_SSL_TLS, certificate pinning in the
                        // banking module, and the update trust path - must keep
                        // reaching it, because there a slow fetch delays only the
                        // operation that asked for it. The rule is not "never use
                        // the network", it is "never use the network while holding
                        // a kernel file operation open".
                        if (CertGetCertificateChain(
                                nullptr, pCertCtx, nullptr, hStore,
                                &chainPara, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                                nullptr, &pChainCtx))
                        {
                            if (pChainCtx->cChain > 0) {
                                const auto* chain = pChainCtx->rgpChain[0];
                                for (DWORD ci = 0; ci < chain->cElement && ci < 16; ++ci) {
                                    wchar_t chainName[512] = {};
                                    CertGetNameStringW(
                                        chain->rgpElement[ci]->pCertContext,
                                        CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                        chainName, _countof(chainName));
                                    sigInfo.certificateChain.emplace_back(chainName);
                                }

                                sigInfo.isTrusted =
                                    (pChainCtx->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);
                            }
                            CertFreeCertificateChain(pChainCtx);
                        }

                        CertFreeCertificateContext(pCertCtx);
                    }
                }
            }

            if (hMsg) CryptMsgClose(hMsg);
            if (hStore) CertCloseStore(hStore, 0);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExtractCertificateDetailsImpl: %hs", e.what());
        }
    }

    // ========================================================================
    // SECURITY MITIGATION DETAIL EXTRACTION
    // ========================================================================

    void ExtractSecurityMitigationsImpl(std::span<const uint8_t> buffer, ExecutableInfo& info) const {
        try {
            if (info.sections.empty()) return;

            const size_t ntOff = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint16_t dllChars = 0;
            if (info.is64Bit) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntOff);
                dllChars = nt->OptionalHeader.DllCharacteristics;
            } else {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntOff);
                dllChars = nt->OptionalHeader.DllCharacteristics;
            }

            info.hasIntegrityCheck = (dllChars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
            info.isAppContainer = (dllChars & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) != 0;

            // CET (Shadow Stack) detection via extended DLL characteristics in debug dir
            // Type 20 (IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS) contains CET flags
            // This is detected if the debug directory was parsed and type matches
            // For now, flag from load config if present
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ExtractSecurityMitigationsImpl: %hs", e.what());
        }
    }

    // ========================================================================
    // COMPUTE SECTION HASHES FORWARDING
    // ========================================================================

    std::unordered_map<std::string, std::string> ComputeSectionHashes(const std::wstring& filePath) const {
        std::unordered_map<std::string, std::string> result;

        try {
            std::vector<std::byte> fileBytes;
            if (!Utils::FileUtils::ReadAllBytes(filePath, fileBytes)) {
                return result;
            }

            std::span<const uint8_t> data(
                reinterpret_cast<const uint8_t*>(fileBytes.data()),
                fileBytes.size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, true);

            for (const auto& section : info.sections) {
                if (!section.sha256Hex.empty()) {
                    result[section.name] = section.sha256Hex;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ExecutableAnalyzer", L"ComputeSectionHashes: %hs", e.what());
        }

        return result;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{ false };
    ExecutableAnalyzerStatistics m_stats;
    ExecutableAnalyzer::KernelScanCallback m_kernelCallback;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

ExecutableAnalyzer::ExecutableAnalyzer()
    : m_impl(std::make_unique<ExecutableAnalyzerImpl>()) {
}

ExecutableAnalyzer::~ExecutableAnalyzer() = default;

ExecutableAnalyzer& ExecutableAnalyzer::Instance() {
    static ExecutableAnalyzer instance;
    return instance;
}

bool ExecutableAnalyzer::Initialize() {
    return m_impl->Initialize();
}

void ExecutableAnalyzer::Shutdown() noexcept {
    m_impl->Shutdown();
}

ExecutableInfo ExecutableAnalyzer::Analyze(const std::wstring& filePath, const AnalysisOptions& options) {
    return m_impl->Analyze(filePath, options);
}

ExecutableInfo ExecutableAnalyzer::AnalyzeBuffer(std::span<const uint8_t> buffer, const AnalysisOptions& options) {
    return m_impl->AnalyzeBuffer(buffer, options);
}

bool ExecutableAnalyzer::IsPE(const std::wstring& filePath) const {
    return m_impl->IsPE(filePath);
}

bool ExecutableAnalyzer::IsPE(std::span<const uint8_t> buffer) const {
    return m_impl->IsPEBuffer(buffer);
}

ExecutableType ExecutableAnalyzer::GetExecutableType(std::span<const uint8_t> buffer) const {
    return m_impl->GetExecutableType(buffer);
}

ExecutableInfo ExecutableAnalyzer::ParseHeaders(const std::wstring& filePath) const {
    AnalysisOptions opts = AnalysisOptions::CreateMinimal();
    return m_impl->Analyze(filePath, opts);
}

std::vector<ImportedDLL> ExecutableAnalyzer::ParseImports(const std::wstring& filePath) const {
    return m_impl->ParseImports(filePath);
}

std::vector<ExportedFunction> ExecutableAnalyzer::ParseExports(const std::wstring& filePath) const {
    return m_impl->ParseExports(filePath);
}

std::vector<ResourceEntry> ExecutableAnalyzer::ExtractResources(const std::wstring& filePath) const {
    return m_impl->ExtractResources(filePath);
}

VersionInfo ExecutableAnalyzer::GetVersionInfo(const std::wstring& filePath) const {
    return m_impl->GetVersionInfoImpl(filePath);
}

SignatureInfo ExecutableAnalyzer::VerifySignature(const std::wstring& filePath) const {
    return m_impl->VerifySignature(filePath);
}

PackerInfo ExecutableAnalyzer::DetectPacker(const std::wstring& filePath) const {
    return m_impl->DetectPacker(filePath);
}

std::vector<DetectedAnomaly> ExecutableAnalyzer::DetectAnomalies(const ExecutableInfo& info) const {
    return m_impl->DetectAnomaliesImpl(info);
}

uint8_t ExecutableAnalyzer::CalculateRiskScore(const ExecutableInfo& info) const {
    return m_impl->CalculateRiskScoreImpl(info);
}

std::string ExecutableAnalyzer::ComputeImpHash(const std::vector<ImportedDLL>& imports) const {
    return m_impl->ComputeImpHashImpl(imports);
}

std::unordered_map<std::string, std::string> ExecutableAnalyzer::ComputeSectionHashes(const std::wstring& filePath) const {
    return m_impl->ComputeSectionHashes(filePath);
}

const ExecutableAnalyzerStatistics& ExecutableAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void ExecutableAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

void ExecutableAnalyzer::RegisterKernelScanCallback(KernelScanCallback callback) {
    m_impl->RegisterKernelScanCallback(std::move(callback));
}

ExecutableInfo ExecutableAnalyzer::AnalyzeForKernel(
    const std::wstring& filePath, uint32_t processId, uint64_t fileSize) {
    return m_impl->AnalyzeForKernel(filePath, processId, fileSize);
}

std::optional<std::vector<float>> ExecutableAnalyzer::ExtractMLFeatures(
    const ExecutableInfo& info) const {
    return m_impl->ExtractMLFeatures(info);
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
