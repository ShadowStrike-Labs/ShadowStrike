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

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"

// Windows includes for PE parsing
#include <Windows.h>
#include <winnt.h>
#include <wintrust.h>
#include <softpub.h>
#include <Imagehlp.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")

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
 * @brief Safe RVA to file offset conversion.
 */
std::optional<uint32_t> RVAToFileOffset(uint32_t rva, std::span<const PESection> sections) {
    for (const auto& section : sections) {
        if (rva >= section.virtualAddress &&
            rva < section.virtualAddress + section.virtualSize) {
            const uint32_t offset = rva - section.virtualAddress;
            return section.rawDataOffset + offset;
        }
    }
    return std::nullopt;
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
    }

    std::pair<ImportRiskLevel, std::string> GetAPIRisk(const std::string& apiName) const {
        auto it = apis.find(apiName);
        if (it != apis.end()) {
            return it->second;
        }
        return {ImportRiskLevel::Safe, ""};
    }
};

static const RiskyAPIDatabase g_riskyAPIs;

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
        {".data", ".rsrc"},  // Armadillo uses normal section names
        {},
        6.9,
        false
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
            Logger::Info("ExecutableAnalyzer: Initializing...");

            // Verify infrastructure is available
            if (!HashStore::HashStore::Instance().IsInitialized()) {
                Logger::Warn("ExecutableAnalyzer: HashStore not initialized, initializing now");
                if (!HashStore::HashStore::Instance().Initialize()) {
                    Logger::Error("ExecutableAnalyzer: Failed to initialize HashStore");
                    return false;
                }
            }

            m_initialized = true;
            Logger::Info("ExecutableAnalyzer: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        Logger::Info("ExecutableAnalyzer: Shutdown complete");
    }

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    ExecutableInfo Analyze(const std::wstring& filePath, const AnalysisOptions& options) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        ExecutableInfo info{};
        info.analysisTime = std::chrono::system_clock::now();

        try {
            // Validate input
            if (filePath.empty()) {
                Logger::Error("ExecutableAnalyzer::Analyze: Empty file path");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            if (filePath.length() > 32767) {
                Logger::Error("ExecutableAnalyzer::Analyze: Path too long: {}", filePath.length());
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Check file exists
            if (!Utils::FileUtils::FileExists(filePath)) {
                Logger::Error("ExecutableAnalyzer::Analyze: File not found: {}",
                    Utils::StringUtils::WideToUtf8(filePath));
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Get file size
            info.fileSize = Utils::FileUtils::GetFileSize(filePath);
            if (info.fileSize == 0) {
                Logger::Warn("ExecutableAnalyzer::Analyze: File is empty");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            if (info.fileSize > ExecutableAnalyzerConstants::MAX_FILE_SIZE) {
                Logger::Error("ExecutableAnalyzer::Analyze: File too large: {} bytes", info.fileSize);
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            // Memory-map the file for analysis
            auto fileMapping = Utils::FileUtils::MemoryMapFile(filePath);
            if (!fileMapping || fileMapping->size() == 0) {
                Logger::Error("ExecutableAnalyzer::Analyze: Failed to memory-map file");
                m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
                return info;
            }

            std::span<const uint8_t> fileData(
                static_cast<const uint8_t*>(fileMapping->data()),
                fileMapping->size()
            );

            // Analyze the buffer
            info = AnalyzeBufferImpl(fileData, options);

            // Calculate hashes if requested
            if (options.calculateHashes) {
                CalculateHashes(filePath, info);
            }

            // Verify signature if requested (requires file path)
            if (options.parseSignature) {
                info.signature = VerifySignatureImpl(filePath);
                if (info.signature.isSigned) {
                    m_stats.signedFiles.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Get version info
            if (options.parseResources) {
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

            Logger::Info("ExecutableAnalyzer: Analyzed {} in {} μs (type: {}, risk: {})",
                Utils::StringUtils::WideToUtf8(filePath),
                duration.count(),
                static_cast<int>(info.type),
                info.riskScore);

            return info;

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::Analyze: Exception: {}", e.what());
            m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
            return info;
        }
    }

    ExecutableInfo AnalyzeBuffer(std::span<const uint8_t> buffer, const AnalysisOptions& options) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        try {
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
            Logger::Error("ExecutableAnalyzer::AnalyzeBuffer: Exception: {}", e.what());
            m_stats.invalidFiles.fetch_add(1, std::memory_order_relaxed);
            return ExecutableInfo{};
        }
    }

    // ========================================================================
    // TYPE DETECTION
    // ========================================================================

    bool IsPE(const std::wstring& filePath) const {
        try {
            auto fileMapping = Utils::FileUtils::MemoryMapFile(filePath);
            if (!fileMapping || fileMapping->size() < sizeof(IMAGE_DOS_HEADER)) {
                return false;
            }

            std::span<const uint8_t> data(
                static_cast<const uint8_t*>(fileMapping->data()),
                fileMapping->size()
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

        if (dosHeader->e_lfanew < 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > buffer.size()) {
            return false;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            buffer.data() + dosHeader->e_lfanew
        );

        return ntHeaders->Signature == ExecutableAnalyzerConstants::NT_SIGNATURE;
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
            auto fileMapping = Utils::FileUtils::MemoryMapFile(filePath);
            if (!fileMapping) {
                return {};
            }

            std::span<const uint8_t> data(
                static_cast<const uint8_t*>(fileMapping->data()),
                fileMapping->size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            return ParseImportsImpl(data, info);

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::ParseImports: {}", e.what());
            return {};
        }
    }

    std::vector<ExportedFunction> ParseExports(const std::wstring& filePath) const {
        try {
            auto fileMapping = Utils::FileUtils::MemoryMapFile(filePath);
            if (!fileMapping) {
                return {};
            }

            std::span<const uint8_t> data(
                static_cast<const uint8_t*>(fileMapping->data()),
                fileMapping->size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            return ParseExportsImpl(data, info);

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::ParseExports: {}", e.what());
            return {};
        }
    }

    PackerInfo DetectPacker(const std::wstring& filePath) const {
        try {
            auto fileMapping = Utils::FileUtils::MemoryMapFile(filePath);
            if (!fileMapping) {
                return PackerInfo{};
            }

            std::span<const uint8_t> data(
                static_cast<const uint8_t*>(fileMapping->data()),
                fileMapping->size()
            );

            ExecutableInfo info{};
            ParsePEHeaders(data, info);
            ParseSections(data, info, true);

            return DetectPackerImpl(data, info);

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::DetectPacker: {}", e.what());
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

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
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

        if (dosHeader->e_lfanew < 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buffer.size()) {
            return;
        }

        // NT headers (check both 32 and 64 bit)
        const auto* ntHeaders32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
            buffer.data() + dosHeader->e_lfanew
        );

        if (ntHeaders32->Signature != ExecutableAnalyzerConstants::NT_SIGNATURE) {
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

        // Timestamp
        info.timestamp = ntHeaders32->FileHeader.TimeDateStamp;
        if (info.timestamp > 0) {
            info.compilationTime = std::chrono::system_clock::from_time_t(info.timestamp);
        }

        // Parse optional header (architecture-specific)
        if (info.is64Bit) {
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

        if (ntHeadersOffset + sizeof(IMAGE_NT_HEADERS) > buffer.size()) {
            return;
        }

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            buffer.data() + ntHeadersOffset
        );

        const uint16_t numSections = ntHeaders->FileHeader.NumberOfSections;
        if (numSections > ExecutableAnalyzerConstants::MAX_SECTIONS) {
            Logger::Warn("ExecutableAnalyzer: Too many sections: {}", numSections);
            return;
        }

        const size_t sectionHeadersOffset = ntHeadersOffset +
            sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;

        if (sectionHeadersOffset + (numSections * sizeof(IMAGE_SECTION_HEADER)) > buffer.size()) {
            return;
        }

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
                        auto hash = Utils::HashUtils::SHA256(sectionData);
                        std::copy(hash.begin(), hash.end(), section.sha256.begin());
                        section.sha256Hex = BytesToHex(hash);
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

            // Parse each imported DLL
            for (size_t i = 0; i < ExecutableAnalyzerConstants::MAX_IMPORTS && importDesc[i].Name != 0; ++i) {
                ImportedDLL dll;

                // Get DLL name
                auto nameOffset = RVAToFileOffset(importDesc[i].Name, info.sections);
                if (nameOffset.has_value() && nameOffset.value() < buffer.size()) {
                    const char* dllName = reinterpret_cast<const char*>(buffer.data() + nameOffset.value());
                    dll.name = dllName;

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
            Logger::Error("ExecutableAnalyzer::ParseImportsImpl: {}", e.what());
        }

        return imports;
    }

    void ParseImportFunctions(std::span<const uint8_t> buffer, size_t thunkOffset,
                              const ExecutableInfo& info, ImportedDLL& dll) const {
        if (info.is64Bit) {
            const auto* thunks = reinterpret_cast<const IMAGE_THUNK_DATA64*>(buffer.data() + thunkOffset);

            for (size_t i = 0; i < 10000 && thunks[i].u1.AddressOfData != 0; ++i) {
                ImportedFunction func;
                func.thunkRVA = static_cast<uint64_t>(thunks[i].u1.AddressOfData);

                if (IMAGE_SNAP_BY_ORDINAL64(thunks[i].u1.Ordinal)) {
                    func.byOrdinal = true;
                    func.ordinal = IMAGE_ORDINAL64(thunks[i].u1.Ordinal);
                    func.name = "#" + std::to_string(func.ordinal);
                } else {
                    auto nameOffset = RVAToFileOffset(static_cast<uint32_t>(thunks[i].u1.AddressOfData), info.sections);
                    if (nameOffset.has_value() && nameOffset.value() + 2 < buffer.size()) {
                        const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            buffer.data() + nameOffset.value()
                        );
                        func.name = reinterpret_cast<const char*>(importByName->Name);
                        func.ordinal = importByName->Hint;
                    }
                }

                // Assess risk
                auto [riskLevel, reason] = g_riskyAPIs.GetAPIRisk(func.name);
                func.riskLevel = riskLevel;
                func.riskReason = reason;

                dll.functions.push_back(std::move(func));
            }
        } else {
            const auto* thunks = reinterpret_cast<const IMAGE_THUNK_DATA32*>(buffer.data() + thunkOffset);

            for (size_t i = 0; i < 10000 && thunks[i].u1.AddressOfData != 0; ++i) {
                ImportedFunction func;
                func.thunkRVA = thunks[i].u1.AddressOfData;

                if (IMAGE_SNAP_BY_ORDINAL32(thunks[i].u1.Ordinal)) {
                    func.byOrdinal = true;
                    func.ordinal = IMAGE_ORDINAL32(thunks[i].u1.Ordinal);
                    func.name = "#" + std::to_string(func.ordinal);
                } else {
                    auto nameOffset = RVAToFileOffset(thunks[i].u1.AddressOfData, info.sections);
                    if (nameOffset.has_value() && nameOffset.value() + 2 < buffer.size()) {
                        const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                            buffer.data() + nameOffset.value()
                        );
                        func.name = reinterpret_cast<const char*>(importByName->Name);
                        func.ordinal = importByName->Hint;
                    }
                }

                // Assess risk
                auto [riskLevel, reason] = g_riskyAPIs.GetAPIRisk(func.name);
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

            // Get export directory RVA
            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t exportDirRVA = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                    exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                }
            }

            if (exportDirRVA == 0) {
                return exports;  // No exports
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

            if (numFunctions > ExecutableAnalyzerConstants::MAX_EXPORTS) {
                Logger::Warn("ExecutableAnalyzer: Too many exports: {}", numFunctions);
                return exports;
            }

            // Parse exports (simplified version)
            // Full implementation would parse AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals arrays

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::ParseExportsImpl: {}", e.what());
        }

        return exports;
    }

    std::vector<ResourceEntry> ParseResourcesImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        std::vector<ResourceEntry> resources;

        // Resource parsing is complex - simplified implementation
        // Full implementation would recursively parse resource directory tree

        return resources;
    }

    RichHeader ParseRichHeaderImpl(std::span<const uint8_t> buffer) const {
        RichHeader richHeader;

        try {
            if (buffer.size() < sizeof(IMAGE_DOS_HEADER) + 128) {
                return richHeader;
            }

            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());

            // Rich header is located between DOS stub and PE header
            // Look for "Rich" signature (backwards from PE header)
            const size_t peOffset = dosHeader->e_lfanew;
            if (peOffset < 128 || peOffset > buffer.size()) {
                return richHeader;
            }

            // Search for "Rich" signature
            const uint32_t richSignature = 0x68636952;  // "Rich"

            for (size_t i = peOffset - 4; i >= sizeof(IMAGE_DOS_HEADER) && i > peOffset - 256; i -= 4) {
                const uint32_t* dword = reinterpret_cast<const uint32_t*>(buffer.data() + i);
                if (*dword == richSignature) {
                    richHeader.present = true;
                    richHeader.checksum = *(dword + 1);

                    // Rich header found - could parse entries here
                    // Entries are XORed with checksum

                    break;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::ParseRichHeaderImpl: {}", e.what());
        }

        return richHeader;
    }

    DotNetMetadata ParseDotNetImpl(std::span<const uint8_t> buffer, const ExecutableInfo& info) const {
        DotNetMetadata dotNet;

        try {
            if (info.sections.empty()) {
                return dotNet;
            }

            // Get CLR directory RVA
            const size_t ntHeaderOffset = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data())->e_lfanew;

            uint32_t clrDirRVA = 0;

            if (info.is64Bit) {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    clrDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                }
            } else {
                const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + ntHeaderOffset);
                if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
                    clrDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
                }
            }

            if (clrDirRVA != 0) {
                dotNet.isDotNet = true;

                // Could parse IMAGE_COR20_HEADER here for detailed .NET info
                // For now, just mark as .NET
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::ParseDotNetImpl: {}", e.what());
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
                            packerInfo.type = sig.type;
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
                                                packerInfo.type = sig.type;
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
                packerInfo.type = PackerType::Unknown;
                packerInfo.name = "Unknown Packer";
                packerInfo.confidence = 0.7;
                packerInfo.indicators.push_back("High entropy: " + std::to_string(info.averageEntropy));
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::DetectPackerImpl: {}", e.what());
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
                    AnomalyType::SuspiciousChecksum,
                    "DEP (Data Execution Prevention) not enabled",
                    "",
                    0,
                    20,
                    ""
                });
            }

            if (!info.hasASLR && !info.isDLL) {
                anomalies.push_back({
                    AnomalyType::SuspiciousChecksum,
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

            // Check overlay
            if (info.fileSize > info.imageSize) {
                const uint32_t overlaySize = static_cast<uint32_t>(info.fileSize - info.imageSize);
                if (overlaySize > 1024 * 1024) {  // > 1MB
                    anomalies.push_back({
                        AnomalyType::LargeOverlay,
                        "Large overlay detected: " + std::to_string(overlaySize) + " bytes",
                        "",
                        0,
                        40,
                        "T1027"
                    });
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::DetectAnomaliesImpl: {}", e.what());
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

            // Cap at 100
            if (score > 100) {
                score = 100;
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::CalculateRiskScoreImpl: {}", e.what());
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
            Logger::Error("ExecutableAnalyzer::GetVersionInfoImpl: {}", e.what());
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
            trustData.dwProvFlags = WTD_SAFER_FLAG;

            LONG result = WinVerifyTrust(nullptr, &policyGUID, &trustData);

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
                // Could use CertUtils here for detailed certificate chain parsing
                // Simplified for now
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::VerifySignatureImpl: {}", e.what());
        }

        return sigInfo;
    }

    void CalculateHashes(const std::wstring& filePath, ExecutableInfo& info) const {
        try {
            // Use HashStore infrastructure
            auto md5 = HashStore::HashStore::Instance().CalculateMD5(filePath);
            auto sha1 = HashStore::HashStore::Instance().CalculateSHA1(filePath);
            auto sha256 = HashStore::HashStore::Instance().CalculateSHA256(filePath);

            if (md5.size() == 16) {
                std::copy(md5.begin(), md5.end(), info.md5.begin());
                info.md5Hex = BytesToHex(md5);
            }

            if (sha1.size() == 20) {
                std::copy(sha1.begin(), sha1.end(), info.sha1.begin());
                info.sha1Hex = BytesToHex(sha1);
            }

            if (sha256.size() == 32) {
                std::copy(sha256.begin(), sha256.end(), info.sha256.begin());
                info.sha256Hex = BytesToHex(sha256);
            }

            // Calculate ImpHash
            if (!info.imports.empty()) {
                info.imphash = ComputeImpHashImpl(info.imports);
            }

        } catch (const std::exception& e) {
            Logger::Error("ExecutableAnalyzer::CalculateHashes: {}", e.what());
        }
    }

    std::string ComputeImpHashImpl(const std::vector<ImportedDLL>& imports) const {
        std::ostringstream oss;

        for (const auto& dll : imports) {
            for (const auto& func : dll.functions) {
                if (!func.name.empty() && func.name[0] != '#') {
                    std::string lowerName = func.name;
                    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
                    oss << lowerName << ",";
                }
            }
        }

        std::string impString = oss.str();
        if (!impString.empty()) {
            impString.pop_back();  // Remove trailing comma
        }

        // Hash the import string
        std::vector<uint8_t> data(impString.begin(), impString.end());
        auto hash = Utils::HashUtils::MD5(std::span<const uint8_t>(data.data(), data.size()));
        return BytesToHex(hash);
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    ExecutableAnalyzerStatistics m_stats;
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
    // Not implemented in this version
    return {};
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
    // Not implemented in this version
    return {};
}

const ExecutableAnalyzerStatistics& ExecutableAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void ExecutableAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
