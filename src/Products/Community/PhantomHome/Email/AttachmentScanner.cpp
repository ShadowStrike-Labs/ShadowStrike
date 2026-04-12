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
 * @file AttachmentScanner.cpp
 * @brief Enterprise implementation of email attachment scanning engine.
 *
 * The Email Guardian of ShadowStrike NGAV - provides comprehensive attachment analysis
 * with archive extraction, format-specific exploit detection, macro scanning, and
 * embedded content analysis to protect against malicious email threats.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "AttachmentScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Scripts/MacroDetector.hpp"
#include "../Core/FileSystem/FileHasher.hpp"
#include "../Core/FileSystem/ArchiveExtractor.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <thread>
#include <future>
#include <cmath>
#include <numeric>
#include <regex>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <imagehlp.h>
#  pragma comment(lib, "imagehlp.lib")
#endif

namespace ShadowStrike {
namespace Email {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Magic byte signatures for file type detection.
 */
struct MagicSignature {
    std::vector<uint8_t> signature;
    FileTypeCategory category;
    std::string mimeType;
};

static const std::vector<MagicSignature> g_magicSignatures = {
    // Executables
    {{0x4D, 0x5A}, FileTypeCategory::Executable, "application/x-msdownload"},  // PE (MZ)
    {{0x7F, 0x45, 0x4C, 0x46}, FileTypeCategory::Executable, "application/x-elf"},  // ELF

    // Archives
    {{0x50, 0x4B, 0x03, 0x04}, FileTypeCategory::Archive, "application/zip"},  // ZIP
    {{0x50, 0x4B, 0x05, 0x06}, FileTypeCategory::Archive, "application/zip"},  // ZIP (empty)
    {{0x52, 0x61, 0x72, 0x21}, FileTypeCategory::Archive, "application/x-rar"},  // RAR
    {{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, FileTypeCategory::Archive, "application/x-7z-compressed"},  // 7z
    {{0x1F, 0x8B}, FileTypeCategory::Archive, "application/gzip"},  // GZIP

    // Documents
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, FileTypeCategory::Document, "application/vnd.ms-office"},  // OLE/DOC
    {{0x25, 0x50, 0x44, 0x46}, FileTypeCategory::PDF, "application/pdf"},  // PDF

    // Disk Images
    {{0x43, 0x44, 0x30, 0x30, 0x31}, FileTypeCategory::DiskImage, "application/x-iso9660-image"},  // ISO
};

/**
 * @brief Calculate Shannon entropy.
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
 * @brief Check if file has PE header.
 */
[[nodiscard]] bool IsPEFile(std::span<const uint8_t> data) noexcept {
    if (data.size() < 64) return false;

    // Check MZ signature
    if (data[0] != 'M' || data[1] != 'Z') return false;

    // Get PE offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[60]);
    if (peOffset + 4 > data.size()) return false;

    // Check PE signature
    return (data[peOffset] == 'P' && data[peOffset + 1] == 'E' &&
            data[peOffset + 2] == 0x00 && data[peOffset + 3] == 0x00);
}

/**
 * @brief Detect if extension is high-risk.
 */
[[nodiscard]] bool IsHighRiskExtensionImpl(std::string_view extension) noexcept {
    for (const auto& ext : AttachmentConstants::HIGH_RISK_EXTENSIONS) {
        if (StringUtils::EqualsIgnoreCase(extension, ext)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Detect if extension is archive.
 */
[[nodiscard]] bool IsArchiveExtensionImpl(std::string_view extension) noexcept {
    for (const auto& ext : AttachmentConstants::ARCHIVE_EXTENSIONS) {
        if (StringUtils::EqualsIgnoreCase(extension, ext)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Convert verdict to string.
 */
[[nodiscard]] std::string_view VerdictToString(AttachmentVerdict verdict) noexcept {
    switch (verdict) {
        case AttachmentVerdict::Clean: return "Clean";
        case AttachmentVerdict::Malicious: return "Malicious";
        case AttachmentVerdict::Suspicious: return "Suspicious";
        case AttachmentVerdict::PotentiallyUnwanted: return "PotentiallyUnwanted";
        case AttachmentVerdict::HighRisk: return "HighRisk";
        case AttachmentVerdict::EncryptedArchive: return "EncryptedArchive";
        case AttachmentVerdict::CorruptedFile: return "CorruptedFile";
        case AttachmentVerdict::UnsupportedType: return "UnsupportedType";
        case AttachmentVerdict::SizeLimitExceeded: return "SizeLimitExceeded";
        case AttachmentVerdict::ScanError: return "ScanError";
        default: return "Unknown";
    }
}

} // anonymous namespace

// ============================================================================
// STRUCTURE JSON SERIALIZATION
// ============================================================================

[[nodiscard]] std::string DetectedArtifact::ToJson() const {
    nlohmann::json j;
    j["artifactType"] = artifactType;
    j["description"] = description;
    j["location"] = location;
    j["riskLevel"] = riskLevel;
    j["extractionSuccessful"] = extractionSuccessful;
    return j.dump();
}

[[nodiscard]] std::string NestedFileInfo::ToJson() const {
    nlohmann::json j;
    j["fileName"] = fileName;
    j["relativePath"] = relativePath;
    j["fileSize"] = fileSize;
    j["compressedSize"] = compressedSize;
    j["fileType"] = static_cast<int>(fileType);
    j["isHighRisk"] = isHighRisk;
    j["isEncrypted"] = isEncrypted;
    j["verdict"] = std::string(VerdictToString(verdict));
    j["threatName"] = threatName;
    return j.dump();
}

[[nodiscard]] bool AttachmentScanResult::IsMalicious() const noexcept {
    return verdict == AttachmentVerdict::Malicious;
}

[[nodiscard]] bool AttachmentScanResult::ShouldBlock() const noexcept {
    return verdict == AttachmentVerdict::Malicious ||
           verdict == AttachmentVerdict::HighRisk ||
           (verdict == AttachmentVerdict::Suspicious && riskScore >= 70);
}

[[nodiscard]] std::string AttachmentScanResult::ToJson() const {
    nlohmann::json j;
    j["fileName"] = fileName;
    j["filePath"] = filePath.string();
    j["verdict"] = std::string(VerdictToString(verdict));
    j["fileType"] = static_cast<int>(fileType);
    j["mimeType"] = mimeType;
    j["isArchive"] = isArchive;
    j["archiveDepth"] = archiveDepth;
    j["threats"] = static_cast<uint32_t>(threats);
    j["threatName"] = threatName;
    j["threatFamily"] = threatFamily;
    j["riskScore"] = riskScore;
    j["sha256"] = sha256;
    j["fileSize"] = fileSize;
    j["hasMacros"] = hasMacros;
    j["hasEmbeddedContent"] = hasEmbeddedContent;
    j["isPasswordProtected"] = isPasswordProtected;
    j["extensionMatchesContent"] = extensionMatchesContent;
    j["scanDuration"] = scanDuration.count();
    j["errorMessage"] = errorMessage;

    nlohmann::json artifacts = nlohmann::json::array();
    for (const auto& artifact : this->artifacts) {
        artifacts.push_back(nlohmann::json::parse(artifact.ToJson()));
    }
    j["artifacts"] = artifacts;

    return j.dump();
}

[[nodiscard]] bool AttachmentScanConfig::IsValid() const noexcept {
    return maxArchiveDepth > 0 && maxArchiveDepth <= 20 &&
           maxExtractionSize > 0;
}

[[nodiscard]] std::string AttachmentScanConfig::ToJson() const {
    nlohmann::json j;
    j["depth"] = static_cast<int>(depth);
    j["extractArchives"] = extractArchives;
    j["maxArchiveDepth"] = maxArchiveDepth;
    j["maxExtractionSize"] = maxExtractionSize;
    j["scanMacros"] = scanMacros;
    j["scanEmbeddedContent"] = scanEmbeddedContent;
    j["useYARA"] = useYARA;
    j["useSandbox"] = useSandbox;
    j["blockHighRiskExtensions"] = blockHighRiskExtensions;
    j["blockPasswordProtected"] = blockPasswordProtected;
    j["calculateAllHashes"] = calculateAllHashes;
    return j.dump();
}

void AttachmentStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    maliciousDetected.store(0, std::memory_order_relaxed);
    suspiciousDetected.store(0, std::memory_order_relaxed);
    cleanDetected.store(0, std::memory_order_relaxed);
    archivesExtracted.store(0, std::memory_order_relaxed);
    nestedFilesScanned.store(0, std::memory_order_relaxed);
    macrosDetected.store(0, std::memory_order_relaxed);
    passwordProtectedBlocked.store(0, std::memory_order_relaxed);
    highRiskExtensionsBlocked.store(0, std::memory_order_relaxed);
    scanErrors.store(0, std::memory_order_relaxed);
    totalBytesScanned.store(0, std::memory_order_relaxed);

    for (auto& counter : byFileType) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byThreatType) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

[[nodiscard]] std::string AttachmentStatistics::ToJson() const {
    nlohmann::json j;
    j["totalScans"] = totalScans.load();
    j["maliciousDetected"] = maliciousDetected.load();
    j["suspiciousDetected"] = suspiciousDetected.load();
    j["cleanDetected"] = cleanDetected.load();
    j["archivesExtracted"] = archivesExtracted.load();
    j["nestedFilesScanned"] = nestedFilesScanned.load();
    j["macrosDetected"] = macrosDetected.load();
    j["passwordProtectedBlocked"] = passwordProtectedBlocked.load();
    j["highRiskExtensionsBlocked"] = highRiskExtensionsBlocked.load();
    j["scanErrors"] = scanErrors.load();
    j["totalBytesScanned"] = totalBytesScanned.load();
    return j.dump();
}

[[nodiscard]] bool AttachmentScannerConfiguration::IsValid() const noexcept {
    return maxConcurrentScans > 0 && maxConcurrentScans <= 32 &&
           defaultScanConfig.IsValid();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAttachmentVerdictName(AttachmentVerdict verdict) noexcept {
    return VerdictToString(verdict);
}

[[nodiscard]] std::string_view GetFileTypeCategoryName(FileTypeCategory cat) noexcept {
    switch (cat) {
        case FileTypeCategory::Unknown: return "Unknown";
        case FileTypeCategory::Executable: return "Executable";
        case FileTypeCategory::Script: return "Script";
        case FileTypeCategory::Document: return "Document";
        case FileTypeCategory::Spreadsheet: return "Spreadsheet";
        case FileTypeCategory::Presentation: return "Presentation";
        case FileTypeCategory::PDF: return "PDF";
        case FileTypeCategory::Archive: return "Archive";
        case FileTypeCategory::DiskImage: return "DiskImage";
        case FileTypeCategory::Media: return "Media";
        case FileTypeCategory::Data: return "Data";
        case FileTypeCategory::Configuration: return "Configuration";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAttachmentThreatTypeName(AttachmentThreatType type) noexcept {
    switch (type) {
        case AttachmentThreatType::None: return "None";
        case AttachmentThreatType::KnownMalware: return "KnownMalware";
        case AttachmentThreatType::SuspiciousContent: return "SuspiciousContent";
        case AttachmentThreatType::MaliciousMacro: return "MaliciousMacro";
        case AttachmentThreatType::PDFJavaScript: return "PDFJavaScript";
        case AttachmentThreatType::OLEObject: return "OLEObject";
        case AttachmentThreatType::DDEExploit: return "DDEExploit";
        case AttachmentThreatType::TemplateInjection: return "TemplateInjection";
        case AttachmentThreatType::EmbeddedExecutable: return "EmbeddedExecutable";
        case AttachmentThreatType::DisguisedExecutable: return "DisguisedExecutable";
        case AttachmentThreatType::ExtensionMismatch: return "ExtensionMismatch";
        case AttachmentThreatType::HighEntropy: return "HighEntropy";
        case AttachmentThreatType::PolyglotFile: return "PolyglotFile";
        case AttachmentThreatType::ExploitCode: return "ExploitCode";
        case AttachmentThreatType::ShellcodeDetected: return "ShellcodeDetected";
        case AttachmentThreatType::PasswordProtected: return "PasswordProtected";
        case AttachmentThreatType::ZipBomb: return "ZipBomb";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetScanDepthName(ScanDepth depth) noexcept {
    switch (depth) {
        case ScanDepth::Quick: return "Quick";
        case ScanDepth::Standard: return "Standard";
        case ScanDepth::Deep: return "Deep";
        case ScanDepth::Forensic: return "Forensic";
        default: return "Unknown";
    }
}

[[nodiscard]] FileTypeCategory ClassifyByExtension(std::string_view extension) noexcept {
    std::string ext = StringUtils::ToLowerCase(std::string(extension));

    // Executables
    if (ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".com" ||
        ext == ".msi" || ext == ".msp") {
        return FileTypeCategory::Executable;
    }

    // Scripts
    if (ext == ".bat" || ext == ".cmd" || ext == ".vbs" || ext == ".vbe" ||
        ext == ".js" || ext == ".jse" || ext == ".wsf" || ext == ".wsh" ||
        ext == ".ps1" || ext == ".psm1" || ext == ".psd1") {
        return FileTypeCategory::Script;
    }

    // Documents
    if (ext == ".doc" || ext == ".docx" || ext == ".dot" || ext == ".dotx" ||
        ext == ".rtf" || ext == ".odt") {
        return FileTypeCategory::Document;
    }

    // Spreadsheets
    if (ext == ".xls" || ext == ".xlsx" || ext == ".xlsm" || ext == ".xlt" ||
        ext == ".xltx" || ext == ".ods") {
        return FileTypeCategory::Spreadsheet;
    }

    // Presentations
    if (ext == ".ppt" || ext == ".pptx" || ext == ".pps" || ext == ".ppsx" ||
        ext == ".odp") {
        return FileTypeCategory::Presentation;
    }

    // PDF
    if (ext == ".pdf") {
        return FileTypeCategory::PDF;
    }

    // Archives
    if (IsArchiveExtensionImpl(extension)) {
        return FileTypeCategory::Archive;
    }

    // Disk Images
    if (ext == ".iso" || ext == ".img" || ext == ".vhd" || ext == ".vhdx") {
        return FileTypeCategory::DiskImage;
    }

    return FileTypeCategory::Unknown;
}

[[nodiscard]] FileTypeCategory ClassifyByMagic(std::span<const uint8_t> header) noexcept {
    for (const auto& sig : g_magicSignatures) {
        if (header.size() >= sig.signature.size()) {
            if (std::equal(sig.signature.begin(), sig.signature.end(), header.begin())) {
                return sig.category;
            }
        }
    }

    return FileTypeCategory::Unknown;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for AttachmentScanner.
 */
class AttachmentScanner::AttachmentScannerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_statsMutex;
    std::mutex m_scanMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};

    // Configuration
    AttachmentScannerConfiguration m_config{};

    // Statistics
    AttachmentStatistics m_stats{};

    // Callbacks
    ScanResultCallback m_scanResultCallback;
    ThreatDetectedCallback m_threatCallback;
    ProgressCallback m_progressCallback;
    ErrorCallback m_errorCallback;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    AttachmentScannerImpl() = default;
    ~AttachmentScannerImpl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const AttachmentScannerConfiguration& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("AttachmentScanner::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("AttachmentScanner::Impl: Initializing");

            m_status.store(ModuleStatus::Initializing, std::memory_order_release);

            // Validate configuration
            if (!config.IsValid()) {
                Logger::Error("AttachmentScanner: Invalid configuration");
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                return false;
            }

            // Store configuration
            m_config = config;

            // Create temp extraction directory
            if (!m_config.tempExtractionPath.empty()) {
                if (!fs::exists(m_config.tempExtractionPath)) {
                    fs::create_directories(m_config.tempExtractionPath);
                }
            } else {
                m_config.tempExtractionPath = fs::temp_directory_path() / "ShadowStrike" / "Attachments";
                fs::create_directories(m_config.tempExtractionPath);
            }

            // Reset statistics
            m_stats.Reset();

            m_initialized.store(true, std::memory_order_release);
            m_status.store(ModuleStatus::Running, std::memory_order_release);

            Logger::Info("AttachmentScanner::Impl: Initialization complete");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("AttachmentScanner::Impl: Initialization exception: {}", e.what());
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("AttachmentScanner::Impl: Shutting down");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_scanResultCallback = nullptr;
            m_threatCallback = nullptr;
            m_progressCallback = nullptr;
            m_errorCallback = nullptr;
        }

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Logger::Info("AttachmentScanner::Impl: Shutdown complete");
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    [[nodiscard]] AttachmentScanResult ScanAttachmentImpl(
        const fs::path& path,
        const AttachmentScanConfig& config
    ) {
        AttachmentScanResult result;
        result.fileName = path.filename().string();
        result.filePath = path;
        result.scanTime = system_clock::now();

        const auto scanStart = steady_clock::now();

        try {
            m_status.store(ModuleStatus::Scanning, std::memory_order_release);

            // Validate file exists
            if (!fs::exists(path)) {
                result.verdict = AttachmentVerdict::ScanError;
                result.errorMessage = "File not found";
                m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            // Check file size
            result.fileSize = fs::file_size(path);
            if (result.fileSize > AttachmentConstants::MAX_ATTACHMENT_SIZE) {
                result.verdict = AttachmentVerdict::SizeLimitExceeded;
                result.riskScore = 50;
                m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            m_stats.totalBytesScanned.fetch_add(result.fileSize, std::memory_order_relaxed);

            // Detect file type
            result.fileType = DetectFileTypeImpl(path);
            m_stats.byFileType[static_cast<size_t>(result.fileType)].fetch_add(1, std::memory_order_relaxed);

            // Check high-risk extension
            std::string extension = path.extension().string();
            if (config.blockHighRiskExtensions && IsHighRiskExtensionImpl(extension)) {
                result.verdict = AttachmentVerdict::HighRisk;
                result.riskScore = 90;
                result.threats = AttachmentThreatType::DisguisedExecutable;
                m_stats.highRiskExtensionsBlocked.fetch_add(1, std::memory_order_relaxed);
                m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

                InvokeThreatCallback(result);
                return result;
            }

            // Read file header for magic byte detection
            std::vector<uint8_t> fileHeader(1024);
            {
                std::ifstream file(path, std::ios::binary);
                if (file) {
                    file.read(reinterpret_cast<char*>(fileHeader.data()), fileHeader.size());
                    fileHeader.resize(file.gcount());
                }
            }

            // Verify extension matches content
            result.extensionMatchesContent = VerifyExtensionImpl(path, fileHeader);
            if (!result.extensionMatchesContent) {
                result.threats = static_cast<AttachmentThreatType>(
                    static_cast<uint32_t>(result.threats) |
                    static_cast<uint32_t>(AttachmentThreatType::ExtensionMismatch)
                );
                result.riskScore += 30;
            }

            // Calculate hashes
            if (config.calculateAllHashes) {
                result.sha256 = HashUtils::CalculateSHA256File(path);
                result.md5 = HashUtils::CalculateMD5File(path);
                result.sha1 = HashUtils::CalculateSHA1File(path);
            } else {
                result.sha256 = HashUtils::CalculateSHA256File(path);
            }

            // Check against known malware hashes
            if (CheckKnownMalwareImpl(result.sha256)) {
                result.verdict = AttachmentVerdict::Malicious;
                result.threatName = "Known.Malware";
                result.riskScore = 100;
                result.threats = AttachmentThreatType::KnownMalware;

                m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

                InvokeThreatCallback(result);
                return result;
            }

            // Entropy analysis
            if (config.depth >= ScanDepth::Standard) {
                double entropy = CalculateEntropy(fileHeader);
                if (entropy >= 7.5) {
                    result.threats = static_cast<AttachmentThreatType>(
                        static_cast<uint32_t>(result.threats) |
                        static_cast<uint32_t>(AttachmentThreatType::HighEntropy)
                    );
                    result.riskScore += 20;
                }
            }

            // PE file detection
            if (IsPEFile(fileHeader)) {
                result.threats = static_cast<AttachmentThreatType>(
                    static_cast<uint32_t>(result.threats) |
                    static_cast<uint32_t>(AttachmentThreatType::EmbeddedExecutable)
                );
                result.riskScore += 40;
            }

            // Archive handling
            result.isArchive = IsArchiveImpl(path);
            if (result.isArchive && config.extractArchives) {
                // Check password protection
                result.isPasswordProtected = IsPasswordProtectedArchiveImpl(path);

                if (result.isPasswordProtected) {
                    if (config.blockPasswordProtected) {
                        result.verdict = AttachmentVerdict::EncryptedArchive;
                        result.riskScore = 70;
                        m_stats.passwordProtectedBlocked.fetch_add(1, std::memory_order_relaxed);
                        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

                        InvokeThreatCallback(result);
                        return result;
                    }

                    result.threats = static_cast<AttachmentThreatType>(
                        static_cast<uint32_t>(result.threats) |
                        static_cast<uint32_t>(AttachmentThreatType::PasswordProtected)
                    );
                    result.riskScore += 30;
                }

                // Extract and scan archive
                auto extractResult = ExtractAndScanArchiveImpl(path, config, 0);
                result.nestedFiles = extractResult.nestedFiles;
                result.archiveDepth = extractResult.maxDepth;

                // Aggregate nested results
                for (const auto& nested : result.nestedFiles) {
                    if (nested.verdict == AttachmentVerdict::Malicious) {
                        result.verdict = AttachmentVerdict::Malicious;
                        result.threatName = nested.threatName;
                        result.riskScore = 100;
                        break;
                    }
                    if (nested.verdict == AttachmentVerdict::Suspicious) {
                        result.verdict = AttachmentVerdict::Suspicious;
                        result.riskScore = std::max(result.riskScore, 70);
                    }
                }

                m_stats.archivesExtracted.fetch_add(1, std::memory_order_relaxed);
            }

            // Macro detection for Office documents
            if (config.scanMacros && (result.fileType == FileTypeCategory::Document ||
                result.fileType == FileTypeCategory::Spreadsheet ||
                result.fileType == FileTypeCategory::Presentation)) {

                result.hasMacros = DetectMacrosImpl(path);
                if (result.hasMacros) {
                    result.threats = static_cast<AttachmentThreatType>(
                        static_cast<uint32_t>(result.threats) |
                        static_cast<uint32_t>(AttachmentThreatType::MaliciousMacro)
                    );
                    result.riskScore += 50;
                    m_stats.macrosDetected.fetch_add(1, std::memory_order_relaxed);

                    // Analyze macro content
                    auto macroResult = AnalyzeMacroContentImpl(path);
                    if (macroResult.isSuspicious) {
                        result.verdict = AttachmentVerdict::Suspicious;
                        result.threatName = "Suspicious.Macro";
                        result.riskScore = std::max(result.riskScore, 80);
                    }
                }
            }

            // Determine final verdict
            if (result.verdict == AttachmentVerdict::Clean) {
                if (result.riskScore >= 80) {
                    result.verdict = AttachmentVerdict::Suspicious;
                    m_stats.suspiciousDetected.fetch_add(1, std::memory_order_relaxed);
                } else if (result.riskScore >= 50) {
                    result.verdict = AttachmentVerdict::HighRisk;
                } else {
                    m_stats.cleanDetected.fetch_add(1, std::memory_order_relaxed);
                }
            }

            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

            result.scanDuration = duration_cast<microseconds>(steady_clock::now() - scanStart);

            InvokeScanResultCallback(result);

            if (result.IsMalicious() || result.verdict == AttachmentVerdict::Suspicious) {
                InvokeThreatCallback(result);
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("AttachmentScanner: Scan exception: {}", e.what());
            result.verdict = AttachmentVerdict::ScanError;
            result.errorMessage = e.what();
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);

            InvokeErrorCallback(e.what(), -1);
            return result;
        } finally {
            m_status.store(ModuleStatus::Running, std::memory_order_release);
        }
    }

    [[nodiscard]] AttachmentScanResult ScanBufferImpl(
        std::span<const uint8_t> buffer,
        const std::string& fileName,
        const AttachmentScanConfig& config
    ) {
        // Write buffer to temp file and scan
        try {
            fs::path tempPath = m_config.tempExtractionPath / fileName;

            std::ofstream outFile(tempPath, std::ios::binary);
            if (!outFile) {
                AttachmentScanResult result;
                result.fileName = fileName;
                result.verdict = AttachmentVerdict::ScanError;
                result.errorMessage = "Failed to create temp file";
                return result;
            }

            outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            outFile.close();

            auto result = ScanAttachmentImpl(tempPath, config);

            // Clean up temp file
            try {
                fs::remove(tempPath);
            } catch (...) {
                // Ignore cleanup errors
            }

            return result;

        } catch (const std::exception& e) {
            Logger::Error("AttachmentScanner: Buffer scan exception: {}", e.what());
            AttachmentScanResult result;
            result.fileName = fileName;
            result.verdict = AttachmentVerdict::ScanError;
            result.errorMessage = e.what();
            return result;
        }
    }

    // ========================================================================
    // FILE TYPE DETECTION
    // ========================================================================

    [[nodiscard]] FileTypeCategory DetectFileTypeImpl(const fs::path& path) {
        // First try by magic bytes
        std::vector<uint8_t> header(64);
        {
            std::ifstream file(path, std::ios::binary);
            if (file) {
                file.read(reinterpret_cast<char*>(header.data()), header.size());
                header.resize(file.gcount());
            }
        }

        FileTypeCategory magicCategory = ClassifyByMagic(header);
        if (magicCategory != FileTypeCategory::Unknown) {
            return magicCategory;
        }

        // Fallback to extension
        return ClassifyByExtension(path.extension().string());
    }

    [[nodiscard]] bool VerifyExtensionImpl(
        const fs::path& path,
        const std::vector<uint8_t>& header
    ) {
        FileTypeCategory extensionCat = ClassifyByExtension(path.extension().string());
        FileTypeCategory magicCat = ClassifyByMagic(header);

        if (magicCat == FileTypeCategory::Unknown) {
            return true;  // Can't verify
        }

        return extensionCat == magicCat;
    }

    // ========================================================================
    // ARCHIVE HANDLING
    // ========================================================================

    struct ArchiveExtractionResult {
        std::vector<NestedFileInfo> nestedFiles;
        size_t maxDepth = 0;
        bool zipBombDetected = false;
    };

    [[nodiscard]] ArchiveExtractionResult ExtractAndScanArchiveImpl(
        const fs::path& archivePath,
        const AttachmentScanConfig& config,
        size_t currentDepth
    ) {
        ArchiveExtractionResult result;

        if (currentDepth >= config.maxArchiveDepth) {
            Logger::Warn("AttachmentScanner: Max archive depth reached");
            return result;
        }

        try {
            // Create extraction directory
            fs::path extractDir = m_config.tempExtractionPath /
                std::format("extract_{}", std::hash<std::string>{}(archivePath.string()));

            fs::create_directories(extractDir);

            // Use ArchiveExtractor infrastructure
            auto& extractor = Core::FileSystem::ArchiveExtractor::Instance();
            auto extractedFiles = extractor.Extract(archivePath, extractDir);

            size_t totalExtractedSize = 0;

            for (const auto& extractedPath : extractedFiles) {
                if (!fs::exists(extractedPath)) continue;

                NestedFileInfo nestedInfo;
                nestedInfo.fileName = extractedPath.filename().string();
                nestedInfo.relativePath = fs::relative(extractedPath, extractDir).string();
                nestedInfo.fileSize = fs::file_size(extractedPath);
                totalExtractedSize += nestedInfo.fileSize;

                // Zip bomb detection
                if (totalExtractedSize > config.maxExtractionSize) {
                    result.zipBombDetected = true;
                    Logger::Critical("AttachmentScanner: Zip bomb detected in {}",
                        archivePath.string());
                    break;
                }

                // Detect nested file type
                nestedInfo.fileType = DetectFileTypeImpl(extractedPath);
                nestedInfo.isHighRisk = IsHighRiskExtensionImpl(extractedPath.extension().string());

                // Scan nested file
                AttachmentScanConfig nestedConfig = config;
                nestedConfig.depth = ScanDepth::Standard;  // Don't do deep scans on nested

                auto nestedResult = ScanAttachmentImpl(extractedPath, nestedConfig);
                nestedInfo.verdict = nestedResult.verdict;
                nestedInfo.threatName = nestedResult.threatName;

                result.nestedFiles.push_back(nestedInfo);
                result.maxDepth = std::max(result.maxDepth, currentDepth + 1);

                m_stats.nestedFilesScanned.fetch_add(1, std::memory_order_relaxed);
            }

            // Clean up extraction directory
            try {
                fs::remove_all(extractDir);
            } catch (...) {
                // Ignore cleanup errors
            }

        } catch (const std::exception& e) {
            Logger::Error("AttachmentScanner: Archive extraction exception: {}", e.what());
        }

        return result;
    }

    [[nodiscard]] bool IsArchiveImpl(const fs::path& path) {
        return IsArchiveExtensionImpl(path.extension().string());
    }

    [[nodiscard]] bool IsPasswordProtectedArchiveImpl(const fs::path& path) {
        // Simplified check - would use libarchive/7z SDK in production
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file) return false;

            std::vector<uint8_t> header(100);
            file.read(reinterpret_cast<char*>(header.data()), header.size());

            // ZIP encryption check (general purpose bit flag bit 0)
            if (header.size() >= 10 && header[0] == 0x50 && header[1] == 0x4B) {
                uint16_t flags = *reinterpret_cast<uint16_t*>(&header[6]);
                return (flags & 0x01) != 0;
            }

            return false;

        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // MALWARE DETECTION
    // ========================================================================

    [[nodiscard]] bool CheckKnownMalwareImpl(const std::string& sha256) {
        try {
            auto& hashStore = HashStore::HashStore::Instance();
            return hashStore.IsMaliciousHash(sha256);
        } catch (...) {
            return false;
        }
    }

    struct MacroAnalysisResult {
        bool isSuspicious = false;
        std::vector<std::string> suspiciousPatterns;
    };

    [[nodiscard]] bool DetectMacrosImpl(const fs::path& path) {
        try {
            auto& macroDetector = Scripts::MacroDetector::Instance();
            return macroDetector.HasMacros(path);
        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] MacroAnalysisResult AnalyzeMacroContentImpl(const fs::path& path) {
        MacroAnalysisResult result;

        try {
            auto& macroDetector = Scripts::MacroDetector::Instance();
            auto macroResult = macroDetector.AnalyzeMacros(path);

            result.isSuspicious = macroResult.isSuspicious;
            // Would populate suspiciousPatterns from macroDetector

        } catch (const std::exception& e) {
            Logger::Error("AttachmentScanner: Macro analysis exception: {}", e.what());
        }

        return result;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeScanResultCallback(const AttachmentScanResult& result) {
        std::shared_lock lock(m_callbackMutex);
        if (m_scanResultCallback) {
            try {
                m_scanResultCallback(result);
            } catch (const std::exception& e) {
                Logger::Error("AttachmentScanner: Scan result callback exception: {}", e.what());
            }
        }
    }

    void InvokeThreatCallback(const AttachmentScanResult& result) {
        std::shared_lock lock(m_callbackMutex);
        if (m_threatCallback) {
            try {
                m_threatCallback(result);
            } catch (const std::exception& e) {
                Logger::Error("AttachmentScanner: Threat callback exception: {}", e.what());
            }
        }
    }

    void InvokeProgressCallback(float progress, const std::string& currentFile) {
        std::shared_lock lock(m_callbackMutex);
        if (m_progressCallback) {
            try {
                m_progressCallback(progress, currentFile);
            } catch (const std::exception& e) {
                Logger::Error("AttachmentScanner: Progress callback exception: {}", e.what());
            }
        }
    }

    void InvokeErrorCallback(const std::string& message, int code) {
        std::shared_lock lock(m_callbackMutex);
        if (m_errorCallback) {
            try {
                m_errorCallback(message, code);
            } catch (const std::exception& e) {
                Logger::Error("AttachmentScanner: Error callback exception: {}", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

std::atomic<bool> AttachmentScanner::s_instanceCreated{false};

[[nodiscard]] AttachmentScanner& AttachmentScanner::Instance() noexcept {
    static AttachmentScanner instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

[[nodiscard]] bool AttachmentScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AttachmentScanner::AttachmentScanner()
    : m_impl(std::make_unique<AttachmentScannerImpl>())
{
    Logger::Info("AttachmentScanner: Constructor called");
}

AttachmentScanner::~AttachmentScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("AttachmentScanner: Destructor called");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool AttachmentScanner::Initialize(const AttachmentScannerConfiguration& config) {
    if (!m_impl) {
        Logger::Critical("AttachmentScanner: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void AttachmentScanner::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool AttachmentScanner::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

[[nodiscard]] ModuleStatus AttachmentScanner::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

[[nodiscard]] bool AttachmentScanner::UpdateConfiguration(const AttachmentScannerConfiguration& config) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AttachmentScanner: Not initialized");
        return false;
    }

    if (!config.IsValid()) {
        Logger::Error("AttachmentScanner: Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    Logger::Info("AttachmentScanner: Configuration updated");
    return true;
}

[[nodiscard]] AttachmentScannerConfiguration AttachmentScanner::GetConfiguration() const {
    if (!m_impl) {
        return AttachmentScannerConfiguration{};
    }

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

[[nodiscard]] AttachmentScanResult AttachmentScanner::ScanAttachment(
    const std::filesystem::path& path,
    const AttachmentScanConfig& config
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AttachmentScanner: Not initialized");
        AttachmentScanResult result;
        result.fileName = path.filename().string();
        result.verdict = AttachmentVerdict::ScanError;
        result.errorMessage = "Scanner not initialized";
        return result;
    }

    return m_impl->ScanAttachmentImpl(path, config);
}

[[nodiscard]] AttachmentScanResult AttachmentScanner::ScanBuffer(
    std::span<const uint8_t> buffer,
    const std::string& fileName,
    const AttachmentScanConfig& config
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AttachmentScanner: Not initialized");
        AttachmentScanResult result;
        result.fileName = fileName;
        result.verdict = AttachmentVerdict::ScanError;
        result.errorMessage = "Scanner not initialized";
        return result;
    }

    return m_impl->ScanBufferImpl(buffer, fileName, config);
}

[[nodiscard]] std::future<AttachmentScanResult> AttachmentScanner::ScanAttachmentAsync(
    const std::filesystem::path& path,
    const AttachmentScanConfig& config
) {
    return std::async(std::launch::async, [this, path, config]() {
        return ScanAttachment(path, config);
    });
}

[[nodiscard]] std::vector<AttachmentScanResult> AttachmentScanner::ScanBatch(
    const std::vector<std::filesystem::path>& paths,
    const AttachmentScanConfig& config
) {
    std::vector<AttachmentScanResult> results;
    results.reserve(paths.size());

    for (const auto& path : paths) {
        results.push_back(ScanAttachment(path, config));
    }

    return results;
}

// ============================================================================
// ANALYSIS
// ============================================================================

[[nodiscard]] FileTypeCategory AttachmentScanner::DetectFileType(const std::filesystem::path& path) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return FileTypeCategory::Unknown;
    }

    return m_impl->DetectFileTypeImpl(path);
}

[[nodiscard]] FileTypeCategory AttachmentScanner::DetectFileType(
    std::span<const uint8_t> buffer,
    const std::string& fileName
) {
    FileTypeCategory magicCat = ClassifyByMagic(buffer);
    if (magicCat != FileTypeCategory::Unknown) {
        return magicCat;
    }

    fs::path path(fileName);
    return ClassifyByExtension(path.extension().string());
}

[[nodiscard]] bool AttachmentScanner::IsHighRiskExtension(std::string_view extension) const noexcept {
    return IsHighRiskExtensionImpl(extension);
}

[[nodiscard]] bool AttachmentScanner::VerifyExtension(const std::filesystem::path& path) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    std::vector<uint8_t> header(64);
    {
        std::ifstream file(path, std::ios::binary);
        if (file) {
            file.read(reinterpret_cast<char*>(header.data()), header.size());
            header.resize(file.gcount());
        }
    }

    return m_impl->VerifyExtensionImpl(path, header);
}

// ============================================================================
// ARCHIVE HANDLING
// ============================================================================

[[nodiscard]] std::vector<NestedFileInfo> AttachmentScanner::ExtractArchive(
    const std::filesystem::path& archivePath,
    const std::filesystem::path& extractTo
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AttachmentScanner: Not initialized");
        return {};
    }

    try {
        auto& extractor = Core::FileSystem::ArchiveExtractor::Instance();
        auto extractedPaths = extractor.Extract(archivePath, extractTo);

        std::vector<NestedFileInfo> nestedFiles;
        for (const auto& path : extractedPaths) {
            NestedFileInfo info;
            info.fileName = path.filename().string();
            info.relativePath = fs::relative(path, extractTo).string();
            info.fileSize = fs::file_size(path);
            info.fileType = m_impl->DetectFileTypeImpl(path);
            info.isHighRisk = IsHighRiskExtensionImpl(path.extension().string());
            nestedFiles.push_back(info);
        }

        return nestedFiles;

    } catch (const std::exception& e) {
        Logger::Error("AttachmentScanner: Extract archive exception: {}", e.what());
        return {};
    }
}

[[nodiscard]] bool AttachmentScanner::IsPasswordProtectedArchive(const std::filesystem::path& path) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->IsPasswordProtectedArchiveImpl(path);
}

[[nodiscard]] bool AttachmentScanner::IsArchive(const std::filesystem::path& path) {
    return IsArchiveExtensionImpl(path.extension().string());
}

// ============================================================================
// CALLBACKS
// ============================================================================

void AttachmentScanner::RegisterScanResultCallback(ScanResultCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanResultCallback = std::move(callback);

    Logger::Debug("AttachmentScanner: Registered scan result callback");
}

void AttachmentScanner::RegisterThreatCallback(ThreatDetectedCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_threatCallback = std::move(callback);

    Logger::Debug("AttachmentScanner: Registered threat callback");
}

void AttachmentScanner::RegisterProgressCallback(ProgressCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);

    Logger::Debug("AttachmentScanner: Registered progress callback");
}

void AttachmentScanner::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);

    Logger::Debug("AttachmentScanner: Registered error callback");
}

void AttachmentScanner::UnregisterCallbacks() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanResultCallback = nullptr;
    m_impl->m_threatCallback = nullptr;
    m_impl->m_progressCallback = nullptr;
    m_impl->m_errorCallback = nullptr;

    Logger::Debug("AttachmentScanner: Unregistered all callbacks");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] AttachmentStatistics AttachmentScanner::GetStatistics() const {
    if (!m_impl) {
        return AttachmentStatistics{};
    }

    std::shared_lock lock(m_impl->m_statsMutex);
    return m_impl->m_stats;
}

void AttachmentScanner::ResetStatistics() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_statsMutex);
    m_impl->m_stats.Reset();

    Logger::Info("AttachmentScanner: Statistics reset");
}

[[nodiscard]] bool AttachmentScanner::SelfTest() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("AttachmentScanner: Self-test failed - not initialized");
        return false;
    }

    try {
        Logger::Info("AttachmentScanner: Running self-test");

        // Test 1: File type detection
        std::vector<uint8_t> peHeader = {0x4D, 0x5A};  // MZ
        if (ClassifyByMagic(peHeader) != FileTypeCategory::Executable) {
            Logger::Error("AttachmentScanner: Self-test failed - PE detection");
            return false;
        }

        // Test 2: Extension classification
        if (ClassifyByExtension(".exe") != FileTypeCategory::Executable) {
            Logger::Error("AttachmentScanner: Self-test failed - extension classification");
            return false;
        }

        // Test 3: High-risk extension detection
        if (!IsHighRiskExtensionImpl(".exe")) {
            Logger::Error("AttachmentScanner: Self-test failed - high-risk detection");
            return false;
        }

        // Test 4: Entropy calculation
        std::vector<uint8_t> randomData(1024);
        for (size_t i = 0; i < randomData.size(); ++i) {
            randomData[i] = static_cast<uint8_t>(i % 256);
        }
        double entropy = CalculateEntropy(randomData);
        if (entropy < 0.0 || entropy > 8.0) {
            Logger::Error("AttachmentScanner: Self-test failed - entropy calculation");
            return false;
        }

        Logger::Info("AttachmentScanner: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("AttachmentScanner: Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string AttachmentScanner::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        AttachmentConstants::VERSION_MAJOR,
        AttachmentConstants::VERSION_MINOR,
        AttachmentConstants::VERSION_PATCH);
}

} // namespace Email
} // namespace ShadowStrike
